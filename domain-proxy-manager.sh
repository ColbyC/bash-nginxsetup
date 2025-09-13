#!/bin/bash
# Author: Colby Cail
# Date: 2025-07-10
# Purpose: Manage secure multi-domain NGINX reverse proxies with TLS, redirect handling, rollback, and config validation

set -euo pipefail

NGINX_CONF_DIR="/etc/nginx/conf.d/domains"
NGINX_CERT_DIR="/etc/nginx/certs"
BACKUP_DIR="/etc/nginx/backups"
ERROR_CONF="/etc/nginx/conf.d/common/error-pages.conf"
HEADERS_CONF="/etc/nginx/conf.d/common/security-headers.conf"
ACME_SH="/root/.acme.sh/acme.sh"

mkdir -p "$NGINX_CONF_DIR" "$NGINX_CERT_DIR" "$BACKUP_DIR"

function banner() {
    echo -e "\n\033[1;34m== NGINX DOMAIN PROXY MANAGER ==\033[0m"
}

function usage() {
    echo -e "\nUsage:"
    echo "  $0 add <domain> <proxy_url>           Add domain with proxy"
    echo "  $0 redirect <domain> <from> <to>      Add path redirect"
    echo "  $0 rollback <domain>                  Roll back to last config"
    echo "  $0 list                                List all domains"
    echo "  $0 reload                              Reload NGINX"
    exit 1
}

function precheck_dns() {
    local domain="$1"
    echo "[*] Verifying DNS resolution for $domain..."
    if ! dig +short "$domain" > /dev/null; then
        echo "[!] DNS resolution failed for $domain"
        return 1
    fi
    return 0
}

function backup_config() {
    local domain="$1"
    local conf_file="$NGINX_CONF_DIR/$domain.conf"
    local timestamp
    timestamp=$(date +"%Y%m%d%H%M%S")
    if [[ -f "$conf_file" ]]; then
        cp "$conf_file" "$BACKUP_DIR/$domain.conf.bak.$timestamp"
        echo "[*] Backup saved: $BACKUP_DIR/$domain.conf.bak.$timestamp"
    fi
}

function rollback_domain() {
    local domain="$1"
    local last_backup
    last_backup=$(ls -t "$BACKUP_DIR"/"$domain".conf.bak.* 2>/dev/null | head -n 1)

    if [[ -z "$last_backup" ]]; then
        echo "[!] No backup found for $domain"
        exit 1
    fi

    echo "[*] Rolling back to: $last_backup"
    cp "$last_backup" "$NGINX_CONF_DIR/$domain.conf"
    reload_nginx
}

function ensure_cert() {
    local domain="$1"
    local cert_path="$NGINX_CERT_DIR/$domain"
    mkdir -p "$cert_path"

    if ! precheck_dns "$domain"; then
        echo "[!] Aborting certificate request."
        exit 1
    fi

    echo "[*] Issuing certificate for $domain (webroot first)..."
    if ! $ACME_SH --issue -d "$domain" --webroot /var/www/html; then
        echo "[!] Webroot challenge failed, trying DNS challenge..."
        if ! $ACME_SH --issue --dns dns_cf -d "$domain"; then
            echo "[✗] DNS challenge also failed."
            exit 1
        fi
    fi

    $ACME_SH --install-cert -d "$domain" \
        --key-file "$cert_path/key.pem" \
        --fullchain-file "$cert_path/full.pem" \
        --reloadcmd "systemctl reload nginx"
}

function create_conf() {
    local domain="$1"
    local proxy_url="$2"
    local conf_file="$NGINX_CONF_DIR/$domain.conf"

    echo "[*] Creating NGINX config for $domain → $proxy_url"
    cat > "$conf_file" <<EOF
server {
    listen 443 ssl http2;
    server_name $domain;

    ssl_certificate     $NGINX_CERT_DIR/$domain/full.pem;
    ssl_certificate_key $NGINX_CERT_DIR/$domain/key.pem;

    include $HEADERS_CONF;
    include $ERROR_CONF;

    access_log /var/log/nginx/${domain}.access.log;
    error_log  /var/log/nginx/${domain}.error.log;

    location / {
        proxy_pass $proxy_url;
        proxy_ssl_verify off;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        limit_req zone=ratelimit_zone burst=20 nodelay;
    }
}

server {
    listen 80;
    server_name $domain;
    return 301 https://\$host\$request_uri;
}
EOF
}

function add_domain() {
    local domain="$1"
    local proxy_url="$2"

    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        echo "[!] Invalid domain: $domain"
        exit 1
    fi

    if [[ ! "$proxy_url" =~ ^https?:// ]]; then
        echo "[!] Invalid proxy URL: $proxy_url"
        exit 1
    fi

    backup_config "$domain"
    ensure_cert "$domain"
    create_conf "$domain" "$proxy_url"
    echo "[✓] Domain $domain configured."
}

function add_redirect() {
    local domain="$1"
    local from_path="$2"
    local to_url="$3"
    local conf_file="$NGINX_CONF_DIR/$domain.conf"

    if [[ ! -f "$conf_file" ]]; then
        echo "[!] Domain config not found: $domain"
        exit 1
    fi

    if [[ ! "$from_path" =~ ^/.* ]]; then
        echo "[!] Redirect path must start with '/'"
        exit 1
    fi

    if [[ ! "$to_url" =~ ^https?:// ]]; then
        echo "[!] Invalid redirect target: $to_url"
        exit 1
    fi

    backup_config "$domain"
    echo "[*] Adding redirect to $domain: $from_path → $to_url"

    # Ensure trailing slash in from_path
    [[ "${from_path}" != */ ]] && from_path="${from_path}/"

    awk -v path="$from_path" -v target="$to_url" '
    BEGIN {
        block1 = "    location = " substr(path, 1, length(path)-1) " {\n" \
                 "        return 301 " path ";\n" \
                 "    }\n"

        block2 = "    location " path " {\n" \
                 "        proxy_pass " target ";\n" \
                 "        proxy_ssl_verify off;\n" \
                 "        proxy_set_header Host $host;\n" \
                 "        proxy_set_header X-Forwarded-For $remote_addr;\n" \
                 "        limit_req zone=ratelimit_zone burst=20 nodelay;\n" \
                 "    }\n"
    }
    {
        print
        if ($0 ~ /location \// && !found) {
            print block1
            print block2
            found = 1
        }
    }' "$conf_file" > "${conf_file}.tmp" && mv "${conf_file}.tmp" "$conf_file"
}

function list_domains() {
    echo -e "\n\033[1;33mConfigured Domains:\033[0m"
    for file in "$NGINX_CONF_DIR"/*.conf; do
        [[ -f "$file" ]] || continue
        domain=$(basename "$file" .conf)
        echo -e "• \033[32m$domain\033[0m"
        grep "proxy_pass" "$file" | sed 's/^/   ↪ /'
    done
}

function reload_nginx() {
    echo "[*] Validating NGINX configuration..."
    if nginx -t; then
        echo "[*] Reloading NGINX..."
        systemctl reload nginx
        echo "[✓] NGINX reloaded."
    else
        echo "[✗] NGINX config invalid. Aborting reload."
        exit 1
    fi
}

### MAIN ###

banner

case "${1:-}" in
    add)
        [[ $# -eq 3 ]] || usage
        add_domain "$2" "$3"
        reload_nginx
        ;;
    redirect)
        [[ $# -eq 4 ]] || usage
        add_redirect "$2" "$3" "$4"
        reload_nginx
        ;;
    rollback)
        [[ $# -eq 2 ]] || usage
        rollback_domain "$2"
        ;;
    list)
        list_domains
        ;;
    reload)
        reload_nginx
        ;;
    *)
        usage
        ;;
esac