#!/bin/bash
# Rewritten: Manage secure multi-domain NGINX reverse proxies with ACME

set -euo pipefail

readonly NGINX_CONF_DIR="/etc/nginx/conf.d/domains"
readonly NGINX_CERT_DIR="/etc/ssl/clients"
readonly BACKUP_DIR="/etc/nginx/backups"
readonly COMMON_DIR="/etc/nginx/conf.d/common"
readonly ERROR_CONF="${COMMON_DIR}/error-pages.conf"
readonly HEADERS_CONF="${COMMON_DIR}/security-headers.conf"
readonly SSL_CONF="${COMMON_DIR}/ssl-params.conf"
readonly ACME_WEBROOT="/var/www/acme-webroot"

# ACME renewal user model (mirrors bootstrap_acme_renewal_user.sh and init)
readonly RENEW_USER="${RENEW_USER:-acmebot}"
readonly RENEW_HOME="${RENEW_HOME:-/var/lib/acme}"
readonly ACME_SH="${RENEW_HOME}/.acme.sh/acme.sh"
readonly DEPLOY_HELPER="${DEPLOY_HELPER:-/usr/local/sbin/acme-deploy}"

info() { printf "\033[1;34m[+] %s\033[0m\n" "$*"; }
warn() { printf "\033[1;33m[!] %s\033[0m\n" "$*"; }
ok()   { printf "\033[1;32m[\xE2\x9C\x93] %s\033[0m\n" "$*"; }

require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        echo "[!] This script must be run as root" >&2
        exit 1
    fi
}

ensure_layout() {
    mkdir -p "${NGINX_CONF_DIR}" "${NGINX_CERT_DIR}" "${BACKUP_DIR}"
    for f in "${ERROR_CONF}" "${HEADERS_CONF}" "${SSL_CONF}" "${COMMON_DIR}/acme-challenge.conf"; do
        if [[ ! -f "$f" ]]; then
            warn "Missing common include: $f. Run ./domain-proxy-init.sh first."
            exit 1
        fi
    done
    if [[ ! -x "$DEPLOY_HELPER" ]]; then
        warn "Deploy helper missing at ${DEPLOY_HELPER}. Run ./domain-proxy-init.sh first."
        exit 1
    fi
}

usage() {
    cat <<USAGE
Usage:
  $0 add <domain> <proxy_url>           Add domain with reverse proxy
  $0 ssl <domain> [webroot_path]        Add static site (TLS) from disk
  $0 site <domain> [webroot_path]       Alias of 'ssl' for static sites
  $0 redirect <domain> <from> <to>      Add path redirect (proxy to URL)
  $0 rollback <domain>                  Roll back the last config
  $0 list                                List all domains
  $0 reload                              Validate and reload NGINX
USAGE
    exit 1
}

valid_domain() {
    local d="$1"
    [[ "$d" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$ ]] && [[ ${#d} -le 253 ]]
}

dns_resolves() {
    local d="$1"
    local out
    out=$(dig +short A "$d" 2>/dev/null || true)
    [[ -n "$out" ]] || out=$(dig +short AAAA "$d" 2>/dev/null || true)
    [[ -n "$out" ]]
}

backup_config() {
    local domain="$1"
    local conf_file="${NGINX_CONF_DIR}/${domain}.conf"
    if [[ -f "$conf_file" ]]; then
        local ts; ts=$(date +%Y%m%d%H%M%S)
        cp "$conf_file" "${BACKUP_DIR}/${domain}.conf.bak.${ts}"
        info "Backup saved: ${BACKUP_DIR}/${domain}.conf.bak.${ts}"
    fi
}

rollback_domain() {
    local domain="$1"
    local last
    last=$(ls -t "${BACKUP_DIR}/${domain}.conf.bak."* 2>/dev/null | head -n1 || true)
    if [[ -z "$last" ]]; then
        warn "No backup found for ${domain}"
        exit 1
    fi
    cp "$last" "${NGINX_CONF_DIR}/${domain}.conf"
    ok "Rolled back ${domain} to ${last}"
}

ensure_cert() {
    local domain="$1"
    local cert_path="${NGINX_CERT_DIR}/${domain}"
    mkdir -p "$cert_path"

    info "Checking DNS for ${domain}"
    if ! dns_resolves "$domain"; then
        warn "Domain ${domain} does not resolve. Aborting."
        exit 1
    fi

    if [[ ! -x "$ACME_SH" ]]; then
        warn "acme.sh not found at $ACME_SH. Run ./domain-proxy-init.sh first."
        exit 1
    fi

    # Preflight HTTP-01: write token as renewal user and fetch via nginx
    preflight_http01 "$domain"

    info "Issuing certificate (HTTP-01 webroot first) as ${RENEW_USER}"
    if ! sudo -u "$RENEW_USER" -H "$ACME_SH" --issue -d "$domain" -w "$ACME_WEBROOT" >/dev/null; then
        warn "Webroot challenge failed. Trying DNS challenge (Cloudflare) if env present."
        if [[ -n "${CF_Token:-}" || ( -n "${CF_Key:-}" && -n "${CF_Email:-}" ) ]]; then
            # Preserve env for CF_* when switching user
            sudo -E -u "$RENEW_USER" -H "$ACME_SH" --issue --dns dns_cf -d "$domain"
        else
            warn "Cloudflare credentials not provided. Export CF_Token or CF_Key/CF_Email."
            exit 1
        fi
    fi

    # Install mapping to a stash under renewal home, deploy via helper (sudo)
    local stash_dir="${RENEW_HOME}/deploy-stash/${domain}"
    sudo -u "$RENEW_USER" -H mkdir -p "$stash_dir"
    sudo -u "$RENEW_USER" -H "$ACME_SH" --install-cert -d "$domain" \
        --key-file       "${stash_dir}/key.pem" \
        --fullchain-file "${stash_dir}/full.pem" \
        --reloadcmd      "sudo ${DEPLOY_HELPER} ${domain} ${stash_dir}/key.pem ${stash_dir}/full.pem ${NGINX_CERT_DIR} 'systemctl reload nginx'" >/dev/null
}

write_proxy_conf() {
    local domain="$1" url="$2" conf_file="${NGINX_CONF_DIR}/${domain}.conf"
    cat >"$conf_file" <<EOF
server {
    listen 443 ssl http2;
    server_name ${domain};
    server_tokens off;

    ssl_certificate     ${NGINX_CERT_DIR}/${domain}/${domain}.crt;
    ssl_certificate_key ${NGINX_CERT_DIR}/${domain}/${domain}.key;

    include ${SSL_CONF};
    include ${HEADERS_CONF};
    include ${ERROR_CONF};
    include ${COMMON_DIR}/acme-challenge.conf;

    access_log /var/log/nginx/${domain}.access.log;
    error_log  /var/log/nginx/${domain}.error.log;

    location / {
        proxy_pass ${url};
        proxy_http_version 1.1;
        proxy_set_header Host               \$host;
        proxy_set_header X-Real-IP          \$remote_addr;
        proxy_set_header X-Forwarded-For    \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto  \$scheme;
        proxy_set_header Upgrade            \$http_upgrade;
        proxy_set_header Connection         \"upgrade\";
        proxy_ssl_server_name on;
        proxy_redirect off;
        proxy_read_timeout 60s;
        limit_req zone=ratelimit_zone burst=20 nodelay;
    }
}

server {
    listen 80;
    server_name ${domain};
    server_tokens off;
    include ${COMMON_DIR}/acme-challenge.conf;
    location / { return 301 https://\$host\$request_uri; }
}
EOF
}

write_static_site_conf() {
    local domain="$1" webroot="${2:-/var/www/html}" conf_file="${NGINX_CONF_DIR}/${domain}.conf"
    mkdir -p "$webroot" && chown -R www-data:www-data "$webroot"
    cat >"$conf_file" <<EOF
server {
    listen 443 ssl http2;
    server_name ${domain};
    server_tokens off;

    ssl_certificate     ${NGINX_CERT_DIR}/${domain}/${domain}.crt;
    ssl_certificate_key ${NGINX_CERT_DIR}/${domain}/${domain}.key;

    include ${SSL_CONF};
    include ${HEADERS_CONF};
    include ${ERROR_CONF};
    include ${COMMON_DIR}/acme-challenge.conf;

    access_log /var/log/nginx/${domain}.access.log;
    error_log  /var/log/nginx/${domain}.error.log;

    root ${webroot};
    index index.html index.htm;
    location / {
        try_files \$uri \$uri/ =404;
        limit_req zone=ratelimit_zone burst=20 nodelay;
    }
}

server {
    listen 80;
    server_name ${domain};
    server_tokens off;
    include ${COMMON_DIR}/acme-challenge.conf;
    location / { return 301 https://\$host\$request_uri; }
}
EOF
}

# Backward-compatible name kept for callers and docs
write_ssl_only_conf() { write_static_site_conf "$@"; }

add_redirect_block() {
    local conf_file="$1" from_path="$2" to_url="$3"
    # Normalize path to ensure trailing slash block + exact match
    [[ "$from_path" == */ ]] || from_path+="/"

    if grep -q "location ${from_path}" "$conf_file"; then
        warn "Redirect for ${from_path} already exists in $(basename "$conf_file")"
        return 0
    fi

    # Insert blocks just after the first location / block inside the 443 server
    awk -v path="$from_path" -v target="$to_url" '
        BEGIN {
          block1 = "    location = " substr(path, 1, length(path)-1) " {\n        return 301 " path ";\n    }\n";
          block2 = "    location " path " {\n        proxy_pass " target ";\n        proxy_http_version 1.1;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n        proxy_ssl_server_name on;\n        proxy_redirect off;\n        limit_req zone=ratelimit_zone burst=20 nodelay;\n    }\n";
          inserted=0; in_server=0; depth=0; ssl_listen=0;
        }
        {
          line=$0
          # Detect entering a server block
          if (match(line, /^\s*server\s*\{/)) { in_server=1; depth=1; ssl_listen=0 }
          else if (in_server) {
            if (index(line, "{")>0) depth++
            if (index(line, "}")>0) depth--
          }

          # Flag SSL listen inside this server
          if (in_server && line ~ /listen\s+443/) ssl_listen=1

          print line

          # After the root location line in the 443 server, inject our blocks once
          if (in_server && ssl_listen && !inserted && line ~ /location\s+\/\s*\{/) {
            print block1
            print block2
            inserted=1
          }

          # Leaving server block
          if (in_server && depth==0) { in_server=0; ssl_listen=0 }
        }
    ' "$conf_file" >"${conf_file}.tmp" && mv "${conf_file}.tmp" "$conf_file"
}

reload_nginx() {
    info "Validating NGINX configuration"
    nginx -t
    systemctl reload nginx
    ok "NGINX reloaded"
}

add_domain() {
    local domain="$1" proxy_url="$2"
    valid_domain "$domain" || { warn "Invalid domain: $domain"; exit 1; }
    [[ "$proxy_url" =~ ^https?:// ]] || { warn "Invalid proxy URL: $proxy_url"; exit 1; }
    backup_config "$domain"
    ensure_cert "$domain"
    write_proxy_conf "$domain" "$proxy_url"
    ok "Configured reverse proxy for ${domain} -> ${proxy_url}"
}

add_ssl_domain() {
    local domain="$1" webroot="${2:-/var/www/html}"
    valid_domain "$domain" || { warn "Invalid domain: $domain"; exit 1; }
    backup_config "$domain"
    ensure_cert "$domain"
    write_static_site_conf "$domain" "$webroot"
    ok "Configured static site for ${domain} (root: ${webroot})"
}

# Alias for clarity: non-proxy local-disk website
add_site_domain() { add_ssl_domain "$@"; }

add_redirect() {
    local domain="$1" from_path="$2" to_url="$3" conf_file="${NGINX_CONF_DIR}/${domain}.conf"
    [[ -f "$conf_file" ]] || { warn "Domain config not found: $domain"; exit 1; }
    [[ "$from_path" =~ ^/ ]] || { warn "Redirect path must start with '/'"; exit 1; }
    [[ "$to_url" =~ ^https?:// ]] || { warn "Invalid redirect target: $to_url"; exit 1; }
    backup_config "$domain"
    add_redirect_block "$conf_file" "$from_path" "$to_url"
    ok "Added redirect on ${domain}: ${from_path} -> ${to_url}"
}

list_domains() {
    printf "\033[1;33mConfigured Domains:\033[0m\n"
    shopt -s nullglob
    for file in "${NGINX_CONF_DIR}"/*.conf; do
        local domain; domain=$(basename "$file" .conf)
        if grep -q "proxy_pass" "$file"; then
            printf "• %s (proxy)\n" "$domain"
            grep -m1 "proxy_pass" "$file" | sed 's/^/   ↪ /'
        else
            printf "• %s (static)\n" "$domain"
            grep -m1 "^\s*root\s" "$file" | sed 's/^/   📁 /'
        fi
        if [[ -f "${NGINX_CERT_DIR}/${domain}/${domain}.crt" ]]; then
            printf "   ✓ cert installed\n"
        else
            printf "   ✗ cert missing\n"
        fi
    done
}

# Write-read test for HTTP-01 via nginx with Host header
preflight_http01() {
    local domain="$1"
    local token=".preflight_$(date +%s)_$RANDOM"
    local path="${ACME_WEBROOT}/.well-known/acme-challenge/${token}"
    info "Preflight HTTP-01 for ${domain}"
    sudo -u "$RENEW_USER" -H bash -lc "echo PREPASS > '$path'" || { warn "Failed to write preflight token"; exit 1; }
    local out
    out=$(curl -sS -H "Host: ${domain}" "http://127.0.0.1/.well-known/acme-challenge/${token}" || true)
    rm -f "$path" || true
    if [[ "$out" != "PREPASS" ]]; then
        warn "Preflight failed for ${domain}. Check webroot serving and rewrite rules."
        exit 1
    fi
}

main() {
    require_root
    ensure_layout
    case "${1:-}" in
        add)      [[ $# -eq 3 ]] || usage; add_domain "$2" "$3"; reload_nginx ;;
        ssl)      [[ $# -ge 2 && $# -le 3 ]] || usage; add_ssl_domain "$2" "${3:-}"; reload_nginx ;;
        site)     [[ $# -ge 2 && $# -le 3 ]] || usage; add_site_domain "$2" "${3:-}"; reload_nginx ;;
        redirect) [[ $# -eq 4 ]] || usage; add_redirect "$2" "$3" "$4"; reload_nginx ;;
        rollback) [[ $# -eq 2 ]] || usage; rollback_domain "$2"; reload_nginx ;;
        list)     list_domains ;;
        reload)   reload_nginx ;;
        *)        usage ;;
    esac
}

main "$@"
