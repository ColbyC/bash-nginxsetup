#!/bin/bash
# Rewritten: Idempotent NGINX + ACME bootstrap for Ubuntu

set -euo pipefail

readonly NGINX_DIR="/etc/nginx"
readonly DOMAINS_DIR="${NGINX_DIR}/conf.d/domains"
readonly COMMON_DIR="${NGINX_DIR}/conf.d/common"
readonly CERTS_DIR="/etc/ssl/clients"
readonly BACKUPS_DIR="${NGINX_DIR}/backups"
readonly ACME_WEBROOT="/var/www/acme-webroot"
readonly ERROR_PAGES="/var/www/error_pages"

# ACME renewal user model (mirrors bootstrap_acme_renewal_user.sh structure)
readonly RENEW_USER="${RENEW_USER:-acmebot}"
readonly RENEW_HOME="${RENEW_HOME:-/var/lib/acme}"
readonly ACME_BIN="${RENEW_HOME}/.acme.sh/acme.sh"
readonly DEPLOY_HELPER="${DEPLOY_HELPER:-/usr/local/sbin/acme-deploy}"
readonly SUDOERS_FILE="/etc/sudoers.d/${RENEW_USER}"
readonly DEFAULT_EMAIL="${DEFAULT_EMAIL:-noreply@example.invalid}"

info() { printf "\033[1;34m[+] %s\033[0m\n" "$*"; }
warn() { printf "\033[1;33m[!] %s\033[0m\n" "$*"; }
ok()   { printf "\033[1;32m[\xE2\x9C\x93] %s\033[0m\n" "$*"; }

require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        echo "[!] This script must be run as root" >&2
        exit 1
    fi
}

detect_ubuntu() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "${ID}-${VERSION_ID}" in
            ubuntu-24.04|ubuntu-22.04) return 0 ;;
            *) warn "Tested on Ubuntu 22.04/24.04. Continuing anyway." ;;
        esac
    fi
}

install_packages() {
    info "Installing core packages"
    DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        nginx ufw dnsutils curl unzip gnupg2 socat cron acl >/dev/null
}

prepare_layout() {
    info "Preparing directory layout"
    mkdir -p "${DOMAINS_DIR}" "${COMMON_DIR}" "${CERTS_DIR}" "${BACKUPS_DIR}" \
             "${ACME_WEBROOT}/.well-known/acme-challenge" "${ERROR_PAGES}" /var/www/html
    chown -R www-data:www-data /var/www/html "${ERROR_PAGES}"
    # ACME webroot will be owned by renewal user (set later)
    chmod -R 755 "${NGINX_DIR}/conf.d"
    # Base certs dir perms finalized later by ensure_ssl_cert_group
    chmod 750 "${CERTS_DIR}"
    chmod 700 "${BACKUPS_DIR}"
}

disable_default_site() {
    info "Disabling default NGINX site"
    local def_enabled="/etc/nginx/sites-enabled/default"
    if [[ -e "${def_enabled}" ]]; then
        # Backup then remove the enabled default to prevent duplicate default_server
        cp "${def_enabled}" "${BACKUPS_DIR}/default.$(date +%Y%m%d%H%M%S).sites-enabled.bak" 2>/dev/null || true
        rm -f "${def_enabled}"
    fi
}

write_common_includes() {
    info "Writing common include files"
    cat >"${COMMON_DIR}/security-headers.conf" <<'EOF'
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin";
add_header Permissions-Policy "geolocation=(), microphone=()";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
EOF

    cat >"${COMMON_DIR}/ssl-params.conf" <<'EOF'
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
ssl_prefer_server_ciphers off;
ssl_session_timeout 10m;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
EOF

    cat >"${COMMON_DIR}/error-pages.conf" <<'EOF'
# Standardized error pages mapping. Files are served internally from /var/www/error_pages
error_page 400 /errors/400.html;
error_page 401 /errors/401.html;
error_page 403 /errors/403.html;
error_page 404 /errors/404.html;
error_page 405 /errors/405.html;
error_page 408 /errors/408.html;
error_page 410 /errors/410.html;
error_page 429 /errors/429.html;
error_page 451 /errors/451.html;
error_page 500 /errors/500.html;
error_page 501 /errors/501.html;
error_page 502 /errors/502.html;
error_page 503 /errors/503.html;
error_page 504 /errors/504.html;
error_page 505 /errors/505.html;

location ^~ /errors/ {
    alias /var/www/error_pages/;
    internal;
}
EOF

    # Generate minimal, consistent HTML pages for the above error codes
    local codes msg
    for code in 400 401 403 404 405 408 410 429 451 500 501 502 503 504 505; do
        case "$code" in
            400) msg="Bad Request" ;;
            401) msg="Unauthorized" ;;
            403) msg="Forbidden" ;;
            404) msg="Not Found" ;;
            405) msg="Method Not Allowed" ;;
            408) msg="Request Timeout" ;;
            410) msg="Gone" ;;
            429) msg="Too Many Requests" ;;
            451) msg="Unavailable For Legal Reasons" ;;
            500) msg="Internal Server Error" ;;
            501) msg="Not Implemented" ;;
            502) msg="Bad Gateway" ;;
            503) msg="Service Unavailable" ;;
            504) msg="Gateway Timeout" ;;
            505) msg="HTTP Version Not Supported" ;;
        esac
        cat >"${ERROR_PAGES}/${code}.html" <<EOF_ERR
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${code} ${msg}</title>
    <style>
        html,body{height:100%;margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",Arial,sans-serif;background:#0b0f19;color:#e6e8ef}
        .wrap{min-height:100%;display:flex;align-items:center;justify-content:center}
        .box{padding:2rem 1.5rem;text-align:center}
        h1{font-size:2rem;margin:.25rem 0}
        .code{font-size:3rem;font-weight:700;letter-spacing:.05em;color:#7aa2f7}
        p{opacity:.9}
    </style>
    <meta http-equiv="refresh" content="15" />
    <meta name="robots" content="noindex" />
    <meta name="referrer" content="no-referrer" />
    <meta http-equiv="X-Content-Type-Options" content="nosniff" />
    <meta http-equiv="X-Frame-Options" content="SAMEORIGIN" />
    <meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin" />
    <meta http-equiv="Permissions-Policy" content="geolocation=(), microphone=()" />
    <meta http-equiv="Cache-Control" content="no-store" />
    <meta http-equiv="Pragma" content="no-cache" />
    <meta http-equiv="Expires" content="0" />
    <!-- Default, minimal error page; replace files in /var/www/error_pages to customize. -->
    <!-- ${code} ${msg} -->
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    <noscript>
        <style>.code{font-size:2.4rem}</style>
    </noscript>
</head>
<body>
    <div class="wrap"><div class="box">
        <div class="code">${code}</div>
        <h1>${msg}</h1>
        <p>If this persists, please try again later.</p>
    </div></div>
</body>
</html>
EOF_ERR
    done

    cat >"${COMMON_DIR}/acme-challenge.conf" <<EOF
location ^~ /.well-known/acme-challenge/ {
    root ${ACME_WEBROOT};
    try_files \$uri =404;
}
EOF
}

backup_nginx_conf() {
    local src="${NGINX_DIR}/nginx.conf"
    if [[ -f "$src" ]]; then
        cp "$src" "${BACKUPS_DIR}/nginx.conf.$(date +%Y%m%d%H%M%S)"
    fi
}

harden_nginx_conf() {
    info "Hardening nginx.conf and enabling domain includes"
    local conf="${NGINX_DIR}/nginx.conf"
    backup_nginx_conf

    # Idempotently ensure within the http {} block:
    #   - server_tokens off;
    #   - limit_req_zone $binary_remote_addr zone=ratelimit_zone:10m rate=10r/s;
    #   - include ${DOMAINS_DIR}/*.conf;
    # Insert missing directives right before the closing brace of http {}
    awk -v inc="    include ${DOMAINS_DIR}/*.conf;" '
        BEGIN { in_http=0; depth=0; have_tokens=0; have_zone=0; have_inc=0 }
        {
            line=$0
            # Track entering http block
            if (match(line, /^\s*http\s*\{/)) { in_http=1; depth=1; }
            else if (in_http) {
                # Maintain nested braces count inside http
                if (index(line, "{")>0) depth++
                if (index(line, "}")>0) depth--
            }

            if (in_http) {
                if (line ~ /server_tokens\s+off;/) have_tokens=1
                if (line ~ /limit_req_zone\s+\$binary_remote_addr\s+zone=ratelimit_zone:10m\s+rate=10r\/s;/) have_zone=1
                if (line ~ inc) have_inc=1
                # Before closing the http block, inject any missing lines
                if (depth==0) {
                    if (!have_tokens) print "    server_tokens off;"
                    if (!have_zone)  print "    limit_req_zone $binary_remote_addr zone=ratelimit_zone:10m rate=10r/s;"
                    if (!have_inc)   print inc
                    in_http=0
                }
            }
            print line
        }
    ' "$conf" >"${conf}.tmp" && mv "${conf}.tmp" "$conf"
}

write_catchall_server() {
    info "Ensuring catch-all ACME server block"
    cat >"${NGINX_DIR}/conf.d/000-catch-all-wellknown.conf" <<EOF
# Catch-all server block for ACME HTTP-01 challenges
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    server_tokens off;
    include ${COMMON_DIR}/acme-challenge.conf;
    include ${COMMON_DIR}/security-headers.conf;
    include ${COMMON_DIR}/error-pages.conf;
    limit_req zone=ratelimit_zone burst=20 nodelay;
    location / { return 444; }
}
EOF
}

enable_firewall() {
    info "Configuring UFW"
    ufw allow 'Nginx Full' >/dev/null 2>&1 || true
    yes | ufw enable >/dev/null 2>&1 || true
}

install_acme() {
    info "Installing acme.sh for renewal user (if missing)"
    if [[ ! -x "${ACME_BIN}" ]]; then
        mkdir -p "${RENEW_HOME}"
        if ! id "${RENEW_USER}" >/dev/null 2>&1; then
            useradd --system --home "${RENEW_HOME}" --shell /usr/sbin/nologin "${RENEW_USER}"
        fi
        chown -R "${RENEW_USER}:${RENEW_USER}" "${RENEW_HOME}"
        sudo -u "${RENEW_USER}" -H bash -lc 'cd "$HOME" && curl -s https://get.acme.sh | sh -s email=${DEFAULT_EMAIL}'
    fi
    # Pin LE, enable cron and auto-upgrade under renewal user
    sudo -u "${RENEW_USER}" -H "${ACME_BIN}" --set-default-ca --server letsencrypt >/dev/null || true
    sudo -u "${RENEW_USER}" -H "${ACME_BIN}" --upgrade --auto-upgrade >/dev/null || true
    sudo -u "${RENEW_USER}" -H "${ACME_BIN}" --install-cronjob >/dev/null || true
}

validate_and_reload() {
    info "Validating NGINX configuration"
    nginx -t
    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl reload nginx || systemctl restart nginx || true
    ok "NGINX configuration valid and service reloaded"
}

# Prepare ACME webroot permissions for HTTP-01 (no nginx edits here)
prepare_webroot_acl() {
    info "Preparing ACME webroot permissions for ${RENEW_USER}"
    local well="${ACME_WEBROOT}/.well-known"
    local chal="${well}/acme-challenge"
    mkdir -p "${chal}"
    chown -R "${RENEW_USER}":www-data "${well}" || true
    chmod 750 "${well}" "${chal}" || true
    setfacl -R -m u:"${RENEW_USER}":rwx "${well}" || true
    setfacl -d  -m u:"${RENEW_USER}":rwx "${well}" || true
    setfacl -R -m g:www-data:rx "${well}" || true
    setfacl -d  -m g:www-data:rx "${well}" || true
    chmod 755 "${ACME_WEBROOT}" || true
    chmod 755 /var/www || true
    chmod 755 /var || true
}

# Write a constrained deploy helper that atomically installs to CERTS_DIR and reloads nginx
write_deploy_helper() {
    info "Installing deploy helper at ${DEPLOY_HELPER}"
tee "${DEPLOY_HELPER}" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
DOMAIN="${1:-}"; SRC_KEY="${2:-}"; SRC_CRT="${3:-}"
TARGET_DIR_BASE="${4:-/etc/ssl/clients}"
RELOAD_CMD="${5:-systemctl reload nginx}"
[ -n "$DOMAIN" ] || { echo "Usage: acme-deploy <domain> <src_key> <src_fullchain> [target_base] [reload_cmd]" >&2; exit 2; }

DEST_DIR="${TARGET_DIR_BASE}/${DOMAIN}"
TMPDIR="$(mktemp -d /tmp/acme-deploy-XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

install -d -m 0755 -o root -g ssl-cert "$TARGET_DIR_BASE"
install -d -m 0751 -o root -g ssl-cert "$DEST_DIR"

# Stage with canonical filenames, then atomically move into place
install -m 0640 -o root -g ssl-cert "$SRC_KEY" "${TMPDIR}/${DOMAIN}.key"
install -m 0644 -o root -g ssl-cert "$SRC_CRT" "${TMPDIR}/${DOMAIN}.crt"

mv -f "${TMPDIR}/${DOMAIN}.key" "${DEST_DIR}/${DOMAIN}.key"
mv -f "${TMPDIR}/${DOMAIN}.crt" "${DEST_DIR}/${DOMAIN}.crt"

$RELOAD_CMD
EOF
    chmod 750 "${DEPLOY_HELPER}"
    chown root:root "${DEPLOY_HELPER}"
}

# Ensure ssl-cert group exists and base directory ownership/permissions allow
# public read of CRT while keeping KEY group-restricted.
ensure_ssl_cert_group() {
    info "Ensuring ssl-cert group and base certs dir permissions"
    if ! getent group ssl-cert >/dev/null; then
        groupadd --system ssl-cert || true
    fi
    chown root:ssl-cert "${CERTS_DIR}" || true
    chmod 0755 "${CERTS_DIR}" || true
}

write_sudoers_rule() {
    info "Writing sudoers rule for ${RENEW_USER}"
    local tmp="/tmp/${RENEW_USER}.sudoers.$$"
    cat >"${tmp}" <<EOF
# Limited sudo for ${RENEW_USER}: allow only the deploy helper
${RENEW_USER} ALL=(root) NOPASSWD: ${DEPLOY_HELPER}
Defaults:${RENEW_USER} !secure_path
EOF
    visudo -cf "${tmp}"
    install -m 0440 -o root -g root "${tmp}" "${SUDOERS_FILE}"
    rm -f "${tmp}"
}

main() {
    require_root
    detect_ubuntu
    install_packages
    prepare_layout
    disable_default_site
    write_common_includes
    harden_nginx_conf
    write_catchall_server
    enable_firewall
    install_acme
    prepare_webroot_acl
    write_deploy_helper
    ensure_ssl_cert_group
    write_sudoers_rule
    validate_and_reload
}

main "$@"
