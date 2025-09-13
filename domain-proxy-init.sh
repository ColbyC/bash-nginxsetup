#!/bin/bash
# Author: Colby Cail
# Date: 2025-07-10
# Purpose: Harden Ubuntu 24.04, install NGINX, and configure acme.sh with Let's Encrypt

set -euo pipefail

ACME_DIR="/root/.acme.sh"

echo -e "\n\033[1;34m[+] Installing core packages...\033[0m"
apt update && apt install -y nginx ufw fail2ban curl vim unzip software-properties-common gnupg2 socat cron

echo -e "\n\033[1;34m[+] Enabling UFW firewall rules...\033[0m"
ufw allow 'OpenSSH'
ufw allow 'Nginx Full'
ufw --force enable

echo -e "\n\033[1;34m[+] Creating directory structure for NGINX proxy manager...\033[0m"
mkdir -p \
  /etc/nginx/conf.d/domains \
  /etc/nginx/conf.d/common \
  /etc/nginx/certs \
  /etc/nginx/backups \
  /var/www/html \
  /var/www/error_pages

chown -R www-data:www-data /var/www/html /var/www/error_pages
chmod -R 750 /etc/nginx/conf.d /etc/nginx/certs
chmod 700 /etc/nginx/backups

echo -e "\n\033[1;34m[+] Writing security headers config...\033[0m"
tee /etc/nginx/conf.d/common/security-headers.conf > /dev/null <<'EOF'
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin";
add_header Content-Security-Policy "default-src https: data: 'self' 'unsafe-inline'" always;
add_header Permissions-Policy "geolocation=(), microphone=()";
EOF

echo -e "\n\033[1;34m[+] Writing custom error page handler config...\033[0m"
tee /etc/nginx/conf.d/common/error-pages.conf > /dev/null <<'EOF'
error_page 404 /custom_404.html;
error_page 500 502 503 504 /custom_50x.html;

location = /custom_404.html {
    root /var/www/error_pages;
    internal;
}

location = /custom_50x.html {
    root /var/www/error_pages;
    internal;
}
EOF

echo '<html><body><h1>404 Not Found</h1></body></html>' > /var/www/error_pages/404.html
echo '<html><body><h1>Service Unavailable</h1></body></html>' > /var/www/error_pages/503.html
chown -R www-data:www-data /var/www/error_pages

echo -e "\n\033[1;34m[+] Configuring NGINX main config for hardening...\033[0m"
# Ensure `server_tokens off;`
grep -q "server_tokens" /etc/nginx/nginx.conf || sed -i '/http {/a \    server_tokens off;' /etc/nginx/nginx.conf

# Add rate limiting config
grep -q "limit_req_zone" /etc/nginx/nginx.conf || sed -i '/http {/a \    limit_req_zone $binary_remote_addr zone=ratelimit_zone:10m rate=10r/s;' /etc/nginx/nginx.conf

echo -e "\n\033[1;34m[+] Installing acme.sh and setting Let's Encrypt as default CA...\033[0m"
if [[ ! -d "$ACME_DIR" ]]; then
  curl https://get.acme.sh | sh -s email=noreply@systemsalt.com
fi

export PATH="$ACME_DIR":$PATH
"$ACME_DIR/acme.sh" --set-default-ca --server letsencrypt
"$ACME_DIR/acme.sh" --upgrade --auto-upgrade

echo -e "\n\033[1;34m[+] Enabling cron for automatic cert renewal...\033[0m"
"$ACME_DIR/acme.sh" --install-cronjob

echo -e "\n\033[1;34m[+] Final validation of NGINX configuration...\033[0m"
nginx -t && systemctl enable nginx && systemctl reload nginx

echo -e "\n\033[1;32m[✓] Hardened NGINX + ACME setup is complete. You can now use your nginx-domain-manager script.\033[0m"
