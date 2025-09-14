# NGINX Domain Proxy Toolkit

This repository provides a minimal, hardened setup to manage multiple domains on a single NGINX host with automatic TLS via acme.sh. It includes:

- One‑time bootstrap: install and harden NGINX, set up ACME, and prepare directory layout.
- Daily operations: add/update domains as reverse proxies or static SSL sites, add path redirects, list and roll back.
- Optional advanced bootstrap for a dedicated ACME renewal user only.

Run these scripts on a clean Ubuntu 22.04/24.04 server with root privileges.


## Runtime Layout (on target host)

- Domain configs: `/etc/nginx/conf.d/domains/*.conf`
- Shared includes: `/etc/nginx/conf.d/common/*.conf`
- Certs: `/etc/ssl/clients/<domain>/<domain>.{crt,key}`
- ACME webroot: `/var/www/acme-webroot`


## Top‑Level Scripts

The repo ships three scripts. Each section explains what it does, what it creates/touches, required inputs, environment variables you can override, and example usage.


### 1) `domain-proxy-init.sh` — One‑time NGINX + ACME bootstrap and hardening

Purpose

- Idempotently prepares the host to serve multiple domains with HTTPS by default.
- Installs NGINX and required tools, writes shared include snippets, and hardens `nginx.conf`.
- Installs acme.sh for a dedicated renewal user, sets automated renewal, and prepares a least‑privilege deploy flow.
- Configures a catch‑all HTTP server that serves `/.well-known/acme-challenge/` for HTTP‑01 issuance.
- Enables the firewall profile for NGINX and validates/reloads the service.

What it creates/changes

- Packages: installs `nginx ufw dnsutils curl unzip gnupg2 socat cron acl`.
- Directories: creates `/etc/nginx/conf.d/{domains,common}` `/etc/nginx/backups` `/etc/ssl/clients` and `/var/www/{acme-webroot,error_pages}`.
- Common includes written to `/etc/nginx/conf.d/common/`:
  - `security-headers.conf`: sensible security headers.
  - `ssl-params.conf`: TLS settings (TLSv1.2/1.3, stapling, etc.).
  - `error-pages.conf`: standard error_page mappings (400–505) served from `/var/www/error_pages`.
    - HTML files generated: `400.html, 401.html, 403.html, 404.html, 405.html, 408.html, 410.html, 429.html, 451.html, 500.html, 501.html, 502.html, 503.html, 504.html, 505.html`.
  - `acme-challenge.conf`: serves `/.well-known/acme-challenge/` from the ACME webroot.
- Catch‑all ACME server: `/etc/nginx/conf.d/000-catch-all-wellknown.conf` listening on :80 (default_server) with rate limiting.
- Hardens `nginx.conf` (idempotent edits in the `http {}` block):
  - `server_tokens off;`
  - `limit_req_zone $binary_remote_addr zone=ratelimit_zone:10m rate=10r/s;`
  - `include /etc/nginx/conf.d/domains/*.conf;`
- ACME renewal user: creates `${RENEW_USER}` (default `acmebot`) with home at `${RENEW_HOME}` (default `/var/lib/acme`).
- Installs acme.sh under `${RENEW_HOME}/.acme.sh`, pins Let’s Encrypt, enables cron + auto‑upgrade.
- Prepares ACME webroot ACLs so `${RENEW_USER}` can write tokens while NGINX can read them.
- Installs a deploy helper at `${DEPLOY_HELPER}` (default `/usr/local/sbin/acme-deploy`) to atomically install certs/keys to `/etc/ssl/clients/<domain>/` and reload NGINX.
- Sudoers entry at `/etc/sudoers.d/${RENEW_USER}` allowing only the deploy helper via `NOPASSWD`.
- Enables UFW ‘Nginx Full’ profile; validates and reloads NGINX.

Inputs and environment overrides

- Run as root: `sudo ./domain-proxy-init.sh`
- Optional env vars:
  - `RENEW_USER` (default: `acmebot`)
  - `RENEW_HOME` (default: `/var/lib/acme`)
  - `DEFAULT_EMAIL` (used for acme.sh registration; default: `noreply@example.invalid`)
  - `DEPLOY_HELPER` (default: `/usr/local/sbin/acme-deploy`)

Usage

```
sudo ./domain-proxy-init.sh
# After it completes, verify:
sudo nginx -t && sudo systemctl reload nginx
```

Notes

- Safe to re‑run: the script is designed to be idempotent.
- Tested on Ubuntu 22.04 and 24.04. Other distros may work but aren’t targeted.


### 2) `domain-proxy-manager.sh` — Manage per‑domain reverse proxies, SSL sites, and redirects

Purpose

- Day‑to‑day domain operations after the one‑time init: add domains, issue TLS certs, and write NGINX server blocks.
- Supports reverse proxy backends, SSL‑only static sites, and path‑scoped redirects.
- Performs an HTTP‑01 preflight to ensure ACME tokens are reachable; falls back to DNS‑01 (Cloudflare) if configured.
- Maintains timestamped backups of each domain config and provides rollback.

What it does

- Ensures prerequisites from `domain-proxy-init.sh` exist (common includes and deploy helper).
- Issues/renews certs using acme.sh as the renewal user:
  - HTTP‑01 via the ACME webroot at `/var/www/acme-webroot` with a preflight token fetch through NGINX on `127.0.0.1` and `Host: <domain>`.
  - If HTTP‑01 fails and Cloudflare credentials are present (`CF_Token` or `CF_Key` + `CF_Email`), retries DNS‑01 via `dns_cf`.
  - Installs certs to `/etc/ssl/clients/<domain>/<domain>.{crt,key}` using the deploy helper, then reloads NGINX.
- Writes per‑domain server blocks to `/etc/nginx/conf.d/domains/<domain>.conf`:
  - Always provides an :80 server that serves ACME and redirects to HTTPS.
  - :443 server includes TLS params, security headers, error pages, and rate limiting.
  - Reverse proxy variant sets standard `proxy_set_header` values and HTTP/2.
  - SSL‑only variant serves static files from a webroot (`index.html` etc.).
- Adds path‑scoped redirect/proxy blocks inside the :443 server for `redirect` subcommand.
- Validates config (`nginx -t`) and reloads the service.

Backups and rollback

- Before writing a domain config, copies the existing file to `/etc/nginx/backups/<domain>.conf.bak.<timestamp>`.
- `rollback <domain>` restores the latest backup and reloads NGINX.

Commands and examples

```
# Reverse proxy a domain to an internal service
sudo ./domain-proxy-manager.sh add example.com https://127.0.0.1:8080

# SSL-only static site (serve files from a webroot)
# SSL-only static site (serve files from a webroot)
sudo ./domain-proxy-manager.sh ssl example.com /var/www/html/example
# Alias for static site
sudo ./domain-proxy-manager.sh site example.com /var/www/html/example

# Add a path redirect/proxy under an existing domain config
sudo ./domain-proxy-manager.sh redirect example.com /old https://target.tld/new

# List configured domains, check cert presence
sudo ./domain-proxy-manager.sh list

# Validate and reload NGINX manually
sudo ./domain-proxy-manager.sh reload

# Roll back the last config for a domain
sudo ./domain-proxy-manager.sh rollback example.com
```

Required inputs and validation

- Must run as root.
- Validates domain syntax and DNS A/AAAA resolution before attempting issuance.
- Validates URL and paths for `add`/`redirect` subcommands.

Environment

- Uses the same environment model as init:
  - `RENEW_USER` (default: `acmebot`), `RENEW_HOME` (default: `/var/lib/acme`)
  - `DEPLOY_HELPER` (default: `/usr/local/sbin/acme-deploy`)
- For DNS‑01 with Cloudflare, export either:
  - `CF_Token` (preferred), or
  - `CF_Key` and `CF_Email`


### 3) `bootstrap_acme_renewal_user.sh` — Standalone ACME renewal user + deploy flow

Purpose

- Advanced, focused bootstrap for certificate management only. It:
  - Creates a dedicated, least‑privilege renewal user and installs acme.sh under that account.
  - Prepares webroot ACLs so the renewal user writes ACME tokens while NGINX reads them.
  - Performs a strict HTTP‑01 preflight against `127.0.0.1` with a `Host: <FQDN>` header.
  - Installs a root‑owned deploy helper and a constrained sudoers rule to deploy certs atomically to `/etc/ssl/clients/<FQDN>/` and reload NGINX.
  - Issues an initial certificate and triggers the first deploy.
  - Configures auto‑upgrade + cron under the renewal user.

What it creates/changes

- System user `${RENEW_USER}` (default `acmebot`) with home `${RENEW_HOME}` (default `/var/lib/acme`).
- Installs acme.sh as `${RENEW_USER}`, registers account with the provided email, sets Let’s Encrypt as default CA.
- Webroot ACLs on `${WEBROOT}/.well-known/acme-challenge` granting `${RENEW_USER}` rwx and `www-data` r‑x.
- Deploy helper `${DEPLOY_HELPER}` (default `/usr/local/sbin/acme-deploy`) and sudoers entry allowing only that helper via `NOPASSWD`.
- Certificates deployed to `${TARGET_BASE}/${FQDN}/${FQDN}.{crt,key}` (default base `/etc/ssl/clients`).

Usage

```
# Non-interactive: pass FQDN and email
sudo ./bootstrap_acme_renewal_user.sh example.com admin@example.com

# Interactive: omit args and you’ll be prompted
sudo ./bootstrap_acme_renewal_user.sh
```

Environment overrides

- `RENEW_USER` (default: `acmebot`) and `RENEW_HOME` (default: `/var/lib/acme`)
- `WEBROOT` (default: `/var/www/html`) — the HTTP‑01 path must be reachable at `http://<FQDN>/.well-known/acme-challenge/...`
- `TARGET_BASE` (default: `/etc/ssl/clients`) — where certs/keys are deployed
- `DEPLOY_HELPER` (default: `/usr/local/sbin/acme-deploy`) and `NGINX_RELOAD_CMD` (default: `/bin/systemctl reload nginx`)
- `KEY_ALGO` (`ec-256` default or `rsa-2048`)
- `DEFAULT_EMAIL` (default: `noreply@systemsalt.com`)

Outputs

- Prints a concise summary with user, paths, deployment locations, and how to verify cron.


## Verifying Your Setup

- Validate config and reload:
  - `sudo nginx -t`
  - `sudo systemctl reload nginx`
- Confirm acme.sh account and issued certs:
  - `sudo -u acmebot -H /var/lib/acme/.acme.sh/acme.sh --list`
- Check logs for a domain:
  - `/var/log/nginx/<domain>.access.log`
  - `/var/log/nginx/<domain>.error.log`


## Development

- Lint: `shellcheck *.sh`
- Optional format: `shfmt -i 4 -ci -sr -w .`


## Security Notes

- These scripts require root and modify firewall, NGINX, and ACME settings—use on controlled hosts only.
- For DNS‑01, export `CF_Token` (preferred) or `CF_Key` and `CF_Email` before running manager commands.
- Never commit real certs, keys, or secrets. Provide them via environment variables at runtime.
