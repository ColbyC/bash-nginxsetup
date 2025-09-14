# Repository Guidelines

## Project Structure & Module Organization
- Top-level scripts: `domain-proxy-init.sh` (provisions NGINX + acme.sh) and `domain-proxy-manager.sh` (manages per-domain configs).
- Example NGINX snippet: `catch-all-wellknown.conf`.
- Runtime paths (created/used on target host):
  - Domain configs: `/etc/nginx/conf.d/domains/*.conf`
  - Shared includes: `/etc/nginx/conf.d/common/*.conf`
  - Certs: `/etc/ssl/clients/<domain>/<domain>.{crt,key}`
  - ACME webroot: `/var/www/acme-webroot`

## Build, Test, and Development Commands
- Run init (one-time hardening + setup):
  - `sudo ./domain-proxy-init.sh`
- Manage domains:
  - Add reverse proxy: `sudo ./domain-proxy-manager.sh add example.com https://127.0.0.1:8080`
  - SSL-only site: `sudo ./domain-proxy-manager.sh ssl example.com /var/www/html/example`
  - Add path redirect: `sudo ./domain-proxy-manager.sh redirect example.com /old https://target.tld/new`
  - List/reload/rollback: `sudo ./domain-proxy-manager.sh list|reload|rollback example.com`
- Lint shell scripts locally:
  - `shellcheck *.sh`
  - Optional format: `shfmt -i 4 -ci -sr -w .`

## Coding Style & Naming Conventions
- Bash scripts use `#!/bin/bash` and `set -euo pipefail`.
- Indentation: 4 spaces; lowercase `snake_case` for functions; constants in `UPPER_SNAKE_CASE`.
- Prefer `printf` over `echo -e` unless colorized output is needed.
- Validate inputs and fail fast with clear `[!]` messages.

## Testing Guidelines
- Smoke test on a disposable Ubuntu 24.04 VM.
- Verify: `nginx -t`, `systemctl reload nginx`, and certificate issuance via `~/.acme.sh/acme.sh --list`.
- If adding logic, consider Bats tests (`bats test/*.bats`) and mock `nginx`/`systemctl` in CI.

## Commit & Pull Request Guidelines
- Use Conventional Commits:
  - `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`, `test:`
- PR checklist:
  - Purpose and scope with sample command(s) and expected output.
  - Impacted paths (e.g., `/etc/nginx/conf.d/**`, cert layout).
  - Logs from `nginx -t` and example `list` output.
  - Backward compatibility notes and rollback steps.

## Security & Configuration Tips
- Scripts require root and modify firewall, NGINX, and ACME settings—run in controlled environments.
- For DNS challenge, export `CF_Token` (preferred) or `CF_Key` and `CF_Email` before running manager commands.
- Never commit real certs, keys, or secrets. Prefer `.env`/export at runtime.
