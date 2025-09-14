#!/usr/bin/env bash
# ====================================================================
# File: scripts/bootstrap_acme_renewal_user.sh
# Author: Colby Cail
# Date: 2025-09-13
# Summary: Provision dedicated ACME renewal user, install acme.sh,
#          enforce HTTP-01 webroot permissions with preflight checks,
#          issue certs, and deploy atomically to:
#          /etc/ssl/clients/<FQDN>/<FQDN>.{crt,key}
#          No Nginx config changes. Renewals via least-privilege cron.
# ====================================================================

set -euo pipefail

# ------------------------
# CONFIG (override via env)
# ------------------------
RENEW_USER="${RENEW_USER:-acmebot}"
RENEW_HOME="${RENEW_HOME:-/var/lib/acme}"
WEBROOT="${WEBROOT:-/var/www/html}"
TARGET_BASE="${TARGET_BASE:-/etc/ssl/clients}"
DEPLOY_HELPER="${DEPLOY_HELPER:-/usr/local/sbin/acme-deploy}"
NGINX_RELOAD_CMD="${NGINX_RELOAD_CMD:-/bin/systemctl reload nginx}"
KEY_ALGO="${KEY_ALGO:-ec-256}"          # ec-256 | rsa-2048
DEFAULT_EMAIL="${DEFAULT_EMAIL:-noreply@systemsalt.com}"
ACME_DEBUG="${ACME_DEBUG:-2}"            # 0..2

# Convenience
ACME_BIN="${RENEW_HOME}/.acme.sh/acme.sh"
ACCOUNT_CONF="${RENEW_HOME}/.acme.sh/account.conf"
SUDOERS_D="/etc/sudoers.d"
SUDOERS_FILE="${SUDOERS_D}/${RENEW_USER}"

# ------------------------
# Utilities
# ------------------------
prompt_for() { local l="$1" d="${2:-}"; local v; read -r -p "${l}${d:+ [${d}]}: " v || true; echo "${v:-$d}"; }

require_bin() {
  local b="$1" pkg="$2"
  if ! command -v "$b" >/dev/null 2>&1; then
    echo "[INFO] Installing ${pkg}..."
    sudo apt-get update -y && sudo apt-get install -y "$pkg"
  fi
}

fail() { echo "[ERROR] $*" >&2; exit 1; }

# ------------------------
# System Setup
# ------------------------
ensure_user() {
  local u="$1" h="$2"
  if ! id "$u" >/dev/null 2>&1; then
    sudo useradd --system --home "$h" --shell /usr/sbin/nologin "$u"
  fi
  sudo mkdir -p "$h"
  sudo chown -R "$u":"$u" "$h"
}

install_acme() {
  local u="$1" h="$2"
  if [[ ! -x "${h}/.acme.sh/acme.sh" ]]; then
    echo "[INFO] Installing acme.sh for ${u}..."
    sudo -u "$u" -H bash -lc 'cd "$HOME" && curl https://get.acme.sh | sh'
  else
    echo "[INFO] acme.sh already present for ${u}."
  fi
}

pin_ca_and_register() {
  local acme="$1" email="$2"
  sudo -u "$RENEW_USER" -H "$acme" --set-default-ca --server letsencrypt
  sudo -u "$RENEW_USER" -H "$acme" --register-account -m "$email" --server letsencrypt || true
}

ensure_cron() {
  sudo -u "$RENEW_USER" -H "$1" --upgrade --auto-upgrade
  sudo -u "$RENEW_USER" -H "$1" --install-cronjob
}

# ------------------------
# Webroot Permission Fixes + Preflight (no Nginx edits)
# ------------------------
prepare_webroot() {
  local wr="$1" u="$2"
  local well="${wr}/.well-known"
  local chal="${well}/acme-challenge"

  sudo mkdir -p "$chal"
  sudo chown -R "$u":www-data "$well"
  sudo chmod 750 "$well" "$chal"

  require_bin setfacl acl
  sudo setfacl -R  -m u:"$u":rwx    "$well"
  sudo setfacl -d  -m u:"$u":rwx    "$well"
  sudo setfacl -R  -m g:www-data:rx "$well"
  sudo setfacl -d  -m g:www-data:rx "$well"

  # Ensure traverse perms up the tree
  sudo chmod 755 "$wr" || true
  sudo chmod 755 "$(dirname "$wr")" || true
  sudo chmod 755 /var/www || true
  sudo chmod 755 /var || true
}

preflight_http01() {
  # Write as acmebot; fetch via nginx with Host header to localhost.
  local fqdn="$1" wr="$2"
  local testf=".preflight_$(date +%s)_$RANDOM"
  local path="${wr}/.well-known/acme-challenge/${testf}"

  echo "[INFO] Preflight: write token as ${RENEW_USER} -> ${path}"
  sudo -u "$RENEW_USER" -H bash -lc "echo PREPASS > '$path'" || fail "Write failed: ${path}"

  echo "[INFO] Preflight: read back via Nginx (Host: ${fqdn})"
  require_bin curl curl
  local out
  if ! out="$(curl -sS -H "Host: ${fqdn}" "http://127.0.0.1/.well-known/acme-challenge/${testf}")"; then
    sudo rm -f "$path" || true
    fail "HTTP GET failed. Ensure port 80 vhost for ${fqdn} serves ${WEBROOT} and does not block the ACME path."
  fi

  sudo rm -f "$path" || true
  [[ "$out" == "PREPASS" ]] || fail "Preflight content mismatch. Got: '$out' (expected PREPASS). Check rewrite/redirect rules."
  echo "[INFO] Preflight passed."
}

# ------------------------
# Deployment & Permissions
# ------------------------
write_deploy_helper() {
  local helper="$1"
  sudo tee "$helper" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
FQDN="${1:-}"; SRC_KEY="${2:-}"; SRC_CRT="${3:-}"
TARGET_BASE="${4:-/etc/ssl/clients}"
RELOAD_CMD="${5:-/bin/systemctl reload nginx}"
[ -z "$FQDN" ] && { echo "Usage: acme-deploy <fqdn> <src_key> <src_crt> [target_base] [reload_cmd]"; exit 2; }

DEST_DIR="${TARGET_BASE}/${FQDN}"
TMPDIR="$(mktemp -d /tmp/acme-deploy-XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

install -d -m 0750 -o root -g root "$TARGET_BASE"
install -d -m 0750 -o root -g root "$DEST_DIR"

# Stage with canonical filenames using FQDN, then atomically move
install -m 0640 -o root -g root "$SRC_KEY" "${TMPDIR}/${FQDN}.key"
install -m 0644 -o root -g root "$SRC_CRT" "${TMPDIR}/${FQDN}.crt"

mv -f "${TMPDIR}/${FQDN}.key" "${DEST_DIR}/${FQDN}.key"
mv -f "${TMPDIR}/${FQDN}.crt" "${DEST_DIR}/${FQDN}.crt"

$RELOAD_CMD
EOF
  sudo chmod 750 "$helper"
  sudo chown root:root "$helper"
}

lock_down_access() {
  : # No-op: using root:root on /etc/ssl/clients with 0640/0644
}

write_sudoers_rule() {
  local sf="$1" user="$2" helper="$3"
  local tmp="/tmp/${user}.sudoers.$$"
  cat > "$tmp" <<EOF
# Limited sudo for ${user}: allow only the deploy helper
${user} ALL=(root) NOPASSWD: ${helper}
Defaults:${user} !secure_path
EOF
  sudo visudo -cf "$tmp"
  sudo install -m 0440 -o root -g root "$tmp" "$sf"
  rm -f "$tmp"
}

# ------------------------
# Issuance & Install Mapping
# ------------------------
issue_and_install() {
  local fqdn="$1"
  local kargs=()
  case "$KEY_ALGO" in
    ec-256)   kargs=(--keylength ec-256 --ecc) ;;
    rsa-2048) kargs=(--keylength 2048) ;;
    *) fail "KEY_ALGO must be ec-256 or rsa-2048" ;;
  esac

  echo "[INFO] Issuing certificate for ${fqdn} via webroot ${WEBROOT} (${KEY_ALGO})"
  sudo -u "$RENEW_USER" -H "$ACME_BIN" --issue -d "$fqdn" -w "$WEBROOT" "${kargs[@]}" --server letsencrypt --debug ${ACME_DEBUG}

  local stash_dir="${RENEW_HOME}/deploy-stash/${fqdn}"
  sudo -u "$RENEW_USER" -H mkdir -p "$stash_dir"

  local install_args=( --install-cert -d "$fqdn"
                       --key-file       "${stash_dir}/key.pem"
                       --fullchain-file "${stash_dir}/full.pem"
                       --reloadcmd      "sudo ${DEPLOY_HELPER} ${fqdn} ${stash_dir}/key.pem ${stash_dir}/full.pem ${TARGET_BASE} '${NGINX_RELOAD_CMD}'" )
  if [[ "$KEY_ALGO" == "ec-256" ]]; then install_args+=( --ecc ); fi

  echo "[INFO] Installing mapping and triggering first deploy..."
  sudo -u "$RENEW_USER" -H "$ACME_BIN" "${install_args[@]}" --server letsencrypt --debug ${ACME_DEBUG}
}

# ------------------------
# Summary
# ------------------------
summarize() {
  local fqdn="$1"
  cat <<EOF
[SUCCESS] ACME bootstrap complete.

User & Storage:
  Renewal user:     ${RENEW_USER}  (home: ${RENEW_HOME})
  acme.sh binary:   ${ACME_BIN}
  Account file:     ${ACCOUNT_CONF}

Webroot (HTTP-01):
  ACME path:        ${WEBROOT}/.well-known/acme-challenge
  Ownership:        ${RENEW_USER}:www-data
  Perms/ACL:        dirs 750; default ACLs keep ${RENEW_USER} rwx and www-data r-x
  Preflight:        verified write/read via Nginx on 127.0.0.1 with Host ${fqdn}

Deployment (final):
  Cert path:        ${TARGET_BASE}/${fqdn}/${fqdn}.crt  (0644 root:root)
  Key path:         ${TARGET_BASE}/${fqdn}/${fqdn}.key  (0640 root:root)
  Deploy helper:    ${DEPLOY_HELPER} (root-owned; sudo NOPASSWD for ${RENEW_USER})

Renewals:
  Cron user:        ${RENEW_USER}
  Check cron:       sudo crontab -u ${RENEW_USER} -l | grep acme.sh
  Manual test:      sudo -u ${RENEW_USER} -H ${ACME_BIN} --cron
EOF
}

# ------------------------
# MAIN
# ------------------------
main() {
  local HOSTNAME="${1:-}"
  local EMAIL="${2:-}"

  if [[ -z "$HOSTNAME" ]]; then HOSTNAME="$(prompt_for "Hostname (FQDN)" "")"; fi
  if [[ -z "$EMAIL"   ]]; then EMAIL="$(prompt_for "Registration email" "$DEFAULT_EMAIL")"; fi
  [[ -n "$HOSTNAME" ]] || fail "Hostname is required."

  require_bin curl curl
  require_bin setfacl acl

  ensure_user "$RENEW_USER" "$RENEW_HOME"
  install_acme "$RENEW_USER" "$RENEW_HOME"
  pin_ca_and_register "$ACME_BIN" "$EMAIL"
  ensure_cron "$ACME_BIN"

  prepare_webroot "$WEBROOT" "$RENEW_USER"
  preflight_http01 "$HOSTNAME" "$WEBROOT"

  write_deploy_helper "$DEPLOY_HELPER"
  lock_down_access
  write_sudoers_rule "$SUDOERS_FILE" "$RENEW_USER" "$DEPLOY_HELPER"

  issue_and_install "$HOSTNAME"
  summarize "$HOSTNAME"
}

main "$@"
