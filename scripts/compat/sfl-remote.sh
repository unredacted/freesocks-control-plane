#!/usr/bin/env bash
# The packaged-SFL driver run inside the desktop VM's own Xfce session
# (FCP_COMPAT_SFL_REMOTE for tests/compat/clients.integration.test.ts; the VM
# comes from scripts/compat/desktop-vm.sh). The subscription the harness serves
# on the runner's 127.0.0.1:4179 is forwarded to the VM's 127.0.0.1:4179, so the
# app fetches it exactly as it would locally. The driver gets the session's own
# environment (display, D-Bus, desktop), read from its xfce4-session process,
# never a made-up one: a missing session fails the run.
set -euo pipefail
: "${FCP_COMPAT_SUB_URL:?set by the harness}"
dir=$(dirname "$0")
vm_ssh() { "$dir/desktop-vm.sh" ssh "$@"; }

status=0
VM_SSH_OPTS='-R 4179:127.0.0.1:4179' "$dir/desktop-vm.sh" ssh \
  "FCP_COMPAT_SUB_URL='$FCP_COMPAT_SUB_URL' FCP_COMPAT_OS='${FCP_COMPAT_OS:-}' bash -s" <<'EOF' || status=$?
set -euo pipefail
pid=$(pgrep -u "$(id -u)" -x xfce4-session)
while IFS= read -r -d '' kv; do
  case "$kv" in
    DISPLAY=* | XAUTHORITY=* | DBUS_SESSION_BUS_ADDRESS=* | XDG_*=* | DESKTOP_SESSION=* | LANG=*) export "${kv?}" ;;
  esac
done <"/proc/$pid/environ"
case "${XDG_CURRENT_DESKTOP:-}" in *XFCE* | *Xfce*) ;; *) echo "not an Xfce session" >&2 && exit 1 ;; esac
test -n "${DISPLAY:-}"
cd ~/fcp
exec node .cache/compat/runtime/sfl.mjs
EOF
# Bring back the driver's result and screenshots (fixture data only).
mkdir -p test-results/compat
vm_ssh 'tar -C ~/fcp -cf - test-results/compat/sfl 2>/dev/null' | tar -xf - 2>/dev/null || true
exit "$status"
