#!/usr/bin/env bash
# v2rayN (Linux, Avalonia) in a virtual X display against a Hysteria target
# (docs/client-compatibility.md § "Hysteria in real apps"; the target is
# common.sh's target.env).
#
#   v2rayn.sh <deb>
#
# The package is installed with apt the way a user installs it. Each raw config
# is added as the app's subscription and fetched and parsed by the app's own
# updater (v2rayN has no URL scheme: the row its "Add subscription" dialog
# writes is written while it is stopped, due at once). The `· UDP` server is
# made the active one, as a click in its list does, and every check is a
# request through the app's own listener. Results:
# test-results/compat/hysteria-apps/v2rayn/result.json (booleans only).
set -uo pipefail
DEB=${1:?deb}
OUT=test-results/compat/hysteria-apps/v2rayn
DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
. "$DIR/common.sh"
export V2RAYN_LOCAL_APPLICATION_DATA_V2=1
DATA="$HOME/.local/share/v2rayN"
# .NET answers an empty path for a folder that does not exist yet.
mkdir -p "$HOME/.local/share"
export DISPLAY=:99
mkdir -p "$OUT"
step=0

snap() { # fixture only: a beta screen shows the node's name and address
  [ "$HY_KIND" = fixture ] || return 0
  step=$((step + 1))
  import -window root "$OUT/$(printf '%02d-%s' "$step" "$1").png" 2>/dev/null || true
}
db() { python3 "$DIR/v2rayn_db.py" "$DATA" "$@"; }
log() { if [ "$HY_KIND" = fixture ]; then cat >>"$OUT/app.log"; else cat >/dev/null; fi; }
start_app() {
  /usr/bin/v2rayn 2>&1 </dev/null | log &
}
stop_app() { # the app and the core it started, nothing else (the fixture's servers run Xray too)
  pkill -u "$(id -u)" -f '^/opt/v2rayN/' 2>/dev/null || true
  sleep 3
}
wait_for() { # wait_for <seconds> <command...>
  local end=$((SECONDS + $1))
  shift
  until "$@" >/dev/null 2>&1; do ((SECONDS > end)) && return 1; sleep 2; done
}
fetched_since() { [ "$(db updated)" != "$1" ] && [ "$(db profiles | wc -l)" -ge 1 ]; }
# fetch_sub <url> <names file>: the app's updater fetches the raw config.
fetch_sub() {
  stop_app
  db sub "$1"
  local was
  was=$(db updated)
  start_app
  wait_for 150 fetched_since "$was" || { echo 'v2rayN never fetched the raw config'; return 1; }
  db profiles >"$2"
}
# refresh_sub <names file>: the same subscription due again, its servers kept.
refresh_sub() {
  stop_app
  local was
  was=$(db updated)
  db due
  start_app
  wait_for 150 fetched_since "$was" || { echo 'v2rayN never refreshed the raw config'; return 1; }
  db profiles >"$1"
}
# run_udp: the `· UDP` server active, the app running.
run_udp() {
  stop_app
  db select '· UDP$' || { echo 'no · UDP server'; return 1; }
  start_app
  # The app's listener up, then a moment for the core behind it.
  wait_for 45 bash -c 'exec 3<>/dev/tcp/127.0.0.1/10808' || { echo 'no listener on 10808'; return 1; }
  sleep 6
  snap running
}
declare -A ok=([rawImport]=false [import]=false [connection]=false [udp]=false
  [refresh]=false [wrongPinRefused]=false [rogueRefused]=false)

sudo apt-get install -y -qq "$PWD/$DEB" >/dev/null
Xvfb :99 -screen 0 1280x800x24 >/dev/null 2>&1 </dev/null &
sleep 2
start_app
wait_for 90 test -f "$DATA/guiConfigs/guiNDB.db" || {
  echo 'v2rayN made no data folder'
  snap no-data
  exit 1
}
sleep 8
snap first-run
stop_app
[ "$HY_KIND" = fixture ] && db schema >"$OUT/schema.txt"

names="$HY_WORK/app-names.txt"
if fetch_sub "$HY_GOOD_URL" "$names"; then
  snap imported
  grep -q '· UDP$' "$names" && grep -q '· Direct$' "$names" && ok[rawImport]=true
  same_names "$names" && ok[import]=true
  before=$(carried node)
  if run_udp && through_until 45 && carried_more "$before"; then
    ok[connection]=true
    snap connected
    drop_udp
    run_udp
    never && ok[udp]=true
    allow_udp
  fi
  # Refresh: the app's updater again, same servers.
  again="$HY_WORK/app-names-again.txt"
  refresh_sub "$again" && same_names "$again" && ok[refresh]=true
fi

if fetch_sub "$HY_WRONGPIN_URL" "$HY_WORK/app-names-wrongpin.txt"; then
  before=$(carried node)
  run_udp && never && [ "$(carried node)" -eq "$before" ] && ok[wrongPinRefused]=true
fi

if fetch_sub "$HY_ROGUE_URL" "$HY_WORK/app-names-rogue.txt"; then
  run_udp && never && [ "$(carried rogue)" -eq 0 ] && ok[rogueRefused]=true
fi
stop_app
# The app's own logs, for a failed step (fixture data only).
[ "$HY_KIND" = fixture ] && cp -r "$DATA/guiLogs" "$OUT/guiLogs" 2>/dev/null

pairs=()
for k in rawImport import connection udp refresh wrongPinRefused rogueRefused; do pairs+=("$k=${ok[$k]}"); done
write_result "$OUT/result.json" v2rayN "$(dpkg-query -W -f '${Version}' v2rayn)" "${pairs[@]}"
