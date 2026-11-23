#!/usr/bin/env bash
# v2rayN (Linux, Avalonia) in a virtual X display against a Hysteria target
# (docs/client-compatibility.md § "Hysteria in real apps").
#
#   v2rayn.sh <deb> <base URL of the raw configs>
#
# The package is installed with apt the way a user installs it. Each raw config
# (`good`, `wrongpin`, `rogue`, fixture.ts) is added as the app's subscription
# and fetched and parsed by the app's own updater; the `· UDP` server is made
# the active one and the app started, and every check is a page fetched through
# the app's own listener. Results: test-results/compat/hysteria-apps/v2rayn/
# result.json (booleans only).
set -uo pipefail
DEB=${1:?deb}
BASE=${2:?base URL}
OUT=test-results/compat/hysteria-apps/v2rayn
DIR=$(cd "$(dirname "$0")" && pwd)
FIXTURE=(bun --no-env-file "$DIR/fixture.ts")
export V2RAYN_LOCAL_APPLICATION_DATA_V2=1
DATA="$HOME/.local/share/v2rayN"
# .NET answers an empty path for a folder that does not exist yet.
mkdir -p "$HOME/.local/share"
export DISPLAY=:99
mkdir -p "$OUT"
step=0
APP_PID=

snap() {
  step=$((step + 1))
  import -window root "$OUT/$(printf '%02d-%s' "$step" "$1").png" 2>/dev/null || true
}
db() { python3 "$DIR/v2rayn_db.py" "$DATA" "$@"; }
nonce() { cat /proc/sys/kernel/random/uuid; }
fetch() {
  local n
  n=$(nonce)
  [ "$(curl --silent --max-time 10 --socks5-hostname 127.0.0.1:10808 "http://10.89.73.20:8080/$n")" = "reality-page /$n" ]
}
fetch_until() {
  local end=$((SECONDS + $1))
  until fetch; do ((SECONDS > end)) && return 1; sleep 2; done
}
carried() { "${FIXTURE[@]}" carried "$1"; }
start_app() {
  /usr/bin/v2rayn >>"$OUT/app.log" 2>&1 </dev/null &
  APP_PID=$!
}
stop_app() {
  pkill -f /opt/v2rayN/v2rayN || true
  pkill -x xray || true
  pkill -x sing-box || true
  sleep 3
}
wait_for() { # wait_for <seconds> <command...>
  local end=$((SECONDS + $1))
  shift
  until "$@" >/dev/null 2>&1; do ((SECONDS > end)) && return 1; sleep 2; done
}
has_profiles() { [ "$(db profiles | wc -l)" -ge 1 ]; }
# Fetch one raw config through the app's updater, then make `· UDP` active and start.
use() { # use <name>
  stop_app
  db sub "$BASE/$1"
  start_app
  wait_for 150 has_profiles || { echo "v2rayN never fetched $1"; snap "no-fetch-$1"; return 1; }
  db profiles >"$OUT/profiles-$1.txt"
  stop_app
  db select '· UDP$' || { echo "no · UDP server in $1"; return 1; }
  start_app
  sleep 12
  snap "running-$1"
}
declare -A result

sudo apt-get install -y -qq "$PWD/$DEB" >/dev/null
Xvfb :99 -screen 0 1280x800x24 >/dev/null 2>&1 </dev/null &
sleep 2
start_app
wait_for 90 test -f "$DATA/guiConfigs/guiNDB.db" || { echo 'v2rayN made no data dir'; snap no-data; exit 1; }
sleep 8
snap first-run
stop_app
db schema >"$OUT/schema.txt"
db config-keys >"$OUT/config-keys.txt"

result[rawImport]=false
result[udp]=false
if use good; then
  grep -q '· UDP$' "$OUT/profiles-good.txt" && grep -q '· Direct$' "$OUT/profiles-good.txt" &&
    result[rawImport]=true
  before=$(carried node)
  if fetch_until 45 && [ "$(carried node)" -gt "$before" ]; then
    sudo iptables -t raw -I OUTPUT -p udp -d 127.0.0.1 --dport 8443 -j DROP
    stop_app
    start_app
    sleep 12
    if ! fetch && ! fetch && ! fetch; then result[udp]=true; fi
    sudo iptables -t raw -D OUTPUT -p udp -d 127.0.0.1 --dport 8443 -j DROP
  fi
fi

result[wrongPinRefused]=false
if use wrongpin; then
  before=$(carried node)
  if ! fetch && ! fetch && ! fetch && [ "$(carried node)" -eq "$before" ]; then
    result[wrongPinRefused]=true
  fi
fi

result[rogueRefused]=false
if use rogue; then
  if ! fetch && ! fetch && ! fetch && [ "$(carried rogue)" -eq 0 ]; then
    result[rogueRefused]=true
  fi
fi
stop_app
# The core v2rayN ran for the Hysteria server, from its own log (no config is kept).
grep -o -E '(Xray|sing-box) [0-9.]+' "$OUT/app.log" | sort -u >"$OUT/cores.txt" || true

python3 - "$OUT/result.json" "$(dpkg-query -W -f '${Version}' v2rayn)" "${result[rawImport]}" \
  "${result[udp]}" "${result[wrongPinRefused]}" "${result[rogueRefused]}" <<'PY'
import json, sys
out, version, *flags = sys.argv[1:]
keys = ['rawImport', 'udp', 'wrongPinRefused', 'rogueRefused']
r = {'client': 'v2rayN', 'appVersion': version, **{k: f == 'true' for k, f in zip(keys, flags)}}
json.dump(r, open(out, 'w'), indent=2)
print(json.dumps(r))
sys.exit(0 if all(r[k] for k in keys) else 1)
PY
