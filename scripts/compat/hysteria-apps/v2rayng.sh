#!/usr/bin/env bash
# v2rayNG on an Android emulator against a Hysteria target
# (docs/client-compatibility.md § "Hysteria in real apps"). Runs inside
# reactivecircus/android-emulator-runner, with adb on PATH and one emulator.
#
#   v2rayng.sh <apk> <base URL of the raw configs, as the emulator reaches it>
#
# The base URL serves `good`, `wrongpin` and `rogue` (fixture.ts). The app takes
# each through its own importer (`v2rayng://install-sub`), the `· UDP` entry is
# chosen and connected from the app's own screen, and every check is a page
# fetched through the app's own listener: through the node when it should work,
# nothing when the pin is wrong or UDP to the node is dropped. The results go to
# test-results/compat/hysteria-apps/v2rayng/result.json (booleans only).
set -uo pipefail
APK=${1:?apk}
BASE=${2:?base URL}
PKG=com.v2ray.ang
OUT=test-results/compat/hysteria-apps/v2rayng
DIR=$(cd "$(dirname "$0")" && pwd)
FIXTURE=(bun --no-env-file "$DIR/fixture.ts")
mkdir -p "$OUT"
step=0

snap() { # snap <name>: a screenshot and a UI dump of fixture data only
  step=$((step + 1))
  local name
  name=$(printf '%02d-%s' "$step" "$1")
  adb exec-out screencap -p >"$OUT/$name.png" 2>/dev/null || true
  adb shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1 &&
    adb pull /sdcard/ui.xml "$OUT/$name.xml" >/dev/null 2>&1
  cp "$OUT/$name.xml" "$OUT/last.xml" 2>/dev/null || true
}
tap_text() { # tap_text <regex>
  local at
  at=$(python3 "$DIR/ui.py" "$OUT/last.xml" text "$1") || return 1
  # shellcheck disable=SC2086
  adb shell input tap $at
}
tap_id() {
  local at
  at=$(python3 "$DIR/ui.py" "$OUT/last.xml" id "$1") || return 1
  # shellcheck disable=SC2086
  adb shell input tap $at
}
nonce() { cat /proc/sys/kernel/random/uuid; }
fetch() { # fetch: 0 when the page answered through the app's listener
  local n
  n=$(nonce)
  [ "$(curl --silent --max-time 10 --socks5-hostname 127.0.0.1:10808 "http://10.89.73.20:8080/$n")" = "reality-page /$n" ]
}
fetch_until() { # fetch_until <seconds>
  local end=$((SECONDS + $1))
  until fetch; do ((SECONDS > end)) && return 1; sleep 2; done
}
carried() { "${FIXTURE[@]}" carried "$1"; }
import() { # import <name>
  adb shell am start -a android.intent.action.VIEW -p "$PKG" \
    -d "'v2rayng://install-sub?url=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$BASE/$1")'" >/dev/null
  sleep 8
}
stop_app_vpn() {
  adb shell am force-stop "$PKG"
  sleep 2
}
connect_udp() { # select the `· UDP` entry on the screen and press start
  snap list
  tap_text '· UDP$' || { echo 'no · UDP entry on screen'; return 1; }
  sleep 1
  snap selected
  tap_id "$PKG:id/fab" || { echo 'no start button'; return 1; }
  sleep 6
  snap connected
}
declare -A result

adb install -r "$APK" >/dev/null
adb shell appops set "$PKG" ACTIVATE_VPN allow
adb forward tcp:10808 tcp:10808 >/dev/null
adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 6
snap first-run

# 1. Import the raw config; both entries show.
import good
snap imported
python3 "$DIR/ui.py" "$OUT/last.xml" texts >"$OUT/imported-texts.txt"
if grep -q '· UDP$' "$OUT/imported-texts.txt" && grep -q '· Direct$' "$OUT/imported-texts.txt"; then
  result[rawImport]=true
else
  result[rawImport]=false
fi

# 2. Connect through `· UDP`: a page answers, and the node carried it.
before=$(carried node)
result[udp]=false
if connect_udp && fetch_until 45 && [ "$(carried node)" -gt "$before" ]; then
  # 3. UDP to the node dropped: nothing answers.
  sudo iptables -t raw -I OUTPUT -p udp -d 127.0.0.1 --dport 8443 -j DROP
  stop_app_vpn
  adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
  sleep 4
  connect_udp
  if ! fetch && ! fetch && ! fetch; then result[udp]=true; fi
  sudo iptables -t raw -D OUTPUT -p udp -d 127.0.0.1 --dport 8443 -j DROP
fi
stop_app_vpn

# 4. One character of the pin changed: refused.
import wrongpin
before=$(carried node)
connect_udp
if ! fetch && ! fetch && ! fetch && [ "$(carried node)" -eq "$before" ]; then
  result[wrongPinRefused]=true
else
  result[wrongPinRefused]=false
fi
stop_app_vpn

# 5. The node's pin, the rogue's address: refused, and the rogue got nothing.
import rogue
connect_udp
if ! fetch && ! fetch && ! fetch && [ "$(carried rogue)" -eq 0 ]; then
  result[rogueRefused]=true
else
  result[rogueRefused]=false
fi
stop_app_vpn

version=$(adb shell dumpsys package "$PKG" | sed -n 's/.*versionName=\([^ ]*\).*/\1/p' | head -1 | tr -d '\r')
python3 - "$OUT/result.json" "$version" "${result[rawImport]}" "${result[udp]}" \
  "${result[wrongPinRefused]}" "${result[rogueRefused]}" <<'PY'
import json, sys
out, version, *flags = sys.argv[1:]
keys = ['rawImport', 'udp', 'wrongPinRefused', 'rogueRefused']
r = {'client': 'v2rayNG', 'appVersion': version, **{k: f == 'true' for k, f in zip(keys, flags)}}
json.dump(r, open(out, 'w'), indent=2)
print(json.dumps(r))
sys.exit(0 if all(r[k] for k in keys) else 1)
PY
