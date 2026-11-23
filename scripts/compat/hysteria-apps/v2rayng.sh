#!/usr/bin/env bash
# v2rayNG on an Android emulator against a Hysteria target
# (docs/client-compatibility.md § "Hysteria in real apps"; the target is
# common.sh's target.env). Runs inside reactivecircus/android-emulator-runner,
# with adb on PATH and one emulator.
#
#   v2rayng.sh <apk>
#
# The app takes each raw config through its own importer
# (`v2rayng://install-sub`, which adds the subscription and fetches it), the
# `· UDP` entry is chosen and started from the app's own screen, and every
# check is a request through the app's own listener (forwarded to the runner).
# Results: test-results/compat/hysteria-apps/v2rayng/result.json (booleans
# only). Screens and the app's log are kept for the fixture only: on beta they
# show the node's name and address.
set -uo pipefail
APK=${1:?apk}
PKG=com.v2ray.ang
OUT=test-results/compat/hysteria-apps/v2rayng
DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
. "$DIR/common.sh"
mkdir -p "$OUT"
UI="$HY_WORK/ui.xml"
step=0

dump() { # the screen's elements, for finding things on it
  adb shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1 && adb pull /sdcard/ui.xml "$UI" >/dev/null 2>&1
}
snap() {
  dump
  [ "$HY_KIND" = fixture ] || return 0
  step=$((step + 1))
  local name
  name=$(printf '%02d-%s' "$step" "$1")
  adb exec-out screencap -p >"$OUT/$name.png" 2>/dev/null || true
  cp "$UI" "$OUT/$name.xml" 2>/dev/null || true
}
tap_at() { # shellcheck disable=SC2086
  adb shell input tap $1
}
find_text() { python3 "$DIR/ui.py" "$UI" text "$1"; }
tap_text() { local at; at=$(find_text "$1") && tap_at "$at"; }
tap_id() { local at; at=$(python3 "$DIR/ui.py" "$UI" id "$1") && tap_at "$at"; }
scroll_down() { adb shell input swipe 160 450 160 200 300; sleep 1; }
scroll_top() { for _ in 1 2 3 4 5 6; do adb shell input swipe 160 200 160 500 150; done; sleep 1; }
launch() {
  adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
  sleep 5
}
stop_app() {
  adb shell am force-stop "$PKG"
  sleep 2
}
# import_sub <url>: through the app's own scheme. The scheme screen closes at
# once and the fetch ends in the background, after the list on screen was
# loaded: the app is opened again.
import_sub() {
  local q
  q=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1")
  adb shell am start -a android.intent.action.VIEW -p "$PKG" -d "'v2rayng://install-sub?url=$q'" >/dev/null 2>&1
  sleep 12
  stop_app
  launch
}
# sub_tab: the list of the imported subscription (the app opens on its own
# `Default` group, which holds nothing here).
sub_tab() {
  dump
  tap_text '^import sub' || { echo 'no tab for the imported subscription'; return 1; }
  sleep 1
}
# names_on_screen <file>: every entry name in the list, scrolled top to bottom.
names_on_screen() {
  : >"$1"
  sub_tab
  scroll_top
  for _ in 1 2 3 4 5 6; do
    dump
    python3 "$DIR/ui.py" "$UI" texts >>"$1"
    scroll_down
  done
  scroll_top
}
# start_udp: the `· UDP` entry selected and started from the app's screen.
start_udp() {
  sub_tab || return 1
  scroll_top
  snap list
  local i
  for i in 1 2 3 4 5 6; do
    tap_text '· UDP$' && break
    ((i == 6)) && { echo 'no · UDP entry on screen'; return 1; }
    scroll_down
    dump
  done
  sleep 1
  snap selected
  # A Compose screen: the button has its label, not a resource id.
  dump
  tap_text '^Start service$' || { echo 'no start button'; return 1; }
  # The app's own listener, forwarded to the runner, up: a refusal below is
  # then the app's, not an app that never started.
  local end=$((SECONDS + 30))
  until bash -c 'exec 3<>/dev/tcp/127.0.0.1/10808' 2>/dev/null; do
    ((SECONDS > end)) && { echo 'the app never listened'; snap not-listening; return 1; }
    sleep 2
  done
  sleep 4
  snap started
}
# fresh: the app with no data, as installed (each raw config on its own, so a
# `· UDP` entry on screen is always the one just imported).
fresh() {
  adb shell pm clear "$PKG" >/dev/null
  adb shell appops set "$PKG" ACTIVATE_VPN allow
  adb shell pm grant "$PKG" android.permission.POST_NOTIFICATIONS 2>/dev/null || true
}
declare -A ok=([rawImport]=false [import]=false [connection]=false [udp]=false
  [refresh]=false [wrongPinRefused]=false [rogueRefused]=false)

adb install -r "$APK" >/dev/null
fresh
adb forward tcp:10808 tcp:10808 >/dev/null
if [ "$HY_KIND" = fixture ]; then
  adb logcat -c
  adb logcat -v time 'com.v2ray.ang:V' 'AndroidRuntime:E' '*:S' >"$OUT/logcat.txt" 2>&1 </dev/null &
fi
launch
snap first-run

# The raw config through the app's importer: every entry, `· UDP` and `· Direct`.
names="$HY_WORK/app-names.txt"
import_sub "$HY_GOOD_URL"
snap imported
names_on_screen "$names"
grep -q '· UDP$' "$names" && grep -q '· Direct$' "$names" && ok[rawImport]=true
has_all_names "$names" && ok[import]=true

before=$(carried node)
if start_udp && through_until 45 && carried_more "$before"; then
  ok[connection]=true
  # UDP to the node dropped: nothing gets through.
  drop_udp
  stop_app
  launch
  start_udp && never && ${ok[connection]} && ok[udp]=true
  allow_udp
fi
stop_app

# Refresh from the app's own menu: the same entries.
launch
dump
if tap_text '^More options$'; then
  sleep 1
  dump
  if tap_text '(?i)update subscription'; then
    sleep 12
    stop_app
    launch
    again="$HY_WORK/app-names-again.txt"
    names_on_screen "$again"
    has_all_names "$again" && ok[refresh]=true
  fi
fi
snap refreshed
stop_app

# One character of the pin changed: refused, and the node saw nothing for it.
fresh
launch
import_sub "$HY_WRONGPIN_URL"
before=$(carried node)
start_udp && never && [ "$(carried node)" -eq "$before" ] && ${ok[connection]} && ok[wrongPinRefused]=true
stop_app

# The node's pin at a rogue with another certificate: refused, and it got nothing.
fresh
launch
import_sub "$HY_ROGUE_URL"
start_udp && never && [ "$(carried rogue)" -eq 0 ] && ${ok[connection]} && ok[rogueRefused]=true
stop_app

version=$(adb shell dumpsys package "$PKG" | sed -n 's/.*versionName=\([^ ]*\).*/\1/p' | head -1 | tr -d '\r')
pairs=()
for k in rawImport import connection udp refresh wrongPinRefused rogueRefused; do pairs+=("$k=${ok[$k]}"); done
write_result "$OUT/result.json" v2rayNG "$version" "${pairs[@]}"
