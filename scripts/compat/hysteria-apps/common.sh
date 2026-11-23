# Shared by the Hysteria app drivers (v2rayng.sh, v2rayn.sh); sourced, not run.
#
# The target (fixture.ts `up` or `beta`) is in .cache/compat/hysteria-apps/
# target.env: where the app imports each raw config from, and the node's UDP
# endpoint. In beta mode the URLs and names are secret: nothing here prints
# them.
#
#   HY_KIND          fixture | beta
#   HY_GOOD_URL      the raw config a member gets (beta: the canary key itself)
#   HY_WRONGPIN_URL  the same, one character of the · UDP entry's pin changed
#   HY_ROGUE_URL     the · UDP entry with the node's pin, at the local rogue
#   HY_NODE_IP       the node's address (the runner's view), for dropping UDP
#   HY_NODE_PORT     its Hysteria port
# names.txt beside it: every entry name of the good raw config, one per line.
HY_WORK=.cache/compat/hysteria-apps
# shellcheck disable=SC1091
. "$HY_WORK/target.env"
export HY_KIND
HY_NAMES="$HY_WORK/names.txt"
HY_FIXTURE=(bun --no-env-file "$(dirname "${BASH_SOURCE[0]}")/fixture.ts")
LISTENER=127.0.0.1:10808
# The runner's own address, to tell a request that went through the node.
HY_DIRECT_IP=
if [ "$HY_KIND" = beta ]; then
  HY_DIRECT_IP=$(curl --silent --max-time 15 https://api.ipify.org || true)
  [ -n "$HY_DIRECT_IP" ] || { echo 'could not read the runner address' >&2; exit 1; }
fi

# through: 0 when a request made through the app's listener went through the
# node. Fixture: the page only the servers reach answers (and the node logs it,
# carried_more). Beta: an HTTPS page, its name resolved at the far end, sees an
# address that is not the runner's.
through() {
  if [ "$HY_KIND" = beta ]; then
    local ip
    ip=$(curl --silent --max-time 15 --socks5-hostname "$LISTENER" https://api.ipify.org) || return 1
    [ -n "$ip" ] && [ "$ip" != "$HY_DIRECT_IP" ]
  else
    local n
    n=$(cat /proc/sys/kernel/random/uuid)
    # A name, not the page's address: the apps' default routing sends a
    # private address straight out. The servers redirect it to the page.
    [ "$(curl --silent --max-time 10 --socks5-hostname "$LISTENER" "http://hysteria-check.example/$n")" = "reality-page /$n" ]
  fi
}
through_until() { # through_until <seconds>
  local end=$((SECONDS + $1))
  until through; do ((SECONDS > end)) && return 1; sleep 2; done
}
# never: three tries, none through.
never() { ! through && ! through && ! through; }
# carried <node|rogue>: requests that server carried for the member. The beta
# node's log is not ours to read: there it is always 0 for the node.
carried() {
  if [ "$1" = node ] && [ "$HY_KIND" = beta ]; then echo 0; else "${HY_FIXTURE[@]}" carried "$1"; fi
}
# carried_more <before>: the node logged more since (always true on beta,
# where `through` proves the path by the address instead).
carried_more() { [ "$HY_KIND" = beta ] || [ "$(carried node)" -gt "$1" ]; }
# UDP from this runner to the node, dropped before any address rewrite (the
# fixture's published port is rewritten by Docker after `raw`).
drop_udp() { sudo iptables -t raw -I OUTPUT -p udp -d "$HY_NODE_IP" --dport "$HY_NODE_PORT" -j DROP; }
allow_udp() { sudo iptables -t raw -D OUTPUT -p udp -d "$HY_NODE_IP" --dport "$HY_NODE_PORT" -j DROP; }
# has_all_names <file>: every entry name of the raw config is in <file>.
has_all_names() {
  python3 - "$HY_NAMES" "$1" <<'PY'
import sys
want = [l.rstrip('\n') for l in open(sys.argv[1]) if l.strip()]
have = {l.rstrip('\n') for l in open(sys.argv[2])}
sys.exit(0 if want and all(n in have for n in want) else 1)
PY
}
# same_names <file>: exactly the raw config's entry names (as a multiset).
same_names() {
  python3 - "$HY_NAMES" "$1" <<'PY'
import sys
a = sorted(l.rstrip('\n') for l in open(sys.argv[1]) if l.strip())
b = sorted(l.rstrip('\n') for l in open(sys.argv[2]) if l.strip())
sys.exit(0 if a and a == b else 1)
PY
}
# write_result <out> <client> <version> key=true|false ...: booleans only;
# exits 1 unless every check passed.
write_result() {
  python3 - "$@" <<'PY'
import json, sys
out, client, version, *pairs = sys.argv[1:]
checks = {k: v == 'true' for k, v in (p.split('=', 1) for p in pairs)}
import os
r = {'client': client, 'appVersion': version, 'target': os.environ.get('HY_KIND', ''), 'checks': checks}
json.dump(r, open(out, 'w'), indent=2)
print(json.dumps(r))
sys.exit(0 if all(checks.values()) else 1)
PY
}
