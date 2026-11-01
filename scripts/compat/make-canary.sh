#!/usr/bin/env bash
# Creates the deployed-smoke canary (docs/client-compatibility.md "Deployed
# canaries") on a stack host, from the stack checkout:
#
#   bash scripts/compat/make-canary.sh <env file> <public origin> [tier slug]
#   e.g. bash scripts/compat/make-canary.sh .env.beta https://<the site's host>
#
# A test account, never a member's: created like a sign-up, moved to a tier with
# no traffic or device limit (default `member`, so the idle-free sweep never
# reclaims it) for ten years, its key issued into the default mode. Every secret
# (account number, subscription token) goes only to root-only files in
# /root/fcp-canary; nothing secret is printed. Hand the targets file to GitHub
# without displaying it:
#
#   ssh root@<stack host> cat /root/fcp-canary/smoke-targets.json |
#     gh secret set FCP_COMPAT_SMOKE_TARGETS --env client-compatibility
set -euo pipefail
ENV_FILE=${1:?env file, e.g. .env.beta}
ORIGIN=${2:?public origin members fetch subscriptions from, https://...}
TIER_SLUG=${3:-member}
DIR=${FCP_CANARY_DIR:-/root/fcp-canary}
# The target's name in the smoke results: the stack, from its env file.
NAME=$(basename "$ENV_FILE" | sed 's/^\.env\.//')
case "$ORIGIN" in https://*) ;; *) echo "the origin must be https://" >&2 && exit 2 ;; esac
if [ -e "$DIR/smoke-targets.json" ]; then
  echo "$DIR already holds a canary; refusing to make a second" >&2
  exit 1
fi
umask 077
mkdir -p "$DIR"

run() { # run <function> <json args>: the result on stdout, never echoed here
  docker compose -f docker-compose.stack.yml --env-file "$ENV_FILE" run --rm --no-deps -T \
    -e FN="$1" -e ARGS="$2" --entrypoint bash deployer -c \
    'export CONVEX_SELF_HOSTED_ADMIN_KEY="$(grep "|" /keys/admin_key | tail -n1 | tr -d "[:space:]")"; bunx convex run "$FN" "$ARGS"' \
    </dev/null 2>"$DIR/last.err"
}
field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$@"; }

run tiers:getBySlug "{\"slug\":\"$TIER_SLUG\"}" >"$DIR/tier.json"
TIER_ID=$(field "$DIR/tier.json" _id)
python3 - "$DIR/tier.json" <<'PY'
import json, sys
t = json.load(open(sys.argv[1]))
assert t["isActive"] and not t["isDefaultFree"], "pick an active, non-free tier"
assert t["monthlyTrafficGb"] == 0 and t["deviceLimit"] == 0 and not t.get("hwidEnabled"), \
    "the canary needs a tier with no traffic or device limit"
PY

run freeTier:createFreeAccount '{"ip":"compat-canary","requestId":"compat-canary-create"}' >"$DIR/create.json"
USER_ID=$(field "$DIR/create.json" userId)
field "$DIR/create.json" accountId >"$DIR/account-number"
rm -f "$DIR/create.json" # also held a session cookie nobody needs
echo "$USER_ID" >"$DIR/user-id"
echo "created test account $USER_ID"

run adminApi:grantMembership "{\"userId\":\"$USER_ID\",\"tierId\":\"$TIER_ID\",\"durationDays\":3650}" >/dev/null
echo "moved to tier $TIER_SLUG for 3650 days"
# The member-facing answer carries no URL: members build it from the token.
run account:regenerate "{\"userId\":\"$USER_ID\",\"requestId\":\"compat-canary-issue\"}" >/dev/null
run subscriptions:resolveCurrentOrActive "{\"userId\":\"$USER_ID\"}" >"$DIR/sub.json"
python3 - "$DIR/sub.json" "$ORIGIN" "$DIR/smoke-targets.json" "$NAME" <<'PY'
import json, sys
sub = json.load(open(sys.argv[1]))
token = sub.get("subToken")
assert token and sub["state"] == "active", "the key was not issued"
json.dump([{"name": sys.argv[4], "url": f"{sys.argv[2].rstrip('/')}/api/v1/sub/{token}"}],
          open(sys.argv[3], "w"))
PY
rm -f "$DIR/sub.json" "$DIR/tier.json" "$DIR/last.err"
echo "key issued; targets in $DIR/smoke-targets.json (secret: it holds the token)"
