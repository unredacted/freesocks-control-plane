#!/usr/bin/env bash
# In-stack deploy: read the admin key the keygen service wrote, push the Convex
# functions, apply the deployment env from .env.convex, then seed. Idempotent,
# so it is safe to re-run on every `up`. Runs as a one-shot service that exits 0
# on success (check `docker compose ... logs deployer`).
set -euo pipefail

KEY_FILE="${KEY_FILE:-/keys/admin_key}"
CONVEX_ENV_FILE="${CONVEX_ENV_FILE:-/run/convex.env}"
export CONVEX_SELF_HOSTED_URL="${CONVEX_SELF_HOSTED_URL:-http://backend:3210}"

echo "[deploy] reading admin key from ${KEY_FILE}"
admin_key=""
for _ in $(seq 1 30); do
  if [ -s "${KEY_FILE}" ]; then
    # The key line is `<instance>|<hex>`; ignore the "Admin key:" banner line.
    admin_key="$(grep '|' "${KEY_FILE}" | tail -n1 | tr -d '[:space:]')"
    [ -n "${admin_key}" ] && break
  fi
  sleep 1
done
if [ -z "${admin_key}" ]; then
  echo "[deploy] ERROR: no admin key in ${KEY_FILE} (did keygen run?)" >&2
  exit 1
fi
export CONVEX_SELF_HOSTED_ADMIN_KEY="${admin_key}"

# A4: a lightweight gate so a type-broken checkout can't deploy on the host.
# (`convex deploy` typechecks convex/ too; this also covers the client + shared
# contracts. The full suite — typecheck + test + lint + build — is the CI gate in
# .github/workflows/ci.yml; not repeated here to keep restarts quick.)
# Set DEPLOY_SKIP_TYPECHECK=true to bypass in an emergency.
if [ "${DEPLOY_SKIP_TYPECHECK:-false}" != "true" ]; then
  echo "[deploy] typechecking before deploy"
  bun run typecheck
fi

echo "[deploy] pushing functions to ${CONVEX_SELF_HOSTED_URL}"
bunx convex deploy -y

if [ -f "${CONVEX_ENV_FILE}" ]; then
  echo "[deploy] applying deployment env from ${CONVEX_ENV_FILE}"
  while IFS= read -r line || [ -n "${line}" ]; do
    case "${line}" in '' | \#*) continue ;; esac
    key="${line%%=*}"
    val="${line#*=}"
    [ "${key}" = "${line}" ] && continue # line had no '='
    val="${val%\"}"
    val="${val#\"}" # strip optional surrounding double quotes
    case "${val}" in *CHANGE_ME*)
      echo "[deploy] ERROR: ${key} still has a CHANGE_ME placeholder; fill .env.convex" >&2
      exit 1
      ;;
    esac
    bunx convex env set "${key}" "${val}" >/dev/null
    echo "[deploy]   env set ${key}"
  done <"${CONVEX_ENV_FILE}"
else
  echo "[deploy] WARNING: ${CONVEX_ENV_FILE} not found; skipping env (create .env.convex)"
fi

echo "[deploy] seeding tiers + settings (+ Remnawave instance if REMNAWAVE_* is set)"
bunx convex run seed:seedCutover '{}'

# One-time migration of the paid 'member' tier to the unlimited FreeSocks
# Membership (the billing flow's target). Guarded: a no-op once the row is
# already unlimited, so it's safe on every deploy and won't clobber admin edits.
echo "[deploy] reconfiguring the membership tier (no-op if already unlimited)"
bunx convex run seed:reconfigureMembershipTier '{}'

echo "[deploy] OK"
