#!/usr/bin/env bash
# In-stack deploy: read the admin key the keygen service wrote, push the Convex
# functions, apply the deployment env from .env.convex, auto-generate any missing
# random secrets, then seed. Idempotent, so it is safe to re-run on every `up`.
# Runs as a one-shot service that exits 0 on success (check
# `docker compose ... logs deployer`).
set -euo pipefail

KEY_FILE="${KEY_FILE:-/keys/admin_key}"
CONVEX_ENV_FILE="${CONVEX_ENV_FILE:-/run/convex.env}"
export CONVEX_SELF_HOSTED_URL="${CONVEX_SELF_HOSTED_URL:-http://backend:3210}"

# Pure-random secrets with no external dependency: the deployer generates these
# ONCE (see the auto-gen pass below) so a fresh deploy needs no manual
# `openssl rand` + paste. Everything else (CAP_*, REMNAWAVE_*, processor keys) is
# an external credential and must be supplied — a CHANGE_ME for those still errors.
AUTO_GEN_SECRETS="SESSION_SIGNING_KEY ADMIN_SESSION_SIGNING_KEY ADMIN_BOOTSTRAP_SECRET IP_HASH_SALT ACCOUNT_ID_PEPPER"

rand_hex32() {
  bun -e 'process.stdout.write([...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, "0")).join(""))'
}
is_auto_gen() {
  case " ${AUTO_GEN_SECRETS} " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

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

# A4: a fast convex-only type gate so a type-broken checkout can't deploy. Scoped
# to convex/ ON PURPOSE: the full monorepo `bun run typecheck` (tsc -b + svelte-check)
# is memory-hungry and OOM-killed the deployer (exit 137) before it could deploy. The
# client + shared contracts are ALREADY gated in this same `up` by the web image build
# (`bun run build` = tsc -b + vite; a type error there fails the build and aborts the
# up) and by CI (.github/workflows/ci.yml). `convex deploy` below also typechecks
# convex/, so this is belt-and-suspenders — clear errors before the (slower) deploy.
# Set DEPLOY_SKIP_TYPECHECK=true to bypass in an emergency.
if [ "${DEPLOY_SKIP_TYPECHECK:-false}" != "true" ]; then
  echo "[deploy] typechecking convex/ before deploy"
  bunx tsc -p convex/tsconfig.json --noEmit
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
      # An auto-generatable secret left as a placeholder is fine — the pass below
      # fills it. Any other CHANGE_ME is a real external credential and must be set.
      if is_auto_gen "${key}"; then
        continue
      fi
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

# Auto-generate the pure-random secrets that are still unset. GENERATE-ONCE: only
# set a secret the deployment doesn't already have — NEVER regenerate (rotating
# ACCOUNT_ID_PEPPER would invalidate every account number; SESSION_SIGNING_KEY,
# every session). A real value set from .env.convex above is already present, so
# it's left untouched. Skipped entirely if the env list can't be read (so a
# transient failure can't trigger a destructive regenerate).
echo "[deploy] ensuring auto-generated secrets exist"
if existing_env="$(bunx convex env list 2>/dev/null)"; then
  for name in ${AUTO_GEN_SECRETS}; do
    if printf '%s\n' "${existing_env}" | grep -q "^${name}="; then
      continue # already set — persisted in the deployment; leave it
    fi
    bunx convex env set "${name}" "$(rand_hex32)" >/dev/null
    echo "[deploy]   generated ${name}"
    if [ "${name}" = "ADMIN_BOOTSTRAP_SECRET" ]; then
      echo "[deploy]   -> retrieve with: bunx convex env get ADMIN_BOOTSTRAP_SECRET (for the first admin passkey)"
    fi
  done
else
  echo "[deploy] WARNING: could not list deployment env; skipping secret auto-generation" >&2
fi

echo "[deploy] seeding tiers + settings (+ Remnawave instance if REMNAWAVE_* is set)"
bunx convex run seed:seedCutover '{}'

# One-time migration of the paid 'member' tier to the unlimited FreeSocks
# Membership (the billing flow's target). Guarded: a no-op once the row is
# already unlimited, so it's safe on every deploy and won't clobber admin edits.
echo "[deploy] reconfiguring the membership tier (no-op if already unlimited)"
bunx convex run seed:reconfigureMembershipTier '{}'

echo "[deploy] OK"
