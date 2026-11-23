// @vitest-environment node
/**
 * Every `v.any()` in a Convex function's arguments, each with the reason.
 *
 * All of these functions are internal: only FCP's own code calls them, after
 * the HTTP layer has authenticated and parsed the request. A `v.any()` arg is
 * therefore not an open door, but it does skip the validator Convex would run
 * for free, so each one must say what checks the value instead. Prefer a real
 * validator: when a value lands in a typed schema field as is, import that
 * field's validator (see `edges.patchEdge` and lib/edges/reachabilityValidators.ts).
 * A new `v.any()` fails this test until it is listed here.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';

const CONVEX = fileURLToPath(new URL('.', import.meta.url));

const ADMIN_JSON =
  'an admin request body: the handler validates it field by field (or through the named resolver/sanitizer) before anything is stored';
const PROVIDER_SHAPE =
  'a provider-specific shape: the edge provider adapter parses and validates it (convex/lib/edges/providers/)';
const WEBAUTHN = 'a WebAuthn response: @simplewebauthn/server verifies it';
const SEALED = 'an HPKE envelope or its plaintext: the sealing layer opens and parses it';
const COMPUTED =
  'a value FCP computed in the calling action; what is stored goes into typed schema fields, which Convex validates on write';

const ALLOWED: Record<string, string> = {
  'adminApi:updateTier.features': `${ADMIN_JSON} (normalizeTierFeatures)`,
  'adminApi:setBillingConfig.patch': `${ADMIN_JSON} (resolveBillingConfig)`,
  'audit:record.payload': 'audit payload: filtered against AUDIT_PAYLOAD_ALLOWLIST (lib/audit.ts)',
  'backendWrites:previewProfilePatch.ops': `${ADMIN_JSON} (checkPatchOps)`,
  'censoredCountries:set.countries': `${ADMIN_JSON} (validateCensoredCountries)`,
  'connectionModes:setModePlacements.patch': `${ADMIN_JSON} (the placement resolver)`,
  'edgeAdmin:patchConfig.patch': ADMIN_JSON,
  'edgeDetector:recordEvaluation.evaluation': COMPUTED,
  'edgeLocations:create.placement': PROVIDER_SHAPE,
  'edgeLocations:create.regionalParams': PROVIDER_SHAPE,
  'edgeLocations:update.regionalParams': `${PROVIDER_SHAPE} (parseRegionalParams)`,
  'edgePlans:costOfPicks.options': PROVIDER_SHAPE,
  'edgeProviderAccounts:update.settings': `${ADMIN_JSON} (the account adapter's settings check)`,
  'edgeProviderAccounts:update.credentials': `${ADMIN_JSON} (the account adapter's credential check)`,
  'edgeProviderAccounts:update.optionDefaults': PROVIDER_SHAPE,
  'edgeProviderAccounts:applyCredentialRotation.credentials': `${PROVIDER_SHAPE} (validateSettings)`,
  'edgeProviderAccounts:applyCredentialRotation.settings': `${PROVIDER_SHAPE} (validateSettings)`,
  'edgeProviderOps:effectiveTemplate.templateParams': PROVIDER_SHAPE,
  'edgeProviderOps:certificatePreflight.certificate': PROVIDER_SHAPE,
  'edgeProviderOps:rotateCredentials.credentials': PROVIDER_SHAPE,
  'edgeProviderOps:rotateCredentials.identifiers': PROVIDER_SHAPE,
  'edgeProviderOps:discoverOptions.credentials': PROVIDER_SHAPE,
  'edgeProviderOps:discoverOptions.settings': PROVIDER_SHAPE,
  'edgeProviderOps:locationOptions.placement': PROVIDER_SHAPE,
  'edgeProviderOps:createLocation.placement': PROVIDER_SHAPE,
  'edgeProviderOps:createLocation.regionalParams': PROVIDER_SHAPE,
  'edgeProviderOps:planProvision.templateParams': PROVIDER_SHAPE,
  'edgeProviderOps:planProvision.choices': PROVIDER_SHAPE,
  'edgeProviderOps:runStep.templateParams': PROVIDER_SHAPE,
  'edgeRotations:commitSelection.templateParams': PROVIDER_SHAPE,
  'edgeSetupPlan:checkPicks.options': PROVIDER_SHAPE,
  'edgeSetupPlan:plan.pickOptions': PROVIDER_SHAPE,
  'edgeSetupPlan:create.pickOptions': PROVIDER_SHAPE,
  'edgeSetupRuns:reprotect.pickOptions': PROVIDER_SHAPE,
  'edgeTemplates:create.params': `${PROVIDER_SHAPE} (validateTemplateWrite)`,
  'edgeTemplates:update.params': `${PROVIDER_SHAPE} (validateTemplateWrite)`,
  'edgeTemplates:validate.params': `${PROVIDER_SHAPE} (validateTemplateWrite)`,
  'lib/hpkeCrypto:openRequest.wireBody': SEALED,
  'lib/hpkeCrypto:sealResponse.responseObj': SEALED,
  'memberWebauthn:registerVerify.response': WEBAUTHN,
  'memberWebauthn:authenticateVerify.response': WEBAUTHN,
  'revocationWatches:applyDecision.decision': COMPUTED,
  'serverAdmin:patchConfig.patch': ADMIN_JSON,
  'sniFamilies:patchConfig.patch': ADMIN_JSON,
  'sniHunt:importCandidates.seed': `${ADMIN_JSON} (parseSeed)`,
  'statusPage:setPageConfig.rows': `${ADMIN_JSON} (sanitizeCensorshipRows)`,
  'statusPage:createIncident.input': `${ADMIN_JSON} (validateIncidentInput)`,
  'statusPage:updateIncident.input': `${ADMIN_JSON} (validateIncidentInput)`,
  'webauthn:registerBootstrapVerify.response': WEBAUTHN,
  'webauthn:authenticateVerify.response': WEBAUTHN,
  'webauthn:registerInviteVerify.response': WEBAUTHN,
};

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      if (name !== '_generated' && name !== 'node_modules') out.push(...sourceFiles(full));
    } else if (name.endsWith('.ts') && !name.endsWith('.test.ts') && !name.endsWith('.d.ts')) {
      out.push(full);
    }
  }
  return out;
}

/** `file:export.field` for every v.any() in a registered function's args. */
function anyArgs(): string[] {
  const keys: string[] = [];
  const fn =
    /export const (\w+) = (?:internalMutation|internalAction|internalQuery|query|mutation|action)\(\{/g;
  for (const file of sourceFiles(CONVEX)) {
    const src = readFileSync(file, 'utf8');
    const mod = relative(CONVEX, file).replace(/\.ts$/, '');
    for (const m of src.matchAll(fn)) {
      const rest = src.slice(m.index! + m[0].length);
      const args = rest.slice(0, rest.indexOf('handler'));
      for (const a of args.matchAll(/(\w+)\??:\s*(?:v\.\w+\(\s*)*v\.any\(\)/g)) {
        keys.push(`${mod}:${m[1]}.${a[1]}`);
      }
      // A v.any() the pattern above cannot attribute still has to be listed.
      const attributed = [...args.matchAll(/(\w+)\??:\s*(?:v\.\w+\(\s*)*v\.any\(\)/g)].length;
      const total = (args.match(/v\.any\(\)/g) ?? []).length;
      if (total > attributed) keys.push(`${mod}:${m[1]}.<unattributed>`);
    }
  }
  return keys.sort();
}

describe('v.any() in function arguments', () => {
  const found = anyArgs();

  test('every v.any() arg is listed with what validates it instead', () => {
    expect(found.filter((k) => !(k in ALLOWED))).toEqual([]);
  });

  test('the list has no stale entries', () => {
    const set = new Set(found);
    expect(Object.keys(ALLOWED).filter((k) => !set.has(k))).toEqual([]);
  });
});
