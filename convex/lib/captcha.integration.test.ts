// @vitest-environment node
/**
 * INTEGRATION test: proves a self-hosted **Cap** token is SINGLE-USE — a token,
 * once redeemed and verified once, is rejected on a second `verifyCaptcha`. This
 * is the assumption the client fix rests on (the server consumes the token during
 * verify, before the account-validity checks, so a failed submit leaves a SPENT
 * token → the widget must remount for a fresh one; see CapWidget.reset() +
 * lib/captcha.ts). It can't be unit-tested offline (no live PoW), so it drives a
 * REAL Cap server end-to-end, mirroring convex/lib/backends/remnawave.integration.test.ts.
 *
 * Gated: skipped unless CAP_API_ENDPOINT + CAP_SITE_KEY + CAP_SECRET point at a
 * live Cap (the dev/beta compose `cap` service). Excluded from the fast offline
 * suite (vitest.config.ts drops `*.integration.test.ts`); run via
 * `bun run test:integration:cap` with those env vars set.
 *
 * The challenge→solve→redeem flow + the `prng` derivation are reproduced from
 * @cap.js/widget's wire protocol (pinned to the installed Cap version); the PoW
 * itself uses the same @cap.js/wasm `solve_pow` the browser widget runs. If Cap
 * changes its protocol, this test fails loudly against the live server — which is
 * exactly the drift an integration test should catch.
 */
import { describe, expect, test } from 'vitest';
// CJS wasm-bindgen module (loads the .wasm synchronously); typed by its sibling
// cap_wasm.d.ts (`export function solve_pow(salt, target): bigint`).
import * as capWasm from '@cap.js/wasm/node/cap_wasm.js';
import { verifyCaptcha } from './captcha';

const ENDPOINT = process.env.CAP_API_ENDPOINT;
const SITE_KEY = process.env.CAP_SITE_KEY;
const SECRET = process.env.CAP_SECRET;

/** Deterministic seeded RNG — verbatim from @cap.js/widget (challenge derivation). */
function prng(seed: string, length: number): string {
  function fnv1a(str: string): number {
    let hash = 2166136261;
    for (let i = 0; i < str.length; i++) {
      hash ^= str.charCodeAt(i);
      hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
    }
    return hash >>> 0;
  }
  let state = fnv1a(seed);
  let result = '';
  const next = (): number => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
  while (result.length < length) result += next().toString(16).padStart(8, '0');
  return result.substring(0, length);
}

type Challenge = [salt: string, target: string];
interface ChallengeResp {
  token: string;
  format?: number;
  challenges?: Challenge[];
  challenge?: { c: number; s: number; d: number };
}

/** Run the full Cap client flow against the live server and return a redeemed token. */
async function mintCapToken(): Promise<string> {
  const base = `${ENDPOINT!.replace(/\/$/, '')}/${SITE_KEY}/`;

  const chRaw = await fetch(`${base}challenge`, { method: 'POST' });
  if (!chRaw.ok) throw new Error(`challenge HTTP ${chRaw.status}`);
  const ch = (await chRaw.json()) as ChallengeResp;

  let challenges: Challenge[];
  if (ch.format === 2 && Array.isArray(ch.challenges)) {
    challenges = ch.challenges;
  } else if (ch.challenge) {
    const { c, s, d } = ch.challenge;
    // i is 1-based in the widget (it increments before use).
    challenges = Array.from({ length: c }, (_v, k) => {
      const i = k + 1;
      return [prng(`${ch.token}${i}`, s), prng(`${ch.token}${i}d`, d)] as Challenge;
    });
  } else {
    throw new Error(`unrecognized challenge shape: ${JSON.stringify(ch)}`);
  }

  const solutions = challenges.map(([salt, target]) => Number(capWasm.solve_pow(salt, target)));

  const rRaw = await fetch(`${base}redeem`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: ch.token, solutions }),
  });
  const r = (await rRaw.json()) as { success?: boolean; token?: string };
  if (!r.success || !r.token) throw new Error(`redeem failed: ${JSON.stringify(r)}`);
  return r.token;
}

describe.skipIf(!ENDPOINT || !SITE_KEY || !SECRET)('cap captcha — single-use (integration)', () => {
  test('a redeemed token verifies once, then is rejected on re-verify', async () => {
    const token = await mintCapToken();

    // verifyCaptcha reads CAP_* from the env (the same live server we minted against).
    const first = await verifyCaptcha(token);
    expect(first).toMatchObject({ success: true, configured: true });

    const second = await verifyCaptcha(token);
    expect(second.configured).toBe(true);
    expect(second.success).toBe(false); // consumed on first verify → not reusable
  });
});
