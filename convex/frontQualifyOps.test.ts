// @vitest-environment node
import { describe, expect, test } from 'vitest';
import { providerVerdict } from './frontQualifyOps';

const failed = (code: string, detail?: string) => ({
  ok: false,
  code,
  ...(detail ? { detail } : {}),
  steps: [],
  checkedAt: 1,
});

describe('providerVerdict', () => {
  test("a Cloudflare 403 to a gRPC proof is the zone's gRPC switch, named for the operator", () => {
    expect(providerVerdict('cloudflare', 'grpc', failed('front_error', '403')).code).toBe(
      'grpc_disabled',
    );
  });

  test('anything else keeps the code the session reported', () => {
    for (const [provider, stream, result] of [
      ['cloudflare', 'ws', failed('front_error', '403')],
      ['cloudflare', 'grpc', failed('front_error', '502')],
      ['cloudflare', 'grpc', failed('auth_failed', 'closed')],
      ['fastly', 'grpc', failed('front_error', '403')],
      [null, 'grpc', failed('front_error', '403')],
    ] as const)
      expect(providerVerdict(provider, stream, result)).toBe(result);
    const ok = { ok: true, steps: [], checkedAt: 1 };
    expect(providerVerdict('cloudflare', 'grpc', ok)).toBe(ok);
  });
});
