import { describe, expect, test } from 'vitest';
import { changeToken } from './digest';
import {
  MAX_SERVER_NAMES,
  PatchRefused,
  applyPatchOps,
  checkPatchOps,
  type PatchOp,
} from './patchOps';

const reality = (tag: string, over: Record<string, unknown> = {}) => ({
  tag,
  port: 443,
  protocol: 'vless',
  settings: { clients: [{ id: 'client-uuid' }], decryption: 'none' },
  streamSettings: {
    network: 'tcp',
    security: 'reality',
    realitySettings: {
      target: 'target.example:443',
      serverNames: ['a.example', 'b.example'],
      privateKey: 'PRIVATE_KEY',
      shortIds: ['ab12'],
      ...over,
    },
  },
});

const config = () => ({
  log: { loglevel: 'none' },
  inbounds: [
    reality('r1'),
    {
      tag: 'ws',
      port: 8443,
      protocol: 'vless',
      streamSettings: { network: 'ws', security: 'tls' },
    },
    reality('r2', { dest: 'old.example:443', target: undefined }),
  ],
  outbounds: [{ protocol: 'freedom', tag: 'DIRECT' }],
  routing: { rules: [{ type: 'field', outboundTag: 'DIRECT' }] },
});

const code = (fn: () => unknown) => {
  try {
    fn();
  } catch (e) {
    return e instanceof PatchRefused ? e.code : `unexpected:${String(e)}`;
  }
  return 'no-refusal';
};

describe('applyPatchOps', () => {
  test('sets the names and nothing else; every untouched value is the SAME reference', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const before: any = config();
    const out = applyPatchOps(before, [
      {
        op: 'setRealityServerNames',
        inboundTag: 'r1',
        names: ['A.Example.', 'c.example', 'a.example'],
      },
    ]);
    expect(out.changed).toBe(true);
    expect(out.touchedTags).toEqual(['r1']);
    expect(out.changes).toEqual([
      {
        inboundTag: 'r1',
        field: 'serverNames',
        before: ['a.example', 'b.example'],
        after: ['a.example', 'c.example'],
      },
    ]);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const next = out.config as any;
    expect(next.inbounds[0].streamSettings.realitySettings.serverNames).toEqual([
      'a.example',
      'c.example',
    ]);
    // Untouched: by reference, key material included.
    expect(next.inbounds[1]).toBe(before.inbounds[1]);
    expect(next.inbounds[2]).toBe(before.inbounds[2]);
    expect(next.outbounds).toBe(before.outbounds);
    expect(next.routing).toBe(before.routing);
    expect(next.inbounds[0].settings).toBe(before.inbounds[0].settings);
    expect(next.inbounds[0].streamSettings.realitySettings.privateKey).toBe('PRIVATE_KEY');
    expect(next.inbounds[0].streamSettings.realitySettings.shortIds).toBe(
      before.inbounds[0].streamSettings.realitySettings.shortIds,
    );
    // The input is never mutated.
    expect(before.inbounds[0].streamSettings.realitySettings.serverNames).toEqual([
      'a.example',
      'b.example',
    ]);
    // Tag, protocol and position are never touched (the backend keys the transport uuid on them).
    expect(
      next.inbounds.map((i: { tag: string; protocol: string }) => [i.tag, i.protocol]),
    ).toEqual(before.inbounds.map((i: { tag: string; protocol: string }) => [i.tag, i.protocol]));
  });

  test('writes whichever of dest / target the transport already carries', () => {
    const out = applyPatchOps(config(), [
      { op: 'setRealityTarget', inboundTag: 'r2', target: 'new.example:8443' },
      { op: 'setRealityTarget', inboundTag: 'r1', target: 'new.example:8443' },
    ]);
    const next = out.config as any;
    expect(next.inbounds[2].streamSettings.realitySettings.dest).toBe('new.example:8443');
    // `dest` stays the key in use: a second spelling is not introduced.
    expect(next.inbounds[2].streamSettings.realitySettings.target).toBeUndefined();
    expect(next.inbounds[0].streamSettings.realitySettings.target).toBe('new.example:8443');
    expect(out.changes.map((c) => [c.inboundTag, c.before])).toEqual([
      ['r2', 'old.example:443'],
      ['r1', 'target.example:443'],
    ]);
  });

  test('a no-op is reported as unchanged and returns the very same config (no write, no node work)', () => {
    const before = config();
    const out = applyPatchOps(before, [
      { op: 'setRealityServerNames', inboundTag: 'r1', names: ['a.example', 'b.example'] },
      { op: 'setRealityTarget', inboundTag: 'r1', target: 'target.example:443' },
    ]);
    expect(out).toMatchObject({ changed: false, changes: [], touchedTags: [] });
    expect(out.config).toBe(before);
  });

  test('randomised configs: everything the ops did not name keeps its token', async () => {
    // Remove the touched field from both sides: what remains must be identical.
    const strip = (c: any) => {
      const copy = structuredClone(c);
      delete copy.inbounds[0].streamSettings.realitySettings.serverNames;
      return copy;
    };
    for (let i = 0; i < 25; i++) {
      const c: any = config();
      c[`extra${i}`] = { nested: [i, { deep: `v${i}` }], n: i };
      c.inbounds[0][`unknown${i}`] = { k: [i] };
      c.inbounds[0].streamSettings.realitySettings[`future${i}`] = i;
      const out = applyPatchOps(c, [
        { op: 'setRealityServerNames', inboundTag: 'r1', names: [`n${i}.example`] },
      ]);
      expect(await changeToken(strip(out.config), 'k')).toBe(await changeToken(strip(c), 'k'));
    }
  });

  test('refuses instead of guessing', () => {
    const names: PatchOp = { op: 'setRealityServerNames', inboundTag: 'r1', names: ['x.example'] };
    expect(code(() => applyPatchOps(null, [names]))).toBe('servers.profile_malformed');
    expect(code(() => applyPatchOps({ inbounds: [] }, [names]))).toBe('servers.profile_malformed');
    expect(code(() => applyPatchOps({ log: {} }, [names]))).toBe('servers.profile_malformed');
    expect(code(() => applyPatchOps(config(), [{ ...names, inboundTag: 'nope' }]))).toBe(
      'servers.unknown_inbound',
    );
    expect(code(() => applyPatchOps(config(), [{ ...names, inboundTag: 'ws' }]))).toBe(
      'servers.not_reality',
    );
    const twice = config();
    twice.inbounds.push(reality('r1') as never);
    expect(code(() => applyPatchOps(twice, [names]))).toBe('servers.profile_malformed');
  });
});

describe('checkPatchOps', () => {
  test('names are normalised, de-duplicated in order, and bounded', () => {
    expect(
      checkPatchOps([
        {
          op: 'setRealityServerNames',
          inboundTag: 'r',
          names: ['B.example', 'a.example.', 'b.example'],
        },
      ]),
    ).toEqual([
      { op: 'setRealityServerNames', inboundTag: 'r', names: ['b.example', 'a.example'] },
    ]);
    const many = Array.from({ length: MAX_SERVER_NAMES + 1 }, (_, i) => `n${i}.example`);
    expect(
      code(() => checkPatchOps([{ op: 'setRealityServerNames', inboundTag: 'r', names: many }])),
    ).toBe('servers.too_many_names');
    expect(
      code(() => checkPatchOps([{ op: 'setRealityServerNames', inboundTag: 'r', names: [] }])),
    ).toBe('validation');
    expect(
      code(() =>
        checkPatchOps([{ op: 'setRealityServerNames', inboundTag: 'r', names: ['not a name'] }]),
      ),
    ).toBe('validation');
  });
  test('targets, unknown ops, duplicates and empties are refused', () => {
    expect(
      code(() => checkPatchOps([{ op: 'setRealityTarget', inboundTag: 'r', target: 'no-port' }])),
    ).toBe('validation');
    expect(code(() => checkPatchOps([{ op: 'rawJson', inboundTag: 'r' } as never]))).toBe(
      'validation',
    );
    expect(code(() => checkPatchOps([]))).toBe('validation');
    const t: PatchOp = { op: 'setRealityTarget', inboundTag: 'r', target: 'x.example:443' };
    expect(code(() => checkPatchOps([t, t]))).toBe('validation');
    expect(code(() => checkPatchOps([{ ...t, inboundTag: '' }]))).toBe('validation');
  });
});
