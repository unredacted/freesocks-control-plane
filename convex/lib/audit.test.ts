/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from '../schema';
import { internal } from '../_generated/api';
import { AUDIT_PAYLOAD_ALLOWLIST, sanitizeAuditPayload } from './audit';

const modules = import.meta.glob('../**/*.*s');

afterEach(() => vi.restoreAllMocks());

describe('sanitizeAuditPayload', () => {
  test('projects a known action to only its allowlisted keys', () => {
    const out = sanitizeAuditPayload('subscription.switch_backend', {
      fromBackend: 'remnawave',
      toBackend: 'outline',
      fromTier: 'free',
      toTier: 'member',
    });
    expect(out).toEqual({
      fromBackend: 'remnawave',
      toBackend: 'outline',
      fromTier: 'free',
      toTier: 'member',
    });
  });

  test('drops non-allowlisted keys (incl. an accidental secret) on a known action', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const out = sanitizeAuditPayload('user.create.free', {
      ipCountry: 'US',
      asn: 13335,
      // A careless caller spreads a whole request body that carries a secret.
      accountId: '01234567890123456789012345678901',
      authorization: 'Bearer fsv1_xxx',
    });
    expect(out).toEqual({ ipCountry: 'US', asn: 13335 });
    expect(out).not.toHaveProperty('accountId');
    expect(out).not.toHaveProperty('authorization');
    // A known action with extra keys is not a "warn" case (it projected fine).
    expect(warn).not.toHaveBeenCalled();
  });

  test('preserves explicit null values for allowlisted keys', () => {
    const out = sanitizeAuditPayload('user.create.free', { ipCountry: null, asn: null });
    expect(out).toEqual({ ipCountry: null, asn: null });
  });

  test('keeps only the present allowlisted keys (partial payload)', () => {
    const out = sanitizeAuditPayload('membership.tier_change', {
      fromTierId: 'a',
      toTierId: 'b',
      // reason omitted
    });
    expect(out).toEqual({ fromTierId: 'a', toTierId: 'b' });
  });

  test('returns undefined when there is no payload', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(sanitizeAuditPayload('admin.login', undefined)).toBeUndefined();
    expect(sanitizeAuditPayload('admin.login', null)).toBeUndefined();
    // No payload is the common, curated case: it must never warn.
    expect(warn).not.toHaveBeenCalled();
  });

  test('fails closed (drops payload + warns) for an unregistered action', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const out = sanitizeAuditPayload('some.future.action', { anything: 'here', secret: 'leak' });
    expect(out).toBeUndefined();
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0]?.[0]).toContain('some.future.action');
  });

  test('drops a non-object payload (array / scalar) and warns', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(sanitizeAuditPayload('user.create.free', ['a', 'b'])).toBeUndefined();
    expect(sanitizeAuditPayload('user.create.free', 'a string body')).toBeUndefined();
    expect(warn).toHaveBeenCalledTimes(2);
  });

  test('returns undefined when none of the allowlisted keys are present', () => {
    const out = sanitizeAuditPayload('user.create.free', { unrelated: 1 });
    expect(out).toBeUndefined();
  });

  test('the allowlist only contains the actions that actually carry a payload', () => {
    // Guardrail: every registered action must map to a non-empty key set, so an
    // empty [] never silently swallows a payload without a maintainer noticing.
    for (const [action, keys] of Object.entries(AUDIT_PAYLOAD_ALLOWLIST)) {
      expect(keys.length, action).toBeGreaterThan(0);
    }
  });
});

describe('audit.record (integration, via the real mutation)', () => {
  test('persists only the allowlisted keys for a known action', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.audit.record, {
      actorType: 'member',
      action: 'subscription.switch_backend',
      payload: {
        fromBackend: 'remnawave',
        toBackend: 'outline',
        fromTier: 'free',
        toTier: 'member',
        // would-be leak if stored verbatim:
        accountIdPlaintext: '01234567890123456789012345678901',
      },
    });
    const rows = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(rows).toHaveLength(1);
    expect(rows[0]!.payload).toEqual({
      fromBackend: 'remnawave',
      toBackend: 'outline',
      fromTier: 'free',
      toTier: 'member',
    });
  });

  test('persists no payload for an unregistered action', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const t = convexTest(schema, modules);
    await t.mutation(internal.audit.record, {
      actorType: 'admin',
      action: 'admin.future.thing',
      payload: { note: 'free text an admin typed', secret: 'do not store' },
    });
    const rows = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(rows).toHaveLength(1);
    expect(rows[0]!.payload).toBeUndefined();
  });
});
