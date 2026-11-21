/// <reference types="vite/client" />
/**
 * One Cloudflare token for the Cloudflare CDN account and the Cloudflare
 * Spectrum account (EDGE_TOKEN_SOURCE): the Spectrum account names the CDN
 * account and holds a copy of its credentials, rewritten on every change.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');

async function lenderAndBorrower() {
  const t = convexTest(schema, modules);
  const { id: cdnId } = await t.mutation(internal.edgeProviderAccounts.create, {
    provider: 'cloudflare',
    name: 'cf-cdn',
    settings: {},
    credentials: { apiToken: 'cf-1' },
  });
  const { id: tcpId } = await t.mutation(internal.edgeProviderAccounts.create, {
    provider: 'cloudflareSpectrum',
    name: 'cf-tcp',
    settings: { tokenAccountId: cdnId },
    // Ignored: the account uses the CDN account's token.
    credentials: { apiToken: 'typed-anyway' },
  });
  const token = async (id: Id<'edgeProviderAccounts'>) =>
    (
      (await t.query(internal.edgeProviderAccounts.getWithSecret, { id }))!
        .credentials as unknown as {
        apiToken: string;
      }
    ).apiToken;
  const row = (id: Id<'edgeProviderAccounts'>) => t.run((ctx) => ctx.db.get(id));
  return { t, cdnId, tcpId, token, row };
}

describe('a Cloudflare Spectrum account using a Cloudflare CDN token', () => {
  test('takes the CDN account token at creation, and needs none of its own', async () => {
    const { t, cdnId, tcpId, token } = await lenderAndBorrower();
    expect(await token(tcpId)).toBe('cf-1');
    const { id } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'cloudflareSpectrum',
      name: 'cf-tcp-2',
      settings: { tokenAccountId: cdnId },
    });
    expect(await token(id)).toBe('cf-1');
    expect(await t.query(internal.edgeProviderAccounts.tokenBorrowersOf, { id: cdnId })).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: tcpId, provider: 'cloudflareSpectrum' }),
        expect.objectContaining({ id, provider: 'cloudflareSpectrum' }),
      ]),
    );
  });

  test('only an account of the lending provider can lend', async () => {
    const t = convexTest(schema, modules);
    const { id: gcoreId } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'gcore',
      name: 'gc',
      settings: {},
      credentials: { apiKey: 'g-1' },
    });
    await expect(
      t.mutation(internal.edgeProviderAccounts.create, {
        provider: 'cloudflareSpectrum',
        name: 'cf-tcp',
        settings: { tokenAccountId: gcoreId },
      }),
    ).rejects.toThrow(/tokenAccountId/);
    await expect(
      t.mutation(internal.edgeProviderAccounts.create, {
        provider: 'cloudflareSpectrum',
        name: 'cf-tcp',
        settings: { tokenAccountId: 'not-an-account' },
      }),
    ).rejects.toThrow(/tokenAccountId/);
  });

  test("an edit of the CDN account's token reaches the Spectrum account as a credential change", async () => {
    const { t, cdnId, tcpId, token, row } = await lenderAndBorrower();
    const before = (await row(tcpId))!.credentialsChangedAt;
    await t.mutation(internal.edgeProviderAccounts.update, {
      id: cdnId,
      credentials: { apiToken: 'cf-2' },
    });
    expect(await token(tcpId)).toBe('cf-2');
    expect((await row(tcpId))!.credentialsChangedAt).toBeGreaterThan(before ?? 0);
  });

  test('a rotation of the CDN account hands the new token over and keeps the trust', async () => {
    const { t, cdnId, tcpId, token, row } = await lenderAndBorrower();
    const cdn = (await row(cdnId))!;
    const changedAt = (await row(tcpId))!.credentialsChangedAt;
    await t.mutation(internal.edgeProviderAccounts.applyCredentialRotation, {
      id: cdnId,
      credentials: { apiToken: 'cf-3' },
      settings: cdn.settings,
      expectedUpdatedAt: cdn.updatedAt,
    });
    expect(await token(tcpId)).toBe('cf-3');
    expect((await row(tcpId))!.credentialsChangedAt).toBe(changedAt);
  });

  test('its own token cannot be typed over the shared one, and leaving needs one', async () => {
    const { t, tcpId } = await lenderAndBorrower();
    await expect(
      t.mutation(internal.edgeProviderAccounts.update, {
        id: tcpId,
        credentials: { apiToken: 'own-1' },
      }),
    ).rejects.toThrow(/another account's token/);
    await expect(
      t.mutation(internal.edgeProviderAccounts.update, { id: tcpId, settings: {} }),
    ).rejects.toThrow(/own token/);
  });

  test('the CDN account stays while it lends its token, and goes once it does not', async () => {
    const { t, cdnId, tcpId, token } = await lenderAndBorrower();
    await expect(t.mutation(internal.edgeProviderAccounts.remove, { id: cdnId })).rejects.toThrow(
      /account_referenced|token/,
    );
    await t.mutation(internal.edgeProviderAccounts.update, {
      id: tcpId,
      settings: {},
      credentials: { apiToken: 'own-1' },
    });
    expect(await token(tcpId)).toBe('own-1');
    await t.mutation(internal.edgeProviderAccounts.remove, { id: cdnId });
    // A later edit of a CDN account reaches nobody.
    expect(await token(tcpId)).toBe('own-1');
  });
});
