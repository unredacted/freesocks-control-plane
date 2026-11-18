// @vitest-environment node
import { afterEach, expect, test, vi } from 'vitest';
import { z } from 'zod';
import { adminInviteUrl } from './adminInvite';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

test('only the fragment carries the minted token', () => {
  const token = 'a'.repeat(64);
  const url = new URL(adminInviteUrl('https://console.example', token));
  expect(new URLSearchParams(url.hash.slice(1)).get('invite')).toBe(token);
  url.hash = '';
  expect(url.href).toBe('https://console.example/admin/register');
});

test('a build without a server key refuses invite operations before fetch', async () => {
  vi.stubEnv('VITE_FS_SERVER_HPKE_PK', '');
  vi.stubEnv('VITE_FS_SERVER_HPKE_KID', '');
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  const { apiClient } = await import('./api');
  for (const path of [
    '/api/v1/admin/admins/invite',
    '/api/admin/auth/register/options',
    '/api/admin/auth/register/verify',
  ]) {
    await expect(apiClient.post(path, {}, z.unknown())).rejects.toMatchObject({
      payload: { error: { code: 'hpke.sealed_required' } },
    });
  }
  expect(fetch).not.toHaveBeenCalled();
});
