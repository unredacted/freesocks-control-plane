// @vitest-environment node
import { afterEach, expect, test, vi } from 'vitest';
import { z } from 'zod';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

test.each(['report-issue', 'switch-server'])(
  'a client without an HPKE pin only sends reason-only %s requests',
  async (operation) => {
    vi.stubEnv('VITE_FS_SERVER_HPKE_PK', '');
    vi.stubEnv('VITE_FS_SERVER_HPKE_KID', '');
    const { apiClient } = await import('./api');
    const fetch = vi.fn().mockResolvedValue(Response.json({ ok: true }));
    vi.stubGlobal('fetch', fetch);
    const path = '/api/v1/account/' + operation;
    const body = { reason: 'slow', confirm: true };
    const schema = z.object({ ok: z.boolean() });
    for (const telemetry of [{ country: 'CA' }, { city: 'Example City' }, { asn: 'AS64512' }]) {
      await expect(apiClient.post(path, { ...body, telemetry }, schema)).rejects.toMatchObject({
        payload: { error: { code: 'hpke.sealed_required' } },
      });
    }
    expect(fetch).not.toHaveBeenCalled();
    await expect(apiClient.post(path, body, schema)).resolves.toEqual({ ok: true });
    expect(fetch).toHaveBeenCalledWith(
      path,
      expect.objectContaining({ body: JSON.stringify(body) }),
    );
  },
);
