import { expect, test } from './fixtures';
import { reportKeys } from './reportKeys';
import { isSealedWire } from '../../../src/shared/crypto/envelope';
import { serverOpenRequest } from '../../../src/shared/crypto/channel';

test('the invite stays out of navigation and both registration requests', async ({ page }) => {
  const token = 'ab'.repeat(32);
  const records: string[] = [];
  page.on('request', (req) =>
    records.push(JSON.stringify([req.url(), req.headers(), req.postData()])),
  );
  const { privateKey, kid } = await reportKeys();
  const received: unknown[] = [];
  await page.route('**/api/admin/auth/register/*', async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    const wire = req.postDataJSON();
    expect(Object.keys(wire)).toEqual(['fsSealed']);
    if (!isSealedWire(wire)) throw new Error('Expected a sealed registration request');
    received.push(
      await serverOpenRequest({
        serverPriv: privateKey,
        serverKid: kid,
        method: 'POST',
        path,
        wireBody: wire,
      }),
    );
    await route.fulfill({
      json: path.endsWith('/options')
        ? {
            options: {
              rp: { name: 'Test admin' },
              user: { id: 'AQ', name: 'invitee', displayName: 'Invitee' },
              challenge: 'Ag',
              pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            },
          }
        : { ok: true, username: 'invitee' },
    });
  });
  // Stand in for the user's authenticator; the browser still runs the registration UI,
  // WebAuthn client library, request sealing and transport.
  await page.addInitScript(() => {
    Object.defineProperty(navigator.credentials, 'create', {
      value: async () => ({
        id: 'AQ',
        rawId: new Uint8Array([1]).buffer,
        type: 'public-key',
        response: {
          attestationObject: new Uint8Array([2]).buffer,
          clientDataJSON: new Uint8Array([3]).buffer,
        },
        getClientExtensionResults: () => ({}),
      }),
    });
  });
  await page.goto('/admin/register#invite=' + token);
  await expect(page).toHaveURL(/\/admin\/register$/);
  // The application shell's "Skip to content" link uses an ordinary page anchor.
  await page.evaluate(() => {
    window.location.hash = 'main';
  });
  await page.getByRole('button', { name: 'Register passkey' }).click();
  await expect(page.getByText("You're set up")).toBeVisible();
  expect(received).toEqual([
    { invite: token },
    { invite: token, deviceLabel: 'unnamed', response: expect.objectContaining({ id: 'AQ' }) },
  ]);
  expect(records.join('\n')).not.toContain(token);
});

test('a legacy query link is scrubbed and cannot start enrollment', async ({ page }) => {
  await page.goto('/admin/register?invite=' + 'ab'.repeat(32));
  await expect(page).toHaveURL(/\/admin\/register$/);
  await expect(page.getByText('Invalid invite link')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Register passkey' })).toHaveCount(0);
});
