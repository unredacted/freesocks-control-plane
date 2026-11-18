import { expect, test } from './fixtures';
import { isSealedWire } from '../../../src/shared/crypto/envelope';
import { serverOpenRequest } from '../../../src/shared/crypto/channel';
import { reportKeys } from './reportKeys';

for (const viewport of [
  { width: 1280, height: 720 },
  { width: 800, height: 450 },
  { width: 375, height: 568 },
]) {
  test(`report can be submitted at ${viewport.width}×${viewport.height}`, async ({ page }) => {
    await page.setViewportSize(viewport);
    let submitted: unknown;
    await page.route('**/api/v1/account/report-issue', async (route) => {
      submitted = route.request().postDataJSON();
      await route.fulfill({ json: { ok: true } });
    });
    await page.goto('/');
    await page.getByRole('button', { name: 'Open report' }).click();
    const dialog = page.getByRole('dialog');
    const send = dialog.getByRole('button', { name: 'Send report', exact: true });
    await expect(send).toBeDisabled();
    await dialog.locator('input[value="other"]').check();
    // No free-text box any more: "something else" points at the support email.
    await expect(dialog.locator('textarea')).toHaveCount(0);
    const mailto = dialog.getByRole('link', { name: 'support@example.test' });
    await expect(mailto).toBeVisible();
    expect(await mailto.getAttribute('href')).toBe(
      'mailto:support@example.test?subject=FreeSocks%20support%20-%20ID%20W3-TEST',
    );
    await send.scrollIntoViewIfNeeded();
    await expect(send).toBeInViewport();
    const bounds = await dialog.boundingBox();
    expect(bounds!.y).toBeGreaterThanOrEqual(0);
    expect(bounds!.height).toBeLessThanOrEqual(viewport.height);
    await send.click();
    await expect(page.getByRole('status')).toHaveText('Report sent');
    expect(Object.keys(submitted as object)).toEqual(['fsSealed']);
    if (!isSealedWire(submitted)) throw new Error('Expected an encrypted report');
    const { privateKey, kid } = await reportKeys();
    expect(
      await serverOpenRequest({
        serverPriv: privateKey,
        serverKid: kid,
        method: 'POST',
        path: '/api/v1/account/report-issue',
        wireBody: submitted,
      }),
    ).toEqual({ reason: 'other', telemetry: { country: 'US', city: 'Chicago', asn: '64512' } });
    // Reopening starts clean: no reason preselected.
    await page.getByRole('button', { name: 'Open report' }).click();
    await expect(dialog.locator('input[value="other"]')).not.toBeChecked();
  });
}
for (const status of [401, 429, 502]) {
  test(`HTTP ${status} preserves the report for retry`, async ({ page }) => {
    let attempts = 0;
    await page.route('**/api/v1/account/report-issue', async (route) => {
      attempts++;
      await route.fulfill(
        attempts === 1
          ? { status, json: { error: { code: `http.${status}`, message: `Test error ${status}` } } }
          : { json: { ok: true } },
      );
    });
    await page.goto('/');
    await page.getByRole('button', { name: 'Open report' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.locator('input[value="disconnects"]').check();
    await dialog.getByRole('button', { name: 'Send report', exact: true }).click();
    await expect(page.getByRole('status')).toHaveText(`Test error ${status}`);
    await expect(dialog.locator('input[value="disconnects"]')).toBeChecked();
    await dialog.getByRole('button', { name: 'Send report', exact: true }).click();
    await expect(page.getByRole('status')).toHaveText('Report sent');
    expect(attempts).toBe(2);
  });
}
