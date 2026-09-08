import { expect, test } from '@playwright/test';

for (const viewport of [
  { width: 1280, height: 720 },
  { width: 800, height: 450 },
  { width: 375, height: 568 },
]) {
  test(`report can be submitted at ${viewport.width}×${viewport.height}`, async ({ page }) => {
    await page.setViewportSize(viewport);
    let submitted: any;
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
    await dialog.locator('textarea').fill('Linux client cannot import the URL');
    await send.scrollIntoViewIfNeeded();
    await expect(send).toBeInViewport();
    const bounds = await dialog.boundingBox();
    expect(bounds!.y).toBeGreaterThanOrEqual(0);
    expect(bounds!.height).toBeLessThanOrEqual(viewport.height);
    await send.click();
    await expect(page.getByRole('status')).toHaveText('Report sent');
    expect(submitted).toMatchObject({
      reason: 'other',
      detail: 'Linux client cannot import the URL',
    });
    await page.getByRole('button', { name: 'Open report' }).click();
    await dialog.locator('input[value="other"]').check();
    await expect(dialog.locator('textarea')).toHaveValue('');
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
    await dialog.locator('input[value="other"]').check();
    await dialog.locator('textarea').fill('Keep this report');
    await dialog.getByRole('button', { name: 'Send report', exact: true }).click();
    await expect(page.getByRole('status')).toHaveText(`Test error ${status}`);
    await expect(dialog.locator('textarea')).toHaveValue('Keep this report');
    await dialog.getByRole('button', { name: 'Send report', exact: true }).click();
    await expect(page.getByRole('status')).toHaveText('Report sent');
    expect(attempts).toBe(2);
  });
}
