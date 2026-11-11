import { test, expect } from '../compat/browser/fixtures';

test('v4 dashboard signs in and loads its assets/API under /cap/', async ({ page }) => {
  test.skip(process.env.FCP_CAP_TEST_V4 !== '1', 'v4 dashboard migration check');
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('response', (response) => {
    if (response.status() >= 400 && /\.(js|css|woff2)(\?|$)/.test(response.url())) {
      errors.push(`asset HTTP ${response.status()}`);
    }
  });
  await page.goto('/cap');
  await expect(page).toHaveURL(`${process.env.FCP_CAP_TEST_URL}/cap/`);
  await page.getByLabel('Admin key', { exact: true }).fill(process.env.CAP_TEST_ADMIN_KEY!);
  const keysResponse = page.waitForResponse(
    (response) =>
      response.url() === `${process.env.FCP_CAP_TEST_URL}/cap/server/keys` &&
      response.status() === 200,
  );
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  const keys = (await (await keysResponse).json()) as { name: string }[];
  expect(keys.some((key) => key.name === 'integration-hashwx')).toBe(true);
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible({
    timeout: 15000,
  });
  expect(errors).toEqual([]);
});
