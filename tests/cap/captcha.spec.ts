import { test, expect } from '../compat/browser/fixtures';
import { verifyCaptcha } from '../../convex/lib/captcha';
import { execFileSync } from 'node:child_process';

const valkey = (...args: string[]) =>
  execFileSync(
    'docker',
    [
      'compose',
      '--env-file',
      '/dev/null',
      '-p',
      process.env.FCP_CAP_TEST_PROJECT!,
      '-f',
      'docker-compose.cap-test.yml',
      'exec',
      '-T',
      'valkey',
      'valkey-cli',
      ...args,
    ],
    { encoding: 'utf8' },
  ).trim();

const keys = JSON.parse(process.env.FCP_CAP_TEST_KEYS!) as Record<
  string,
  { siteKey: string; secretKey: string }
>;

for (const protocol of ['hashwx', 'sha256-pow']) {
  test(`${protocol}: real solve, single-use verification and retry under production CSP`, async ({
    page,
  }) => {
    const key = keys[protocol]!;
    if (protocol === 'sha256-pow') {
      await page.addInitScript(() => {
        Object.defineProperty(window, 'DecompressionStream', { value: undefined });
      });
    }
    const external: string[] = [];
    const cspErrors: string[] = [];
    await page.route('**/*', async (route) => {
      if (new URL(route.request().url()).origin !== process.env.FCP_CAP_TEST_URL) {
        external.push(route.request().url());
        await route.abort();
      } else await route.continue();
    });
    page.on('console', (message) => {
      if (/violates.*Content Security Policy|Refused to/i.test(message.text()))
        cspErrors.push(message.text());
    });
    const response = await page.goto(`/?siteKey=${key.siteKey}`);
    expect(response!.headers()['content-security-policy']).toContain("'nonce-");
    expect(response!.headers()['content-security-policy']).not.toContain('cdn.jsdelivr.net');
    await page.locator('cap-widget').getByRole('button').click();
    const token = page.getByTestId('token');
    await expect(token).not.toHaveText('', { timeout: 60_000 });
    const first = (await token.textContent())!;
    process.env.CAP_API_ENDPOINT = `${process.env.FCP_CAP_TEST_URL}/cap`;
    process.env.CAP_SITE_KEY = key.siteKey;
    process.env.CAP_SECRET = key.secretKey;
    expect(await verifyCaptcha(first)).toMatchObject({ success: true, configured: true });
    expect(await verifyCaptcha(first)).toMatchObject({ success: false, configured: true });

    // A failed login consumes its token. Exercise the component's real remount.
    await page.getByRole('button', { name: 'Retry submission' }).click();
    await expect(token).toHaveText('');
    await page.locator('cap-widget').getByRole('button').click();
    await expect(token).not.toHaveText('', { timeout: 60_000 });
    const second = (await token.textContent())!;
    expect(second).not.toBe(first);
    expect(Number(valkey('PTTL', `token:${second}`))).toBeGreaterThan(0);
    expect(valkey('PEXPIRE', `token:${second}`, '1')).toBe('1');
    await expect.poll(() => valkey('EXISTS', `token:${second}`)).toBe('0');
    expect(await verifyCaptcha(second)).toMatchObject({ success: false });
    await page.getByRole('button', { name: 'Retry submission' }).click();
    await page.locator('cap-widget').getByRole('button').click();
    await expect(token).not.toHaveText('', { timeout: 60_000 });
    expect(await verifyCaptcha((await token.textContent())!)).toMatchObject({ success: true });
    expect(external).toEqual([]);
    expect(cspErrors).toEqual([]);
    expect(await page.evaluate(() => window.CAP_ISOLATE)).toBe(true);
    expect(await page.evaluate(() => window.CAP_DISABLE_WIDGET_REF)).toBe(true);
  });
}

test('instrumentation is isolated and error recovery stays on our origin', async ({ page }) => {
  const key = keys.hashwx!;
  await page.addInitScript(() => {
    // Capture the permissions at insertion, even if a fast solve removes the
    // frame before Playwright can locate it. This does not replace the solver.
    const permissions: (string | null)[] = [];
    Object.assign(window, { capFramePermissions: permissions });
    const append = Node.prototype.appendChild;
    Node.prototype.appendChild = function <T extends Node>(node: T): T {
      if (node instanceof HTMLIFrameElement) permissions.push(node.getAttribute('sandbox'));
      return append.call(this, node) as T;
    };
  });
  await page.goto(`/?siteKey=${key.siteKey}`);
  await page.locator('cap-widget').getByRole('button').click();
  await expect(page.getByTestId('token')).not.toHaveText('', { timeout: 60_000 });
  const permissions = await page.evaluate(
    () => (window as unknown as { capFramePermissions: string[] }).capFramePermissions,
  );
  expect(permissions.length).toBeGreaterThan(0);
  expect(permissions.every((value) => value === 'allow-scripts')).toBe(true);
  expect(await page.locator('cap-widget').getAttribute('data-cap-troubleshooting-url')).toBe(
    '/#faq',
  );
  await page.locator('cap-widget').evaluate((widget) => {
    HTMLElement.prototype.dispatchEvent.call(
      widget,
      new CustomEvent('error', { detail: { code: 'instr_timeout' } }),
    );
  });
  await expect(page.locator('cap-widget')).toHaveCount(0);
  await expect(page.getByTestId('token')).toHaveText('');
  await expect(page.locator('iframe')).toHaveCount(0);
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.locator('cap-widget')).toHaveCount(1);
});
