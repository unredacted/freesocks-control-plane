import { createHash } from 'node:crypto';
import { test, expect } from '../compat/browser/fixtures';

for (const changed of [false, true]) {
  test(
    changed ? 'rejects a changed lazy module' : 'loads the original lazy module',
    async ({ page }) => {
      const response = await page.goto('/');
      const map = await page.locator('script[type="importmap"]').textContent();
      expect(map).toBeTruthy();
      const digest = createHash('sha384').update(map!).digest('base64');
      const policy = await response!.headerValue('content-security-policy');
      const scriptSrc = policy!
        .split(';')
        .find((directive) => directive.trim().startsWith('script-src '));
      expect(scriptSrc?.split(/\s+/)).toContain(`'sha384-${digest}'`);
      const chunk = Object.keys(JSON.parse(map!).integrity).find((url) =>
        /^\/assets\/AdminRouter-[^/]+\.js$/.test(url),
      );
      expect(chunk).toBeDefined();

      // Both responses are valid JavaScript. Only their digest differs.
      const diagnostics: string[] = [];
      page.on('console', (message) => diagnostics.push(message.text()));
      let served = false;
      await page.route(chunk!, async (route) => {
        const original = await route.fetch({
          headers: { ...route.request().headers(), 'accept-encoding': 'identity' },
        });
        expect(original.status()).toBe(200);
        const bytes = await original.body();
        const body = changed ? Buffer.concat([bytes, Buffer.from('\n')]) : bytes;
        served = true;
        await route.fulfill({
          response: original,
          headers: { ...original.headers(), 'content-length': String(body.length) },
          body,
        });
      });
      const loaded = await page.evaluate(async (url) => {
        try {
          await import(url);
          return 'loaded';
        } catch (error) {
          return String(error);
        }
      }, chunk!);
      expect(served).toBe(true);
      if (changed) {
        expect(loaded).not.toBe('loaded');
        await expect.poll(() => diagnostics.join('\n')).toMatch(/integrity/i);
      } else {
        expect(loaded).toBe('loaded');
      }
    },
  );
}
