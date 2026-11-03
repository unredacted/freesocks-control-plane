import { test as base, expect } from '@playwright/test';
import { assertLocalBrowser, assertSecureChromium } from '../browserSecurity';

export { expect };
export const test = base.extend({
  connectOptions: [
    async ({ connectOptions }, use) => {
      // Check before the built-in fixture connects or launches: Playwright Test
      // reads PW_TEST_CONNECT_WS_ENDPOINT; Chromium.launch also honors Selenium.
      assertLocalBrowser(connectOptions, process.env.SELENIUM_REMOTE_URL);
      await use(undefined);
    },
    { scope: 'worker' },
  ],
  browser: [
    async ({ browser, browserName }, use) => {
      if (browserName === 'chromium') await assertSecureChromium(browser);
      await use(browser);
    },
    { scope: 'worker' },
  ],
});
