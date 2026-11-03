import type { Browser } from '@playwright/test';

// Chrome's 2026-10-27 stable update fixes CVE-2026-118306, -118331,
// -118348 and -118344. CI refreshes stable Chrome on every run as well.
// https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_0562499947.html
export const MIN_CHROMIUM_VERSION = '156.0.8078.73';

export function assertLocalBrowser(connectOptions: unknown, seleniumRemoteUrl?: string): void {
  if (connectOptions || seleniumRemoteUrl) {
    throw new Error('Compatibility browser tests require a local sandboxed browser');
  }
}

export function assertPatchedChromium(version: string): void {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(version)) {
    throw new Error('Cannot verify the Chromium version; a four-part browser version is required');
  }
  const actual = version.split('.').map(Number);
  if (!actual.every(Number.isSafeInteger)) throw new Error('Cannot verify the Chromium version');
  const minimum = MIN_CHROMIUM_VERSION.split('.').map(Number);
  for (let i = 0; i < minimum.length; i++) {
    if (actual[i]! > minimum[i]!) return;
    if (actual[i]! < minimum[i]!) {
      throw new Error(
        `Chromium ${version} is vulnerable; update Chrome stable to ${MIN_CHROMIUM_VERSION} or newer`,
      );
    }
  }
}

const UNSAFE_SWITCHES = new Set([
  '--no-sandbox',
  '--disable-sandbox',
  '--disable-setuid-sandbox',
  '--disable-seccomp-filter-sandbox',
  '--disable-gpu-sandbox',
  '--single-process',
  '--in-process-gpu',
]);

export function assertSandboxArguments(args: readonly string[]): void {
  // Chromium also accepts single-dash switches, and slash/case variants on
  // Windows. Inspect them as switches rather than treating argv as exact text.
  const unsafe = args
    .map((arg) =>
      arg
        .split('=')[0]!
        .replace(/^(?:--?|\/)/, '--')
        .toLowerCase(),
    )
    .find((arg) => UNSAFE_SWITCHES.has(arg));
  if (unsafe) throw new Error(`Browser sandbox protection is disabled by ${unsafe}`);
}

/** Check the worker's actual browser before a context can load fixture content. */
export async function assertSecureChromium(browser: Browser): Promise<void> {
  assertPatchedChromium(browser.version());
  const session = await browser.newBrowserCDPSession();
  try {
    // This fails closed if command-line inspection is unavailable. Do not
    // substitute a check of chromium.executablePath(): headless and remote
    // connections may use a completely different browser executable.
    const { arguments: args } = await session.send('Browser.getBrowserCommandLine');
    assertSandboxArguments(args);
  } finally {
    await session.detach();
  }
}
