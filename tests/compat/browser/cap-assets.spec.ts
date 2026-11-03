import { deflateRawSync } from 'node:zlib';
import { expect, test } from './fixtures';

test('Cap can load its same-origin classic pako fallback and inflate raw data', async ({
  page,
}) => {
  await page.goto('/');
  const url = await page.evaluate(() => window.CAP_PAKO_URL);
  expect(typeof url).toBe('string');
  expect(new URL(url!, page.url()).origin).toBe(new URL(page.url()).origin);
  // Match Cap's classic script loader: an ESM URL does not install window.pako.
  await page.addScriptTag({ url: url! });
  const payload = 'Cap compressed instrumentation fallback';
  const compressed = [...deflateRawSync(Buffer.from(payload))];
  const inflated = await page.evaluate((bytes) => {
    const { pako } = window as unknown as {
      pako: { inflateRaw: (data: Uint8Array) => Uint8Array };
    };
    return new TextDecoder().decode(pako.inflateRaw(Uint8Array.from(bytes)));
  }, compressed);
  expect(inflated).toBe(payload);
});
