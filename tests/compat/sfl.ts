/** Drives the installed application's UI; uses its read-only bridge for assertions. */
import { chromium, expect, type Browser, type Page } from '@playwright/test';
import { mkdtemp, mkdir, rm, writeFile, readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildImportLink } from '../../src/client/lib/appLinks';

const url = process.env.FCP_COMPAT_SUB_URL;
if (!url || !['127.0.0.1', 'localhost', 'host.docker.internal'].includes(new URL(url).hostname))
  throw new Error('SFL application test requires a disposable local subscription');
const version = JSON.parse(await readFile('.cache/compat/resolved-artifacts.json', 'utf8')).sfl
  .version;
const profileName = 'FCP compatibility';
const data = await mkdtemp(join(tmpdir(), 'fcp-sfl-'));
const output = 'test-results/compat/sfl';
await mkdir(output, { recursive: true });
// The official package disables Electron's Node inspector fuse. Attach to its
// renderer CDP endpoint instead; no package patch or replacement runtime.
const child = spawn(
  process.env.FCP_COMPAT_SFL_EXECUTABLE ?? '/opt/sing-box/sing-box',
  [
    `--user-data-dir=${data}`,
    '--no-sandbox',
    '--disable-gpu',
    '--lang=en-US',
    '--remote-debugging-port=0',
    buildImportLink('sing-box', url, profileName)!,
  ],
  { stdio: ['ignore', 'pipe', 'pipe'] },
);
let browser: Browser | undefined;
try {
  const endpoint = await new Promise<string>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error('SFL renderer debugging endpoint did not start')),
      30_000,
    );
    let output = '';
    child.stderr.on('data', (chunk) => {
      output += String(chunk);
      const match = /DevTools listening on (ws:\/\/127\.0\.0\.1:[^\s]+)/.exec(output);
      if (match) {
        clearTimeout(timer);
        resolve(match[1]!);
      }
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('exit', () => {
      clearTimeout(timer);
      reject(new Error('SFL exited before renderer attachment'));
    });
  });
  browser = await chromium.connectOverCDP(endpoint);
  const context = browser.contexts()[0]!;
  // The app also owns a tray window (tray.html); drive the main window only.
  const isMainWindow = (candidate: Page) => /\/index\.html(?:[?#]|$)/.test(candidate.url());
  let page = context.pages().find(isMainWindow);
  for (const deadline = Date.now() + 30_000; !page && Date.now() < deadline; ) {
    await new Promise((resolve) => setTimeout(resolve, 250));
    page = context.pages().find(isMainWindow);
  }
  if (!page) throw new Error('SFL main window did not appear');

  page.setDefaultTimeout(30_000);
  await page.getByRole('button', { name: 'Import', exact: true }).click();
  // Confirm the generated deep link arrived intact at the real app.
  await expect(page.getByPlaceholder('https://')).toHaveValue(url);
  // Exercise manual URL entry in the same real remote-profile form.
  await page.getByPlaceholder('https://').fill('');
  await page.getByPlaceholder('https://').fill(url);
  await page.getByRole('button', { name: 'Create', exact: true }).click();
  await expect(page.getByRole('button', { name: profileName, exact: true })).toBeVisible();
  const selected = await page.evaluate(async () => {
    const state = await (window as any).desktop.profiles.list();
    const profile = state.profiles.find((p: any) => p.id === state.selectedId);
    return {
      id: profile.id,
      lastUpdated: profile.lastUpdated,
      content: await (window as any).desktop.profiles.readContent(profile.id),
    };
  });
  const config = JSON.parse(selected.content);
  if (!config.outbounds.some((o: any) => o.type === 'vless'))
    throw new Error('SFL imported no VLESS outbound');
  await page.getByRole('button', { name: 'Update', exact: true }).click();
  await expect
    .poll(async () =>
      page.evaluate(async (id) => {
        const state = await (window as any).desktop.profiles.list();
        return state.profiles.find((p: any) => p.id === id)?.lastUpdated;
      }, selected.id),
    )
    .toBeGreaterThan(selected.lastUpdated);
  await page.screenshot({ path: `${output}/imported.png` });
  await writeFile(
    `${output}/result.json`,
    JSON.stringify(
      {
        version,
        import: 'passed',
        manualUrlEntry: 'passed',
        refresh: 'passed',
        tunnel: 'not-tested',
        os: process.env.FCP_COMPAT_OS ?? 'debian-13-container',
      },
      null,
      2,
    ),
  );
  console.log('SFL_IMPORT_REFRESH_OK');
} catch (error) {
  const page = browser?.contexts()[0]?.pages()[0];
  if (page) await page.screenshot({ path: `${output}/failure.png` }).catch(() => {});
  throw error;
} finally {
  await browser?.close();
  child.kill('SIGTERM');
  if (child.exitCode === null)
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        resolve();
      }, 3000);
      child.once('exit', () => {
        clearTimeout(timer);
        resolve();
      });
    });
  await rm(data, { recursive: true, force: true });
}
