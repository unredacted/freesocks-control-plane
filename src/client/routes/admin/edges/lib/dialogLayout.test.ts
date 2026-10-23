import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, test } from 'vitest';
import { CONFIRM_BODY, CONFIRM_FIT, DIALOG_FIT, STICKY_FOOTER } from './dialogLayout';

const EDGES = resolve(__dirname, '..');

function svelteFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return svelteFiles(path);
    return name.endsWith('.svelte') ? [path] : [];
  });
}

/** Every `<Tag ...>` opening tag in a source, attributes included. */
const openings = (source: string, tag: string): string[] =>
  [...source.matchAll(new RegExp(`<${tag.replace('.', '\\.')}\\b[^>]*>`, 'g'))].map((m) => m[0]);

describe('edges dialogs never grow past the window', () => {
  const files = svelteFiles(EDGES).map((path) => ({
    path: path.slice(EDGES.length + 1),
    source: readFileSync(path, 'utf8'),
  }));

  test('every dialog content fits the window and scrolls inside it', () => {
    const unfit: string[] = [];
    for (const f of files) {
      for (const tag of openings(f.source, 'Dialog.Content'))
        if (!tag.includes('DIALOG_FIT')) unfit.push(`${f.path}: ${tag}`);
      for (const tag of openings(f.source, 'AlertDialog.Content'))
        if (!tag.includes('CONFIRM_FIT')) unfit.push(`${f.path}: ${tag}`);
    }
    expect(unfit).toEqual([]);
    // There is something to check (the scan reaches the dialogs).
    expect(files.filter((f) => f.source.includes('DIALOG_FIT')).length).toBeGreaterThan(10);
  });

  test("a scrolling dialog's footer stays in view", () => {
    const loose: string[] = [];
    for (const f of files)
      for (const tag of openings(f.source, 'Dialog.Footer'))
        if (!tag.includes('STICKY_FOOTER')) loose.push(`${f.path}: ${tag}`);
    expect(loose).toEqual([]);
  });

  test('the confirm dialog keeps its title and buttons put and scrolls its body', () => {
    const confirm = files.find((f) => f.path === 'components/ConfirmDialog.svelte')!.source;
    expect(confirm).toMatch(
      /<AlertDialog\.Header class=\{body \? 'shrink-0 -mb-2\.5' : 'shrink-0'\}>/,
    );
    expect(confirm).toMatch(/<AlertDialog\.Footer class="shrink-0">/);
    expect(confirm).toMatch(/data-slot="confirm-body" class=\{CONFIRM_BODY\}/);
    // Only the title is fixed: a long explanation scrolls with the rest.
    const header = confirm.slice(
      confirm.indexOf('<AlertDialog.Header'),
      confirm.indexOf('</AlertDialog.Header>'),
    );
    expect(header).not.toContain('Description');
    const body = confirm.slice(confirm.indexOf('data-slot="confirm-body"'));
    expect(body.indexOf('<AlertDialog.Description')).toBeGreaterThan(0);
  });

  test('the classes bound the height by the window and scroll', () => {
    for (const fit of [CONFIRM_FIT, DIALOG_FIT]) expect(fit).toContain('max-h-[calc(100dvh-2rem)]');
    expect(DIALOG_FIT).toContain('overflow-y-auto');
    expect(CONFIRM_FIT).toContain('flex-col');
    expect(CONFIRM_BODY).toMatch(/min-h-0.*overflow-y-auto/);
    expect(STICKY_FOOTER).toMatch(/^sticky -bottom-4 /);
  });
});
