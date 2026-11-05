import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import NameDialog from './NameDialog.svelte';

const save = vi.fn<(name: string) => Promise<unknown>>();

let client: QueryClient;
let app: ReturnType<typeof mountWithQuery> | null = null;
const props = $state({
  open: true,
  name: 'Cover A',
  title: 'Rename Cover A',
  description: 'Only admins see this name.',
  empty: 'Give the list a name.',
  saved: 'List renamed',
  save,
  errorWords: (e: unknown) => `Refused: ${(e as Error).message}`,
});

beforeEach(() => {
  save.mockReset().mockResolvedValue({ ok: true });
  client = new QueryClient();
  props.open = true;
  app = mountWithQuery(client, NameDialog, props);
  flushSync();
});
afterEach(() => {
  if (app) unmount(app);
  app = null;
  client.clear();
});

const input = () => document.querySelector<HTMLInputElement>('input')!;
const button = (label: string) =>
  [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === label)!;
const type = (value: string) => {
  input().value = value;
  input().dispatchEvent(new Event('input', { bubbles: true }));
  flushSync();
};

describe('Rename', () => {
  test('opens on the name it has, nothing to save yet', () => {
    expect(document.body.textContent).toContain('Rename Cover A');
    expect(input().value).toBe('Cover A');
    expect(input().maxLength).toBe(80);
    expect(button('Save').disabled).toBe(true);
  });

  test('saves the new name, trimmed, and closes', async () => {
    type('  Shared cover A ');
    expect(button('Save').disabled).toBe(false);
    button('Save').click();
    await vi.waitFor(() => expect(save.mock.calls).toEqual([['Shared cover A']]));
    await vi.waitFor(() => expect(document.querySelector('input')).toBeNull());
  });

  test('an empty name cannot be saved', () => {
    type('   ');
    expect(document.body.textContent).toContain('Give the list a name.');
    expect(button('Save').disabled).toBe(true);
  });

  test('a refusal stays in the dialog, in words', async () => {
    save.mockRejectedValue(new Error('gone'));
    type('Shared cover A');
    button('Save').click();
    await vi.waitFor(() => expect(document.body.textContent).toContain('Refused: gone'));
    expect(input().value).toBe('Shared cover A');
  });
});
