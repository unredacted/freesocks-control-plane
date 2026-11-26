import { flushSync, mount, unmount } from 'svelte';
import { afterEach, describe, expect, test } from 'vitest';
import MoreText from './MoreText.svelte';

let app: ReturnType<typeof mount> | null = null;
afterEach(() => {
  if (app) unmount(app);
  app = null;
  document.body.innerHTML = '';
});

const show = (text: string) => {
  app = mount(MoreText, { target: document.body, props: { text } });
  flushSync();
};

describe('MoreText', () => {
  test('one sentence shows as it is, with no control', () => {
    show('Read 4 minutes ago.');
    expect(document.body.textContent?.trim()).toBe('Read 4 minutes ago.');
    expect(document.querySelector('button')).toBeNull();
  });

  test('shows the first sentence, and More reveals the rest', () => {
    show('Automatic replacement held. Check the provider from that country.');
    expect(document.body.textContent).toMatch(/Automatic replacement held\./);
    expect(document.body.textContent).not.toMatch(/Check the provider/);
    const more = document.querySelector('button')!;
    expect(more.getAttribute('aria-expanded')).toBe('false');
    more.click();
    flushSync();
    expect(document.body.textContent).toMatch(/Check the provider from that country\./);
    expect(more.textContent?.trim()).toBe('Less');
  });
});
