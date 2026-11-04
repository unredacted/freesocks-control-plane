import { flushSync, mount, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import AppNoticeHint from './AppNoticeHint.svelte';

let app: ReturnType<typeof mount> | null = null;
afterEach(() => {
  if (app) unmount(app);
  app = null;
  document.body.innerHTML = '';
  vi.unstubAllGlobals();
});

const show = (family: 'clash' | 'singbox' | 'links') => {
  app = mount(AppNoticeHint, {
    target: document.body,
    props: { notice: { family, at: '2026-11-04T00:00:00.000Z' } },
  });
  flushSync();
};
const text = () => document.body.textContent ?? '';

describe('AppNoticeHint', () => {
  test('an old Clash app: too old to connect, other apps unaffected', () => {
    show('clash');
    expect(text()).toContain('One of your apps is too old to connect');
    expect(text()).toContain('Your other apps are not affected.');
    const note = document.querySelector('[role="note"]')!;
    expect(note.getAttribute('aria-labelledby')).toBe('app-notice-title');
    expect(text()).not.toContain('—');
  });

  test('an app whose format cannot carry the mode: says so, and offers another mode', () => {
    show('singbox');
    expect(text()).toContain("One of your apps can't use this connection mode");
    expect(text()).toContain('pick another connection mode');
  });

  test('the button takes the member to the supported apps and moves focus there', () => {
    vi.stubGlobal('matchMedia', () => ({ matches: true }));
    const target = document.createElement('section');
    target.id = 'setup-apps';
    const title = document.createElement('h2');
    title.tabIndex = -1;
    title.setAttribute('data-setup-title', '');
    target.append(title);
    document.body.append(target);
    const scrolled = vi.fn();
    target.scrollIntoView = scrolled;
    show('clash');
    [...document.querySelectorAll('button')]
      .find((b) => b.textContent?.includes('See supported apps'))!
      .click();
    expect(scrolled).toHaveBeenCalledWith({ behavior: 'auto', block: 'start' });
    expect(document.activeElement).toBe(title);
  });
});
