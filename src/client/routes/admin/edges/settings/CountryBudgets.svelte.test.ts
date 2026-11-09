import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import type { EdgeConfigView } from '../../../../../shared/contracts/edges';
import CountryBudgets from './CountryBudgets.svelte';
import { ConfigForm } from './form.svelte';
import { AUDIENCE_BUDGETS_PATH } from './fields';

const view = {
  config: { audience: { replacesPerDay: 1, replacesPerDayByCountry: { RU: 3 } } },
  defaults: {},
  bounds: {},
} as unknown as EdgeConfigView;

let form: ConfigForm;
let app: ReturnType<typeof mount> | null = null;
let cleanup: (() => void) | null = null;

beforeEach(() => {
  cleanup = $effect.root(() => {
    form = new ConfigForm(() => view);
  });
  app = mount(CountryBudgets, { target: document.body, props: { codes: ['IR', 'RU'], form } });
  flushSync();
});
afterEach(() => {
  if (app) unmount(app);
  app = null;
  cleanup?.();
  document.body.innerHTML = '';
});

const input = (code: string) =>
  document.querySelector<HTMLInputElement>(`input[aria-label^="Replacements a day for ${code}"]`)!;
const type = (code: string, value: string) => {
  input(code).value = value;
  input(code).dispatchEvent(new Event('input', { bubbles: true }));
  flushSync();
};

describe("a country's own replacement budget", () => {
  test('one field per listed country, showing what is stored; blank follows the fleet', () => {
    expect(input('IR').value).toBe('');
    expect(input('RU').value).toBe('3');
  });

  test('a number sets it, a blank drops it', () => {
    type('IR', '2');
    expect(form.get(AUDIENCE_BUDGETS_PATH)).toEqual({ RU: 3, IR: 2 });
    type('RU', '');
    expect(form.get(AUDIENCE_BUDGETS_PATH)).toEqual({ IR: 2 });
  });

  test('anything but a whole number from 0 to 10 marks the form invalid until fixed', () => {
    type('IR', '11');
    expect(form.invalid[AUDIENCE_BUDGETS_PATH]).toBe(true);
    expect(document.body.textContent).toContain('Use a whole number from 0 to 10');
    type('IR', '0');
    expect(form.invalid[AUDIENCE_BUDGETS_PATH]).toBeUndefined();
    expect(form.get(AUDIENCE_BUDGETS_PATH)).toEqual({ RU: 3, IR: 0 });
  });
});
