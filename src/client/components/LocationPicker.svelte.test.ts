import { flushSync, mount, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import LocationPicker from './LocationPicker.svelte';
import SwitchLocationModal from './SwitchLocationModal.svelte';

let app: ReturnType<typeof mount> | null = null;
afterEach(() => {
  if (app) unmount(app);
  app = null;
  document.body.innerHTML = '';
});

const LOCATIONS = [
  { code: 'MCI', label: 'Kansas City, MO', online: true, load: 'quiet' as const, tiers: null },
  { code: 'CHI', label: 'Chicago, IL', online: true, load: 'quiet' as const, tiers: ['member'] },
];
const text = () => document.body.textContent ?? '';
const button = (label: string) =>
  [...document.querySelectorAll('button')].find((b) => b.textContent?.includes(label))!;

describe('LocationPicker', () => {
  test('a members-only location reads "Members" and opens the upgrade note instead of selecting', () => {
    const onSeeMembership = vi.fn();
    const props = $state({ value: 'auto' });
    app = mount(LocationPicker, {
      target: document.body,
      props: {
        locations: LOCATIONS,
        get value() {
          return props.value;
        },
        set value(v: string) {
          props.value = v;
        },
        tierSlug: 'free',
        onSeeMembership,
      },
    });
    flushSync();
    expect(text()).toContain('Members');
    button('Chicago, IL').click();
    flushSync();
    expect(props.value).toBe('auto');
    expect(text()).toContain('Chicago, IL is for members');
    button('See membership').click();
    expect(onSeeMembership).toHaveBeenCalledOnce();
    // An open location still selects, and the note goes away.
    button('Kansas City, MO').click();
    flushSync();
    expect(props.value).toBe('MCI');
    expect(text()).not.toContain('is for members');
    expect(text()).not.toContain('—');
  });

  test("a member's tier sees no lock on its own location", () => {
    app = mount(LocationPicker, {
      target: document.body,
      props: { locations: LOCATIONS, value: 'auto', tierSlug: 'member' },
    });
    flushSync();
    expect(document.querySelector('svg.lucide-lock')).toBeNull();
    expect(text()).not.toContain('Members');
  });
});

describe('SwitchLocationModal', () => {
  test('a tier that may not switch gets the membership note and the same-location fix', () => {
    const onSeeMembership = vi.fn();
    const onSwitchServer = vi.fn();
    app = mount(SwitchLocationModal, {
      target: document.body,
      props: {
        open: true,
        locations: LOCATIONS,
        tierSlug: 'free',
        canSwitch: false,
        currentCode: 'MCI',
        currentLabel: 'Kansas City, MO',
        busy: false,
        onCancel: () => {},
        onConfirm: () => {},
        onSeeMembership,
        onSwitchServer,
      },
    });
    flushSync();
    expect(text()).toContain('Choosing your location is part of membership');
    expect(text()).toContain('Your free key stays in Kansas City, MO');
    expect(text()).toContain('Members can also use: Chicago, IL');
    button('See membership').click();
    button('Switch server instead').click();
    expect(onSeeMembership).toHaveBeenCalledOnce();
    expect(onSwitchServer).toHaveBeenCalledOnce();
  });

  test('a member picks another location and confirms it', () => {
    const onConfirm = vi.fn();
    app = mount(SwitchLocationModal, {
      target: document.body,
      props: {
        open: true,
        locations: LOCATIONS,
        tierSlug: 'member',
        canSwitch: true,
        currentCode: 'MCI',
        currentLabel: 'Kansas City, MO',
        busy: false,
        onCancel: () => {},
        onConfirm,
      },
    });
    flushSync();
    const confirm = button('Move my key');
    expect(confirm.disabled).toBe(true);
    const radio = document.querySelector<HTMLInputElement>('input[value="CHI"]')!;
    radio.click();
    flushSync();
    expect(confirm.disabled).toBe(false);
    confirm.click();
    expect(onConfirm).toHaveBeenCalledWith('CHI');
    // The current location is not offered as a destination.
    expect(document.querySelector('input[value="MCI"]')).toBeNull();
  });
});
