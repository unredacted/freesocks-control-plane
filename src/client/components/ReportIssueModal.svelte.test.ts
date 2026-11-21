import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, beforeAll, describe, expect, test } from 'vitest';
import { mountWithQuery } from '../testing/mountWithQuery';
import ReportIssueModal from './ReportIssueModal.svelte';

// jsdom has no Web Animations: the dialog's transitions finish at once.
beforeAll(() => {
  Element.prototype.animate ??= function () {
    const animation = {
      onfinish: null as null | (() => void),
      cancel() {},
      finished: Promise.resolve(),
      currentTime: 0,
    };
    setTimeout(() => animation.onfinish?.(), 0);
    return animation as unknown as Animation;
  };
});

type Connection = {
  label: string;
  base?: string;
  role: 'primary' | 'backup';
  entry?: 'encrypted' | 'plain';
};

const A = '🌐 via CDN 1';
const B = '🌐 via CDN 2';
const one: Connection[] = [
  { label: A, base: A, role: 'primary' },
  { label: B, base: B, role: 'backup' },
];
// The app holds each address twice: the encrypted entry, and the plain one under the address's name.
const EA = `${A} · Encrypted`;
const EB = `${B} · Encrypted`;
const twice: Connection[] = [
  { label: EA, base: EA, role: 'primary', entry: 'encrypted' },
  { label: EB, base: EB, role: 'backup', entry: 'encrypted' },
  { label: A, base: A, role: 'primary', entry: 'plain' },
  { label: B, base: B, role: 'backup', entry: 'plain' },
];

let app: ReturnType<typeof mountWithQuery> | null = null;
const props = $state({
  open: true,
  reason: null as null | 'cant-connect',
  connections: one,
  connection: null as 'primary' | 'backup' | 'unsure' | null,
  connectionEntry: null as 'encrypted' | 'plain' | null,
});
// What the page binds (`bind:connection`, `bind:connectionEntry`): accessors
// the dialog writes its answer through.
const bound = {
  get open() {
    return props.open;
  },
  set open(v) {
    props.open = v;
  },
  get reason() {
    return props.reason;
  },
  set reason(v) {
    props.reason = v;
  },
  get connections() {
    return props.connections;
  },
  get connection() {
    return props.connection;
  },
  set connection(v) {
    props.connection = v;
  },
  get connectionEntry() {
    return props.connectionEntry;
  },
  set connectionEntry(v) {
    props.connectionEntry = v;
  },
  telemetryContext: undefined,
  onCancel: () => {},
  onConfirm: () => {},
  busy: false,
};

function mount(connections: Connection[]) {
  props.connections = connections;
  props.connection = null;
  props.connectionEntry = null;
  app = mountWithQuery(new QueryClient(), ReportIssueModal, bound as never);
  flushSync();
  const options = () =>
    [...document.body.querySelectorAll<HTMLInputElement>('input[name="report-issue-connection"]')]
      .map((input) => ({ input, label: input.closest('label')!.textContent!.trim() }))
      .filter((o) => o.label !== '');
  return {
    labels: () => options().map((o) => o.label),
    pick: (label: string) => {
      const o = options().find((x) => x.label === label)!;
      o.input.click();
      flushSync();
    },
    checked: () =>
      options()
        .filter((o) => o.input.checked)
        .map((o) => o.label),
    text: () => (document.body.textContent ?? '').replace(/\s+/g, ' '),
  };
}

afterEach(() => {
  if (app) unmount(app);
  app = null;
  document.body.innerHTML = '';
});

const HINT = 'If the one marked Encrypted does not connect, try the other one';

describe('which connection a report names', () => {
  test('one entry per address: one option each, and no hint', () => {
    const v = mount(one);
    expect(v.labels()).toEqual([A, B, 'Not sure']);
    expect(v.text()).not.toContain(HINT);
    v.pick(B);
    expect([props.connection, props.connectionEntry]).toEqual(['backup', null]);
  });

  test('an address the app holds twice: each entry is its own option, with the way out for an old app', () => {
    const v = mount(twice);
    expect(v.labels()).toEqual([EA, A, EB, B, 'Not sure']);
    expect(v.text()).toContain(HINT);

    v.pick(EA);
    expect([props.connection, props.connectionEntry]).toEqual(['primary', 'encrypted']);
    expect(v.checked()).toEqual([EA]);

    // The same address, the other entry: one option stays chosen.
    v.pick(A);
    expect([props.connection, props.connectionEntry]).toEqual(['primary', 'plain']);
    expect(v.checked()).toEqual([A]);

    v.pick('Not sure');
    expect([props.connection, props.connectionEntry]).toEqual(['unsure', null]);
    expect(v.checked()).toEqual(['Not sure']);
  });

  test('only the address handed out twice gets two options', () => {
    const v = mount([
      { label: EA, base: EA, role: 'primary', entry: 'encrypted' },
      { label: B, base: B, role: 'backup' },
      { label: A, base: A, role: 'primary', entry: 'plain' },
    ]);
    expect(v.labels()).toEqual([EA, A, B, 'Not sure']);
    v.pick(B);
    expect([props.connection, props.connectionEntry]).toEqual(['backup', null]);
  });

  test('an address handed out encrypted alone is one option: there is no second entry to tell apart', () => {
    // Alone, the encrypted entry has the address's name.
    const v = mount([{ label: A, base: A, role: 'primary', entry: 'encrypted' }]);
    expect(v.labels()).toEqual([A, 'Not sure']);
    expect(v.text()).not.toContain(HINT);
    v.pick(A);
    expect([props.connection, props.connectionEntry]).toEqual(['primary', null]);
  });
});
