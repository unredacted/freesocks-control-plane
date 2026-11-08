import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, tick, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { approveNode, reviewQuery } from '@client/lib/serversApi';
import { mountWithQuery } from '../../../../testing/mountWithQuery';
import NodeApprovalCard from './NodeApprovalCard.svelte';

vi.mock('@client/lib/serversApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/serversApi')>()),
  approveNode: vi.fn(),
  reviewQuery: vi.fn(),
}));

/** What the review route answers for a live fronted node gaining its first edges. */
function reviewWith(blockers: string[], atOnce: 'kept' | 'external' | null = null) {
  return {
    isPending: false,
    isError: false,
    error: null,
    refetch: () => Promise.resolve(),
    data: {
      reviewHash: 'h1',
      blockers,
      stage: 'candidates_verified',
      shape: {
        listeners: [],
        addressTuples: [],
        configRevision: 'abcdef12',
        subscriptionTemplates: {},
      },
      display: {
        standbys: [
          {
            listenerKey: 'ws',
            layer: 'l7',
            endpoint: 'front-a.example.org:443',
            accountName: 'CDN',
            locationLabel: 'Anycast',
          },
        ],
        atOnce,
      },
    },
  };
}

let client: QueryClient;
let app: ReturnType<typeof mountWithQuery> | null = null;

function mount(blockers: string[], atOnce: 'kept' | 'external' | null = null) {
  vi.mocked(reviewQuery).mockReturnValue(reviewWith(blockers, atOnce) as never);
  vi.mocked(approveNode).mockReset().mockResolvedValue({ runId: 'run1' });
  client = new QueryClient();
  app = mountWithQuery(client, NodeApprovalCard, {
    slug: 'panel',
    intentId: 'i1',
    nodeName: 'node-a',
    fronted: true,
  });
  flushSync();
}
afterEach(() => {
  if (app) unmount(app);
  app = null;
  client.clear();
});

const button = (label: string) =>
  [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === label);

describe('What you approve', () => {
  test('a live node that needs its gate closed is approved in one step, which closes it itself', async () => {
    mount(['servers.maintenance_required']);
    expect(button('Start maintenance')).toBeUndefined();
    const approve = button('Approve go-live')!;
    expect(approve.disabled).toBe(false);
    expect(document.body.textContent).toMatch(
      /Approving closes this node to members for about a minute/,
    );
    expect(document.querySelector('.text-amber-700')).toBeNull();

    approve.click();
    flushSync();
    await tick();
    expect(document.body.textContent).toMatch(
      /This closes node-a to members for about a minute, until it goes live/,
    );
    const input = document.querySelector<HTMLInputElement>('[role="alertdialog"] input')!;
    input.value = 'node-a';
    input.dispatchEvent(new Event('input', { bubbles: true }));
    flushSync();
    [...document.querySelectorAll<HTMLButtonElement>('[role="alertdialog"] button')]
      .find((b) => b.textContent?.trim() === 'Approve go-live')!
      .click();
    await vi.waitFor(() => expect(approveNode).toHaveBeenCalled());
    expect(vi.mocked(approveNode).mock.lastCall).toEqual(['panel', 'i1', 'h1', true]);
  });

  test('another blocker still keeps Approve off, and is named', () => {
    mount(['servers.maintenance_required', 'servers.template_drifted']);
    expect(button('Approve go-live')!.disabled).toBe(true);
    const amber = document.querySelector('.text-amber-700')!;
    expect(amber.textContent).not.toMatch(/Approving closes/);
    expect(amber.textContent?.length).toBeGreaterThan(0);
  });

  test('with nothing to close, the approval sends no gate change', async () => {
    mount([]);
    expect(document.body.textContent).not.toMatch(/Approving closes/);
    button('Approve go-live')!.click();
    flushSync();
    await tick();
    const input = document.querySelector<HTMLInputElement>('[role="alertdialog"] input')!;
    input.value = 'node-a';
    input.dispatchEvent(new Event('input', { bubbles: true }));
    flushSync();
    [...document.querySelectorAll<HTMLButtonElement>('[role="alertdialog"] button')]
      .find((b) => b.textContent?.trim() === 'Approve go-live')!
      .click();
    await vi.waitFor(() => expect(approveNode).toHaveBeenCalled());
    expect(vi.mocked(approveNode).mock.lastCall).toEqual(['panel', 'i1', 'h1', false]);
  });

  test('after a maintenance with its tests current, it reopens on the addresses it has, at once', async () => {
    mount([], 'kept');
    expect(document.body.textContent).toMatch(
      /Approve reopens it on the addresses it already has. Nothing new is bought./,
    );
    expect(document.body.textContent).toMatch(/members get front-a\.example\.org:443/);
    button('Approve go-live')!.click();
    flushSync();
    await tick();
    const dialog = document.querySelector('[role="alertdialog"]')!;
    expect(dialog.textContent).toMatch(/through the addresses it already has/);
    expect(dialog.textContent).not.toMatch(/rehearses/);
    const input = dialog.querySelector<HTMLInputElement>('input')!;
    input.value = 'node-a';
    input.dispatchEvent(new Event('input', { bubbles: true }));
    flushSync();
    [...dialog.querySelectorAll<HTMLButtonElement>('button')]
      .find((b) => b.textContent?.trim() === 'Approve go-live')!
      .click();
    await vi.waitFor(() => expect(approveNode).toHaveBeenCalled());
    await vi.waitFor(() => expect(document.body.textContent).toMatch(/It is live again\./));
  });
});
