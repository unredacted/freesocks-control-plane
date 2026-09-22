/**
 * Attention items -> what the row says and where its button goes (pure).
 *
 * Every `AttentionAction` literal is classified here:
 *   - navigate: a pure navigation, AttentionList performs it itself.
 *   - call:     a server call; AttentionList hands the item to `onAction`
 *               (after a ConfirmDialog when `confirm` is set).
 * The `satisfies Record<AttentionAction, …>` makes a new server action fail typecheck.
 *
 * Exports: attentionTarget(item), ATTENTION_ACTION_PLAN, attentionSubject(item),
 *          attentionFactsLine(item), AttentionPlan, AttentionConfirmCopy.
 */
import type { z } from 'zod';
import type { AttentionItem as AttentionItemSchema } from '../../../../../shared/contracts/edges';
import type { AttentionAction } from '../../../../../shared/contracts/edgeCodes';
import { edgesPaths } from './routes';
import { durationLabel } from './time';

export type AttentionItem = z.infer<typeof AttentionItemSchema>;

export interface AttentionConfirmCopy {
  title: string;
  body: string;
  confirmLabel: string;
  danger: boolean;
}
export type AttentionPlan =
  | { type: 'navigate' }
  | { type: 'call'; confirm: AttentionConfirmCopy | null };

export const ATTENTION_ACTION_PLAN = {
  resolve_quarantine: { type: 'navigate' },
  resolve_operator: { type: 'navigate' },
  look_at_host: { type: 'navigate' },
  open_setup: { type: 'navigate' },
  open_relay: { type: 'navigate' },
  open_edge: { type: 'navigate' },
  open_account: { type: 'navigate' },
  open_settings: { type: 'navigate' },
  publish: {
    type: 'call',
    confirm: {
      title: 'Publish this edge?',
      body: 'Members of this origin start receiving the edge address on their next subscription refresh.',
      confirmLabel: 'Publish',
      danger: false,
    },
  },
  provision: {
    type: 'call',
    confirm: {
      title: 'Provision a new edge?',
      body: 'This creates a billable resource at the provider and counts against the account budget for today.',
      confirmLabel: 'Provision',
      danger: false,
    },
  },
  qualify_front: { type: 'call', confirm: null },
  rotate: {
    type: 'call',
    confirm: {
      title: 'Replace this edge?',
      body: 'A new edge is provisioned and published, then the current one drains and is destroyed. Members move over on their next subscription refresh.',
      confirmLabel: 'Replace edge',
      danger: true,
    },
  },
  test_credentials: { type: 'call', confirm: null },
  // The endpoint test is a card (import the test link, connect, tick), never a
  // one-click call: the tick must echo the binding the operator was shown. A
  // host page that offers `onAction` opens the card in place; without one the
  // row navigates to the node page, which opens the same card.
  verify_endpoint: { type: 'call', confirm: null },
  thaw: {
    type: 'call',
    confirm: {
      title: 'Resume edge work?',
      body: 'Provisioning, publishing and automatic rotation are allowed again for the whole fleet.',
      confirmLabel: 'Resume',
      danger: false,
    },
  },
  rebalance: {
    type: 'call',
    confirm: {
      title: 'Make room for the listener?',
      body: 'One duplicate edge goes back to standby so the uncovered listener can be published. Members using that edge move to another one on their next subscription refresh.',
      confirmLabel: 'Make room',
      danger: true,
    },
  },
  // Go-live applies the activation policy: the host page calls `require-edges`
  // and renders the test card for whatever comes back pending. Without
  // `onAction` the row navigates to the node page, which offers the same button.
  require_edges: { type: 'call', confirm: null },
} as const satisfies Record<AttentionAction, AttentionPlan>;

/**
 * Where the action's button leads. For `navigate` actions this IS the action;
 * for `call` actions it is the page where the operator can do the same thing
 * by hand (used as the fallback when the host page passes no `onAction`).
 */
export function attentionTarget(item: AttentionItem): string {
  const slug = item.relaySlug;
  const relay = (params: Parameters<typeof edgesPaths.relay>[1]) =>
    slug ? edgesPaths.relay(slug, params) : edgesPaths.home();
  switch (item.action) {
    case 'resolve_quarantine':
      return relay({ tab: 'rotations', rotation: item.rotationId });
    case 'resolve_operator':
    case 'open_edge':
    case 'publish':
    case 'qualify_front':
    case 'rotate':
      return relay({ tab: 'edges', edge: item.edgeId });
    // The simple node page renders the test card (`?test=<edgeId>`) and the go-live button.
    case 'verify_endpoint':
      return slug ? edgesPaths.node(slug, { test: item.edgeId }) : edgesPaths.home();
    case 'require_edges':
      return slug ? edgesPaths.node(slug) : edgesPaths.home();
    case 'look_at_host':
      return relay({ tab: 'listeners', listener: item.listenerKey });
    case 'provision':
      return relay({ tab: 'edges' });
    case 'open_relay':
      return relay(item.rotationId ? { tab: 'rotations', rotation: item.rotationId } : undefined);
    case 'open_setup':
      return edgesPaths.setup({ relay: slug });
    case 'open_account':
    case 'test_credentials':
      return item.accountId ? edgesPaths.provider(item.accountId) : edgesPaths.providers();
    case 'open_settings':
      return edgesPaths.settings();
    case 'thaw':
      return edgesPaths.settings({ section: 'maintenance' });
    case 'rebalance':
      return relay({ tab: 'edges' });
  }
}

/** What the row is about, in words: "origin <slug>", plus the listener when known. */
export function attentionSubject(item: AttentionItem): string {
  const parts: string[] = [];
  if (item.relaySlug) parts.push(`Origin ${item.relaySlug}`);
  if (item.listenerKey) parts.push(`listener ${item.listenerKey}`);
  return parts.join(', ');
}

/**
 * The small facts of a row as one line. Only well-known keys are rendered
 * (counts, country codes, ages); anything else in `facts` is ignored so a new
 * server fact never shows up as a raw key.
 */
export function attentionFactsLine(item: AttentionItem): string {
  const f = item.facts;
  const out: string[] = [];
  const num = (k: string): number | null => (typeof f[k] === 'number' ? (f[k] as number) : null);
  const str = (k: string): string | null =>
    typeof f[k] === 'string' && f[k] !== '' ? (f[k] as string) : null;
  const name = str('name');
  if (name !== null) out.push(`Account ${name}`);
  const kind = str('kind');
  if (kind !== null) out.push(`${kind.charAt(0).toUpperCase()}${kind.slice(1)} run`);
  const op = str('op');
  if (op !== null) out.push(op === 'create' ? 'Creating the Host' : 'Deleting the Host');
  const published = num('published');
  const desired = num('desired');
  if (published !== null && desired !== null) out.push(`${published} of ${desired} published`);
  const standbys = num('standbys');
  if (standbys !== null && standbys > 0)
    out.push(`${standbys} ${standbys === 1 ? 'standby' : 'standbys'} ready`);
  const count = num('count');
  if (count !== null) out.push(`${count} affected`);
  const attempts = num('attempts');
  if (attempts !== null) out.push(`${attempts} ${attempts === 1 ? 'attempt' : 'attempts'}`);
  const ageMs = num('ageMs');
  if (ageMs !== null) out.push(`for ${durationLabel(ageMs)}`);
  const countries = f['countries'];
  if (Array.isArray(countries) && countries.length > 0) {
    const codes = countries.filter((c): c is string => typeof c === 'string').slice(0, 6);
    if (codes.length > 0) out.push(`in ${codes.join(', ')}`);
  }
  return out.join(' · ');
}
