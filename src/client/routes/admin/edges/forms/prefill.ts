/**
 * What the new-origin dialog can be opened with: the guided setup's draft fits
 * (`StoredDraft` in setup/draft.ts is this shape).
 *
 * Exports:
 *   RelayPrefill
 *   suggestListenerKey(form, taken)     a free key derived from what the listener speaks
 *   relaySlugIssue(slug)                why a slug is unusable, in words (null = fine)
 */
import type { OriginDraft } from './origin';
import { formCombo, type ListenerForm } from './listenerForm';

export interface RelayPrefill {
  origin: OriginDraft | null;
  listeners: ListenerForm[];
}

export function suggestListenerKey(
  form: Pick<ListenerForm, 'combo'>,
  taken: readonly string[],
): string {
  const c = formCombo(form);
  const base =
    c.security === 'reality'
      ? 'reality'
      : c.streamTransport === 'raw'
        ? c.protocol === 'shadowsocks'
          ? 'ss'
          : c.protocol
        : c.streamTransport === 'udp'
          ? c.protocol
          : c.streamTransport;
  const stem = base.replace(/[^a-z0-9]/g, '').slice(0, 14);
  if (!taken.includes(stem)) return stem;
  for (let i = 2; i < 100; i++) if (!taken.includes(`${stem}${i}`)) return `${stem}${i}`;
  return stem;
}

const SLUG_RE = /^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$/;
export function relaySlugIssue(slug: string): string | null {
  const s = slug.trim();
  if (s === '') return 'Enter a slug.';
  if (!SLUG_RE.test(s))
    return 'Use lowercase letters, digits and dashes (at most 48 characters, no dash at either end).';
  return null;
}
