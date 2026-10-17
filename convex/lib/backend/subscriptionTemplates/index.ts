/**
 * The backend's subscription templates FCP keeps in shape (pure). Moved from
 * the node role: the backend splices proxies into these bodies at the
 * "# LEAVE THIS LINE!" anchors, so the YAML ones travel BYTE-EXACT (`String.raw`,
 * compared as their base64 encoding, which is what the backend stores), and the
 * JSON one is compared structurally. A template the backend does not have is
 * skipped; the backend owns the type list.
 */
import { sha256Hex } from '../../crypto';
import { canonicalJson } from '../digest';
import { CLASH_YAML } from './CLASH';
import { MIHOMO_YAML } from './MIHOMO';
import { SINGBOX_JSON } from './SINGBOX';
import { STASH_YAML } from './STASH';

export type TemplateFamily = 'SINGBOX' | 'MIHOMO' | 'STASH' | 'CLASH';
export const TEMPLATE_FAMILIES: readonly TemplateFamily[] = ['SINGBOX', 'MIHOMO', 'STASH', 'CLASH'];

export type DesiredTemplate = { kind: 'json'; body: unknown } | { kind: 'yaml'; body: string };

export const SUBSCRIPTION_TEMPLATES: Readonly<Record<TemplateFamily, DesiredTemplate>> = {
  SINGBOX: { kind: 'json', body: SINGBOX_JSON },
  MIHOMO: { kind: 'yaml', body: MIHOMO_YAML },
  STASH: { kind: 'yaml', body: STASH_YAML },
  CLASH: { kind: 'yaml', body: CLASH_YAML },
};

/** Standard base64 of a UTF-8 string (the backend's `encodedTemplateYaml`). */
export function base64Utf8(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** The PATCH body that installs a desired template. */
export function desiredTemplateBody(
  d: DesiredTemplate,
): { templateJson: unknown } | { encodedTemplateYaml: string } {
  return d.kind === 'json' ? { templateJson: d.body } : { encodedTemplateYaml: base64Utf8(d.body) };
}

/** Whether the live template differs from the desired one. */
export function templateDrift(
  live: { templateJson: unknown | null; encodedTemplateYaml: string | null },
  desired: DesiredTemplate,
): boolean {
  if (desired.kind === 'json')
    return canonicalJson(live.templateJson ?? null) !== canonicalJson(desired.body);
  return (live.encodedTemplateYaml ?? '') !== base64Utf8(desired.body);
}

/** A stable hash of a template body (what activation evidence records). */
export async function templateHash(d: DesiredTemplate): Promise<string> {
  return sha256Hex(d.kind === 'json' ? canonicalJson(d.body) : d.body);
}

/** The hash of every template FCP ships today, by family. */
export async function shippedTemplateHashes(): Promise<Record<TemplateFamily, string>> {
  const out = {} as Record<TemplateFamily, string>;
  for (const f of TEMPLATE_FAMILIES) out[f] = await templateHash(SUBSCRIPTION_TEMPLATES[f]);
  return out;
}

/**
 * Whether a backend's recorded templates need installing again: one is not
 * matched, or was matched under a template FCP no longer ships (a release
 * changed it). A family FCP no longer ships is judged by its state alone.
 */
export function templatesOutdated(
  recorded: readonly { family: string; hash: string; state: string }[],
  shipped: Readonly<Record<string, string>>,
): boolean {
  return recorded.some(
    (t) => t.state !== 'matched' || (t.family in shipped && t.hash !== shipped[t.family]),
  );
}

/**
 * The record a re-sync starts from: an entry FCP now ships differently takes
 * the new hash, not matched, before anything is written; the rest stay.
 */
export function stageShippedTemplates<
  T extends { family: string; hash: string; state: 'matched' | 'drifted' | 'refused' },
>(recorded: readonly T[], shipped: Readonly<Record<string, string>>): T[] {
  return recorded.map((t) =>
    t.family in shipped && t.hash !== shipped[t.family]
      ? { ...t, hash: shipped[t.family]!, state: 'drifted' }
      : t,
  );
}
