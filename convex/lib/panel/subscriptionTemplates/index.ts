/**
 * The panel's subscription templates FCP keeps in shape (pure). Moved from
 * the node role: the panel splices proxies into these bodies at the
 * "# LEAVE THIS LINE!" anchors, so the YAML ones travel BYTE-EXACT (`String.raw`,
 * compared as their base64 encoding, which is what the panel stores), and the
 * JSON one is compared structurally. A template the panel does not have is
 * skipped; the panel owns the type list.
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

/** Standard base64 of a UTF-8 string (the panel's `encodedTemplateYaml`). */
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

/** The hash of what the panel holds, in the same terms, or null when it holds nothing. */
export async function liveTemplateHash(live: {
  templateJson: unknown | null;
  encodedTemplateYaml: string | null;
}): Promise<string | null> {
  if (live.templateJson !== null && live.templateJson !== undefined)
    return sha256Hex(canonicalJson(live.templateJson));
  if (live.encodedTemplateYaml) {
    const bin = atob(live.encodedTemplateYaml);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return sha256Hex(new TextDecoder().decode(bytes));
  }
  return null;
}
