/** Display names for render client families and body formats (pure). */
import type { EdgeRenderPreviewResponse, RenderClientFamily } from '@shared/contracts/edges';

export const FAMILY_LABELS: Record<RenderClientFamily, string> = {
  singbox: 'sing-box',
  mihomo: 'Mihomo / Clash',
  'xray-links': 'Xray links',
  happ: 'Happ',
  hiddify: 'Hiddify',
  streisand: 'Streisand',
  v2rayng: 'v2rayNG',
  other: 'Other clients',
};

export const FORMAT_LABELS: Record<EdgeRenderPreviewResponse['format'], string> = {
  links: 'share links',
  'singbox-json': 'sing-box JSON',
  'clash-yaml': 'Clash YAML',
};

const TIER_WORDS = ['works there', 'not known there', 'blocked there'];
const BAND_WORDS = { near: 'near', medium: 'medium distance', far: 'far' } as const;

/**
 * One endpoint's reason "as a member in <country>": its tier there, then, when
 * it applies, that its location is meant for the country and how far its whole
 * path is (latency ordering on). Null when there is no such endpoint.
 */
export function endpointWhy(
  tier: number | null | undefined,
  why: EdgeRenderPreviewResponse['primaryWhy'],
): string | null {
  if (tier === null || tier === undefined) return null;
  const parts = [TIER_WORDS[tier] ?? 'unknown'];
  if (why?.meantFor) parts.push('at a location meant for it');
  if (why?.audience?.length) parts.push(`only for ${why.audience.join(', ')}`);
  const l = why?.latency;
  if (l)
    parts.push(
      l.ms === null
        ? `${BAND_WORDS[l.band]} (no distance known)`
        : `${BAND_WORDS[l.band]} (about ${l.ms} ms over the whole path${l.measured ? ', timed from there' : ''})`,
    );
  return parts.join(', ');
}

/** "Addresses ordered for a member in <country>: the primary ..., the backup ...". */
export function orderedLine(
  countryLabel: string,
  data: Pick<EdgeRenderPreviewResponse, 'primaryTier' | 'backupTier' | 'primaryWhy' | 'backupWhy'>,
): string {
  const primary = endpointWhy(data.primaryTier, data.primaryWhy) ?? 'is unknown';
  const backup = endpointWhy(data.backupTier, data.backupWhy);
  return `Addresses ordered for a member in ${countryLabel}: the primary ${primary}${backup ? `, the backup ${backup}` : ''}.`;
}
