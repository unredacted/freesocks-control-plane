/**
 * Built-in copy for the SHIPPED connection modes, keyed by FAMILY id and by
 * LEAF id, plus the resolution helpers every mode surface renders through.
 * Shared by DeliveryPreference (the picker) and ConnectionModeSwitcher (the
 * confirm dialog + toasts) so the two can never drift.
 *
 * Resolution order everywhere: an admin-set catalog label/description
 * (verbatim, all locales) → the built-in i18n key below → a HUMANIZED slug as
 * the last resort (raw ids must never render; the CMS requires a label on
 * admin-created ids, so the humanizer only covers deploy skew and legacy
 * rows). Icons live in connectionModeIcons.ts (an open iconId registry,
 * .svelte-bearing — deliberately NOT imported here so this module stays
 * loadable in pure-TS tests) and ride the wire per family.
 */
import { t, type MessageKey } from './i18n/index.svelte';
import { humanizeSlug } from './humanize';

export { humanizeSlug } from './humanize';

export interface FamilyCopy {
  titleKey: MessageKey;
  bodyKey: MessageKey;
  /** The who-is-this-for chip. Named separately from the body because an admin
   *  label/description override replaces the copy but not the audience. */
  audienceKey: MessageKey;
}

export const FAMILY_COPY: Record<string, FamilyCopy> = {
  freedom: {
    titleKey: 'delivery.freedomTitle',
    bodyKey: 'delivery.freedomBody',
    audienceKey: 'delivery.freedomAudience',
  },
  privacy: {
    titleKey: 'delivery.privacyTitle',
    bodyKey: 'delivery.privacyBody',
    audienceKey: 'delivery.privacyAudience',
  },
};

export const MODE_COPY: Record<string, { titleKey: MessageKey; bodyKey: MessageKey }> = {
  'freedom-ws': { titleKey: 'delivery.freedomWsTitle', bodyKey: 'delivery.freedomWsBody' },
  'freedom-reality': {
    titleKey: 'delivery.freedomRealityTitle',
    bodyKey: 'delivery.freedomRealityBody',
  },
  'privacy-reality': {
    titleKey: 'delivery.privacyRealityTitle',
    bodyKey: 'delivery.privacyRealityBody',
  },
};

interface FamilyLike {
  id: string;
  label?: string | null;
  description?: string | null;
  audience?: string | null;
}
interface ModeLike {
  id: string;
  family?: string | null;
  label?: string | null;
  description?: string | null;
}

export function familyTitle(f: FamilyLike): string {
  if (f.label?.trim()) return f.label;
  return FAMILY_COPY[f.id] ? t(FAMILY_COPY[f.id]!.titleKey) : humanizeSlug(f.id);
}
export function familyBody(f: FamilyLike): string {
  if (f.description?.trim()) return f.description;
  return FAMILY_COPY[f.id] ? t(FAMILY_COPY[f.id]!.bodyKey) : '';
}
/** The audience chip: admin-set text → built-in i18n → none (''). A DB-created
 *  family gets a chip exactly when the admin typed one. */
export function familyAudience(f: FamilyLike): string {
  if (f.audience?.trim()) return f.audience;
  return FAMILY_COPY[f.id] ? t(FAMILY_COPY[f.id]!.audienceKey) : '';
}
export function modeTitle(m: ModeLike): string {
  if (m.label?.trim()) return m.label;
  return MODE_COPY[m.id] ? t(MODE_COPY[m.id]!.titleKey) : humanizeSlug(m.id);
}
export function modeBody(m: ModeLike): string {
  if (m.description?.trim()) return m.description;
  return MODE_COPY[m.id] ? t(MODE_COPY[m.id]!.bodyKey) : '';
}

/**
 * The name to show when a mode is referenced OUTSIDE the picker (confirm dialog,
 * toasts, audit-facing copy). Qualified with its family so "REALITY" alone is
 * never ambiguous — two families can each have a REALITY transport.
 */
export function qualifiedModeLabel(m: ModeLike, families: FamilyLike[]): string {
  const leaf = modeTitle(m);
  const family = m.family ? families.find((f) => f.id === m.family) : undefined;
  if (!family) return leaf;
  const parent = familyTitle(family);
  return parent && parent !== leaf ? `${parent} - ${leaf}` : leaf;
}
