/**
 * Built-in copy + icons for the shipped connection modes, keyed by FAMILY id and
 * by LEAF id. Shared by DeliveryPreference (the picker) and ConnectionModeSwitcher
 * (the confirm dialog + toasts) so the two can never drift — they used to carry
 * separate hardcoded maps and disagreed on what a mode was called.
 *
 * Resolution order everywhere: an admin-set catalog label/description (verbatim,
 * all locales) → the built-in i18n key below → the raw id as a last resort. A
 * novel mode with no entry here therefore only needs an admin-set label to be
 * presentable.
 */
import ShieldCheck from '@lucide/svelte/icons/shield-check';
import Zap from '@lucide/svelte/icons/zap';
import type { Component } from 'svelte';
import { t, type MessageKey } from './i18n/index.svelte';

export interface FamilyCopy {
  icon: Component;
  titleKey: MessageKey;
  bodyKey: MessageKey;
  /** The who-is-this-for chip. Named separately from the body because an admin
   *  label/description override replaces the copy but not the audience. */
  audienceKey: MessageKey;
}

export const FAMILY_COPY: Record<string, FamilyCopy> = {
  freedom: {
    icon: Zap,
    titleKey: 'delivery.freedomTitle',
    bodyKey: 'delivery.freedomBody',
    audienceKey: 'delivery.freedomAudience',
  },
  privacy: {
    icon: ShieldCheck,
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
}
interface ModeLike {
  id: string;
  family?: string;
  label?: string | null;
  description?: string | null;
}

export function familyTitle(f: FamilyLike): string {
  if (f.label?.trim()) return f.label;
  return FAMILY_COPY[f.id] ? t(FAMILY_COPY[f.id]!.titleKey) : f.id;
}
export function familyBody(f: FamilyLike): string {
  if (f.description?.trim()) return f.description;
  return FAMILY_COPY[f.id] ? t(FAMILY_COPY[f.id]!.bodyKey) : '';
}
export function familyIcon(f: FamilyLike): Component {
  return FAMILY_COPY[f.id]?.icon ?? Zap;
}

export function modeTitle(m: ModeLike): string {
  if (m.label?.trim()) return m.label;
  return MODE_COPY[m.id] ? t(MODE_COPY[m.id]!.titleKey) : m.id;
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
