/**
 * The curated family-icon id set — a PURE module (no .svelte imports) so the
 * admin editor's <select> options and unit tests can consume it without
 * loading component files. The components themselves live in
 * connectionModeIcons.ts, whose Record over this union enforces that every id
 * here has an icon (and vice versa) at compile time.
 */
export const MODE_ICON_IDS = [
  'zap',
  'shield-check',
  'shield',
  'globe',
  'lock',
  'eye-off',
  'wifi',
  'rocket',
  'layers',
  'gauge',
  'satellite-dish',
  'waves',
] as const;

export type ModeIconId = (typeof MODE_ICON_IDS)[number];

export const DEFAULT_MODE_ICON_ID: ModeIconId = 'zap';

export function isModeIconId(v: unknown): v is ModeIconId {
  return typeof v === 'string' && (MODE_ICON_IDS as readonly string[]).includes(v);
}
