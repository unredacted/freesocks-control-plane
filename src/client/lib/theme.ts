/**
 * Client theme system (W3-3). The brand palette is admin-selectable: a curated
 * preset + an optional hue override. This module owns the actual oklch values
 * and the runtime applier; the server (convex/lib/themeConfig.ts) only validates
 * the preset id + hue and serves them via publicConfig.
 *
 * How it applies: we inject a single `<style id="fs-theme">` that redefines
 * `--primary` + `--ring` for `:root` (light) and `.dark`. That element is
 * UNLAYERED, so it wins over globals.css's `@layer base` token defaults
 * regardless of specificity — and the `.dark` rule (declared after `:root`)
 * handles dark mode without the applier needing to react to mode toggles.
 *
 * Only hue/chroma/lightness of the brand tokens change between presets; the
 * hue override rotates hue ONLY (keeping the preset's AA-tuned L/C), so any
 * choice stays readable. THEME_PRESETS' `emerald` mirrors the baked default in
 * globals.css. Keep the ids in sync with convex/lib/themeConfig.ts.
 */
export interface ThemePreset {
  id: string;
  label: string;
  /** A representative swatch colour for the picker gallery. */
  swatch: string;
  hue: number;
  chroma: number;
  ringChroma: number;
  primaryL: { light: number; dark: number };
  ringL: { light: number; dark: number };
  /** The hue slider applies only to chromatic presets (not monochrome Classic). */
  hueAdjustable: boolean;
}

export const THEME_PRESETS: ThemePreset[] = [
  {
    id: 'emerald',
    label: 'Emerald',
    swatch: 'oklch(0.6 0.13 158)',
    hue: 158,
    chroma: 0.13,
    ringChroma: 0.1,
    primaryL: { light: 0.52, dark: 0.72 },
    ringL: { light: 0.58, dark: 0.64 },
    hueAdjustable: true,
  },
  {
    id: 'teal',
    label: 'Teal',
    swatch: 'oklch(0.62 0.1 210)',
    hue: 210,
    chroma: 0.1,
    ringChroma: 0.085,
    primaryL: { light: 0.54, dark: 0.74 },
    ringL: { light: 0.6, dark: 0.66 },
    hueAdjustable: true,
  },
  {
    id: 'indigo',
    label: 'Indigo',
    swatch: 'oklch(0.55 0.13 280)',
    hue: 280,
    chroma: 0.12,
    ringChroma: 0.1,
    primaryL: { light: 0.52, dark: 0.7 },
    ringL: { light: 0.58, dark: 0.64 },
    hueAdjustable: true,
  },
  {
    id: 'classic',
    label: 'Classic',
    swatch: 'oklch(0.55 0 0)',
    hue: 0,
    chroma: 0,
    ringChroma: 0,
    primaryL: { light: 0.205, dark: 0.922 },
    ringL: { light: 0.708, dark: 0.556 },
    hueAdjustable: false,
  },
];

export const DEFAULT_THEME_PRESET = 'emerald';

const STYLE_ID = 'fs-theme';
export const THEME_LS_KEY = 'fs_theme';
export const THEME_CSS_LS_KEY = 'fs_theme_css';

export function presetById(id: string): ThemePreset {
  return THEME_PRESETS.find((p) => p.id === id) ?? THEME_PRESETS[0]!;
}

/** The hue actually used to render a preset (the override when allowed, else the
 *  preset's own hue). */
export function effectiveHue(presetId: string, hue: number | null): number {
  const p = presetById(presetId);
  if (p.hueAdjustable && hue != null && Number.isFinite(hue)) return ((hue % 360) + 360) % 360;
  return p.hue;
}

/** Build the `:root` + `.dark` override CSS for a preset (+ optional hue). Pure. */
export function themeCss(presetId: string, hue: number | null): string {
  const p = presetById(presetId);
  const h = effectiveHue(presetId, hue);
  const primary = (l: number) => `oklch(${l} ${p.chroma} ${h})`;
  const ring = (l: number) => `oklch(${l} ${p.ringChroma} ${h})`;
  return (
    `:root{--primary:${primary(p.primaryL.light)};--ring:${ring(p.ringL.light)}}` +
    `.dark{--primary:${primary(p.primaryL.dark)};--ring:${ring(p.ringL.dark)}}`
  );
}

/** Inject/replace the override <style> WITHOUT persisting — for live preview. */
export function applyThemeCss(css: string): void {
  if (typeof document === 'undefined') return;
  let el = document.getElementById(STYLE_ID) as HTMLStyleElement | null;
  if (!el) {
    el = document.createElement('style');
    el.id = STYLE_ID;
    document.head.appendChild(el);
  }
  el.textContent = css;
}

/** Apply a theme AND cache it for the next load's flash-free replay (theme-init.js). */
export function applyTheme(presetId: string, hue: number | null): void {
  const css = themeCss(presetId, hue);
  applyThemeCss(css);
  try {
    localStorage.setItem(THEME_LS_KEY, JSON.stringify({ preset: presetId, hue }));
    localStorage.setItem(THEME_CSS_LS_KEY, css);
  } catch {
    /* private mode: skip caching; the live <style> still applies this session */
  }
}
