<script lang="ts">
  import { resolvePrimaryRgb } from '../lib/oklch';

  /**
   * The brand's signature texture as a backdrop: a single Bayer-dithered
   * radial mass of `--primary` on a LOW-RES backing canvas, upscaled with
   * `image-rendering: pixelated` - same technique as DitherChart, but a
   * static field instead of a chart. Off-cells are TRUE holes (the page
   * background shows through), so the mass dissolves outward like light
   * falling off, rendered in chunky ordered-dither pixels.
   *
   * Used sparingly by design: the Home hero backdrop, and the dithered
   * empty-state disc. Static - no animation, so the reduced-motion clamp has
   * nothing to neutralize. Decorative: aria-hidden.
   *
   * The root element IS the <canvas> - callers position it via `class`
   * (e.g. "absolute -inset-x-6 -top-8 bottom-0 -z-10"); the parent provides
   * the containing block. Redraws on mount and on <html class> mutation
   * (dark-mode toggle); the admin brand hue applies on next page load (the
   * theme-init replay), same as every other token-derived style. RTL mirrors
   * the anchor so the mass stays anchored to the inline-start side.
   */
  interface Props {
    /** Falloff center, normalized [0..1] within the box (x pre-mirroring). */
    anchor?: { x: number; y: number };
    /** Falloff radius, in box-height units (the mass reaches 0 at this distance). */
    radius?: number;
    /** Peak alpha at the anchor, per theme. */
    alphaLight?: number;
    alphaDark?: number;
    /** CSS px per dither cell (bigger = chunkier pixels). */
    cell?: number;
    class?: string;
  }
  let {
    anchor = { x: 0.35, y: 0.3 },
    radius = 0.75,
    alphaLight = 0.14,
    alphaDark = 0.22,
    cell = 3,
    class: klass = '',
  }: Props = $props();

  // 4×4 ordered (Bayer) threshold matrix, normalized to 0–1.
  const BAYER = [
    [0, 8, 2, 10],
    [12, 4, 14, 6],
    [3, 11, 1, 9],
    [15, 7, 13, 5],
  ].map((row) => row.map((v) => (v + 0.5) / 16));

  // Emerald midpoint used only if the token can't be resolved (very old engines).
  const FALLBACK_RGB: [number, number, number] = [82, 179, 135];

  let canvas = $state<HTMLCanvasElement | null>(null);

  function draw() {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    if (!w || !h) return;
    const cols = Math.max(8, Math.round(w / cell));
    const rows = Math.max(8, Math.round(h / cell));
    canvas.width = cols;
    canvas.height = rows;
    const maxA = document.documentElement.classList.contains('dark') ? alphaDark : alphaLight;
    const [r, g, b] = resolvePrimaryRgb() ?? FALLBACK_RGB;
    // Distances in pixel space: x runs 0..aspect, y runs 0..1.
    const aspect = cols / rows;
    const ax = (document.dir === 'rtl' ? 1 - anchor.x : anchor.x) * aspect;
    const ay = anchor.y;
    for (let y = 0; y < rows; y++) {
      for (let x = 0; x < cols; x++) {
        const nx = ((x + 0.5) / cols) * aspect;
        const ny = (y + 0.5) / rows;
        const dx = nx - ax;
        const dy = ny - ay;
        const t = Math.min(1, Math.sqrt(dx * dx + dy * dy) / radius);
        // smoothstep falloff: 1 at the anchor, easing to 0 at `radius`.
        const f = 1 - t * t * (3 - 2 * t);
        if (f <= 0) continue;
        if (f <= (BAYER[y & 3]?.[x & 3] ?? 0.5)) continue;
        ctx.fillStyle = `rgba(${r},${g},${b},${(f * maxA).toFixed(3)})`;
        ctx.fillRect(x, y, 1, 1);
      }
    }
  }

  $effect(() => {
    void anchor;
    void radius;
    void alphaLight;
    void alphaDark;
    void cell;
    draw();
    // Dark-mode toggle flips the `dark` class on <html>; redraw with the
    // other theme step's token + alpha cap.
    const mo = new MutationObserver(draw);
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
    return () => mo.disconnect();
  });
</script>

<canvas
  bind:this={canvas}
  class="block {klass}"
  style="image-rendering: pixelated;"
  aria-hidden="true"
></canvas>
