<script lang="ts">
  /**
   * Dependency-free dithered chart: a hand-rolled ordered-dither (4×4 Bayer)
   * fill on a LOW-RES backing <canvas>, upscaled with `image-rendering:
   * pixelated` — the chunky pixel texture is the aesthetic. No chart library
   * (keeps the bundle lean and the CSP pure-'self'; same rationale as
   * Sparkline.svelte). Every cell is the single `color` varying ONLY its alpha
   * (dense at the floor, dissolving toward the value line, with a soft top
   * border row), so the same fill reads correctly on light AND dark themes.
   *
   * `color` must be a #rrggbb hex: oklch() theme tokens silently fail in
   * canvas on older engines (the documented QrCode.svelte gotcha), and this
   * audience realistically runs them. Default approximates --donation-gold.
   *
   * Static by design — no entrance animation, so the global reduced-motion
   * clamp has nothing to neutralize. Decorative: the numeric stats beside it
   * are the accessible signal; `ariaLabel` summarizes the series for AT.
   */
  interface Props {
    /** Series values, left→right (e.g. bonus GB per month). */
    values: number[];
    /** Optional per-point labels; first + last render under the chart. */
    labels?: string[];
    /** 'bars' = one dithered column per value (discrete months); 'area' = a
     *  continuous dithered slope sampled across the width. */
    variant?: 'bars' | 'area';
    /** Backing-resolution basis in CSS px (the canvas stretches to its box). */
    width?: number;
    height?: number;
    /** #rrggbb fill (hex only — see the oklch note above). */
    color?: string;
    /** Explicit scale ceiling; defaults to max(values, 1). */
    max?: number;
    ariaLabel: string;
    class?: string;
  }
  let {
    values,
    labels = [],
    variant = 'bars',
    width = 320,
    height = 96,
    color = '#e3b34d',
    max,
    ariaLabel,
    class: klass = '',
  }: Props = $props();

  // CSS px per dither cell — chunky enough to read pixelated once upscaled.
  const CELL = 2;
  // 4×4 ordered (Bayer) threshold matrix, normalized to 0–1.
  const BAYER = [
    [0, 8, 2, 10],
    [12, 4, 14, 6],
    [3, 11, 1, 9],
    [15, 7, 13, 5],
  ].map((row) => row.map((v) => (v + 0.5) / 16));
  // Alpha of a dither "off" cell relative to an "on" cell: a faint tint of the
  // SAME color instead of a hole, so the background never punches through.
  const OFF_TIER = 0.4;
  const BORDER_ALPHA = 0.72;

  let canvas = $state<HTMLCanvasElement | null>(null);

  function hexToRgb(hex: string): [number, number, number] {
    const m = /^#?([0-9a-f]{6})$/i.exec(hex);
    const n = m?.[1] ? parseInt(m[1], 16) : 0xe3b34d;
    return [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
  }

  /** Fill one backing column from the value line (`top`) down to the floor:
   *  density rises toward the floor and drives both the Bayer threshold and
   *  the alpha, then a soft border row caps the top edge. */
  function paintColumn(
    octx: CanvasRenderingContext2D,
    x: number,
    top: number,
    rows: number,
    rgb: [number, number, number],
  ) {
    const floor = rows - 1;
    const depth = floor - top;
    const paint = (y: number, alpha: number) => {
      octx.fillStyle = `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${alpha})`;
      octx.fillRect(x, y, 1, 1);
    };
    for (let y = top + 1; y <= floor; y++) {
      const density = depth <= 0 ? 1 : (y - top) / depth;
      const lit = density > (BAYER[y & 3]?.[x & 3] ?? 0.5);
      const k = 0.3 + 0.7 * density;
      paint(y, lit ? k : k * OFF_TIER);
    }
    // The value line itself: a soft border + a faint feather row beneath.
    paint(top, BORDER_ALPHA);
    if (depth > 1) paint(top + 1, BORDER_ALPHA * 0.5);
  }

  /** Linear-interpolated sample of `values` at fraction t ∈ [0,1] (area). */
  function sampleAt(t: number): number {
    if (values.length === 1) return values[0] ?? 0;
    const pos = t * (values.length - 1);
    const i = Math.floor(pos);
    const f = pos - i;
    const a = values[i] ?? 0;
    const b = values[Math.min(i + 1, values.length - 1)] ?? a;
    return a + (b - a) * f;
  }

  function draw() {
    if (!canvas || values.length === 0) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const cols = Math.max(8, Math.round(width / CELL));
    const rows = Math.max(8, Math.round(height / CELL));
    canvas.width = cols;
    canvas.height = rows;
    ctx.clearRect(0, 0, cols, rows);
    const rgb = hexToRgb(color);
    const scale = Math.max(max ?? 0, ...values, 1);
    // v → the backing row of the value line (row 0 = full scale).
    const topRow = (v: number) =>
      Math.min(rows - 1, Math.max(0, Math.round((1 - v / scale) * (rows - 1))));

    if (variant === 'area') {
      for (let x = 0; x < cols; x++) {
        paintColumn(ctx, x, topRow(sampleAt(cols > 1 ? x / (cols - 1) : 0)), rows, rgb);
      }
      return;
    }
    // Bars: partition the columns into per-value buckets with a 1-cell gap.
    const n = values.length;
    const gap = n > 1 ? 1 : 0;
    const barW = Math.max(1, Math.floor((cols - gap * (n - 1)) / n));
    const used = barW * n + gap * (n - 1);
    const offset = Math.max(0, Math.floor((cols - used) / 2));
    for (let i = 0; i < n; i++) {
      const top = topRow(values[i] ?? 0);
      const x0 = offset + i * (barW + gap);
      for (let x = x0; x < Math.min(x0 + barW, cols); x++) {
        paintColumn(ctx, x, top, rows, rgb);
      }
    }
  }

  // Redraw whenever the series / geometry / color changes ($effect runs
  // post-mount, so this also covers the initial paint).
  $effect(() => {
    void values;
    void variant;
    void width;
    void height;
    void color;
    void max;
    draw();
  });
</script>

{#if values.length > 0}
  <div class={klass}>
    <canvas
      bind:this={canvas}
      class="block w-full rounded-md"
      style="height: {height}px; image-rendering: pixelated;"
      role="img"
      aria-label={ariaLabel}
    ></canvas>
    {#if labels.length > 1}
      <div class="mt-1 flex justify-between text-[10px] text-muted-foreground" aria-hidden="true">
        <span>{labels[0]}</span>
        <span>{labels[labels.length - 1]}</span>
      </div>
    {/if}
  </div>
{/if}
