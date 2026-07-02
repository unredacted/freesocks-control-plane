<script lang="ts">
  /**
   * Dependency-free inline-SVG sparkline: renders `points` as a normalized
   * polyline + soft area fill scaled to the viewBox. No chart library (keeps the
   * bundle lean and the CSP pure-'self'). Uses `currentColor`, so the parent
   * picks the hue (e.g. `text-primary`). Decorative — the numeric total is the
   * accessible signal, so this is aria-hidden.
   */
  interface Props {
    points: number[];
    width?: number;
    height?: number;
    class?: string;
  }
  let { points, width = 240, height = 48, class: klass = '' }: Props = $props();

  let path = $derived.by(() => {
    const n = points.length;
    if (n === 0) return { line: '', area: '' };
    const max = Math.max(...points, 1); // avoid /0; an all-zero series sits on the baseline
    const stepX = n > 1 ? width / (n - 1) : 0;
    const y = (v: number) => height - (v / max) * (height - 2) - 1; // 1px top/bottom padding
    const pts = points.map((v, i) => `${(i * stepX).toFixed(1)},${y(v).toFixed(1)}`);
    const line = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p}`).join(' ');
    const area = `${line} L${width.toFixed(1)},${height} L0,${height} Z`;
    return { line, area };
  });
</script>

<svg
  viewBox="0 0 {width} {height}"
  class={klass}
  preserveAspectRatio="none"
  role="img"
  aria-hidden="true"
>
  <path d={path.area} fill="currentColor" fill-opacity="0.12" stroke="none" />
  <path
    d={path.line}
    fill="none"
    stroke="currentColor"
    stroke-width="1.5"
    stroke-linejoin="round"
    stroke-linecap="round"
    vector-effect="non-scaling-stroke"
  />
</svg>
