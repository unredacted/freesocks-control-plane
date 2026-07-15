<script lang="ts">
  /**
   * Locale-formatted number that counts up from 0 once `start` flips true
   * (typically wired to the `reveal` action's onReveal). Honest delight only:
   * the target is a real figure and the final frame renders it exactly. Skipped
   * entirely under prefers-reduced-motion (final value renders immediately).
   */
  interface Props {
    value: number;
    start?: boolean;
    durationMs?: number;
  }
  let { value, start = false, durationMs = 700 }: Props = $props();

  let done = $state(false);
  let shown = $state(0);

  const fmt = (n: number) => n.toLocaleString(undefined, { maximumFractionDigits: 2 });

  $effect(() => {
    if (!start || done) return;
    if (value <= 0 || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      done = true;
      return;
    }
    const target = value;
    const t0 = performance.now();
    let raf = 0;
    const tick = (now: number) => {
      const p = Math.min(1, (now - t0) / durationMs);
      shown = Math.round(target * (1 - Math.pow(1 - p, 3))); // ease-out cubic
      if (p < 1) raf = requestAnimationFrame(tick);
      else done = true;
    };
    raf = requestAnimationFrame(tick);
    // If animation frames never tick (backgrounded/non-painting renderer),
    // land on the exact final value anyway.
    const failsafe = setTimeout(() => (done = true), durationMs + 500);
    return () => {
      cancelAnimationFrame(raf);
      clearTimeout(failsafe);
    };
  });
</script>

{done || !start ? fmt(value) : fmt(shown)}
