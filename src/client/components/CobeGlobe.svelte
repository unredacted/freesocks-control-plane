<script lang="ts">
  import { onMount } from 'svelte';
  import { t, type MessageKey } from '../lib/i18n/index.svelte';

  /**
   * The cobe WebGL globe on the front page: markers on censored countries, and
   * every voice country carries a LABEL (its line + city tag) pinned to its
   * marker. Positioning is plain JS: each layout pass copies the marker's stage
   * position off cobe v2's DOM anchor divs onto the label (CSS anchor
   * positioning — the earlier approach — never shipped on iOS/Firefox, which
   * left the globe label-less there); the `--cobe-visible-<id>` variable still
   * fades a label as its marker rotates to the far side. Only 3 labels show at
   * a time (1 on small stages; a sliding schedule), and each alternates between
   * lines on a slow staggered clock, so the hemisphere keeps murmuring without
   * crowding. Illustrative, not live data: fixed coordinates, archetypal lines
   * with city tags (no names — these are not testimonials).
   *
   * Engineering notes:
   *  - `cobe` is imported DYNAMICALLY on mount (code-split, like the admin CMS).
   *  - prefers-reduced-motion → a static globe, static first lines, no clock.
   *  - The rAF loop only calls `update({ phi })` (v2 API); GL context and the
   *    label clock are torn down on unmount.
   */
  interface Props {
    size?: number;
    class?: string;
  }
  let { size = 460, class: className = '' }: Props = $props();

  // The voices: id (→ the cobe DOM anchor + visibility variable) and capital
  // coordinates — EVERY dot speaks (there are no unlabeled markers). Order is
  // interleaved by region so the fill pass never clusters three labels in one
  // corner of the globe.
  const VOICES = [
    { id: 'ir', location: [35.7, 51.4] },
    { id: 'cu', location: [23.1, -82.4] },
    { id: 'ru', location: [55.8, 37.6] },
    { id: 'sa', location: [24.7, 46.7] },
    { id: 'vn', location: [14.1, 108.3] },
    { id: 'by', location: [53.9, 27.6] },
    { id: 'pk', location: [30.4, 69.3] },
    { id: 'tr', location: [39.0, 35.2] },
    { id: 've', location: [10.5, -66.9] },
    { id: 'cn', location: [35.0, 105.0] },
    { id: 'uz', location: [41.4, 64.6] },
    { id: 'tm', location: [38.9, 59.6] },
    { id: 'mm', location: [19.8, 96.2] },
    { id: 'eg', location: [30.0, 31.2] },
    { id: 'et', location: [9.0, 39.5] },
    { id: 'az', location: [40.4, 47.8] },
  ] as const;
  type VoiceId = (typeof VOICES)[number]['id'];
  const voiceKeys = (id: VoiceId) =>
    ({
      place: `home.globe.voices.${id}.place`,
      lines: [
        `home.globe.voices.${id}.l1`,
        `home.globe.voices.${id}.l2`,
        `home.globe.voices.${id}.l3`,
      ],
    }) as { place: MessageKey; lines: [MessageKey, MessageKey, MessageKey] };

  // Censored countries are amber "signals".
  const SIGNAL: [number, number, number] = [0.92, 0.48, 0.22];

  let canvas: HTMLCanvasElement | undefined = $state();
  let stageEl: HTMLDivElement | undefined = $state();
  // Anti-overlap scheduler: every animation frame we read each label's ACTUAL
  // rendered rect (its box as the browser placed it at its marker anchor —
  // no estimates) and cobe's per-marker visibility flag, then greedily keep
  // the currently-visible labels that are STILL collision-free (sticky, so
  // they don't flicker) and fill up to MAX_VISIBLE with the next candidates
  // in a rotating priority. A label can therefore only pop up when it
  // provably doesn't overlap another label or the stage edge — what you see
  // is exactly what was measured. Every voice cycles through over time.
  let tick = $state(0);
  let visibleIds = $state<string[]>([]);
  let reducedMotion = $state(false);
  const MAX_VISIBLE = 3;
  // Anti-blink cooldown: a label dropped (collision, edge, limb) may not be
  // re-admitted for this long — without it a label that collides one frame
  // after admission blinks in and out.
  const READMIT_COOLDOWN_MS = 4000;
  const droppedAt = new Map<string, number>();
  // Fairness: when each voice was last admitted. Empty slots always go to the
  // least-recently-shown admissible candidate, so a label can't starve behind
  // a collision-prone neighbor (e.g. Moscow/Minsk, Hanoi/Yangon) — EVERY dot's
  // message gets its turn.
  const lastShownAt = new Map<string, number>();
  const labelEls = new Map<string, HTMLElement>();

  function registerLabel(el: HTMLElement, id: string) {
    labelEls.set(id, el);
    return {
      destroy: () => {
        labelEls.delete(id);
      },
    };
  }

  type Rect = readonly [number, number, number, number];
  const MARGIN = 6;
  const hits = (a: Rect, b: Rect) => a[0] < b[2] && a[2] > b[0] && a[1] < b[3] && a[3] > b[1];
  function layoutPass() {
    const stage = stageEl;
    if (!stage) return;
    const srect = stage.getBoundingClientRect();
    if (srect.width === 0) return;
    const rootStyle = getComputedStyle(document.documentElement);
    // cobe's flag marks a marker "visible" on the front face OR BEHIND the
    // globe but outside its silhouette (the dot still draws around the edge) —
    // admitting on that flag alone lets a label pop up at the limb and vanish a
    // second later as the marker rotates deeper behind. Strict admission below
    // therefore also requires the anchor inside the DISC (true front face).
    const cobeFront = (id: string) =>
      rootStyle.getPropertyValue(`--cobe-visible-${id}`).trim() !== '';
    const z = canvas?.parentElement; // cobe's anchor wrapper
    const anchorDiv = (id: string) =>
      z?.querySelector<HTMLElement>(`div[style*="anchor-name: --cobe-${id}"]`) ?? null;
    // Pin every label to its marker in plain JS (cobe's anchor divs carry the
    // marker's stage position each frame). CSS anchor positioning — the old
    // approach — never shipped on iOS/Firefox, which left the globe label-less
    // there. Labels are positioned even while hidden so the admission pass
    // below measures each box exactly where it would appear.
    for (const v of VOICES) {
      const el = labelEls.get(v.id);
      const div = anchorDiv(v.id);
      if (!el || !div) continue;
      const r = div.getBoundingClientRect();
      el.style.left = `${r.left + r.width / 2 - srect.left}px`;
      el.style.top = `${r.top + r.height / 2 - srect.top}px`;
    }
    const DISC_R = 0.4; // disc radius as a fraction of the stage (slightly inside the silhouette)
    const onFrontFace = (id: string): boolean => {
      if (!cobeFront(id)) return false;
      const div = anchorDiv(id);
      if (!div) return false;
      const dx = parseFloat(div.style.left) / 100 - 0.5;
      const dy = parseFloat(div.style.top) / 100 - 0.5;
      return Math.hypot(dx, dy) < DISC_R;
    };
    // The label's real box in stage coordinates, inflated by a small margin so
    // near-misses wait too. Opacity-0 labels are still laid out at their
    // anchor, so candidates measure exactly as they would appear.
    const rectOf = (id: string): Rect | null => {
      const el = labelEls.get(id);
      if (!el) return null;
      const r = el.getBoundingClientRect();
      return [
        r.left - srect.left - MARGIN,
        r.top - srect.top - MARGIN,
        r.right - srect.left + MARGIN,
        r.bottom - srect.top + MARGIN,
      ] as const;
    };
    // ADMISSION is strict: the whole label must be inside the stage AND its
    // anchor on the front face inside the central band, so it can never pop up
    // half-off the edge or appear at the limb and vanish a second later —
    // everyone gets reading time.
    const BAND: readonly [number, number] = [0.2, 0.8];
    const admissible = (id: string): Rect | null => {
      if (!onFrontFace(id)) return null;
      const r = rectOf(id);
      if (!r) return null;
      if (r[0] < 0 || r[1] < 0 || r[2] > srect.width || r[3] > srect.height) return null;
      const cx = (r[0] + r[2]) / 2;
      if (cx < srect.width * BAND[0] || cx > srect.width * BAND[1]) return null;
      return r;
    };
    const kept: { id: string; r: Rect }[] = [];
    const now = Date.now();
    // Small stages can't breathe with three labels — show one at a time there
    // (the rotation still cycles every voice through).
    const maxVisible = srect.width < 480 ? 1 : MAX_VISIBLE;
    // Sticky: a visible label STAYS until it is genuinely no longer visible —
    // the marker is drawn (cobe's flag), the box is (mostly) inside the stage,
    // and no collision. There is no timed eviction: the priority rotation only
    // fills EMPTY slots. A dropped label goes on the re-admission cooldown.
    for (const id of visibleIds) {
      const drop = !cobeFront(id);
      const r = drop ? null : rectOf(id);
      const gone =
        drop ||
        !r ||
        kept.length >= maxVisible || // a resize can shrink the budget mid-flight
        r[0] < -12 ||
        r[1] < -12 ||
        r[2] > srect.width + 12 ||
        r[3] > srect.height + 12 ||
        kept.some((k) => hits(k.r, r)); // senior label (earlier) wins
      if (gone) {
        droppedAt.set(id, now);
        continue;
      }
      kept.push({ id, r: r! });
    }
    // Fill empty slots — least-recently-shown first, strictly admissible only,
    // and never a label that was just dropped (the anti-blink cooldown).
    const candidates = [...VOICES].sort(
      (a, b) => (lastShownAt.get(a.id) ?? 0) - (lastShownAt.get(b.id) ?? 0),
    );
    for (const v of candidates) {
      if (kept.length >= maxVisible) break;
      if (kept.some((k) => k.id === v.id)) continue;
      const dropped = droppedAt.get(v.id);
      if (dropped && now - dropped < READMIT_COOLDOWN_MS) continue;
      const r = admissible(v.id);
      if (!r || kept.some((k) => hits(k.r, r))) continue;
      kept.push({ id: v.id, r });
      lastShownAt.set(v.id, now);
    }
    // Assign only on change (a fresh array every frame would re-render needlessly).
    const next = kept.map((k) => k.id);
    if (next.join() !== visibleIds.join()) visibleIds = next;
  }
  // Each label's three lines rotate slowly (9s), staggered by index.
  const TICKS_PER_CYCLE = 15; // 15 × 600ms = 9s per line swap
  function variant(i: number): 0 | 1 | 2 {
    return (Math.floor((tick + i * 1.5) / TICKS_PER_CYCLE) % 3) as 0 | 1 | 2;
  }
  onMount(() => {
    reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const interval = reducedMotion
      ? 0
      : window.setInterval(() => {
          if (!document.hidden) {
            tick++;
            layoutPass();
          }
        }, 600);
    const onResize = () => layoutPass();
    window.addEventListener('resize', onResize);
    if (!canvas) {
      return () => {
        window.clearInterval(interval);
        window.removeEventListener('resize', onResize);
      };
    }
    let globe: { update: (s: Record<string, unknown>) => void; destroy: () => void } | undefined;
    let raf = 0;
    let destroyed = false;
    const dark = document.documentElement.classList.contains('dark');
    const el = canvas;
    void import('cobe').then(({ default: createGlobe }) => {
      if (destroyed) return;
      globe = createGlobe(el, {
        devicePixelRatio: 2,
        width: size * 2,
        height: size * 2,
        phi: 2.35, // start facing the censored bloc (Europe→Asia)
        theta: 0.25,
        dark: dark ? 1 : 0,
        diffuse: 1.2,
        mapSamples: 16000,
        mapBrightness: 6,
        baseColor: dark ? [0.85, 0.85, 0.85] : [0.35, 0.35, 0.35],
        markerColor: SIGNAL,
        glowColor: dark ? [0.12, 0.12, 0.12] : [0.92, 0.92, 0.92],
        markers: VOICES.map((v) => ({
          id: v.id,
          location: [v.location[0], v.location[1]] as [number, number],
          size: 0.055,
          color: SIGNAL,
        })),
        scale: 1.04,
      });
      // Anchors exist after the first render — run the first layout pass.
      layoutPass();
      if (!reducedMotion) {
        let phi = 2.35;
        let last = performance.now();
        const tickGlobe = (now: number) => {
          // Time-based (NOT per-frame): a 120Hz display must not spin the globe
          // twice as fast as a 60Hz one. dt is capped so a backgrounded tab
          // doesn't jump. ~97s per revolution at every refresh rate.
          const dt = Math.min(100, now - last);
          last = now;
          phi += 0.0018 * (dt / 16.667);
          globe?.update({ phi });
          // Collision-check against the freshly-moved anchors: a label drops
          // the frame it would start overlapping, not up to 600ms later.
          layoutPass();
          raf = requestAnimationFrame(tickGlobe);
        };
        raf = requestAnimationFrame(tickGlobe);
      }
    });
    return () => {
      destroyed = true;
      window.clearInterval(interval);
      window.removeEventListener('resize', onResize);
      cancelAnimationFrame(raf);
      globe?.destroy();
    };
  });
</script>

<div class="voice-stage" bind:this={stageEl}>
  <canvas
    bind:this={canvas}
    class={className}
    style="width:{size}px;max-width:100%;aspect-ratio:1"
    role="img"
    aria-label={t('home.globe.aria')}
  ></canvas>

  <!-- Voice labels, pinned to their markers (left/top set by layoutPass).
       Visibility cascades in the STYLESHEET only (never inline): per-id rules
       fade a label as its marker crosses the limb (cobe's --cobe-visible-<id>
       variable), and the LATER `.off` rule always wins for labels the
       scheduler has turned off — an inline `opacity: var(...)` would beat
       `.off` for every front-facing marker and show them all at once (the
       pile-up bug). Decorative; the sr list carries them. -->
  {#each VOICES as v, i (v.id)}
    {@const keys = voiceKeys(v.id)}
    <blockquote
      class="voice-float"
      class:off={!visibleIds.includes(v.id)}
      data-voice={v.id}
      aria-hidden="true"
      use:registerLabel={v.id}
    >
      {#key variant(i)}
        <p class="line">“{t(keys.lines[variant(i)])}”</p>
      {/key}
      <footer>{t(keys.place)}</footer>
    </blockquote>
  {/each}

  <!-- All voices for screen readers (the animated labels are decorative). -->
  <ul class="sr-only">
    {#each VOICES as v (v.id)}
      {@const keys = voiceKeys(v.id)}
      <li>{t(keys.place)}: {t(keys.lines[0])} {t(keys.lines[1])} {t(keys.lines[2])}</li>
    {/each}
  </ul>
</div>

<style>
  .voice-stage {
    position: relative;
    display: inline-block;
    max-width: 100%;
  }

  .voice-float {
    display: block;
    position: absolute;
    /* left/top are set per-frame by layoutPass (the marker's stage position);
       this translate floats the card centered above its marker. */
    translate: -50% calc(-100% - 8px);
    width: max-content;
    max-width: 10.5rem;
    padding: 0.4rem 0.6rem;
    border-radius: 0.65rem;
    border: 1px solid var(--border);
    background: var(--popover);
    color: var(--popover-foreground);
    box-shadow: 0 6px 20px rgb(0 0 0 / 0.18);
    font-size: 0.72rem;
    line-height: 1.35;
    pointer-events: none;
    z-index: 2;
    /* Base opacity 1; per-id rules below fade far-side markers; `.off` (last)
       always wins for scheduler-hidden labels. */
    opacity: 1;
    transition: opacity 0.7s ease;
  }
  /* Far-side fade per marker: cobe sets --cobe-visible-<id> while the marker
     faces the camera (deleted when hidden → the fallback 0 applies; an
     invalid value resolves to the base 1 — robust either way). */
  .voice-float[data-voice='ir'] {
    opacity: var(--cobe-visible-ir, 0);
  }
  .voice-float[data-voice='cu'] {
    opacity: var(--cobe-visible-cu, 0);
  }
  .voice-float[data-voice='ru'] {
    opacity: var(--cobe-visible-ru, 0);
  }
  .voice-float[data-voice='sa'] {
    opacity: var(--cobe-visible-sa, 0);
  }
  .voice-float[data-voice='vn'] {
    opacity: var(--cobe-visible-vn, 0);
  }
  .voice-float[data-voice='by'] {
    opacity: var(--cobe-visible-by, 0);
  }
  .voice-float[data-voice='pk'] {
    opacity: var(--cobe-visible-pk, 0);
  }
  .voice-float[data-voice='tr'] {
    opacity: var(--cobe-visible-tr, 0);
  }
  .voice-float[data-voice='ve'] {
    opacity: var(--cobe-visible-ve, 0);
  }
  .voice-float[data-voice='cn'] {
    opacity: var(--cobe-visible-cn, 0);
  }
  .voice-float[data-voice='uz'] {
    opacity: var(--cobe-visible-uz, 0);
  }
  .voice-float[data-voice='tm'] {
    opacity: var(--cobe-visible-tm, 0);
  }
  .voice-float[data-voice='mm'] {
    opacity: var(--cobe-visible-mm, 0);
  }
  .voice-float[data-voice='eg'] {
    opacity: var(--cobe-visible-eg, 0);
  }
  .voice-float[data-voice='et'] {
    opacity: var(--cobe-visible-et, 0);
  }
  .voice-float[data-voice='az'] {
    opacity: var(--cobe-visible-az, 0);
  }
  /* The scheduler's gate — declared LAST so it beats every per-id rule. */
  .voice-float.off {
    opacity: 0;
  }
  .voice-float .line {
    font-weight: 500;
  }
  .voice-float footer {
    margin-top: 0.1rem;
    font-size: 0.65rem;
    color: var(--muted-foreground);
  }
  .voice-float::after {
    content: '';
    position: absolute;
    top: 100%;
    left: 50%;
    width: 0.5rem;
    height: 0.5rem;
    background: inherit;
    border-inline-end: 1px solid var(--border);
    border-block-end: 1px solid var(--border);
    translate: -50% -0.25rem;
    rotate: 45deg;
  }
  .line {
    animation: voice-in 0.6s ease-out;
  }
  @keyframes voice-in {
    from {
      opacity: 0;
    }
    to {
      opacity: 1;
    }
  }
</style>
