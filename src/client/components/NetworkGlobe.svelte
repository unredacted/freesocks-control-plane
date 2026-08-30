<script lang="ts">
  import { onMount } from 'svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { resolvePrimaryRgb } from '../lib/oklch';

  /**
   * The home page's live-network globe. Two kinds of marks:
   *
   *  - GREEN markers: real FreeSocks server locations, straight from
   *    publicConfig.locations (the same DB-driven feed as the network-status
   *    strip; only locations the operator gave map coordinates). Each carries
   *    a small label chip (code + city + online state) pinned to its marker.
   *  - AMBER dots: fixed, unlabeled context marks on regions where the
   *    internet is heavily censored. Not live data and not a claim about
   *    users; the section copy says exactly what they are.
   *
   * This replaced the earlier "voices" globe (invented quotes from censored
   * cities): fabricated testimonial-ish lines undercut the page's factual
   * voice, and real server locations are the stronger, verifiable story.
   *
   * Label positioning is plain JS: each layout pass copies the marker's stage
   * position off cobe v2's DOM anchor divs onto the label (CSS anchor
   * positioning never shipped on iOS/Firefox). A label shows only while its
   * marker is on the front face inside the disc, the chip fits fully inside
   * the stage, and it doesn't collide with an already-shown chip - opacity is
   * driven by the `off` class, so hides/shows fade via the CSS transition.
   *
   * Engineering notes:
   *  - `cobe` is imported DYNAMICALLY on mount (code-split, shared chunk with
   *    the account globe).
   *  - prefers-reduced-motion → a static globe (drag still repaints).
   *  - The rAF loop only calls `update({ phi })` (v2 API); GL context is torn
   *    down on unmount.
   *  - Grabbable: a horizontal drag spins it (vertical stays with the page
   *    scroll - touch-action: pan-y); a release hands the flick's velocity to
   *    the loop, which glides back to the base spin.
   */
  interface MapLocation {
    code: string;
    label: string;
    online: boolean;
    coords?: { lat: number; lng: number } | null;
  }
  interface Props {
    locations: MapLocation[];
    size?: number;
    class?: string;
  }
  let { locations, size = 460, class: className = '' }: Props = $props();

  // Only locations the operator mapped; the section itself is hidden by the
  // caller when this is empty.
  const servers = $derived(locations.filter((l) => l.coords != null));

  // Censored-region context dots (amber, unlabeled): capital coordinates for
  // regions with pervasive national filtering. Static context, not live data.
  const REGIONS: readonly [number, number][] = [
    [35.7, 51.4], // Iran
    [23.1, -82.4], // Cuba
    [55.8, 37.6], // Russia
    [24.7, 46.7], // Saudi Arabia
    [14.1, 108.3], // Vietnam
    [53.9, 27.6], // Belarus
    [30.4, 69.3], // Pakistan
    [39.0, 35.2], // Türkiye
    [10.5, -66.9], // Venezuela
    [35.0, 105.0], // China
    [41.4, 64.6], // Uzbekistan
    [38.9, 59.6], // Turkmenistan
    [19.8, 96.2], // Myanmar
    [30.0, 31.2], // Egypt
    [9.0, 39.5], // Ethiopia
    [40.4, 47.8], // Azerbaijan
  ];
  const SIGNAL: [number, number, number] = [0.92, 0.48, 0.22];
  // Server-marker palette; ACTIVE is re-resolved from the theme --primary at
  // mount (same trick as the account globe), OFFLINE goes gray.
  let ACTIVE: [number, number, number] = [0.15, 0.62, 0.41];
  const OFFLINE: [number, number, number] = [0.55, 0.55, 0.55];

  // Marker/anchor id for a server. Namespaced so an operator-chosen location
  // code can never collide with a region marker id (a location literally
  // coded "r0" would otherwise share `r0` with the first region dot, and the
  // chip would pin itself to the wrong marker). Region ids stay `r<i>`, which
  // no `s-<code>` can equal.
  const sid = (code: string) => `s-${code}`;

  function buildMarkers() {
    return [
      ...REGIONS.map((loc, i) => ({
        id: `r${i}`,
        location: loc as [number, number],
        size: 0.04,
        color: SIGNAL,
      })),
      ...servers.map((s) => ({
        id: sid(s.code),
        location: [s.coords!.lat, s.coords!.lng] as [number, number],
        size: 0.08,
        color: s.online ? ACTIVE : OFFLINE,
      })),
    ];
  }

  let canvas: HTMLCanvasElement | undefined = $state();
  let stageEl: HTMLDivElement | undefined = $state();
  let visibleIds = $state<string[]>([]);
  let reducedMotion = $state(false);

  let globe: { update: (s: Record<string, unknown>) => void; destroy: () => void } | undefined;
  let phi = 2.35; // start facing Europe→Asia
  let dragging = $state(false);
  let dragX = 0;
  let momentum = 0;
  function onPointerDown(e: PointerEvent) {
    if (!globe) return;
    dragging = true;
    dragX = e.clientX;
    momentum = 0;
    try {
      (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    } catch {
      // capture is a nicety (drag keeps tracking outside the canvas); a
      // browser that refuses it still gets the in-bounds drag
    }
  }
  function onPointerMove(e: PointerEvent) {
    if (!dragging || !globe) return;
    // A move with no button held means the release happened where we couldn't
    // see it (capture refused, browser quirk) - never spin an unpressed hover.
    if (e.buttons === 0) {
      endDrag();
      return;
    }
    const dx = e.clientX - dragX;
    dragX = e.clientX;
    const dphi = dx / 160;
    phi += dphi;
    momentum = Math.max(-0.08, Math.min(0.08, dphi));
    if (reducedMotion) {
      momentum = 0;
      globe.update({ phi });
      layoutPass();
    }
  }
  function endDrag() {
    dragging = false;
  }

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
    // cobe's flag marks a marker "visible" on the front face OR just past the
    // limb (the dot still draws around the edge); admission below also
    // requires the anchor inside the DISC (true front face) so a chip never
    // pops up at the limb and vanishes a second later.
    const cobeFront = (id: string) =>
      rootStyle.getPropertyValue(`--cobe-visible-${id}`).trim() !== '';
    const z = canvas?.parentElement; // cobe's anchor wrapper
    // Anchor lookup by EXACT marker id: a substring selector on the style
    // attribute (`[style*="--cobe-US"]`) would also match `--cobe-US-EAST`,
    // so parse each anchor's full name out of the raw attribute instead (the
    // attribute string, not CSSStyleDeclaration - browsers without CSS anchor
    // positioning don't reflect the unknown property).
    const anchors = new Map<string, HTMLElement>();
    if (z) {
      for (const div of z.querySelectorAll<HTMLElement>('div[style*="anchor-name: --cobe-"]')) {
        const m = /anchor-name:\s*--cobe-([^;]+)/.exec(div.getAttribute('style') ?? '');
        if (m) anchors.set(m[1]!.trim(), div);
      }
    }
    const anchorDiv = (id: string) => anchors.get(id) ?? null;
    // Pin every chip to its marker (positioned even while hidden, so the
    // admission pass measures each box exactly where it would appear).
    for (const s of servers) {
      const el = labelEls.get(sid(s.code));
      const div = anchorDiv(sid(s.code));
      if (!el || !div) continue;
      const r = div.getBoundingClientRect();
      el.style.left = `${r.left + r.width / 2 - srect.left}px`;
      el.style.top = `${r.top + r.height / 2 - srect.top}px`;
    }
    const DISC_R = 0.42; // disc radius as a fraction of the stage
    const onFrontFace = (id: string): boolean => {
      if (!cobeFront(id)) return false;
      const div = anchorDiv(id);
      if (!div) return false;
      const dx = parseFloat(div.style.left) / 100 - 0.5;
      const dy = parseFloat(div.style.top) / 100 - 0.5;
      return Math.hypot(dx, dy) < DISC_R;
    };
    // The chip's real box in stage coordinates, inflated by a small margin.
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
    const inStage = (r: Rect, slack: number) =>
      r[0] >= -slack &&
      r[1] >= -slack &&
      r[2] <= srect.width + slack &&
      r[3] <= srect.height + slack;
    // Sticky keep: a shown chip stays while its marker is drawn and it fits
    // (small slack so a chip mid-fade doesn't flicker at the boundary);
    // seniors (earlier in the kept list) win collisions.
    const kept: { id: string; r: Rect }[] = [];
    for (const id of visibleIds) {
      if (!cobeFront(id)) continue;
      const r = rectOf(id);
      if (!r || !inStage(r, 12) || kept.some((k) => hits(k.r, r))) continue;
      kept.push({ id, r });
    }
    // Admit the rest strictly (front face, fully inside, collision-free).
    // Server count is small, so there's no visible-count budget or rotation:
    // every chip that fits is shown.
    for (const s of servers) {
      const id = sid(s.code);
      if (kept.some((k) => k.id === id)) continue;
      if (!onFrontFace(id)) continue;
      const r = rectOf(id);
      if (!r || !inStage(r, 0) || kept.some((k) => hits(k.r, r))) continue;
      kept.push({ id, r });
    }
    // Assign only on change (a fresh array every frame would re-render needlessly).
    const next = kept.map((k) => k.id);
    if (next.join() !== visibleIds.join()) visibleIds = next;
  }

  // Live updates: the config query refetches periodically; repaint markers
  // when the catalog (or an online bit) changes. First run happens before the
  // globe exists and is a no-op; creation applies the same state itself.
  $effect(() => {
    const markers = buildMarkers();
    globe?.update({ markers });
  });

  onMount(() => {
    reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    // Theme-accurate marker green: the theme declares --primary as oklch(),
    // which computed styles can hand back verbatim (the brand-preset tokens
    // do exactly that), so use the repo's oklch resolver rather than probing
    // for an rgb() serialization. Falls back to the hardcoded triple when the
    // token is unavailable or unparseable.
    const rgb = resolvePrimaryRgb();
    if (rgb) ACTIVE = [rgb[0] / 255, rgb[1] / 255, rgb[2] / 255];
    const onResize = () => layoutPass();
    window.addEventListener('resize', onResize);
    if (!canvas) {
      return () => {
        window.removeEventListener('resize', onResize);
      };
    }
    let raf = 0;
    let destroyed = false;
    const timers: number[] = [];
    const dark = document.documentElement.classList.contains('dark');
    const el = canvas;
    void import('cobe').then(({ default: createGlobe }) => {
      if (destroyed) return;
      globe = createGlobe(el, {
        devicePixelRatio: 2,
        width: size * 2,
        height: size * 2,
        phi,
        theta: 0.25,
        dark: dark ? 1 : 0,
        diffuse: 1.2,
        mapSamples: 16000,
        mapBrightness: 6,
        baseColor: dark ? [0.85, 0.85, 0.85] : [0.35, 0.35, 0.35],
        markerColor: ACTIVE,
        glowColor: dark ? [0.12, 0.12, 0.12] : [0.92, 0.92, 0.92],
        markers: buildMarkers(),
        scale: 1.04,
      });
      // Anchors exist after the first render — run the first layout pass.
      layoutPass();
      if (!reducedMotion) {
        let last = performance.now();
        const tickGlobe = (now: number) => {
          // Time-based (NOT per-frame): a 120Hz display must not spin the globe
          // twice as fast as a 60Hz one. dt is capped so a backgrounded tab
          // doesn't jump. ~97s per revolution at every refresh rate. A held
          // pointer parks the auto-advance (the drag handler moves phi itself);
          // after release the flick's momentum decays back into the base spin.
          const dt = Math.min(100, now - last);
          last = now;
          const dtn = dt / 16.667;
          if (!dragging) {
            momentum *= Math.exp(-0.035 * dtn);
            phi += (0.0018 + momentum) * dtn;
          }
          globe?.update({ phi });
          // Chip admission runs against the freshly-moved anchors: a chip
          // drops the frame it would start overlapping, not later.
          layoutPass();
          raf = requestAnimationFrame(tickGlobe);
        };
        raf = requestAnimationFrame(tickGlobe);
      } else {
        // Reduced motion has no loop, so its single creation-time render can
        // beat the async map-texture load - schedule two static repaints.
        for (const delay of [150, 600]) {
          timers.push(
            window.setTimeout(() => {
              globe?.update({ phi });
              layoutPass();
            }, delay),
          );
        }
      }
    });
    return () => {
      destroyed = true;
      window.removeEventListener('resize', onResize);
      cancelAnimationFrame(raf);
      for (const id of timers) window.clearTimeout(id);
      globe?.destroy();
      globe = undefined;
    };
  });
</script>

<div class="space-y-3">
  <div class="loc-stage" bind:this={stageEl}>
    <canvas
      bind:this={canvas}
      class="{className} {dragging ? 'cursor-grabbing' : 'cursor-grab'}"
      style="width:{size}px;max-width:100%;aspect-ratio:1;touch-action:pan-y"
      role="img"
      aria-label={t('home.globe.aria')}
      onpointerdown={onPointerDown}
      onpointermove={onPointerMove}
      onpointerup={endDrag}
      onpointercancel={endDrag}
      onlostpointercapture={endDrag}
    ></canvas>

    <!-- Server chips, pinned to their markers (left/top set by layoutPass).
         Decorative for AT; the sr list below carries the same facts. -->
    {#each servers as s (s.code)}
      <div
        class="loc-float"
        class:off={!visibleIds.includes(sid(s.code))}
        aria-hidden="true"
        use:registerLabel={sid(s.code)}
      >
        <span class="dot" class:on={s.online}></span>
        <span class="code">{s.code}</span>
        <span class="name">{s.label}</span>
        {#if !s.online}
          <span class="offline">({t('home.network.offline')})</span>
        {/if}
      </div>
    {/each}
  </div>

  <!-- Legend: what the two mark colors mean. -->
  <div
    class="flex flex-wrap items-center justify-center gap-x-5 gap-y-1 text-xs text-muted-foreground"
  >
    <span class="inline-flex items-center gap-1.5">
      <span class="size-2 rounded-full bg-primary" aria-hidden="true"></span>
      {t('home.globe.legendServers')}
    </span>
    <span class="inline-flex items-center gap-1.5">
      <span class="size-2 rounded-full bg-amber-500/80" aria-hidden="true"></span>
      {t('home.globe.legendRegions')}
    </span>
  </div>

  <!-- The server list for screen readers (the floating chips are decorative). -->
  <ul class="sr-only">
    {#each servers as s (s.code)}
      <li>
        {s.code}: {s.label} ({s.online ? t('home.network.srOnline') : t('home.network.srOffline')})
      </li>
    {/each}
  </ul>
</div>

<style>
  .loc-stage {
    position: relative;
    display: inline-block;
    max-width: 100%;
  }

  .loc-float {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    position: absolute;
    /* left/top are set per-frame by layoutPass (the marker's stage position);
       this translate floats the chip centered above its marker. */
    translate: -50% calc(-100% - 10px);
    width: max-content;
    max-width: 12rem;
    padding: 0.3rem 0.55rem;
    border-radius: 0.55rem;
    border: 1px solid var(--border);
    background: var(--popover);
    color: var(--popover-foreground);
    box-shadow: 0 6px 20px rgb(0 0 0 / 0.18);
    font-size: 0.72rem;
    line-height: 1.3;
    pointer-events: none;
    z-index: 2;
    opacity: 1;
    transition: opacity 0.5s ease;
  }
  .loc-float.off {
    opacity: 0;
  }
  .loc-float::after {
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
  .loc-float .dot {
    width: 0.4rem;
    height: 0.4rem;
    border-radius: 9999px;
    background: var(--muted-foreground);
    opacity: 0.5;
  }
  .loc-float .dot.on {
    background: var(--primary);
    opacity: 1;
  }
  .loc-float .code {
    font-family: var(--font-mono, monospace);
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--muted-foreground);
  }
  .loc-float .name {
    font-weight: 500;
  }
  .loc-float .offline {
    font-size: 0.65rem;
    color: var(--muted-foreground);
  }
</style>
