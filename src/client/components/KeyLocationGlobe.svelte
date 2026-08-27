<script lang="ts">
  import { onMount } from 'svelte';
  import { t } from '../lib/i18n/index.svelte';

  /**
   * The account page's location globe: every FreeSocks location with map
   * coordinates as a dot, the member's own key as a larger bright marker. It
   * arrives facing the key's location, then keeps a slow steady spin; when the
   * key moves (a server/location switch, a regenerate to another node) it
   * eases its rotation over to the new point - the visible payoff of the
   * switch - and resumes spinning from there.
   *
   * Shares the dynamically-imported `cobe` chunk with the Home globe. One rAF
   * loop drives everything (spin, the travel ease, drag momentum); browsers
   * park rAF in hidden tabs, so a background account tab costs nothing.
   * Reduced motion: no loop at all - a static globe facing the key, updated
   * only by an explicit drag or a location change (which jumps).
   *
   * The globe is grabbable: a horizontal drag spins it by hand (vertical
   * stays with the page scroll - touch-action: pan-y) and a release hands the
   * flick's velocity to the loop, which glides it back down to the base spin.
   */
  interface MapLocation {
    code: string;
    label: string;
    online: boolean;
    coords?: { lat: number; lng: number } | null;
  }
  interface Props {
    locations: MapLocation[];
    /** The location code the member's key is currently homed to. */
    currentCode: string | null;
    /** Its display label (shown under the globe). */
    currentLabel: string | null;
    size?: number;
  }
  let { locations, currentCode, currentLabel, size = 240 }: Props = $props();

  const dotted = $derived(locations.filter((l) => l.coords != null));
  // Focus = the key's location when it has coordinates; otherwise the first
  // dotted location (the globe still shows the network, just without a "you
  // are here" highlight).
  const focus = $derived(dotted.find((l) => l.code === currentCode) ?? dotted[0] ?? null);
  const highlighted = $derived(focus != null && focus.code === currentCode);

  // cobe's own example formula for the phi that centers a longitude; theta is
  // SOFTENED (over half the latitude, capped) rather than matched exactly - a
  // full-latitude tilt for a northern city pitched the whole globe over and
  // read as off-center. The marker lands slightly above center instead, and
  // the sphere keeps a level, centered look while it spins.
  const anglesFor = (lat: number, lng: number): [number, number] => [
    Math.PI - ((lng * Math.PI) / 180 - Math.PI / 2),
    Math.max(-0.5, Math.min(0.5, (lat * Math.PI) / 180 / 2)),
  ];

  // Marker palette (0..1 RGB triples, resolved from the theme at mount when
  // possible). The key's marker wears the brand primary; sibling locations
  // are muted; an offline location goes gray.
  let ACTIVE: [number, number, number] = [0.15, 0.62, 0.41];
  const dim = (c: [number, number, number]): [number, number, number] => [
    c[0] * 0.55 + 0.18,
    c[1] * 0.55 + 0.18,
    c[2] * 0.55 + 0.18,
  ];
  const OFFLINE: [number, number, number] = [0.55, 0.55, 0.55];

  function buildMarkers(focusCode: string | null) {
    return dotted.map((l) => {
      const isKey = focusCode !== null && l.code === focusCode;
      return {
        id: l.code,
        location: [l.coords!.lat, l.coords!.lng] as [number, number],
        size: isKey ? 0.1 : 0.05,
        color: isKey ? ACTIVE : l.online ? dim(ACTIVE) : OFFLINE,
      };
    });
  }

  let canvas: HTMLCanvasElement | undefined = $state();
  let globe: { update: (s: Record<string, unknown>) => void; destroy: () => void } | null = null;
  let reducedMotion = false;
  let phi = 0;
  let theta = 0.3;
  let raf = 0;

  // One loop, three regimes: a live drag renders from the pointer handler,
  // a travel target eases toward a location, otherwise the base spin plus
  // whatever momentum the last flick left behind (decaying toward zero).
  const BASE_SPIN = 0.0015; // rad per 60Hz-normalized frame (~70s/revolution)
  let travel: [number, number] | null = null;
  let momentum = 0;
  let dragging = $state(false);
  let dragX = 0;

  function startLoop() {
    if (reducedMotion) return;
    cancelAnimationFrame(raf);
    let last = performance.now();
    const step = (now: number) => {
      if (!globe) return;
      // Time-based, like the Home globe: identical speed at 60Hz and 120Hz.
      const dtn = Math.min(100, now - last) / 16.667;
      last = now;
      if (!dragging) {
        if (travel) {
          // Shortest way around for phi (never the long way past the antimeridian).
          const dp =
            ((((travel[0] - phi) % (2 * Math.PI)) + 3 * Math.PI) % (2 * Math.PI)) - Math.PI;
          const dt = travel[1] - theta;
          if (Math.abs(dp) < 0.002 && Math.abs(dt) < 0.002) {
            [phi, theta] = travel;
            travel = null;
          } else {
            phi += dp * 0.07 * dtn;
            theta += dt * 0.07 * dtn;
          }
        } else {
          momentum *= Math.exp(-0.035 * dtn);
          phi += (BASE_SPIN + momentum) * dtn;
        }
        globe.update({ phi, theta });
      }
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
  }

  function onPointerDown(e: PointerEvent) {
    if (!globe) return;
    dragging = true;
    dragX = e.clientX;
    momentum = 0;
    travel = null; // the hand wins over an in-flight travel
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
    const dphi = dx / 110;
    phi += dphi;
    // The flick's velocity (clamped) carries past the release and glides back
    // down to the base spin.
    momentum = Math.max(-0.08, Math.min(0.08, dphi));
    globe.update({ phi, theta });
  }
  function endDrag() {
    dragging = false;
  }

  function faceLocation(lat: number, lng: number) {
    const target = anglesFor(lat, lng);
    if (reducedMotion) {
      [phi, theta] = target;
      globe?.update({ phi, theta });
      return;
    }
    momentum = 0;
    travel = target;
  }

  // React to the key moving (or the catalog changing): repaint the markers on
  // every run, but only travel when the focus CODE actually changed - the
  // config query refetches periodically and hands us fresh objects for the
  // same location, and re-centering on each of those would yank the spin.
  // First run happens before the globe exists and is a no-op; the creation
  // path below applies the same state itself.
  let lastFocusCode: string | null = null;
  $effect(() => {
    const f = focus;
    const markers = buildMarkers(highlighted ? f!.code : null);
    if (!globe) return;
    globe.update({ markers });
    if (f?.coords && f.code !== lastFocusCode) {
      lastFocusCode = f.code;
      faceLocation(f.coords.lat, f.coords.lng);
    }
  });

  onMount(() => {
    reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    // Theme-accurate marker green: resolve --primary to device RGB (falls back
    // to the hardcoded triple on any parse miss, e.g. exotic color spaces).
    try {
      const probe = document.createElement('span');
      probe.style.color = 'var(--primary)';
      probe.style.display = 'none';
      document.body.append(probe);
      const resolved = getComputedStyle(probe).color;
      probe.remove();
      const m =
        resolved.match(/rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)/) ??
        resolved.match(/color\(srgb\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)/);
      if (m) {
        const scale = resolved.startsWith('color(') ? 1 : 255;
        ACTIVE = [Number(m[1]) / scale, Number(m[2]) / scale, Number(m[3]) / scale];
      }
    } catch {
      // keep the fallback triple
    }
    if (!canvas) return;
    const el = canvas;
    const dark = document.documentElement.classList.contains('dark');
    let introPhi = 0;
    let introTheta = 0.3;
    if (focus?.coords) {
      lastFocusCode = focus.code;
      [introPhi, introTheta] = anglesFor(focus.coords.lat, focus.coords.lng);
    }
    // Arrive at the key's location instead of starting on it: a short eased
    // approach from just west, after which the loop settles into the base spin.
    phi = reducedMotion ? introPhi : introPhi - 0.55;
    theta = introTheta;
    if (!reducedMotion) travel = [introPhi, introTheta];
    let destroyed = false;
    const timers: number[] = [];
    void import('cobe').then(({ default: createGlobe }) => {
      if (destroyed) return;
      globe = createGlobe(el, {
        devicePixelRatio: 2,
        width: size * 2,
        height: size * 2,
        phi,
        theta,
        dark: dark ? 1 : 0,
        diffuse: 1.2,
        mapSamples: 14000,
        mapBrightness: 6,
        baseColor: dark ? [0.85, 0.85, 0.85] : [0.35, 0.35, 0.35],
        markerColor: ACTIVE,
        glowColor: dark ? [0.12, 0.12, 0.12] : [0.92, 0.92, 0.92],
        markers: buildMarkers(highlighted ? focus!.code : null),
        scale: 1.02,
      });
      startLoop();
      // Reduced motion has no loop, so its single creation-time render can
      // beat the async map-texture load - schedule two static repaints.
      if (reducedMotion) {
        for (const delay of [150, 600]) {
          timers.push(
            window.setTimeout(() => {
              globe?.update({ phi, theta });
            }, delay),
          );
        }
      }
    });
    return () => {
      destroyed = true;
      cancelAnimationFrame(raf);
      for (const id of timers) window.clearTimeout(id);
      globe?.destroy();
      globe = null;
    };
  });
</script>

<div class="flex h-full flex-col rounded-xl border border-border bg-card p-4">
  <h3 class="text-sm font-semibold">{t('account.map.title')}</h3>
  <div class="flex flex-1 items-center justify-center py-3">
    <canvas
      bind:this={canvas}
      style="width:{size}px;max-width:100%;aspect-ratio:1;touch-action:pan-y"
      class={dragging ? 'cursor-grabbing' : 'cursor-grab'}
      role="img"
      aria-label={t('account.map.aria')}
      onpointerdown={onPointerDown}
      onpointermove={onPointerMove}
      onpointerup={endDrag}
      onpointercancel={endDrag}
      onlostpointercapture={endDrag}
    ></canvas>
  </div>
  <div class="space-y-0.5 text-center">
    {#if currentLabel}
      <p class="text-sm font-medium">
        <span
          class="me-1.5 inline-block size-2 rounded-full bg-primary align-middle"
          aria-hidden="true"
        ></span>{currentLabel}
      </p>
    {/if}
    {#if locations.length > 1}
      <p class="text-xs text-muted-foreground">
        {t('account.map.network', { count: locations.length })}
      </p>
    {/if}
  </div>
</div>
