<script lang="ts">
  import { onMount } from 'svelte';
  import { t } from '../lib/i18n/index.svelte';

  /**
   * The account page's location globe: every FreeSocks location with map
   * coordinates as a dot, the member's own key as a larger bright marker, and
   * the globe turned so that marker faces the camera. When the key moves (a
   * server/location switch, a regenerate to another node) the globe eases its
   * rotation over to the new point - the visible payoff of the switch.
   *
   * Shares the dynamically-imported `cobe` chunk with the Home globe. Unlike
   * that one this globe does NOT spin: it renders once facing the key and only
   * animates while traveling to a new focus (reduced motion jumps instead), so
   * an open account tab costs nothing.
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
  let { locations, currentCode, currentLabel, size = 230 }: Props = $props();

  const dotted = $derived(locations.filter((l) => l.coords != null));
  // Focus = the key's location when it has coordinates; otherwise the first
  // dotted location (the globe still shows the network, just without a "you
  // are here" highlight).
  const focus = $derived(dotted.find((l) => l.code === currentCode) ?? dotted[0] ?? null);
  const highlighted = $derived(focus != null && focus.code === currentCode);

  // cobe's own example formula: the (phi, theta) that puts a lat/lng at the
  // center of the visible face.
  const anglesFor = (lat: number, lng: number): [number, number] => [
    Math.PI - ((lng * Math.PI) / 180 - Math.PI / 2),
    (lat * Math.PI) / 180,
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

  function animateTo(tp: number, tt: number) {
    cancelAnimationFrame(raf);
    if (!globe) return;
    if (reducedMotion) {
      phi = tp;
      theta = tt;
      globe.update({ phi, theta });
      return;
    }
    const step = () => {
      if (!globe) return;
      // Shortest way around for phi (never the long way past the antimeridian).
      const dp = ((((tp - phi) % (2 * Math.PI)) + 3 * Math.PI) % (2 * Math.PI)) - Math.PI;
      const dt = tt - theta;
      if (Math.abs(dp) < 0.002 && Math.abs(dt) < 0.002) {
        phi = tp;
        theta = tt;
        globe.update({ phi, theta });
        return; // settled - no idle frames
      }
      phi += dp * 0.07;
      theta += dt * 0.07;
      globe.update({ phi, theta });
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
  }

  // React to the key moving (or the catalog changing): repaint the markers and
  // travel to the new focus. First run happens before the globe exists and is
  // a no-op; the creation path below applies the same state itself.
  $effect(() => {
    const f = focus;
    const markers = buildMarkers(highlighted ? f!.code : null);
    if (!globe) return;
    globe.update({ markers });
    if (f?.coords) {
      const [tp, tt] = anglesFor(f.coords.lat, f.coords.lng);
      animateTo(tp, tt);
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
      [introPhi, introTheta] = anglesFor(focus.coords.lat, focus.coords.lng);
    }
    // Arrive at the key's location instead of starting on it: a short eased
    // approach from just west. Beyond the welcome, this also repaints past the
    // async map-texture load (this globe is otherwise static, and a single
    // creation-time render happens before the texture is ready).
    phi = reducedMotion ? introPhi : introPhi - 0.55;
    theta = introTheta;
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
      if (!reducedMotion) animateTo(introPhi, introTheta);
      // Belt-and-braces repaints in case the texture beats/loses every other
      // render (reduced motion has no animation frames at all).
      for (const delay of [150, 600]) {
        timers.push(
          window.setTimeout(() => {
            globe?.update({ phi, theta });
          }, delay),
        );
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
      style="width:{size}px;max-width:100%;aspect-ratio:1"
      role="img"
      aria-label={t('account.map.aria')}
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
