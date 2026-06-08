<script lang="ts">
  import { onMount } from 'svelte';
  import QRCode from 'qrcode';

  /**
   * Renders a QR code for arbitrary text content. We use the canvas-based
   * encoder from the `qrcode` lib (vanilla, framework-agnostic). On the
   * subscription page this lets a desktop user point their phone at the
   * screen instead of hand-typing the long `vless://` URL.
   *
   * The container has `currentColor` background so the QR adapts to dark
   * mode automatically: we tell the encoder to render dark squares as
   * `--foreground` and light squares as `--background`.
   */
  interface Props {
    text: string;
    /** Pixel size of the rendered QR (square). Default 192. */
    size?: number;
    class?: string;
  }
  let { text, size = 192, class: cls }: Props = $props();

  let canvas = $state<HTMLCanvasElement | null>(null);
  let error = $state<string | null>(null);

  // Resolve the actual computed colours from the CSS custom properties. We
  // read them at draw time so the QR re-tints if the user toggles theme.
  function readThemeColors() {
    const root = getComputedStyle(document.documentElement);
    return {
      fg: root.getPropertyValue('--foreground').trim() || '#000',
      bg: root.getPropertyValue('--background').trim() || '#fff',
    };
  }

  // Convert an oklch() / hex value to an explicit rgb the qrcode lib can
  // accept. The library wants `#rrggbb` strings; oklch() wouldn't parse.
  function toCssColor(raw: string): string {
    if (!raw) return '#000';
    if (raw.startsWith('#')) return raw;
    // Coerce via temporary canvas: easiest cross-browser oklch→hex path.
    const c = document.createElement('canvas');
    c.width = 1;
    c.height = 1;
    const ctx = c.getContext('2d');
    if (!ctx) return '#000';
    ctx.fillStyle = raw;
    ctx.fillRect(0, 0, 1, 1);
    const data = ctx.getImageData(0, 0, 1, 1).data;
    // `noUncheckedIndexedAccess` makes data[i] possibly-undefined; the canvas
    // always returns 4 bytes for a 1×1 fill, so default-zero is safe.
    return `#${[data[0] ?? 0, data[1] ?? 0, data[2] ?? 0]
      .map((n) => n.toString(16).padStart(2, '0'))
      .join('')}`;
  }

  async function draw() {
    if (!canvas) return;
    error = null;
    try {
      const { fg, bg } = readThemeColors();
      await QRCode.toCanvas(canvas, text, {
        width: size,
        margin: 1,
        errorCorrectionLevel: 'M',
        color: {
          dark: toCssColor(fg),
          light: toCssColor(bg),
        },
      });
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  onMount(draw);

  // Re-render when text or size changes, OR when the user toggles theme. We
  // observe class changes on <html> (mode-watcher toggles `.dark` there).
  $effect(() => {
    void text;
    void size;
    void draw();
  });

  $effect(() => {
    if (typeof MutationObserver === 'undefined') return;
    const obs = new MutationObserver(() => void draw());
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
    return () => obs.disconnect();
  });
</script>

<div class={cls}>
  {#if error}
    <div class="rounded-md bg-destructive/10 border border-destructive/40 px-3 py-2 text-xs">
      QR generation failed: {error}
    </div>
  {:else}
    <canvas
      bind:this={canvas}
      width={size}
      height={size}
      class="rounded-md border border-border"
      aria-label="QR code for the subscription URL"
    ></canvas>
  {/if}
</div>
