<script lang="ts">
  import { onMount } from 'svelte';
  import QRCode from 'qrcode';
  import { t } from '../lib/i18n/index.svelte';

  /**
   * Renders a QR code for arbitrary text content. We use the canvas-based
   * encoder from the `qrcode` lib (vanilla, framework-agnostic). On the
   * subscription page this lets a desktop user point their phone at the
   * screen instead of hand-typing the long `vless://` URL.
   *
   * Colors are fixed black-on-white in both themes. Deriving them from the
   * oklch() theme tokens silently fell back to canvas-default black for BOTH
   * squares on browsers without canvas oklch support (Chrome <111, Safari
   * <15.4 — realistic for this audience), producing an unscannable QR. Max
   * contrast is also simply what scanners want.
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

  async function draw() {
    if (!canvas) return;
    error = null;
    try {
      await QRCode.toCanvas(canvas, text, {
        width: size,
        margin: 1,
        errorCorrectionLevel: 'M',
        color: { dark: '#000000', light: '#ffffff' },
      });
    } catch (e) {
      console.error('QR generation failed', e);
      error = t('qr.failed');
    }
  }

  onMount(draw);

  // Re-render when text or size changes.
  $effect(() => {
    void text;
    void size;
    void draw();
  });
</script>

<div class={cls}>
  {#if error}
    <div class="rounded-md bg-destructive/10 border border-destructive/40 px-3 py-2 text-xs">
      {error}
    </div>
  {:else}
    <canvas
      bind:this={canvas}
      width={size}
      height={size}
      class="rounded-md border border-border"
      role="img"
      aria-label={t('qr.ariaLabel')}
    ></canvas>
  {/if}
</div>
