<script lang="ts">
  /**
   * A sock (footwear) brand glyph for FreeSocks. Lucide ships no socks icon, so
   * this is a hand-rolled solid mark: two overlapping rounded rects (a vertical
   * leg + a horizontal foot sharing a left edge) that fuse into a seamless
   * L-shaped sock — rounded cuff at the top, rounded toe at the right, rounded
   * heel at the bottom-left. Filled with `currentColor` so it inherits text color
   * like a lucide icon. Pass a `class` (e.g. `size-4`) exactly as with a lucide icon.
   */
  let { class: className = '' }: { class?: string } = $props();
</script>

<svg
  xmlns="http://www.w3.org/2000/svg"
  width="24"
  height="24"
  viewBox="0 0 24 24"
  fill="currentColor"
  class={className}
  aria-hidden="true"
>
  <rect x="7.5" y="3" width="6.5" height="12" rx="2" />
  <rect x="7.5" y="11" width="12.5" height="8" rx="3.5" />
</svg>
