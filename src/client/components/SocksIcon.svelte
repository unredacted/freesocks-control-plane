<script lang="ts">
  /**
   * A sock (footwear) brand glyph for FreeSocks. Lucide ships no socks icon, so
   * this is hand-rolled in lucide's outline style (24×24, stroke-width 2, round
   * caps/joins, currentColor): a leg that bends at the ankle into a foot with a
   * rounded toe and heel, plus a cuff line at the opening - the cues that read as
   * a sock rather than a bare L. Pass a `class` (e.g. `size-4`) like a lucide icon.
   */
  let { class: className = '' }: { class?: string } = $props();
</script>

<svg
  xmlns="http://www.w3.org/2000/svg"
  width="24"
  height="24"
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="2"
  stroke-linecap="round"
  stroke-linejoin="round"
  class={className}
  aria-hidden="true"
>
  <path d="M8 4h6v7q0 2.8 3 2.8a3.4 3.4 0 0 1 0 6.8h-7a2.9 2.9 0 0 1-2-2.9V4Z" />
  <path d="M8 7.2h6" />
</svg>
