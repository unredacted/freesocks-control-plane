<script lang="ts">
  /**
   * The FreeSocks sock brand glyph, hand-rolled in lucide's outline style
   * (24×24, stroke-width 2, round caps/joins, currentColor - lucide ships no
   * socks icon). A single crew sock in profile facing right-down: a clean leg
   * with a cuff band, a bent heel, and a rounded toe — the three accent marks
   * (cuff / heel / toe curve) are what read instantly as "sock" at 16px.
   * Pass a `class` (e.g. `size-4`) like a lucide icon.
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
  <!-- Silhouette: cuff opening at top, leg descending, ankle bending into a
       diagonal foot with a rounded toe. -->
  <path
    d="M7 2.5h7v9.2c0 .5.2 1 .6 1.4l4.9 4.6a3.4 3.4 0 1 1-4.6 4.4l-6.1-5.6a5.4 5.4 0 0 1-1.8-4V2.5Z"
  />
  <!-- Cuff band -->
  <path d="M7 5.4h7" />
  <!-- Heel curve -->
  <path d="M10.4 12.7a4.6 4.6 0 0 0 2.1 3.9" />
</svg>
