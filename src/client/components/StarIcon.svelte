<script lang="ts">
  /**
   * The FreeSocks brand glyph: an eight-pointed star, hand-rolled in lucide's
   * outline style (24×24, stroke-width 2, round caps/joins, currentColor).
   * Alternating outer (R=10) and inner (r=4) vertices around the center — the
   * long cardinal points with short diagonal points between them read crisply
   * at 16px. Pass a `class` (e.g. `size-4`) like a lucide icon.
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
  <path
    d="M12 2l1.53 6.3 5.54-3.37-3.37 5.54L22 12l-6.3 1.53 3.37 5.54-5.54-3.37L12 22l-1.53-6.3-5.54 3.37 3.37-5.54L2 12l6.3-1.53L4.93 4.93l5.54 3.37L12 2Z"
  />
</svg>
