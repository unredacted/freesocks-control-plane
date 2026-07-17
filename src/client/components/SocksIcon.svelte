<script lang="ts">
  /**
   * The FreeSocks sock brand glyph, hand-rolled in lucide's outline style
   * (24×24, stroke-width 2, round caps/joins, currentColor - lucide ships no
   * socks icon). A single ANKLE-LENGTH sock facing right: a flared cuff band
   * at the top (the elastic rim - the feature that reads instantly as
   * "sock"), a short leg bending into a roomy foot with a rounded toe. Kept
   * chunky so it fills the frame and stays legible at 16px. Pass a `class`
   * (e.g. `size-4`) like a lucide icon.
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
    d="M6.7 3h10.6q1.2 0 1.2 1.2v2.1q0 1.2-1.2 1.2h-0.8v5q0 2.4 2.6 2.4a3.2 3.2 0 0 1 0 6.4h-8.1q-3-0.2-3-2.9V7.5h-1.3q-1.2 0-1.2-1.2V4.2q0-1.2 1.2-1.2Z"
  />
</svg>
