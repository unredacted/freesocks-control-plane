<script lang="ts">
  /**
   * The FreeSocks logo mark: the white eight-point star on the logo-green
   * rounded square. Fixed brand colors (it is the logo, so it does not follow
   * the theme preset). Decorative: the wordmark or an aria-label beside it
   * names the link.
   */
  let { class: klass = 'size-8' }: { class?: string } = $props();
</script>

<svg class={klass} viewBox="0 0 1024 1024" aria-hidden="true">
  <rect width="1024" height="1024" rx="245" fill="#007e4b" />
  <path
    transform="translate(174.08 174.08) scale(28.16)"
    d="M12 2l1.53 6.3 5.54-3.37-3.37 5.54L22 12l-6.3 1.53 3.37 5.54-5.54-3.37L12 22l-1.53-6.3-5.54 3.37 3.37-5.54L2 12l6.3-1.53L4.93 4.93l5.54 3.37L12 2Z"
    fill="#ffffff"
  />
</svg>
