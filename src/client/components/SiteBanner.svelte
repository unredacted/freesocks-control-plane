<script lang="ts">
  import { configQuery } from '../lib/queries';

  /**
   * Admin-configurable site-wide announcement bar (DB-driven via publicConfig).
   * A quiet, neutral full-width strip above the header - deliberately calmer than
   * the destructive-styled <E2eeAlert/> so an operational notice ("maintenance at
   * 03:00 UTC") reads as info, not alarm. The text is operator free-form: rendered
   * as ESCAPED text (never {@html}), and NOT run through t() (it's not a catalog
   * key). Renders nothing unless the operator has enabled it AND set text.
   */
  const cfg = configQuery();
  const site = $derived(cfg.data?.site);
</script>

{#if site?.bannerEnabled && site.bannerText}
  <div
    role="status"
    class="flex items-center justify-center gap-2 border-b border-border bg-muted/60 px-3 py-1.5 text-center text-xs text-foreground"
  >
    <span class="font-medium">{site.bannerText}</span>
  </div>
{/if}
