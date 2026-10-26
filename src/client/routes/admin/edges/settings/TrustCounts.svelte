<script lang="ts">
  /**
   * Address suspicion as counts only (docs/edges.md "Address enumeration"):
   * how many accounts are suspected now and today's strikes. Never an account:
   * the admin sees no per-member suspicion.
   */
  import { trustSummaryQuery } from '@client/lib/edgesApi';
  import { trustCountsLine } from './trustWords';

  const q = trustSummaryQuery();
</script>

{#if q.data}
  <p class="text-muted-foreground mt-4 text-xs">{trustCountsLine(q.data)}</p>
{/if}
