<script lang="ts">
  /**
   * A loud "FAKE (dev)" chip for a provider account backed by the in-memory fake
   * adapter (`EdgeProviderAccountAdmin.fake` / `ProvidersUsageResponse.accounts[].fake`;
   * never true outside development). Renders nothing when `fake` is false.
   *
   * Props:
   *   fake: boolean
   *   class?: string
   */
  import { Badge } from '@client/components/ui/badge';
  import FlaskConical from '@lucide/svelte/icons/flask-conical';
  import { cn } from '@client/lib/utils';

  interface Props {
    fake: boolean;
    class?: string;
  }
  let { fake, class: className }: Props = $props();
</script>

{#if fake}
  <Badge
    variant="warning"
    class={cn('border-amber-500/60 font-semibold uppercase tracking-wide', className)}
    title="This account uses the in-memory fake provider. Nothing is created at a real provider."
  >
    <FlaskConical aria-hidden="true" />
    Fake (dev)
  </Badge>
{/if}
