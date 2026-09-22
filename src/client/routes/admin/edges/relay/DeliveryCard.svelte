<script lang="ts">
  /**
   * Edge-required delivery of one origin: are members served through edges, or
   * dark, and why (derived in relayLogic.deriveDelivery from the origin, its
   * setup status and the attention list). Also addresses the render preview.
   *
   * Props: origin
   */
  import type { OriginAdmin } from '@shared/contracts/edges';
  import * as Card from '@client/components/ui/card';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import Link from '@client/components/Link.svelte';
  import { attentionQuery, setupStatusQuery } from '@client/lib/edgesApi';
  import { SETUP_STEP_TITLES } from '@client/lib/edgeCodes';
  import RenderPreview from '../forms/RenderPreview.svelte';
  import { edgesPaths } from '../lib/routes';
  import { deriveDelivery } from './relayLogic';

  interface Props {
    relay: OriginAdmin;
  }
  let { relay }: Props = $props();

  const setupQ = setupStatusQuery(() => relay.slug);
  const attentionQ = attentionQuery();
  const delivery = $derived(
    deriveDelivery({
      relay,
      setup: setupQ.data ?? null,
      attention: attentionQ.data?.items ?? null,
    }),
  );
  const setup = $derived(setupQ.data ?? null);
  let previewOpen = $state(false);
</script>

<Card.Root>
  <Card.Header>
    <Card.Title class="flex flex-wrap items-center gap-2">
      Delivery
      <Badge variant={delivery.tone}>{delivery.headline}</Badge>
    </Card.Title>
    <Card.Description>
      Delivery is edge-required: members on this origin get edge addresses or nothing, never the
      origin address.
    </Card.Description>
  </Card.Header>
  <Card.Content class="space-y-3 text-sm">
    <p>{delivery.detail}</p>
    {#if delivery.reason}
      <div
        class={delivery.kind === 'dark'
          ? 'rounded-md border border-destructive/40 bg-destructive/10 p-3'
          : 'rounded-md border border-amber-500/40 bg-amber-500/10 p-3'}
      >
        <p class="font-medium">Why: {delivery.reason}</p>
        {#if delivery.fix}
          <p class="mt-1 text-muted-foreground">{delivery.fix}</p>
        {/if}
      </div>
    {/if}
    {#if setup && !setup.complete && setup.currentStep}
      <p class="text-muted-foreground">
        Setup is not finished. Next step: {SETUP_STEP_TITLES[setup.currentStep]}.
        <Link
          href={edgesPaths.setup({ relay: relay.slug, step: setup.currentStep })}
          class="font-medium text-primary hover:underline">Resume setup</Link
        >
      </p>
    {/if}
    {#if relay.origin.kind !== 'manual'}
      <div>
        <Button variant="outline" size="sm" onclick={() => (previewOpen = !previewOpen)}>
          {previewOpen ? 'Hide the preview' : 'Preview what a member receives'}
        </Button>
      </div>
      {#if previewOpen}
        <RenderPreview relayId={relay.id} />
      {/if}
    {/if}
  </Card.Content>
</Card.Root>
