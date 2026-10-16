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
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import {
    attentionQuery,
    edgeKeys,
    serveRelayDirect,
    setupStatusQuery,
  } from '@client/lib/edgesApi';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
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

  // "Serve this node directly again" (the restore workflow, `release_requirement`):
  // offered on an edge-required origin no setup run owns and no restore runs on.
  // The server releases the binding BEFORE any direct Host is enabled again.
  const qc = useQueryClient();
  const canServeDirect = $derived(
    relay.origin.kind !== 'manual' && !relay.bindingDeferred && !relay.setupOwned && !relay.restore,
  );
  let directOpen = $state(false);
  async function serveDirect() {
    await serveRelayDirect(relay.id);
    void qc.invalidateQueries({ queryKey: edgeKeys.all });
    toast.success('Putting the direct address back', {
      description: 'Each step is checked first; the node page shows where it is.',
    });
  }
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
    {#if canServeDirect}
      <div class="border-t pt-3">
        <p class="text-muted-foreground">
          {relay.quarantine
            ? 'Members can be served this node directly again once the quarantine is resolved.'
            : 'To stop using edges for this node, serve members its own address again.'}
        </p>
        <Button
          class="mt-2"
          variant="outline"
          size="sm"
          disabled={!!relay.quarantine}
          onclick={() => (directOpen = true)}
        >
          Serve this node directly again
        </Button>
      </div>
    {/if}
  </Card.Content>
</Card.Root>

<ConfirmDialog
  bind:open={directOpen}
  title="Serve this node directly again?"
  body="Members stop receiving edge addresses for this node and get its own address back. FCP first checks that every member is served, releases edge-required delivery, and only then re-enables the direct addresses it hid. The edges stay, so the node can be protected again later."
  confirmLabel="Serve directly"
  danger
  onConfirm={serveDirect}
/>
