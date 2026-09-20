<script lang="ts">
  /**
   * Publish one edge into its origin's pool. The dry run (preflight) is shown
   * first; the start button stays off while anything blocks it.
   *
   * Props:
   *   open: boolean (bindable)
   *   relayId: string
   *   relaySlug: string
   *   edgeId: string
   *   onStarted: (rotationId: string) => void     open the rotation drawer with it
   */
  import { untrack } from 'svelte';
  import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import * as Dialog from '@client/components/ui/dialog';
  import { Button } from '@client/components/ui/button';
  import InlineError from '@client/components/InlineError.svelte';
  import {
    edgeKeys,
    invalidateRelay,
    preflightRelay,
    publishRelayEdge,
  } from '@client/lib/edgesApi';
  import PreflightPanel from '../components/PreflightPanel.svelte';
  import CodeNote from '../components/CodeNote.svelte';
  import { edgeErrorIssue, edgeErrorMessage } from '../lib/edgeErrors';
  import { shortId } from '../lib/time';

  interface Props {
    open: boolean;
    relayId: string;
    relaySlug: string;
    edgeId: string;
    onStarted: (rotationId: string) => void;
  }
  let { open = $bindable(false), relayId, relaySlug, edgeId, onStarted }: Props = $props();

  const qc = useQueryClient();
  const preflight = createQuery(() => ({
    queryKey: [...edgeKeys.relay(relaySlug), 'preflight', 'publish', edgeId] as const,
    queryFn: () => preflightRelay(relayId, { kind: 'publish', edgeId }),
    enabled: open && relayId !== '' && edgeId !== '',
    staleTime: 0,
    gcTime: 0,
    retry: false,
  }));

  const publish = createMutation(() => ({
    mutationFn: () => publishRelayEdge(relayId, { edgeId }),
    onSuccess: (r) => {
      invalidateRelay(qc, relaySlug);
      toast.success('Publishing started');
      open = false;
      onStarted(r.rotationId);
    },
  }));
  $effect(() => {
    if (!open) untrack(() => publish.reset());
  });
  const refusal = $derived(publish.error ? edgeErrorIssue(publish.error) : null);
</script>

<Dialog.Root bind:open>
  <Dialog.Content class="max-h-[90vh] overflow-y-auto sm:max-w-xl">
    <Dialog.Header>
      <Dialog.Title>Publish edge {shortId(edgeId)}</Dialog.Title>
      <Dialog.Description>
        Publishing puts the edge in the pool of relay {relaySlug}. The client-facing Host is pointed
        at it and members start dialing it on their next subscription refresh.
      </Dialog.Description>
    </Dialog.Header>
    <PreflightPanel
      kind="publish"
      result={preflight.data}
      pending={preflight.isFetching}
      error={preflight.isError ? preflight.error : undefined}
      onRetry={() => void preflight.refetch()}
    />
    {#if refusal}
      <CodeNote issue={refusal} />
    {:else if publish.error}
      <InlineError message={edgeErrorMessage(publish.error)} />
    {/if}
    <Dialog.Footer>
      <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
      <Button
        variant="outline"
        disabled={preflight.isFetching}
        onclick={() => void preflight.refetch()}
      >
        Check again
      </Button>
      <Button
        disabled={!preflight.data?.ok || preflight.isFetching || publish.isPending}
        onclick={() => publish.mutate()}
      >
        {publish.isPending ? 'Starting' : 'Publish'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
