<script lang="ts">
  /**
   * One port a name list is used on, on the list's page: the same status line
   * and next step as the node page (TransportNames, for every node at once),
   * then each node behind it with what its members get and, where names wait
   * for a test there, "Test one name" through one of its proven addresses.
   *
   * A port the backend no longer lists (as Servers last read it) says so and
   * keeps "Stop managing", so the list can still change network or be removed.
   *
   * Props: binding (the list's binding to that port).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '@client/components/Link.svelte';
  import { ApiCallError } from '@client/lib/api';
  import { invalidateSni, transportsQuery, unbindFamily } from '@client/lib/sniApi';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { sniErrorWords } from './lib/words';
  import type { SniBinding, SniTransportNode } from '../../../../../shared/contracts/sni';
  import { serversPaths } from '../../servers/lib/routes';
  import StatusDot from '../simple/StatusDot.svelte';
  import TestNameDialog from './TestNameDialog.svelte';
  import TransportNames from './TransportNames.svelte';
  import { nodeLineWords } from './lib/transportWords';

  let { binding }: { binding: SniBinding } = $props();
  const view = transportsQuery(() => binding.backendSlug);
  let transport = $derived(view.data?.transports.find((t) => t.list?.bindingId === binding.id));

  let testing = $state<SniTransportNode | null>(null);
  let testOpen = $state(false);

  const qc = useQueryClient();
  let stopOpen = $state(false);
  async function stop() {
    try {
      await unbindFamily(binding.id);
      stopOpen = false;
      toast.success('FCP no longer manages the names of that port.');
    } catch (e) {
      toast.error(sniErrorWords(e instanceof ApiCallError ? e.payload.error.code : null));
    } finally {
      invalidateSni(qc);
    }
  }
</script>

<section class="rounded-lg border p-3 text-sm" aria-label={binding.inboundTag}>
  <p class="font-medium break-all">
    {binding.inboundTag}
    <span class="text-muted-foreground font-normal">
      on {binding.backendSlug}{transport?.port ? `, port ${transport.port}` : ''}
    </span>
  </p>
  {#if view.isError}
    <p class="text-muted-foreground mt-2">Where these names stand could not be read just now.</p>
  {:else if view.data && !transport}
    <div class="mt-2 flex flex-wrap items-center gap-3">
      <p class="min-w-0 flex-1 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2">
        This port is not on the backend as Servers last read it. Refresh it under Servers, or stop
        managing it here: the list can then change its network or be removed.
      </p>
      <Button variant="outline" size="sm" onclick={() => (stopOpen = true)}>Stop managing</Button>
    </div>
    <ConfirmDialog
      bind:open={stopOpen}
      title="Stop managing this port's names?"
      body="Whatever names the port still has stay as they are. The name list itself is kept."
      confirmLabel="Stop managing"
      danger
      onConfirm={stop}
    />
  {:else}
    <TransportNames
      backendSlug={binding.backendSlug}
      nodeUuid={null}
      {transport}
      switches={view.data?.switches}
      names={[]}
      serversHref={serversPaths.home({ instance: binding.backendSlug })}
    />
    {#if !transport}
      <Skeleton class="mt-2 h-5 w-48" />
    {:else if transport.nodes.length === 0}
      <p class="text-muted-foreground mt-2">
        No node behind this port is protected yet: members get its names through protected addresses
        only.
      </p>
    {:else}
      <ul class="mt-3 divide-y rounded-md border" aria-label="Nodes">
        {#each transport.nodes as n (n.relaySlug)}
          {@const w = nodeLineWords(n)}
          <li class="flex flex-wrap items-center gap-3 p-3">
            <span class="min-w-0 flex-1">
              <span class="flex items-center gap-2 font-medium">
                <StatusDot dot={w.dot} />
                {n.nodeName}
              </span>
              <span class="text-muted-foreground block">{w.text}</span>
            </span>
            {#if n.waitingTest > 0 && transport.send?.phase === 'panel_confirmed' && n.testable.length > 0}
              <Button
                size="sm"
                onclick={() => {
                  testing = n;
                  testOpen = true;
                }}
              >
                Test one name
              </Button>
            {/if}
            {#if n.nodeUuid}
              <Link
                href={serversPaths.node(n.nodeUuid, { instance: binding.backendSlug })}
                class="text-primary underline underline-offset-4"
              >
                Open the node
              </Link>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
    {#if testing && transport?.send}
      <TestNameDialog bind:open={testOpen} send={transport.send} node={testing} />
    {/if}
  {/if}
</section>
