<script lang="ts">
  /**
   * Port changes that wait for the nodes' firewalls, and what each node waits
   * on: the node role's report (run the role on it), or an admin's
   * confirmation for a node no role runs (unmanaged or adopted). A change
   * still waiting can be cancelled; nothing was sent yet.
   *
   * Props: slug, profileUuid? (only this profile's changes), canWrite
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import {
    acknowledgePortChange,
    cancelPortChange,
    invalidateServers,
    portChangesQuery,
  } from '@client/lib/serversApi';
  import StatusDot from '../../edges/simple/StatusDot.svelte';
  import { codeOf } from '../lib/run';
  import {
    firewallNodeWords,
    portChangeTitle,
    portChangeWords,
    serverErrorWords,
  } from '../lib/words';

  let {
    slug,
    profileUuid = null,
    canWrite,
  }: { slug: string; profileUuid?: string | null; canWrite: boolean } = $props();
  const qc = useQueryClient();
  const changes = portChangesQuery(() => slug);
  const DAY = 24 * 3600_000;

  // Open changes, and a refused or hand-settled one for a day so the operator sees why.
  let shown = $derived(
    (changes.data?.changes ?? []).filter(
      (c) =>
        (!profileUuid || c.profileUuid === profileUuid) &&
        (c.state === 'waiting' ||
          c.state === 'applying' ||
          ((c.state === 'refused' || c.state === 'recovered') &&
            Date.now() - Date.parse(c.updatedAt) < DAY)),
    ),
  );
  let busy = $state(false);

  async function act(run: () => Promise<unknown>, done: string) {
    if (busy) return;
    busy = true;
    try {
      await run();
      toast.success(done);
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateServers(qc);
    }
  }
</script>

{#if shown.length > 0}
  <section aria-labelledby="port-changes" class="space-y-3">
    <h2 id="port-changes" class="text-base font-semibold">Port changes</h2>
    {#each shown as c (c.id)}
      {@const w = portChangeWords(c)}
      <div class="rounded-lg border p-3 text-sm">
        <p class="flex items-center gap-2 font-medium">
          <StatusDot dot={w.dot} />
          <span class="break-all">{portChangeTitle(c)}</span>
        </p>
        <p class="text-muted-foreground mt-1">{w.sentence}</p>
        {#if c.state === 'waiting' && c.nodes.length > 0}
          <ul class="mt-2 space-y-1.5" aria-label="Nodes this change waits for">
            {#each c.nodes as n (n.name)}
              <li class="flex flex-wrap items-center gap-x-3 gap-y-1">
                <span class="font-medium break-all">{n.name}</span>
                <span class="text-muted-foreground">{firewallNodeWords(n, c.toPort)}</span>
                {#if canWrite && n.confirmedBy === 'operator' && n.state === 'waiting'}
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={busy}
                    onclick={() =>
                      act(
                        () => acknowledgePortChange(slug, c.id, [n.name]),
                        `${n.name}: confirmed.`,
                      )}
                  >
                    Its firewall lets {c.toPort} in
                  </Button>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
        {#if canWrite && c.state === 'waiting'}
          <Button
            variant="ghost"
            size="sm"
            class="-ms-2 mt-2"
            disabled={busy}
            onclick={() => act(() => cancelPortChange(slug, c.id), 'Cancelled. Nothing was sent.')}
          >
            Cancel this change
          </Button>
        {/if}
      </div>
    {/each}
  </section>
{/if}
