<script lang="ts">
  import MoreText from '../../edges/components/MoreText.svelte';
  /**
   * A node's encrypted twin (docs/servers.md "A node serving the encrypted
   * twin"): the mode's own WebSocket transport a second time, encrypted inside
   * the connection, behind the same fronts, so a CDN carries ciphertext only.
   * Turning it on is staged: its address stays off until a test connection
   * through each front reaches the twin. The node's own connection is never
   * touched, and apps that cannot use the twin keep the plain one.
   *
   * Shown only where it applies: the node's mode has a twin on this backend,
   * or the node already serves one.
   *
   * Props: slug, intent (NodeIntentView), canWrite
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { invalidateServers, nodeTwinAction, setupQuery } from '@client/lib/serversApi';
  import type { NodeIntentView } from '../../../../../shared/contracts/servers';
  import StatusDot from '../../edges/simple/StatusDot.svelte';
  import { codeOf } from '../lib/run';
  import { nodeTwinWords, serverErrorWords } from '../lib/words';

  interface Props {
    slug: string;
    intent: NodeIntentView;
    canWrite: boolean;
  }
  let { slug, intent, canWrite }: Props = $props();
  const qc = useQueryClient();
  const uid = $props.id();
  const setup = setupQuery(() => slug);

  let busy = $state(false);

  // The mode's twin on this backend (a second, encrypted transport of the mode).
  let offered = $derived(
    (setup.data?.modes ?? []).find((m) => m.slug === intent.mode.slug)?.twin ?? null,
  );
  let canAdd = $derived(
    canWrite && !intent.twin && !!offered && !offered.detaching && !intent.retirement,
  );
  let words = $derived(intent.twin ? nodeTwinWords(intent.twin) : null);

  async function act(action: 'add' | 'remove', done: string) {
    if (busy) return;
    busy = true;
    try {
      await nodeTwinAction(slug, intent.id, action);
      toast.success(done);
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateServers(qc);
    }
  }
</script>

{#if intent.twin || canAdd || intent.staleRoutes.length > 0}
  <section aria-labelledby={`${uid}-twin`} class="space-y-3">
    <h2 id={`${uid}-twin`} class="text-base font-semibold">Encrypted twin</h2>
    {#each intent.staleRoutes as r (`${r.path}:${r.port}`)}
      <p class="flex items-start gap-2 rounded-md border p-3 text-sm" role="status">
        <StatusDot dot="amber" class="mt-1.5" />
        <MoreText
          text={`The node’s front server still sends ${r.path} to 127.0.0.1:${r.port} from an earlier role run, and FCP no longer hands that route out. Run the node role on this node to take it away. Until then no new transport can use that port or path.`}
        />
      </p>
    {/each}
    {#if intent.twin && words}
      <div class="space-y-2 rounded-md border p-3 text-sm">
        <p class="flex items-start gap-2" role="status">
          <StatusDot dot={words.dot} class="mt-1.5" />
          <span>{words.sentence}</span>
        </p>
        {#if intent.twin.route && intent.twin.state !== 'removing'}
          <p class="text-muted-foreground text-xs break-all">
            Route on the node’s front server: {intent.twin.route.path} to 127.0.0.1:{intent.twin
              .route.port}.
            {#if intent.twin.state === 'activating'}
              {intent.twin.routeBy === 'operator'
                ? 'No role runs this node, so it is added by hand.'
                : intent.twin.routeServed === true
                  ? 'The node role was handed it on its last run.'
                  : 'Run the node role on this node to add it.'}
            {/if}
          </p>
        {/if}
        {#if canWrite && intent.twin.state !== 'removing'}
          <Button
            size="sm"
            variant="ghost"
            class="text-destructive"
            disabled={busy}
            onclick={() => act('remove', 'Being removed.')}
          >
            Stop serving it
          </Button>
        {/if}
      </div>
    {:else if canAdd}
      <Button
        size="sm"
        disabled={busy}
        onclick={() => act('add', 'Turning on. Members get it once each front is checked.')}
      >
        Serve the encrypted twin here
      </Button>
      <p class="text-muted-foreground text-xs">
        <MoreText
          text="The same connection, encrypted inside, so a CDN in front cannot read it. The node’s connections restart once when it turns on. Members get it only through fronts a test connection reached it on, and the plain connection stays for apps that cannot use it."
        />
      </p>
    {/if}
  </section>
{/if}
