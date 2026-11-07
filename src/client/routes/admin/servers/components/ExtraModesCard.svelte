<script lang="ts">
  /**
   * The modes a node serves beside its own (docs/servers.md "A node serving an
   * extra mode"): today a Hysteria 2 transport (UDP 443) on a direct REALITY
   * node. Each has its own stage. Adding one is staged: nothing changes on the
   * node until its firewall lets the port in (the role's report, or an admin
   * for a node no role runs). Removing one takes its address away first.
   *
   * Props: slug, intent (NodeIntentView), canWrite
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Label } from '@client/components/ui/label';
  import { extraModeAction, invalidateServers, setupQuery } from '@client/lib/serversApi';
  import type { NodeIntentView } from '../../../../../shared/contracts/servers';
  import StatusDot from '../../edges/simple/StatusDot.svelte';
  import { codeOf } from '../lib/run';
  import { extraModeWords, serverErrorWords } from '../lib/words';

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
  let pick = $state('');

  // A node members reach at its own address can serve a direct Hysteria mode
  // the backend is set up for (the server refuses anything else and says why).
  let candidates = $derived(
    intent.mode.shape.fronting !== 'direct' || intent.retirement
      ? []
      : (setup.data?.modes ?? []).filter(
          (m) =>
            m.shape.transport === 'hysteria' &&
            m.shape.fronting === 'direct' &&
            m.slug !== intent.mode.slug &&
            !intent.extraModes.some((x) => x.slug === m.slug),
        ),
  );
  let nameOf = $derived(
    Object.fromEntries((setup.data?.modes ?? []).map((m) => [m.slug, m.name])) as Record<
      string,
      string
    >,
  );

  async function act(mode: string, action: 'add' | 'firewall-confirmed' | 'remove', done: string) {
    if (busy) return;
    busy = true;
    try {
      await extraModeAction(slug, intent.id, mode, action);
      toast.success(done);
      if (action === 'add') pick = '';
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateServers(qc);
    }
  }
</script>

{#if intent.extraModes.length > 0 || (canWrite && candidates.length > 0)}
  <section aria-labelledby={`${uid}-extra`} class="space-y-3">
    <h2 id={`${uid}-extra`} class="text-base font-semibold">Also serves</h2>
    {#each intent.extraModes as m (m.slug)}
      {@const w = extraModeWords(m)}
      <div class="space-y-2 rounded-md border p-3 text-sm">
        <p class="font-medium break-all">{nameOf[m.slug] ?? m.slug}</p>
        <p class="flex items-start gap-2" role="status">
          <StatusDot dot={w.dot} class="mt-1.5" />
          <span>{w.sentence}</span>
        </p>
        {#if canWrite}
          <div class="flex flex-wrap gap-2">
            {#if m.state === 'waiting_firewall' && m.firewall.confirmedBy === 'operator'}
              <Button
                size="sm"
                variant="outline"
                disabled={busy}
                onclick={() => act(m.slug, 'firewall-confirmed', 'Confirmed. Turning it on.')}
              >
                Its firewall lets {m.firewall.port}
                {m.firewall.protocol === 'udp' ? '(UDP)' : ''} in
              </Button>
            {/if}
            {#if m.state !== 'removing'}
              <Button
                size="sm"
                variant="ghost"
                class="text-destructive"
                disabled={busy}
                onclick={() => act(m.slug, 'remove', 'Being removed.')}
              >
                Stop serving it
              </Button>
            {/if}
          </div>
        {/if}
      </div>
    {/each}
    {#if canWrite && candidates.length > 0}
      <div class="flex flex-wrap items-end gap-2">
        <div class="space-y-1">
          <Label for={`${uid}-pick`} class="text-xs">Serve another mode here</Label>
          <select
            id={`${uid}-pick`}
            class="bg-background rounded-md border px-2 py-1.5 text-sm"
            bind:value={pick}
          >
            <option value="">Pick a mode</option>
            {#each candidates as m (m.slug)}
              <option value={m.slug}>{m.name}</option>
            {/each}
          </select>
        </div>
        <Button
          size="sm"
          disabled={!pick || busy}
          onclick={() => act(pick, 'add', 'Added. It waits for the node’s firewall.')}
        >
          Add
        </Button>
      </div>
      <p class="text-muted-foreground text-xs">
        It needs its port open on the node first. Members get it only once it is checked, and the
        node’s own mode keeps serving throughout.
      </p>
    {/if}
  </section>
{/if}
