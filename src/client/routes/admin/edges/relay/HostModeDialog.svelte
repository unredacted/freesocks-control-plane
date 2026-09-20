<script lang="ts">
  /**
   * Switch who writes the client-facing backend Hosts (`fcp` <-> `operator`), with
   * the consequences spelled out. `operator -> fcp` needs every listener Host
   * adopted first; the refusal (`host_adopt_required`) is shown in words.
   *
   * Props: open (bindable); origin; listeners
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import type { HostMode, RelayAdmin, RelayListenerAdmin } from '@shared/contracts/edges';
  import { invalidateRelay, updateRelay } from '@client/lib/edgesApi';
  import Link from '@client/components/Link.svelte';
  import { assertEdgeOk } from '../lib/edgeErrors';
  import { edgesPaths } from '../lib/routes';
  import ActionConfirm from './ActionConfirm.svelte';
  import { HOST_MODE_WORDS } from './relayLogic';

  interface Props {
    open: boolean;
    relay: RelayAdmin;
    listeners: RelayListenerAdmin[];
  }
  let { open = $bindable(false), relay, listeners }: Props = $props();

  const qc = useQueryClient();
  const target = $derived<HostMode>(relay.hostMode === 'fcp' ? 'operator' : 'fcp');
  /** Live listeners whose Host FCP has not adopted (or created) yet. */
  const unadopted = $derived(
    listeners.filter((l) => !l.retired && l.panelBinding !== null && l.host?.ownership == null),
  );

  async function run(): Promise<void> {
    assertEdgeOk(await updateRelay(relay.id, { hostMode: target }));
    toast.success(
      target === 'fcp' ? 'FCP writes the backend Hosts now.' : 'You write the backend Hosts now.',
    );
    invalidateRelay(qc, relay.slug);
  }
</script>

<ActionConfirm
  bind:open
  title={target === 'fcp'
    ? 'Let FCP write the panel Hosts?'
    : 'Take over the panel Hosts yourself?'}
  body={HOST_MODE_WORDS[target].explain}
  confirmLabel={target === 'fcp' ? 'Hand the Hosts to FCP' : 'I will write the Hosts'}
  danger={target === 'operator'}
  {run}
>
  {#if target === 'operator'}
    <ul class="list-disc space-y-1 ps-5 text-muted-foreground">
      <li>
        Every existing Host stays in the backend and is marked as adopted: FCP never deletes it.
      </li>
      <li>
        After each publish or rotation you must apply the Hosts plan (Listeners tab) yourself, or
        members keep dialling the old edge.
      </li>
      <li>
        The block detector cannot rotate the first edge of a listener any more: those replacements
        are refused unless an admin forces them.
      </li>
    </ul>
  {:else}
    <ul class="list-disc space-y-1 ps-5 text-muted-foreground">
      <li>
        FCP must first adopt the Host of every listener, so it knows exactly which backend rows it
        may rewrite. It never guesses by name.
      </li>
      <li>Adopted Hosts are rewritten on rotations but never deleted by FCP.</li>
    </ul>
    {#if unadopted.length > 0}
      <p
        class="mt-3 rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-amber-800 dark:text-amber-200"
      >
        {unadopted.length === 1 ? 'One listener has' : `${unadopted.length} listeners have`} no adopted
        Host yet ({unadopted.map((l) => l.listenerKey).join(', ')}). The switch will be refused
        until you use "Adopt a Host" on
        <Link
          href={edgesPaths.relay(relay.slug, { tab: 'listeners' })}
          class="font-medium underline"
          onclick={() => (open = false)}>the Listeners tab</Link
        >.
      </p>
    {/if}
  {/if}
</ActionConfirm>
