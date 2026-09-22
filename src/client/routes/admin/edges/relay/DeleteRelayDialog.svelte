<script lang="ts">
  /**
   * Delete an origin: the typed slug AND a required choice of what the members on
   * this origin get afterwards (`restore-direct` | `keep-dark`).
   *
   * Props: open (bindable); origin; edgeCount (non-destroyed edges that will be torn down)
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import type { OriginAdmin } from '@shared/contracts/edges';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Label } from '@client/components/ui/label';
  import {
    deleteRelay,
    edgeKeys,
    invalidateRelay,
    type RelayDeleteDisposition,
  } from '@client/lib/edgesApi';
  import { router } from '@client/stores/router.svelte';
  import { assertEdgeOk } from '../lib/edgeErrors';
  import { edgesPaths } from '../lib/routes';
  import ActionConfirm from './ActionConfirm.svelte';

  interface Props {
    open: boolean;
    relay: OriginAdmin;
    edgeCount: number;
  }
  let { open = $bindable(false), relay, edgeCount }: Props = $props();

  const qc = useQueryClient();
  let disposition = $state<RelayDeleteDisposition | null>(null);
  let force = $state(false);
  $effect(() => {
    if (open) {
      disposition = null;
      force = false;
    }
  });

  const manual = $derived(relay.origin.kind === 'manual');
  const OPTIONS: Array<{ id: RelayDeleteDisposition; title: string; text: string }> = [
    {
      id: 'restore-direct',
      title: 'Give members the direct address again',
      text: 'Edge-required delivery is lifted for this origin. At their next refresh, members on this node receive the origin address itself, as before the origin existed. Choose this when the node stays in service without edges. The origin address becomes visible to members and to anyone watching them.',
    },
    {
      id: 'keep-dark',
      title: 'Keep members dark',
      text: 'Edge-required delivery stays in force with no origin behind it. Members on this node are answered "temporarily unavailable" and keep their last configuration, which stops working once the edges are destroyed. Choose this when the origin address must never be handed out, for example before you register a new origin for it. The leftover binding can be released later from Settings.',
    },
  ];

  async function run(): Promise<void> {
    if (!disposition) return;
    assertEdgeOk(await deleteRelay(relay.id, disposition, force));
    toast.success('Origin delete started. Its edges are torn down in the background.');
    invalidateRelay(qc, relay.slug);
    void qc.invalidateQueries({ queryKey: edgeKeys.deliveryBindings });
    router.navigate(edgesPaths.overview());
  }
</script>

<ActionConfirm
  bind:open
  title={`Delete origin ${relay.slug}?`}
  body={`This retires every listener and destroys ${edgeCount === 1 ? 'the 1 edge' : `all ${edgeCount} edges`} of the origin at the provider. It cannot be undone.`}
  typed={relay.slug}
  confirmLabel="Delete relay"
  danger
  disabled={disposition === null}
  {run}
>
  <fieldset class="space-y-2">
    <legend class="mb-1 font-medium">
      What should members on this origin get afterwards? (required)
    </legend>
    {#if manual}
      <p class="text-xs text-muted-foreground">
        FCP serves no subscriptions for a manual origin, so both choices behave the same here. Pick
        either.
      </p>
    {/if}
    {#each OPTIONS as opt (opt.id)}
      <label
        class="flex cursor-pointer items-start gap-2 rounded-md border p-3 has-[:checked]:border-primary has-[:checked]:bg-primary/5"
      >
        <input
          type="radio"
          name="relay-delete-disposition"
          class="mt-1 accent-primary"
          value={opt.id}
          checked={disposition === opt.id}
          onchange={() => (disposition = opt.id)}
        />
        <span>
          <span class="block font-medium">{opt.title}</span>
          <span class="block text-xs text-muted-foreground">{opt.text}</span>
        </span>
      </label>
    {/each}
    {#if disposition === null}
      <p class="text-xs text-muted-foreground">Confirm does nothing until one is chosen.</p>
    {/if}
  </fieldset>
  {#if relay.activeRotationId || relay.quarantine}
    <div class="mt-3 flex items-start gap-2">
      <Checkbox id="relay-delete-force" bind:checked={force} class="mt-0.5" />
      <div>
        <Label for="relay-delete-force">Delete even though the origin is busy</Label>
        <p class="text-xs text-muted-foreground">
          {relay.quarantine
            ? 'The relay is quarantined: FCP does not know which Hosts the panel serves. Forcing skips that question, so check the panel Hosts by hand afterwards.'
            : 'A rotation is running. Forcing abandons it where it stands.'}
        </p>
      </div>
    </div>
  {/if}
</ActionConfirm>
