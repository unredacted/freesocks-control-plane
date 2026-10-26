<script lang="ts">
  /**
   * A node's address lanes (docs/edges.md "Address enumeration"), on the node
   * page once members are spread over the addresses (`edgePick: hrw1`). Off:
   * what lanes do and "Set up trusted addresses". On: per transport, what each
   * lane holds against its target, the open lane's budget today, Change and
   * Turn off. The dialog says what switching on does to the addresses in use
   * (they all become open; fresh trusted ones are made, each a load balancer);
   * turning off says the trusted ones become open for good. Words: lanesWords.ts.
   *
   * Props:
   *   relay: { id, slug, lanes }   the origin (its lanes, null = off)
   *   busy: boolean                a run holds the node (no switch then)
   *   promoteAfterDays: number     `edge.trust.promoteAfterDays`, for the off text
   *   nameOf: (listenerKey) => string
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { invalidateRelay, relayLanesQuery, setRelayLanes } from '@client/lib/edgesApi';
  import ActionConfirm from '../relay/ActionConfirm.svelte';
  import NumberField from '../components/NumberField.svelte';
  import {
    LANES_CARD,
    LANES_DIALOG,
    LANES_OFF,
    laneLine,
    lanesInputProblem,
    openBudgetLine,
  } from './lanesWords';

  interface Props {
    relay: { id: string; slug: string; lanes: { open: number; trusted: number } | null };
    busy: boolean;
    promoteAfterDays: number;
    nameOf: (listenerKey: string) => string;
  }
  let { relay, busy, promoteAfterDays, nameOf }: Props = $props();
  const uid = $props.id();
  const qc = useQueryClient();
  const lanesQ = relayLanesQuery({ slug: () => relay.slug, id: () => relay.id });
  const view = $derived(lanesQ.data ?? null);

  let editOpen = $state(false);
  let offOpen = $state(false);
  let open = $state(1);
  let trusted = $state(4);
  const problem = $derived(lanesInputProblem(open, trusted));
  function edit() {
    open = relay.lanes?.open ?? 1;
    trusted = relay.lanes?.trusted ?? 4;
    editOpen = true;
  }
  async function save(next: { open: number; trusted: number } | null) {
    await setRelayLanes(relay.id, next);
    toast.success(
      next
        ? 'Trusted addresses are set. FCP makes the new ones next.'
        : 'Trusted addresses are off.',
    );
    invalidateRelay(qc, relay.slug);
  }
</script>

<section class="rounded-lg border p-3" aria-labelledby={`${uid}-lanes`}>
  <h3 id={`${uid}-lanes`} class="text-sm font-semibold">{LANES_CARD.title}</h3>
  {#if !relay.lanes}
    <p class="text-muted-foreground mt-1 text-sm">{LANES_CARD.off(promoteAfterDays)}</p>
    <Button class="mt-2" size="sm" variant="outline" disabled={busy} onclick={edit}>
      {LANES_CARD.setUp}
    </Button>
  {:else}
    {#if view}
      <ul class="text-muted-foreground mt-1 space-y-1 text-sm">
        {#each view.transports as t (t.listenerId)}
          <li>{nameOf(t.listenerKey)}: {laneLine(t, relay.lanes)}</li>
        {/each}
      </ul>
      <p class="text-muted-foreground mt-1 text-xs">{openBudgetLine(view)}</p>
    {/if}
    <div class="mt-2 flex flex-wrap gap-2">
      <Button size="sm" variant="outline" disabled={busy} onclick={edit}>{LANES_CARD.change}</Button
      >
      <Button size="sm" variant="outline" disabled={busy} onclick={() => (offOpen = true)}>
        {LANES_CARD.turnOff}
      </Button>
    </div>
  {/if}
</section>

<ActionConfirm
  bind:open={editOpen}
  title={LANES_DIALOG.title}
  body={relay.lanes ? LANES_DIALOG.changeBody : LANES_DIALOG.onBody}
  confirmLabel={relay.lanes ? LANES_DIALOG.save : LANES_DIALOG.turnOn}
  disabled={problem !== null}
  run={() => save({ open, trusted })}
>
  <div class="flex flex-col gap-3">
    <NumberField
      bind:value={trusted}
      label={LANES_DIALOG.trusted}
      min={1}
      max={32}
      helper={LANES_DIALOG.trustedHelp}
    />
    <NumberField
      bind:value={open}
      label={LANES_DIALOG.open}
      min={0}
      max={32}
      helper={LANES_DIALOG.openHelp}
    />
    {#if problem}<p class="text-destructive text-sm">{problem}</p>{/if}
  </div>
</ActionConfirm>

<ActionConfirm
  bind:open={offOpen}
  title={LANES_OFF.title}
  body={LANES_OFF.body}
  confirmLabel={LANES_OFF.label}
  danger
  run={() => save(null)}
/>
