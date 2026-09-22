<script lang="ts">
  /**
   * Step 1, origin source. With an origin: what it dials, read only (the origin
   * kind never changes). With a draft: choose the origin and say what its
   * transport will speak, so the next steps are judged against it.
   *
   * Props: StepBodyProps + draft (bindable StoredDraft | null; null = origin mode)
   */
  import Plus from '@lucide/svelte/icons/plus';
  import Trash2 from '@lucide/svelte/icons/trash-2';
  import { Button, buttonVariants } from '@client/components/ui/button';
  import Link from '@client/components/Link.svelte';
  import { adminBackendServersQuery } from '@client/lib/queries';
  import KeyValue from '../components/KeyValue.svelte';
  import OriginPicker from '../forms/OriginPicker.svelte';
  import ListenerFields from '../forms/ListenerFields.svelte';
  import { emptyOrigin, type OriginDraft } from '../forms/origin';
  import { emptyListenerForm, formCombo } from '../forms/listenerForm';
  import type { KeyValueRow } from '../lib/types';
  import StepIssues from './StepIssues.svelte';
  import { backendServersHref } from './issueActions';
  import type { StoredDraft } from './draft';
  import type { StepBodyProps } from './types';

  interface Props extends StepBodyProps {
    draft: StoredDraft | null;
  }
  let { step, relay, linkCtx, draft = $bindable() }: Props = $props();

  const servers = adminBackendServersQuery();
  const KIND_WORDS = {
    'panel-node': 'A node of a backend',
    'backend-server': 'A whole backend server',
    manual: 'An address described by hand',
  } as const;

  const relayRows = $derived.by((): KeyValueRow[] => {
    if (!relay) return [];
    const o = relay.origin;
    const rows: KeyValueRow[] = [{ label: 'Kind', value: KIND_WORDS[o.kind] }];
    if (o.kind !== 'manual') {
      const server = servers.data?.find((s) => s.id === o.backendServerId);
      rows.push({
        label: o.kind === 'panel-node' ? 'Panel' : 'Backend server',
        value: server?.name ?? 'A backend server that is no longer registered',
      });
    }
    if (o.kind === 'panel-node') rows.push({ label: 'Node', value: o.nodeName, mono: true });
    rows.push({
      label: 'Origin address',
      value: relay.originAddress,
      mono: true,
      copy: true,
      hint: 'What edges dial. Members never see it.',
    });
    return rows;
  });

  const blank = emptyOrigin();
  const origin = $derived<OriginDraft>(draft?.origin ?? blank);
  function onOrigin(next: OriginDraft) {
    if (draft) draft = { ...draft, origin: next };
  }
  function addListener() {
    if (draft)
      draft = { ...draft, listeners: [...draft.listeners, emptyListenerForm(origin.kind)] };
  }
  function removeListener(i: number) {
    if (draft) draft = { ...draft, listeners: draft.listeners.filter((_, idx) => idx !== i) };
  }
</script>

<div class="space-y-4">
  <StepIssues {step} ctx={linkCtx} hide={draft ? ['no_origin'] : []} />

  {#if relay}
    <KeyValue title="What this relay's edges dial" rows={relayRows} columns={2} />
    <p class="text-muted-foreground text-sm">
      The kind of target never changes. To front something else, start a new origin.
    </p>
  {:else if draft}
    <div class="rounded-md border p-3 text-sm">
      <p class="font-medium">Is the backend or server not registered yet?</p>
      <p class="text-muted-foreground">
        A backend node or a backend server origin needs its backend registered first. An address you
        describe by hand needs nothing else.
      </p>
      <Link
        href={backendServersHref(linkCtx.returnTo)}
        class={buttonVariants({ size: 'sm', variant: 'outline', class: 'mt-2' })}
      >
        Open Backend servers
      </Link>
    </div>

    <OriginPicker bind:value={() => origin, onOrigin} />

    <section class="space-y-3">
      <div class="flex items-center justify-between gap-2">
        <div>
          <h3 class="text-sm font-semibold">What will the transport speak?</h3>
          <p class="text-muted-foreground text-xs">
            Used to judge which provider accounts can front it. Nothing is created yet.
          </p>
        </div>
        <Button size="sm" variant="outline" onclick={addListener}>
          <Plus class="size-4" aria-hidden="true" /> Add
        </Button>
      </div>
      {#each draft.listeners as _, i (i)}
        <div class="space-y-3 rounded-lg border p-3">
          <div class="flex items-center justify-between gap-2">
            <p class="text-sm font-medium">{formCombo(draft.listeners[i]!).label}</p>
            <Button
              size="sm"
              variant="ghost"
              aria-label="Remove this intended listener"
              onclick={() => removeListener(i)}
            >
              <Trash2 class="size-4" aria-hidden="true" />
            </Button>
          </div>
          <ListenerFields bind:form={draft.listeners[i]!} originKind={origin.kind} brief />
        </div>
      {:else}
        <p class="text-muted-foreground rounded-lg border border-dashed p-4 text-center text-sm">
          No intended listener yet. Add one so the account step can check compatibility, or skip
          this when the node role will register the listeners.
        </p>
      {/each}
    </section>
  {/if}
</div>
