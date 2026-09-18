<script lang="ts">
  /**
   * Step 4, relay and listener. Two paths side by side: register here, or let
   * the node role register (copyable role variables, a link to mint its token).
   *
   * Props: StepBodyProps + draft (StoredDraft | null) + onRelayCreated(slug) + onWatchSlug(slug)
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import { Button, buttonVariants } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import Link from '@client/components/Link.svelte';
  import { invalidateRelay, relayListenersQuery } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import CodeNote from '../components/CodeNote.svelte';
  import ProtocolBadge from '../components/ProtocolBadge.svelte';
  import LayerBadge from '../components/LayerBadge.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import NewRelayDialog from '../forms/NewRelayDialog.svelte';
  import AddListenerDialog from '../forms/AddListenerDialog.svelte';
  import { relaySlugIssue } from '../forms/prefill';
  import { edgesPaths } from '../lib/routes';
  import StepIssues from './StepIssues.svelte';
  import RoleVarsCard from './RoleVarsCard.svelte';
  import type { StoredDraft } from './draft';
  import type { StepBodyProps } from './types';

  interface Props extends StepBodyProps {
    draft: StoredDraft | null;
    onRelayCreated: (slug: string) => void;
    onWatchSlug: (slug: string) => void;
  }
  let { step, status, relay, linkCtx, draft, onRelayCreated, onWatchSlug }: Props = $props();

  const uid = $props.id();
  const qc = useQueryClient();
  const listeners = relayListenersQuery({
    slug: () => relay?.slug ?? null,
    id: () => relay?.id ?? null,
  });
  const live = $derived((listeners.data?.listeners ?? []).filter((l) => !l.retired));
  const membersDark = $derived(step.warnings.find((w) => w.code === 'members_dark') ?? null);

  let newRelayOpen = $state(false);
  let addListenerOpen = $state(false);
  let watchSlug = $state('');
  let watchTried = $state(false);
  const watchProblem = $derived(relaySlugIssue(watchSlug));
</script>

<div class="space-y-4">
  {#if membersDark}
    <div
      class="rounded-md border border-amber-500/50 bg-amber-500/10 px-3 py-2.5 text-sm"
      role="alert"
    >
      <p class="font-semibold">Members on this node are unavailable right now.</p>
      <p>
        This relay requires an edge, so members whose key lives on it receive a temporary failure
        instead of a subscription until an edge is published and rendering is on. Finish the steps
        below without a long pause.
      </p>
    </div>
  {/if}
  <StepIssues {step} ctx={linkCtx} hide={['members_dark', 'no_relay', 'relay_without_listener']} />

  <div class="grid gap-4 xl:grid-cols-2">
    <Card>
      <CardHeader>
        <CardTitle class="text-base">Register here</CardTitle>
        <CardDescription>
          Describe the relay and its listeners in this console. Good for a manual origin or a
          backend server, and for a node the role does not manage.
        </CardDescription>
      </CardHeader>
      <CardContent class="space-y-3">
        {#if !relay}
          <Button onclick={() => (newRelayOpen = true)}>Create the relay</Button>
          {#if draft && (draft.origin || draft.listeners.length > 0)}
            <p class="text-muted-foreground text-xs">
              The form opens with the origin and the listeners you described in step 1.
            </p>
          {/if}
        {:else}
          {#if listeners.isError}
            <AdminListState error={listeners.error} onRetry={() => void listeners.refetch()} />
          {:else if !listeners.isPending && live.length === 0}
            <AdminListState
              emptyText="This relay has no listener yet. Add one here, or let the node role register it."
            />
          {:else}
            <ul class="divide-y rounded-md border text-sm">
              {#each live as l (l.id)}
                <li class="flex flex-wrap items-center gap-2 px-3 py-2">
                  <span class="font-mono">{l.listenerKey}</span>
                  <ProtocolBadge
                    protocol={l.protocol}
                    streamTransport={l.streamTransport}
                    security={l.security}
                    compact
                  />
                  {#each l.layers as layer (layer)}<LayerBadge {layer} />{/each}
                  {#if !l.deployed}
                    <StatusBadge kind="setup" value="blocked" label="Not deployed" />
                  {:else if !l.enabled}
                    <StatusBadge kind="setup" value="blocked" label="Disabled" />
                  {/if}
                  <span class="text-muted-foreground ms-auto text-xs">
                    {l.source === 'role' ? 'from the node role' : 'added here'}
                  </span>
                </li>
              {/each}
            </ul>
          {/if}
          <div class="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onclick={() => (addListenerOpen = true)}>
              Add a listener
            </Button>
            <Link
              href={edgesPaths.relay(relay.slug, { tab: 'listeners' })}
              class={buttonVariants({ size: 'sm', variant: 'ghost' })}
            >
              Manage listeners
            </Link>
          </div>
        {/if}
      </CardContent>
    </Card>

    <Card>
      <CardHeader>
        <CardTitle class="text-base">Waiting for the node role</CardTitle>
        <CardDescription>
          The node role registers the relay and its listeners itself, with one idempotent call,
          every time it runs. Nothing to type here.
        </CardDescription>
      </CardHeader>
      <CardContent class="space-y-3">
        {#if relay}
          <RoleVarsCard roleVars={status.roleVars} lastRegisteredAt={relay.lastRegisteredAt} />
        {:else}
          <p class="text-sm">
            Pick the slug the role will register under, give the role a token, run it, then watch
            for the relay here.
          </p>
          <RoleVarsCard roleVars={null} />
          <form
            class="space-y-1.5"
            onsubmit={(e) => {
              e.preventDefault();
              watchTried = true;
              if (watchProblem === null) onWatchSlug(watchSlug.trim());
            }}
          >
            <Label for={`${uid}-watch`}>Slug the role registers under</Label>
            <div class="flex gap-2">
              <Input
                id={`${uid}-watch`}
                class="font-mono"
                placeholder="node1"
                bind:value={watchSlug}
              />
              <Button type="submit" variant="outline">Watch for it</Button>
            </div>
            {#if watchTried && watchProblem}
              <p class="text-destructive text-xs" role="alert">{watchProblem}</p>
            {/if}
          </form>
        {/if}
      </CardContent>
    </Card>
  </div>

  {#if relay && live.length === 0 && !listeners.isPending}
    <CodeNote tone="info" issue={{ code: 'relay_without_listener', subject: relay.slug }} />
  {/if}
</div>

<NewRelayDialog bind:open={newRelayOpen} {draft} onCreated={onRelayCreated} />
{#if relay}
  <AddListenerDialog
    bind:open={addListenerOpen}
    relayId={relay.id}
    relaySlug={relay.slug}
    originKind={relay.origin.kind}
    onSaved={() => invalidateRelay(qc, relay.slug)}
  />
{/if}
