<script lang="ts">
  /**
   * One backend's status on Nodes, above the table: its sentence and when the
   * panel was read, its Action needed (held nodes, setup, a key that does not
   * match, a profile edited elsewhere, SNIs that wait: names/lib/transportWords.ts)
   * and its port changes. With more than one backend, each says its name.
   *
   * Props:
   *   slug: string                      the backend's slug
   *   name: string                      its name
   *   showName: boolean                 more than one backend: say whose this is
   *   canWrite: boolean                 changes from here are on and the backend is set up
   *   manageOn: boolean                 changes from here are on
   *   setUp: boolean                    the node role follows the ownership protocol here
   *   observeOn: boolean                regular reading is on
   *   onSetUp: () => void               opens the setup sheet for this backend
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '@client/components/Link.svelte';
  import { transportsQuery } from '@client/lib/sniApi';
  import {
    acknowledgeForeignEdit,
    intentsQuery,
    invalidateServers,
    opsQuery,
    releaseHold,
    serverTreeQuery,
    setupQuery,
  } from '@client/lib/serversApi';
  import { edgesPaths } from '../../edges/lib/routes';
  import { namesNeedsYou } from '../../edges/names/lib/transportWords';
  import StatusDot from '../../edges/simple/StatusDot.svelte';
  import PortChangesCard from './PortChangesCard.svelte';
  import { codeOf } from '../lib/run';
  import { serversPaths } from '../lib/routes';
  import {
    ago,
    fleetSentence,
    intentRestarting,
    needsYou,
    nodesBeingChanged,
    serverErrorWords,
    setupWords,
  } from '../lib/words';

  interface Props {
    slug: string;
    name: string;
    showName: boolean;
    canWrite: boolean;
    manageOn: boolean;
    setUp: boolean;
    observeOn: boolean;
    onSetUp: () => void;
  }
  let { slug, name, showName, canWrite, manageOn, setUp, observeOn, onSetUp }: Props = $props();

  const qc = useQueryClient();
  const tree = serverTreeQuery(() => slug);
  const setup = setupQuery(() => slug);
  const intents = intentsQuery(() => slug);
  const sniTransports = transportsQuery(() => slug);
  const ops = opsQuery(
    () => slug,
    () => true,
  );
  const namesRows = $derived(sniTransports.data ? namesNeedsYou(sniTransports.data) : []);
  const holds = $derived(intents.data?.holds ?? []);
  const setupRow = $derived(setup.data ? setupWords(setup.data) : null);
  const applyingTo = $derived(nodesBeingChanged(ops.data?.ops ?? []));
  const intentOf = (node: { nodeUuid: string; name: string }) =>
    intents.data?.intents.find((i) => i.nodeUuid === node.nodeUuid || i.name === node.name) ?? null;
  const restarting = (node: { nodeUuid: string; name: string }): boolean => {
    if (applyingTo.has(node.nodeUuid)) return true;
    const i = intentOf(node);
    return !!i && intentRestarting(i, Date.now());
  };

  async function release(holdId: string) {
    try {
      await releaseHold(slug, holdId);
      toast.success('Hold released.');
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      invalidateServers(qc);
    }
  }

  async function seen(profileUuid: string) {
    try {
      await acknowledgeForeignEdit(slug, profileUuid);
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      invalidateServers(qc);
    }
  }

  const ITEM =
    'flex flex-wrap items-center gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2.5 text-sm';
</script>

{#if tree.isPending}
  <Skeleton class="h-6 w-64" />
{:else if tree.isError}
  <p class="text-destructive text-sm">
    {#if showName}{name}:
    {/if}{serverErrorWords(codeOf(tree.error))}
  </p>
{:else if tree.data}
  {@const t = tree.data}
  {@const headline = fleetSentence(t.nodes, restarting)}
  {@const attention = needsYou(t)}
  <div>
    <p class="flex items-center gap-2 text-lg font-medium" role="status">
      <StatusDot dot={t.state.ok === false ? 'red' : headline.dot} class="size-3" />
      {#if showName}<span>{name}:</span>{/if}
      {t.state.ok === false ? 'The panel could not be read.' : headline.text}
    </p>
    <p class="text-muted-foreground mt-1 text-sm">
      {#if t.state.observedAt}
        Read {ago(Date.now() - Date.parse(t.state.observedAt))}{observeOn
          ? ''
          : '. Regular reading is off'}.
      {:else}
        Not read yet.
      {/if}
    </p>
  </div>

  {#if attention.length > 0 || namesRows.length > 0 || holds.length > 0 || (manageOn && setupRow) || (manageOn && !setUp && !setupRow)}
    <section aria-labelledby={`needs-you-${slug}`}>
      <h2 id={`needs-you-${slug}`} class="mb-3 text-base font-semibold">
        Action needed{showName ? ` on ${name}` : ''}
      </h2>
      <ul class="space-y-2">
        {#each holds as h (h.id)}
          <li class={ITEM}>
            <span class="min-w-0 flex-1">
              {h.heldNodeNames.join(', ')}
              {h.heldNodeNames.length === 1 ? 'is' : 'are'} held closed since a profile change
              {ago(Date.now() - Date.parse(h.since))}. Nothing re-checks nodes that are not
              enrolled. Check them yourself, then release the hold.
            </span>
            {#if canWrite}
              <Button variant="outline" size="sm" onclick={() => release(h.id)}>Release</Button>
            {/if}
          </li>
        {/each}
        {#if manageOn && setupRow}
          <li class={ITEM}>
            <span class="min-w-0 flex-1">{setupRow}</span>
            <Button variant="outline" size="sm" onclick={onSetUp}>Set up</Button>
          </li>
        {:else if manageOn && !setUp}
          <li class="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2.5 text-sm">
            Changes are on but refused until this backend is set up. Set it up first.
          </li>
        {/if}
        {#each attention as row (row.key)}
          <li class={ITEM}>
            <span class="min-w-0 flex-1">{row.text}</span>
            {#if row.key.startsWith('edit:') && canWrite}
              <Button variant="outline" size="sm" onclick={() => seen(row.key.slice(5))}>
                Seen it
              </Button>
            {:else if row.nodeUuid}
              <Link
                href={serversPaths.node(row.nodeUuid, { backend: slug })}
                class="text-primary text-sm underline underline-offset-4"
              >
                Open
              </Link>
            {/if}
          </li>
        {/each}
        {#each namesRows as row (row.key)}
          <li class={ITEM}>
            <span class="min-w-0 flex-1">{row.text}</span>
            {#if row.nodeUuid}
              <Link
                href={serversPaths.node(row.nodeUuid, { backend: slug })}
                class="text-primary text-sm underline underline-offset-4"
              >
                Open
              </Link>
            {:else if row.family}
              <Link
                href={edgesPaths.family(row.family)}
                class="text-primary text-sm underline underline-offset-4"
              >
                Open the SNI list
              </Link>
            {/if}
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  <PortChangesCard {slug} {canWrite} />
{/if}
