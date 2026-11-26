<script lang="ts">
  /**
   * One backend on Nodes, as one line of the Backends list: its dot and name,
   * its one status sentence and when its panel was read (amber when reading
   * has fallen behind), then two disclosures, both closed by default:
   *
   *   Action needed (N)   its own rows, grouped like the Overview's
   *                       (overviewModel.ts `backendRows` + ../overview/ActionNeeded):
   *                       held nodes, setup, a key that does not match, a
   *                       profile edited elsewhere, SNIs that wait. Opens by
   *                       itself when one is critical.
   *   Details             BackendDetails: setup, encryption, mode groups,
   *                       recent changes.
   *
   * Its port changes (PortChangesCard) show under the line while there are any.
   *
   * Props:
   *   slug: string                      the backend's slug
   *   name: string                      its name
   *   canWrite: boolean                 changes from here are on and the backend is set up
   *   manageOn: boolean                 changes from here are on
   *   setUp: boolean                    the node role follows the ownership protocol here
   *   active: boolean                   switched on (Backends settings); a switched-off backend
   *                                     is never read, so it says so instead of a stale status
   *   observeOn: boolean                regular reading is on
   *   canChangeSetup: boolean           changes from here are on and the backend can be written to
   *   onSetUp: () => void               opens the setup sheet for this backend
   */
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import { Badge } from '@client/components/ui/badge';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { transportsQuery } from '@client/lib/sniApi';
  import { cn } from '@client/lib/utils';
  import { intentsQuery, opsQuery, serverTreeQuery, setupQuery } from '@client/lib/serversApi';
  import { namesNeedsYou } from '../../edges/names/lib/transportWords';
  import StatusDot from '../../edges/simple/StatusDot.svelte';
  import ActionNeeded from '../overview/ActionNeeded.svelte';
  import { backendRows, groupRows } from '../overview/overviewModel';
  import BackendDetails from './BackendDetails.svelte';
  import PortChangesCard from './PortChangesCard.svelte';
  import { codeOf } from '../lib/run';
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
    canWrite: boolean;
    manageOn: boolean;
    setUp: boolean;
    active: boolean;
    observeOn: boolean;
    canChangeSetup: boolean;
    onSetUp: () => void;
  }
  let { slug, name, canWrite, manageOn, setUp, active, observeOn, canChangeSetup, onSetUp }: Props =
    $props();

  const uid = $props.id();
  const tree = serverTreeQuery(() => slug);
  const setup = setupQuery(() => slug);
  const intents = intentsQuery(() => slug);
  const sniTransports = transportsQuery(() => slug);
  const ops = opsQuery(
    () => slug,
    () => true,
  );
  const applyingTo = $derived(nodesBeingChanged(ops.data?.ops ?? []));
  const intentOf = (node: { nodeUuid: string; name: string }) =>
    intents.data?.intents.find((i) => i.nodeUuid === node.nodeUuid || i.name === node.name) ?? null;
  const restarting = (node: { nodeUuid: string; name: string }): boolean => {
    if (applyingTo.has(node.nodeUuid)) return true;
    const i = intentOf(node);
    return !!i && intentRestarting(i, Date.now());
  };

  // The same rows the Overview lists for this backend (its port changes have their own card here).
  const rows = $derived(
    tree.data
      ? backendRows(
          {
            slug,
            name,
            canWrite,
            manageOn,
            setUp,
            setupRow: setup.data ? setupWords(setup.data) : null,
            holds: intents.data?.holds ?? [],
            needs: needsYou(tree.data),
            names: sniTransports.data ? namesNeedsYou(sniTransports.data) : [],
            portChanges: [],
            ops: [],
            unadopted: 0,
            readFailed: false,
          },
          false,
          Date.now(),
        )
      : [],
  );
  const groups = $derived(groupRows(rows));
  const hasCritical = $derived(groups.some((g) => g.severity === 'critical'));
  const worst = $derived(
    hasCritical ? 'danger' : groups.some((g) => g.severity === 'warning') ? 'warning' : 'info',
  );

  let actionsOpen = $state<boolean | null>(null);
  const actionsShown = $derived(actionsOpen ?? hasCritical);
  let detailsOpen = $state(false);

  /** Panels are read every ten minutes; an hour without a read is worth a look. */
  const STALE_MS = 3_600_000;
  const readAge = $derived(
    tree.data?.state.observedAt ? Date.now() - Date.parse(tree.data.state.observedAt) : null,
  );
  const stale = $derived(active && observeOn && readAge !== null && readAge > STALE_MS);

  const TOGGLE =
    'text-muted-foreground hover:text-foreground focus-visible:ring-ring/50 inline-flex h-8 items-center gap-1.5 rounded-md px-2 text-sm outline-none focus-visible:ring-3';
</script>

<div class="px-3 py-3 sm:px-4">
  {#if tree.isPending}
    <Skeleton class="h-6 w-64" />
  {:else if tree.isError}
    <p class="text-sm">
      <span class="font-medium">{name}</span>
      <span class="text-destructive">{serverErrorWords(codeOf(tree.error))}</span>
    </p>
  {:else if tree.data}
    {@const t = tree.data}
    {@const headline = fleetSentence(t.nodes, restarting)}
    <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
      <div class="min-w-0 flex-1 basis-72">
        <p class="flex items-center gap-2" role="status">
          <StatusDot
            dot={!active ? 'grey' : t.state.ok === false ? 'red' : headline.dot}
            class="size-2.5"
          />
          <span class="truncate font-medium" title={name}>{name}</span>
          {#if !active}<Badge variant="muted">Switched off</Badge>{/if}
        </p>
        <p class="text-muted-foreground mt-0.5 ps-4.5 text-sm">
          {#if !active}
            Not used for keys and not read; switch it on under Settings, Backends.
          {:else}
            {t.state.ok === false ? 'The panel could not be read.' : headline.text}
          {/if}
          {#if !active}
            <!-- Nothing reads a switched-off backend: no read age to show. -->
          {:else if t.state.observedAt}
            <span
              class={cn(stale && 'text-amber-700 dark:text-amber-400')}
              title={stale
                ? 'Panels are read every ten minutes; this one has fallen behind.'
                : undefined}
            >
              Read {ago(readAge ?? 0)}{observeOn ? '' : ' (regular reading is off)'}.
            </span>
          {:else}
            Not read yet.
          {/if}
        </p>
      </div>
      <div class="flex shrink-0 flex-wrap items-center gap-1">
        {#if groups.length > 0}
          <button
            type="button"
            class={TOGGLE}
            aria-expanded={actionsShown}
            aria-controls={`${uid}-actions`}
            onclick={() => (actionsOpen = !actionsShown)}
          >
            Action needed
            <Badge variant={worst} class="tabular-nums">{groups.length}</Badge>
            <ChevronDown
              class={cn('size-4 transition-transform', actionsShown && 'rotate-180')}
              aria-hidden="true"
            />
          </button>
        {/if}
        <button
          type="button"
          class={TOGGLE}
          aria-expanded={detailsOpen}
          aria-controls={`${uid}-details`}
          onclick={() => (detailsOpen = !detailsOpen)}
        >
          Details
          <ChevronDown
            class={cn('size-4 transition-transform', detailsOpen && 'rotate-180')}
            aria-hidden="true"
          />
        </button>
      </div>
    </div>

    {#if actionsShown && rows.length > 0}
      <div id={`${uid}-actions`} class="mt-3">
        <ActionNeeded {rows} {onSetUp} title={`Action needed on ${name}`} max={8} />
      </div>
    {/if}
    <div class="mt-3 empty:hidden"><PortChangesCard {slug} {canWrite} /></div>
    {#if detailsOpen}
      <div id={`${uid}-details`} class="mt-4 border-t pt-4">
        <BackendDetails {slug} {canWrite} {canChangeSetup} onChangeSetup={onSetUp} />
      </div>
    {/if}
  {/if}
</div>
