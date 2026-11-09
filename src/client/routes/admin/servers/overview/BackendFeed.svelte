<script lang="ts" module>
  import type { BackendInput } from './overviewModel';
  import type { OpView } from '../../../../../shared/contracts/servers';

  /** What one backend tells the Overview: its Action needed input, its node counts, its changes. */
  export interface BackendReport {
    input: BackendInput;
    /** Nodes switched on, and how many are online (null until read, or when the panel read failed). */
    nodes: { online: number; total: number } | null;
    ops: readonly OpView[];
    /** When the oldest of its queries was read (ms; 0 before any). */
    updatedAt: number;
  }
</script>

<script lang="ts">
  /**
   * One backend server's own queries for the Overview, drawn as nothing: the
   * same ones the Nodes page reads (tree, intents, setup, SNI transports, port
   * changes, recent changes), so the cache is shared. What they say is handed
   * up through `onReport` (null when this backend goes away), where
   * overviewModel.ts merges every backend into one Action needed list.
   *
   * Props:
   *   slug, name, writable, setUp, manageOn: from the server summary
   *   onReport: (slug, report | null) => void
   */
  import { untrack } from 'svelte';
  import { transportsQuery } from '@client/lib/sniApi';
  import {
    intentsQuery,
    opsQuery,
    portChangesQuery,
    serverTreeQuery,
    setupQuery,
  } from '@client/lib/serversApi';
  import { namesNeedsYou } from '../../edges/names/lib/transportWords';
  import { needsYou, setupWords } from '../lib/words';
  import { backendNodeCounts, oldestRead, unadoptedCount } from './overviewModel';

  interface Props {
    slug: string;
    name: string;
    writable: boolean;
    setUp: boolean;
    manageOn: boolean;
    onReport: (slug: string, report: BackendReport | null) => void;
  }
  let { slug, name, writable, setUp, manageOn, onReport }: Props = $props();

  const tree = serverTreeQuery(() => slug);
  const intents = intentsQuery(() => slug);
  const setup = setupQuery(() => slug);
  const transports = transportsQuery(() => slug);
  const portChanges = portChangesQuery(() => slug);
  const ops = opsQuery(
    () => slug,
    () => true,
  );

  const report = $derived.by((): BackendReport => {
    const canWrite = manageOn && writable && setUp;
    const t = tree.data;
    return {
      input: {
        slug,
        name,
        canWrite,
        manageOn,
        setUp,
        setupRow: setup.data ? setupWords(setup.data) : null,
        holds: intents.data?.holds ?? [],
        needs: t ? needsYou(t) : [],
        names: transports.data ? namesNeedsYou(transports.data) : [],
        portChanges: portChanges.data?.changes ?? [],
        ops: ops.data?.ops ?? [],
        unadopted:
          t && intents.data && canWrite && setup.data?.state === 'ready'
            ? unadoptedCount(t.nodes, intents.data.intents)
            : 0,
        // As the Nodes page: "The panel could not be read" (cached nodes are not current).
        readFailed: tree.isError || t?.state.ok === false,
      },
      nodes: backendNodeCounts(tree.isError ? null : (t ?? null)),
      ops: ops.data?.ops ?? [],
      updatedAt: oldestRead([
        tree.dataUpdatedAt,
        intents.dataUpdatedAt,
        setup.dataUpdatedAt,
        transports.dataUpdatedAt,
        portChanges.dataUpdatedAt,
        ops.dataUpdatedAt,
      ]),
    };
  });

  // Handed up outside tracking: the parent's state it writes is never read here.
  $effect(() => {
    const s = slug;
    const r = report;
    untrack(() => onReport(s, r));
  });
  $effect(() => {
    const s = slug;
    return () => untrack(() => onReport(s, null));
  });
</script>
