<script lang="ts" module>
  import type { BackendInput } from './overviewModel';
  import type { OpView } from '../../../../../shared/contracts/servers';

  /** What one backend tells the Overview: its Action needed input, its node counts, its changes. */
  export interface BackendReport {
    input: BackendInput;
    /** Nodes switched on, and how many of them are online (null until the tree is read). */
    nodes: { online: number; total: number } | null;
    ops: readonly OpView[];
    /** When its tree was read (ms; 0 before). */
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
    const intentList = intents.data?.intents ?? [];
    const enrolled = (n: { nodeUuid: string; name: string }) =>
      intentList.some((i) => i.nodeUuid === n.nodeUuid || i.name === n.name);
    const on = (t?.nodes ?? []).filter((n) => !n.isDisabled);
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
            ? t.nodes.filter((n) => !enrolled(n)).length
            : 0,
      },
      nodes: t ? { online: on.filter((n) => n.online).length, total: on.length } : null,
      ops: ops.data?.ops ?? [],
      updatedAt: tree.dataUpdatedAt,
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
