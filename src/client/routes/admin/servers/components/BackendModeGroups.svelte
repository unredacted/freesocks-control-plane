<script lang="ts">
  /**
   * One backend's mode groups on its row of Settings -> Backends: the same card
   * as on Nodes (ModeGroupsCard: add, change, remove), read from the backend's
   * cached tree. Changes need "Changes from here" on and a backend the node
   * role has set up; until the panel was read once, it says how to get there.
   *
   * Props: slug (the backend server's slug)
   */
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '@client/components/Link.svelte';
  import { serverSummaryQuery, serverTreeQuery } from '@client/lib/serversApi';
  import { edgesPaths } from '../../edges/lib/routes';
  import ModeGroupsCard from './ModeGroupsCard.svelte';

  let { slug }: { slug: string } = $props();

  const summary = serverSummaryQuery();
  const instance = $derived(summary.data?.instances.find((i) => i.slug === slug) ?? null);
  const tree = serverTreeQuery(() => (instance?.observable ? slug : null));
  const canWrite = $derived(
    !!summary.data?.config['manage.enabled'] && !!instance?.writable && !!instance?.setUp,
  );
</script>

{#if instance?.observable}
  {#if tree.isPending}
    <Skeleton class="h-16" />
  {:else if tree.isError}
    <p class="text-muted-foreground text-sm">Its mode groups could not be read just now.</p>
  {:else if tree.data && !tree.data.state.observedAt && tree.data.modeGroups.length === 0}
    <p class="text-muted-foreground text-sm">
      Its mode groups show once its panel has been read.
      <Link
        href={edgesPaths.settings({ field: 'manage.observe' })}
        class="underline underline-offset-2">Read panels every ten minutes</Link
      >
      is in Settings, Maintenance.
    </p>
  {:else if tree.data}
    <ModeGroupsCard {slug} tree={tree.data} {canWrite} />
  {/if}
{/if}
