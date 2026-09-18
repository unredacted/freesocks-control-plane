<script lang="ts">
  /**
   * The wizard's first screen (no `?relay`): resume a relay whose setup is not
   * finished, or start a new one. Progress is never stored here: the list comes
   * from the fleet setup status.
   *
   * Props:
   *   hasDraft: boolean                  a draft from an earlier visit exists in this browser
   *   onStartNew: (keepDraft: boolean) => void
   */
  import { Button, buttonVariants } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '@client/components/Link.svelte';
  import { setupStatusQuery } from '@client/lib/edgesApi';
  import { SETUP_STEP_TITLES } from '@client/lib/edgeCodes';
  import AdminListState from '../../AdminListState.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import { edgesPaths } from '../lib/routes';

  interface Props {
    hasDraft: boolean;
    onStartNew: (keepDraft: boolean) => void;
  }
  let { hasDraft, onStartNew }: Props = $props();

  const fleet = setupStatusQuery(() => null);
  const resume = $derived(fleet.data?.resume ?? []);
  const incomplete = $derived(resume.filter((r) => !r.complete));
  const complete = $derived(resume.filter((r) => r.complete));
</script>

<div class="grid gap-4 lg:grid-cols-2">
  <section class="space-y-3 rounded-lg border p-4">
    <div>
      <h2 class="text-base font-semibold">Continue a relay</h2>
      <p class="text-muted-foreground text-sm">
        Relays whose setup is not finished. The steps are judged by the server each time, so you can
        leave and come back at any point.
      </p>
    </div>
    {#if fleet.isError}
      <AdminListState error={fleet.error} onRetry={() => void fleet.refetch()} />
    {:else if fleet.isPending}
      <Skeleton class="h-16 w-full" />
    {:else if incomplete.length === 0}
      <AdminListState
        emptyText={complete.length > 0
          ? 'Every relay has finished its setup. Start a new relay to add another origin.'
          : 'No relay exists yet. Start a new relay on the right.'}
      />
    {:else}
      <ul class="divide-y rounded-md border">
        {#each incomplete as r (r.relayId)}
          <li class="flex flex-wrap items-center gap-2 px-3 py-2">
            <span class="font-mono text-sm">{r.relaySlug}</span>
            {#if r.currentStep}
              <StatusBadge
                kind="setup"
                value="ready"
                label={`Next: ${SETUP_STEP_TITLES[r.currentStep]}`}
              />
            {/if}
            <Link
              href={edgesPaths.setup({ relay: r.relaySlug })}
              class={buttonVariants({ size: 'sm', class: 'ms-auto' })}
            >
              Continue
            </Link>
          </li>
        {/each}
      </ul>
    {/if}
    {#if complete.length > 0}
      <p class="text-muted-foreground text-xs">
        Finished: {complete.map((r) => r.relaySlug).join(', ')}.
      </p>
    {/if}
  </section>

  <section class="space-y-3 rounded-lg border p-4">
    <div>
      <h2 class="text-base font-semibold">Start a new relay</h2>
      <p class="text-muted-foreground text-sm">
        Nine short steps from an origin to a published, watched edge. Until the relay is created,
        what you choose is kept as a draft in this browser only.
      </p>
    </div>
    <div class="flex flex-wrap gap-2">
      {#if hasDraft}
        <Button onclick={() => onStartNew(true)}>Continue my draft</Button>
        <Button variant="outline" onclick={() => onStartNew(false)}
          >Discard it and start over</Button
        >
      {:else}
        <Button onclick={() => onStartNew(false)}>Start a new relay</Button>
      {/if}
    </div>
  </section>
</div>
