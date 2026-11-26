<script lang="ts">
  /**
   * One backend's set-up-once parts on Nodes, behind its Details disclosure
   * (BackendStatus): its quiet notes (leftovers worth knowing, words.ts
   * `quietNotes`), how it is set up (with Change setup), the encrypted twins of
   * its CDN-fronted modes, its mode groups and its recent changes.
   *
   * Props:
   *   slug: string
   *   canWrite: boolean               changes from here are on and the backend is set up
   *   canChangeSetup: boolean         changes from here are on and the backend can be written to
   *   onChangeSetup: () => void       opens the setup sheet for this backend
   */
  import { Button } from '@client/components/ui/button';
  import { serverTreeQuery, setupQuery } from '@client/lib/serversApi';
  import ModeGroupsCard from './ModeGroupsCard.svelte';
  import ModeTwinsCard from './ModeTwinsCard.svelte';
  import OpsList from './OpsList.svelte';
  import { setupSummary } from '../lib/setupChange';
  import { quietNotes } from '../lib/words';

  interface Props {
    slug: string;
    canWrite: boolean;
    canChangeSetup: boolean;
    onChangeSetup: () => void;
  }
  let { slug, canWrite, canChangeSetup, onChangeSetup }: Props = $props();

  const tree = serverTreeQuery(() => slug);
  const setup = setupQuery(() => slug);
  const notes = $derived(tree.data ? quietNotes(tree.data) : []);
</script>

{#if tree.data}
  <section class="space-y-6" aria-label="Backend details">
    {#if notes.length > 0}
      <ul class="text-muted-foreground space-y-1 text-sm" aria-label="Notes">
        {#each notes as n (n)}
          <li>{n}</li>
        {/each}
      </ul>
    {/if}

    {#if setup.data?.established && setup.data.state === 'ready'}
      <section aria-labelledby={`backend-setup-${slug}`}>
        <div class="mb-1 flex items-center justify-between gap-3">
          <h2 id={`backend-setup-${slug}`} class="text-base font-semibold">Backend setup</h2>
          {#if canChangeSetup}
            <Button
              variant="outline"
              size="sm"
              disabled={setup.data.running}
              onclick={onChangeSetup}
            >
              Change setup
            </Button>
          {/if}
        </div>
        <p class="text-muted-foreground text-sm">{setupSummary(setup.data)}</p>
      </section>
    {/if}

    {#if setup.data?.established && setup.data.state === 'ready'}
      <ModeTwinsCard {slug} {canWrite} />
    {/if}
    <ModeGroupsCard {slug} tree={tree.data} {canWrite} />
    {#if canChangeSetup}
      <OpsList {slug} />
    {/if}
  </section>
{/if}
