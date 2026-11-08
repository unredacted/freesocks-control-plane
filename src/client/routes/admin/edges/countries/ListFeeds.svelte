<script lang="ts">
  /**
   * Where a country list's names go as finding-names candidates: networks and
   * families (none by default), each with what its last run added. Choosing a
   * feed starts a run of the version in use; a new version runs again on its
   * own. Qualification then checks each name as usual.
   *
   * Props: list: CountryListView
   * All wording lives in ./listWords.ts (pure, unit-tested).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Card, CardContent } from '@client/components/ui/card';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Dialog from '@client/components/ui/dialog';
  import { Label } from '@client/components/ui/label';
  import { ApiCallError } from '@client/lib/api';
  import {
    feedCountryListAgain,
    invalidateCountryLists,
    setCountryListFeeds,
  } from '@client/lib/countryListsApi';
  import { familiesQuery, networksQuery } from '@client/lib/sniApi';
  import { MAX_LIST_FEEDS, type CountryListView } from '@shared/contracts/countryLists';
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { feedLine, listErrorWords } from './listWords';

  let { list }: { list: CountryListView } = $props();
  const qc = useQueryClient();
  const uid = $props.id();
  const networks = networksQuery();
  const families = familiesQuery();
  let open = $state(false);
  let busy = $state(false);
  let picked = $state<string[]>([]);

  const keyOf = (f: { kind: 'network' | 'family'; slug: string | null }) => `${f.kind}:${f.slug}`;
  function edit() {
    picked = list.feeds.filter((f) => f.slug).map(keyOf);
    open = true;
  }
  const toggle = (key: string, on: boolean) =>
    (picked = on ? [...picked, key] : picked.filter((k) => k !== key));

  async function run(work: () => Promise<{ started: number }>, done: (n: number) => string) {
    busy = true;
    try {
      const r = await work();
      toast.success(done(r.started));
      return true;
    } catch (e) {
      toast.error(listErrorWords(e instanceof ApiCallError ? e.payload.error.code : null));
      return false;
    } finally {
      busy = false;
      invalidateCountryLists(qc);
    }
  }

  async function save() {
    const feeds = picked.map((k) => {
      const [kind, slug] = [k.slice(0, k.indexOf(':')), k.slice(k.indexOf(':') + 1)];
      return kind === 'network' ? { network: slug } : { family: slug };
    });
    if (
      await run(
        () => setCountryListFeeds(list.id, feeds),
        (n) => (n > 0 ? 'Saved. Its hostnames are going in now.' : 'Saved.'),
      )
    )
      open = false;
  }
</script>

<Card class="mt-4">
  <CardContent class="space-y-3 py-5 text-sm">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div class="min-w-0 flex-1">
        <h2 class="text-base font-medium">Hostnames as SNI candidates</h2>
        <p class="text-muted-foreground mt-1">
          Its hostnames can go to networks and SNI lists as candidates, checked like any other.
          Being on the list says nothing about the address an SNI is used with.
        </p>
      </div>
      <div class="flex flex-wrap gap-2">
        <Button size="sm" variant="outline" disabled={busy} onclick={edit}>Choose</Button>
        {#if list.feeds.length > 0}
          <Button
            size="sm"
            variant="outline"
            disabled={busy || !list.active}
            onclick={() =>
              void run(
                () => feedCountryListAgain(list.id),
                (n) => (n > 0 ? 'Its hostnames are going in again.' : 'Nothing to feed now.'),
              )}
          >
            Feed again
          </Button>
        {/if}
      </div>
    </div>
    {#if list.feeds.length === 0}
      <p class="text-muted-foreground">Its hostnames go nowhere.</p>
    {:else}
      <ul class="divide-y rounded-md border" aria-label="Feeds">
        {#each list.feeds as f, i (i)}
          <li class="space-y-0.5 p-3">
            <p class="font-medium">
              {f.label ?? 'Removed'}
              <span class="text-muted-foreground font-normal">
                ({f.kind === 'network' ? 'network' : 'SNI list'})
              </span>
            </p>
            <p class="text-muted-foreground">{feedLine(f)}</p>
          </li>
        {/each}
      </ul>
    {/if}
  </CardContent>
</Card>

<Dialog.Root bind:open>
  <Dialog.Content class={`${DIALOG_FIT} sm:max-w-md`}>
    <Dialog.Header>
      <Dialog.Title>Where its hostnames go</Dialog.Title>
      <Dialog.Description>
        At most {MAX_LIST_FEEDS}. A new choice takes the version in use now.
      </Dialog.Description>
    </Dialog.Header>
    <div class="space-y-4 text-sm">
      <div class="space-y-2">
        <p class="font-medium">Networks</p>
        {#each networks.data?.networks ?? [] as n (n.slug)}
          <div class="flex items-center gap-2">
            <Checkbox
              id={`${uid}-n-${n.slug}`}
              checked={picked.includes(`network:${n.slug}`)}
              onCheckedChange={(v) => toggle(`network:${n.slug}`, v === true)}
            />
            <Label for={`${uid}-n-${n.slug}`} class="font-normal">{n.label}</Label>
          </div>
        {:else}
          <p class="text-muted-foreground">No network yet.</p>
        {/each}
      </div>
      <div class="space-y-2">
        <p class="font-medium">SNI lists</p>
        {#each families.data?.families ?? [] as f (f.slug)}
          <div class="flex items-center gap-2">
            <Checkbox
              id={`${uid}-f-${f.slug}`}
              checked={picked.includes(`family:${f.slug}`)}
              onCheckedChange={(v) => toggle(`family:${f.slug}`, v === true)}
            />
            <Label for={`${uid}-f-${f.slug}`} class="font-normal">{f.label}</Label>
          </div>
        {:else}
          <p class="text-muted-foreground">No SNI list yet.</p>
        {/each}
      </div>
    </div>
    <Dialog.Footer class={STICKY_FOOTER}>
      <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
      <Button disabled={busy || picked.length > MAX_LIST_FEEDS} onclick={() => void save()}>
        {busy ? 'Working…' : 'Save'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
