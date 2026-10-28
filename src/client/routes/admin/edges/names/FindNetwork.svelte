<script lang="ts">
  /**
   * Names found on one network (`/admin/edges/find-names/:slug`; docs/edges.md
   * "Finding names"): the sites grouped by the address they live on (each a
   * possible target with the names it serves), and every candidate. A family
   * made from a group starts with the target only; its names are added from
   * the list below, through the family's normal path.
   *
   * All wording lives in ./lib/huntWords.ts (pure, unit-tested).
   */
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Card, CardContent, CardHeader, CardTitle } from '@client/components/ui/card';
  import * as Dialog from '@client/components/ui/dialog';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import Link from '@client/components/Link.svelte';
  import { ApiCallError } from '@client/lib/api';
  import { createFamily, familiesQuery, huntNetworkQuery, invalidateSni } from '@client/lib/sniApi';
  import SectionHeader from '../components/SectionHeader.svelte';
  import { edgesPaths } from '../lib/routes';
  import HuntTable from './HuntTable.svelte';
  import { ctWords, familySlugFor } from './lib/huntWords';
  import { sniErrorWords } from './lib/words';

  let { slug }: { slug: string } = $props();
  const qc = useQueryClient();
  const uid = $props.id();
  const view = huntNetworkQuery(() => slug);
  // Every family (the network list names only the first ones), those on this network.
  const families = familiesQuery();
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);
  let onNetwork = $derived(
    (families.data?.families ?? [])
      .filter((f) => f.network?.slug === slug)
      .map((f) => ({ slug: f.slug, label: f.label })),
  );

  // The first addresses, then every one on asking (none is ever left out).
  const GROUPS_FIRST = 20;
  let allGroups = $state(false);

  // --- a family from a group ---------------------------------------------------------------------
  let open = $state(false);
  let target = $state('');
  let label = $state('');
  let familySlug = $state('');
  let busy = $state(false);
  let slugOk = $derived(/^[a-z0-9][a-z0-9-]{0,39}$/.test(familySlug.trim()));
  function startFamily(best: string) {
    target = best;
    familySlug = familySlugFor(best);
    label = best.replace(/^www\./, '');
    open = true;
  }
  async function makeFamily() {
    if (!slugOk || busy) return;
    busy = true;
    try {
      await createFamily({
        slug: familySlug.trim(),
        label: label.trim() || target,
        targetAddress: target,
        targetPort: 443,
        requireH2: true,
        network: slug,
      });
      open = false;
      toast.success('Family made. Add its names from the list: each is checked against it.');
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateSni(qc);
    }
  }
</script>

<p class="mb-2 text-sm">
  <Link href={edgesPaths.findNames()} class="text-muted-foreground underline underline-offset-4">
    Find names
  </Link>
</p>

{#if view.isPending}
  <p class="text-muted-foreground text-sm">Loading…</p>
{:else if view.isError}
  <p class="text-destructive text-sm">{sniErrorWords(codeOf(view.error))}</p>
{:else if view.data}
  {@const v = view.data}
  <SectionHeader
    title={`Names on ${v.scope.label}`}
    description="Real sites whose every address is on this network. Each one is checked the way a family would check it; adding one to a family checks it again there before it can be used."
  />

  <Card>
    <CardHeader>
      <CardTitle class="text-base">Sites by address</CardTitle>
    </CardHeader>
    <CardContent class="space-y-3 text-sm">
      <p class="text-muted-foreground">
        Names that live on one address can share a target: make a family with one of them as its
        target, then add the others.
      </p>
      {#if v.groups.length === 0}
        <p class="text-muted-foreground">No site of this network has been found and checked yet.</p>
      {:else}
        <ul class="divide-y rounded-md border" aria-label="Sites by address">
          {#each allGroups ? v.groups : v.groups.slice(0, GROUPS_FIRST) as g (g.address)}
            <li class="flex flex-wrap items-center justify-between gap-3 p-3">
              <div class="min-w-0 flex-1">
                <p class="font-mono break-all">{g.address}</p>
                <p class="text-muted-foreground">
                  {g.passing} of {g.names}
                  {g.names === 1 ? 'name' : 'names'} would qualify, such as
                  <span class="font-mono">{g.best}</span>.
                </p>
              </div>
              <Button
                size="sm"
                variant="outline"
                class="h-11 sm:h-8"
                disabled={g.passing === 0}
                onclick={() => startFamily(g.best)}
              >
                Make a family with this target
              </Button>
            </li>
          {/each}
        </ul>
        {#if v.groups.length > GROUPS_FIRST}
          <Button variant="outline" size="sm" onclick={() => (allGroups = !allGroups)}>
            {allGroups ? `Show the first ${GROUPS_FIRST}` : `Show all ${v.groups.length} addresses`}
          </Button>
        {/if}
      {/if}
      {#if v.families.length > 0}
        <div class="space-y-1">
          <p class="font-medium">Found for the families on this network</p>
          <p class="text-muted-foreground">
            Each was checked against its family's target, so they are listed on the family's page.
          </p>
          <ul>
            {#each v.families as f (f.slug)}
              <li>
                <Link href={edgesPaths.family(f.slug)} class="underline underline-offset-4">
                  {f.label}
                </Link>: {f.candidates.total} found, {f.candidates.ready} would qualify.
              </li>
            {/each}
          </ul>
        </div>
      {/if}
      {#if v.ct.length > 0}
        <div class="space-y-1">
          <p class="font-medium">Certificate logs</p>
          <ul class="text-muted-foreground">
            {#each v.ct as r (r.domain)}
              <li>{ctWords(r)}</li>
            {/each}
          </ul>
        </div>
      {/if}
    </CardContent>
  </Card>

  <Card class="mt-6">
    <CardHeader>
      <CardTitle class="text-base">Names</CardTitle>
    </CardHeader>
    <CardContent class="text-sm">
      {#if onNetwork.length === 0}
        <p class="text-muted-foreground mb-3">
          No family is on this network yet: make one above to add names to it.
        </p>
      {/if}
      <HuntTable kind="network" {slug} families={onNetwork} />
    </CardContent>
  </Card>
{/if}

<Dialog.Root bind:open>
  <Dialog.Content class={`${DIALOG_FIT} sm:max-w-md`}>
    <Dialog.Header>
      <Dialog.Title>Make a family with this target</Dialog.Title>
      <Dialog.Description>
        Its target is <span class="font-mono">{target}</span> on port 443, over HTTP/2, on this network.
        A family's target never changes.
      </Dialog.Description>
    </Dialog.Header>
    <form
      class="space-y-3"
      onsubmit={(e) => {
        e.preventDefault();
        void makeFamily();
      }}
    >
      <div class="space-y-1.5">
        <Label for={`${uid}-label`}>Name</Label>
        <Input id={`${uid}-label`} bind:value={label} autocomplete="off" />
      </div>
      <div class="space-y-1.5">
        <Label for={`${uid}-slug`}>Short id</Label>
        <Input
          id={`${uid}-slug`}
          bind:value={familySlug}
          autocomplete="off"
          autocapitalize="off"
          spellcheck={false}
          aria-invalid={!slugOk}
        />
      </div>
      <Dialog.Footer class={STICKY_FOOTER}>
        <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button type="submit" disabled={!slugOk || busy}>{busy ? 'Working…' : 'Make it'}</Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
