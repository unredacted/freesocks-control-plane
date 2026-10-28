<script lang="ts">
  /**
   * Networks (docs/edges.md "Networks"): one or more ASNs and the address
   * ranges they announce, plus ranges entered by hand. A name list on a
   * network has its cover site and every name on it; a port using such a list
   * gets addresses only from locations on it. Ranges are counted here, never listed.
   *
   * All wording lives in ./lib/words.ts (pure, unit-tested).
   */
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Card, CardContent } from '@client/components/ui/card';
  import * as Dialog from '@client/components/ui/dialog';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { ApiCallError } from '@client/lib/api';
  import {
    createNetwork,
    invalidateSni,
    networksQuery,
    refreshNetwork,
    removeNetwork,
    updateNetwork,
  } from '@client/lib/sniApi';
  import type { EdgeNetworkView } from '../../../../../shared/contracts/sni';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { networkLine, parseAsns, parseRanges, sniErrorWords } from './lib/words';

  const qc = useQueryClient();
  const uid = $props.id();
  const networks = networksQuery();
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);

  let busy = $state(false);
  async function run<T>(work: () => Promise<T>): Promise<T | null> {
    busy = true;
    try {
      return await work();
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
      return null;
    } finally {
      busy = false;
      invalidateSni(qc);
    }
  }

  // --- add / edit ----------------------------------------------------------------------------
  let open = $state(false);
  let editing = $state<EdgeNetworkView | null>(null);
  let label = $state('');
  let slug = $state('');
  let asns = $state('');
  let ranges = $state('');
  let slugOk = $derived(/^[a-z0-9][a-z0-9-]{0,39}$/.test(slug.trim()));
  let parsedAsns = $derived(parseAsns(asns));
  let parsedRanges = $derived(parseRanges(ranges));
  let valid = $derived(
    label.trim().length > 0 &&
      (editing !== null || slugOk) &&
      parsedAsns !== null &&
      parsedRanges !== null &&
      parsedAsns.length + parsedRanges.length > 0,
  );

  function startAdd() {
    editing = null;
    label = '';
    slug = '';
    asns = '';
    ranges = '';
    open = true;
  }
  function startEdit(n: EdgeNetworkView) {
    editing = n;
    label = n.label;
    slug = n.slug;
    asns = n.asns.map((a) => `AS${a}`).join(' ');
    ranges = n.manualPrefixes.join('\n');
    open = true;
  }
  async function save() {
    if (!valid || busy) return;
    const body = {
      label: label.trim(),
      asns: parsedAsns ?? [],
      manualPrefixes: parsedRanges ?? [],
    };
    const done = await run(() =>
      editing ? updateNetwork(editing.slug, body) : createNetwork({ ...body, slug: slug.trim() }),
    );
    if (done !== null) {
      open = false;
      toast.success(editing ? 'Network saved.' : 'Network added. Its ranges are being read.');
    }
  }

  async function refresh(n: EdgeNetworkView) {
    const r = await run(() => refreshNetwork(n.slug));
    if (r) toast.message(r.failed > 0 ? 'The ranges could not be read.' : 'Ranges read again.');
  }

  let removing = $state<EdgeNetworkView | null>(null);
  let removeOpen = $state(false);
</script>

<Card class="mt-8">
  <CardContent class="space-y-4 py-5 text-sm">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div class="min-w-0 flex-1">
        <h2 class="text-base font-medium">Networks</h2>
        <p class="text-muted-foreground mt-1">
          Where a name list's cover site and names live, by the ASNs that announce their addresses.
          A port using a list on a network gets addresses only from that network, so a name and the
          address it is shown to belong together.
        </p>
      </div>
      <Button size="sm" onclick={startAdd}>Add a network</Button>
    </div>
    {#if networks.isError}
      <p class="text-destructive">{sniErrorWords(codeOf(networks.error))}</p>
    {:else if (networks.data?.networks.length ?? 0) === 0}
      <p class="text-muted-foreground">
        No network yet. Name lists without one may use any address.
      </p>
    {:else}
      <ul class="divide-y rounded-md border" aria-label="Networks">
        {#each networks.data?.networks ?? [] as n (n.id)}
          <li class="flex flex-wrap items-start justify-between gap-3 p-3">
            <div class="min-w-0 flex-1 space-y-1">
              <p class="font-medium">{n.label}</p>
              <p class="text-muted-foreground">{networkLine(n)}</p>
            </div>
            <div class="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="outline"
                class="h-11 sm:h-8"
                disabled={busy || n.asns.length === 0}
                onclick={() => void refresh(n)}
              >
                Read ranges again
              </Button>
              <Button
                size="sm"
                variant="outline"
                class="h-11 sm:h-8"
                disabled={busy}
                onclick={() => startEdit(n)}
              >
                Edit
              </Button>
              <Button
                size="sm"
                variant="ghost"
                class="text-destructive h-11 sm:h-8"
                disabled={busy || n.families.length > 0}
                title={n.families.length > 0 ? 'A name list is on this network' : undefined}
                onclick={() => {
                  removing = n;
                  removeOpen = true;
                }}
              >
                Remove
              </Button>
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </CardContent>
</Card>

<Dialog.Root bind:open>
  <Dialog.Content class={`${DIALOG_FIT} sm:max-w-md`}>
    <Dialog.Header>
      <Dialog.Title>{editing ? `Edit ${editing.label}` : 'Add a network'}</Dialog.Title>
      <Dialog.Description>
        Its ranges are read from the ASNs once a day. Only the ASN is asked about, never an address.
      </Dialog.Description>
    </Dialog.Header>
    <form
      class="space-y-3"
      onsubmit={(e) => {
        e.preventDefault();
        void save();
      }}
    >
      <div class="space-y-1.5">
        <Label for={`${uid}-label`}>Name</Label>
        <Input id={`${uid}-label`} bind:value={label} autocomplete="off" />
      </div>
      {#if !editing}
        <div class="space-y-1.5">
          <Label for={`${uid}-slug`}>Short id</Label>
          <Input
            id={`${uid}-slug`}
            bind:value={slug}
            autocomplete="off"
            autocapitalize="off"
            spellcheck={false}
          />
        </div>
      {/if}
      <div class="space-y-1.5">
        <Label for={`${uid}-asns`}>ASNs</Label>
        <Input
          id={`${uid}-asns`}
          bind:value={asns}
          placeholder="AS64500 AS64501"
          autocomplete="off"
          autocapitalize="off"
          spellcheck={false}
          aria-invalid={parsedAsns === null}
        />
      </div>
      <div class="space-y-1.5">
        <Label for={`${uid}-ranges`}>Ranges by hand (optional, one per line)</Label>
        <textarea
          id={`${uid}-ranges`}
          bind:value={ranges}
          rows="3"
          class="border-input bg-background w-full rounded-md border px-3 py-2 font-mono text-xs"
          placeholder="192.0.2.0/24"
          aria-invalid={parsedRanges === null}
        ></textarea>
      </div>
      <Dialog.Footer class={STICKY_FOOTER}>
        <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button type="submit" disabled={!valid || busy}>{busy ? 'Working…' : 'Save'}</Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>

<ConfirmDialog
  bind:open={removeOpen}
  title={`Remove the network ${removing?.label ?? ''}?`}
  body="Locations set to it go back to no network. A name list or a port on it must be changed first."
  confirmLabel="Remove network"
  danger
  onConfirm={async () => {
    if (!removing) return;
    const slugToRemove = removing.slug;
    await run(() => removeNetwork(slugToRemove));
  }}
/>
