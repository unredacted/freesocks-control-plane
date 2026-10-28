<script lang="ts">
  /**
   * "Manage these names with FCP" (docs/edges.md "A transport's names"): one
   * call that makes a name list with the port's own cover site, takes in the
   * names it lists now, and from then on is the only writer of them. Opening it
   * asks the server what it would suggest (a dry run resolves the cover site):
   * the network, only when the cover site and every address in use are on it.
   * An unused list with the same cover site is offered instead of a new one.
   * Nothing reaches the node here.
   *
   * Props: open (bindable), backendSlug, transport, nodeUuid (the page's node:
   * its place becomes an unplaced network's, for timing found names).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Collapsible from '@client/components/ui/collapsible';
  import * as Dialog from '@client/components/ui/dialog';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { ApiCallError } from '@client/lib/api';
  import { invalidateSni, manageTransport, previewManage } from '@client/lib/sniApi';
  import type { SniManageDryRun, SniTransport } from '../../../../../shared/contracts/sni';
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { managedWords } from './lib/transportWords';
  import { sniErrorWords } from './lib/words';

  let {
    open = $bindable(false),
    backendSlug,
    transport,
    nodeUuid,
  }: {
    open: boolean;
    backendSlug: string;
    transport: SniTransport;
    nodeUuid: string | null;
  } = $props();
  const qc = useQueryClient();
  const uid = $props.id();
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);

  let preview = $state<SniManageDryRun | null>(null);
  let previewError = $state<string | null>(null);
  let useNetwork = $state(true);
  // '' = a new list; else the slug of an unused list with the same cover site.
  let existing = $state('');
  let label = $state('');
  let requireH2 = $state(false);
  let busy = $state(false);

  $effect(() => {
    if (!open) return;
    preview = null;
    previewError = null;
    useNetwork = true;
    existing = transport.sameCoverSite[0]?.slug ?? '';
    label = '';
    requireH2 = false;
    previewManage({ backendSlug, transportUuid: transport.transportUuid })
      .then((p) => {
        preview = p;
        label = p.label;
      })
      .catch((e) => (previewError = sniErrorWords(codeOf(e))));
  });

  async function manage() {
    busy = true;
    try {
      const done = await manageTransport({
        backendSlug,
        transportUuid: transport.transportUuid,
        ...(existing
          ? { family: existing }
          : {
              network: useNetwork && preview?.network ? preview.network.slug : null,
              ...(label.trim() ? { label: label.trim() } : {}),
              requireH2,
            }),
        ...(nodeUuid ? { nodeUuid } : {}),
      });
      open = false;
      toast.success(managedWords(done));
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateSni(qc);
    }
  }
</script>

<Dialog.Root bind:open>
  <Dialog.Content class={`${DIALOG_FIT} sm:max-w-lg`}>
    <Dialog.Header>
      <Dialog.Title>Manage these names with FCP</Dialog.Title>
      <Dialog.Description>
        {transport.tag}{transport.port ? `, port ${transport.port}` : ''}
      </Dialog.Description>
    </Dialog.Header>
    <div class="space-y-4 text-sm">
      <p>
        FCP takes over the {transport.listed === 1 ? 'name' : `${transport.listed} names`} this port lists
        now. It checks each one against the cover site
        <span class="font-mono break-all">{transport.coverSite}</span>, the real site this port
        shows anyone without a member's key, suggests more names that site serves, and from then on
        is the only one that changes this port's names.
      </p>
      <p class="text-muted-foreground">
        Nothing is sent to the node yet. Members keep the names they have.
      </p>

      {#if transport.sameCoverSite.length > 0}
        <fieldset class="space-y-2">
          <legend class="font-medium">Name list</legend>
          {#each transport.sameCoverSite as f (f.slug)}
            <label class="flex items-start gap-2">
              <input type="radio" class="mt-1" bind:group={existing} value={f.slug} />
              <span
                >Use {f.label}, which has the same cover site ({f.names}
                {f.names === 1 ? 'name' : 'names'})</span
              >
            </label>
          {/each}
          <label class="flex items-start gap-2">
            <input type="radio" class="mt-1" bind:group={existing} value="" />
            <span>Make a new list for this port</span>
          </label>
        </fieldset>
      {/if}

      {#if !existing}
        <div class="space-y-1">
          <p class="font-medium">Network</p>
          {#if previewError}
            <p class="text-destructive">{previewError}</p>
          {:else if !preview}
            <Skeleton class="h-5 w-64" />
          {:else if preview.network}
            <label class="flex items-start gap-2">
              <Checkbox id={`${uid}-net`} bind:checked={useNetwork} class="mt-0.5" />
              <span>
                Keep names on {preview.network.label}. The cover site and every address of this port
                are on it, so only names that live there are used.
              </span>
            </label>
          {:else}
            <p class="text-muted-foreground">
              {preview.resolved
                ? 'Anywhere: no network holds both the cover site and every address of this port.'
                : 'Anywhere: the cover site could not be looked up just now.'}
            </p>
          {/if}
        </div>

        <Collapsible.Root>
          <Collapsible.Trigger
            class="text-muted-foreground hover:text-foreground min-h-11 sm:min-h-0"
          >
            More options
          </Collapsible.Trigger>
          <Collapsible.Content class="mt-2 space-y-3">
            <div class="space-y-1.5">
              <Label for={`${uid}-label`}>Name of the list</Label>
              <Input id={`${uid}-label`} bind:value={label} autocomplete="off" maxlength={80} />
            </div>
            <label class="flex items-start gap-2">
              <Checkbox bind:checked={requireH2} class="mt-0.5" />
              <span>Only use names the cover site serves over HTTP/2</span>
            </label>
          </Collapsible.Content>
        </Collapsible.Root>
      {/if}
    </div>
    <Dialog.Footer class={STICKY_FOOTER}>
      <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
      <Button disabled={busy || (!existing && !preview && !previewError)} onclick={manage}>
        {busy ? 'Working…' : 'Manage names'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
