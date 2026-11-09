<script lang="ts">
  /**
   * "Add an SNI list": the ONE dialog every entry point opens (docs/edges.md
   * "The page"), prefilled from where it was opened. An SNI list is one cover
   * site (the real site a REALITY port shows anyone without a member's key)
   * plus the SNIs that site serves. Its cover site never changes later.
   *
   * Two shapes, picked by `from`:
   *   - `{kind: 'site', prefill}`: the form (name, short id, cover site, port,
   *     HTTP/2 only, network), blank on the SNIs page, prefilled from a found
   *     site or a seed. `POST sni/families`. The short id and the name follow
   *     the cover site until they are edited. A seed's short id is locked
   *     (`lockSlug`): the next import of the seed finds its list by it.
   *   - `{kind: 'port', backendSlug, transport, nodeUuid}`: a node's REALITY
   *     port (docs/edges.md "A transport's names"). The cover site is the
   *     port's own. One call makes the list, takes in the SNIs the port lists
   *     now, and from then on is the only writer of them. Opening it asks the
   *     server what it would suggest (a dry run resolves the cover site): the
   *     network, only when the cover site and every address in use are on it.
   *     An unused list with the same cover site is offered instead of a new
   *     one. Nothing reaches the node here.
   *
   * Props:
   *   open      (bindable)
   *   from      where it was opened (default: a blank form)
   *   onAdded?  called with the list's slug once it exists. Default: a new list
   *             from the form opens its page; a port's list stays on the node page.
   *
   * Wording and checks live in ./lib/addList.ts (pure, unit-tested).
   */
  import { untrack } from 'svelte';
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
  import {
    createFamily,
    invalidateSni,
    manageTransport,
    networksQuery,
    previewManage,
  } from '@client/lib/sniApi';
  import { router } from '@client/stores/router.svelte';
  import type { SniManageDryRun } from '../../../../../shared/contracts/sni';
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { edgesPaths } from '../lib/routes';
  import {
    createBody,
    draftFrom,
    draftProblem,
    slugFor,
    slugProblem,
    type AddListFrom,
    type ListDraft,
  } from './lib/addList';
  import { managedWords } from './lib/transportWords';
  import { sniErrorWords } from './lib/words';

  let {
    open = $bindable(false),
    from = { kind: 'site' },
    onAdded,
  }: {
    open: boolean;
    from?: AddListFrom;
    onAdded?: (slug: string) => void;
  } = $props();
  const qc = useQueryClient();
  const uid = $props.id();
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);
  const networks = networksQuery();
  const SELECT = 'border-input bg-background h-11 w-full rounded-md border px-2 text-sm sm:h-9';

  let busy = $state(false);

  // --- from the form ---------------------------------------------------------------------------
  let draft = $state<ListDraft>(draftFrom());
  // The short id and the name follow the cover site until someone edits them.
  let slugEdited = $state(false);
  // A seed's list: its short id is how the next import of the seed finds it.
  let slugLocked = $derived(from.kind === 'site' && from.lockSlug === true);
  let labelEdited = $state(false);
  let tried = $state(false);
  let problem = $derived(draftProblem(draft));
  let slugIssue = $derived(draft.slug.trim() ? slugProblem(draft.slug) : null);
  function onCoverSite(value: string) {
    draft.coverSite = value;
    if (!slugEdited && !slugLocked) draft.slug = slugFor(value);
    if (!labelEdited) draft.label = value.trim().replace(/^www\./, '');
  }

  // --- from a port -----------------------------------------------------------------------------
  let preview = $state<SniManageDryRun | null>(null);
  let previewError = $state<string | null>(null);
  let useNetwork = $state(true);
  // '' = a new list; else the slug of an unused list with the same cover site.
  let existing = $state('');
  let portLabel = $state('');
  let portH2 = $state(false);

  // Every opening starts from `from` again; typing never resets (untracked).
  $effect(() => {
    if (!open) return;
    untrack(() => {
      tried = false;
      busy = false;
      if (from.kind === 'site') {
        draft = draftFrom(from.prefill);
        slugEdited = !!from.prefill?.slug;
        labelEdited = !!from.prefill?.label;
        return;
      }
      const port = from;
      preview = null;
      previewError = null;
      useNetwork = true;
      existing = port.transport.sameCoverSite[0]?.slug ?? '';
      portLabel = '';
      portH2 = false;
      previewManage({ backendSlug: port.backendSlug, transportUuid: port.transport.transportUuid })
        .then((p) => {
          preview = p;
          portLabel = p.label;
        })
        .catch((e) => (previewError = sniErrorWords(codeOf(e))));
    });
  });

  async function addFromForm() {
    tried = true;
    if (problem || busy) return;
    busy = true;
    try {
      const body = createBody(draft);
      await createFamily(body);
      open = false;
      if (onAdded) onAdded(body.slug);
      else router.navigate(edgesPaths.family(body.slug));
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateSni(qc);
    }
  }

  async function addFromPort() {
    if (from.kind !== 'port' || busy) return;
    const port = from;
    busy = true;
    try {
      const done = await manageTransport({
        backendSlug: port.backendSlug,
        transportUuid: port.transport.transportUuid,
        ...(existing
          ? { family: existing }
          : {
              network: useNetwork && preview?.network ? preview.network.slug : null,
              ...(portLabel.trim() ? { label: portLabel.trim() } : {}),
              requireH2: portH2,
            }),
        ...(port.nodeUuid ? { nodeUuid: port.nodeUuid } : {}),
      });
      open = false;
      toast.success(managedWords(done));
      onAdded?.(done.family);
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
      <Dialog.Title>Add an SNI list</Dialog.Title>
      <Dialog.Description>
        {#if from.kind === 'port'}
          From {from.transport.tag}{from.transport.port ? `, port ${from.transport.port}` : ''}.
        {:else}
          One cover site and the SNIs it serves. The cover site cannot be changed later.
        {/if}
      </Dialog.Description>
    </Dialog.Header>

    {#if from.kind === 'port'}
      {@const t = from.transport}
      <div class="space-y-4 text-sm">
        <p>
          FCP takes over the {t.listed === 1 ? 'SNI' : `${t.listed} SNIs`} this port lists now and checks
          them against the cover site
          <span class="font-mono break-all">{t.coverSite}</span>. It suggests more SNIs that site
          serves and, from then on, is the only one that changes this port's SNIs.
        </p>
        <p class="text-muted-foreground">
          Nothing is sent to the node yet. Members keep the SNIs they have.
        </p>

        {#if t.sameCoverSite.length > 0}
          <fieldset class="space-y-2">
            <legend class="font-medium">SNI list</legend>
            {#each t.sameCoverSite as f (f.slug)}
              <label class="flex items-start gap-2">
                <input type="radio" class="mt-1" bind:group={existing} value={f.slug} />
                <span
                  >Use {f.label}, which has the same cover site ({f.names}
                  {f.names === 1 ? 'SNI' : 'SNIs'})</span
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
                  Keep SNIs on {preview.network.label}. The cover site and every address of this
                  port are on it, so only SNIs that resolve there are used.
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
                <Label for={`${uid}-port-label`}>Name of the list</Label>
                <Input
                  id={`${uid}-port-label`}
                  bind:value={portLabel}
                  autocomplete="off"
                  maxlength={80}
                />
              </div>
              <label class="flex items-start gap-2">
                <Checkbox bind:checked={portH2} class="mt-0.5" />
                <span>Only use SNIs the cover site serves over HTTP/2</span>
              </label>
            </Collapsible.Content>
          </Collapsible.Root>
        {/if}
      </div>
      <Dialog.Footer class={STICKY_FOOTER}>
        <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button disabled={busy || (!existing && !preview && !previewError)} onclick={addFromPort}>
          {busy ? 'Working…' : existing ? 'Use this list' : 'Add the list'}
        </Button>
      </Dialog.Footer>
    {:else}
      <form
        class="space-y-3"
        novalidate
        onsubmit={(e) => {
          e.preventDefault();
          void addFromForm();
        }}
      >
        <div class="grid grid-cols-3 gap-3">
          <div class="col-span-2 space-y-1.5">
            <Label for={`${uid}-target`}>Cover site</Label>
            <Input
              id={`${uid}-target`}
              value={draft.coverSite}
              oninput={(e) => onCoverSite(e.currentTarget.value)}
              placeholder="site.example"
              autocomplete="off"
              autocapitalize="off"
              spellcheck={false}
            />
          </div>
          <div class="space-y-1.5">
            <Label for={`${uid}-port`}>Port</Label>
            <Input
              id={`${uid}-port`}
              bind:value={draft.port}
              inputmode="numeric"
              autocomplete="off"
            />
          </div>
        </div>
        <div class="space-y-1.5">
          <Label for={`${uid}-label`}>Name</Label>
          <Input
            id={`${uid}-label`}
            value={draft.label}
            oninput={(e) => {
              draft.label = e.currentTarget.value;
              labelEdited = true;
            }}
            autocomplete="off"
            maxlength={80}
          />
        </div>
        {#if slugLocked}
          <div class="space-y-1.5">
            <p class="text-sm font-medium">Short id</p>
            <p class="font-mono text-sm break-all" data-testid="locked-slug">{draft.slug}</p>
            <p class={slugIssue ? 'text-destructive text-sm' : 'text-muted-foreground text-sm'}>
              {slugIssue ??
                'Set by the seed: importing the seed again fills the list with this short id.'}
            </p>
          </div>
        {:else}
          <div class="space-y-1.5">
            <Label for={`${uid}-slug`}>Short id</Label>
            <Input
              id={`${uid}-slug`}
              value={draft.slug}
              oninput={(e) => {
                draft.slug = e.currentTarget.value;
                slugEdited = true;
              }}
              autocomplete="off"
              autocapitalize="off"
              spellcheck={false}
              aria-invalid={slugIssue !== null}
              aria-describedby={`${uid}-slug-help`}
            />
            <p
              id={`${uid}-slug-help`}
              class={slugIssue ? 'text-destructive text-sm' : 'text-muted-foreground text-sm'}
            >
              {slugIssue ?? "The list page's address. It never changes."}
            </p>
          </div>
        {/if}
        <div class="flex items-start gap-2">
          <Checkbox id={`${uid}-h2`} bind:checked={draft.requireH2} />
          <Label for={`${uid}-h2`} class="leading-snug font-normal">
            Only use SNIs the cover site serves over HTTP/2
          </Label>
        </div>
        <div class="space-y-1.5">
          <Label for={`${uid}-network`}>Network (optional)</Label>
          <select
            id={`${uid}-network`}
            bind:value={draft.network}
            class={SELECT}
            aria-describedby={`${uid}-network-help`}
          >
            <option value="">Anywhere</option>
            {#each networks.data?.networks ?? [] as n (n.slug)}
              <option value={n.slug}>{n.label}</option>
            {/each}
            {#if draft.network && !(networks.data?.networks ?? []).some((n) => n.slug === draft.network)}
              <option value={draft.network}>{draft.network}</option>
            {/if}
          </select>
          <p id={`${uid}-network-help`} class="text-muted-foreground text-sm">
            On a network, the cover site and every SNI must resolve inside it, and a port using the
            list gets addresses only from it.
          </p>
        </div>
        {#if tried && problem}
          <p class="text-destructive text-sm" role="alert">{problem}</p>
        {/if}
        <Dialog.Footer class={STICKY_FOOTER}>
          <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
          <Button type="submit" disabled={busy}>{busy ? 'Working…' : 'Add'}</Button>
        </Dialog.Footer>
      </form>
    {/if}
  </Dialog.Content>
</Dialog.Root>
