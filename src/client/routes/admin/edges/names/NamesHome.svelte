<script lang="ts">
  /**
   * Admin -> Servers -> SNIs (`/admin/servers/snis`): the switch (its line
   * says what is true now), testing new names with FCP's client check (shown
   * while server names are on), then the name lists. A name list is one cover site
   * (the real site a REALITY port shows anyone without a member's key) plus the
   * names that site really serves; on a port, its names are what members are
   * spread across. Each list's line has the same counts as its page and the
   * node page (lib/listWords.ts). A list usually starts from a node's page.
   *
   * Wording lives in ./lib/listWords.ts and ./lib/words.ts (pure, unit-tested).
   */
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Card, CardContent } from '@client/components/ui/card';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Dialog from '@client/components/ui/dialog';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { Switch } from '@client/components/ui/switch';
  import Link from '@client/components/Link.svelte';
  import { ApiCallError } from '@client/lib/api';
  import {
    createFamily,
    familiesQuery,
    invalidateSni,
    networksQuery,
    patchSniConfig,
    sniConfigQuery,
  } from '@client/lib/sniApi';
  import { router } from '@client/stores/router.svelte';
  import SectionHeader from '../components/SectionHeader.svelte';
  import { edgesPaths } from '../lib/routes';
  import { autoTestSwitchLine, listDot, listLine, namesSwitchLine } from './lib/listWords';
  import { sniErrorWords, type Dot } from './lib/words';

  const qc = useQueryClient();
  const uid = $props.id();
  const families = familiesQuery();
  const config = sniConfigQuery();
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);

  const DOT: Record<Dot, string> = {
    green: 'bg-emerald-500',
    amber: 'bg-amber-500',
    red: 'bg-destructive',
    grey: 'bg-muted-foreground/50',
  };

  let on = $derived(config.data?.config.enabled ?? false);
  let autoOn = $derived(config.data?.config.autoConfirm ?? false);
  let saving = $state(false);
  async function setOn(v: boolean) {
    saving = true;
    try {
      await patchSniConfig({ enabled: v });
      toast.success(v ? 'SNI lists are on.' : 'SNI lists are off.');
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
    } finally {
      saving = false;
      invalidateSni(qc);
    }
  }
  async function setAutoOn(v: boolean) {
    saving = true;
    try {
      await patchSniConfig({ autoConfirm: v });
      toast.success(
        v ? 'FCP tests new SNIs on each node by itself.' : 'Only a person tests new SNIs now.',
      );
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
    } finally {
      saving = false;
      invalidateSni(qc);
    }
  }

  let open = $state(false);
  let label = $state('');
  let slug = $state('');
  let target = $state('');
  let port = $state('443');
  let requireH2 = $state(false);
  let network = $state('');
  const networks = networksQuery();
  let busy = $state(false);
  let slugOk = $derived(/^[a-z0-9][a-z0-9-]{0,39}$/.test(slug.trim()));
  let valid = $derived(
    label.trim().length > 0 && slugOk && target.trim().includes('.') && /^\d{1,5}$/.test(port),
  );

  async function create() {
    if (!valid || busy) return;
    busy = true;
    try {
      await createFamily({
        slug: slug.trim(),
        label: label.trim(),
        targetAddress: target.trim(),
        targetPort: Number(port),
        requireH2,
        ...(network ? { network } : {}),
      });
      open = false;
      invalidateSni(qc);
      router.navigate(edgesPaths.family(slug.trim()));
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
    } finally {
      busy = false;
    }
  }
</script>

<SectionHeader
  title="SNIs"
  description="The SNIs a REALITY port answers to, grouped in SNI lists. Each list has one cover site, the real site shown to anyone without a member's key, and the SNIs it serves."
>
  {#snippet actions()}
    <Button size="sm" variant="outline" onclick={() => router.navigate(edgesPaths.findNames())}>
      Find more
    </Button>
    <Button size="sm" variant="outline" onclick={() => (open = true)}>Add an SNI list</Button>
  {/snippet}
</SectionHeader>

<div class="mb-6 flex items-start gap-3 text-sm">
  <Switch
    id={`${uid}-on`}
    class="mt-0.5"
    checked={on}
    disabled={saving || config.isPending}
    aria-describedby={`${uid}-on-help`}
    onCheckedChange={(v) => void setOn(v)}
  />
  <div>
    <Label for={`${uid}-on`} class="font-medium">SNI lists</Label>
    <p id={`${uid}-on-help`} class="text-muted-foreground">{namesSwitchLine(on)}</p>
  </div>
</div>
{#if on}
  <div class="mb-6 flex items-start gap-3 text-sm">
    <Switch
      id={`${uid}-auto`}
      class="mt-0.5"
      checked={autoOn}
      disabled={saving || config.isPending}
      aria-describedby={`${uid}-auto-help`}
      onCheckedChange={(v) => void setAutoOn(v)}
    />
    <div>
      <Label for={`${uid}-auto`} class="font-medium">Test new SNIs with FCP's client check</Label>
      <p id={`${uid}-auto-help`} class="text-muted-foreground">
        {autoTestSwitchLine(autoOn, config.data?.clientCheck)}
      </p>
    </div>
  </div>
{/if}

{#if families.isPending}
  <p class="text-muted-foreground text-sm">Loading…</p>
{:else if families.isError}
  <p class="text-destructive text-sm">{sniErrorWords(codeOf(families.error))}</p>
{:else if (families.data?.families.length ?? 0) === 0}
  <Card>
    <CardContent class="text-muted-foreground space-y-1 py-8 text-center text-sm">
      <p>No SNI list yet.</p>
      <p>
        Open a node under Servers and choose "Manage these SNIs with FCP" on its REALITY transport.
        Its SNIs become a list here.
      </p>
    </CardContent>
  </Card>
{:else}
  <ul class="space-y-3" aria-label="SNI lists">
    {#each families.data?.families ?? [] as f (f.id)}
      <li>
        <Link
          href={edgesPaths.family(f.slug)}
          class="hover:bg-accent/40 focus-visible:ring-ring/50 flex min-h-14 items-center gap-3 rounded-lg border px-4 py-3 outline-none focus-visible:ring-3"
        >
          <span
            class={`inline-block size-2.5 shrink-0 rounded-full ${DOT[listDot(f)]}`}
            aria-hidden="true"
          ></span>
          <span class="min-w-0 flex-1">
            <span class="block truncate font-medium">{f.label}</span>
            <span class="text-muted-foreground block text-sm">{listLine(f)}</span>
          </span>
          <span class="text-muted-foreground hidden text-sm break-all sm:block">
            {f.target.address}:{f.target.port}{f.network ? ` · ${f.network.label}` : ''}
          </span>
        </Link>
      </li>
    {/each}
  </ul>
{/if}

<Dialog.Root bind:open>
  <Dialog.Content class={`${DIALOG_FIT} sm:max-w-md`}>
    <Dialog.Header>
      <Dialog.Title>Add an SNI list</Dialog.Title>
      <Dialog.Description>
        Usually a list starts from a node's page. Its cover site cannot be changed later.
      </Dialog.Description>
    </Dialog.Header>
    <form
      class="space-y-3"
      onsubmit={(e) => {
        e.preventDefault();
        void create();
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
          bind:value={slug}
          autocomplete="off"
          autocapitalize="off"
          spellcheck={false}
          aria-describedby={`${uid}-slug-help`}
        />
        <p id={`${uid}-slug-help`} class="text-muted-foreground text-sm">
          Lowercase letters, digits and dashes.
        </p>
      </div>
      <div class="grid grid-cols-3 gap-3">
        <div class="col-span-2 space-y-1.5">
          <Label for={`${uid}-target`}>Cover site</Label>
          <Input
            id={`${uid}-target`}
            bind:value={target}
            placeholder="site.example"
            autocomplete="off"
            autocapitalize="off"
            spellcheck={false}
          />
        </div>
        <div class="space-y-1.5">
          <Label for={`${uid}-port`}>Port</Label>
          <Input id={`${uid}-port`} bind:value={port} inputmode="numeric" autocomplete="off" />
        </div>
      </div>
      <div class="flex items-start gap-2">
        <Checkbox id={`${uid}-h2`} bind:checked={requireH2} />
        <Label for={`${uid}-h2`} class="leading-snug font-normal">
          Only use SNIs the cover site serves over HTTP/2
        </Label>
      </div>
      <div class="space-y-1.5">
        <Label for={`${uid}-network`}>Network (optional)</Label>
        <select
          id={`${uid}-network`}
          bind:value={network}
          class="border-input bg-background h-11 w-full rounded-md border px-2 text-sm sm:h-9"
          aria-describedby={`${uid}-network-help`}
        >
          <option value="">Anywhere</option>
          {#each networks.data?.networks ?? [] as n (n.slug)}
            <option value={n.slug}>{n.label}</option>
          {/each}
        </select>
        <p id={`${uid}-network-help`} class="text-muted-foreground text-sm">
          On a network, the cover site and every SNI must resolve inside it, and a port using the
          list gets addresses only from it.
        </p>
      </div>
      <Dialog.Footer class={STICKY_FOOTER}>
        <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button type="submit" disabled={!valid || busy}>{busy ? 'Working…' : 'Add'}</Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
