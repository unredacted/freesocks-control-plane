<script lang="ts">
  /**
   * Admin -> Edges -> Server names (`/admin/edges/names`): the families. A family
   * is one target site plus the names that site really serves; bound to a
   * REALITY transport, its names are what members are spread across.
   *
   * All wording lives in ./lib/words.ts (pure, unit-tested).
   */
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
    patchSniConfig,
    sniConfigQuery,
  } from '@client/lib/sniApi';
  import { router } from '@client/stores/router.svelte';
  import SectionHeader from '../components/SectionHeader.svelte';
  import { edgesPaths } from '../lib/routes';
  import { familyDot, familyLine, sniErrorWords, type Dot } from './lib/words';

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
  let saving = $state(false);
  async function setOn(v: boolean) {
    saving = true;
    try {
      await patchSniConfig({ enabled: v });
      toast.success(v ? 'Server name families are on.' : 'Server name families are off.');
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
  title="Server names"
  description="Names a REALITY node answers to, in families: one target site and the names it really serves."
>
  {#snippet actions()}
    <Button size="sm" onclick={() => (open = true)}>Add a family</Button>
  {/snippet}
</SectionHeader>

{#if families.isPending}
  <p class="text-muted-foreground text-sm">Loading…</p>
{:else if families.isError}
  <p class="text-destructive text-sm">{sniErrorWords(codeOf(families.error))}</p>
{:else if (families.data?.families.length ?? 0) === 0}
  <Card>
    <CardContent class="text-muted-foreground py-8 text-center text-sm">No family yet.</CardContent>
  </Card>
{:else}
  <ul class="space-y-3" aria-label="Families">
    {#each families.data?.families ?? [] as f (f.id)}
      <li>
        <Link
          href={edgesPaths.family(f.slug)}
          class="hover:bg-accent/40 focus-visible:ring-ring/50 flex min-h-14 items-center gap-3 rounded-lg border px-4 py-3 outline-none focus-visible:ring-3"
        >
          <span
            class={`inline-block size-2.5 shrink-0 rounded-full ${DOT[familyDot(f)]}`}
            aria-hidden="true"
          ></span>
          <span class="min-w-0 flex-1">
            <span class="block truncate font-medium">{f.label}</span>
            <span class="text-muted-foreground block text-sm">{familyLine(f)}</span>
          </span>
          <span class="text-muted-foreground hidden text-sm break-all sm:block">
            {f.target.address}:{f.target.port}
          </span>
        </Link>
      </li>
    {/each}
  </ul>
{/if}

<footer class="text-muted-foreground mt-8 flex items-center gap-3 border-t pt-4 text-sm">
  <Switch
    id={`${uid}-on`}
    checked={on}
    disabled={saving || config.isPending}
    onCheckedChange={(v) => void setOn(v)}
  />
  <Label for={`${uid}-on`} class="font-normal">Server name families are {on ? 'on' : 'off'}</Label>
</footer>

<Dialog.Root bind:open>
  <Dialog.Content class="sm:max-w-md">
    <Dialog.Header>
      <Dialog.Title>Add a family</Dialog.Title>
      <Dialog.Description>The target site cannot be changed later.</Dialog.Description>
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
          <Label for={`${uid}-target`}>Target site</Label>
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
          Only accept names the target serves over HTTP/2
        </Label>
      </div>
      <Dialog.Footer>
        <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button type="submit" disabled={!valid || busy}>{busy ? 'Working…' : 'Add'}</Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
