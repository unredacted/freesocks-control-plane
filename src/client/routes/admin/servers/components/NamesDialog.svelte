<script lang="ts">
  /**
   * Edit the server names and the target of one REALITY inbound: write, preview
   * (what changes, which nodes restart, which relays feel it), then apply. The
   * apply is conditioned on the profile still being what the preview read.
   *
   * A name listed on the panel is not yet a name a node accepts, so new names
   * are NOT given to members by this edit (docs/servers.md).
   *
   * Props: open (bindable), slug, profileUuid, inbound
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { applyProfilePatch, previewProfilePatch } from '@client/lib/serversApi';
  import type {
    PanelInboundView,
    ProfilePatchOp,
    ProfilePatchPreview,
  } from '../../../../../shared/contracts/servers';
  import { codeOf, runWrite } from '../lib/run';
  import { namesDelta, parseNames, serverErrorWords } from '../lib/words';

  interface Props {
    open: boolean;
    slug: string;
    profileUuid: string;
    inbound: PanelInboundView;
  }
  let { open = $bindable(false), slug, profileUuid, inbound }: Props = $props();
  const qc = useQueryClient();
  const uid = $props.id();

  let namesText = $state('');
  let target = $state('');
  let preview = $state<ProfilePatchPreview | null>(null);
  let typed = $state('');
  let busy = $state(false);

  $effect(() => {
    if (!open) return;
    namesText = (inbound.serverNames ?? []).join('\n');
    target = inbound.realityTarget ?? '';
    preview = null;
    typed = '';
  });

  let names = $derived(parseNames(namesText));
  let before = $derived(inbound.serverNames ?? []);
  let namesChanged = $derived(names.join('\n') !== before.join('\n'));
  let targetChanged = $derived(target.trim() !== (inbound.realityTarget ?? ''));
  let dirty = $derived(namesChanged || targetChanged);
  // More than one node restarting is a typed confirmation.
  let needsTyped = $derived((preview?.restartsNodes.length ?? 0) > 1);
  let canApply = $derived(!!preview?.changed && (!needsTyped || typed.trim() === inbound.tag));

  let unmanaged = $state<'hold' | 'acknowledge'>('hold');

  async function doPreview() {
    if (!dirty || busy) return;
    const ops: ProfilePatchOp[] = [];
    if (namesChanged) ops.push({ op: 'setRealityServerNames', inboundTag: inbound.tag, names });
    if (targetChanged)
      ops.push({ op: 'setRealityTarget', inboundTag: inbound.tag, target: target.trim() });
    busy = true;
    try {
      preview = await previewProfilePatch(slug, profileUuid, ops);
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busy = false;
    }
  }

  async function apply() {
    if (!preview || !canApply || busy) return;
    busy = true;
    try {
      const p = preview;
      const op = await runWrite(qc, () => applyProfilePatch(slug, profileUuid, p, unmanaged));
      if (op) open = false;
      else preview = null;
    } finally {
      busy = false;
    }
  }
</script>

<Dialog.Root bind:open>
  <Dialog.Content class="sm:max-w-lg">
    <Dialog.Header>
      <Dialog.Title>Server names of <span class="break-all">{inbound.tag}</span></Dialog.Title>
      <Dialog.Description>Every name must be one the target site really serves.</Dialog.Description>
    </Dialog.Header>

    {#if !preview}
      <div class="space-y-3">
        <div class="space-y-1.5">
          <Label for={`${uid}-names`}>Server names, one per line</Label>
          <textarea
            id={`${uid}-names`}
            bind:value={namesText}
            rows="8"
            spellcheck="false"
            autocapitalize="off"
            class="border-input focus-visible:ring-ring/50 w-full rounded-md border bg-transparent px-3 py-2 font-mono text-sm outline-none focus-visible:ring-3"
          ></textarea>
          <p class="text-muted-foreground text-sm">
            {names.length}
            {names.length === 1 ? 'name' : 'names'}{namesChanged
              ? ` · ${namesDelta(before, names)}`
              : ''}
          </p>
        </div>
        <div class="space-y-1.5">
          <Label for={`${uid}-target`}>Target site</Label>
          <Input
            id={`${uid}-target`}
            bind:value={target}
            placeholder="site.example:443"
            autocomplete="off"
            spellcheck={false}
          />
        </div>
      </div>
      <Dialog.Footer>
        <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button disabled={!dirty || busy} onclick={doPreview}>
          {busy ? 'Reading the panel…' : 'Preview'}
        </Button>
      </Dialog.Footer>
    {:else}
      <div class="space-y-3 text-sm" aria-live="polite">
        {#if !preview.changed}
          <p>The panel already has exactly this. There is nothing to apply.</p>
        {:else}
          <ul class="space-y-2">
            {#each preview.changes as c (c.inboundTag + c.field)}
              <li class="bg-muted/30 rounded-md border p-3">
                {#if c.field === 'serverNames'}
                  {@const was = Array.isArray(c.before) ? c.before : []}
                  {@const now = Array.isArray(c.after) ? c.after : []}
                  <p class="font-medium">Server names: {namesDelta(was, now)}</p>
                  {#each now.filter((n) => !was.includes(n)) as n (n)}
                    <p class="break-all text-emerald-700 dark:text-emerald-400">+ {n}</p>
                  {/each}
                  {#each was.filter((n) => !now.includes(n)) as n (n)}
                    <p class="text-destructive break-all">- {n}</p>
                  {/each}
                {:else}
                  <p class="font-medium">Target site</p>
                  <p class="text-muted-foreground break-all">{c.before ?? 'None'}</p>
                  <p class="break-all">{c.after}</p>
                {/if}
              </li>
            {/each}
          </ul>

          <p>
            {#if preview.restartsNodes.length === 0}
              No node runs this profile, so nothing restarts.
            {:else}
              The panel pushes this to {preview.restartsNodes.join(', ')}. People connected there
              are cut off for a few seconds.
            {/if}
          </p>
          {#if preview.affectedRelays.length > 0}
            <p class="text-muted-foreground">
              {preview.affectedRelays.map((r) => r.relaySlug).join(', ')}
              {preview.affectedRelays.length === 1 ? 'forwards' : 'forward'} to this inbound{targetChanged
                ? ', and a new target means its addresses are due a fresh test'
                : ''}.
            </p>
          {/if}
          {#if namesChanged}
            <p class="text-muted-foreground">
              New names reach members only after a node has proven it accepts them.
            </p>
          {/if}
          {#if preview.restartsNodes.length > 0}
            <div class="space-y-1.5">
              <Label for={`${uid}-unmanaged`}>Nodes FCP does not manage that run this</Label>
              <select
                id={`${uid}-unmanaged`}
                class="bg-background w-full rounded-md border px-3 py-2 text-sm"
                bind:value={unmanaged}
              >
                <option value="hold">Hold them closed until I release them</option>
                <option value="acknowledge">They change in place; I acknowledge that</option>
              </select>
              <p class="text-muted-foreground text-xs">
                Enrolled nodes close on their own and come back once verified and approved again.
              </p>
            </div>
          {/if}
          {#if needsTyped}
            <div class="space-y-1.5">
              <Label for={`${uid}-typed`}>
                Type <span class="font-mono font-semibold">{inbound.tag}</span> to confirm
              </Label>
              <Input id={`${uid}-typed`} bind:value={typed} autocomplete="off" spellcheck={false} />
            </div>
          {/if}
        {/if}
      </div>
      <Dialog.Footer>
        <Button variant="outline" disabled={busy} onclick={() => (preview = null)}>Back</Button>
        <Button disabled={!canApply || busy} onclick={apply}>
          {busy ? 'Working…' : 'Apply'}
        </Button>
      </Dialog.Footer>
    {/if}
  </Dialog.Content>
</Dialog.Root>
