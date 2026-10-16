<script lang="ts">
  /**
   * Add a transport to a profile from the catalogue the nodes are built for
   * (the same shapes as "Set up this backend"): write, preview, apply. A
   * REALITY transport takes its target and names from a server-name family,
   * and its key is made when the change is sent, never shown or stored.
   *
   * No node serves a new transport until one is assigned to it (measured), so
   * the add opens no port anywhere and closes no node. Setting the backend up
   * again with a mode of this tag adopts it.
   *
   * Props: open (bindable), slug, profileUuid, profileName
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Dialog from '@client/components/ui/dialog';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { familiesQuery } from '@client/lib/sniApi';
  import { applyProfilePatch, previewProfilePatch } from '@client/lib/serversApi';
  import type {
    ProfilePatchPreview,
    TransportTemplateOp,
  } from '../../../../../shared/contracts/servers';
  import { codeOf, runWrite } from '../lib/run';
  import { serverErrorWords, templateWords } from '../lib/words';

  interface Props {
    open: boolean;
    slug: string;
    profileUuid: string;
    profileName: string;
  }
  let { open = $bindable(false), slug, profileUuid, profileName }: Props = $props();
  const qc = useQueryClient();
  const uid = $props.id();
  const families = familiesQuery();

  let tag = $state('');
  let kind = $state<'reality' | 'xhttp-reality' | 'ws'>('reality');
  let port = $state('443');
  let familySlug = $state('');
  let path = $state('/ws');
  let proxyProtocol = $state(false);
  let preview = $state<ProfilePatchPreview | null>(null);
  let busy = $state(false);

  $effect(() => {
    if (!open) return;
    tag = '';
    kind = 'reality';
    port = '443';
    familySlug = '';
    path = '/ws';
    proxyProtocol = false;
    preview = null;
  });
  // A loopback WebSocket sits behind the node proxy on a high port.
  $effect(() => {
    if (kind === 'ws' && port === '443') port = '8443';
    if (kind !== 'ws' && port === '8443') port = '443';
  });

  let familyRows = $derived((families.data?.families ?? []).filter((f) => f.enabled));
  let tagOk = $derived(/^[A-Za-z0-9_-]{2,40}$/.test(tag.trim()));
  let portOk = $derived(/^\d{1,5}$/.test(port.trim()) && +port >= 1 && +port <= 65535);
  let valid = $derived(
    tagOk &&
      portOk &&
      (kind === 'ws' ? /^\/\S*$/.test(path.trim()) && +port >= 1024 : familySlug !== ''),
  );
  let added = $derived(
    preview?.ops[0]?.op === 'addInboundFromTemplate' ? preview.ops[0].template : null,
  );

  function template(): TransportTemplateOp {
    return kind === 'ws'
      ? { kind, port: Number(port), path: path.trim() }
      : { kind, port: Number(port), familySlug, acceptProxyProtocol: proxyProtocol };
  }

  async function doPreview() {
    if (!valid || busy) return;
    busy = true;
    try {
      preview = await previewProfilePatch(slug, profileUuid, [
        { op: 'addInboundFromTemplate', transportTag: tag.trim(), template: template() },
      ]);
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busy = false;
    }
  }

  async function apply() {
    if (!preview?.changed || busy) return;
    busy = true;
    try {
      const p = preview;
      const op = await runWrite(qc, () => applyProfilePatch(slug, profileUuid, p));
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
      <Dialog.Title>Add a transport to <span class="break-all">{profileName}</span></Dialog.Title>
      <Dialog.Description>
        Built the way setup builds one. No node serves it until one is assigned to it.
      </Dialog.Description>
    </Dialog.Header>

    {#if !preview}
      <div class="space-y-3">
        <div class="space-y-1.5">
          <Label for={`${uid}-kind`}>Kind</Label>
          <select
            id={`${uid}-kind`}
            class="bg-background w-full rounded-md border px-3 py-2 text-sm"
            bind:value={kind}
          >
            <option value="reality">{templateWords('reality')}</option>
            <option value="xhttp-reality">{templateWords('xhttp-reality')}</option>
            <option value="ws">{templateWords('ws')}</option>
          </select>
        </div>
        <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div class="space-y-1.5">
            <Label for={`${uid}-tag`}>Tag</Label>
            <Input
              id={`${uid}-tag`}
              bind:value={tag}
              placeholder="FREEDOM_XHTTP"
              autocomplete="off"
              spellcheck={false}
            />
          </div>
          <div class="space-y-1.5">
            <Label for={`${uid}-port`}>Port</Label>
            <Input id={`${uid}-port`} bind:value={port} inputmode="numeric" autocomplete="off" />
          </div>
        </div>
        <p class="text-muted-foreground text-xs">
          Setting the backend up with a mode adopts the transport whose tag is the mode group's name
          in capitals.
        </p>
        {#if kind === 'ws'}
          <div class="space-y-1.5">
            <Label for={`${uid}-path`}>Path</Label>
            <Input id={`${uid}-path`} bind:value={path} autocomplete="off" spellcheck={false} />
          </div>
        {:else}
          <div class="space-y-1.5">
            <Label for={`${uid}-family`}>Server-name family</Label>
            <select
              id={`${uid}-family`}
              class="bg-background w-full rounded-md border px-3 py-2 text-sm"
              bind:value={familySlug}
            >
              <option value="" disabled>Pick a family</option>
              {#each familyRows as f (f.id)}
                <option value={f.slug}>{f.label}</option>
              {/each}
            </select>
            <p class="text-muted-foreground text-xs">
              Its target and the names usable today become the transport's.
            </p>
          </div>
          <div class="flex items-center gap-2">
            <Checkbox id={`${uid}-proxy`} bind:checked={proxyProtocol} />
            <Label for={`${uid}-proxy`} class="font-normal">
              The edge in front adds a PROXY protocol header
            </Label>
          </div>
        {/if}
      </div>
      <Dialog.Footer>
        <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button disabled={!valid || busy} onclick={doPreview}>
          {busy ? 'Reading the panel…' : 'Preview'}
        </Button>
      </Dialog.Footer>
    {:else}
      <div class="space-y-3 text-sm" aria-live="polite">
        {#if added}
          <div class="bg-muted/30 space-y-1 rounded-md border p-3">
            <p class="font-medium break-all">{preview.ops[0]?.transportTag}</p>
            <p>{templateWords(added.kind)}, port {added.port}</p>
            {#if added.kind !== 'ws'}
              <p class="text-muted-foreground break-all">
                {added.serverNames?.length ?? 0}
                {added.serverNames?.length === 1 ? 'server name' : 'server names'}, from {added.target}
              </p>
            {:else}
              <p class="text-muted-foreground break-all">Path {added.path}</p>
            {/if}
          </div>
        {/if}
        {#if added && added.kind !== 'ws'}
          <p class="text-muted-foreground">
            Its REALITY key is made when the change is sent. It is never shown or stored here.
          </p>
        {/if}
        <p>
          {#if preview.restartsNodes.length === 0}
            No node runs this profile, so nothing restarts.
          {:else}
            The panel pushes the profile to {preview.restartsNodes.join(', ')}. People connected
            there are cut off for a few seconds; none of them is moved to the new transport.
          {/if}
        </p>
      </div>
      <Dialog.Footer>
        <Button variant="outline" disabled={busy} onclick={() => (preview = null)}>Back</Button>
        <Button disabled={!preview.changed || busy} onclick={apply}>
          {busy ? 'Working…' : 'Add it'}
        </Button>
      </Dialog.Footer>
    {/if}
  </Dialog.Content>
</Dialog.Root>
