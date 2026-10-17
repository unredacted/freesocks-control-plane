<script lang="ts">
  /**
   * Move one transport to another port: write, preview (which nodes must let the
   * new port in, and who confirms each), then stage. Nothing is sent until every
   * node has confirmed its firewall: the node role reports it on its next run,
   * an admin confirms a node no role runs (docs/servers.md "Firewall
   * acknowledgement"). The nodes on the transport then close for maintenance
   * and come back once verified and approved on the new port.
   *
   * Props: open (bindable), slug, profileUuid, transport
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { invalidateServers, previewProfilePatch, stagePortChange } from '@client/lib/serversApi';
  import type { ProfilePatchPreview, TransportView } from '../../../../../shared/contracts/servers';
  import { codeOf } from '../lib/run';
  import { portChangeTitle, serverErrorWords } from '../lib/words';

  interface Props {
    open: boolean;
    slug: string;
    profileUuid: string;
    inbound: TransportView;
  }
  let { open = $bindable(false), slug, profileUuid, inbound }: Props = $props();
  const qc = useQueryClient();
  const uid = $props.id();

  let port = $state('');
  let preview = $state<ProfilePatchPreview | null>(null);
  let typed = $state('');
  let unmanaged = $state<'hold' | 'acknowledge'>('hold');
  let busy = $state(false);

  $effect(() => {
    if (!open) return;
    port = '';
    preview = null;
    typed = '';
    unmanaged = 'hold';
  });

  let portOk = $derived(/^\d{1,5}$/.test(port.trim()) && +port >= 1 && +port <= 65535);
  let fw = $derived(preview?.firewall ?? null);
  let byOperator = $derived(fw?.nodes.filter((n) => n.confirmedBy === 'operator') ?? []);
  let byRole = $derived(fw?.nodes.filter((n) => n.confirmedBy === 'role') ?? []);
  // Nodes FCP does not manage need a treatment, as for every shared change.
  let unenrolled = $derived(fw?.nodes.filter((n) => !n.enrolled) ?? []);
  // More than one node restarting is a typed confirmation, as for every profile edit.
  let needsTyped = $derived((fw?.nodes.length ?? 0) > 1);
  let canStage = $derived(!!preview?.changed && (!needsTyped || typed.trim() === inbound.tag));

  async function doPreview() {
    if (!portOk || busy) return;
    busy = true;
    try {
      preview = await previewProfilePatch(slug, profileUuid, [
        { op: 'setInboundPort', transportTag: inbound.tag, port: Number(port) },
      ]);
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busy = false;
    }
  }

  async function stage() {
    if (!preview || !canStage || busy) return;
    busy = true;
    try {
      const change = await stagePortChange(
        slug,
        profileUuid,
        preview,
        unenrolled.length > 0 ? unmanaged : undefined,
      );
      toast.success(
        change.nodes.length === 0
          ? `${portChangeTitle(change)}: no node listens there yet, so it is sent now.`
          : `${portChangeTitle(change)}: staged. Nothing changes until every node lets the port in.`,
      );
      open = false;
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
      preview = null;
    } finally {
      busy = false;
      invalidateServers(qc);
    }
  }
</script>

<Dialog.Root bind:open>
  <Dialog.Content class="sm:max-w-lg">
    <Dialog.Header>
      <Dialog.Title>Change the port of <span class="break-all">{inbound.tag}</span></Dialog.Title>
      <Dialog.Description>
        It listens on port {inbound.port ?? 'several ports'} today. Every node on it moves together.
      </Dialog.Description>
    </Dialog.Header>

    {#if !preview}
      <div class="space-y-1.5">
        <Label for={`${uid}-port`}>New port</Label>
        <Input
          id={`${uid}-port`}
          bind:value={port}
          inputmode="numeric"
          placeholder="8443"
          autocomplete="off"
        />
      </div>
      <Dialog.Footer>
        <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button disabled={!portOk || busy} onclick={doPreview}>
          {busy ? 'Reading the panel…' : 'Preview'}
        </Button>
      </Dialog.Footer>
    {:else}
      <div class="space-y-3 text-sm" aria-live="polite">
        {#if !preview.changed}
          <p>It already listens on that port. There is nothing to change.</p>
        {:else}
          <p class="font-medium">
            {portChangeTitle({
              transportTag: inbound.tag,
              fromPort: inbound.port,
              toPort: fw?.port ?? Number(port),
            })}
          </p>
          {#if !fw || fw.nodes.length === 0}
            <p>No node serves this transport, so nothing has to wait. It is sent at once.</p>
          {:else}
            <p>
              Nothing is sent until every node below lets port {fw.port} in. Members keep the old port
              meanwhile. Then the nodes close for maintenance and come back once they are verified and
              approved on the new port.
            </p>
            <ul class="bg-muted/30 space-y-1 rounded-md border p-3">
              {#each byRole as n (n.name)}
                <li class="flex flex-wrap gap-x-2">
                  <span class="font-medium break-all">{n.name}</span>
                  <span class="text-muted-foreground">The node role opens it and reports it.</span>
                </li>
              {/each}
              {#each byOperator as n (n.name)}
                <li class="flex flex-wrap gap-x-2">
                  <span class="font-medium break-all">{n.name}</span>
                  <span class="text-muted-foreground">
                    No role runs here. You confirm its firewall once the port is open.
                  </span>
                </li>
              {/each}
            </ul>
          {/if}
          {#if preview.otherAddresses.length > 0}
            <div class="space-y-1">
              <p>
                {preview.otherAddresses.length === 1
                  ? 'This address keeps'
                  : 'These addresses keep'}
                the port it names. Change it yourself if nothing in front of the node maps the port:
              </p>
              <ul class="text-muted-foreground">
                {#each preview.otherAddresses as h (h.remark + h.address)}
                  <li class="break-all">{h.remark}: {h.address}:{h.port}</li>
                {/each}
              </ul>
            </div>
          {/if}
          {#if unenrolled.length > 0}
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
        <Button disabled={!canStage || busy} onclick={stage}>
          {busy ? 'Working…' : fw && fw.nodes.length > 0 ? 'Wait for the firewalls' : 'Apply'}
        </Button>
      </Dialog.Footer>
    {/if}
  </Dialog.Content>
</Dialog.Root>
