<script lang="ts">
  /**
   * Add or change one address members are given for a transport (a backend Host).
   * An address that belongs to an origin is changed from Edges; the server
   * refuses it here and says so.
   *
   * Props:
   *   open (bindable), slug, transportUuid, transportTag
   *   host?: the Host being changed; absent = a new one
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Dialog from '@client/components/ui/dialog';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { createAddress, deleteAddress, updateAddress } from '@client/lib/serversApi';
  import type { AddressView } from '../../../../../shared/contracts/servers';
  import ConfirmDialog from '../../edges/components/ConfirmDialog.svelte';
  import { runWrite } from '../lib/run';

  interface Props {
    open: boolean;
    slug: string;
    transportUuid: string;
    transportTag: string;
    host?: AddressView | null;
  }
  let { open = $bindable(false), slug, transportUuid, transportTag, host = null }: Props = $props();
  const qc = useQueryClient();
  const uid = $props.id();

  let remark = $state('');
  let address = $state('');
  let port = $state('443');
  let sni = $state('');
  let fingerprint = $state('');
  let disabled = $state(false);
  let restore = $state(false);
  let busy = $state(false);
  let removeOpen = $state(false);

  // A fresh form every time it opens.
  $effect(() => {
    if (!open) return;
    remark = host?.remark ?? '';
    address = host?.address ?? '';
    port = String(host?.port ?? 443);
    sni = host?.sni ?? '';
    fingerprint = host?.fingerprint ?? '';
    disabled = host?.isDisabled ?? false;
    restore = false;
  });

  let portOk = $derived(/^\d{1,5}$/.test(port.trim()) && +port >= 1 && +port <= 65535);
  let valid = $derived(remark.trim().length > 0 && address.trim().length > 0 && portOk);
  const orNull = (s: string) => (s.trim() === '' ? null : s.trim());

  async function save() {
    if (!valid || busy) return;
    busy = true;
    try {
      const fields = {
        remark: remark.trim(),
        address: address.trim(),
        port: Number(port),
        sni: orNull(sni),
        fingerprint: orNull(fingerprint),
        isDisabled: disabled,
      };
      const op = await runWrite(qc, () =>
        host
          ? updateAddress(slug, host.addressUuid, fields)
          : createAddress(slug, { ...fields, transportUuid, restore }),
      );
      if (op) open = false;
    } finally {
      busy = false;
    }
  }

  async function remove() {
    if (!host) return;
    removeOpen = false;
    open = false;
    await runWrite(qc, () => deleteAddress(slug, host.addressUuid));
  }
</script>

<Dialog.Root bind:open>
  <Dialog.Content class="sm:max-w-md">
    <Dialog.Header>
      <Dialog.Title>{host ? `Change ${host.remark}` : 'Add an address'}</Dialog.Title>
      <Dialog.Description>
        For <span class="break-all">{transportTag}</span>. Members see it at their next update.
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
        <Label for={`${uid}-remark`}>Name shown in the app</Label>
        <Input id={`${uid}-remark`} bind:value={remark} autocomplete="off" spellcheck={false} />
      </div>
      <div class="grid grid-cols-3 gap-3">
        <div class="col-span-2 space-y-1.5">
          <Label for={`${uid}-address`}>Address</Label>
          <Input id={`${uid}-address`} bind:value={address} autocomplete="off" spellcheck={false} />
        </div>
        <div class="space-y-1.5">
          <Label for={`${uid}-port`}>Port</Label>
          <Input
            id={`${uid}-port`}
            bind:value={port}
            inputmode="numeric"
            autocomplete="off"
            aria-invalid={!portOk}
          />
        </div>
      </div>
      <div class="space-y-1.5">
        <Label for={`${uid}-sni`}>Server name (optional)</Label>
        <Input id={`${uid}-sni`} bind:value={sni} autocomplete="off" spellcheck={false} />
      </div>
      <div class="space-y-1.5">
        <Label for={`${uid}-fp`}>Browser fingerprint (optional)</Label>
        <Input
          id={`${uid}-fp`}
          bind:value={fingerprint}
          placeholder="chrome"
          autocomplete="off"
          spellcheck={false}
        />
      </div>
      <div class="flex items-center gap-2">
        <Checkbox id={`${uid}-off`} bind:checked={disabled} />
        <Label for={`${uid}-off`} class="font-normal">Do not give this to members for now</Label>
      </div>
      {#if !host}
        <div class="flex items-start gap-2">
          <Checkbox id={`${uid}-restore`} bind:checked={restore} />
          <Label for={`${uid}-restore`} class="leading-snug font-normal">
            Bring back this exact address if it was removed on purpose
          </Label>
        </div>
      {/if}
      <Dialog.Footer class="gap-2 sm:justify-between">
        {#if host}
          <Button type="button" variant="ghost" onclick={() => (removeOpen = true)}>Remove</Button>
        {:else}
          <span></span>
        {/if}
        <span class="flex gap-2">
          <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
          <Button type="submit" disabled={!valid || busy}>{busy ? 'Working…' : 'Save'}</Button>
        </span>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>

<ConfirmDialog
  bind:open={removeOpen}
  title={`Remove ${host?.remark ?? ''}?`}
  body="Members stop getting it at their next update."
  confirmLabel="Remove"
  danger
  onConfirm={remove}
/>
