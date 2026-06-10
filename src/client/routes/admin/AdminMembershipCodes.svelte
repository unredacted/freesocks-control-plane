<script lang="ts">
  import { z } from 'zod';
  import { Card, CardHeader, CardContent } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Button } from '@client/components/ui/button';
  import AdminLayout from './AdminLayout.svelte';
  import { apiClient } from '../../lib/api';
  import { adminMembershipCodesQuery, adminTiersQuery } from '../../lib/queries';
  import {
    MintCodesRequest,
    MintCodesResponse,
    type MembershipCodeAdmin,
  } from '../../../shared/contracts/membershipCodes';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  const qc = useQueryClient();
  const tiers = adminTiersQuery();
  let statusFilter = $state('');
  const codes = adminMembershipCodesQuery(() => statusFilter);

  // Mint form state.
  let tierId = $state('');
  let durationDays = $state(30);
  let count = $state(1);
  let note = $state('');

  // Reveal-once: the freshly minted plaintext codes + an acknowledgement gate.
  let revealed = $state<string[] | null>(null);
  let acknowledged = $state(false);

  const mint = createMutation(() => ({
    mutationFn: () =>
      apiClient.post(
        '/api/v1/admin/membership-codes',
        MintCodesRequest.parse({ tierId, durationDays, count, note: note || undefined }),
        MintCodesResponse,
      ),
    onSuccess: (result) => {
      revealed = result.codes;
      acknowledged = false;
      note = '';
      void qc.invalidateQueries({ queryKey: ['admin', 'membership-codes'] });
      toast.success(`Minted ${result.codes.length} code${result.codes.length === 1 ? '' : 's'}`);
    },
    onError: (err) => toast.error('Mint failed', { description: err instanceof Error ? err.message : String(err) }),
  }));

  const revoke = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.delete(`/api/v1/admin/membership-codes/${id}`, z.object({ ok: z.boolean() })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['admin', 'membership-codes'] });
      toast.success('Code revoked');
    },
    onError: (err) => toast.error('Revoke failed', { description: err instanceof Error ? err.message : String(err) }),
  }));

  async function copyAll() {
    if (!revealed) return;
    try {
      await navigator.clipboard.writeText(revealed.join('\n'));
      toast.success('Codes copied to clipboard');
    } catch {
      toast.error('Copy failed — select the codes and copy manually');
    }
  }
  function downloadAll() {
    if (!revealed) return;
    const blob = new Blob([revealed.join('\n') + '\n'], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'freesocks-membership-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  }

  const STATUS_COLORS: Record<MembershipCodeAdmin['status'], string> = {
    active: 'bg-emerald-500/15 text-emerald-500',
    redeemed: 'bg-muted text-muted-foreground',
    revoked: 'bg-destructive/15 text-destructive',
  };
</script>

<AdminLayout>
  <h1 class="text-2xl font-bold mb-2">Membership codes</h1>
  <p class="text-sm text-muted-foreground mb-6">
    Mint redeemable codes that grant or extend a paid tier. Hand a code to a donor; they redeem it
    on their account page. Codes are shown once — store them now.
  </p>

  <!-- Mint form -->
  <Card class="mb-6">
    <CardHeader><h2 class="font-semibold">Mint codes</h2></CardHeader>
    <CardContent class="grid gap-3 sm:grid-cols-2">
      <label class="text-sm">
        <span class="mb-1 block text-muted-foreground">Tier</span>
        <select
          bind:value={tierId}
          class="min-h-9 w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
        >
          <option value="" disabled>Select a tier…</option>
          {#each tiers.data ?? [] as tier (tier.id)}
            <option value={tier.id}>{tier.name} ({tier.slug})</option>
          {/each}
        </select>
      </label>
      <label class="text-sm">
        <span class="mb-1 block text-muted-foreground">Duration (days)</span>
        <input
          type="number"
          min="1"
          max="3650"
          bind:value={durationDays}
          class="min-h-9 w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
        />
      </label>
      <label class="text-sm">
        <span class="mb-1 block text-muted-foreground">Count</span>
        <input
          type="number"
          min="1"
          max="100"
          bind:value={count}
          class="min-h-9 w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
        />
      </label>
      <label class="text-sm">
        <span class="mb-1 block text-muted-foreground">Note (optional)</span>
        <input
          type="text"
          bind:value={note}
          placeholder="e.g. launch batch"
          class="min-h-9 w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
        />
      </label>
      <div class="sm:col-span-2">
        <Button onclick={() => mint.mutate()} disabled={!tierId || mint.isPending}>
          {mint.isPending ? 'Minting…' : `Mint ${count} code${count === 1 ? '' : 's'}`}
        </Button>
      </div>
    </CardContent>
  </Card>

  <!-- Status filter -->
  <div class="mb-3 flex items-center gap-2 text-sm">
    <span class="text-muted-foreground">Filter:</span>
    {#each [['', 'All'], ['active', 'Active'], ['redeemed', 'Redeemed'], ['revoked', 'Revoked']] as const as [val, label] (val)}
      <button
        type="button"
        onclick={() => (statusFilter = val)}
        class="rounded-md px-2 py-1 {statusFilter === val
          ? 'bg-primary text-primary-foreground'
          : 'bg-muted text-muted-foreground hover:text-foreground'}"
      >
        {label}
      </button>
    {/each}
  </div>

  {#if codes.isPending}
    <div class="space-y-2">
      {#each Array(3) as _, i (i)}<Skeleton class="h-12 w-full" />{/each}
    </div>
  {:else if codes.isError}
    <div class="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
      {codes.error instanceof Error ? codes.error.message : String(codes.error)}
    </div>
  {:else if (codes.data?.length ?? 0) === 0}
    <div class="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
      No codes yet.
    </div>
  {:else}
    <ul class="divide-y divide-border rounded-lg border border-border bg-card">
      {#each codes.data ?? [] as code (code.id)}
        <li class="flex flex-wrap items-center justify-between gap-2 px-4 py-3 text-sm">
          <div class="flex items-center gap-3">
            <code class="font-mono">{code.codePrefix}…</code>
            <span class="rounded px-2 py-0.5 text-xs {STATUS_COLORS[code.status]}">{code.status}</span>
            <span class="text-muted-foreground">{code.tierSlug} · {code.durationDays}d</span>
            {#if code.note}<span class="text-xs text-muted-foreground">“{code.note}”</span>{/if}
          </div>
          <div class="flex items-center gap-3 text-xs text-muted-foreground">
            {#if code.redeemedAt}
              redeemed {new Date(code.redeemedAt).toLocaleDateString()}
            {/if}
            {#if code.status === 'active'}
              <Button size="sm" variant="ghost" onclick={() => revoke.mutate(code.id)}>Revoke</Button>
            {/if}
          </div>
        </li>
      {/each}
    </ul>
  {/if}

  <!-- Reveal-once dialog for freshly minted codes. -->
  <AlertDialog.Root
    open={!!revealed}
    onOpenChange={(next) => {
      if (!next && !acknowledged) {
        toast.warning('Save the codes first', { description: 'They are shown only once.' });
        return;
      }
      if (!next) revealed = null;
    }}
  >
    <AlertDialog.Content>
      <AlertDialog.Header>
        <AlertDialog.Title>Save these codes now</AlertDialog.Title>
        <AlertDialog.Description>
          This is the only time the codes are shown. Copy or download them, then hand them out.
        </AlertDialog.Description>
      </AlertDialog.Header>
      <pre class="max-h-48 overflow-auto rounded bg-muted p-3 font-mono text-xs">{(revealed ?? []).join('\n')}</pre>
      <div class="flex gap-2">
        <Button variant="outline" size="sm" onclick={copyAll}>Copy all</Button>
        <Button variant="outline" size="sm" onclick={downloadAll}>Download</Button>
      </div>
      <label class="flex cursor-pointer select-none items-center gap-2 text-sm">
        <Checkbox bind:checked={acknowledged} id="ack-codes" />
        I have saved these codes.
      </label>
      <AlertDialog.Footer>
        <Button disabled={!acknowledged} onclick={() => (revealed = null)}>Done</Button>
      </AlertDialog.Footer>
    </AlertDialog.Content>
  </AlertDialog.Root>
</AdminLayout>
