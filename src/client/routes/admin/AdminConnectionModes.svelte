<script lang="ts">
  import AdminLayout from './AdminLayout.svelte';
  import ConnectionModeEditor from './ConnectionModeEditor.svelte';
  import ConnectionModeFamilyEditor from './ConnectionModeFamilyEditor.svelte';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Button } from '@client/components/ui/button';
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import AdminListState from './AdminListState.svelte';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { adminConnectionModesQuery, queryKeys } from '../../lib/queries';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import type {
    AdminConnectionMode,
    AdminConnectionModeFamily,
  } from '../../../shared/contracts/connectionModes';
  import { resolveModeIcon } from '../../lib/connectionModeIcons';
  import { ADMIN_BACKEND_LABELS } from '../../lib/backendLabels';
  import Link from '../../components/Link.svelte';
  import { toast } from 'svelte-sonner';
  import Plus from '@lucide/svelte/icons/plus';
  import { z } from 'zod';

  /**
   * The DB-driven connection-mode catalog manager: create/edit/delete families
   * and modes (the member picker is entirely data-driven off this). Placement
   * POOLS (which nodes a mode issues onto) are backend-specific + write-only
   * and stay on Admin → Remnawave — this page links there.
   */
  const catalog = adminConnectionModesQuery();
  const qc = useQueryClient();

  let creatingFamily = $state(false);
  let creatingMode = $state(false);
  let editingFamily = $state<AdminConnectionModeFamily | null>(null);
  let editingMode = $state<AdminConnectionMode | null>(null);
  let pendingDelete = $state<
    | { kind: 'family'; entity: AdminConnectionModeFamily }
    | { kind: 'mode'; entity: AdminConnectionMode }
    | null
  >(null);

  let families = $derived(catalog.data?.families ?? []);
  let modes = $derived(catalog.data?.modes ?? []);
  // Family sections in order, then a bucket for orphan modes (family row gone)
  // so nothing is ever unmanageable (the old editors hid orphans entirely).
  let sections = $derived([
    ...families.map((f) => ({
      family: f as AdminConnectionModeFamily | null,
      children: modes.filter((m) => m.family === f.id),
    })),
    ...(() => {
      const known = new Set(families.map((f) => f.id));
      const orphans = modes.filter((m) => !m.family || !known.has(m.family));
      return orphans.length ? [{ family: null, children: orphans }] : [];
    })(),
  ]);

  function invalidate() {
    void qc.invalidateQueries({ queryKey: queryKeys.adminConnectionModes });
    // publicConfig ships the member projection; the member picker of an admin
    // testing in another tab should update within its staleTime.
    void qc.invalidateQueries({ queryKey: queryKeys.config });
    void qc.invalidateQueries({ queryKey: queryKeys.adminNodeStats });
  }

  const remove = createMutation(() => ({
    mutationFn: async (target: NonNullable<typeof pendingDelete>) => {
      const base =
        target.kind === 'family'
          ? '/api/v1/admin/connection-mode-families'
          : '/api/v1/admin/connection-modes';
      await apiClient.delete(
        `${base}/${encodeURIComponent(target.entity.id)}`,
        z.object({ ok: z.boolean() }),
      );
    },
    onSuccess: () => {
      invalidate();
      toast.success(pendingDelete?.kind === 'family' ? 'Family removed' : 'Mode removed');
      pendingDelete = null;
    },
    onError: (err) => {
      toast.error('Could not delete', { description: apiErrorMessage(err) });
    },
  }));

  const makeDefault = createMutation(() => ({
    mutationFn: async (slug: string) => {
      await apiClient.patch(
        `/api/v1/admin/connection-modes/${encodeURIComponent(slug)}`,
        { makeDefault: true },
        z.object({ ok: z.boolean() }),
      );
    },
    onSuccess: () => {
      invalidate();
      toast.success('Default mode updated');
    },
    onError: (err) => {
      toast.error('Could not set the default', { description: apiErrorMessage(err) });
    },
  }));
</script>

<AdminLayout>
  <div class="flex items-center justify-between mb-6 flex-wrap gap-3">
    <div>
      <h1 class="text-2xl font-bold">Connection modes</h1>
      <p class="text-sm text-muted-foreground mt-1">
        The member transport picker, fully data-driven: families are the parent cards, modes are the
        transports inside them. A new mode ships unselectable until it is enabled here AND its
        placement pool is bound in <Link href="/admin/remnawave" class="underline">Remnawave</Link>.
        While the catalog is empty the picker falls back to the built-in defaults.
      </p>
    </div>
    <div class="flex gap-2">
      <Button variant="outline" onclick={() => (creatingFamily = true)}>
        <Plus class="size-4" />
        Add family
      </Button>
      <Button onclick={() => (creatingMode = true)} disabled={families.length === 0}>
        <Plus class="size-4" />
        Add mode
      </Button>
    </div>
  </div>

  {#if catalog.isPending}
    <div class="space-y-3">
      {#each Array(2) as _, i (i)}
        <Card>
          <CardHeader><Skeleton class="h-5 w-48" /></CardHeader>
          <CardContent><Skeleton class="h-4 w-2/3" /></CardContent>
        </Card>
      {/each}
    </div>
  {:else if catalog.isError}
    <AdminListState error={catalog.error} onRetry={() => void catalog.refetch()} />
  {:else}
    <div class="space-y-4">
      {#each sections as section (section.family?.id ?? '__orphans__')}
        {@const f = section.family}
        {@const FamIcon = f ? resolveModeIcon(f.iconId) : null}
        <Card>
          <CardHeader>
            <CardTitle class="text-lg flex items-center justify-between flex-wrap gap-2">
              <span class="flex items-center gap-2">
                {#if FamIcon}<FamIcon class="size-4 text-primary" />{/if}
                {#if f}
                  <span>{f.label ?? '(translated name)'}</span>
                  <code class="text-xs font-normal text-muted-foreground">{f.id}</code>
                {:else}
                  <span>No family</span>
                {/if}
              </span>
              <span class="flex items-center gap-2">
                {#if f && !f.enabled}
                  <span class="text-xs px-2 py-1 rounded bg-muted text-muted-foreground">
                    Disabled
                  </span>
                {/if}
                {#if f}
                  <Button size="sm" variant="outline" onclick={() => (editingFamily = f)}>
                    Edit
                  </Button>
                  <Button
                    size="sm"
                    variant="destructive"
                    disabled={section.children.length > 0}
                    title={section.children.length > 0
                      ? 'Move or delete its modes first'
                      : undefined}
                    onclick={() => (pendingDelete = { kind: 'family', entity: f })}
                  >
                    Remove
                  </Button>
                {/if}
              </span>
            </CardTitle>
            {#if f?.audience}
              <p class="text-xs text-muted-foreground">{f.audience}</p>
            {/if}
            {#if !f}
              <p class="text-xs text-muted-foreground">
                These modes reference a family that no longer exists. They resolve DISABLED for
                members until re-parented (Edit → Family) or deleted.
              </p>
            {/if}
          </CardHeader>
          <CardContent class="space-y-2">
            {#if section.children.length === 0}
              <p class="text-sm text-muted-foreground">
                No modes yet. A family with no enabled modes is hidden from members.
              </p>
            {/if}
            {#each section.children as m (m.id)}
              <div
                class="rounded-lg border border-border p-3 flex flex-wrap items-center justify-between gap-2"
              >
                <div class="min-w-0">
                  <div class="flex items-center gap-2 flex-wrap text-sm">
                    <span class="font-semibold">{m.label ?? '(translated name)'}</span>
                    <code class="text-xs text-muted-foreground">{m.id}</code>
                    <span class="text-xs px-1.5 py-0.5 rounded bg-primary/10 text-primary">
                      {m.deliveryStyle === 'rawConfig' ? 'raw config' : 'URL'}
                    </span>
                    {#if m.isDefault}
                      <span class="text-xs px-1.5 py-0.5 rounded bg-primary/10 text-primary">
                        Default
                      </span>
                    {/if}
                    {#if m.isFamilyDefault}
                      <span class="text-xs px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                        family default
                      </span>
                    {/if}
                    {#if m.isCensorshipRecommended}
                      <span class="text-xs px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                        censorship pick
                      </span>
                    {/if}
                    {#if !m.enabled}
                      <span class="text-xs px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                        Disabled
                      </span>
                    {/if}
                  </div>
                  <div class="mt-1 flex items-center gap-2 flex-wrap text-xs text-muted-foreground">
                    {#each m.backends as b (b)}
                      {@const summary = m.placements.find((p) => p.backendId === b)}
                      <span
                        class="rounded px-1.5 py-0.5 {summary && !summary.bound
                          ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400'
                          : 'bg-muted'}"
                      >
                        {ADMIN_BACKEND_LABELS[b as keyof typeof ADMIN_BACKEND_LABELS] ?? b}:
                        {summary
                          ? summary.bound
                            ? `${summary.boundCount} bound`
                            : 'no pool bound'
                          : 'no placement needed'}
                      </span>
                    {/each}
                    <span class="tabular-nums">order {m.order}</span>
                  </div>
                </div>
                <div class="flex items-center gap-2">
                  {#if !m.isDefault && m.enabled}
                    <Button
                      size="sm"
                      variant="ghost"
                      onclick={() => makeDefault.mutate(m.id)}
                      disabled={makeDefault.isPending}
                    >
                      Make default
                    </Button>
                  {/if}
                  <Button size="sm" variant="outline" onclick={() => (editingMode = m)}>
                    Edit
                  </Button>
                  <Button
                    size="sm"
                    variant="destructive"
                    onclick={() => (pendingDelete = { kind: 'mode', entity: m })}
                  >
                    Remove
                  </Button>
                </div>
              </div>
            {/each}
          </CardContent>
        </Card>
      {/each}
    </div>
  {/if}

  {#if creatingFamily}
    <ConnectionModeFamilyEditor
      onClose={() => (creatingFamily = false)}
      onSaved={() => {
        creatingFamily = false;
        invalidate();
      }}
    />
  {/if}
  {#if editingFamily}
    <ConnectionModeFamilyEditor
      family={editingFamily}
      onClose={() => (editingFamily = null)}
      onSaved={() => {
        editingFamily = null;
        invalidate();
      }}
    />
  {/if}
  {#if creatingMode}
    <ConnectionModeEditor
      {families}
      onClose={() => (creatingMode = false)}
      onSaved={() => {
        creatingMode = false;
        invalidate();
      }}
    />
  {/if}
  {#if editingMode}
    <ConnectionModeEditor
      mode={editingMode}
      {families}
      onClose={() => (editingMode = null)}
      onSaved={() => {
        editingMode = null;
        invalidate();
      }}
    />
  {/if}

  <AlertDialog.Root
    open={!!pendingDelete}
    onOpenChange={(o) => (o ? null : (pendingDelete = null))}
  >
    <AlertDialog.Content>
      <AlertDialog.Header>
        <AlertDialog.Title>
          Remove {pendingDelete?.kind === 'family' ? 'family' : 'mode'} "{pendingDelete?.entity
            .id}"?
        </AlertDialog.Title>
        <AlertDialog.Description>
          {#if pendingDelete?.kind === 'mode'}
            The server refuses while members are on this mode (disable it instead), or while it is
            the default. Its placement bindings are removed with it.
          {:else}
            The server refuses while the family still contains modes.
          {/if}
        </AlertDialog.Description>
      </AlertDialog.Header>
      <AlertDialog.Footer>
        <AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
        <AlertDialog.Action
          onclick={() => pendingDelete && remove.mutate(pendingDelete)}
          disabled={remove.isPending}
        >
          {remove.isPending ? 'Removing…' : 'Remove'}
        </AlertDialog.Action>
      </AlertDialog.Footer>
    </AlertDialog.Content>
  </AlertDialog.Root>
</AdminLayout>
