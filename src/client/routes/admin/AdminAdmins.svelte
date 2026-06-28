<script lang="ts">
  import { Card, CardHeader, CardContent } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import AdminLayout from './AdminLayout.svelte';
  import AdminListState from './AdminListState.svelte';
  import { z } from 'zod';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage, firstIssueMessage } from '../../lib/errors';
  import { formatDate } from '../../lib/i18n/format';
  import { adminAdminsQuery, adminCredentialsQuery, queryKeys } from '../../lib/queries';
  import {
    CreateInviteRequest,
    CreateInviteResponse,
    type AdminCredential,
    type AdminListItem,
  } from '../../../shared/contracts/admin';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';

  const qc = useQueryClient();
  const admins = adminAdminsQuery();

  // Invite form.
  let username = $state('');
  let displayName = $state('');

  // Reveal-once: the freshly minted invite LINK + an acknowledgement gate. The
  // raw token is shown only here (the server stores only its hash).
  let revealed = $state<{ url: string; username: string; expiresAtMs: number } | null>(null);
  let acknowledged = $state(false);

  const invite = createMutation(() => ({
    mutationFn: (body: CreateInviteRequest) =>
      apiClient.post('/api/v1/admin/admins/invite', body, CreateInviteResponse),
    onSuccess: (res) => {
      const url = `${window.location.origin}/admin/register?invite=${res.inviteToken}`;
      revealed = { url, username: res.username, expiresAtMs: res.expiresAtMs };
      acknowledged = false;
      username = '';
      displayName = '';
      void qc.invalidateQueries({ queryKey: queryKeys.adminAdmins });
      toast.success(`Invite created for ${res.username}`);
    },
    onError: (err) => toast.error('Could not create invite', { description: apiErrorMessage(err) }),
  }));

  function submitInvite() {
    const parsed = CreateInviteRequest.safeParse({
      username: username.trim(),
      displayName: displayName.trim() || undefined,
    });
    if (!parsed.success) {
      toast.error('Check the form', { description: firstIssueMessage(parsed.error) });
      return;
    }
    invite.mutate(parsed.data);
  }

  async function copyUrl() {
    if (!revealed) return;
    try {
      await navigator.clipboard.writeText(revealed.url);
      toast.success('Invite link copied');
    } catch {
      toast.error('Copy failed — select the link and copy manually');
    }
  }

  // --- W3-8a: lifecycle (deactivate / reactivate + per-passkey revoke) -------
  let expandedId = $state<string | null>(null);
  let confirmDeactivate = $state<AdminListItem | null>(null);
  let confirmRevoke = $state<{ adminId: string; cred: AdminCredential } | null>(null);

  // One lazy query for whichever row is expanded (only fetches when open).
  const creds = adminCredentialsQuery(
    () => expandedId,
    () => expandedId !== null,
  );

  const setActive = createMutation(() => ({
    mutationFn: ({ id, isActive }: { id: string; isActive: boolean }) =>
      apiClient.patch(
        `/api/v1/admin/admins/${encodeURIComponent(id)}`,
        { isActive },
        z.object({ ok: z.boolean(), isActive: z.boolean(), username: z.string() }),
      ),
    onSuccess: (res) => {
      confirmDeactivate = null;
      void qc.invalidateQueries({ queryKey: queryKeys.adminAdmins });
      toast.success(res.isActive ? `Reactivated ${res.username}` : `Deactivated ${res.username}`);
    },
    onError: (err) => toast.error('Could not update admin', { description: apiErrorMessage(err) }),
  }));

  const revoke = createMutation(() => ({
    mutationFn: ({ cred }: { adminId: string; cred: AdminCredential }) =>
      apiClient.delete(
        `/api/v1/admin/admins/credentials/${encodeURIComponent(cred.id)}`,
        z.object({ ok: z.boolean(), revoked: z.boolean() }),
      ),
    onSuccess: (_res, vars) => {
      confirmRevoke = null;
      void qc.invalidateQueries({ queryKey: queryKeys.adminCredentials(vars.adminId) });
      void qc.invalidateQueries({ queryKey: queryKeys.adminAdmins }); // passkeyCount changed
      toast.success('Passkey revoked');
    },
    onError: (err) =>
      toast.error('Could not revoke passkey', { description: apiErrorMessage(err) }),
  }));

  function toggle(id: string) {
    expandedId = expandedId === id ? null : id;
  }
</script>

<AdminLayout>
  <h1 class="text-2xl font-bold mb-2">Admins</h1>
  <p class="text-sm text-muted-foreground mb-6">
    Admins sign in with a passkey — no shared username or password. To add another admin, create an
    invite and send them the one-time link; they open it on their own device and register their
    passkey. Links are shown once and expire in 24 hours.
  </p>

  <!-- Invite form -->
  <Card class="mb-6">
    <CardHeader><h2 class="font-semibold">Invite an admin</h2></CardHeader>
    <CardContent class="grid gap-3 sm:grid-cols-2">
      <label class="text-sm">
        <span class="mb-1 block text-muted-foreground">Username</span>
        <Input bind:value={username} placeholder="e.g. alex" autocomplete="off" />
      </label>
      <label class="text-sm">
        <span class="mb-1 block text-muted-foreground">Display name (optional)</span>
        <Input bind:value={displayName} placeholder="defaults to username" autocomplete="off" />
      </label>
      <div class="sm:col-span-2">
        <Button onclick={submitInvite} disabled={!username.trim() || invite.isPending}>
          {invite.isPending ? 'Creating…' : 'Create invite link'}
        </Button>
      </div>
    </CardContent>
  </Card>

  {#if admins.isPending}
    <div class="space-y-2">
      {#each Array(2) as _, i (i)}<Skeleton class="h-12 w-full" />{/each}
    </div>
  {:else if admins.isError}
    <AdminListState error={admins.error} onRetry={() => void admins.refetch()} />
  {:else if (admins.data?.length ?? 0) === 0}
    <AdminListState emptyText="No admins yet." />
  {:else}
    <ul class="divide-y divide-border rounded-lg border border-border bg-card">
      {#each admins.data ?? [] as a (a.id)}
        <li class="px-4 py-3 text-sm">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div class="flex items-center gap-3">
              <span class="font-medium">{a.username}</span>
              {#if a.displayName !== a.username}
                <span class="text-muted-foreground">{a.displayName}</span>
              {/if}
              {#if a.passkeyCount > 0}
                <span class="rounded bg-emerald-500/15 px-2 py-0.5 text-xs text-emerald-500">
                  {a.passkeyCount} passkey{a.passkeyCount === 1 ? '' : 's'}
                </span>
              {:else if a.pendingInvite}
                <span class="rounded bg-amber-500/15 px-2 py-0.5 text-xs text-amber-500">
                  invite pending
                </span>
              {:else}
                <span class="rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                  no passkey
                </span>
              {/if}
              {#if !a.isActive}
                <span class="rounded bg-destructive/15 px-2 py-0.5 text-xs text-destructive">
                  inactive
                </span>
              {/if}
            </div>
            <div class="flex items-center gap-2">
              <span class="hidden text-xs text-muted-foreground sm:inline">
                {a.lastLoginAt ? `last in ${formatDate(a.lastLoginAt)}` : 'never signed in'}
              </span>
              {#if a.passkeyCount > 0}
                <Button variant="ghost" size="sm" onclick={() => toggle(a.id)}>
                  Passkeys
                  <ChevronDown
                    class="size-4 transition-transform {expandedId === a.id ? 'rotate-180' : ''}"
                  />
                </Button>
              {/if}
              {#if a.isActive}
                <Button variant="outline" size="sm" onclick={() => (confirmDeactivate = a)}>
                  Deactivate
                </Button>
              {:else}
                <Button
                  variant="outline"
                  size="sm"
                  disabled={setActive.isPending}
                  onclick={() => setActive.mutate({ id: a.id, isActive: true })}
                >
                  Reactivate
                </Button>
              {/if}
            </div>
          </div>

          <!-- Expandable passkey list (lazy: only the open row fetches). -->
          {#if expandedId === a.id}
            <div class="mt-3 border-t border-border pt-3">
              {#if creds.isPending}
                <Skeleton class="h-10 w-full" />
              {:else if creds.isError}
                <p class="text-xs text-destructive">{apiErrorMessage(creds.error)}</p>
              {:else if (creds.data?.length ?? 0) === 0}
                <p class="text-xs text-muted-foreground">No passkeys registered.</p>
              {:else}
                <ul class="space-y-2">
                  {#each creds.data ?? [] as c (c.id)}
                    <li
                      class="flex items-center justify-between gap-2 rounded border border-border bg-background px-3 py-2"
                    >
                      <div class="min-w-0">
                        <p class="truncate font-medium">{c.deviceLabel ?? 'Passkey'}</p>
                        <p class="text-xs text-muted-foreground">
                          {c.lastUsedAt ? `last used ${formatDate(c.lastUsedAt)}` : 'never used'} · added
                          {formatDate(c.createdAt)}
                        </p>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        class="text-destructive hover:text-destructive"
                        disabled={revoke.isPending}
                        onclick={() => (confirmRevoke = { adminId: a.id, cred: c })}
                      >
                        Revoke
                      </Button>
                    </li>
                  {/each}
                </ul>
              {/if}
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}

  <!-- Reveal-once dialog for the freshly minted invite link. -->
  <AlertDialog.Root
    open={!!revealed}
    onOpenChange={(next) => {
      if (!next && !acknowledged) {
        toast.warning('Copy the link first', { description: 'It is shown only once.' });
        return;
      }
      if (!next) revealed = null;
    }}
  >
    <AlertDialog.Content>
      <AlertDialog.Header>
        <AlertDialog.Title>Send this invite link to {revealed?.username}</AlertDialog.Title>
        <AlertDialog.Description>
          This is the only time the link is shown. Share it over a secure channel; whoever opens it
          can register a passkey as this admin. It expires
          {revealed ? formatDate(revealed.expiresAtMs) : ''} (24 hours).
        </AlertDialog.Description>
      </AlertDialog.Header>
      <pre
        class="max-h-32 overflow-auto rounded bg-muted p-3 font-mono text-xs break-all whitespace-pre-wrap">{revealed?.url}</pre>
      <div class="flex gap-2">
        <Button variant="outline" size="sm" onclick={copyUrl}>Copy link</Button>
      </div>
      <label class="flex cursor-pointer select-none items-center gap-2 text-sm">
        <Checkbox bind:checked={acknowledged} id="ack-invite" />
        I have copied the link.
      </label>
      <AlertDialog.Footer>
        <Button disabled={!acknowledged} onclick={() => (revealed = null)}>Done</Button>
      </AlertDialog.Footer>
    </AlertDialog.Content>
  </AlertDialog.Root>

  <!-- Deactivate confirmation (the backend blocks deactivating the last admin who can sign in). -->
  <AlertDialog.Root
    open={!!confirmDeactivate}
    onOpenChange={(next) => {
      if (!next) confirmDeactivate = null;
    }}
  >
    <AlertDialog.Content>
      <AlertDialog.Header>
        <AlertDialog.Title>Deactivate {confirmDeactivate?.username}?</AlertDialog.Title>
        <AlertDialog.Description>
          Their existing sessions stop working immediately and they cannot sign in again until an
          admin reactivates them. If this is your own account, make sure another admin with a
          passkey can still sign in — the last admin who can sign in cannot be deactivated.
        </AlertDialog.Description>
      </AlertDialog.Header>
      <AlertDialog.Footer>
        <AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
        <Button
          variant="destructive"
          disabled={setActive.isPending}
          onclick={() =>
            confirmDeactivate && setActive.mutate({ id: confirmDeactivate.id, isActive: false })}
        >
          {setActive.isPending ? 'Deactivating…' : 'Deactivate'}
        </Button>
      </AlertDialog.Footer>
    </AlertDialog.Content>
  </AlertDialog.Root>

  <!-- Revoke-passkey confirmation (the backend blocks revoking the last signable passkey). -->
  <AlertDialog.Root
    open={!!confirmRevoke}
    onOpenChange={(next) => {
      if (!next) confirmRevoke = null;
    }}
  >
    <AlertDialog.Content>
      <AlertDialog.Header>
        <AlertDialog.Title>Revoke this passkey?</AlertDialog.Title>
        <AlertDialog.Description>
          “{confirmRevoke?.cred.deviceLabel ?? 'Passkey'}” will no longer be able to sign in. This
          cannot be undone — the device must re-register via a new invite. The last passkey that can
          sign in cannot be revoked.
        </AlertDialog.Description>
      </AlertDialog.Header>
      <AlertDialog.Footer>
        <AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
        <Button
          variant="destructive"
          disabled={revoke.isPending}
          onclick={() => confirmRevoke && revoke.mutate(confirmRevoke)}
        >
          {revoke.isPending ? 'Revoking…' : 'Revoke'}
        </Button>
      </AlertDialog.Footer>
    </AlertDialog.Content>
  </AlertDialog.Root>
</AdminLayout>
