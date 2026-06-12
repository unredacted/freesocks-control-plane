<script lang="ts">
  import { Card, CardHeader, CardContent } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import AdminLayout from './AdminLayout.svelte';
  import AdminListState from './AdminListState.svelte';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage, firstIssueMessage } from '../../lib/errors';
  import { formatDate } from '../../lib/i18n/format';
  import { adminAdminsQuery, queryKeys } from '../../lib/queries';
  import { CreateInviteRequest, CreateInviteResponse } from '../../../shared/contracts/admin';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

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
        <li class="flex flex-wrap items-center justify-between gap-2 px-4 py-3 text-sm">
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
          <span class="text-xs text-muted-foreground">
            {a.lastLoginAt ? `last in ${formatDate(a.lastLoginAt)}` : 'never signed in'}
          </span>
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
</AdminLayout>
