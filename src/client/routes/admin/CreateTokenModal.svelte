<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { Input } from '@client/components/ui/input';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Select from '@client/components/ui/select';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { CreateTokenResponse } from '../../../shared/contracts/tokens';
  import { type ApiScope, SCOPE_GROUPS } from '../../../shared/contracts/scopes';
  import { createMutation } from '@tanstack/svelte-query';
  import { adminBackendServersQuery } from '../../lib/queries';
  import { toast } from 'svelte-sonner';

  interface Props {
    onClose: () => void;
    onCreated: (plaintext: string, name: string) => void;
    /** Prefill from a deep link (`tokenPrefill.ts`); read once, when the dialog mounts. */
    initialName?: string;
    initialScopes?: readonly ApiScope[];
    /** Registration boundary presets for an `admin:edges:register` token. */
    initialServers?: readonly string[];
    initialNodes?: readonly string[];
  }
  let {
    onClose,
    onCreated,
    initialName = '',
    initialScopes = [],
    initialServers = [],
    initialNodes = [],
  }: Props = $props();

  let open = $state(true);
  // svelte-ignore state_referenced_locally -- deliberate mount-time snapshot of the prefill.
  let name = $state(initialName);
  // svelte-ignore state_referenced_locally -- deliberate mount-time snapshot of the prefill.
  let scopes = $state<Set<ApiScope>>(new Set(initialScopes));
  let expiry = $state<string>('none');

  // A relay-registration token is confined to a boundary: the backend servers
  // (and optionally the node names) the node role may register relays for.
  // The server refuses the scope without one, so the dialog asks for it.
  const REGISTER_SCOPE: ApiScope = 'admin:edges:register';
  const needsBoundary = $derived(scopes.has(REGISTER_SCOPE));
  const servers = adminBackendServersQuery();
  // svelte-ignore state_referenced_locally -- deliberate mount-time snapshot of the prefill.
  let boundaryServers = $state<Set<string>>(new Set(initialServers));
  // svelte-ignore state_referenced_locally -- deliberate mount-time snapshot of the prefill.
  let boundaryNodes = $state(initialNodes.join(', '));
  const nodeNames = $derived([
    ...new Set(
      boundaryNodes
        .split(',')
        .map((n) => n.trim())
        .filter(Boolean),
    ),
  ]);
  const boundaryMissing = $derived(needsBoundary && boundaryServers.size === 0);

  function toggleServer(id: string, next: boolean) {
    const draft = new Set(boundaryServers);
    if (next) draft.add(id);
    else draft.delete(id);
    boundaryServers = draft;
  }

  const SCOPE_SECTIONS = [
    { label: 'Member', scopes: SCOPE_GROUPS.member },
    { label: 'Admin', scopes: SCOPE_GROUPS.admin },
  ] as const;

  function groupAllSelected(group: readonly ApiScope[]): boolean {
    return group.every((s) => scopes.has(s));
  }

  function toggleGroup(group: readonly ApiScope[], next: boolean) {
    const draft = new Set(scopes);
    for (const s of group) {
      if (next) draft.add(s);
      else draft.delete(s);
    }
    scopes = draft;
  }

  const expiryLabel = $derived(
    expiry === 'none'
      ? 'No expiry'
      : expiry === '30'
        ? '30 days'
        : expiry === '90'
          ? '90 days'
          : '1 year',
  );

  function toggle(s: ApiScope, next: boolean) {
    const draft = new Set(scopes);
    if (next) draft.add(s);
    else draft.delete(s);
    scopes = draft;
  }

  const create = createMutation(() => ({
    mutationFn: () => {
      const expiresInDays =
        expiry === 'none' ? null : expiry === '30' ? 30 : expiry === '90' ? 90 : 365;
      return apiClient.post(
        '/api/v1/admin/tokens',
        {
          name,
          scopes: Array.from(scopes),
          subjectType: 'service',
          expiresInDays,
          ...(needsBoundary
            ? {
                edgeRegistration: {
                  backendServerIds: Array.from(boundaryServers),
                  ...(nodeNames.length > 0 ? { nodeNames } : {}),
                },
              }
            : {}),
        },
        CreateTokenResponse,
      );
    },
    onSuccess: (res) => {
      open = false;
      onCreated(res.plaintext, res.token.name);
    },
    onError: (err) => {
      toast.error('Could not create token', {
        description: apiErrorMessage(err),
      });
    },
  }));

  function onOpenChange(next: boolean) {
    open = next;
    if (!next) onClose();
  }
</script>

<Dialog.Root bind:open {onOpenChange}>
  <Dialog.Content class="sm:max-w-lg">
    <Dialog.Header>
      <Dialog.Title>Create API token</Dialog.Title>
      <Dialog.Description>
        Tokens are shown in plaintext exactly once. Pick the minimum scopes required.
      </Dialog.Description>
    </Dialog.Header>

    <div class="space-y-4">
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="tok-name">Name</label>
        <Input id="tok-name" bind:value={name} placeholder="e.g. iOS app prod, monitoring bot" />
      </div>

      <div>
        <span class="text-xs text-muted-foreground mb-1 block">Scopes</span>
        <div class="space-y-3 max-h-60 overflow-y-auto border rounded p-2">
          {#each SCOPE_SECTIONS as section (section.label)}
            <div class="space-y-1.5">
              <label class="flex items-center gap-2 cursor-pointer text-sm font-medium">
                <Checkbox
                  checked={groupAllSelected(section.scopes)}
                  onCheckedChange={(next) => toggleGroup(section.scopes, next === true)}
                  id={`scope-group-${section.label}`}
                />
                <span>All {section.label.toLowerCase()} scopes</span>
              </label>
              <div class="ps-6 space-y-1.5">
                {#each section.scopes as s (s)}
                  <label class="flex items-center gap-2 cursor-pointer text-sm">
                    <Checkbox
                      checked={scopes.has(s)}
                      onCheckedChange={(next) => toggle(s, next === true)}
                      id={`scope-${s}`}
                    />
                    <code>{s}</code>
                  </label>
                {/each}
              </div>
            </div>
          {/each}
        </div>
      </div>

      {#if needsBoundary}
        <div class="space-y-2 rounded border p-3">
          <div>
            <span class="text-sm font-medium block">Relay registration boundary</span>
            <p class="text-xs text-muted-foreground">
              A relay registration token may only register relays on the backend servers ticked
              here. Pick at least one.
            </p>
          </div>
          {#if servers.isPending}
            <p class="text-xs text-muted-foreground">Loading backend servers...</p>
          {:else if servers.isError}
            <p class="text-xs text-destructive">{apiErrorMessage(servers.error)}</p>
          {:else if (servers.data ?? []).length === 0}
            <p class="text-xs text-muted-foreground">
              No backend servers yet. Add one under Servers first.
            </p>
          {:else}
            <div class="space-y-1.5 max-h-32 overflow-y-auto">
              {#each servers.data ?? [] as srv (srv.id)}
                <label class="flex items-center gap-2 cursor-pointer text-sm">
                  <Checkbox
                    checked={boundaryServers.has(srv.id)}
                    onCheckedChange={(next) => toggleServer(srv.id, next === true)}
                    id={`boundary-${srv.id}`}
                  />
                  <span>{srv.name}</span>
                  <code class="text-xs text-muted-foreground">{srv.slug}</code>
                </label>
              {/each}
            </div>
          {/if}
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="tok-nodes">
              Node names (optional, comma separated)
            </label>
            <Input id="tok-nodes" bind:value={boundaryNodes} placeholder="node-one, node-two" />
            <p class="text-xs text-muted-foreground mt-1">
              Empty means any node on the ticked servers.
            </p>
          </div>
        </div>
      {/if}

      <div>
        <span class="text-xs text-muted-foreground mb-1 block">Expires</span>
        <Select.Root type="single" bind:value={expiry}>
          <Select.Trigger class="w-full">{expiryLabel}</Select.Trigger>
          <Select.Content>
            <Select.Item value="none">No expiry</Select.Item>
            <Select.Item value="30">30 days</Select.Item>
            <Select.Item value="90">90 days</Select.Item>
            <Select.Item value="365">1 year</Select.Item>
          </Select.Content>
        </Select.Root>
      </div>
    </div>

    <Dialog.Footer>
      <Button variant="ghost" onclick={() => (open = false)} disabled={create.isPending}>
        Cancel
      </Button>
      <Button
        onclick={() => create.mutate()}
        disabled={create.isPending || !name || scopes.size === 0 || boundaryMissing}
      >
        {create.isPending ? 'Creating...' : 'Create token'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
