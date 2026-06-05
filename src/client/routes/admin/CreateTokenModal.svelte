<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { Input } from '@client/components/ui/input';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Select from '@client/components/ui/select';
  import { apiClient } from '../../lib/api';
  import { CreateTokenResponse } from '../../../shared/contracts/tokens';
  import { type ApiScope, SCOPE_GROUPS } from '../../../shared/contracts/scopes';
  import { createMutation } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  interface Props {
    onClose: () => void;
    onCreated: (plaintext: string, name: string) => void;
  }
  let { onClose, onCreated }: Props = $props();

  let open = $state(true);
  let name = $state('');
  let scopes = $state<Set<ApiScope>>(new Set());
  let expiry = $state<string>('none');

  const allScopes: ApiScope[] = [...SCOPE_GROUPS.member, ...SCOPE_GROUPS.admin];

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
        description: err instanceof Error ? err.message : String(err),
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
        <div class="space-y-1.5 max-h-48 overflow-y-auto border rounded p-2">
          {#each allScopes as s (s)}
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
        disabled={create.isPending || !name || scopes.size === 0}
      >
        {create.isPending ? 'Creating...' : 'Create token'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
