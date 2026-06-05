<script lang="ts">
  import type { z } from 'zod';
  import * as Dialog from '@client/components/ui/dialog';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { apiClient } from '../../lib/api';
  import { OutlineServerAdmin, OutlineServerUpsert } from '../../../shared/contracts/admin';
  import { createMutation } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { z as zod } from 'zod';

  /**
   * Modal editor for a single Outline server. Used for both create and edit
   * — when `server` is provided, the form pre-fills (minus the secret-laden
   * `apiUrl`, which is masked on read and only re-submitted if the admin
   * actually retypes it).
   */
  interface Props {
    server?: z.infer<typeof OutlineServerAdmin>;
    onClose: () => void;
    onSaved: () => void;
  }
  let { server, onClose, onSaved }: Props = $props();

  let open = $state(true);
  const isEdit = !!server;

  // Form state. On edit, the existing `apiUrlMasked` is shown as placeholder
  // text in the apiUrl input — the admin can leave it blank to keep the
  // existing URL, or type a new one to rotate the secret.
  let name = $state(server?.name ?? '');
  let slug = $state(server?.slug ?? '');
  let apiUrl = $state('');
  let websocketEnabled = $state(server?.websocketEnabled ?? false);
  let websocketDomain = $state(server?.websocketDomain ?? '');
  let prometheusUrl = $state(server?.prometheusUrl ?? '');
  let isActive = $state(server?.isActive ?? true);
  let priority = $state(server?.priority ?? 0);

  // Test connection state (a separate side flow — independent of save).
  let testing = $state(false);
  let testResult = $state<{ ok: boolean; message: string } | null>(null);

  async function runTest() {
    if (!apiUrl) {
      testResult = { ok: false, message: 'Paste an apiUrl first' };
      return;
    }
    testing = true;
    testResult = null;
    try {
      const TestResp = zod.union([
        zod.object({ ok: zod.literal(true), keyCount: zod.number() }),
        zod.object({ ok: zod.literal(false), error: zod.string() }),
      ]);
      const result = await apiClient.post(
        '/api/v1/admin/outline-servers/test-connection',
        { apiUrl },
        TestResp,
      );
      if (result.ok) {
        testResult = { ok: true, message: `Reachable. Current key count: ${result.keyCount}` };
      } else {
        testResult = { ok: false, message: result.error };
      }
    } catch (err) {
      testResult = { ok: false, message: err instanceof Error ? err.message : String(err) };
    } finally {
      testing = false;
    }
  }

  const save = createMutation(() => ({
    mutationFn: async () => {
      // For edits where the admin didn't retype apiUrl, omit it from the
      // PATCH body so the server keeps the existing value.
      const payload: Partial<z.infer<typeof OutlineServerUpsert>> = {
        name,
        slug,
        websocketEnabled,
        websocketDomain: websocketDomain || null,
        prometheusUrl: prometheusUrl || null,
        isActive,
        priority,
      };
      if (apiUrl) payload.apiUrl = apiUrl;

      if (isEdit) {
        return apiClient.patch(
          `/api/v1/admin/outline-servers/${server!.id}`,
          payload,
          OutlineServerAdmin,
        );
      }
      // Create requires apiUrl
      if (!apiUrl) throw new Error('apiUrl is required to register a new server');
      return apiClient.post(
        '/api/v1/admin/outline-servers',
        { ...payload, apiUrl },
        OutlineServerAdmin,
      );
    },
    onSuccess: () => {
      open = false;
      onSaved();
      toast.success(isEdit ? 'Server updated' : 'Server registered');
    },
    onError: (err) => {
      toast.error('Save failed', {
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
  <Dialog.Content class="sm:max-w-lg max-h-[90vh] overflow-y-auto">
    <Dialog.Header>
      <Dialog.Title>{isEdit ? `Edit ${server?.name}` : 'Register an Outline server'}</Dialog.Title>
      <Dialog.Description>
        The Outline server's TLS certificate must be valid — Workers <code>fetch</code> rejects self-signed
        certs. Either front it with Cloudflare or install a real LE certificate.
      </Dialog.Description>
    </Dialog.Header>

    <div class="space-y-4">
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="srv-name">Display name</label>
        <Input id="srv-name" bind:value={name} placeholder="e.g. EU North" />
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="srv-slug">Slug</label>
        <Input id="srv-slug" bind:value={slug} placeholder="eu-north" autocomplete="off" />
        <p class="text-xs text-muted-foreground/80 mt-1">
          Used internally + in audit logs. Lowercase, alphanumeric, hyphens. Immutable once set.
        </p>
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="srv-url">
          Outline Manager API URL
        </label>
        <Input
          id="srv-url"
          bind:value={apiUrl}
          type="password"
          placeholder={isEdit ? server?.apiUrlMasked : 'https://host:port/<secret>'}
          autocomplete="off"
        />
        <p class="text-xs text-muted-foreground/80 mt-1">
          Includes the secret path segment. {isEdit ? 'Leave blank to keep the existing URL.' : ''}
          <button
            type="button"
            class="text-primary underline ml-1"
            onclick={runTest}
            disabled={testing}
          >
            {testing ? 'Testing…' : 'Test connection'}
          </button>
        </p>
        {#if testResult}
          <div
            class="mt-2 rounded-md px-3 py-2 text-xs {testResult.ok
              ? 'bg-emerald-500/10 border border-emerald-500/40 text-emerald-600'
              : 'bg-destructive/10 border border-destructive/40 text-destructive'}"
          >
            {testResult.message}
          </div>
        {/if}
      </div>

      <div class="space-y-3 border-t border-border pt-4">
        <label class="flex items-center gap-3 text-sm">
          <Checkbox
            checked={websocketEnabled}
            onCheckedChange={(v) => (websocketEnabled = v === true)}
          />
          <span>WSS-wrapped Shadowsocks (non-stock Outline fork only)</span>
        </label>
        {#if websocketEnabled}
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="srv-wsdomain">
              WSS domain
            </label>
            <Input id="srv-wsdomain" bind:value={websocketDomain} placeholder="ws.example.org" />
          </div>
        {/if}
      </div>

      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="srv-prom">
          Prometheus URL (optional)
        </label>
        <Input id="srv-prom" bind:value={prometheusUrl} placeholder="https://prom.example.org" />
        <p class="text-xs text-muted-foreground/80 mt-1">
          Reserved for future per-key metrics; not used in v1.
        </p>
      </div>

      <div class="grid grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="srv-priority">
            Priority
          </label>
          <Input
            id="srv-priority"
            type="number"
            min={0}
            value={priority}
            oninput={(e) =>
              (priority = Math.max(0, parseInt((e.target as HTMLInputElement).value, 10) || 0))}
          />
        </div>
        <label class="flex items-center gap-3 text-sm pt-5">
          <Checkbox checked={isActive} onCheckedChange={(v) => (isActive = v === true)} />
          <span>Active (eligible for new key issuance)</span>
        </label>
      </div>
    </div>

    <Dialog.Footer>
      <Button variant="ghost" onclick={() => (open = false)} disabled={save.isPending}>
        Cancel
      </Button>
      <Button onclick={() => save.mutate()} disabled={save.isPending || !name || !slug}>
        {save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Register server'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
