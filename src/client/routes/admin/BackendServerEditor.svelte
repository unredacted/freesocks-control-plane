<script lang="ts">
  import type { z } from 'zod';
  import * as Dialog from '@client/components/ui/dialog';
  import * as Select from '@client/components/ui/select';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { ADMIN_BACKEND_LABELS } from '../../lib/backendLabels';
  import { BackendServerAdmin } from '../../../shared/contracts/admin';
  import { BACKEND_IDS, type BackendId } from '../../../shared/contracts/backends';
  import { createMutation } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { z as zod } from 'zod';

  /**
   * Modal editor for a single backend instance (any type). On create the admin
   * picks the backend type, then the form shows that type's connection fields.
   * On edit the type is fixed; secret-bearing fields (Remnawave apiToken,
   * Outline apiUrl) are blanked and only re-submitted if the admin retypes them.
   */
  interface Props {
    server?: z.infer<typeof BackendServerAdmin>;
    onClose: () => void;
    onSaved: () => void;
  }
  let { server, onClose, onSaved }: Props = $props();

  let open = $state(true);
  const isEdit = !!server;

  // One-time snapshot of the prop into plain locals (an editor keeps its own
  // editable copy; later prop changes shouldn't blow it away mid-edit). The IIFE
  // breaks the compiler's "captures initial value of prop" analysis, mirroring
  // TierEditor.svelte.
  const init = ((s: Props['server']) => {
    const rw = s?.config.type === 'remnawave' ? s.config : null;
    const ol = s?.config.type === 'outline' ? s.config : null;
    return {
      backend: s?.backend ?? ('remnawave' as BackendId),
      name: s?.name ?? '',
      slug: s?.slug ?? '',
      location: s?.location ?? '',
      locationLabel: s?.locationLabel ?? '',
      isActive: s?.isActive ?? true,
      priority: s?.priority ?? 0,
      maxKeys: s?.maxKeys ?? null,
      baseUrl: rw?.baseUrl ?? '',
      apiTokenSet: rw?.apiTokenSet ?? false,
      apiUrlMasked: ol?.apiUrlMasked ?? '',
      websocketEnabled: ol?.websocketEnabled ?? false,
      websocketDomain: ol?.websocketDomain ?? '',
      prometheusUrl: ol?.prometheusUrl ?? '',
    };
  })(server);

  let backend = $state<BackendId>(init.backend);
  let name = $state(init.name);
  let slug = $state(init.slug);
  let location = $state(init.location);
  let locationLabel = $state(init.locationLabel);
  let isActive = $state(init.isActive);
  let priority = $state(init.priority);
  // Free-text so the field can be blank (= no cap); parsed on save.
  let maxKeysText = $state(init.maxKeys != null ? String(init.maxKeys) : '');
  // Remnawave (apiToken) + Outline (apiUrl) secrets stay blank until retyped.
  let baseUrl = $state(init.baseUrl);
  let apiToken = $state('');
  let apiUrl = $state('');
  let websocketEnabled = $state(init.websocketEnabled);
  let websocketDomain = $state(init.websocketDomain);
  let prometheusUrl = $state(init.prometheusUrl);

  let testing = $state(false);
  let testResult = $state<{ ok: boolean; message: string } | null>(null);

  // A green "Reachable" badge must describe the CURRENT config: editing any
  // connection-relevant field invalidates the last test verdict.
  $effect(() => {
    void backend;
    void baseUrl;
    void apiToken;
    void apiUrl;
    void websocketEnabled;
    void websocketDomain;
    testResult = null;
  });

  function testBody(): Record<string, unknown> | { error: string } {
    // On edit, blank fields fall back SERVER-SIDE to the stored config (the
    // secrets deliberately never round-trip to the client) — so an existing
    // instance is testable without retyping its token/apiUrl. Anything typed
    // here still overrides the stored value for the test.
    if (backend === 'remnawave') {
      if (isEdit) {
        return {
          backend,
          id: server!.id,
          ...(baseUrl ? { baseUrl } : {}),
          ...(apiToken ? { apiToken } : {}),
        };
      }
      if (!baseUrl || !apiToken) return { error: 'Enter a base URL and an API token to test' };
      return { backend, baseUrl, apiToken };
    }
    if (isEdit) {
      return {
        backend,
        id: server!.id,
        ...(apiUrl ? { apiUrl } : {}),
        websocketEnabled,
        websocketDomain: websocketDomain || null,
      };
    }
    if (!apiUrl) return { error: 'Enter an apiUrl to test' };
    return { backend, apiUrl, websocketEnabled, websocketDomain: websocketDomain || null };
  }

  async function runTest() {
    const body = testBody();
    if ('error' in body) {
      testResult = { ok: false, message: body.error as string };
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
        '/api/v1/admin/backend-servers/test-connection',
        body,
        TestResp,
      );
      testResult = result.ok
        ? { ok: true, message: `Reachable. Current key count: ${result.keyCount}` }
        : { ok: false, message: result.error };
    } catch (err) {
      testResult = { ok: false, message: apiErrorMessage(err) };
    } finally {
      testing = false;
    }
  }

  function buildPayload(): Record<string, unknown> {
    const common: Record<string, unknown> = { name, slug, isActive, priority };
    // Blank clears the location (the instance drops out of the member picker).
    common.location = location.trim() || null;
    common.locationLabel = locationLabel.trim() || null;
    // Blank = clear the cap (null); a positive integer sets it.
    const parsedMax = parseInt(maxKeysText.trim(), 10);
    common.maxKeys = Number.isInteger(parsedMax) && parsedMax >= 1 ? parsedMax : null;
    if (backend === 'remnawave') {
      if (baseUrl) common.baseUrl = baseUrl;
      if (apiToken) common.apiToken = apiToken;
    } else {
      if (apiUrl) common.apiUrl = apiUrl;
      common.websocketEnabled = websocketEnabled;
      common.websocketDomain = websocketDomain || null;
      common.prometheusUrl = prometheusUrl || null;
    }
    return common;
  }

  const save = createMutation(() => ({
    mutationFn: async () => {
      const payload = buildPayload();
      if (isEdit) {
        // The backend type is immutable, so it is NOT sent on edit.
        return apiClient.patch(
          `/api/v1/admin/backend-servers/${server!.id}`,
          payload,
          BackendServerAdmin,
        );
      }
      if (backend === 'remnawave' && (!baseUrl || !apiToken)) {
        throw new Error('A Remnawave instance needs a base URL and an API token');
      }
      if (backend === 'outline' && !apiUrl) {
        throw new Error('An Outline instance needs an apiUrl');
      }
      return apiClient.post(
        '/api/v1/admin/backend-servers',
        { backend, ...payload },
        BackendServerAdmin,
      );
    },
    onSuccess: () => {
      open = false;
      onSaved();
      toast.success(isEdit ? 'Instance updated' : 'Instance registered');
    },
    onError: (err) => {
      toast.error('Save failed', { description: apiErrorMessage(err) });
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
      <Dialog.Title>
        {isEdit ? `Edit ${server?.name}` : 'Register a backend instance'}
      </Dialog.Title>
      <Dialog.Description>
        A backend instance is one deployed proxy server. Connection secrets are stored server-side
        and never shown again.
      </Dialog.Description>
    </Dialog.Header>

    <div class="space-y-4">
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="srv-backend"
          >Backend type</label
        >
        {#if isEdit}
          <div id="srv-backend" class="text-sm font-medium py-1">
            {ADMIN_BACKEND_LABELS[backend]}
          </div>
          <p class="text-xs text-muted-foreground/80">The backend type is fixed once created.</p>
        {:else}
          <Select.Root
            type="single"
            value={backend}
            onValueChange={(v) => (backend = v as BackendId)}
          >
            <Select.Trigger id="srv-backend" class="w-56"
              >{ADMIN_BACKEND_LABELS[backend]}</Select.Trigger
            >
            <Select.Content>
              {#each BACKEND_IDS as id (id)}
                <Select.Item value={id}>{ADMIN_BACKEND_LABELS[id]}</Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
        {/if}
      </div>

      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="srv-name">Display name</label>
        <Input id="srv-name" bind:value={name} placeholder="e.g. EU North" />
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="srv-slug">Slug</label>
        <Input id="srv-slug" bind:value={slug} placeholder="eu-north" autocomplete="off" />
        <p class="text-xs text-muted-foreground/80 mt-1">
          Used internally + in audit logs. Lowercase, alphanumeric, hyphens.
        </p>
      </div>

      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="srv-location"
            >Location code</label
          >
          <Input id="srv-location" bind:value={location} placeholder="MCI" autocomplete="off" />
          <p class="mt-1 text-[11px] text-muted-foreground">
            Short code (e.g. an airport code). Members can pick their config's location by it. Blank
            = not offered in the member location picker.
          </p>
        </div>
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="srv-location-label"
            >Location label</label
          >
          <Input id="srv-location-label" bind:value={locationLabel} placeholder="Kansas City, MO" />
          <p class="mt-1 text-[11px] text-muted-foreground">
            What members see. Falls back to the code when blank.
          </p>
        </div>
      </div>

      {#if backend === 'remnawave'}
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="srv-baseurl"
            >Panel base URL</label
          >
          <Input
            id="srv-baseurl"
            bind:value={baseUrl}
            placeholder="https://panel.example.org"
            autocomplete="off"
          />
        </div>
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="srv-token">API token</label>
          <Input
            id="srv-token"
            bind:value={apiToken}
            type="password"
            placeholder={isEdit && init.apiTokenSet ? 'set (leave blank to keep)' : 'Bearer token'}
            autocomplete="off"
          />
          <p class="text-xs text-muted-foreground/80 mt-1">
            Stored server-side, never shown again.{isEdit
              ? ' Leave blank to keep the existing token.'
              : ''}
          </p>
        </div>
      {:else}
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="srv-url">
            Outline Manager API URL
          </label>
          <Input
            id="srv-url"
            bind:value={apiUrl}
            type="password"
            placeholder={isEdit ? init.apiUrlMasked : 'https://host:port/<secret>'}
            autocomplete="off"
          />
          <p class="text-xs text-muted-foreground/80 mt-1">
            Includes the secret path segment. The server's TLS cert must be valid (self-signed is
            rejected).{isEdit ? ' Leave blank to keep the existing URL.' : ''}
          </p>
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
              <label class="text-xs text-muted-foreground mb-1 block" for="srv-wsdomain"
                >WSS domain</label
              >
              <Input id="srv-wsdomain" bind:value={websocketDomain} placeholder="ws.example.org" />
            </div>
          {/if}
        </div>
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="srv-prom">
            Prometheus URL (optional)
          </label>
          <Input id="srv-prom" bind:value={prometheusUrl} placeholder="https://prom.example.org" />
        </div>
      {/if}

      <div>
        <button
          type="button"
          class="text-primary text-xs underline"
          onclick={runTest}
          disabled={testing}
        >
          {testing ? 'Testing…' : 'Test connection'}
        </button>
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

      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="srv-priority">Priority</label
          >
          <Input
            id="srv-priority"
            type="number"
            min={0}
            value={priority}
            oninput={(e) =>
              (priority = Math.max(0, parseInt((e.target as HTMLInputElement).value, 10) || 0))}
          />
        </div>
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="srv-max-keys"
            >Max keys (capacity cap)</label
          >
          <Input
            id="srv-max-keys"
            type="number"
            min={1}
            placeholder="No cap"
            value={maxKeysText}
            oninput={(e) => (maxKeysText = (e.target as HTMLInputElement).value)}
          />
          <p class="mt-1 text-[11px] text-muted-foreground">
            When reached, this instance is skipped at issuance (all instances full → members see a
            retryable "unavailable"). Blank = no cap.
          </p>
        </div>
      </div>
      <label class="flex items-center gap-3 text-sm">
        <Checkbox checked={isActive} onCheckedChange={(v) => (isActive = v === true)} />
        <span>Active (eligible for new key issuance)</span>
      </label>
    </div>

    <Dialog.Footer>
      <Button variant="ghost" onclick={() => (open = false)} disabled={save.isPending}
        >Cancel</Button
      >
      <Button onclick={() => save.mutate()} disabled={save.isPending || !name || !slug}>
        {save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Register instance'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
