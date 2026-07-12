<script lang="ts">
  import type { z } from 'zod';
  import * as Dialog from '@client/components/ui/dialog';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { MirrorProviderAdmin } from '../../../shared/contracts/admin';
  import { createMutation } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { z as zod } from 'zod';

  /**
   * Modal editor for one S3 mirror provider. The secretAccessKey is write-only:
   * blanked on open, only re-submitted if the admin retypes it (so editing other
   * fields never wipes the stored credential - same idiom as BackendServerEditor).
   */
  interface Props {
    provider?: z.infer<typeof MirrorProviderAdmin>;
    onClose: () => void;
    onSaved: () => void;
  }
  let { provider, onClose, onSaved }: Props = $props();

  let open = $state(true);
  const isEdit = !!provider;

  // One-time snapshot of the prop into plain locals (the IIFE breaks the
  // compiler's "captures initial value of prop" analysis, mirroring the other
  // editors). The secret is never round-tripped, so it always starts blank.
  const init = ((p: Props['provider']) => ({
    name: p?.name ?? '',
    endpoint: p?.endpoint ?? '',
    bucket: p?.bucket ?? '',
    publicUrl: p?.publicUrl ?? '',
    region: p?.region ?? 'us-east-1',
    accessKeyId: p?.accessKeyId ?? '',
    secretAccessKeySet: p?.secretAccessKeySet ?? false,
    countryCodes: (p?.countryCodes ?? []).join(' '),
    isActive: p?.isActive ?? true,
    priority: p?.priority ?? 0,
  }))(provider);

  let name = $state(init.name);
  let endpoint = $state(init.endpoint);
  let bucket = $state(init.bucket);
  let publicUrl = $state(init.publicUrl);
  let region = $state(init.region);
  let accessKeyId = $state(init.accessKeyId);
  let secretAccessKey = $state('');
  // Preferred country codes as a free-text list (space/comma separated); parsed
  // to an array on save. Empty = global fallback.
  let countryCodes = $state(init.countryCodes);
  let isActive = $state(init.isActive);
  let priority = $state(init.priority);

  let testing = $state(false);
  let testResult = $state<{ ok: boolean; message: string } | null>(null);

  // A green "Reachable" verdict must describe the CURRENT inputs: editing any
  // connection-relevant field invalidates the last test result.
  $effect(() => {
    void endpoint;
    void bucket;
    void region;
    void accessKeyId;
    void secretAccessKey;
    testResult = null;
  });

  async function runTest() {
    if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) {
      testResult = {
        ok: false,
        message: 'Enter the endpoint, bucket, access key ID and secret to test.',
      };
      return;
    }
    testing = true;
    testResult = null;
    try {
      const TestResp = zod.union([
        zod.object({ ok: zod.literal(true) }),
        zod.object({ ok: zod.literal(false), error: zod.string() }),
      ]);
      const result = await apiClient.post(
        '/api/v1/admin/mirror-providers/test-connection',
        { endpoint, bucket, region, accessKeyId, secretAccessKey },
        TestResp,
      );
      testResult = result.ok
        ? { ok: true, message: 'Reachable - a health object was written to the bucket.' }
        : { ok: false, message: result.error };
    } catch (err) {
      testResult = { ok: false, message: apiErrorMessage(err) };
    } finally {
      testing = false;
    }
  }

  function buildPayload(): Record<string, unknown> {
    const body: Record<string, unknown> = {
      name,
      endpoint,
      bucket,
      publicUrl,
      region,
      // Split on commas/whitespace; the server normalizes (uppercase, 2-letter, dedupe).
      countryCodes: countryCodes.split(/[\s,]+/).filter(Boolean),
      isActive,
      priority,
    };
    if (accessKeyId) body.accessKeyId = accessKeyId;
    if (secretAccessKey) body.secretAccessKey = secretAccessKey;
    return body;
  }

  const save = createMutation(() => ({
    mutationFn: async () => {
      const payload = buildPayload();
      if (isEdit) {
        return apiClient.patch(
          `/api/v1/admin/mirror-providers/${provider!.id}`,
          payload,
          MirrorProviderAdmin,
        );
      }
      if (!accessKeyId || !secretAccessKey) {
        throw new Error('A new provider needs an access key ID and a secret access key');
      }
      return apiClient.post('/api/v1/admin/mirror-providers', payload, MirrorProviderAdmin);
    },
    onSuccess: () => {
      open = false;
      onSaved();
      toast.success(isEdit ? 'Provider updated' : 'Provider added');
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
        {isEdit ? `Edit ${provider?.name}` : 'Add a mirror provider'}
      </Dialog.Title>
      <Dialog.Description>
        An S3-compatible bucket the subscription content is copied to. The secret access key is
        stored server-side and never shown again.
      </Dialog.Description>
    </Dialog.Header>

    <div class="space-y-4">
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="mp-name">Name</label>
        <Input id="mp-name" bind:value={name} placeholder="e.g. backblaze-eu" autocomplete="off" />
        <p class="text-xs text-muted-foreground/80 mt-1">
          Stable identifier used to match uploaded mirror objects. Avoid renaming one with live
          mirrors.
        </p>
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="mp-endpoint">
          S3 endpoint
        </label>
        <Input
          id="mp-endpoint"
          bind:value={endpoint}
          placeholder="https://s3.eu-central.example.com"
          autocomplete="off"
        />
      </div>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="mp-bucket">Bucket</label>
          <Input id="mp-bucket" bind:value={bucket} placeholder="subs" autocomplete="off" />
        </div>
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="mp-region">Region</label>
          <Input id="mp-region" bind:value={region} placeholder="us-east-1" autocomplete="off" />
        </div>
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="mp-public">Public URL</label>
        <Input
          id="mp-public"
          bind:value={publicUrl}
          placeholder="https://cdn.example.com"
          autocomplete="off"
        />
        <p class="text-xs text-muted-foreground/80 mt-1">
          The base URL a client fetches the mirrored object from (the object path is appended).
        </p>
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="mp-akid">Access key ID</label>
        <Input id="mp-akid" bind:value={accessKeyId} placeholder="AKIA…" autocomplete="off" />
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="mp-secret">
          Secret access key
        </label>
        <Input
          id="mp-secret"
          bind:value={secretAccessKey}
          type="password"
          placeholder={isEdit && init.secretAccessKeySet ? 'set (leave blank to keep)' : 'secret'}
          autocomplete="off"
        />
        <p class="text-xs text-muted-foreground/80 mt-1">
          Stored server-side, never shown again.{isEdit
            ? ' Leave blank to keep the existing secret.'
            : ''}
        </p>
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="mp-countries">
          Preferred countries (optional)
        </label>
        <Input
          id="mp-countries"
          bind:value={countryCodes}
          placeholder="IR RU CN"
          autocomplete="off"
        />
        <p class="text-xs text-muted-foreground/80 mt-1">
          ISO 2-letter codes this host is preferred for (space/comma separated). Leave blank for a
          global fallback usable from any country.
        </p>
      </div>

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
          <label class="text-xs text-muted-foreground mb-1 block" for="mp-priority">Priority</label>
          <Input
            id="mp-priority"
            type="number"
            min={0}
            value={priority}
            oninput={(e) =>
              (priority = Math.max(0, parseInt((e.target as HTMLInputElement).value, 10) || 0))}
          />
        </div>
        <label class="flex items-center gap-3 text-sm pt-5">
          <Checkbox checked={isActive} onCheckedChange={(v) => (isActive = v === true)} />
          <span>Active (mirror new keys here)</span>
        </label>
      </div>
    </div>

    <Dialog.Footer>
      <Button variant="ghost" onclick={() => (open = false)} disabled={save.isPending}
        >Cancel</Button
      >
      <Button
        onclick={() => save.mutate()}
        disabled={save.isPending || !name || !endpoint || !bucket || !publicUrl}
      >
        {save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Add provider'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
