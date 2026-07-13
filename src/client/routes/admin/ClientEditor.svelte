<script lang="ts">
  import type { z } from 'zod';
  import * as Dialog from '@client/components/ui/dialog';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { ClientAdmin } from '../../../shared/contracts/admin';
  import { SCHEME_IDS } from '../../lib/appLinks';
  import { createMutation } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  /**
   * Modal editor for one recommended client app (the DB-driven catalog). No
   * secrets. `schemeId` picks the one-tap import deep-link builder (SCHEME_IDS,
   * code-defined) - "None" = the app only supports manual / QR import.
   */
  interface Props {
    client?: z.infer<typeof ClientAdmin>;
    onClose: () => void;
    onSaved: () => void;
  }
  let { client, onClose, onSaved }: Props = $props();

  let open = $state(true);
  const isEdit = !!client;
  const ALL_PLATFORMS = ['android', 'ios', 'windows', 'desktop'] as const;
  const ALL_BACKENDS = ['remnawave', 'outline'] as const;

  // One-time snapshot of the prop into plain locals (IIFE breaks the compiler's
  // "captures initial prop" analysis, mirroring the other editors).
  const init = ((c: Props['client']) => ({
    name: c?.name ?? '',
    platforms: new Set<string>(c?.platforms ?? []),
    backends: new Set<string>(c?.backends ?? ['remnawave']),
    homepageUrl: c?.homepageUrl ?? '',
    schemeId: c?.schemeId ?? '',
    hwid: c?.hwid ?? false,
    openSource: c?.openSource ?? false,
    license: c?.license ?? '',
    sourceUrl: c?.sourceUrl ?? '',
    easeOfUse: c?.easeOfUse ?? '',
    enabled: c?.enabled ?? true,
    priority: c?.priority ?? 0,
  }))(client);

  let name = $state(init.name);
  let platforms = $state(init.platforms);
  let backends = $state(init.backends);
  let homepageUrl = $state(init.homepageUrl);
  let schemeId = $state(init.schemeId);
  let hwid = $state(init.hwid);
  let openSource = $state(init.openSource);
  let license = $state(init.license);
  let sourceUrl = $state(init.sourceUrl);
  let easeOfUse = $state(init.easeOfUse);
  let enabled = $state(init.enabled);
  let priority = $state(init.priority);

  function toggle(set: Set<string>, key: string, on: boolean): Set<string> {
    const next = new Set(set);
    if (on) next.add(key);
    else next.delete(key);
    return next;
  }

  function buildPayload(): Record<string, unknown> {
    return {
      name,
      platforms: [...platforms],
      backends: [...backends],
      homepageUrl,
      schemeId: schemeId || null,
      hwid,
      openSource,
      license: license || null,
      sourceUrl: sourceUrl || null,
      easeOfUse: easeOfUse || null,
      enabled,
      priority,
    };
  }

  const save = createMutation(() => ({
    mutationFn: async () => {
      const payload = buildPayload();
      if (isEdit) {
        return apiClient.patch(`/api/v1/admin/clients/${client!.id}`, payload, ClientAdmin);
      }
      return apiClient.post('/api/v1/admin/clients', payload, ClientAdmin);
    },
    onSuccess: () => {
      open = false;
      onSaved();
      toast.success(isEdit ? 'Client updated' : 'Client added');
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
      <Dialog.Title>{isEdit ? `Edit ${client?.name}` : 'Add a client app'}</Dialog.Title>
      <Dialog.Description>
        A recommended VPN app for the member "set up your app" section. Leave the import scheme
        "None" for apps that only support manual / QR import.
      </Dialog.Description>
    </Dialog.Header>

    <div class="space-y-4">
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="cl-name">Name</label>
        <Input id="cl-name" bind:value={name} placeholder="e.g. Hiddify" autocomplete="off" />
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="cl-home">
          Install / homepage URL
        </label>
        <Input id="cl-home" bind:value={homepageUrl} placeholder="https://…" autocomplete="off" />
      </div>
      <div>
        <span class="text-xs text-muted-foreground mb-1 block">Platforms</span>
        <div class="flex flex-wrap gap-3">
          {#each ALL_PLATFORMS as p (p)}
            <label class="flex items-center gap-2 text-sm">
              <Checkbox
                checked={platforms.has(p)}
                onCheckedChange={(v) => (platforms = toggle(platforms, p, v === true))}
              />
              <span class="capitalize">{p}</span>
            </label>
          {/each}
        </div>
      </div>
      <div>
        <span class="text-xs text-muted-foreground mb-1 block">Backends</span>
        <div class="flex flex-wrap gap-3">
          {#each ALL_BACKENDS as b (b)}
            <label class="flex items-center gap-2 text-sm">
              <Checkbox
                checked={backends.has(b)}
                onCheckedChange={(v) => (backends = toggle(backends, b, v === true))}
              />
              <span class="capitalize">{b}</span>
            </label>
          {/each}
        </div>
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="cl-scheme">Import scheme</label
        >
        <select
          id="cl-scheme"
          bind:value={schemeId}
          class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
        >
          <option value="">None (manual / QR only)</option>
          {#each SCHEME_IDS as s (s)}<option value={s}>{s}</option>{/each}
        </select>
        <p class="text-xs text-muted-foreground/80 mt-1">
          The one-tap import deep-link builder. Only code-defined schemes are listed; a new scheme
          needs a small code add.
        </p>
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="cl-ease">Ease of use</label>
        <select
          id="cl-ease"
          bind:value={easeOfUse}
          class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
        >
          <option value="">Unrated (treated as moderate)</option>
          <option value="easy">Easy</option>
          <option value="moderate">Moderate</option>
          <option value="advanced">Advanced</option>
        </select>
        <p class="text-xs text-muted-foreground/80 mt-1">
          Within each open-source group, easier apps rank first in the member list. "Easy" and
          "Advanced" also show a badge.
        </p>
      </div>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="cl-priority">Priority</label>
          <Input
            id="cl-priority"
            type="number"
            min={0}
            value={priority}
            oninput={(e) =>
              (priority = Math.max(0, parseInt((e.target as HTMLInputElement).value, 10) || 0))}
          />
        </div>
        <div class="flex flex-col gap-2 pt-5">
          <label class="flex items-center gap-3 text-sm">
            <Checkbox checked={hwid} onCheckedChange={(v) => (hwid = v === true)} />
            <span>Supports device limit (HWID)</span>
          </label>
          <label class="flex items-center gap-3 text-sm">
            <Checkbox checked={enabled} onCheckedChange={(v) => (enabled = v === true)} />
            <span>Enabled (shown to members)</span>
          </label>
        </div>
      </div>
      <div>
        <label class="flex items-center gap-3 text-sm">
          <Checkbox checked={openSource} onCheckedChange={(v) => (openSource = v === true)} />
          <span>Open source</span>
        </label>
        <p class="text-xs text-muted-foreground/80 mt-1">
          Open-source apps get an "Open source" badge + a link to their source, and rank ahead of
          proprietary apps in the member list.
        </p>
      </div>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="cl-license">License</label>
          <Input
            id="cl-license"
            bind:value={license}
            placeholder="e.g. GPL-3.0 or Proprietary"
            autocomplete="off"
          />
        </div>
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="cl-source">Source URL</label>
          <Input
            id="cl-source"
            bind:value={sourceUrl}
            placeholder="https://github.com/…"
            autocomplete="off"
          />
        </div>
      </div>
    </div>

    <Dialog.Footer>
      <Button variant="ghost" onclick={() => (open = false)} disabled={save.isPending}
        >Cancel</Button
      >
      <Button onclick={() => save.mutate()} disabled={save.isPending || !name || !homepageUrl}>
        {save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Add client'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
