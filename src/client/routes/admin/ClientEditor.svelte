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
    // Tri-state select value: '' untested, 'yes' works, 'no' IPv4-only.
    ipv6: c?.ipv6 === true ? 'yes' : c?.ipv6 === false ? 'no' : '',
    // The same tri-state for XHTTP: '' untested, 'yes' works, 'no' can't.
    xhttp: c?.xhttp === true ? 'yes' : c?.xhttp === false ? 'no' : '',
    // And for Hysteria 2, where only 'yes' is offered to members.
    hysteria2: c?.hysteria2 === true ? 'yes' : c?.hysteria2 === false ? 'no' : '',
    // '' = from the app's name.
    format: c?.format ?? '',
    description: c?.description ?? '',
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
  let ipv6 = $state(init.ipv6);
  let xhttp = $state(init.xhttp);
  let hysteria2 = $state(init.hysteria2);
  let format = $state<string>(init.format);
  let description = $state(init.description);
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
      ipv6: ipv6 === 'yes' ? true : ipv6 === 'no' ? false : null,
      xhttp: xhttp === 'yes' ? true : xhttp === 'no' ? false : null,
      hysteria2: hysteria2 === 'yes' ? true : hysteria2 === 'no' ? false : null,
      format: format || null,
      description: description.trim() || null,
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
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="cl-ipv6">IPv6 support</label>
        <select
          id="cl-ipv6"
          bind:value={ipv6}
          class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
        >
          <option value="">Untested (no badge)</option>
          <option value="yes">Works (verified)</option>
          <option value="no">IPv4 only</option>
        </select>
        <p class="text-xs text-muted-foreground/80 mt-1">
          Verified IPv6-through-tunnel behavior only. "IPv4 only" shows members a badge so v6 users
          pick a different app; leave untested apps blank rather than guessing.
        </p>
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="cl-xhttp">XHTTP support</label>
        <select
          id="cl-xhttp"
          bind:value={xhttp}
          class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
        >
          <option value="">Untested (still shown)</option>
          <option value="yes">Works</option>
          <option value="no">Can't use it (hidden on XHTTP)</option>
        </select>
        <p class="text-xs text-muted-foreground/80 mt-1">
          XHTTP under REALITY as this app receives it from FCP, not what its core could do: an app
          served sing-box bodies can't use it. Members on an XHTTP connection mode don't see apps
          marked "Can't use it".
        </p>
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="cl-hysteria2"
          >Hysteria support</label
        >
        <select
          id="cl-hysteria2"
          bind:value={hysteria2}
          class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
        >
          <option value="">Untested (hidden on Hysteria)</option>
          <option value="yes">Works, pin checked (recorded)</option>
          <option value="no">Can't use it, or ignores the pin</option>
        </select>
        <p class="text-xs text-muted-foreground/80 mt-1">
          Members on a Hysteria connection mode see only apps marked "Works". Set it only with a
          recorded test of this app's version: it imported the raw config, connected over UDP, and
          refused to connect once one character of the entry's pin was changed. An app that ignores
          the pin would send the member's password to any server.
        </p>
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="cl-format"
          >Subscription format</label
        >
        <select
          id="cl-format"
          bind:value={format}
          class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
        >
          <option value="">From the app's name</option>
          <option value="links">Share-link list (base64)</option>
          <option value="clash">Clash / Mihomo YAML</option>
          <option value="singbox">sing-box JSON</option>
        </select>
        <p class="text-xs text-muted-foreground/80 mt-1">
          What the app imports, so members get the mirror link in that format. Set it when the name
          doesn't say (a renamed or translated label); left blank, it follows the name.
        </p>
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="cl-description">
          Description
        </label>
        <textarea
          id="cl-description"
          bind:value={description}
          rows={2}
          maxlength={280}
          placeholder="Why choose this app? Shown to members under the app name."
          class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"></textarea>
        <p class="text-xs text-muted-foreground/80 mt-1">
          Shown verbatim in every language. Leave blank to use the built-in translated description
          for known default apps.
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
