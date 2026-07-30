<script lang="ts">
  import * as Dialog from '@client/components/ui/dialog';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import type {
    AdminConnectionMode,
    AdminConnectionModeFamily,
  } from '../../../shared/contracts/connectionModes';
  import { ADMIN_BACKEND_LABELS } from '../../lib/backendLabels';
  import { BACKEND_IDS } from '../../../shared/contracts/backends';
  import { createMutation } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { z } from 'zod';

  /**
   * Modal editor for one connection MODE (a transport leaf). The slug is the
   * immutable wire id (it is what member rows store) — set once at create. A
   * label is required for admin-created modes; built-ins may leave it blank to
   * keep the translated copy. Placement pools are NOT edited here (they are
   * backend-specific and write-only — Admin → Remnawave).
   */
  interface Props {
    mode?: AdminConnectionMode;
    families: AdminConnectionModeFamily[];
    onClose: () => void;
    onSaved: () => void;
  }
  let { mode, families, onClose, onSaved }: Props = $props();

  let open = $state(true);
  const isEdit = !!mode;

  const init = ((m: Props['mode']) => ({
    slug: m?.id ?? '',
    label: m?.label ?? '',
    description: m?.description ?? '',
    family: m?.family ?? families[0]?.id ?? '',
    deliveryStyle: m?.deliveryStyle ?? 'url',
    enabled: m?.ownEnabled ?? true,
    isFamilyDefault: m?.isFamilyDefault ?? false,
    isCensorshipRecommended: m?.isCensorshipRecommended ?? false,
    backends: new Set<string>(m?.backends ?? ['remnawave']),
    order: m?.order ?? 0,
  }))(mode);

  let slug = $state(init.slug);
  let label = $state(init.label);
  let description = $state(init.description);
  let family = $state(init.family);
  let deliveryStyle = $state<'url' | 'rawConfig'>(init.deliveryStyle);
  let enabled = $state(init.enabled);
  let isFamilyDefault = $state(init.isFamilyDefault);
  let isCensorshipRecommended = $state(init.isCensorshipRecommended);
  let backends = $state(init.backends);
  let order = $state(init.order);

  function toggleBackend(id: string, on: boolean) {
    const next = new Set(backends);
    if (on) next.add(id);
    else next.delete(id);
    backends = next;
  }

  const save = createMutation(() => ({
    mutationFn: async () => {
      const payload: Record<string, unknown> = {
        label: label.trim() || null,
        description: description.trim() || null,
        family,
        deliveryStyle,
        enabled,
        isFamilyDefault,
        isCensorshipRecommended,
        backends: [...backends],
        order,
      };
      if (isEdit) {
        return apiClient.patch(
          `/api/v1/admin/connection-modes/${encodeURIComponent(mode!.id)}`,
          payload,
          z.object({ ok: z.boolean() }),
        );
      }
      return apiClient.post(
        '/api/v1/admin/connection-modes',
        { ...payload, slug: slug.trim(), label: label.trim() },
        z.object({ id: z.string(), slug: z.string() }),
      );
    },
    onSuccess: () => {
      open = false;
      onSaved();
      toast.success(isEdit ? 'Mode updated' : 'Mode created');
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
      <Dialog.Title>{isEdit ? `Edit mode: ${mode?.id}` : 'Add a connection mode'}</Dialog.Title>
      <Dialog.Description>
        A transport leaf inside a family. New modes ship unselectable until they are enabled AND (on
        placement-capable backends) a placement pool is bound in Admin → Remnawave.
      </Dialog.Description>
    </Dialog.Header>

    <div class="space-y-4">
      {#if !isEdit}
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="cm-slug">Slug</label>
          <Input id="cm-slug" bind:value={slug} placeholder="e.g. stealth-x" autocomplete="off" />
          <p class="text-xs text-muted-foreground/80 mt-1">
            The permanent id members' accounts store (lowercase letters, digits, hyphens). It cannot
            be changed later — renaming means create + delete.
          </p>
        </div>
      {/if}
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="cm-label">Label</label>
        <Input id="cm-label" bind:value={label} placeholder="e.g. Stealth X" maxlength={64} />
        {#if mode?.builtIn}
          <p class="text-xs text-muted-foreground/80 mt-1">
            Built-in mode: leave blank to use the translated name in every language.
          </p>
        {:else}
          <p class="text-xs text-muted-foreground/80 mt-1">
            Required. Shown verbatim in every language.
          </p>
        {/if}
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="cm-desc">Description</label>
        <textarea
          id="cm-desc"
          bind:value={description}
          rows={2}
          maxlength={500}
          placeholder="Shown under the transport in the member picker."
          class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
        ></textarea>
      </div>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="cm-family">Family</label>
          <select
            id="cm-family"
            bind:value={family}
            class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
          >
            {#each families as f (f.id)}
              <option value={f.id}>{f.label ?? f.id}</option>
            {/each}
          </select>
        </div>
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="cm-delivery">
            Delivery style
          </label>
          <select
            id="cm-delivery"
            bind:value={deliveryStyle}
            class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
          >
            <option value="url">Subscription link (auto-updating)</option>
            <option value="rawConfig">Raw config (manual copy)</option>
          </select>
          <p class="text-xs text-muted-foreground/80 mt-1">
            Raw config hides the CDN-fetched link and suppresses public mirrors (the privacy
            posture).
          </p>
        </div>
      </div>
      <div>
        <span class="text-xs text-muted-foreground mb-1 block">Backends</span>
        <div class="flex flex-wrap gap-3">
          {#each BACKEND_IDS as b (b)}
            <label class="flex items-center gap-2 text-sm">
              <Checkbox
                checked={backends.has(b)}
                onCheckedChange={(v) => toggleBackend(b, v === true)}
              />
              <span>{ADMIN_BACKEND_LABELS[b]}</span>
            </label>
          {/each}
        </div>
        <p class="text-xs text-muted-foreground/80 mt-1">
          Which backend types offer this mode. At least one is required.
        </p>
      </div>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="cm-order">Order</label>
          <Input
            id="cm-order"
            type="number"
            value={order}
            oninput={(e) => (order = parseInt((e.target as HTMLInputElement).value, 10) || 0)}
          />
        </div>
        <div class="flex flex-col gap-2 pt-5">
          <label class="flex items-center gap-3 text-sm">
            <Checkbox checked={enabled} onCheckedChange={(v) => (enabled = v === true)} />
            <span>Enabled</span>
          </label>
        </div>
      </div>
      <label class="flex items-center gap-3 text-sm">
        <Checkbox
          checked={isFamilyDefault}
          onCheckedChange={(v) => (isFamilyDefault = v === true)}
        />
        <span>Family default (what clicking the parent card selects)</span>
      </label>
      <label class="flex items-center gap-3 text-sm">
        <Checkbox
          checked={isCensorshipRecommended}
          onCheckedChange={(v) => (isCensorshipRecommended = v === true)}
        />
        <span>Censorship recommendation</span>
      </label>
      <p class="text-xs text-muted-foreground/80 -mt-2">
        Suggested to members in the admin-listed censored countries (only while enabled and
        available on their backend).
      </p>
      {#if isEdit && mode && mode.ownEnabled && !enabled}
        <p class="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs">
          Members currently on this mode keep their key and see it as "Currently unavailable" until
          they switch.
        </p>
      {/if}
    </div>

    <Dialog.Footer>
      <Button variant="ghost" onclick={() => (open = false)} disabled={save.isPending}>
        Cancel
      </Button>
      <Button
        onclick={() => save.mutate()}
        disabled={save.isPending ||
          backends.size === 0 ||
          !family ||
          (!isEdit && (!slug.trim() || !label.trim())) ||
          (isEdit && !mode?.builtIn && !label.trim())}
      >
        {save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Create mode'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
