<script lang="ts">
  import * as Dialog from '@client/components/ui/dialog';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import type { AdminConnectionModeFamily } from '../../../shared/contracts/connectionModes';
  import { MODE_ICON_IDS } from '../../lib/connectionModeIconIds';
  import { resolveModeIcon } from '../../lib/connectionModeIcons';
  import { createMutation } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { z } from 'zod';

  /**
   * Modal editor for one connection-mode FAMILY (the parent card in the member
   * picker). The slug is the immutable wire id — set once at create. A label is
   * required for admin-created families (new ids have no built-in translation);
   * built-ins may leave it blank to keep the translated copy.
   */
  interface Props {
    family?: AdminConnectionModeFamily;
    onClose: () => void;
    onSaved: () => void;
  }
  let { family, onClose, onSaved }: Props = $props();

  let open = $state(true);
  const isEdit = !!family;

  const init = ((f: Props['family']) => ({
    slug: f?.id ?? '',
    label: f?.label ?? '',
    description: f?.description ?? '',
    audience: f?.audience ?? '',
    iconId: f?.iconId ?? 'zap',
    enabled: f?.enabled ?? true,
    order: f?.order ?? 0,
  }))(family);

  let slug = $state(init.slug);
  let label = $state(init.label);
  let description = $state(init.description);
  let audience = $state(init.audience);
  let iconId = $state(init.iconId);
  let enabled = $state(init.enabled);
  let order = $state(init.order);

  let PreviewIcon = $derived(resolveModeIcon(iconId));

  const save = createMutation(() => ({
    mutationFn: async () => {
      const payload: Record<string, unknown> = {
        label: label.trim() || null,
        description: description.trim() || null,
        audience: audience.trim() || null,
        iconId,
        enabled,
        order,
      };
      if (isEdit) {
        return apiClient.patch(
          `/api/v1/admin/connection-mode-families/${encodeURIComponent(family!.id)}`,
          payload,
          z.object({ ok: z.boolean() }),
        );
      }
      return apiClient.post(
        '/api/v1/admin/connection-mode-families',
        { ...payload, slug: slug.trim(), label: label.trim() },
        z.object({ id: z.string(), slug: z.string() }),
      );
    },
    onSuccess: () => {
      open = false;
      onSaved();
      toast.success(isEdit ? 'Family updated' : 'Family created');
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
      <Dialog.Title>{isEdit ? `Edit family: ${family?.id}` : 'Add a mode family'}</Dialog.Title>
      <Dialog.Description>
        The parent card members pick first ("Freedom Mode", "Privacy Mode"). Modes inside it are the
        transports.
      </Dialog.Description>
    </Dialog.Header>

    <div class="space-y-4">
      {#if !isEdit}
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="fam-slug">Slug</label>
          <Input id="fam-slug" bind:value={slug} placeholder="e.g. stealth" autocomplete="off" />
          <p class="text-xs text-muted-foreground/80 mt-1">
            The permanent id (lowercase letters, digits, hyphens). It cannot be changed later.
          </p>
        </div>
      {/if}
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="fam-label">Label</label>
        <Input id="fam-label" bind:value={label} placeholder="e.g. Stealth Mode" maxlength={64} />
        {#if family?.builtIn}
          <p class="text-xs text-muted-foreground/80 mt-1">
            Built-in family: leave blank to use the translated name in every language. A value here
            is shown verbatim to all locales.
          </p>
        {:else}
          <p class="text-xs text-muted-foreground/80 mt-1">
            Required. Shown verbatim in every language.
          </p>
        {/if}
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="fam-desc">Description</label>
        <textarea
          id="fam-desc"
          bind:value={description}
          rows={2}
          maxlength={500}
          placeholder="What this family is for, shown on the member card."
          class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
        ></textarea>
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="fam-audience">
          Audience chip
        </label>
        <Input
          id="fam-audience"
          bind:value={audience}
          placeholder="e.g. For heavily censored networks"
          maxlength={80}
        />
        <p class="text-xs text-muted-foreground/80 mt-1">
          The small "who is this for" chip on the picker card. Optional; built-ins fall back to
          their translated chip.
        </p>
      </div>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="fam-icon">Icon</label>
          <div class="flex items-center gap-2">
            <select
              id="fam-icon"
              bind:value={iconId}
              class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            >
              {#each MODE_ICON_IDS as id (id)}<option value={id}>{id}</option>{/each}
            </select>
            <span class="rounded-md border border-border p-2">
              <PreviewIcon class="size-4 text-primary" />
            </span>
          </div>
        </div>
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="fam-order">Order</label>
          <Input
            id="fam-order"
            type="number"
            value={order}
            oninput={(e) => (order = parseInt((e.target as HTMLInputElement).value, 10) || 0)}
          />
        </div>
      </div>
      <label class="flex items-center gap-3 text-sm">
        <Checkbox checked={enabled} onCheckedChange={(v) => (enabled = v === true)} />
        <span>Enabled (a disabled family hides ALL of its modes)</span>
      </label>
    </div>

    <Dialog.Footer>
      <Button variant="ghost" onclick={() => (open = false)} disabled={save.isPending}>
        Cancel
      </Button>
      <Button
        onclick={() => save.mutate()}
        disabled={save.isPending ||
          (!isEdit && (!slug.trim() || !label.trim())) ||
          (isEdit && !family?.builtIn && !label.trim())}
      >
        {save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Create family'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
