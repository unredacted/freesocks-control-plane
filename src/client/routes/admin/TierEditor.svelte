<script lang="ts">
  import * as Dialog from '@client/components/ui/dialog';
  import * as Select from '@client/components/ui/select';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { ADMIN_BACKEND_LABELS } from '../../lib/backendLabels';
  import {
    TrafficStrategy,
    type TierAdmin,
    type TierUpsert,
  } from '../../../shared/contracts/admin';

  /**
   * Tier editor, both modes:
   *  - edit (tier prop set): the common knobs (name, backend, limits)
   *  - create (no tier): adds the identity/policy fields a new row needs
   *    (slug, description, strategy, priority, flags)
   * Uses Dialog.Root (focus trap + Escape) — the old hand-rolled fixed
   * overlay had neither. The parent owns the mutation; this stays
   * presentational.
   */
  interface Props {
    /** Absent → create mode. */
    tier?: TierAdmin | null;
    onCancel: () => void;
    onSave: (draft: TierUpsert) => void;
    busy?: boolean;
  }
  let { tier = null, onCancel, onSave, busy = false }: Props = $props();

  const isEdit = !!tier;
  let open = $state(true);

  const CREATE_DEFAULTS: TierUpsert = {
    slug: '',
    name: '',
    description: null,
    backend: 'remnawave',
    monthlyTrafficGb: 50,
    deviceLimit: 1,
    hwidLimit: 1,
    hwidEnabled: true,
    trafficStrategy: 'MONTH',
    remnawaveSquadUuid: null,
    isDefaultFree: false,
    isActive: true,
    priority: 100,
    expirationDaysAfterMembershipLapse: 90,
  };

  // Snapshot once at init (an open editor keeps its own copy; prop changes
  // mustn't blow it away mid-edit). IIFE breaks the compiler's
  // captures-initial-prop analysis, same as before the Dialog port.
  let draft = $state<TierUpsert>(
    ((t: TierAdmin | null) => {
      if (!t) return { ...CREATE_DEFAULTS };
      const { id: _id, createdAt: _c, updatedAt: _u, ...rest } = $state.snapshot(t);
      return { ...rest };
    })(tier),
  );

  // Disable Save when nothing changed (edit) / required identity missing (create).
  let isPristine = $derived(
    isEdit
      ? JSON.stringify(draft) ===
          JSON.stringify(
            ((t: TierAdmin) => {
              const { id: _id, createdAt: _c, updatedAt: _u, ...rest } = t;
              return rest;
            })(tier!),
          )
      : false,
  );
  let canSave = $derived(!isPristine && !!draft.name && (isEdit || !!draft.slug));

  function onOpenChange(next: boolean) {
    if (!next && busy) return;
    open = next;
    if (!next) onCancel();
  }
</script>

<Dialog.Root bind:open {onOpenChange}>
  <Dialog.Content class="sm:max-w-lg max-h-[90vh] overflow-y-auto">
    <Dialog.Header>
      <Dialog.Title>{isEdit ? `Edit tier · ${tier?.name}` : 'New tier'}</Dialog.Title>
      {#if !isEdit}
        <Dialog.Description>
          Defines an entitlement template (limits + backend). New sign-ups land on the default-free
          tier; paid tiers are granted via membership codes or the billing seam.
        </Dialog.Description>
      {/if}
    </Dialog.Header>

    <div class="space-y-3">
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="tier-name">Display name</label>
        <Input id="tier-name" bind:value={draft.name} placeholder="e.g. Member" />
      </div>
      {#if !isEdit}
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="tier-slug">Slug</label>
          <Input id="tier-slug" bind:value={draft.slug} placeholder="member" autocomplete="off" />
          <p class="text-xs text-muted-foreground/80 mt-1">
            Stable identifier used by webhooks and membership codes. Lowercase, no spaces; immutable
            in practice once referenced.
          </p>
        </div>
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="tier-desc">
            Description (optional)
          </label>
          <Input
            id="tier-desc"
            value={draft.description ?? ''}
            oninput={(e) =>
              (draft = {
                ...draft,
                description: (e.currentTarget as HTMLInputElement).value || null,
              })}
          />
        </div>
      {/if}
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="tier-backend">Backend</label>
        <Select.Root
          type="single"
          value={draft.backend}
          onValueChange={(v) => (draft = { ...draft, backend: v as 'remnawave' | 'outline' })}
        >
          <Select.Trigger id="tier-backend" class="w-48">
            {ADMIN_BACKEND_LABELS[draft.backend]}
          </Select.Trigger>
          <Select.Content>
            <!--
              Backend ids are the internal discriminator (`remnawave` /
              `outline`); the shared ADMIN_BACKEND_LABELS map names them the
              way end users see them (Xray), with the panel in parentheses.
            -->
            <Select.Item value="remnawave">{ADMIN_BACKEND_LABELS.remnawave}</Select.Item>
            <Select.Item value="outline">{ADMIN_BACKEND_LABELS.outline}</Select.Item>
          </Select.Content>
        </Select.Root>
        {#if isEdit && draft.backend !== tier?.backend}
          <p class="text-xs text-amber-600 dark:text-amber-400 mt-1 leading-snug">
            Changing backend does not migrate existing users on this tier. They keep their current
            backend until they regenerate or switch explicitly.
          </p>
        {/if}
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="tier-traffic">
          Monthly traffic (GB, 0 = unlimited)
        </label>
        <Input id="tier-traffic" type="number" min={0} bind:value={draft.monthlyTrafficGb} />
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="tier-devices">
          Device limit
        </label>
        <Input id="tier-devices" type="number" min={0} bind:value={draft.deviceLimit} />
      </div>
      {#if draft.backend === 'remnawave'}
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="tier-hwid">HWID limit</label>
          <Input id="tier-hwid" type="number" min={0} bind:value={draft.hwidLimit} />
          <p class="text-xs text-muted-foreground/80 mt-1 leading-snug">
            Xray-only. Number of distinct device fingerprints allowed per subscription.
          </p>
        </div>
      {/if}
      {#if !isEdit}
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="tier-strategy">
            Traffic reset strategy
          </label>
          <Select.Root
            type="single"
            value={draft.trafficStrategy}
            onValueChange={(v) =>
              (draft = { ...draft, trafficStrategy: v as TierUpsert['trafficStrategy'] })}
          >
            <Select.Trigger id="tier-strategy" class="w-48">{draft.trafficStrategy}</Select.Trigger>
            <Select.Content>
              {#each TrafficStrategy.options as s (s)}
                <Select.Item value={s}>{s}</Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
        </div>
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="tier-priority">
              Priority (lower = first)
            </label>
            <Input id="tier-priority" type="number" bind:value={draft.priority} />
          </div>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="tier-expiry">
              Expiry days after lapse
            </label>
            <Input
              id="tier-expiry"
              type="number"
              min={0}
              bind:value={draft.expirationDaysAfterMembershipLapse}
            />
          </div>
        </div>
        <label class="flex items-center gap-3 text-sm">
          <Checkbox
            checked={draft.isActive}
            onCheckedChange={(v) => (draft = { ...draft, isActive: v === true })}
          />
          <span>Active (eligible for issuance)</span>
        </label>
        <label class="flex items-center gap-3 text-sm">
          <Checkbox
            checked={draft.isDefaultFree}
            onCheckedChange={(v) => (draft = { ...draft, isDefaultFree: v === true })}
          />
          <span>Default free tier for its backend (new sign-ups land here)</span>
        </label>
      {/if}
    </div>

    <Dialog.Footer>
      <Button variant="ghost" onclick={onCancel} disabled={busy}>Cancel</Button>
      <Button onclick={() => onSave(draft)} disabled={!canSave || busy}>
        {busy ? 'Saving…' : isEdit ? (isPristine ? 'No changes' : 'Save') : 'Create tier'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
