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
   * Tier editor. Edit mode exposes EVERY field except `slug` (the immutable
   * identity referenced by billing.tierSlug / membership codes / webhooks);
   * create mode adds the slug. `updateTier` accepts every field, so an admin
   * can change a tier's description, limits, device-limit enforcement,
   * strategy, priority, and flags after creation — keeping the public
   * comparison cards (which render name/description/limits) DB-driven.
   * Uses Dialog.Root (focus trap + Escape) — the old hand-rolled fixed
   * overlay had neither. The parent owns the mutation; this stays
   * presentational.
   */
  interface Props {
    /** Absent → create mode. */
    tier?: TierAdmin | null;
    /** Create mode only: pre-fill the form (e.g. duplicating an existing tier). */
    initial?: TierUpsert | null;
    /** All tiers, for the cross-backend peer selector (D-1). */
    allTiers?: TierAdmin[];
    onCancel: () => void;
    onSave: (draft: TierUpsert) => void;
    busy?: boolean;
  }
  let {
    tier = null,
    initial = null,
    allTiers = [],
    onCancel,
    onSave,
    busy = false,
  }: Props = $props();

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
    peerTierId: null,
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
      if (t) {
        const { id: _id, createdAt: _c, updatedAt: _u, ...rest } = $state.snapshot(t);
        return { ...rest };
      }
      // Create mode: pre-filled (duplicate) or blank defaults.
      return initial ? { ...initial } : { ...CREATE_DEFAULTS };
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

  // Cross-backend peer selector (D-1): an admin links a PAID tier to its
  // equivalent on the OTHER backend so members on it can switch backends. Free
  // tiers auto-peer via the per-backend default-free row, so the selector is
  // hidden for them. Candidates are active tiers on the other backend (not self).
  const NONE = '__none__';
  let peerCandidates = $derived(
    allTiers.filter((t) => t.backend !== draft.backend && t.id !== tier?.id && t.isActive),
  );
  let peerLabel = $derived(
    draft.peerTierId
      ? (allTiers.find((t) => t.id === draft.peerTierId)?.name ?? 'Linked tier')
      : 'None',
  );

  function onOpenChange(next: boolean) {
    if (!next && busy) return;
    open = next;
    if (!next) onCancel();
  }
</script>

<Dialog.Root bind:open {onOpenChange}>
  <Dialog.Content class="sm:max-w-lg max-h-[90vh] overflow-y-auto">
    <Dialog.Header>
      <Dialog.Title>
        {isEdit ? `Edit tier · ${tier?.name}` : initial ? 'Duplicate tier' : 'New tier'}
      </Dialog.Title>
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
      {/if}
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
        <p class="text-xs text-muted-foreground/80 mt-1 leading-snug">
          Shown on the public tier-comparison cards.
        </p>
      </div>
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
      {#if !draft.isDefaultFree}
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="tier-peer">
            Cross-backend peer (optional)
          </label>
          <Select.Root
            type="single"
            value={draft.peerTierId ?? NONE}
            onValueChange={(v) => (draft = { ...draft, peerTierId: v === NONE ? null : v })}
          >
            <Select.Trigger id="tier-peer" class="w-full">{peerLabel}</Select.Trigger>
            <Select.Content>
              <Select.Item value={NONE}>None</Select.Item>
              {#each peerCandidates as t (t.id)}
                <Select.Item value={t.id}>
                  {t.name} · {ADMIN_BACKEND_LABELS[t.backend]}
                </Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
          <p class="text-xs text-muted-foreground/80 mt-1 leading-snug">
            The equivalent tier on the other backend, so members on this tier can switch backends
            (Account → switch server type). The link resolves both ways, so setting it on either
            tier is enough. Free tiers link automatically.
          </p>
        </div>
      {/if}
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
        <label class="flex items-center gap-3 text-sm">
          <Checkbox
            checked={draft.hwidEnabled}
            onCheckedChange={(v) => (draft = { ...draft, hwidEnabled: v === true })}
          />
          <span>Enforce device limit (HWID) — off = unlimited devices</span>
        </label>
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="tier-hwid">HWID limit</label>
          <Input id="tier-hwid" type="number" min={0} bind:value={draft.hwidLimit} />
          <p class="text-xs text-muted-foreground/80 mt-1 leading-snug">
            Xray-only. Number of distinct device fingerprints allowed per subscription. Only takes
            effect when the global device-limit toggle is on (Settings → Device limits) AND the
            Remnawave panel has HWID_DEVICE_LIMIT_ENABLED=true.
          </p>
        </div>
      {/if}
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
    </div>

    <Dialog.Footer>
      <Button variant="ghost" onclick={onCancel} disabled={busy}>Cancel</Button>
      <Button onclick={() => onSave(draft)} disabled={!canSave || busy}>
        {busy ? 'Saving…' : isEdit ? (isPristine ? 'No changes' : 'Save') : 'Create tier'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
