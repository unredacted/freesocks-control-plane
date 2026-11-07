<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import ChevronUp from '@lucide/svelte/icons/chevron-up';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import Trash2 from '@lucide/svelte/icons/trash-2';
  import Plus from '@lucide/svelte/icons/plus';
  import {
    MAX_TIER_FEATURES,
    MAX_TIER_FEATURE_LABEL,
    PRESET_ICONS,
    TIER_FEATURE_ICON_IDS,
    TIER_FEATURE_PRESETS,
    type TierFeatureWire,
    type TierFeaturePreset,
  } from '../../../shared/contracts/tierFeatures';
  import { resolveTierFeatureIcon } from '../../lib/tierFeatureIcons';
  import { PRESET_ADMIN_NAMES } from '../../lib/tierFeatureCopy';

  /**
   * Card features of one tier (Admin → Tiers → edit): the ordered lines shown
   * under the tier's limits on every plan card. A built-in line is translated
   * for members; typed text replaces it (verbatim, every language). Icons come
   * from a fixed list. `isDefault` = the tier shows the built-in defaults (no
   * list saved); `onReset` asks the parent to save "back to defaults".
   */
  interface Props {
    features: TierFeatureWire[];
    isDefault: boolean;
    onChange: (next: TierFeatureWire[]) => void;
    onReset: () => void;
  }
  let { features, isDefault, onChange, onReset }: Props = $props();

  let full = $derived(features.length >= MAX_TIER_FEATURES);
  let addPreset = $state('');

  function set(i: number, patch: Partial<TierFeatureWire>) {
    onChange(features.map((f, j) => (j === i ? { ...f, ...patch } : f)));
  }
  function move(i: number, delta: -1 | 1) {
    const j = i + delta;
    if (j < 0 || j >= features.length) return;
    const next = features.slice();
    [next[i], next[j]] = [next[j]!, next[i]!];
    onChange(next);
  }
  function remove(i: number) {
    onChange(features.filter((_, j) => j !== i));
  }
  function addBuiltIn(p: TierFeaturePreset) {
    onChange([...features, { preset: p, iconId: PRESET_ICONS[p], label: null }]);
  }
  function addCustom() {
    onChange([...features, { preset: null, iconId: 'check', label: '' }]);
  }
</script>

<div class="space-y-2 rounded-md border border-border p-3">
  <div class="flex items-start justify-between gap-3">
    <div>
      <p class="text-sm font-medium">Card features</p>
      <p class="text-xs text-muted-foreground leading-snug">
        Lines under the limits on this tier's plan card, the sign-up section and the payment form. A
        built-in line is translated for members; text you type replaces it and shows as typed in
        every language.
      </p>
    </div>
    {#if !isDefault}
      <Button variant="ghost" size="sm" class="shrink-0" onclick={onReset}>Use defaults</Button>
    {/if}
  </div>

  {#if features.length === 0}
    <p class="text-xs text-muted-foreground">No lines: the card shows the limits only.</p>
  {/if}

  <ul class="space-y-2">
    {#each features as f, i (i)}
      {@const Icon = resolveTierFeatureIcon(f.iconId)}
      <li class="flex flex-wrap items-center gap-2">
        <span class="rounded-md border border-border p-2" aria-hidden="true">
          <Icon class="size-4 text-primary" />
        </span>
        <select
          aria-label="Icon for line {i + 1}"
          value={f.iconId}
          onchange={(e) => set(i, { iconId: (e.target as HTMLSelectElement).value })}
          class="rounded-md border border-input bg-background px-2 py-2 text-sm"
        >
          {#each TIER_FEATURE_ICON_IDS as id (id)}<option value={id}>{id}</option>{/each}
        </select>
        <Input
          class="min-w-0 flex-1"
          aria-label="Text for line {i + 1}"
          value={f.label ?? ''}
          maxlength={MAX_TIER_FEATURE_LABEL}
          placeholder={f.preset ? `${PRESET_ADMIN_NAMES[f.preset]} (built-in, translated)` : 'Text'}
          oninput={(e) => set(i, { label: (e.target as HTMLInputElement).value })}
        />
        <div class="flex gap-1">
          <Button
            variant="outline"
            size="icon-sm"
            aria-label="Move line {i + 1} up"
            disabled={i === 0}
            onclick={() => move(i, -1)}><ChevronUp class="size-4" /></Button
          >
          <Button
            variant="outline"
            size="icon-sm"
            aria-label="Move line {i + 1} down"
            disabled={i === features.length - 1}
            onclick={() => move(i, 1)}><ChevronDown class="size-4" /></Button
          >
          <Button
            variant="outline"
            size="icon-sm"
            aria-label="Remove line {i + 1}"
            onclick={() => remove(i)}><Trash2 class="size-4" /></Button
          >
        </div>
      </li>
    {/each}
  </ul>

  <div class="flex flex-wrap items-center gap-2">
    <select
      aria-label="Add a built-in line"
      bind:value={addPreset}
      disabled={full}
      onchange={() => {
        if (addPreset) addBuiltIn(addPreset as TierFeaturePreset);
        addPreset = '';
      }}
      class="rounded-md border border-dashed border-input bg-background px-2 py-2 text-sm"
    >
      <option value="">Add a built-in line…</option>
      {#each TIER_FEATURE_PRESETS as p (p)}<option value={p}>{PRESET_ADMIN_NAMES[p]}</option>{/each}
    </select>
    <Button variant="outline" size="sm" disabled={full} onclick={addCustom}>
      <Plus class="size-4" /> Add custom line
    </Button>
    <span class="text-xs text-muted-foreground">
      Up to {MAX_TIER_FEATURES} lines, {MAX_TIER_FEATURE_LABEL} characters each.
    </span>
  </div>
</div>
