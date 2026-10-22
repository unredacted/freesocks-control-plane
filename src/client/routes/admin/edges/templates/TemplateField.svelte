<script lang="ts">
  /**
   * One provider option, rendered by its descriptor type
   * (string | number | boolean | select | string-list | key-value).
   *
   * Props:
   *   field: EdgeTemplateField
   *   value: unknown                      the current value at `field.key` (undefined = inherited)
   *   defaultValue: unknown               what applies without a value here (the provider's
   *                                       default in a template; the template's for a node)
   *   changed: boolean                    shows the "differs from ..." chip + Reset
   *   baseWord?: string                   what `defaultValue` is, in the chip ("default")
   *   offered?: { id, label, plan? }[]    the location's sizes, for a `from: 'flavors'` field
   *                                       (`plan`: its price, traffic and what it accepts; a
   *                                       size FCP refuses for a node cannot be picked)
   *   disabled?: boolean
   *   onchange(value: unknown)            undefined clears the key
   *   onreset()
   */
  import { untrack } from 'svelte';
  import RotateCcw from '@lucide/svelte/icons/rotate-ccw';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { Switch } from '@client/components/ui/switch';
  import * as Select from '@client/components/ui/select';
  import type { EdgeTemplateField } from '../../../../../shared/contracts/edges';
  import { displayValue } from '../lib/format';
  import { listToText, numberFromInput, textToList } from './params';
  import { kvToText, textToKv } from '../lib/options';
  import { planOptionLabel, planRefused, type PlanLike } from '../lib/planWords';
  import PlanFacts from '../components/PlanFacts.svelte';

  interface Props {
    field: EdgeTemplateField;
    value: unknown;
    defaultValue: unknown;
    changed: boolean;
    baseWord?: string;
    offered?: ReadonlyArray<{ id: string; label: string; plan?: PlanLike }>;
    disabled?: boolean;
    onchange: (value: unknown) => void;
    onreset: () => void;
  }
  let {
    field,
    value,
    defaultValue,
    changed,
    baseWord = 'default',
    offered = [],
    disabled = false,
    onchange,
    onreset,
  }: Props = $props();
  // A size picked from what the location offers (the current value stays a choice).
  const sizeChoices = $derived.by(() => {
    if (field.from !== 'flavors' || offered.length === 0) return null;
    const cur = typeof value === 'string' && value !== '' ? value : null;
    const list: ReadonlyArray<{ id: string; label: string; plan?: PlanLike }> = offered;
    return cur && !list.some((o) => o.id === cur) ? [...list, { id: cur, label: cur }] : list;
  });
  /** The plan of the size shown (its price and terms under the picker). */
  const shownPlan = $derived(sizeChoices?.find((o) => o.id === shown)?.plan ?? null);

  const uid = $props.id();
  const shown = $derived(value === undefined ? defaultValue : value);
  // The number input keeps its own text so clearing it does not snap back to
  // the default mid-edit; only EXTERNAL changes (reset, the JSON editor) refill it.
  const numText = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? String(v) : '');
  const seed = () => numText(shown);
  let text = $state(seed());
  $effect(() => {
    const v = shown;
    untrack(() => {
      if (text.trim() === '' ? value !== undefined : Number(text) !== v) text = numText(v);
    });
  });
  const numberInvalid = $derived(field.type === 'number' && Number.isNaN(numberFromInput(text)));
  const missing = $derived(
    field.required === true && (shown === undefined || shown === null || shown === ''),
  );
  const defaultWords = $derived.by(() => {
    if (defaultValue === undefined || defaultValue === null) return 'none';
    if (field.type === 'select') {
      return (
        field.options?.find((o) => o.value === defaultValue)?.label ?? displayValue(defaultValue)
      );
    }
    const s = displayValue(defaultValue);
    return s === '' ? 'empty' : s;
  });
  const selectLabel = $derived(
    field.options?.find((o) => o.value === shown)?.label ??
      (typeof shown === 'string' && shown !== '' ? shown : 'Choose'),
  );
</script>

<div class="space-y-1.5">
  <div class="flex flex-wrap items-center justify-between gap-2">
    <Label for={`${uid}-f`}>
      {field.label}{#if field.unit}<span class="text-muted-foreground">
          ({field.unit})</span
        >{/if}{#if field.required}<span class="text-destructive" aria-hidden="true"> *</span>{/if}
    </Label>
    {#if changed}
      <span class="flex items-center gap-1">
        <Badge variant="info">Differs from {baseWord}</Badge>
        <Button
          size="sm"
          variant="ghost"
          class="h-6 px-1.5 text-xs"
          {disabled}
          title={`Back to the ${baseWord} (${defaultWords})`}
          onclick={onreset}
        >
          <RotateCcw class="size-3" /> Reset
        </Button>
      </span>
    {/if}
  </div>

  {#if field.type === 'boolean'}
    <div class="flex items-center gap-2 text-sm">
      <Switch
        id={`${uid}-f`}
        checked={shown === true}
        {disabled}
        onCheckedChange={(v) => onchange(v === true)}
      />
      <span class="text-muted-foreground">{shown === true ? 'On' : 'Off'}</span>
    </div>
  {:else if field.type === 'select'}
    <Select.Root
      type="single"
      value={typeof shown === 'string' ? shown : ''}
      {disabled}
      onValueChange={(v) => onchange(v)}
    >
      <Select.Trigger id={`${uid}-f`} class="w-full">{selectLabel}</Select.Trigger>
      <Select.Content>
        {#each field.options ?? [] as o (o.value)}
          <Select.Item value={o.value}>{o.label}</Select.Item>
        {/each}
      </Select.Content>
    </Select.Root>
  {:else if sizeChoices}
    <Select.Root
      type="single"
      value={typeof shown === 'string' ? shown : ''}
      {disabled}
      onValueChange={(v) => onchange(v)}
    >
      <Select.Trigger id={`${uid}-f`} class="w-full"
        >{sizeChoices.find((o) => o.id === shown)?.label ??
          (typeof shown === 'string' && shown !== '' ? shown : 'Choose')}</Select.Trigger
      >
      <Select.Content>
        {#each sizeChoices as o (o.id)}
          <Select.Item
            value={o.id}
            label={o.label}
            disabled={!!o.plan && planRefused(o.plan) && o.id !== shown}
            >{o.plan ? planOptionLabel(o.plan) : o.label}</Select.Item
          >
        {/each}
      </Select.Content>
    </Select.Root>
    {#if shownPlan}<PlanFacts plan={shownPlan} />{/if}
  {:else if field.type === 'number'}
    <Input
      id={`${uid}-f`}
      type="number"
      inputmode="decimal"
      min={field.min}
      max={field.max}
      {disabled}
      aria-invalid={numberInvalid || missing}
      value={text}
      oninput={(e) => {
        text = e.currentTarget.value;
        const n = numberFromInput(text);
        if (n === undefined || !Number.isNaN(n)) onchange(n);
      }}
    />
  {:else if field.type === 'string-list'}
    <textarea
      id={`${uid}-f`}
      rows="3"
      {disabled}
      class="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs shadow-xs focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none disabled:opacity-50"
      value={listToText(shown)}
      onchange={(e) => onchange(textToList(e.currentTarget.value))}
    ></textarea>
    <p class="text-xs text-muted-foreground">One entry per line.</p>
  {:else if field.type === 'key-value'}
    <textarea
      id={`${uid}-f`}
      rows="3"
      {disabled}
      class="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs shadow-xs focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none disabled:opacity-50"
      value={kvToText(shown)}
      onchange={(e) => onchange(textToKv(e.currentTarget.value, field.pairs === true))}
    ></textarea>
    <p class="text-xs text-muted-foreground">One key=value per line.</p>
  {:else}
    <Input
      id={`${uid}-f`}
      {disabled}
      aria-invalid={missing}
      value={typeof shown === 'string' ? shown : shown === undefined ? '' : displayValue(shown)}
      oninput={(e) => onchange(e.currentTarget.value)}
    />
  {/if}

  {#if field.help}<p class="text-xs text-muted-foreground">{field.help}</p>{/if}
  {#if missing}<p class="text-xs text-destructive">This field is required.</p>{/if}
</div>
