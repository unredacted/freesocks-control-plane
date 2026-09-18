<script lang="ts">
  /**
   * One template parameter, rendered by its descriptor type
   * (string | number | boolean | select | string-list).
   *
   * Props:
   *   field: EdgeTemplateField
   *   value: unknown                      the current value at `field.key` (undefined = default applies)
   *   defaultValue: unknown               the provider default at the same key
   *   changed: boolean                    shows the "differs from default" chip + Reset
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

  interface Props {
    field: EdgeTemplateField;
    value: unknown;
    defaultValue: unknown;
    changed: boolean;
    disabled?: boolean;
    onchange: (value: unknown) => void;
    onreset: () => void;
  }
  let {
    field,
    value,
    defaultValue,
    changed,
    disabled = false,
    onchange,
    onreset,
  }: Props = $props();

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
      {field.label}{#if field.required}<span class="text-destructive" aria-hidden="true">
          *</span
        >{/if}
    </Label>
    {#if changed}
      <span class="flex items-center gap-1">
        <Badge variant="info">Differs from default</Badge>
        <Button
          size="sm"
          variant="ghost"
          class="h-6 px-1.5 text-xs"
          {disabled}
          title={`Back to the default (${defaultWords})`}
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
  {:else if field.type === 'number'}
    <Input
      id={`${uid}-f`}
      type="number"
      inputmode="decimal"
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
