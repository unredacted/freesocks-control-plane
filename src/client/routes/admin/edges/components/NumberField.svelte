<script lang="ts">
  /**
   * Labelled integer / decimal input with a unit, server bounds and helper text.
   * Out-of-range or empty input is flagged in place and reported through
   * `invalid`; `value` only ever receives a finite number.
   *
   * Props:
   *   value: number (bindable)
   *   label: string
   *   unit?: string                         'min', 's', 'edges', '%'
   *   bounds?: { min: number; max: number } EdgeConfigView.bounds['<flat.path>'] (wins over min / max)
   *   min?: number, max?: number
   *   step?: number                         default 1; a fractional step allows decimals
   *   helper?: string                       one line: what the knob does
   *   defaultValue?: number                 EdgeConfigView.defaults[...]: shows "Default 15" + a reset button
   *   invalid?: boolean (bindable, out)     true while the text is not an in-range number
   *   disabled?: boolean
   *   onchange?: (next: number) => void     fires with every valid change
   *   class?: string
   */
  import { untrack } from 'svelte';
  import RotateCcw from '@lucide/svelte/icons/rotate-ccw';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { Button } from '@client/components/ui/button';
  import { cn } from '@client/lib/utils';
  import { parseBounded } from '../lib/number';

  interface Props {
    value: number;
    label: string;
    unit?: string;
    bounds?: { min: number; max: number };
    min?: number;
    max?: number;
    step?: number;
    helper?: string;
    defaultValue?: number;
    invalid?: boolean;
    disabled?: boolean;
    onchange?: (next: number) => void;
    class?: string;
  }
  let {
    value = $bindable(),
    label,
    unit,
    bounds,
    min,
    max,
    step = 1,
    helper,
    defaultValue,
    invalid = $bindable(false),
    disabled = false,
    onchange,
    class: className,
  }: Props = $props();

  const uid = $props.id();
  const lo = $derived(bounds?.min ?? min);
  const hi = $derived(bounds?.max ?? max);
  const integer = $derived(Number.isInteger(step));

  // Seeded from the prop once (through a function so the first paint is already
  // valid), then only EXTERNAL value changes are followed.
  const seed = () => (Number.isFinite(value) ? String(value) : '');
  const seedValue = () => value;
  let text = $state(seed());
  // Syncing on every text change would refill the field while the operator is
  // clearing it, so compare against the last value this component saw.
  let lastSeen: number | undefined = seedValue();
  $effect(() => {
    const v = value;
    if (v === lastSeen) return;
    lastSeen = v;
    untrack(() => {
      if (text.trim() === '' || Number(text) !== v) text = Number.isFinite(v) ? String(v) : '';
    });
  });

  const parsed = $derived(parseBounded(text, { min: lo, max: hi, integer }));
  $effect(() => {
    invalid = !parsed.ok;
  });

  function oninput(e: Event) {
    text = (e.currentTarget as HTMLInputElement).value;
    const p = parseBounded(text, { min: lo, max: hi, integer });
    if (p.ok && p.value !== value) {
      lastSeen = p.value;
      value = p.value;
      onchange?.(p.value);
    }
  }

  function reset() {
    if (defaultValue === undefined) return;
    text = String(defaultValue);
    lastSeen = defaultValue;
    value = defaultValue;
    onchange?.(defaultValue);
  }

  const range = $derived(
    lo !== undefined && hi !== undefined
      ? `${lo} to ${hi}`
      : lo !== undefined
        ? `at least ${lo}`
        : hi !== undefined
          ? `at most ${hi}`
          : '',
  );
</script>

<div class={cn('space-y-1.5', className)}>
  <div class="flex items-center justify-between gap-2">
    <Label for={`${uid}-input`}>{label}</Label>
    {#if defaultValue !== undefined && value !== defaultValue}
      <Button
        type="button"
        variant="ghost"
        size="xs"
        {disabled}
        onclick={reset}
        aria-label={`Reset ${label} to the default, ${defaultValue}`}
      >
        <RotateCcw aria-hidden="true" />
        Default {defaultValue}
      </Button>
    {/if}
  </div>
  <div class="flex items-center gap-2">
    <Input
      id={`${uid}-input`}
      type="number"
      inputmode={integer ? 'numeric' : 'decimal'}
      class="w-32"
      value={text}
      min={lo}
      max={hi}
      {step}
      {disabled}
      aria-invalid={!parsed.ok ? 'true' : undefined}
      aria-describedby={`${uid}-help`}
      {oninput}
    />
    {#if unit}<span class="text-muted-foreground text-sm">{unit}</span>{/if}
  </div>
  <p id={`${uid}-help`} class="text-xs">
    {#if !parsed.ok}
      <span class="text-destructive" role="alert">{parsed.message}</span>
    {:else}
      <span class="text-muted-foreground">
        {helper ?? ''}{helper && range ? ' ' : ''}{range ? `Allowed: ${range}.` : ''}
      </span>
    {/if}
  </p>
</div>
