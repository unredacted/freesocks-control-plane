<script lang="ts">
  /**
   * One knob of the edge config, rendered from its descriptor (settings/fields.ts)
   * against the shared ConfigForm: a switch with its consequence, a NumberField
   * with the server bounds and default, a select, or a short text.
   *
   * Props:
   *   field: Field
   *   form: ConfigForm
   *   disabled?: boolean
   */
  import RotateCcw from '@lucide/svelte/icons/rotate-ccw';
  import { Switch } from '@client/components/ui/switch';
  import { Label } from '@client/components/ui/label';
  import { Input } from '@client/components/ui/input';
  import { Button } from '@client/components/ui/button';
  import * as Select from '@client/components/ui/select';
  import NumberField from '../components/NumberField.svelte';
  import { sameValue } from './configDiff';
  import type { Field } from './fields';
  import type { ConfigForm } from './form.svelte';

  interface Props {
    field: Field;
    form: ConfigForm;
    disabled?: boolean;
  }
  let { field, form, disabled = false }: Props = $props();

  const uid = $props.id();
  const dflt = $derived(form.defaultOf(field.path));
  const offDefault = $derived(dflt !== undefined && !sameValue(dflt, form.get(field.path)));
  const defaultWords = $derived.by(() => {
    if (field.kind === 'switch') return dflt === true ? 'on' : 'off';
    if (field.kind === 'select')
      return field.options.find((o) => o.value === dflt)?.label ?? String(dflt);
    return String(dflt);
  });
</script>

{#snippet resetButton()}
  {#if offDefault}
    <Button
      type="button"
      variant="ghost"
      size="xs"
      {disabled}
      onclick={() => form.set(field.path, dflt)}
      aria-label={`Reset ${field.label} to the default, ${defaultWords}`}
    >
      <RotateCcw aria-hidden="true" />
      Default {defaultWords}
    </Button>
  {/if}
{/snippet}

{#if field.kind === 'switch'}
  <div class="flex items-start gap-3">
    <Switch
      id={`${uid}-sw`}
      class="mt-0.5"
      {disabled}
      aria-describedby={`${uid}-help`}
      bind:checked={() => form.bool(field.path), (v) => form.set(field.path, v)}
    />
    <div class="min-w-0 flex-1">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <Label for={`${uid}-sw`}>{field.label}</Label>
        {@render resetButton()}
      </div>
      <p id={`${uid}-help`} class="text-muted-foreground mt-1 text-xs">{field.helper}</p>
    </div>
  </div>
{:else if field.kind === 'number'}
  <NumberField
    label={field.label}
    unit={field.unit}
    step={field.step}
    helper={field.helper}
    bounds={form.bounds(field.path)}
    defaultValue={form.defaultNumber(field.path)}
    {disabled}
    bind:value={() => form.num(field.path), (v) => form.set(field.path, v)}
    bind:invalid={() => form.invalid[field.path] ?? false, (v) => form.setInvalid(field.path, v)}
  />
{:else if field.kind === 'select'}
  <div class="space-y-1.5">
    <div class="flex items-center justify-between gap-2">
      <Label for={`${uid}-sel`}>{field.label}</Label>
      {@render resetButton()}
    </div>
    <Select.Root
      type="single"
      {disabled}
      bind:value={() => form.str(field.path), (v) => form.set(field.path, v)}
    >
      <Select.Trigger id={`${uid}-sel`} class="w-full sm:w-80">
        {field.options.find((o) => o.value === form.str(field.path))?.label ?? 'Choose'}
      </Select.Trigger>
      <Select.Content>
        {#each field.options as o (o.value)}
          <Select.Item value={o.value} label={o.label}>{o.label}</Select.Item>
        {/each}
      </Select.Content>
    </Select.Root>
    <p class="text-muted-foreground text-xs">{field.helper}</p>
  </div>
{:else}
  <div class="space-y-1.5">
    <div class="flex items-center justify-between gap-2">
      <Label for={`${uid}-txt`}>{field.label}</Label>
      {@render resetButton()}
    </div>
    <Input
      id={`${uid}-txt`}
      class="w-full sm:w-80"
      maxlength={field.maxLength}
      {disabled}
      value={form.str(field.path)}
      oninput={(e) => form.set(field.path, e.currentTarget.value)}
    />
    <p class="text-muted-foreground text-xs">{field.helper}</p>
  </div>
{/if}
