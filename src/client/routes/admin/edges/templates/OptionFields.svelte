<script lang="ts">
  /**
   * A provider's options, rendered from their descriptors (`optionSchemas` or a
   * templates response's `schemas`): grouped by the resource they configure,
   * a `when` field only while its condition holds, the advanced ones folded.
   * The template editor, an account's defaults, a node's pick and one address
   * all use it; only `values` and `base` differ.
   *
   * Props:
   *   fields: EdgeTemplateField[]
   *   values: Params                     what this level sets (absent = inherited)
   *   base: Params                       what applies without it
   *   baseWord?: string                  what `base` is, in words ("default", "template")
   *   offered?: { id, label }[]          the location's sizes (for `from: 'flavors'`)
   *   prominentFirst?: boolean           show the main choices; the rest under "All options"
   *   disabled?: boolean
   *   onchange(values: Params)
   */
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import * as Collapsible from '@client/components/ui/collapsible';
  import type { EdgeTemplateField } from '../../../../../shared/contracts/edges';
  import TemplateField from './TemplateField.svelte';
  import {
    differsFromDefault,
    getPath,
    resetField,
    setPath,
    unsetPath,
    type Params,
  } from './params';
  import { groupsOf, visibleFields } from '../lib/options';

  interface Props {
    fields: readonly EdgeTemplateField[];
    values: Params;
    base: Params;
    baseWord?: string;
    offered?: ReadonlyArray<{ id: string; label: string }>;
    prominentFirst?: boolean;
    disabled?: boolean;
    onchange: (values: Params) => void;
  }
  let {
    fields,
    values,
    base,
    baseWord = 'default',
    offered = [],
    prominentFirst = false,
    disabled = false,
    onchange,
  }: Props = $props();

  const shown = $derived(visibleFields(fields, values, base));
  const main = $derived(
    prominentFirst ? shown.filter((f) => f.prominent) : shown.filter((f) => !f.advanced),
  );
  const more = $derived(
    prominentFirst ? shown.filter((f) => !f.prominent) : shown.filter((f) => f.advanced),
  );
  const changedMore = $derived(more.filter((f) => differsFromDefault(values, base, f.key)).length);
  let open = $state(false);

  const set = (key: string, v: unknown) =>
    onchange(v === undefined ? unsetPath(values, key) : setPath(values, key, v));
  const reset = (key: string) => {
    // Back to what is inherited: the key goes (a node's pick, a default) or
    // takes the base value (a template keeps every key it was given).
    const inherited = getPath(base, key);
    onchange(inherited === undefined ? unsetPath(values, key) : resetField(values, base, key));
  };
</script>

{#snippet section(list: readonly EdgeTemplateField[])}
  {#each groupsOf(list) as g (g.group)}
    <fieldset class="space-y-3">
      <legend class="text-xs font-medium tracking-wide text-muted-foreground uppercase">
        {g.group}
      </legend>
      <div class="grid gap-4 sm:grid-cols-2">
        {#each g.fields as f (f.key)}
          <TemplateField
            field={f}
            value={getPath(values, f.key)}
            defaultValue={getPath(base, f.key) ?? f.default}
            changed={differsFromDefault(values, base, f.key)}
            {baseWord}
            {offered}
            {disabled}
            onchange={(v) => set(f.key, v)}
            onreset={() => reset(f.key)}
          />
        {/each}
      </div>
    </fieldset>
  {/each}
{/snippet}

<div class="space-y-4">
  {#if main.length > 0}{@render section(main)}{/if}
  {#if more.length > 0}
    <Collapsible.Root bind:open>
      <Collapsible.Trigger
        class="group flex items-center gap-1 text-sm font-medium text-muted-foreground hover:text-foreground"
      >
        <ChevronRight class="size-4 transition-transform group-data-[state=open]:rotate-90" />
        {prominentFirst ? 'All options' : 'More options'} ({more.length}{changedMore > 0
          ? `, ${changedMore} changed`
          : ''})
      </Collapsible.Trigger>
      <Collapsible.Content class="space-y-4 pt-3">
        {@render section(more)}
      </Collapsible.Content>
    </Collapsible.Root>
  {/if}
</div>
