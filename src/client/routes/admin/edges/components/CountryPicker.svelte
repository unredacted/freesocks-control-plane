<script lang="ts">
  /**
   * Pick countries (ISO 3166-1 alpha-2) by name or code. Multi-select by default;
   * `max={1}` makes it a single picker (the array then holds zero or one code).
   *
   * Props:
   *   value: string[] (bindable)            upper-case codes
   *   label: string
   *   placeholder?: string                  default 'Search countries'
   *   helper?: string
   *   max?: number
   *   disabled?: boolean
   *   onchange?: (next: string[]) => void
   *   class?: string
   */
  import X from '@lucide/svelte/icons/x';
  import * as Combobox from '@client/components/ui/combobox';
  import { Label } from '@client/components/ui/label';
  import { cn } from '@client/lib/utils';
  import { countryName } from '@client/lib/countries';
  import { countryOptions, filterCountries } from '../lib/countries';

  interface Props {
    value: string[];
    label: string;
    placeholder?: string;
    helper?: string;
    max?: number;
    disabled?: boolean;
    onchange?: (next: string[]) => void;
    class?: string;
  }
  let {
    value = $bindable([]),
    label,
    placeholder = 'Search countries',
    helper,
    max,
    disabled = false,
    onchange,
    class: className,
  }: Props = $props();

  const uid = $props.id();
  const options = countryOptions('en');
  let query = $state('');
  let open = $state(false);
  const filtered = $derived(filterCountries(options, query).slice(0, 60));
  const full = $derived(max !== undefined && value.length >= max);

  function set(next: string[]) {
    // A single picker replaces its one value instead of refusing the second pick.
    const capped = max === 1 ? next.slice(-1) : max !== undefined ? next.slice(0, max) : next;
    value = capped;
    onchange?.(capped);
  }
  function remove(code: string) {
    set(value.filter((c) => c !== code));
  }
</script>

<div class={cn('space-y-1.5', className)}>
  <Label for={`${uid}-input`}>{label}</Label>
  {#if value.length > 0}
    <ul class="flex flex-wrap gap-1" aria-label={`Selected: ${label}`}>
      {#each value as code (code)}
        <li
          class="bg-secondary text-secondary-foreground inline-flex items-center gap-0.5 rounded-md py-0.5 ps-1.5 pe-0.5 text-xs"
        >
          <span class="font-mono">{code}</span>
          <span>{countryName(code, 'en')}</span>
          <button
            type="button"
            class="hover:bg-foreground/10 focus-visible:ring-ring/60 rounded-sm p-0.5 outline-none focus-visible:ring-2"
            aria-label={`Remove ${countryName(code, 'en')}`}
            {disabled}
            onclick={() => remove(code)}
          >
            <X class="size-3" aria-hidden="true" />
          </button>
        </li>
      {/each}
    </ul>
  {/if}
  <Combobox.Root
    type="multiple"
    bind:open
    {value}
    onValueChange={(next: string[]) => set(next)}
    {disabled}
    onOpenChangeComplete={(o: boolean) => {
      if (!o) query = '';
    }}
  >
    <div class="relative">
      <Combobox.Input
        id={`${uid}-input`}
        class="pe-9"
        placeholder={full && max !== 1 ? `At most ${max} countries` : placeholder}
        aria-describedby={helper ? `${uid}-help` : undefined}
        oninput={(e) => (query = e.currentTarget.value)}
        onfocus={() => (open = true)}
      />
      <Combobox.Trigger class="absolute end-0.5 top-0" aria-label={`Show countries for ${label}`} />
    </div>
    <Combobox.Content>
      {#each filtered as o (o.code)}
        <Combobox.Item
          value={o.code}
          label={o.name}
          disabled={full && max !== 1 && !value.includes(o.code)}
        >
          <span class="text-muted-foreground w-7 font-mono text-xs">{o.code}</span>
          {o.name}
        </Combobox.Item>
      {:else}
        <p class="text-muted-foreground px-2 py-1.5 text-sm">No country matches.</p>
      {/each}
    </Combobox.Content>
  </Combobox.Root>
  {#if helper}
    <p id={`${uid}-help`} class="text-muted-foreground text-xs">{helper}</p>
  {/if}
</div>
