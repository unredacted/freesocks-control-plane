<script lang="ts">
  /**
   * "Mark for a country": the operator's word about one address (`scope:
   * 'edge'`) or one provider location (`scope: 'group'`) in one checked
   * country: Works there, Blocked there, or Use the checks (removes the mark).
   * A mark wins over every check and never expires; a check that disagrees
   * shows as a conflict beside it. `POST countries/marks`.
   *
   * Props:
   *   open (bindable)
   *   scope: 'edge' | 'group'
   *   ref: string                  the edge id, or the group key
   *   name: string                 the address or the location, for the title
   *   countries: string[]          the checked countries
   *   marks: CountryMarkRow[]      the marks on this address or location (any country)
   *   country?: string | null      preselect a country
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import * as Select from '@client/components/ui/select';
  import { Label } from '@client/components/ui/label';
  import { countryName } from '@client/lib/countries';
  import { invalidateCountries, setCountryMark } from '@client/lib/edgesApi';
  import type { CountryMarkRow } from '@shared/contracts/edges';
  import ActionConfirm from '../relay/ActionConfirm.svelte';
  import { MARK_WORDS } from '../lib/statusWords';

  type Choice = 'proven' | 'blocked' | 'clear';
  interface Props {
    open: boolean;
    scope: 'edge' | 'group';
    ref: string;
    name: string;
    countries: string[];
    marks: CountryMarkRow[];
    country?: string | null;
  }
  let {
    open = $bindable(false),
    scope,
    ref,
    name,
    countries,
    marks,
    country = null,
  }: Props = $props();
  const uid = $props.id();
  const qc = useQueryClient();

  let picked = $state('');
  let choice = $state<Choice | null>(null);
  // Every opening starts from the preset country and its current mark.
  $effect(() => {
    if (!open) return;
    picked = country ?? countries[0] ?? '';
  });
  const current = $derived(marks.find((m) => m.country === picked)?.state ?? null);
  $effect(() => {
    if (open) choice = current ?? 'clear';
  });

  const CHOICES: Array<{ value: Choice; label: string; hint: string }> = [
    {
      value: 'proven',
      label: MARK_WORDS.proven,
      hint: 'Count it as working there, whatever the checks find.',
    },
    {
      value: 'blocked',
      label: MARK_WORDS.blocked,
      hint: 'Count it as blocked there, whatever the checks find.',
    },
    {
      value: 'clear',
      label: MARK_WORDS.clear,
      hint: 'No mark: the checks from there decide.',
    },
  ];
  const unchanged = $derived((choice === 'clear' ? null : choice) === current);
  const body = $derived(
    scope === 'group'
      ? 'A mark on a location counts for every address in it, now and later. It wins over every check from that country and never expires.'
      : 'A mark wins over every check from that country and never expires. The checks keep running and show beside it when they disagree.',
  );

  async function save() {
    const state = choice === 'clear' ? null : choice;
    await setCountryMark({ scope, ref, country: picked, state });
    invalidateCountries(qc);
    const where = countryName(picked, 'en');
    toast.success(
      state === null
        ? `The checks decide for ${where} again.`
        : `Marked: ${MARK_WORDS[state].toLowerCase().replace('there', `in ${where}`)}.`,
    );
  }
</script>

<ActionConfirm
  bind:open
  title={`Mark ${name} for a country`}
  {body}
  confirmLabel="Save"
  disabled={!picked || choice === null || unchanged}
  run={save}
>
  <div class="space-y-4">
    {#if countries.length > 1}
      <div class="space-y-1.5">
        <Label for={`${uid}-country`}>Country</Label>
        <Select.Root type="single" value={picked} onValueChange={(v) => (picked = v)}>
          <Select.Trigger id={`${uid}-country`} class="w-full">
            {picked ? countryName(picked, 'en') : 'Choose a country'}
          </Select.Trigger>
          <Select.Content>
            {#each countries as c (c)}
              <Select.Item value={c}>{countryName(c, 'en')}</Select.Item>
            {/each}
          </Select.Content>
        </Select.Root>
      </div>
    {:else if picked}
      <p class="text-sm">Country: {countryName(picked, 'en')}</p>
    {/if}
    <fieldset class="space-y-2">
      <legend class="mb-1 text-sm font-medium">In this country</legend>
      {#each CHOICES as c (c.value)}
        <label
          class="has-[:checked]:border-primary has-[:checked]:bg-primary/5 flex cursor-pointer items-start gap-2 rounded-md border px-3 py-2"
        >
          <input
            type="radio"
            class="accent-primary mt-1"
            name={`${uid}-choice`}
            value={c.value}
            checked={choice === c.value}
            onchange={() => (choice = c.value)}
          />
          <span class="min-w-0">
            <span class="block text-sm">
              {c.label}
              {#if (c.value === 'clear' ? null : c.value) === current}
                <span class="text-muted-foreground ms-1">(now)</span>
              {/if}
            </span>
            <span class="text-muted-foreground block text-xs">{c.hint}</span>
          </span>
        </label>
      {/each}
    </fieldset>
  </div>
</ActionConfirm>
