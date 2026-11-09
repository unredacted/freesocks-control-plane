<script lang="ts">
  /**
   * A country's own replacement budget, one number per censored country
   * (`audience.replacesPerDayByCountry`, docs/edges.md "A country on its own
   * addresses"): a blank follows the fleet's value; anything but a whole number
   * from 0 to 10 marks the form invalid.
   *
   * Props:
   *   codes: string[]   the censored-country list
   *   form: ConfigForm
   */
  import { SvelteSet } from 'svelte/reactivity';
  import { Input } from '@client/components/ui/input';
  import { AUDIENCE_BUDGETS_PATH } from './fields';
  import type { ConfigForm } from './form.svelte';

  interface Props {
    codes: string[];
    form: ConfigForm;
  }
  let { codes, form }: Props = $props();

  const MAX = 10;
  const budgets = () => form.rule(AUDIENCE_BUDGETS_PATH) as Record<string, number>;
  const shown = (code: string) => {
    const n = budgets()[code];
    return n === undefined ? '' : String(n);
  };
  const bad = new SvelteSet<string>();
  const change = (code: string, text: string) => {
    const next = { ...budgets() };
    const t = text.trim();
    const n = Number(t);
    if (t === '') {
      delete next[code];
      bad.delete(code);
    } else if (Number.isInteger(n) && n >= 0 && n <= MAX) {
      next[code] = n;
      bad.delete(code);
    } else bad.add(code);
    form.setInvalid(AUDIENCE_BUDGETS_PATH, bad.size > 0);
    form.set(AUDIENCE_BUDGETS_PATH, next);
  };
</script>

{#if codes.length > 0}
  <fieldset class="mt-5 space-y-2">
    <legend class="text-sm font-medium">A country's own addresses replaced, by country</legend>
    <p class="text-muted-foreground text-xs">
      Replacements a day per node and transport for one country. Blank follows the line above.
    </p>
    <div class="flex flex-wrap gap-3">
      {#each codes as code (code)}
        <label class="flex items-center gap-2 text-sm">
          <span class="w-8 font-mono">{code}</span>
          <Input
            class="w-20"
            inputmode="numeric"
            aria-label={`Replacements a day for ${code}'s own addresses`}
            aria-invalid={bad.has(code)}
            value={shown(code)}
            oninput={(e) => change(code, e.currentTarget.value)}
          />
        </label>
      {/each}
    </div>
    {#if bad.size > 0}
      <p class="text-destructive text-xs">Use a whole number from 0 to {MAX}, or leave it blank.</p>
    {/if}
  </fieldset>
{/if}
