<script lang="ts">
  /**
   * What one account costs (docs/edges.md § "Plans and prices"): what you pay
   * per edge (a load balancer account: the list price its locations' plans
   * carry, free or credits, or your own amount; a CDN account is never priced
   * on its own, so it reads "no price set" until you say), an optional note,
   * and the monthly spend cap that stops new edges once the account's estimate
   * would pass it (off by default). Below, the estimate over its live edges.
   *
   * Props:
   *   account: EdgeProviderAccountAdmin
   */
  import { untrack } from 'svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { Switch } from '@client/components/ui/switch';
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import type { EdgeProviderAccountAdmin } from '../../../../../shared/contracts/edges';
  import { invalidateProviders, setProviderCost } from '../../../../lib/edgesApi';
  import { EDGE_PROVIDER_META } from '../../../../lib/edgeProviderMeta';
  import NumberField from '../components/NumberField.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { money, totalWords } from '../lib/planWords';

  interface Props {
    account: EdgeProviderAccountAdmin;
  }
  let { account }: Props = $props();

  const qc = useQueryClient();
  const uid = $props.id();
  /** A CDN account has no list price: it is free, an amount, or not set. */
  const cdn = $derived(EDGE_PROVIDER_META[account.provider].layer === 'l7');

  type Paid = 'list' | 'free' | 'amount' | 'unset';
  /** The currency the account's plans are priced in, to suggest one. */
  const planCurrency = untrack(
    () =>
      account.locations.find((l) => l.pricing?.plan?.currency)?.pricing?.plan?.currency ??
      account.locations.flatMap((l) => l.pricing?.plans ?? []).find((p) => p.currency)?.currency ??
      'EUR',
  );
  interface Choice {
    paid: Paid;
    amount: number;
    currency: string;
    note: string;
    capOn: boolean;
    cap: number;
  }
  const choiceOf = (c: EdgeProviderAccountAdmin['cost']): Choice => ({
    paid: (c?.paid ?? (cdn ? 'unset' : 'list')) as Paid,
    amount: c?.perEdgeMonthly ?? 0,
    currency: c?.currency ?? planCurrency,
    note: c?.note ?? '',
    capOn: c?.monthlyCap !== null && c?.monthlyCap !== undefined,
    cap: c?.monthlyCap ?? 100,
  });
  /** What is saved: null when every choice is the default (nothing stored). */
  function bodyOf(c: Choice) {
    const cur = c.currency.trim().toUpperCase();
    // A CDN account with no price set has nothing to cap or note.
    if (c.paid === 'unset') return null;
    if (c.paid === 'list' && !c.capOn && c.note.trim() === '') return null;
    return {
      paid: c.paid,
      ...(c.paid === 'amount' ? { perEdgeMonthly: c.amount } : {}),
      ...(c.paid === 'amount' || c.capOn ? { currency: cur } : {}),
      ...(c.note.trim() ? { note: c.note.trim() } : {}),
      ...(c.capOn ? { monthlyCap: c.cap } : {}),
    };
  }
  const seed = untrack(() => choiceOf(account.cost));
  let paid = $state<Paid>(seed.paid);
  let amount = $state(seed.amount);
  let currency = $state(seed.currency);
  let note = $state(seed.note);
  let capOn = $state(seed.capOn);
  let cap = $state(seed.cap);
  let badAmount = $state(false);
  let badCap = $state(false);

  const currencyOk = $derived(/^[A-Z]{3}$/.test(currency.trim().toUpperCase()));
  const body = $derived(bodyOf({ paid, amount, currency, note, capOn, cap }));
  const changed = $derived(JSON.stringify(body) !== JSON.stringify(bodyOf(choiceOf(account.cost))));
  const needsCurrency = $derived(paid === 'amount' || (capOn && paid !== 'unset'));
  const invalid = $derived(
    (paid === 'amount' && badAmount) ||
      (capOn && paid !== 'unset' && (badCap || cap <= 0)) ||
      (needsCurrency && !currencyOk),
  );

  const save = createMutation(() => ({
    mutationFn: () => setProviderCost(account.id, { cost: body }),
    onSuccess: () => {
      invalidateProviders(qc);
      toast.success('Cost saved');
    },
    onError: (err: unknown) =>
      toast.error('Could not save the cost', { description: edgeErrorMessage(err) }),
  }));

  const spend = $derived(account.cost?.spend ?? null);
  const spendLine = $derived.by(() => {
    if (!spend) return null;
    if (spend.edges === 0) return 'No live edge in this account now.';
    const total = totalWords(spend);
    return `${spend.edges} live edge${spend.edges === 1 ? '' : 's'}. ${total ?? 'No price known for them.'}`;
  });
  const CHOICE =
    'has-[:checked]:border-primary has-[:checked]:bg-primary/5 flex cursor-pointer items-start gap-3 rounded-md border p-3';
</script>

<Card>
  <CardHeader>
    <CardTitle class="text-base">Cost</CardTitle>
    <CardDescription>
      {cdn
        ? 'What this CDN account costs you. FCP never prices a CDN on its own: say what you pay, or that it is free.'
        : "What this account's edges cost you. FCP reads each location's list prices from the provider; say here when you pay something else."}
    </CardDescription>
  </CardHeader>
  <CardContent class="space-y-4">
    <fieldset class="grid gap-2 sm:grid-cols-3">
      <legend class="mb-1.5 text-sm font-medium">What you pay per edge</legend>
      {#if cdn}
        <label class={CHOICE}>
          <input type="radio" class="accent-primary mt-1" bind:group={paid} value="unset" />
          <span class="text-sm">Not set</span>
        </label>
      {:else}
        <label class={CHOICE}>
          <input type="radio" class="accent-primary mt-1" bind:group={paid} value="list" />
          <span class="text-sm">The list price</span>
        </label>
      {/if}
      <label class={CHOICE}>
        <input type="radio" class="accent-primary mt-1" bind:group={paid} value="free" />
        <span class="text-sm">Free or credits</span>
      </label>
      <label class={CHOICE}>
        <input type="radio" class="accent-primary mt-1" bind:group={paid} value="amount" />
        <span class="text-sm">Another amount</span>
      </label>
    </fieldset>

    <div class="grid gap-4 sm:grid-cols-3">
      {#if paid === 'amount'}
        <NumberField
          bind:value={amount}
          bind:invalid={badAmount}
          label="Per edge a month"
          min={0}
          max={1_000_000}
          step={0.01}
          helper="What one edge of this account costs you each month."
        />
      {/if}
      {#if needsCurrency}
        <div class="space-y-1.5">
          <Label for={`${uid}-cur`}>Currency</Label>
          <Input
            id={`${uid}-cur`}
            class="font-mono uppercase"
            maxlength={3}
            bind:value={currency}
            aria-invalid={!currencyOk}
          />
          <p class="text-muted-foreground text-xs">
            A three-letter code like EUR. Amounts in other currencies are never added to it.
          </p>
        </div>
      {/if}
    </div>

    {#if paid !== 'unset'}
      <div class="space-y-1.5">
        <Label for={`${uid}-note`}>Note (optional)</Label>
        <Input
          id={`${uid}-note`}
          bind:value={note}
          maxlength={120}
          placeholder="Credits until the end of the year"
        />
      </div>

      <div class="space-y-3 rounded-md border p-3">
        <div class="flex items-center justify-between gap-3">
          <div>
            <p class="text-sm font-medium">Monthly spend cap</p>
            <p class="text-muted-foreground text-xs">
              When on, FCP creates no new edge here once the account's monthly estimate would pass
              the cap. Edges whose price is not known count for nothing.
            </p>
          </div>
          <Switch checked={capOn} onCheckedChange={(v) => (capOn = v === true)} />
        </div>
        {#if capOn}
          <NumberField
            bind:value={cap}
            bind:invalid={badCap}
            label={`Cap a month${currencyOk ? ` (${currency.trim().toUpperCase()})` : ''}`}
            min={0.01}
            max={1_000_000}
            step={0.01}
            class="max-w-xs"
          />
        {/if}
      </div>
    {/if}

    {#if spendLine}
      <p class="text-sm">{spendLine}</p>
    {/if}
    {#if spend?.atCap && account.cost?.monthlyCap !== null && account.cost?.currency}
      <p class="text-sm text-amber-700 dark:text-amber-300" role="status">
        At the cap: about {money(spend.monthly, account.cost.currency)} of {money(
          account.cost.monthlyCap ?? 0,
          account.cost.currency,
        )} a month. No new edge is created here until the cap is raised or edges go.
      </p>
    {/if}

    <div class="flex items-center justify-end gap-3">
      {#if changed}<span class="text-muted-foreground text-xs">Not saved</span>{/if}
      <Button disabled={!changed || invalid || save.isPending} onclick={() => save.mutate()}>
        {save.isPending ? 'Saving' : 'Save'}
      </Button>
    </div>
  </CardContent>
</Card>
