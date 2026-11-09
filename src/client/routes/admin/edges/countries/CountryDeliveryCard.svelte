<script lang="ts">
  /**
   * Countries -> Delivery: "Where members connect from" (lib/memberCountry.ts,
   * docs/privacy.md). Guess the country, ask at sign-up, order addresses by
   * country (and by distance), how long a guess lasts, the service's own exit
   * ranges, and the exit location for each listed country. It moved here from
   * Admin -> Settings and keeps its own working copy: Save sends only these
   * settings (./delivery.ts) in one `PATCH /api/v1/admin/settings`.
   * Each country page edits its own exit row too (its Exit section).
   *
   * Props: id?: string   the card's element id
   */
  import { z } from 'zod';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import {
    Card,
    CardHeader,
    CardTitle,
    CardDescription,
    CardContent,
  } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Input } from '@client/components/ui/input';
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '@client/components/Link.svelte';
  import { apiClient } from '@client/lib/api';
  import { apiErrorMessage } from '@client/lib/errors';
  import { countryName } from '@client/lib/countries';
  import {
    adminCensoredCountriesQuery,
    appSettingsQuery,
    configQuery,
    queryKeys,
  } from '@client/lib/queries';
  import { edgeKeys } from '@client/lib/edgesApi';
  import { EXIT_SLOTS, editorCountries, slotsOf, withSlot } from '@client/lib/countryExits';
  import { AppSettingsRecord } from '@shared/contracts/admin';
  import { edgesPaths } from '../lib/routes';
  import {
    REFRESH_HOURS,
    STICKY_DAYS,
    clampWhole,
    deliveryChanged,
    deliveryDraft,
    deliveryPatch,
    parseExitRanges,
    type DeliveryDraft,
  } from './delivery';

  let { id }: { id?: string } = $props();
  const uid = $props.id();
  const qc = useQueryClient();
  const settings = appSettingsQuery();
  const censored = adminCensoredCountriesQuery();
  const cfg = configQuery();

  // The working copy, taken once from the settings (a background refetch
  // never drops an edit); null until they load.
  let draft = $state<DeliveryDraft | null>(null);
  // Free-text mirror of the exit ranges so typing a new line is not reflowed.
  let rangesText = $state('');
  $effect(() => {
    if (settings.data && draft === null) reset();
  });
  function reset() {
    draft = deliveryDraft(settings.data);
    rangesText = draft.ownExitRanges.join('\n');
  }
  const dirty = $derived(!!draft && deliveryChanged(draft, settings.data));

  // Listed countries, then any that left the list but keep a mapping (to clear it).
  const exitCountries = $derived(
    editorCountries(
      (censored.data?.countries ?? []).map((c) => c.code),
      draft?.exits ?? [],
    ),
  );

  const save = createMutation(() => ({
    mutationFn: (d: DeliveryDraft) =>
      apiClient.patch(
        '/api/v1/admin/settings',
        deliveryPatch(d),
        z.object({ settings: AppSettingsRecord }),
      ),
    onSuccess: (res) => {
      draft = deliveryDraft(res.settings);
      rangesText = draft.ownExitRanges.join('\n');
      void qc.invalidateQueries({ queryKey: queryKeys.adminSettings });
      void qc.invalidateQueries({ queryKey: queryKeys.config });
      // The country pages say where each country's members exit.
      void qc.invalidateQueries({ queryKey: edgeKeys.countries });
      toast.success('Delivery saved');
    },
    onError: (err) => toast.error('Could not save delivery', { description: apiErrorMessage(err) }),
  }));
</script>

<Card {id}>
  <CardHeader>
    <CardTitle class="text-base">Delivery: where members connect from</CardTitle>
    <CardDescription class="space-y-1">
      <span class="block">Where members connect from decides which addresses they get first.</span>
      <span class="block">
        A member's own choice always wins. Members who opt out are never ordered.
      </span>
    </CardDescription>
  </CardHeader>
  <CardContent class="space-y-3 text-sm">
    {#if settings.isPending || !draft}
      {#if settings.isError}
        <p class="text-destructive">
          Could not load the settings: {apiErrorMessage(settings.error)}
        </p>
      {:else}
        <Skeleton class="h-32 w-full" />
      {/if}
    {:else}
      <label class="flex items-start gap-3">
        <Checkbox
          class="mt-0.5"
          checked={draft.detect}
          disabled={save.isPending}
          onCheckedChange={(v) => draft && (draft.detect = v === true)}
        />
        <span>
          Guess the country from the connection
          <span class="text-muted-foreground block text-xs">
            Off: the country the CDN reports is used for one response and stored nowhere. On: for
            freedom members on Automatic, a censored country is kept with their key as a guess
            (shown to them and to admins, never logged, audited or sent to analytics), forgotten
            after the days below, and deleted with the key. Needs Cloudflare in front (CF_FRONTED).
          </span>
        </span>
      </label>
      <label class="flex items-start gap-3">
        <Checkbox
          class="mt-0.5"
          checked={draft.ask}
          disabled={save.isPending}
          onCheckedChange={(v) => draft && (draft.ask = v === true)}
        />
        <span>
          Ask members where they connect from
          <span class="text-muted-foreground block text-xs">
            At sign-up and when they add a mirror link (a mirror can't tell where its reader is, so
            only this answer shapes it). It is the same answer as on the account page, and
            "Somewhere else, or I'd rather not say" is always allowed. Needs a censored-country
            list.
          </span>
        </span>
      </label>
      <label class="flex items-start gap-3">
        <Checkbox
          class="mt-0.5"
          checked={draft.steer}
          disabled={save.isPending}
          onCheckedChange={(v) => draft && (draft.steer = v === true)}
        />
        <span>
          Order addresses by country
          <span class="text-muted-foreground block text-xs">
            Addresses that work there first, blocked ones only when nothing else is left. Uses the
            member's own choice or a kept guess only.
          </span>
        </span>
      </label>
      <label class="flex items-start gap-3">
        <Checkbox
          class="mt-0.5"
          checked={draft.latency}
          disabled={save.isPending}
          onCheckedChange={(v) => draft && (draft.latency = v === true)}
        />
        <span>
          Also order by distance
          <span class="text-muted-foreground block text-xs">
            Near addresses first, over the whole path from the member's country through the address
            to the node (timed by probes where they run, else from the map). The guess may then be
            any country, and another replaces it only after a day. Needs both switches above.
          </span>
        </span>
      </label>
      <div class="flex flex-wrap gap-6">
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for={`${uid}-sticky`}>
            Forget a guess after (days, {STICKY_DAYS.min} to {STICKY_DAYS.max})
          </label>
          <Input
            id={`${uid}-sticky`}
            type="number"
            min={STICKY_DAYS.min}
            max={STICKY_DAYS.max}
            class="w-32"
            disabled={save.isPending}
            value={draft.stickyDays}
            oninput={(e) =>
              draft &&
              (draft.stickyDays = clampWhole((e.target as HTMLInputElement).value, STICKY_DAYS))}
          />
        </div>
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for={`${uid}-refresh`}>
            Write a guess again at most every (hours, {REFRESH_HOURS.min} to {REFRESH_HOURS.max})
          </label>
          <Input
            id={`${uid}-refresh`}
            type="number"
            min={REFRESH_HOURS.min}
            max={REFRESH_HOURS.max}
            class="w-32"
            disabled={save.isPending}
            value={draft.refreshHours}
            oninput={(e) =>
              draft &&
              (draft.refreshHours = clampWhole(
                (e.target as HTMLInputElement).value,
                REFRESH_HOURS,
              ))}
          />
        </div>
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for={`${uid}-ranges`}>
          Extra exit ranges (CIDR, one per line)
        </label>
        <textarea
          id={`${uid}-ranges`}
          rows="3"
          class="border-input bg-background w-full max-w-md rounded-md border px-3 py-2 font-mono text-xs"
          placeholder="192.0.2.0/24"
          disabled={save.isPending}
          value={rangesText}
          oninput={(e) => {
            rangesText = (e.target as HTMLTextAreaElement).value;
            if (draft) draft.ownExitRanges = parseExitRanges(rangesText);
          }}></textarea>
        <p class="text-xs text-muted-foreground mt-1">
          A request from one of the service's own exits (a member's app refreshing through the
          tunnel) never sets a guess. Node, origin and edge addresses are known already; add ranges
          traffic leaves from otherwise (NAT, a separate egress).
        </p>
      </div>
      <div class="space-y-2">
        <p class="font-medium">Exit location for each country</p>
        <p class="text-xs text-muted-foreground">
          A new key of a member on Automatic who chose one of these countries themselves goes to the
          first of its locations that can take it, with ordering by country on. Never for a guessed
          country, and keys already issued never move by themselves: the member's account page
          offers them a one-time move instead. The location a key is on then hints at the country
          its member chose, as a location they picked would.
        </p>
        {#if exitCountries.length === 0}
          <p class="text-xs text-muted-foreground">No country is on the censored-country list.</p>
        {:else}
          <div class="space-y-2">
            {#each exitCountries as c (c.code)}
              {@const slots = slotsOf(draft.exits, c.code)}
              <div class="flex flex-wrap items-center gap-2">
                <span class="w-32 text-xs">
                  <Link
                    href={edgesPaths.country(c.code, { section: 'exit' })}
                    class="underline-offset-2 hover:underline"
                  >
                    {countryName(c.code, 'en')}
                  </Link>
                  {#if !c.listed}
                    <span class="text-muted-foreground block">
                      Not on the list: unused, but it applies again if the country is listed. Clear
                      it here.
                    </span>
                  {/if}
                </span>
                {#each Array.from({ length: EXIT_SLOTS }, (_, i) => i) as i (i)}
                  <select
                    aria-label={`${countryName(c.code, 'en')}: location ${i + 1}`}
                    class="border-input bg-background h-9 rounded-md border px-2 text-xs"
                    value={slots[i]}
                    disabled={save.isPending || (i > 0 && !slots[i - 1])}
                    onchange={(e) =>
                      draft &&
                      (draft.exits = withSlot(draft.exits, c.code, i, e.currentTarget.value))}
                  >
                    <option value="">{i === 0 ? 'Least loaded' : 'None'}</option>
                    {#each cfg.data?.locations ?? [] as l (l.code)}
                      <option value={l.code}>{l.label}</option>
                    {/each}
                  </select>
                {/each}
              </div>
            {/each}
          </div>
        {/if}
      </div>
      <div class="flex justify-end gap-2">
        {#if dirty}
          <Button variant="ghost" onclick={reset} disabled={save.isPending}>Undo changes</Button>
        {/if}
        <Button onclick={() => draft && save.mutate(draft)} disabled={!dirty || save.isPending}>
          {save.isPending ? 'Saving…' : 'Save delivery'}
        </Button>
      </div>
    {/if}
  </CardContent>
</Card>
