<script lang="ts">
  /**
   * An allowlist's "Prefer its SNIs" (docs/edges.md "Names on a country's
   * allowlist"): the switch, why nothing is preferred when it is on and
   * something holds it back, and how many SNIs in use the list holds. Turning
   * it on changes what members in the list's country get, so it asks first.
   *
   * Props:
   *   list: CountryListView    an allowlist
   *   listsOn: boolean         `edge.lists.enabled`
   *   preferSwitch: boolean    `edge.lists.preferNames`
   *   counts: CountryListDetail['prefer']
   * All wording lives in ./listWords.ts (pure, unit-tested).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Card, CardContent } from '@client/components/ui/card';
  import { Switch } from '@client/components/ui/switch';
  import Link from '@client/components/Link.svelte';
  import { ApiCallError } from '@client/lib/api';
  import { invalidateCountryLists, updateCountryList } from '@client/lib/countryListsApi';
  import type { CountryListDetail, CountryListView } from '@shared/contracts/countryLists';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { edgesPaths } from '../lib/routes';
  import {
    listErrorWords,
    preferConfirm,
    preferCountsLine,
    preferLine,
    preferNetworksLine,
    preferWaitsLine,
    PREFER_RULES,
  } from './listWords';

  let {
    list,
    listsOn,
    preferSwitch,
    counts,
  }: {
    list: CountryListView;
    listsOn: boolean;
    preferSwitch: boolean;
    counts: CountryListDetail['prefer'];
  } = $props();
  const qc = useQueryClient();
  const uid = $props.id();
  let busy = $state(false);
  let asking = $state(false);

  async function setPrefer(on: boolean) {
    busy = true;
    try {
      await updateCountryList(list.id, { preferNames: on });
      toast.success(on ? 'Its SNIs are preferred now.' : 'No longer preferred.');
    } catch (e) {
      toast.error(listErrorWords(e instanceof ApiCallError ? e.payload.error.code : null));
    } finally {
      busy = false;
      invalidateCountryLists(qc);
    }
  }

  const waits = $derived(
    list.preferNames
      ? preferWaitsLine(list, { listsOn, preferSwitch, curated: counts?.curated ?? true })
      : null,
  );
  const networks = $derived(preferNetworksLine(list));
  const confirm = $derived(preferConfirm(counts, list.country));
</script>

<Card class="mt-4">
  <CardContent class="space-y-2 py-5 text-sm">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div class="min-w-0 flex-1">
        <h2 class="text-base font-medium">
          <label for={`${uid}-prefer`}>Prefer its SNIs</label>
        </h2>
        <p class="text-muted-foreground">{preferLine(list.preferNames, list.country, !waits)}</p>
      </div>
      <Switch
        id={`${uid}-prefer`}
        checked={list.preferNames}
        disabled={busy}
        onCheckedChange={(on) => {
          if (on) asking = true;
          else void setPrefer(false);
        }}
      />
    </div>
    {#if waits}
      <p class="text-amber-700 dark:text-amber-400">
        {waits}
        {#if !preferSwitch}
          <Link
            href={edgesPaths.settings({ section: 'lists' })}
            class="underline underline-offset-2"
          >
            Open Settings.
          </Link>
        {/if}
      </p>
    {/if}
    <p>{preferCountsLine(counts, list.country)}</p>
    {#if networks}
      <p class="text-muted-foreground">{networks}</p>
    {/if}
    <p class="text-muted-foreground">{PREFER_RULES}</p>
  </CardContent>
</Card>

<ConfirmDialog
  bind:open={asking}
  title={confirm.title}
  body={confirm.body}
  confirmLabel={confirm.confirmLabel}
  onConfirm={() => setPrefer(true)}
/>
