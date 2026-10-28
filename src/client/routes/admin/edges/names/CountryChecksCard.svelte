<script lang="ts">
  /**
   * Checks from inside countries (docs/edges.md "Checks from inside a
   * country"), on the Advanced page: the switch for `edge.sni.vantage.enabled`
   * with its residual risk beside it, the countries they run from (read only:
   * Settings, Censored countries), the services, "Apply suggestions by
   * themselves", real-site checks, and the budget in one line.
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Card, CardContent } from '@client/components/ui/card';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Label } from '@client/components/ui/label';
  import { Switch } from '@client/components/ui/switch';
  import Link from '@client/components/Link.svelte';
  import { ApiCallError } from '@client/lib/api';
  import { invalidateSni, patchSniConfig, sniConfigQuery } from '@client/lib/sniApi';
  import type { SniConfigPatch } from '../../../../../shared/contracts/sni';
  import { sniErrorWords, vantageState } from './lib/words';

  const qc = useQueryClient();
  const uid = $props.id();
  const config = sniConfigQuery();
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);

  let on = $derived(config.data?.config.enabled ?? false);
  let saving = $state(false);
  let vantage = $derived(config.data?.vantage);
  let curated = $derived(config.data?.config.curatedCountries ?? []);
  let checkedIn = $derived((vantage?.countries ?? []).filter((c) => curated.includes(c)));
  async function patchVantage(patch: NonNullable<SniConfigPatch['vantage']>, done?: string) {
    saving = true;
    try {
      await patchSniConfig({ vantage: patch });
      if (done) toast.success(done);
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
    } finally {
      saving = false;
      invalidateSni(qc);
    }
  }
</script>

{#if vantage}
  <Card class="mt-6">
    <CardContent class="space-y-4 py-5 text-sm">
      <div>
        <h2 class="text-base font-medium">Checks from inside countries</h2>
        <p class="text-muted-foreground mt-1">
          Measurement services try each name against one of your published addresses from inside the
          countries you turn on, alongside the address's other names. The name list pages then
          suggest where a name works or is blocked. You decide what is applied.
        </p>
      </div>
      <p class="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2">
        These checks run on other people's machines inside those countries, often home connections.
        Each one is a single handshake, shaped like a member's, with a name a large site really
        serves, at most once every few days per name. Nothing in it names FreeSocks, but whoever
        runs a vantage sees the address and the name. Turn a country on only if that is acceptable
        there.
      </p>
      <div class="flex items-start gap-3">
        <Switch
          id={`${uid}-vantage`}
          class="mt-0.5"
          checked={vantage.enabled}
          disabled={saving}
          onCheckedChange={(v) =>
            void patchVantage({ enabled: v }, v ? 'Checks are on.' : 'Checks are off.')}
        />
        <div>
          <Label for={`${uid}-vantage`}>Run checks</Label>
          <p class="text-muted-foreground">
            {vantageState(on, vantage.enabled, checkedIn)}
          </p>
        </div>
      </div>
      <div class="space-y-1">
        <p class="font-medium">Countries</p>
        <p class="text-muted-foreground">
          {checkedIn.length > 0 ? `${checkedIn.join(', ')}.` : 'None.'}
          These are the countries on the censored-country list with "Check names from inside" on.
          <Link href="/admin/settings" class="underline underline-offset-2">
            Change them in Settings, Censored countries.
          </Link>
        </p>
      </div>
      <fieldset class="space-y-2">
        <legend class="font-medium">Services</legend>
        <div class="flex items-center gap-2">
          <Checkbox
            id={`${uid}-gp`}
            checked={vantage.sources.globalping}
            disabled={saving}
            onCheckedChange={(v) => void patchVantage({ sources: { globalping: v === true } })}
          />
          <Label for={`${uid}-gp`} class="font-normal">Globalping</Label>
        </div>
        <div class="flex items-center gap-2">
          <Checkbox
            id={`${uid}-ra`}
            checked={vantage.sources.ripeatlas}
            disabled={saving}
            onCheckedChange={(v) => void patchVantage({ sources: { ripeatlas: v === true } })}
          />
          <Label for={`${uid}-ra`} class="font-normal">RIPE Atlas</Label>
          {#if vantage.sources.ripeatlas && !config.data?.vantageSources.ripeatlas}
            <span class="text-muted-foreground">Needs its key under Edges, Settings.</span>
          {/if}
        </div>
      </fieldset>
      <div class="flex items-start gap-3">
        <Switch
          id={`${uid}-auto`}
          class="mt-0.5"
          checked={vantage.autoApply}
          disabled={saving}
          onCheckedChange={(v) => void patchVantage({ autoApply: v })}
        />
        <div>
          <Label for={`${uid}-auto`}>Apply suggestions by themselves</Label>
          <p class="text-muted-foreground">
            Only where nobody has judged the name in that country, never over a mark an operator
            set, and never a block that would leave a node with no usable name there.
          </p>
        </div>
      </div>
      <div class="flex items-start gap-3">
        <Switch
          id={`${uid}-real`}
          class="mt-0.5"
          checked={vantage.realHost}
          disabled={saving}
          onCheckedChange={(v) =>
            void patchVantage(
              { realHost: v },
              v ? 'Real-site checks are on.' : 'Real-site checks are off.',
            )}
        />
        <div>
          <Label for={`${uid}-real`}>Also check each name against its real site</Label>
          <p class="text-muted-foreground">
            The same vantages also try each name on the site that really serves it (its public
            address, found and checked from FCP first). That tells a blocked name from a blocked
            address, and shows when the censor checks a name against its real address. It is an
            ordinary visit to that site, and it doubles the checks each batch spends. Shown on
            Countries; nothing is applied from it.
          </p>
        </div>
      </div>
      <p class="text-muted-foreground">
        At most {vantage.hourlyBudget} checks an hour, each name again after
        {vantage.intervalHours} hours, from up to {vantage.perCountryLimit} vantages.
      </p>
    </CardContent>
  </Card>
{/if}
