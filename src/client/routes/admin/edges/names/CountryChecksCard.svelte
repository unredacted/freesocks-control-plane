<script lang="ts">
  /**
   * Checks from inside countries (docs/edges.md "Checks from inside a
   * country"), the SNIs tab's "Checks from inside countries" view
   * (`/admin/servers/snis/checks`): the switch for `edge.sni.vantage.enabled`
   * with its residual risk beside it, the countries they run from (read only:
   * changed on the Countries tab), the services, "Apply suggestions by
   * themselves", real-site checks, and the budget in one line (its numbers
   * are under SNIs, More settings).
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
  import SectionHeader from '../components/SectionHeader.svelte';
  import { edgesPaths } from '../lib/routes';
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

<SectionHeader
  title="Checks from inside countries"
  description="Measurement services try each SNI on one of your published addresses from inside the countries you turn on. SNI list pages then suggest where an SNI works or is blocked, and you decide what is applied."
/>

{#if config.isPending}
  <p class="text-muted-foreground text-sm">Loading…</p>
{:else if config.isError}
  <p class="text-destructive text-sm">{sniErrorWords(codeOf(config.error))}</p>
{:else if vantage}
  <Card>
    <CardContent class="space-y-4 py-5 text-sm">
      <p class="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2">
        These checks run on other people's machines in those countries, often home connections. Each
        is one member-like handshake with an SNI a large site serves, at most every few days per
        SNI. Nothing in it names FreeSocks, but whoever runs a vantage sees the address and the SNI.
        Turn a country on only if that is acceptable there.
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
          These are the countries on the censored-country list with "Check SNIs from inside" on.
          <Link href={edgesPaths.countries()} class="underline underline-offset-2">
            Change them on the Countries tab.
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
            <span class="text-muted-foreground">
              Needs its key under
              <Link
                href={edgesPaths.settings({ section: 'probes' })}
                class="underline underline-offset-2">Settings, Probes</Link
              >.
            </span>
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
            Only where nobody has judged the SNI in that country. Never over an operator's mark, and
            never a block that would leave a node with no usable SNI there.
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
          <Label for={`${uid}-real`}>Also check each SNI against its real site</Label>
          <p class="text-muted-foreground">
            The same vantages also try each SNI on its real site. That tells a blocked SNI from a
            blocked address. It is an ordinary visit to that site, but it doubles the checks each
            batch spends. Results show on Countries and are never applied.
          </p>
        </div>
      </div>
      <p class="text-muted-foreground">
        At most {vantage.hourlyBudget} checks an hour, each SNI again after
        {vantage.intervalHours} hours, from up to {vantage.perCountryLimit} vantages.
        <Link href={edgesPaths.sniSettings()} class="underline underline-offset-2">
          Change these numbers.
        </Link>
      </p>
    </CardContent>
  </Card>
{/if}
