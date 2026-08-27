<script lang="ts">
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Input } from '@client/components/ui/input';
  import * as Select from '@client/components/ui/select';
  import { t, getLocale } from '../lib/i18n/index.svelte';
  import { COUNTRY_CODES, countryName } from '../lib/countries';
  import type { TelemetryContextResponse } from '../../shared/contracts/telemetry';

  /**
   * The consent block shared by SwitchServerModal and ReportIssueModal: an
   * on-by-default checkbox plus the exact values that would be sent, EDITABLE.
   * Prefilled from what the CDN edge detected - which is wrong by construction
   * when the member is connected through the VPN while reporting (the edge sees
   * the exit node's network), so the copy says to correct them. Everything here
   * is optional; unchecking sends the reason alone.
   *
   * The parent reads the outcome via `payload()` (null = declined). Fields the
   * deployment doesn't collect never render, so the disclosure can't overstate.
   */
  interface Props {
    /** From telemetryContextQuery; undefined while loading (block hidden). */
    context: TelemetryContextResponse | undefined;
    busy?: boolean;
  }
  let { context, busy = false }: Props = $props();

  const locale = getLocale();
  let send = $state(true);
  let country = $state('');
  let city = $state('');
  let asn = $state('');

  // Seed the editable fields ONCE from the detected values (later refetches
  // must not clobber what the member typed).
  let seeded = $state(false);
  $effect(() => {
    if (!seeded && context) {
      seeded = true;
      country = context.detected.country ?? '';
      city = context.detected.city ?? '';
      asn = context.detected.asn !== null ? String(context.detected.asn) : '';
    }
  });

  const regions = COUNTRY_CODES.map((c) => ({ code: c, name: countryName(c, locale) })).sort(
    (a, b) => a.name.localeCompare(b.name, locale),
  );
  const countryLabel = $derived(
    country ? (regions.find((r) => r.code === country)?.name ?? country) : t('telemetry.notSet'),
  );

  /** What the parent should send: null = declined / nothing to send. */
  export function payload(): {
    country: string | null;
    city: string | null;
    asn: string | null;
  } | null {
    if (!context?.enabled || !send) return null;
    return {
      country: context.fields.country && country ? country : null,
      city: context.fields.city && city.trim() ? city.trim() : null,
      asn: context.fields.asn && asn.trim() ? asn.trim() : null,
    };
  }

  const anyField = $derived(
    !!context?.enabled && (context.fields.country || context.fields.city || context.fields.asn),
  );
</script>

{#if anyField && context}
  <div class="space-y-3 rounded-lg border border-border/60 bg-muted/30 p-3">
    <label class="flex items-start gap-3">
      <Checkbox checked={send} onCheckedChange={(v) => (send = v === true)} disabled={busy} />
      <span class="min-w-0">
        <span class="block text-sm font-medium">{t('telemetry.sendLabel')}</span>
        <span class="mt-0.5 block text-xs text-muted-foreground">
          {t('telemetry.sendExplainer')}
        </span>
      </span>
    </label>

    {#if send}
      <div class="grid gap-2 sm:grid-cols-3">
        {#if context.fields.country}
          <div>
            <label
              class="mb-1 block truncate text-xs text-muted-foreground"
              for="telemetry-country"
            >
              {t('telemetry.countryLabel')}
            </label>
            <Select.Root
              type="single"
              value={country}
              onValueChange={(v) => (country = v ?? '')}
              disabled={busy}
            >
              <Select.Trigger id="telemetry-country" class="w-full">{countryLabel}</Select.Trigger>
              <Select.Content class="max-h-72 overflow-y-auto">
                <Select.Item value="">{t('telemetry.notSet')}</Select.Item>
                {#each regions as r (r.code)}
                  <Select.Item value={r.code}>{r.name}</Select.Item>
                {/each}
              </Select.Content>
            </Select.Root>
          </div>
        {/if}
        {#if context.fields.city}
          <div>
            <label class="mb-1 block truncate text-xs text-muted-foreground" for="telemetry-city">
              {t('telemetry.cityLabel')}
            </label>
            <Input
              id="telemetry-city"
              value={city}
              maxlength={64}
              disabled={busy}
              oninput={(e) => (city = (e.target as HTMLInputElement).value)}
            />
          </div>
        {/if}
        {#if context.fields.asn}
          <div>
            <label class="mb-1 block truncate text-xs text-muted-foreground" for="telemetry-asn">
              {t('telemetry.asnLabel')}
            </label>
            <Input
              id="telemetry-asn"
              value={asn}
              placeholder="AS44244"
              disabled={busy}
              oninput={(e) => (asn = (e.target as HTMLInputElement).value)}
            />
          </div>
        {/if}
      </div>
      <!-- The dirty-data warning: reporting through the VPN means the prefill
           shows OUR server's network, not theirs. -->
      <p class="text-xs text-muted-foreground">{t('telemetry.editHint')}</p>
    {/if}
  </div>
{/if}
