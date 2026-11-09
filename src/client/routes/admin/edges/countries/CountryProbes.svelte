<script lang="ts">
  /**
   * The country page's "Probes" section: which outside probe sources answer
   * from here (and why one went quiet), then the Probes tab's reachability
   * matrix with only this country's column (plus FCP's own check). Probe now
   * and run history work as on the Probes tab, which stays its own tab.
   *
   * Props:
   *   code: string                 the country (ISO 3166-1 alpha-2)
   *   view: CountryViewResponse
   */
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import Link from '@client/components/Link.svelte';
  import { probeMatrixQuery } from '@client/lib/edgesApi';
  import type { CountryViewResponse } from '@shared/contracts/edges';
  import ProbeMatrix from '../probes/ProbeMatrix.svelte';
  import { edgesPaths } from '../lib/routes';
  import { countryLabel, coverageLines } from './words';

  interface Props {
    code: string;
    view: CountryViewResponse;
  }
  let { code, view: v }: Props = $props();

  // The same read the matrix makes (one cache entry): is this country a column?
  const matrix = probeMatrixQuery();
  const probedHere = $derived((matrix.data?.countries ?? []).includes(code));
  const lines = $derived(coverageLines(v.probes, v.sources, v.switches.probes, v.generatedAt));
</script>

<div class="space-y-6">
  <Card>
    <CardHeader>
      <CardTitle class="text-base">Probes from {countryLabel(code)}</CardTitle>
      <CardDescription>
        Whether networks here reach FCP's addresses. The
        <Link href={edgesPaths.probes()} class="underline underline-offset-2">Probes tab</Link>
        shows every country, the sources and custom targets.
      </CardDescription>
    </CardHeader>
    <CardContent class="space-y-1 text-sm">
      {#if !v.switches.probes}
        <p class="text-muted-foreground">
          Probes are off: nothing measures the addresses from outside.
          <Link
            href={edgesPaths.settings({ section: 'probes' })}
            class="underline underline-offset-2"
          >
            Probe settings
          </Link>
        </p>
      {/if}
      {#each lines as line (line)}<p class="text-muted-foreground">{line}</p>{/each}
      {#if matrix.data && !probedHere}
        <p class="text-muted-foreground">
          The matrix has no column for this country yet.
          <Link href={edgesPaths.country(code, { section: 'checks' })} class="underline">
            Checks from here
          </Link>
        </p>
      {/if}
    </CardContent>
  </Card>

  <Card>
    <CardContent class="pt-6">
      <ProbeMatrix country={code} />
    </CardContent>
  </Card>
</div>
