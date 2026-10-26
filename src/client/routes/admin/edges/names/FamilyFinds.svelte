<script lang="ts">
  /**
   * "Find more names" on a family's page (docs/edges.md "Finding names"): the
   * names on its target's certificate (FCP talks only to that target), the
   * certificate logs of the target's site, and what was found for it, to add
   * through the family's normal path.
   *
   * All wording lives in ./lib/huntWords.ts (pure, unit-tested).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Card, CardContent, CardHeader, CardTitle } from '@client/components/ui/card';
  import { ApiCallError } from '@client/lib/api';
  import { huntFamilyQuery, invalidateSni, lookUpCt, readTargetCert } from '@client/lib/sniApi';
  import HuntTable from './HuntTable.svelte';
  import { ctWords } from './lib/huntWords';
  import { CHECK_WORDS, sniErrorWords } from './lib/words';

  let { slug, label, target }: { slug: string; label: string; target: string } = $props();
  const qc = useQueryClient();
  const view = huntFamilyQuery(() => slug);
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);
  const literal = $derived(/^[0-9.]+$/.test(target) || target.includes(':'));

  let busy = $state(false);
  async function readCert() {
    busy = true;
    try {
      const r = await readTargetCert(slug);
      if (r.ok)
        toast.success(
          `The certificate lists ${r.listed} ${r.listed === 1 ? 'name' : 'names'}: ${r.added} new, ${r.known} already found, ${r.inFamily} already in a family.`,
        );
      else toast.error(CHECK_WORDS[r.code ?? ''] ?? 'The target could not be read.');
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateSni(qc);
    }
  }
  async function readLogs() {
    busy = true;
    try {
      const r = await lookUpCt([target], { family: slug });
      toast.success(
        r.queued > 0 ? 'Reading the certificate logs.' : 'Already read in full this week.',
      );
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateSni(qc);
    }
  }
</script>

<Card class="mt-6">
  <CardHeader class="flex flex-row flex-wrap items-center justify-between gap-2">
    <CardTitle class="text-base">Find more names</CardTitle>
    <div class="flex flex-wrap gap-2">
      <Button variant="outline" size="sm" disabled={busy} onclick={readCert}>
        Read the target's certificate
      </Button>
      {#if !literal}
        <Button variant="outline" size="sm" disabled={busy} onclick={readLogs}>
          Look up certificate logs
        </Button>
      {/if}
    </div>
  </CardHeader>
  <CardContent class="space-y-3 text-sm">
    <p class="text-muted-foreground">
      Names the target may serve. Each is checked against this family's target before it shows as
      ready, and adding it checks it again like any name you paste.
    </p>
    {#if view.isError}
      <p class="text-destructive">{sniErrorWords(codeOf(view.error))}</p>
    {:else if view.data}
      {#if view.data.ct.length > 0}
        <ul class="text-muted-foreground">
          {#each view.data.ct as r (r.domain)}
            <li>{ctWords(r)}</li>
          {/each}
        </ul>
      {/if}
      {#if view.data.counts.new + view.data.counts.failing + view.data.counts.gone + view.data.counts.ignored + view.data.counts.added === 0}
        <p class="text-muted-foreground">Nothing found for it yet.</p>
      {:else}
        <HuntTable kind="family" {slug} families={[{ slug, label }]} />
      {/if}
    {/if}
  </CardContent>
</Card>
