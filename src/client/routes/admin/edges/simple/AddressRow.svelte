<script lang="ts">
  /**
   * One address of a node, as one row (words: addressWords.ts): a health dot,
   * its forms (IPv4 and IPv6 side by side, or the name a CDN front answers
   * on), what it is (In use, Spare, Retiring) and whether it is tested, and
   * every checked country in one short line grouped by what it counts as
   * there. The main action sits on the row (Test it, Put in use, Delete now);
   * Details opens the rest: the provider's and the outside checks, FCP's
   * client check, each country in full with its Countries menu
   * (EdgeCountryActions), "Check with FCP's client" and "Keep as a spare".
   *
   * Props:
   *   edge: EdgeAdmin
   *   transport?: string | null       its transport in words (only when the node has several)
   *   lanes?: boolean                 address lanes are on: an address in use says its lane
   *   countries?: EdgeCountriesResponse | null   the checks from each country (absent = not shown)
   *   onTest: (edgeId) => void
   *   publishable?: boolean           the server names this spare as the one to put in use now
   *   onPublish?: () => void
   *   onRetiring?: (edge, 'delete' | 'keep') => void   absent = no drain actions
   */
  import type { EdgeAdmin, EdgeCountriesResponse } from '@shared/contracts/edges';
  import { useQueryClient } from '@tanstack/svelte-query';
  import { slide } from 'svelte/transition';
  import { toast } from 'svelte-sonner';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import { Button } from '@client/components/ui/button';
  import { clientCheckEdge, clientCheckStatusQuery, edgeKeys } from '@client/lib/edgesApi';
  import { PLAIN_ATTENTION_ACTION_LABELS, type Tone } from '@client/lib/edgeCodes';
  import { cn } from '@client/lib/utils';
  import EdgeCountryActions from '../components/EdgeCountryActions.svelte';
  import { edgeCountryLines } from '../lib/countryChecks';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import {
    addressDot,
    addressForms,
    addressHealthLine,
    addressStateWord,
    countrySummary,
    testedWord,
  } from './addressWords';
  import { clientCheckLine, clientCheckToast } from './clientCheckWords';
  import { endNowWords, retiringWords } from './drainWords';
  import StatusDot from './StatusDot.svelte';

  interface Props {
    edge: EdgeAdmin;
    transport?: string | null;
    lanes?: boolean;
    countries?: EdgeCountriesResponse | null;
    onTest: (edgeId: string) => void;
    publishable?: boolean;
    onPublish?: () => void;
    onRetiring?: (edge: EdgeAdmin, action: 'delete' | 'keep') => void;
  }
  let {
    edge: e,
    transport = null,
    lanes = false,
    countries = null,
    onTest,
    publishable = false,
    onPublish,
    onRetiring,
  }: Props = $props();

  const uid = $props.id();
  const qc = useQueryClient();
  const clientCheckStatus = clientCheckStatusQuery();
  const canClientCheck = $derived(clientCheckStatus.data?.configured === true);

  const retiring = $derived(e.publication === 'draining' || e.status === 'destroying');
  const r = $derived(retiring ? retiringWords(e) : null);
  const forms = $derived(addressForms(e));
  const tested = $derived(testedWord(e, retiring));
  const checkLine = $derived(retiring ? null : clientCheckLine(e.clientCheck));

  let now = $state(Date.now());
  $effect(() => {
    const t = setInterval(() => (now = Date.now()), 30_000);
    return () => clearInterval(t);
  });
  const groups = $derived(
    countries && !retiring ? countrySummary(edgeCountryLines(countries, e.id), now) : [],
  );

  const TONE_TEXT: Record<Tone, string> = {
    success: 'text-emerald-700 dark:text-emerald-400',
    danger: 'text-destructive',
    warning: 'text-amber-700 dark:text-amber-400',
    info: 'text-sky-700 dark:text-sky-300',
    neutral: 'text-foreground',
    muted: 'text-muted-foreground',
  };

  let open = $state(false);
  let checking = $state(false);
  async function clientCheck() {
    checking = true;
    try {
      const t = clientCheckToast(await clientCheckEdge(e.id));
      toast[t.tone](t.title, { description: t.body });
      await qc.invalidateQueries({ queryKey: edgeKeys.all });
    } catch (err) {
      toast.error(edgeErrorMessage(err));
    } finally {
      checking = false;
    }
  }

  const LINK = 'h-auto min-h-11 p-0 sm:min-h-0';
</script>

<li class="py-2.5 first:pt-1 last:pb-1">
  <div class="flex flex-wrap items-start gap-x-3 gap-y-1">
    <StatusDot dot={retiring ? 'grey' : addressDot(e)} class="mt-1.5" />
    <div class="min-w-0 flex-1 space-y-0.5">
      <p class="flex flex-wrap items-baseline gap-x-3 gap-y-0.5">
        <span class="font-mono text-xs break-all">{forms.main}</span>
        {#each forms.others as a (a)}
          <span class="text-muted-foreground font-mono text-xs break-all">{a}</span>
        {/each}
      </p>
      <!-- Spaces as {' '} expressions: Svelte drops the whitespace at the edges of a tag. -->
      <p class="text-muted-foreground text-xs">
        <span class="text-foreground">{r ? r.word : addressStateWord(e, lanes)}</span
        >{#if tested}{', '}<span class={tested.needsTest ? TONE_TEXT.warning : ''}
            >{tested.word}</span
          >{/if}{#if transport}{' · '}{transport}{/if}{#if r}{'. '}{r.line}{/if}
      </p>
      {#if groups.length > 0}
        <p class="text-xs">
          {#each groups as g, i (g.label)}{#if i > 0}<span
                class="text-muted-foreground"
                aria-hidden="true">{' · '}</span
              >{/if}<span class={TONE_TEXT[g.tone]}>{g.label}:</span
            >{#each g.countries as c (c.code)}{' '}<abbr class="no-underline" title={c.title}
                >{c.code}</abbr
              >{/each}{/each}
        </p>
      {/if}
    </div>
    <div class="flex flex-wrap items-center gap-x-3">
      {#if tested?.needsTest}
        <Button variant="link" size="sm" class={LINK} onclick={() => onTest(e.id)}>Test it</Button>
      {/if}
      {#if publishable && onPublish}
        <Button variant="link" size="sm" class={LINK} onclick={onPublish}>
          {PLAIN_ATTENTION_ACTION_LABELS.publish}
        </Button>
      {/if}
      {#if r && onRetiring && r.canDelete}
        <Button
          variant="link"
          size="sm"
          class={cn(LINK, 'text-destructive')}
          onclick={() => onRetiring(e, 'delete')}
        >
          {endNowWords(e, forms.main).label}
        </Button>
      {/if}
      <Button
        variant="ghost"
        size="sm"
        class="h-11 px-2 text-xs sm:h-7"
        aria-expanded={open}
        aria-controls={`${uid}-details`}
        onclick={() => (open = !open)}
      >
        Details
        <ChevronDown
          class={cn('transition-transform motion-reduce:transition-none', open && 'rotate-180')}
          aria-hidden="true"
        />
      </Button>
    </div>
  </div>
  {#if open}
    <div
      id={`${uid}-details`}
      class="ms-[1.375rem] mt-2 space-y-1.5 border-s ps-3"
      transition:slide={{ duration: 160 }}
    >
      <p class="text-muted-foreground text-xs">{addressHealthLine(e)}</p>
      {#if checkLine}<p class="text-muted-foreground text-xs">{checkLine}</p>{/if}
      {#if (canClientCheck && !retiring && e.layer !== 'l7') || (r && onRetiring && r.canKeep)}
        <div class="flex flex-wrap gap-x-4">
          {#if canClientCheck && !retiring && e.layer !== 'l7'}
            <Button
              variant="link"
              size="sm"
              class={LINK}
              disabled={checking}
              onclick={() => void clientCheck()}
            >
              {checking ? 'Checking...' : "Check with FCP's client"}
            </Button>
          {/if}
          {#if r && onRetiring && r.canKeep}
            <Button variant="link" size="sm" class={LINK} onclick={() => onRetiring(e, 'keep')}>
              Keep as a spare
            </Button>
          {/if}
        </div>
      {/if}
      {#if countries && !retiring}
        <EdgeCountryActions edgeId={e.id} name={forms.main} data={countries} />
      {/if}
    </div>
  {/if}
</li>
