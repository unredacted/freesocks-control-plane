<script lang="ts">
  /**
   * Admin -> Users -> Live details: where a member connects from, per active key
   * (convex/memberCountry.ts `adminView`). The country, where it came from (their
   * choice or a guess from the connection), first and last seen, the member's
   * choice, the key's mode family, and what their last render handed out. Read
   * sealed; never audited (docs/privacy.md).
   *
   * Props: userId: string
   */
  import { adminMemberCountryQuery } from '../../lib/queries';
  import { countryName } from '../../lib/countries';
  import { formatDateTime } from '../../lib/i18n/format';
  import { sealingEnabled } from '../../lib/hpke';

  interface Props {
    userId: string;
  }
  let { userId }: Props = $props();

  const canSeal = sealingEnabled();
  const view = adminMemberCountryQuery(
    () => userId,
    () => canSeal,
  );
  const name = (code: string) => `${countryName(code, 'en')} (${code})`;
  const choiceWords = (c: string | null) =>
    c === null ? 'Automatic' : c === 'ZZ' ? 'Somewhere else' : name(c);
</script>

<div class="mt-2 space-y-1 border-t border-border pt-2">
  <div class="font-medium text-foreground">Where they connect from</div>
  {#if !canSeal}
    <p class="text-muted-foreground">Needs a build with sealing (HPKE) keys.</p>
  {:else if view.isPending}
    <p class="text-muted-foreground">Loading…</p>
  {:else if view.isError || !view.data}
    <p class="text-muted-foreground">Couldn't load it.</p>
  {:else if view.data.keys.length === 0}
    <p class="text-muted-foreground">No active key.</p>
  {:else}
    {#each view.data.keys as k, i (i)}
      <div class="text-muted-foreground">
        {#if view.data.keys.length > 1}
          <span class="text-foreground">{k.current ? 'Current key' : 'Other key'}:</span>
        {/if}
        {#if !k.applies}
          Not used: the key's mode is {k.family === 'privacy'
            ? 'privacy-family'
            : 'one without a country'}.
        {:else}
          <span class="text-foreground">{k.effective ? name(k.effective) : 'Elsewhere'}</span>
          {#if k.source === 'choice'}
            · their choice ({choiceWords(k.choice)})
          {:else if k.source === 'guess' && k.guess}
            · guessed from the connection, first seen {formatDateTime(k.guess.firstAt)}, last seen
            {formatDateTime(k.guess.lastAt)}; their choice: Automatic
          {:else}
            · nothing stored; their choice: Automatic{view.data.detect ? '' : ' (guessing is off)'}
          {/if}
          {#if k.delivered}
            <div>
              Last delivery {formatDateTime(k.delivered.at)}: primary {k.delivered.primary ??
                'none'}{k.delivered.backup ? `, backup ${k.delivered.backup}` : ''}
            </div>
          {/if}
        {/if}
      </div>
    {/each}
  {/if}
</div>
