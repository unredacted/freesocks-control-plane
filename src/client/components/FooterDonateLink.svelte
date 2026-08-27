<script lang="ts">
  import Link from './Link.svelte';
  import { configQuery, meQuery } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';

  /**
   * Footer "Donate" link, routed IN-APP (a signed-in member lands on their
   * account's Membership tab, an anonymous visitor on the public /donate page,
   * which offers sign-in or an anonymous gift) so gifts go through FreeSocks
   * and feed the free-user bandwidth pool - never to the external nonprofit
   * donate page, which confused people about where to give. Its own component
   * (not inline in App.svelte's footer) because App hosts the
   * QueryClientProvider, so configQuery()/meQuery() can only run from a child
   * inside the provider tree (the FooterRepoLink pattern). Hidden entirely
   * while in-app donations are disabled.
   */
  const cfg = configQuery();
  const me = meQuery();
  const enabled = $derived(!!cfg.data?.billing?.enabled && !!cfg.data.billing.donation?.enabled);
  const href = $derived(me.data?.authenticated ? '/account?tab=membership' : '/donate');
</script>

{#if enabled}
  <Link class="hover:text-foreground" {href}>
    {t('renew.donate')}
  </Link>
{/if}
