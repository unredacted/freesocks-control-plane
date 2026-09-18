<script lang="ts">
  /**
   * What the node role needs to register this relay: public values only, as
   * copyable lines. Tokens are minted on the API tokens page (the button deep
   * links into its create dialog, see `tokenPrefill.ts`), never shown here.
   *
   * Props:
   *   roleVars: Record<string, string> | null
   *   lastRegisteredAt?: string | null
   */
  import Link from '@client/components/Link.svelte';
  import { buttonVariants } from '@client/components/ui/button';
  import CopyButton from '../components/CopyButton.svelte';
  import { relativeTime } from '../lib/time';
  import { ApiScope } from '../../../../../shared/contracts/scopes';
  import { newTokenHref } from '../../tokenPrefill';
  import { formatRoleVars, roleVarRows } from './roleVars';

  interface Props {
    roleVars: Record<string, string> | null;
    lastRegisteredAt?: string | null;
    /** Presets for the token's registration boundary, when the origin is known. */
    backendServerId?: string | null;
    nodeName?: string | null;
  }
  let {
    roleVars,
    lastRegisteredAt = null,
    backendServerId = null,
    nodeName = null,
  }: Props = $props();

  const rows = $derived(roleVarRows(roleVars));
  const text = $derived(formatRoleVars(roleVars));
  const scope = $derived(roleVars?.['fcp_relay_register_scope'] ?? 'admin:edges:register');
  // Opens "Create API token" with the scope ticked and a name suggested.
  const tokenHref = $derived.by(() => {
    const known = ApiScope.safeParse(scope);
    const slug = roleVars?.['fcp_relay_slug'];
    return newTokenHref({
      scope: known.success ? known.data : 'admin:edges:register',
      name: slug ? `node-role-${slug}` : 'node-role',
      servers: backendServerId ? [backendServerId] : undefined,
      nodes: nodeName ? [nodeName] : undefined,
    });
  });
</script>

<div class="space-y-3">
  {#if lastRegisteredAt}
    <p class="rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm">
      The node role last registered this relay {relativeTime(lastRegisteredAt)}.
    </p>
  {:else}
    <p class="text-muted-foreground text-sm">
      The node role has not registered this relay yet. This page checks again every few seconds.
    </p>
  {/if}

  {#if rows.length > 0}
    <div class="space-y-1">
      <div class="flex items-center justify-between gap-2">
        <h4 class="text-sm font-medium">Role variables</h4>
        <CopyButton value={text} label="Copy the role variables" />
      </div>
      <!-- svelte-ignore a11y_no_noninteractive_tabindex (a scrollable region must be keyboard reachable) -->
      <pre
        class="bg-muted overflow-x-auto rounded-md p-2 text-xs leading-relaxed"
        tabindex="0">{text}</pre>
      <dl class="text-muted-foreground space-y-0.5 text-xs">
        {#each rows.filter((r) => r.label) as r (r.key)}
          <div class="flex gap-1.5">
            <dt class="font-mono">{r.key}</dt>
            <dd>{r.label}</dd>
          </div>
        {/each}
      </dl>
    </div>
  {/if}

  <div class="space-y-1.5 text-sm">
    <p>
      The role needs an API token with the scope
      <span class="font-mono">{scope}</span>, confined to this relay. The button opens the API
      tokens page with that scope chosen and a name suggested: a token is shown once and never
      appears on this page.
    </p>
    <Link href={tokenHref} class={buttonVariants({ size: 'sm', variant: 'outline' })}>
      Mint role token
    </Link>
  </div>
</div>
