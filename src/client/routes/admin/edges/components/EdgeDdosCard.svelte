<script lang="ts">
  /**
   * An edge's paid DDoS protection at its provider (capability
   * `ddosProtection`; Gcore's Advanced DDoS protection). Nothing is read until
   * the operator asks: each read is a provider call. Then: whether the region
   * offers it, the provider's price, the profile on each address, and turning
   * it on (with a profile and BGP), off, or removing it.
   *
   * Props:
   *   edgeId: string
   *   canChange: boolean   the address is up and FCP's to change (managed, live states)
   */
  import { createMutation } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import RefreshCw from '@lucide/svelte/icons/refresh-cw';
  import type { EdgeDdosAction, EdgeDdosView } from '@shared/contracts/edges';
  import { Button } from '@client/components/ui/button';
  import { Badge } from '@client/components/ui/badge';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Label } from '@client/components/ui/label';
  import InlineError from '@client/components/InlineError.svelte';
  import { ApiCallError } from '@client/lib/api';
  import { changeEdgeDdos, fetchEdgeDdos } from '@client/lib/edgesApi';
  import { EDGE_CODE_COPY, codeFix, codeLabel } from '@client/lib/edgeCodes';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import ConfirmDialog from './ConfirmDialog.svelte';

  interface Props {
    edgeId: string;
    canChange: boolean;
  }
  let { edgeId, canChange }: Props = $props();

  const SELECT = 'border-border bg-background min-h-9 rounded-md border px-2 py-1.5 text-sm';

  let view = $state<EdgeDdosView | null>(null);
  let profileChoice = $state('');
  let bgp = $state(true);
  let confirmRemove = $state(false);

  // A new edge in the drawer starts unread.
  $effect(() => {
    void edgeId;
    view = null;
    profileChoice = '';
    bgp = true;
  });

  /** The adapter's `ddos_*` codes arrive bare: word them like any edge code. */
  function failure(err: unknown): string {
    if (err instanceof ApiCallError && err.status !== 0 && err.status !== 429) {
      const code = err.payload.error.code.replace(/^edge\./, '');
      if (EDGE_CODE_COPY[code]) {
        const fix = codeFix(code);
        return fix ? `${codeLabel(code)}. ${fix}` : `${codeLabel(code)}.`;
      }
    }
    return edgeErrorMessage(err);
  }

  function take(v: EdgeDdosView) {
    view = v;
    const current = v.profiles.find((p) => p.address === v.addresses.v4) ?? v.profiles[0];
    profileChoice =
      current?.templateId != null
        ? String(current.templateId)
        : v.templates.length === 1 && v.templates[0]!.fieldsNeeded.length === 0
          ? String(v.templates[0]!.id)
          : '';
    bgp = current?.bgp ?? true;
  }

  const read = createMutation(() => ({
    mutationFn: (id: string) => fetchEdgeDdos(id),
    onSuccess: (v, id) => {
      if (id === edgeId) take(v);
    },
  }));

  const DONE_WORDS: Record<EdgeDdosAction, string> = {
    enable: 'DDoS protection is on',
    disable: 'DDoS protection is off',
    remove: 'DDoS protection removed',
  };
  const change = createMutation(() => ({
    mutationFn: (a: { id: string; action: EdgeDdosAction }) =>
      changeEdgeDdos(a.id, {
        action: a.action,
        // The template only when it changes (or there is no profile yet): a
        // BGP or on/off change keeps the profile's own without re-reading the list.
        ...(a.action === 'enable' && profileChoice && (!profile || changingTemplate)
          ? { profileTemplate: profileChoice }
          : {}),
        ...(a.action === 'enable' ? { bgp } : {}),
      }),
    onSuccess: (res, a) => {
      if (a.id === edgeId && res.view) take(res.view);
      if (res.state === 'pending')
        toast.info(
          a.action === 'enable'
            ? 'The provider is still applying it. FCP finishes turning it on by itself; check again in a few minutes.'
            : 'The provider is still applying it. Check again in a minute.',
        );
      else if (res.state === 'unchanged') toast.info('Nothing to change.');
      else toast.success(DONE_WORDS[a.action]);
    },
  }));

  const readError = $derived(
    read.isError && read.variables === edgeId ? failure(read.error) : null,
  );
  const changeError = $derived(
    change.isError && change.variables?.id === edgeId ? failure(change.error) : null,
  );
  const busy = $derived(read.isPending || change.isPending);
  const profile = $derived(
    view ? (view.profiles.find((p) => p.address === view!.addresses.v4) ?? null) : null,
  );
  const changingTemplate = $derived(
    !!profile && profileChoice !== '' && String(profile.templateId ?? '') !== profileChoice,
  );
  const bgpChanged = $derived(!!profile && profile.bgp !== null && profile.bgp !== bgp);
  const enableLabel = $derived(
    !profile ? 'Turn on' : profile.active && (changingTemplate || bgpChanged) ? 'Apply' : 'Turn on',
  );
  const canEnable = $derived(
    canChange &&
      view !== null &&
      view.available !== false &&
      (profileChoice !== '' || view.templates.length === 0) &&
      (!profile || !profile.active || changingTemplate || bgpChanged),
  );

  const statusWord = (p: EdgeDdosView['profiles'][number]): string =>
    p.active === true ? 'On' : p.active === false ? 'Off' : 'Unknown';
  const money = (n: number, currency: string | null) =>
    currency ? `${n.toLocaleString(undefined, { maximumFractionDigits: 2 })} ${currency}` : `${n}`;
</script>

<section class="space-y-3" aria-labelledby="edge-ddos-title">
  <div class="flex flex-wrap items-start justify-between gap-2">
    <div>
      <h3 id="edge-ddos-title" class="text-sm font-semibold">DDoS protection</h3>
      <p class="text-muted-foreground text-xs">
        The provider's paid Advanced DDoS protection on this address. Reading it asks the provider.
      </p>
    </div>
    <Button size="sm" variant="outline" disabled={busy} onclick={() => read.mutate(edgeId)}>
      <RefreshCw class={read.isPending ? 'animate-spin' : ''} aria-hidden="true" />
      {read.isPending ? 'Checking…' : view ? 'Check again' : 'Check protection'}
    </Button>
  </div>

  {#if readError}
    <InlineError message={readError} />
  {/if}

  {#if view}
    <ul class="space-y-1 text-sm">
      <li>
        Region:
        {#if view.available === true}
          <span>offers it</span>
        {:else if view.available === false}
          <span class="text-destructive">does not offer it</span>
        {:else}
          <span class="text-muted-foreground">the provider did not say</span>
        {/if}
      </li>
      {#if view.price?.per30d != null}
        <li class="text-muted-foreground text-xs">
          The provider lists {money(view.price.per30d, view.price.currency)} per 30 days for each protected
          address{view.price.feature ? ` (${view.price.feature})` : ''}.
        </li>
      {/if}
      {#if view.unread.length > 0}
        <li class="text-muted-foreground text-xs">
          Could not read: {view.unread.join(', ')}.
        </li>
      {/if}
    </ul>

    {#if view.profiles.length === 0}
      <p class="text-sm">Not protected.</p>
    {:else}
      <ul class="space-y-2 text-sm">
        {#each view.profiles as p (p.id)}
          <li class="space-y-0.5">
            <div class="flex flex-wrap items-center gap-2">
              <span class="font-mono text-xs">{p.address}</span>
              <Badge variant={p.active ? 'default' : 'outline'}>{statusWord(p)}</Badge>
              {#if p.status}<span class="text-muted-foreground text-xs">{p.status}</span>{/if}
            </div>
            <p class="text-muted-foreground text-xs">
              Profile {p.templateName ??
                (p.templateId != null ? `#${p.templateId}` : 'unknown')}{p.bgp !== null
                ? `, BGP ${p.bgp ? 'on' : 'off'}`
                : ''}
            </p>
            {#if p.error}<p class="text-destructive text-xs">{p.error}</p>{/if}
          </li>
        {/each}
      </ul>
    {/if}

    {#if canChange}
      <div class="space-y-2">
        {#if view.templates.length > 0}
          <div class="flex flex-col gap-1">
            <Label for="edge-ddos-profile" class="text-xs">Protection profile</Label>
            <select
              id="edge-ddos-profile"
              class={SELECT}
              bind:value={profileChoice}
              disabled={busy}
            >
              <option value="" disabled>Pick a profile</option>
              {#each view.templates as t (t.id)}
                <option value={String(t.id)} disabled={t.fieldsNeeded.length > 0}>
                  {t.fieldsNeeded.length > 0
                    ? `${t.name} (needs settings FCP cannot fill)`
                    : t.name}
                </option>
              {/each}
            </select>
            {#each view.templates.filter((t) => String(t.id) === profileChoice && t.description) as t (t.id)}
              <p class="text-muted-foreground text-xs">{t.description}</p>
            {/each}
            {#if view.templates.some((t) => t.fieldsNeeded.length > 0)}
              <p class="text-muted-foreground text-xs">
                A profile marked as needing settings has required values with no default. Set it up
                in Gcore's console instead.
              </p>
            {/if}
          </div>
        {/if}
        <div class="flex items-center gap-2">
          <Checkbox
            id="edge-ddos-bgp"
            checked={bgp}
            disabled={busy}
            onCheckedChange={(v) => (bgp = v === true)}
          />
          <Label for="edge-ddos-bgp" class="text-sm font-normal">
            Route through filtering (BGP)
          </Label>
        </div>
        <div class="flex flex-wrap gap-2">
          <Button
            size="sm"
            disabled={busy || !canEnable}
            onclick={() => change.mutate({ id: edgeId, action: 'enable' })}
          >
            {enableLabel}
          </Button>
          {#if profile?.active}
            <Button
              size="sm"
              variant="outline"
              disabled={busy}
              onclick={() => change.mutate({ id: edgeId, action: 'disable' })}
            >
              Turn off
            </Button>
          {/if}
          {#if profile}
            <Button
              size="sm"
              variant="ghost"
              disabled={busy}
              onclick={() => (confirmRemove = true)}
            >
              Remove
            </Button>
          {/if}
        </div>
      </div>
    {:else}
      <p class="text-muted-foreground text-xs">
        Protection can change only on an address FCP manages that is up.
      </p>
    {/if}

    {#if changeError}
      <InlineError message={changeError} />
    {/if}
  {/if}
</section>

<ConfirmDialog
  bind:open={confirmRemove}
  title="Remove DDoS protection?"
  body="The provider stops protecting this address and its profile is deleted. Turning it on again makes a new one."
  confirmLabel="Remove"
  danger
  onConfirm={() => change.mutateAsync({ id: edgeId, action: 'remove' })}
/>
