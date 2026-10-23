<script lang="ts">
  /**
   * Provision one more edge for the origin (spends provider budget), behind a
   * dry run: the ONE provision dialog (the separate "test provision" dialog is
   * folded in). Two ways, picked by what the operator names:
   *
   *  - FCP chooses the account (the default): an ordinary provision; the
   *    listener may be left to FCP too, and "publish when ready" makes it a
   *    published edge instead of a standby. Only trusted (qualified) accounts
   *    are picked this way.
   *  - A named account (any tested one): the bootstrap provision
   *    (`test-provision`), which allows an account that is not trusted yet
   *    (`allowUnqualified`, chosen here automatically) and needs a listener and,
   *    optionally, a template. Its edge always waits unpublished, so it can be
   *    tried before members depend on it. This is also how a manual or Outline
   *    origin gets its first edge.
   *
   * Props: open (bindable); relay; listeners; listenerKey? / accountId? (preselect);
   *        onStarted(rotationId)
   */
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { untrack } from 'svelte';
  import { createQuery, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import type { OriginAdmin, RelayListenerAdmin } from '@shared/contracts/edges';
  import * as Dialog from '@client/components/ui/dialog';
  import * as Select from '@client/components/ui/select';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Label } from '@client/components/ui/label';
  import InlineError from '@client/components/InlineError.svelte';
  import Link from '@client/components/Link.svelte';
  import {
    edgeKeys,
    invalidateProviders,
    invalidateRelay,
    preflightRelay,
    providersQuery,
    provisionRelay,
    templatesQuery,
    testProvisionRelay,
  } from '@client/lib/edgesApi';
  import PreflightPanel from '../components/PreflightPanel.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { protocolLine, providerLabel } from '../lib/format';
  import { edgesPaths } from '../lib/routes';

  interface Props {
    open: boolean;
    relay: OriginAdmin;
    listeners: RelayListenerAdmin[];
    /** Preselect a listener (the Listeners tab's "Provision an edge for this listener"). */
    listenerKey?: string | null;
    /** Preselect an account (a named account takes the bootstrap path). */
    accountId?: string | null;
    onStarted: (rotationId: string) => void;
  }
  let {
    open = $bindable(false),
    relay,
    listeners,
    listenerKey = null,
    accountId: accountPreset = null,
    onStarted,
  }: Props = $props();

  const uid = $props.id();
  const qc = useQueryClient();
  const providers = providersQuery();
  const templates = templatesQuery();
  const usable = $derived(listeners.filter((l) => !l.retired && l.enabled && l.deployed));
  // Any tested account can be named; an untrusted one is fine on the bootstrap path.
  const accounts = $derived(
    (providers.data?.accounts ?? []).filter((a) => a.enabled && a.lastTestOkAt !== null),
  );

  let chosenKey = $state('');
  let accountId = $state('');
  let templateId = $state('');
  /** '' = the account's default location. */
  let locationId = $state('');
  let publish = $state(false);
  let busy = $state(false);
  let error = $state<unknown>(null);
  let seeded = false;
  $effect(() => {
    if (!open) {
      seeded = false;
      return;
    }
    if (seeded) return;
    seeded = true;
    untrack(() => {
      chosenKey = listenerKey ?? (usable.length === 1 ? usable[0]!.listenerKey : '');
      accountId = accountPreset ?? '';
      templateId = '';
      locationId = '';
      publish = false;
      error = null;
    });
  });

  const chosen = $derived(usable.find((l) => l.listenerKey === chosenKey) ?? null);
  const account = $derived(accounts.find((a) => a.id === accountId) ?? null);
  // A named account takes the bootstrap path: it needs a listener and never publishes.
  const named = $derived(!!account);
  const accountTemplates = $derived(
    account
      ? (templates.data?.templates ?? []).filter(
          (t) =>
            t.provider === account.provider && (t.accountId === null || t.accountId === account.id),
        )
      : [],
  );
  const template = $derived(accountTemplates.find((t) => t.id === templateId) ?? null);
  $effect(() => {
    if (templateId && !template) templateId = '';
  });
  // Where in that account the edge is created: its switched-on locations.
  const accountLocations = $derived((account?.locations ?? []).filter((l) => l.enabled));
  const location = $derived(accountLocations.find((l) => l.id === locationId) ?? null);
  const defaultLocation = $derived(accountLocations.find((l) => l.isDefault) ?? null);
  $effect(() => {
    if (locationId && !location) locationId = '';
  });
  const ready = $derived(!named || !!chosen);

  const preflight = createQuery(() => ({
    queryKey: [
      ...edgeKeys.relay(relay.slug),
      'preflight',
      named ? 'test-provision' : 'provision',
      chosenKey,
      accountId,
      locationId,
      templateId,
      publish,
    ] as const,
    queryFn: () =>
      named
        ? preflightRelay(relay.id, {
            kind: 'test-provision',
            accountId,
            ...(locationId ? { locationId } : {}),
            listenerKey: chosenKey,
            ...(templateId ? { templateId } : {}),
          })
        : preflightRelay(relay.id, {
            kind: 'provision',
            trigger: 'manual',
            publish,
            ...(chosenKey ? { listenerKey: chosenKey } : {}),
          }),
    enabled: open && ready,
    staleTime: 0,
    gcTime: 0,
    retry: false,
  }));
  const blocked = $derived(!preflight.data?.ok);

  async function start(): Promise<void> {
    if (busy || !ready || blocked) return;
    busy = true;
    error = null;
    try {
      const res = named
        ? await testProvisionRelay(relay.id, {
            accountId,
            ...(locationId ? { locationId } : {}),
            listenerKey: chosenKey,
            ...(templateId ? { templateId } : {}),
          })
        : // `publish` is always sent: the route reads a missing one as "publish when ready".
          await provisionRelay(relay.id, {
            ...(chosen ? { listenerId: chosen.id } : {}),
            publish,
          });
      toast.success(
        named ? 'Provisioning started. The edge waits unpublished.' : 'Provisioning started.',
      );
      invalidateRelay(qc, relay.slug);
      invalidateProviders(qc);
      open = false;
      onStarted(res.rotationId);
    } catch (e) {
      error = e;
    } finally {
      busy = false;
    }
  }
</script>

<Dialog.Root bind:open>
  <Dialog.Content class={`${DIALOG_FIT} sm:max-w-xl`}>
    <Dialog.Header>
      <Dialog.Title>Provision an edge for {relay.slug}</Dialog.Title>
      <Dialog.Description>
        FCP creates a new provider resource in front of this origin. That spends one allocation of
        the account's daily budget and starts billing at the provider.
      </Dialog.Description>
    </Dialog.Header>

    <div class="space-y-4">
      <div class="space-y-1.5">
        <Label for={`${uid}-listener`}>Listener</Label>
        <Select.Root type="single" value={chosenKey} onValueChange={(v) => (chosenKey = v)}>
          <Select.Trigger id={`${uid}-listener`} class="w-full">
            {chosen
              ? `${chosen.listenerKey} (${protocolLine(chosen)})`
              : named
                ? 'Choose a listener'
                : 'Let FCP choose'}
          </Select.Trigger>
          <Select.Content>
            {#if !named}<Select.Item value="">Let FCP choose</Select.Item>{/if}
            {#each usable as l (l.id)}
              <Select.Item value={l.listenerKey}>{l.listenerKey} ({protocolLine(l)})</Select.Item>
            {/each}
          </Select.Content>
        </Select.Root>
        {#if usable.length === 0}
          <p class="text-muted-foreground text-xs">
            No listener is deployed and enabled yet. Add or enable one on the Listeners tab first.
          </p>
        {/if}
      </div>

      <div class="space-y-1.5">
        <Label for={`${uid}-account`}>Account</Label>
        <Select.Root
          type="single"
          value={accountId || 'auto'}
          onValueChange={(v: string) => (accountId = v === 'auto' ? '' : v)}
        >
          <Select.Trigger id={`${uid}-account`} class="w-full">
            {account ? `${account.name} (${providerLabel(account.provider)})` : 'Let FCP choose'}
          </Select.Trigger>
          <Select.Content>
            <Select.Item value="auto" label="Let FCP choose">Let FCP choose</Select.Item>
            {#each accounts as a (a.id)}
              <Select.Item value={a.id} label={a.name}>
                {a.name}
                <span class="text-muted-foreground text-xs">
                  {providerLabel(a.provider)}, {a.qualified ? 'trusted' : 'tested, not trusted yet'}
                </span>
              </Select.Item>
            {/each}
          </Select.Content>
        </Select.Root>
        <p class="text-muted-foreground text-xs">
          {#if named}
            A named account may be one that is not trusted yet. Its edge waits unpublished, so you
            can try it before members depend on it, then publish it from the edges table.
          {:else}
            FCP picks a trusted account that can carry the listener.
          {/if}
          {#if !providers.isPending && accounts.length === 0}
            No account has passed a credential test yet:
            <Link class="underline underline-offset-2" href={edgesPaths.providers()}>Providers</Link
            >.
          {/if}
        </p>
      </div>

      {#if named && accountLocations.length > 1}
        <div class="space-y-1.5">
          <Label for={`${uid}-location`}>Location</Label>
          <Select.Root
            type="single"
            value={locationId || 'default'}
            onValueChange={(v: string) => (locationId = v === 'default' ? '' : v)}
          >
            <Select.Trigger id={`${uid}-location`} class="w-full">
              {location ? location.label : `The default (${defaultLocation?.label ?? 'none'})`}
            </Select.Trigger>
            <Select.Content>
              <Select.Item value="default" label="The default">
                The default ({defaultLocation?.label ?? 'none'})
              </Select.Item>
              {#each accountLocations as l (l.id)}
                <Select.Item value={l.id} label={l.label}>
                  {l.label}
                  <span class="text-muted-foreground text-xs">
                    {l.qualified ? 'trusted' : 'not trusted yet'}
                  </span>
                </Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
          <p class="text-muted-foreground text-xs">
            The edge stays in this location for its whole life. Its first tested address trusts a
            new location.
          </p>
        </div>
      {/if}

      {#if named}
        <div class="space-y-1.5">
          <Label for={`${uid}-template`}>Template (optional)</Label>
          <Select.Root
            type="single"
            value={templateId || 'default'}
            onValueChange={(v: string) => (templateId = v === 'default' ? '' : v)}
          >
            <Select.Trigger id={`${uid}-template`} class="w-full">
              {template ? template.name : "The account's default"}
            </Select.Trigger>
            <Select.Content>
              <Select.Item value="default" label="The account's default">
                The account's default
              </Select.Item>
              {#each accountTemplates as t (t.id)}
                <Select.Item value={t.id} label={t.name}>{t.name}</Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
        </div>
      {:else}
        <div class="flex items-start gap-2">
          <Checkbox id={`${uid}-publish`} bind:checked={publish} class="mt-0.5" />
          <div>
            <Label for={`${uid}-publish`}>Publish it when it is ready</Label>
            <p class="text-muted-foreground text-xs">
              Off: the edge waits as a standby until you publish it or a rotation needs it.
            </p>
          </div>
        </div>
      {/if}

      {#if ready}
        <PreflightPanel
          kind={named ? 'test-provision' : 'provision'}
          result={preflight.data}
          pending={preflight.isFetching}
          error={preflight.isError ? preflight.error : undefined}
          onRetry={() => void preflight.refetch()}
        />
      {:else}
        <p class="text-muted-foreground text-sm">
          Choose the listener to see whether the provision can start.
        </p>
      {/if}
      {#if error !== null}
        <InlineError message={edgeErrorMessage(error)} />
      {/if}
    </div>

    <Dialog.Footer class={STICKY_FOOTER}>
      <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
      <Button disabled={!ready || blocked || preflight.isFetching || busy} onclick={start}>
        {busy ? 'Starting' : 'Provision'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
