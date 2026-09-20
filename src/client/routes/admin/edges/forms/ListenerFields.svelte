<script lang="ts">
  /**
   * The fields of one listener (what the transport behind an origin speaks), shared
   * by the new-origin dialog, the add/edit listener dialog and the setup draft.
   * Only the fields the chosen combination uses are shown.
   *
   * Props:
   *   form: ListenerForm (bindable)          forms/listenerForm.ts
   *   originKind: OriginKind
   *   keyLocked?: boolean                    editing: the key identifies the listener
   *   comboLocked?: boolean                  editing: what it speaks is fixed once edges exist
   *   brief?: boolean                        draft mode: combination, port and names only
   *   disabled?: boolean
   */
  import * as Select from '@client/components/ui/select';
  import * as Collapsible from '@client/components/ui/collapsible';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { Switch } from '@client/components/ui/switch';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import { EDGE_PROVIDER_IDS } from '@shared/contracts/edges';
  import { LISTENER_COMBOS, type ListenerComboKey } from '@shared/contracts/edgeProtocolIds';
  import TagInput from '../components/TagInput.svelte';
  import { normalizeHostname } from '../lib/tags';
  import { providerLabel } from '../lib/format';
  import type { OriginKind } from './origin';
  import {
    formCombo,
    normalizeCertName,
    type ListenerForm,
    type MatchRuleChoice,
  } from './listenerForm';

  interface Props {
    form: ListenerForm;
    originKind: OriginKind;
    keyLocked?: boolean;
    comboLocked?: boolean;
    brief?: boolean;
    disabled?: boolean;
  }
  let {
    form = $bindable(),
    originKind,
    keyLocked = false,
    comboLocked = false,
    brief = false,
    disabled = false,
  }: Props = $props();

  const uid = $props.id();
  const combo = $derived(formCombo(form));
  const canBind = $derived(originKind === 'panel-node');

  const MATCH_LABELS: Record<MatchRuleChoice, string> = {
    auto: 'Automatic',
    address: 'By origin address and port',
    'whole-body': 'The whole subscription',
    remark: 'By the entry remark',
  };
  const MATCH_HINTS: Record<MatchRuleChoice, string> = {
    auto: 'The remark of the backend Host when the transport is bound, the origin address and port otherwise.',
    address: 'Entries that dial the origin address on this port are rewritten.',
    'whole-body':
      'Every entry is rewritten. Only valid when this is the only listener of the origin.',
    remark:
      'Entries whose remark equals the text below are rewritten. Needs the backend transport.',
  };
  const matchChoices = $derived(
    (['auto', 'address', 'whole-body', 'remark'] as const).filter((m) => m !== 'remark' || canBind),
  );
</script>

<div class="space-y-4">
  <div class="grid gap-4 sm:grid-cols-2">
    {#if !brief}
      <div class="space-y-1.5">
        <Label for={`${uid}-key`}>Listener key</Label>
        <Input
          id={`${uid}-key`}
          class="font-mono"
          placeholder="reality"
          maxlength={16}
          bind:value={form.listenerKey}
          disabled={disabled || keyLocked}
        />
        <p class="text-muted-foreground text-xs">
          1 to 16 lowercase letters or digits. The node role uses the same key.
        </p>
      </div>
    {/if}
    <div class="space-y-1.5">
      <Label for={`${uid}-combo`}>What it speaks</Label>
      <Select.Root
        type="single"
        value={form.combo}
        onValueChange={(v: string) => (form.combo = v as ListenerComboKey)}
        disabled={disabled || comboLocked}
      >
        <Select.Trigger id={`${uid}-combo`} class="w-full">{combo.label}</Select.Trigger>
        <Select.Content>
          {#each LISTENER_COMBOS as c (c.key)}
            <Select.Item value={c.key} label={c.label}>{c.label}</Select.Item>
          {/each}
        </Select.Content>
      </Select.Root>
      {#if combo.transport === 'udp'}
        <p class="text-xs text-amber-700 dark:text-amber-300">
          This listener registers, but no provider forwards UDP today, so no edge can front it yet.
        </p>
      {:else if combo.l7Proof === 'vless'}
        <p class="text-muted-foreground text-xs">
          Can sit behind a CDN front (L7) when you describe how the front reaches it below.
        </p>
      {:else}
        <p class="text-muted-foreground text-xs">Fronted by load balancers (L4) only.</p>
      {/if}
    </div>
    <div class="space-y-1.5">
      <Label for={`${uid}-port`}>Origin port</Label>
      <Input
        id={`${uid}-port`}
        class="font-mono"
        inputmode="numeric"
        placeholder="443"
        bind:value={form.originPort}
        {disabled}
      />
      <p class="text-muted-foreground text-xs">The port the transport listens on at the origin.</p>
    </div>
  </div>

  {#if combo.usesSni}
    <TagInput
      bind:value={form.tlsNames}
      label={combo.security === 'reality' ? 'Server names (REALITY)' : 'Server names'}
      normalize={normalizeHostname}
      placeholder="cdn.example"
      helper={combo.security === 'reality'
        ? 'Names the inbound accepts. Members are spread across them, and a blocked name can be retired later.'
        : 'Names the certificate covers. Members present one of them.'}
      invalidText="Not a valid DNS name."
      max={32}
      mono
      {disabled}
    />
  {/if}

  {#if combo.needsTarget && !brief}
    <div class="grid gap-4 sm:grid-cols-[1fr_8rem]">
      <div class="space-y-1.5">
        <Label for={`${uid}-target`}>REALITY target</Label>
        <Input
          id={`${uid}-target`}
          class="font-mono"
          placeholder="target.example"
          bind:value={form.targetAddress}
          {disabled}
        />
        <p class="text-muted-foreground text-xs">The site the transport impersonates.</p>
      </div>
      <div class="space-y-1.5">
        <Label for={`${uid}-target-port`}>Target port</Label>
        <Input
          id={`${uid}-target-port`}
          class="font-mono"
          inputmode="numeric"
          bind:value={form.targetPort}
          {disabled}
        />
      </div>
    </div>
  {/if}

  {#if combo.isHttpTransport}
    {#if !brief}
      <div class="grid gap-4 sm:grid-cols-2">
        {#if combo.streamTransport === 'grpc'}
          <div class="space-y-1.5">
            <Label for={`${uid}-service`}>gRPC service name</Label>
            <Input
              id={`${uid}-service`}
              class="font-mono"
              bind:value={form.serviceName}
              {disabled}
            />
          </div>
        {:else}
          <div class="space-y-1.5">
            <Label for={`${uid}-path`}>Path</Label>
            <Input
              id={`${uid}-path`}
              class="font-mono"
              placeholder="/stream"
              bind:value={form.path}
              {disabled}
            />
          </div>
          <div class="space-y-1.5">
            <Label for={`${uid}-host`}>Host header (optional)</Label>
            <Input
              id={`${uid}-host`}
              class="font-mono"
              placeholder="cdn.example"
              bind:value={form.host}
              {disabled}
            />
          </div>
          {#if combo.streamTransport === 'xhttp'}
            <div class="space-y-1.5">
              <Label for={`${uid}-xhttp-mode`}>XHTTP mode</Label>
              <Select.Root
                type="single"
                value={form.xhttpMode}
                onValueChange={(v: string) => (form.xhttpMode = v)}
                {disabled}
              >
                <Select.Trigger id={`${uid}-xhttp-mode`} class="w-full font-mono">
                  {form.xhttpMode}
                </Select.Trigger>
                <Select.Content>
                  {#each ['packet-up', 'auto', 'stream-up', 'stream-one'] as m (m)}
                    <Select.Item value={m}>{m}</Select.Item>
                  {/each}
                </Select.Content>
              </Select.Root>
              <p class="text-muted-foreground text-xs">
                As the transport declares it. A CDN front is only checked against packet-up and
                auto; the stream modes need a front that streams request bodies.
              </p>
            </div>
          {/if}
        {/if}
      </div>
    {/if}

    <div class="space-y-3 rounded-md border p-3">
      <div class="flex items-start justify-between gap-3">
        <div>
          <Label for={`${uid}-frontable`}>A CDN front can reach this transport</Label>
          <p class="text-muted-foreground text-xs">
            Off: only load balancers (L4) front it. On: describe how a front dials the origin, and
            the server decides whether L7 is allowed.
          </p>
        </div>
        <Switch id={`${uid}-frontable`} bind:checked={form.frontable} {disabled} />
      </div>
      {#if form.frontable}
        <div class="grid gap-4 sm:grid-cols-2">
          <div class="space-y-1.5">
            <Label for={`${uid}-scheme`}>The front dials the origin over</Label>
            <Select.Root
              type="single"
              value={form.scheme}
              onValueChange={(v: string) => (form.scheme = v === 'http' ? 'http' : 'https')}
              {disabled}
            >
              <Select.Trigger id={`${uid}-scheme`} class="w-full">
                {form.scheme === 'https' ? 'HTTPS' : 'Plain HTTP'}
              </Select.Trigger>
              <Select.Content>
                <Select.Item value="https" label="HTTPS">HTTPS</Select.Item>
                <Select.Item value="http" label="Plain HTTP">Plain HTTP</Select.Item>
              </Select.Content>
            </Select.Root>
            {#if form.scheme === 'http'}
              <p class="text-muted-foreground text-xs">
                A plain HTTP origin can only sit behind a CDN front (L7 only).
              </p>
            {/if}
          </div>
          <div class="space-y-1.5">
            <Label for={`${uid}-hosthdr`}>Host header the node accepts</Label>
            <Select.Root
              type="single"
              value={form.acceptsHostHeader}
              onValueChange={(v: string) =>
                (form.acceptsHostHeader = v === 'any' ? 'any' : 'names')}
              {disabled}
            >
              <Select.Trigger id={`${uid}-hosthdr`} class="w-full">
                {form.acceptsHostHeader === 'any' ? 'Any name' : 'Only its own names'}
              </Select.Trigger>
              <Select.Content>
                <Select.Item value="any" label="Any name">Any name</Select.Item>
                <Select.Item value="names" label="Only its own names"
                  >Only its own names</Select.Item
                >
              </Select.Content>
            </Select.Root>
          </div>
        </div>
        {#if form.scheme === 'https'}
          <div class="flex items-start justify-between gap-3">
            <div>
              <Label for={`${uid}-certpublic`}>The origin certificate is publicly trusted</Label>
              <p class="text-muted-foreground text-xs">
                A front refuses a self-signed origin, so L7 needs a public certificate.
              </p>
            </div>
            <Switch id={`${uid}-certpublic`} bind:checked={form.certPublic} {disabled} />
          </div>
          <TagInput
            bind:value={form.certNames}
            label="Names on the origin certificate"
            normalize={normalizeCertName}
            placeholder="origin.example"
            helper="Every active server name must be covered by one of these (a leading wildcard label is allowed)."
            invalidText="Not a valid certificate name."
            max={16}
            mono
            {disabled}
          />
        {/if}
      {/if}
    </div>
  {/if}

  {#if !brief}
    <Collapsible.Root>
      <Collapsible.Trigger
        class="text-muted-foreground hover:text-foreground group flex items-center gap-1 text-sm"
      >
        <ChevronRight
          class="size-4 transition-transform group-data-[state=open]:rotate-90"
          aria-hidden="true"
        />
        Backend transport, matching and provider scope
      </Collapsible.Trigger>
      <Collapsible.Content class="space-y-4 pt-3">
        {#if canBind}
          <div class="space-y-3 rounded-md border p-3">
            <div class="flex items-start justify-between gap-3">
              <div>
                <Label for={`${uid}-bind`}>Bind the backend transport</Label>
                <p class="text-muted-foreground text-xs">
                  Needed for FCP to create and flip the backend Host itself. The node role normally
                  fills this in when it registers.
                </p>
              </div>
              <Switch id={`${uid}-bind`} bind:checked={form.bindPanel} {disabled} />
            </div>
            {#if form.bindPanel}
              <div class="grid gap-4 sm:grid-cols-3">
                <div class="space-y-1.5">
                  <Label for={`${uid}-tag`}>Transport tag</Label>
                  <Input
                    id={`${uid}-tag`}
                    class="font-mono"
                    placeholder="VLESS_REALITY"
                    bind:value={form.inboundTag}
                    {disabled}
                  />
                </div>
                <div class="space-y-1.5">
                  <Label for={`${uid}-profile`}>Config profile id</Label>
                  <Input
                    id={`${uid}-profile`}
                    class="font-mono"
                    placeholder="00000000-0000-4000-8000-000000000000"
                    bind:value={form.configProfileUuid}
                    {disabled}
                  />
                </div>
                <div class="space-y-1.5">
                  <Label for={`${uid}-inbound`}>Transport id</Label>
                  <Input
                    id={`${uid}-inbound`}
                    class="font-mono"
                    placeholder="00000000-0000-4000-8000-000000000000"
                    bind:value={form.configProfileInboundUuid}
                    {disabled}
                  />
                </div>
              </div>
            {/if}
          </div>
        {/if}

        <div class="grid gap-4 sm:grid-cols-2">
          <div class="space-y-1.5">
            <Label for={`${uid}-match`}>Which subscription entries are rewritten</Label>
            <Select.Root
              type="single"
              value={form.matchRule}
              onValueChange={(v: string) => (form.matchRule = v as MatchRuleChoice)}
              {disabled}
            >
              <Select.Trigger id={`${uid}-match`} class="w-full">
                {MATCH_LABELS[form.matchRule]}
              </Select.Trigger>
              <Select.Content>
                {#each matchChoices as m (m)}
                  <Select.Item value={m} label={MATCH_LABELS[m]}>{MATCH_LABELS[m]}</Select.Item>
                {/each}
              </Select.Content>
            </Select.Root>
            <p class="text-muted-foreground text-xs">{MATCH_HINTS[form.matchRule]}</p>
            {#if form.matchRule === 'remark'}
              <Input
                class="font-mono"
                placeholder="node1-relay-reality"
                aria-label="Remark to match"
                bind:value={form.remark}
                {disabled}
              />
            {/if}
          </div>
          <div class="space-y-1.5">
            <Label for={`${uid}-scope`}>Only this provider may front it</Label>
            <Select.Root
              type="single"
              value={form.providerScope}
              onValueChange={(v: string) => (form.providerScope = v === 'any' ? '' : v)}
              {disabled}
            >
              <Select.Trigger id={`${uid}-scope`} class="w-full">
                {form.providerScope ? providerLabel(form.providerScope) : 'Any provider'}
              </Select.Trigger>
              <Select.Content>
                <Select.Item value="any" label="Any provider">Any provider</Select.Item>
                {#each EDGE_PROVIDER_IDS as p (p)}
                  <Select.Item value={p} label={providerLabel(p)}>{providerLabel(p)}</Select.Item>
                {/each}
              </Select.Content>
            </Select.Root>
          </div>
        </div>

        <div class="flex items-start justify-between gap-3">
          <div>
            <Label for={`${uid}-deployed`}>The transport is deployed on the origin</Label>
            <p class="text-muted-foreground text-xs">
              Off while the node is still being prepared. No edge is provisioned for a listener that
              is not deployed.
            </p>
          </div>
          <Switch id={`${uid}-deployed`} bind:checked={form.deployed} {disabled} />
        </div>
      </Collapsible.Content>
    </Collapsible.Root>
  {/if}
</div>
