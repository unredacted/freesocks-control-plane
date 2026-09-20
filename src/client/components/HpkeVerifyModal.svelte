<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { t } from '../lib/i18n/index.svelte';
  import { hpkeSession, ensureAttestationChecked } from '../lib/hpke-status.svelte';
  import { router } from '../stores/router.svelte';
  import { configQuery } from '../lib/queries';
  import { copyText } from '../lib/utils';
  import ShieldCheck from '@lucide/svelte/icons/shield-check';
  import ShieldAlert from '@lucide/svelte/icons/shield-alert';
  import CopyIcon from '@lucide/svelte/icons/copy';

  /**
   * "Verify this connection" backend. Shows the out-of-band-comparable fingerprints
   * of the baked HPKE keys (the SAME values scripts/hpke-fingerprint.mjs prints),
   * the live server attestation (read from the shared hpke-status store, so the
   * badge and this backend share one fetch), and how to verify off-CDN - including a
   * DNS TXT pin the user looks up themselves with dig. The heavy hpke chunk is
   * lazy-imported only when the backend is opened, so a dark build never pulls it.
   * Honest by design: the in-page check is a convenience; the trust root is the
   * off-CDN comparison (signed release / .onion / the DNS lookup you run yourself).
   * Mirrors the RotateAccountIdModal dialog shape.
   */
  interface Props {
    open: boolean;
  }
  let { open = $bindable() }: Props = $props();

  let fps = $state<{ hpke?: string; manifest?: string; manifestPq?: string }>({});
  let pins = $state<{ hpkeKid?: string; suiteId: string }>({ suiteId: '' });
  let dns = $state<{ hpke?: string; ed25519?: string; mldsa?: string }>({});
  let copied = $state<string | null>(null);

  // Admin surface: the HPKE layer's scope is the member account-number/key flows,
  // NOT admin actions - so on /admin the backend adds a line saying so, to keep the
  // badge from over-implying that admin actions are sealed.
  const isAdmin = $derived(router.pathname.startsWith('/admin'));

  // Admin-configured off-CDN channels; the backend lists only those actually set.
  const cfg = configQuery();
  const verification = $derived(cfg.data?.verification);
  const hasChannel = $derived(
    !!(verification?.releaseUrl || verification?.onionAddress || verification?.sourceUrl),
  );

  // The _fcp-pin record lives at the app's own hostname (no port); show the exact
  // lookup the user runs on their own machine + the answer it should return.
  const host = typeof location !== 'undefined' ? location.hostname : '';
  const digCommand = $derived(`dig +short TXT _fcp-pin.${host}`);
  const txtValue = $derived(
    [
      'v=fcp1',
      dns.hpke ? `hpke=${dns.hpke}` : null,
      dns.ed25519 ? `ed25519=${dns.ed25519}` : null,
      dns.mldsa ? `mldsa=${dns.mldsa}` : null,
    ]
      .filter(Boolean)
      .join('; '),
  );

  // Lazy-load the hpke chunk + populate on open (keeps a dark build from pulling it).
  // Attestation comes from the shared store (one fetch across badge + backend).
  $effect(() => {
    if (!open) return;
    // `force`: opening the backend is an explicit "check this now", so it bypasses the
    // re-check throttle rather than showing a verdict from minutes ago.
    void ensureAttestationChecked({ force: true });
    void import('../lib/hpke').then(async (m) => {
      const p = m.hpkePins();
      pins = { hpkeKid: p.hpkeKid, suiteId: p.suiteId };
      fps = await m.connectionFingerprints();
      dns = await m.dnsPinFields();
    });
  });

  async function copy(label: string, value: string) {
    // Silent on failure: the value is selectable in the code block below.
    if (await copyText(value)) {
      copied = label;
      setTimeout(() => {
        if (copied === label) copied = null;
      }, 1500);
    }
  }

  const fmtExpiry = (ms?: number | null) => (ms ? new Date(ms).toLocaleString() : '');

  let rows = $derived([
    { label: t('hpke.fpHpke'), value: fps.hpke },
    { label: t('hpke.fpManifest'), value: fps.manifest },
    { label: t('hpke.fpManifestPq'), value: fps.manifestPq },
  ]);
</script>

<Dialog.Root bind:open>
  <Dialog.Content class="sm:max-w-lg max-h-[85vh] overflow-y-auto">
    <Dialog.Header>
      <Dialog.Title>{t('hpke.verifyTitle')}</Dialog.Title>
      <Dialog.Description>{t('hpke.verifyIntro')}</Dialog.Description>
    </Dialog.Header>

    <div class="space-y-4 text-sm">
      <section class="space-y-1">
        <h3 class="font-semibold">{t('hpke.protectHeading')}</h3>
        {#if isAdmin}
          <p class="rounded-md border border-border bg-muted/40 p-2 text-muted-foreground">
            {t('hpke.protectAdmin')}
          </p>
        {/if}
        <p class="text-muted-foreground">{t('hpke.protectScope')}</p>
        <p class="text-muted-foreground">{t('hpke.protectServerReads')}</p>
        <p class="text-muted-foreground">{t('hpke.protectTunnel')}</p>
      </section>

      <section class="space-y-2">
        <h3 class="font-semibold">{t('hpke.fingerprintsHeading')}</h3>
        {#each rows as row (row.label)}
          {#if row.value}
            <div class="rounded-md border border-border bg-muted/30 p-2">
              <div class="flex items-center justify-between gap-2">
                <span class="text-xs text-muted-foreground">{row.label}</span>
                <button
                  type="button"
                  class="text-xs underline underline-offset-2 hover:no-underline inline-flex items-center gap-1"
                  onclick={() => copy(row.label, row.value!)}
                >
                  <CopyIcon class="size-3" />{copied === row.label
                    ? t('hpke.copied')
                    : t('hpke.copy')}
                </button>
              </div>
              <code class="mt-1 block break-all font-mono text-[11px] leading-relaxed"
                >{row.value}</code
              >
            </div>
          {/if}
        {/each}
        {#if pins.hpkeKid}
          <p class="text-xs text-muted-foreground">
            {t('hpke.fpKid')}: <code class="font-mono">{pins.hpkeKid}</code>
          </p>
        {/if}
        <p class="text-xs text-muted-foreground">
          {t('hpke.fpSuite')}: <code class="font-mono break-all">{pins.suiteId}</code>
        </p>
      </section>

      <section class="space-y-1">
        <h3 class="font-semibold">{t('hpke.attestationHeading')}</h3>
        {#if hpkeSession.attestation === 'pending'}
          <p class="text-xs text-muted-foreground">…</p>
        {:else if hpkeSession.attestation === 'active'}
          <p class="inline-flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400">
            <ShieldCheck class="size-4 shrink-0" />{t('hpke.attestationOk')}
          </p>
          {#if hpkeSession.epochKid}
            <p class="text-xs text-muted-foreground">
              {t('hpke.attestationEpoch', {
                kid: hpkeSession.epochKid,
                expiry: fmtExpiry(hpkeSession.notAfter),
              })}
            </p>
          {/if}
        {:else if hpkeSession.attestation === 'warn'}
          <p class="inline-flex items-center gap-1.5 text-destructive">
            <ShieldAlert class="size-4 shrink-0" />{t('hpke.attestationFail')}
          </p>
        {:else if hpkeSession.attestation === 'stale'}
          <p class="text-xs text-muted-foreground">{t('hpke.attestationStale')}</p>
        {:else if hpkeSession.attestation === 'unconfigured'}
          <p class="text-xs text-muted-foreground">{t('hpke.attestationUnconfigured')}</p>
        {:else}
          <p class="text-xs text-muted-foreground">{t('hpke.attestationUnreachable')}</p>
        {/if}
      </section>

      <section class="space-y-2">
        <h3 class="font-semibold">{t('hpke.compareHeading')}</h3>
        <p class="text-muted-foreground">{t('hpke.compareBody')}</p>
        {#if hasChannel}
          <ul class="space-y-1.5">
            {#if verification?.releaseUrl}
              <li>
                <a
                  href={verification.releaseUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  class="break-all text-primary underline underline-offset-2 hover:no-underline"
                >
                  {t('hpke.channelRelease')}
                </a>
              </li>
            {/if}
            {#if verification?.sourceUrl}
              <li>
                <a
                  href={verification.sourceUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  class="break-all text-primary underline underline-offset-2 hover:no-underline"
                >
                  {t('hpke.channelSource')}
                </a>
              </li>
            {/if}
            {#if verification?.onionAddress}
              <li class="text-muted-foreground">
                {t('hpke.channelOnion')}:
                <code class="break-all font-mono text-[11px]">{verification.onionAddress}</code>
              </li>
            {/if}
          </ul>
        {/if}
      </section>

      <section class="space-y-2">
        <h3 class="font-semibold">{t('hpke.dnsHeading')}</h3>
        <p class="text-muted-foreground">{t('hpke.dnsBody')}</p>
        <div class="rounded-md border border-border bg-muted/30 p-2">
          <div class="flex items-center justify-between gap-2">
            <span class="text-xs text-muted-foreground">{t('hpke.dnsCommand')}</span>
            <button
              type="button"
              class="text-xs underline underline-offset-2 hover:no-underline inline-flex items-center gap-1"
              onclick={() => copy('dns-cmd', digCommand)}
            >
              <CopyIcon class="size-3" />{copied === 'dns-cmd' ? t('hpke.copied') : t('hpke.copy')}
            </button>
          </div>
          <code class="mt-1 block break-all font-mono text-[11px] leading-relaxed"
            >{digCommand}</code
          >
        </div>
        <div class="rounded-md border border-border bg-muted/30 p-2">
          <div class="flex items-center justify-between gap-2">
            <span class="text-xs text-muted-foreground">{t('hpke.dnsExpected')}</span>
            <button
              type="button"
              class="text-xs underline underline-offset-2 hover:no-underline inline-flex items-center gap-1"
              onclick={() => copy('dns-txt', txtValue)}
            >
              <CopyIcon class="size-3" />{copied === 'dns-txt' ? t('hpke.copied') : t('hpke.copy')}
            </button>
          </div>
          <code class="mt-1 block break-all font-mono text-[11px] leading-relaxed">{txtValue}</code>
        </div>
        <p class="text-xs text-muted-foreground">{t('hpke.dnsCaveat')}</p>
      </section>

      <div class="space-y-1 border-t border-border pt-3 text-xs text-muted-foreground">
        <p>{t('hpke.caveat')}</p>
        {#if verification?.extensionUrl}
          <p>
            <a
              href={verification.extensionUrl}
              target="_blank"
              rel="noopener noreferrer"
              class="break-all text-primary underline underline-offset-2 hover:no-underline"
            >
              {t('hpke.verifierExtensionInstall')}
            </a>
          </p>
        {:else}
          <p>{t('hpke.verifierExtension')}</p>
        {/if}
      </div>
    </div>

    <Dialog.Footer>
      <Button variant="ghost" onclick={() => (open = false)}>{t('hpke.close')}</Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
