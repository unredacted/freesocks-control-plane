<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { t } from '../lib/i18n/index.svelte';
  import { e2eeSession, ensureAttestationChecked } from '../lib/e2ee-status.svelte';
  import { router } from '../stores/router.svelte';
  import ShieldCheck from '@lucide/svelte/icons/shield-check';
  import ShieldAlert from '@lucide/svelte/icons/shield-alert';
  import CopyIcon from '@lucide/svelte/icons/copy';

  /**
   * "Verify this connection" panel. Shows the out-of-band-comparable fingerprints
   * of the baked E2EE keys (the SAME values scripts/e2ee-fingerprint.mjs prints),
   * the live server attestation (read from the shared e2ee-status store, so the
   * badge and this panel share one fetch), and how to verify off-CDN - including a
   * DNS TXT pin the user looks up themselves with dig. The heavy e2ee chunk is
   * lazy-imported only when the panel is opened, so a dark build never pulls it.
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
  // NOT admin actions - so on /admin the panel adds a line saying so, to keep the
  // badge from over-implying that admin actions are sealed.
  const isAdmin = $derived(router.pathname.startsWith('/admin'));

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

  // Lazy-load the e2ee chunk + populate on open (keeps a dark build from pulling it).
  // Attestation comes from the shared store (one fetch across badge + panel).
  $effect(() => {
    if (!open) return;
    void ensureAttestationChecked();
    void import('../lib/e2ee').then(async (m) => {
      const p = m.e2eePins();
      pins = { hpkeKid: p.hpkeKid, suiteId: p.suiteId };
      fps = await m.connectionFingerprints();
      dns = await m.dnsPinFields();
    });
  });

  async function copy(label: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      copied = label;
      setTimeout(() => {
        if (copied === label) copied = null;
      }, 1500);
    } catch {
      /* clipboard unavailable - the value is selectable in the code block */
    }
  }

  const fmtExpiry = (ms?: number | null) => (ms ? new Date(ms).toLocaleString() : '');

  let rows = $derived([
    { label: t('e2ee.fpHpke'), value: fps.hpke },
    { label: t('e2ee.fpManifest'), value: fps.manifest },
    { label: t('e2ee.fpManifestPq'), value: fps.manifestPq },
  ]);
</script>

<Dialog.Root bind:open>
  <Dialog.Content class="sm:max-w-lg max-h-[85vh] overflow-y-auto">
    <Dialog.Header>
      <Dialog.Title>{t('e2ee.verifyTitle')}</Dialog.Title>
      <Dialog.Description>{t('e2ee.verifyIntro')}</Dialog.Description>
    </Dialog.Header>

    <div class="space-y-4 text-sm">
      <section class="space-y-1">
        <h3 class="font-semibold">{t('e2ee.protectHeading')}</h3>
        {#if isAdmin}
          <p class="rounded-md border border-border bg-muted/40 p-2 text-muted-foreground">
            {t('e2ee.protectAdmin')}
          </p>
        {/if}
        <p class="text-muted-foreground">{t('e2ee.protectScope')}</p>
        <p class="text-muted-foreground">{t('e2ee.protectServerReads')}</p>
        <p class="text-muted-foreground">{t('e2ee.protectMetadata')}</p>
        <p class="text-muted-foreground">{t('e2ee.protectTunnel')}</p>
      </section>

      <section class="space-y-2">
        <h3 class="font-semibold">{t('e2ee.fingerprintsHeading')}</h3>
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
                    ? t('e2ee.copied')
                    : t('e2ee.copy')}
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
            {t('e2ee.fpKid')}: <code class="font-mono">{pins.hpkeKid}</code>
          </p>
        {/if}
        <p class="text-xs text-muted-foreground">
          {t('e2ee.fpSuite')}: <code class="font-mono break-all">{pins.suiteId}</code>
        </p>
      </section>

      <section class="space-y-1">
        <h3 class="font-semibold">{t('e2ee.attestationHeading')}</h3>
        {#if e2eeSession.attestation === 'pending'}
          <p class="text-xs text-muted-foreground">…</p>
        {:else if e2eeSession.attestation === 'active'}
          <p class="inline-flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400">
            <ShieldCheck class="size-4 shrink-0" />{t('e2ee.attestationOk')}
          </p>
          {#if e2eeSession.epochKid}
            <p class="text-xs text-muted-foreground">
              {t('e2ee.attestationEpoch', {
                kid: e2eeSession.epochKid,
                expiry: fmtExpiry(e2eeSession.notAfter),
              })}
            </p>
          {/if}
        {:else if e2eeSession.attestation === 'warn'}
          <p class="inline-flex items-center gap-1.5 text-destructive">
            <ShieldAlert class="size-4 shrink-0" />{t('e2ee.attestationFail')}
          </p>
        {:else}
          <p class="text-xs text-muted-foreground">{t('e2ee.attestationUnreachable')}</p>
        {/if}
      </section>

      <section class="space-y-1">
        <h3 class="font-semibold">{t('e2ee.compareHeading')}</h3>
        <p class="text-muted-foreground">{t('e2ee.compareBody')}</p>
      </section>

      <section class="space-y-2">
        <h3 class="font-semibold">{t('e2ee.dnsHeading')}</h3>
        <p class="text-muted-foreground">{t('e2ee.dnsBody')}</p>
        <div class="rounded-md border border-border bg-muted/30 p-2">
          <div class="flex items-center justify-between gap-2">
            <span class="text-xs text-muted-foreground">{t('e2ee.dnsCommand')}</span>
            <button
              type="button"
              class="text-xs underline underline-offset-2 hover:no-underline inline-flex items-center gap-1"
              onclick={() => copy('dns-cmd', digCommand)}
            >
              <CopyIcon class="size-3" />{copied === 'dns-cmd' ? t('e2ee.copied') : t('e2ee.copy')}
            </button>
          </div>
          <code class="mt-1 block break-all font-mono text-[11px] leading-relaxed"
            >{digCommand}</code
          >
        </div>
        <div class="rounded-md border border-border bg-muted/30 p-2">
          <div class="flex items-center justify-between gap-2">
            <span class="text-xs text-muted-foreground">{t('e2ee.dnsExpected')}</span>
            <button
              type="button"
              class="text-xs underline underline-offset-2 hover:no-underline inline-flex items-center gap-1"
              onclick={() => copy('dns-txt', txtValue)}
            >
              <CopyIcon class="size-3" />{copied === 'dns-txt' ? t('e2ee.copied') : t('e2ee.copy')}
            </button>
          </div>
          <code class="mt-1 block break-all font-mono text-[11px] leading-relaxed">{txtValue}</code>
        </div>
        <p class="text-xs text-muted-foreground">{t('e2ee.dnsCaveat')}</p>
      </section>

      <section class="space-y-1">
        <h3 class="font-semibold">{t('e2ee.bundleHeading')}</h3>
        <p class="text-muted-foreground">{t('e2ee.bundleHint')}</p>
        <p class="text-muted-foreground">{t('e2ee.verifierExtension')}</p>
      </section>

      <p class="border-t border-border pt-3 text-xs text-muted-foreground">{t('e2ee.caveat')}</p>
    </div>

    <Dialog.Footer>
      <Button variant="ghost" onclick={() => (open = false)}>{t('e2ee.close')}</Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
