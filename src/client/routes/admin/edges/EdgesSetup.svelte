<script lang="ts">
  /**
   * Guided setup (`/admin/edges/setup`). URL state: `?relay=<slug>` (the relay
   * being set up), `?step=<id>` (a peek at a step other than the current one),
   * `?new=1` (working from a draft, before the relay exists), `?rotation=<id>`
   * (the rotation drawer).
   *
   * The SERVER drives the wizard: which step is current, what blocks it and
   * what is done all come from setup-status, re-read after every action. The
   * only thing kept in the browser is the DRAFT (origin + intended listeners)
   * used to judge steps 1 to 3 before a relay row exists.
   */
  import { untrack } from 'svelte';
  import { router } from '@client/stores/router.svelte';
  import { searchParam, setSearchParams } from '@client/lib/urlState.svelte';
  import { setupDraftStatusQuery, setupStatusQuery, relayLookupQuery } from '@client/lib/edgesApi';
  import { ApiCallError } from '@client/lib/api';
  import SectionHeader from './components/SectionHeader.svelte';
  import { edgesPaths } from './lib/routes';
  import SetupContextPicker from './setup/SetupContextPicker.svelte';
  import SetupWizard from './setup/SetupWizard.svelte';
  import WaitingForRelay from './setup/WaitingForRelay.svelte';
  import {
    clearDraft,
    draftIsEmpty,
    emptyDraft,
    loadDraft,
    saveDraft,
    toSetupDraft,
    type StoredDraft,
  } from './setup/draft';
  import type { SetupDraftBody } from '@client/lib/edgesApi';

  const relayParam = searchParam('relay');
  const newParam = searchParam('new');
  const relaySlug = $derived(relayParam.value || null);
  const draftMode = $derived(relaySlug === null && newParam.value === '1');

  let draft = $state<StoredDraft>(loadDraft());
  const hadDraft = untrack(() => !draftIsEmpty(draft));

  // Persist the draft, and debounce what the server is asked to judge.
  let judged = $state<SetupDraftBody | null>(null);
  let judgedKey = '';
  $effect(() => {
    const snapshot = JSON.stringify(draft);
    if (!draftMode) return;
    const copy = JSON.parse(snapshot) as StoredDraft;
    saveDraft(copy);
    const body = toSetupDraft(copy);
    const key = JSON.stringify(body);
    if (key === judgedKey) return;
    const apply = () => {
      judgedKey = key;
      judged = body;
    };
    if (judgedKey === '') {
      apply();
      return;
    }
    const t = setTimeout(apply, 500);
    return () => clearTimeout(t);
  });

  const relayStatus = setupStatusQuery(() => relaySlug);
  const draftStatus = setupDraftStatusQuery(() => (draftMode ? judged : null));
  const relay = relayLookupQuery(() => relaySlug);

  const status = $derived(relaySlug ? relayStatus : draftStatus);
  const unknownRelay = $derived(
    relaySlug !== null &&
      [relayStatus.error, relay.error].some((e) => e instanceof ApiCallError && e.status === 404),
  );

  function startNew(keepDraft: boolean) {
    if (!keepDraft) {
      clearDraft();
      draft = emptyDraft();
    }
    setSearchParams({ new: '1', relay: null, step: null });
  }
  function onRelayCreated(slug: string) {
    clearDraft();
    draft = emptyDraft();
    router.navigate(edgesPaths.setup({ relay: slug }), { replace: true });
  }
  function watchSlug(slug: string) {
    router.navigate(edgesPaths.setup({ relay: slug }), { replace: true });
  }
  function leaveRelay() {
    setSearchParams({ relay: null, step: null, rotation: null, new: null });
  }
</script>

<SectionHeader
  title="Guided setup"
  description="Take one relay from an origin to a published, watched edge, one step at a time."
  back={{ href: edgesPaths.overview(), label: 'All relays' }}
/>

{#if relaySlug === null && !draftMode}
  <SetupContextPicker hasDraft={hadDraft || !draftIsEmpty(draft)} onStartNew={startNew} />
{:else if unknownRelay && relaySlug}
  <WaitingForRelay
    slug={relaySlug}
    onCheck={() => {
      void relayStatus.refetch();
      void relay.refetch();
    }}
    onLeave={leaveRelay}
  />
{:else}
  <SetupWizard
    {status}
    relay={relaySlug ? (relay.data ?? null) : null}
    {relaySlug}
    bind:draft
    {draftMode}
    {onRelayCreated}
    onWatchSlug={watchSlug}
    onLeave={leaveRelay}
  />
{/if}
