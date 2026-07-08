<script lang="ts">
  import { z } from 'zod';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import DeliveryPreference from './DeliveryPreference.svelte';
  import SwitchModeModal from './SwitchModeModal.svelte';
  import { apiClient } from '../lib/api';
  import { apiErrorMessage } from '../lib/errors';
  import { t } from '../lib/i18n/index.svelte';
  import { queryKeys } from '../lib/queries';
  import { setConnectionModePref } from '../lib/connectionModePref.svelte';
  import { shouldConfirmSwitch } from '../lib/connectionMode';

  /**
   * The connection-mode (transport) switcher, shared by BOTH /account and
   * /get-account so they behave identically (this file is the single source of the
   * switch behavior — previously /account had it and /get-account silently didn't).
   *
   * Wraps the presentational DeliveryPreference and owns the switch machinery:
   *  - `serverBacked` (a key exists AND a placement pool is bound) → a pick opens a
   *    confirm modal, then `POST /switch-mode` re-issues the key into the chosen
   *    mode's least-loaded node and tombstones the old one (24h grace). The inline
   *    hero/raw-config refresh via the `account` + `subscriptionContent` invalidation.
   *  - otherwise (pre-first-key onboarding, or no bound pool) → a pick is a local
   *    presentation preference only (localStorage), no server round-trip.
   * `pendingModeId` drives the optimistic picker highlight while the re-issue is in flight.
   */
  interface Mode {
    id: string;
    deliveryStyle: 'url' | 'rawConfig';
    label: string | null;
    description: string | null;
    isDefault: boolean;
    available: boolean;
  }
  interface Props {
    /** The public mode catalog (config.connectionModes). */
    modes: Mode[];
    /** The parent's effectiveModeId — the base highlight (server-authoritative or local). */
    selected: string;
    /** Server's country-based recommendation id, badged. */
    suggested?: string | null;
    /** True once a key exists AND a mode pool is bound → picking re-issues the key. */
    serverBacked?: boolean;
    /** Device count on the current sub, for the confirm modal's impact note. */
    deviceCount?: number;
    /** Block the re-issue path (e.g. a disabled account). */
    disabled?: boolean;
    /** Sign-up context (pre-first-key onboarding copy). Mutually exclusive with serverBacked. */
    signup?: boolean;
  }
  let {
    modes,
    selected,
    suggested = null,
    serverBacked = false,
    deviceCount = 0,
    disabled = false,
    signup = false,
  }: Props = $props();

  const qc = useQueryClient();

  // Optimistic highlight + confirm-modal state, live while the re-issue + account
  // refetch are in flight.
  let switchModeOpen = $state(false);
  let pendingModeId = $state<string | null>(null);

  // a11y: sonner toasts aren't reliably announced; feed a visually hidden
  // role="status" region so the switch outcome is spoken once. Never the account number.
  let liveMessage = $state('');

  // Mode title for the toast + confirm dialog: an admin-set catalog label overrides
  // the translated copy verbatim (all locales); else the known-mode i18n, else the id.
  function modeLabel(id: string): string {
    const custom = modes.find((m) => m.id === id)?.label;
    if (custom?.trim()) return custom;
    if (id === 'privacy') return t('delivery.privacyTitle');
    if (id === 'evade') return t('delivery.evadeTitle');
    return id;
  }

  const switchMode = createMutation(() => ({
    mutationFn: () => {
      if (!pendingModeId) throw new Error('No mode selected');
      return apiClient.post(
        '/api/v1/account/switch-mode',
        { modeId: pendingModeId, confirm: true },
        z.object({
          subscriptionUrl: z.string(),
          shortUuid: z.string(),
          mode: z.object({ id: z.string(), label: z.string().nullable() }),
          // Null when there was no live previous subscription to tombstone.
          oldSubscriptionDeletedAt: z.string().nullable(),
        }),
      );
    },
    onSuccess: (result) => {
      switchModeOpen = false;
      // Keep the local presentation hint in sync so the delivery panels don't
      // flash the old focus before the account query returns the new mode.
      setConnectionModePref(result.mode.id);
      pendingModeId = null;
      void qc.invalidateQueries({ queryKey: queryKeys.account });
      // Re-fetch the raw-config viewer (separate key). In rawConfig mode this
      // prominent block is the ONLY thing shown, so it must not stay stale.
      void qc.invalidateQueries({ queryKey: queryKeys.subscriptionContent });
      liveMessage = t('delivery.switchSuccessTitle', { label: modeLabel(result.mode.id) });
      toast.success(t('delivery.switchSuccessTitle', { label: modeLabel(result.mode.id) }), {
        description: result.oldSubscriptionDeletedAt
          ? t('delivery.switchSuccessBodyGrace')
          : t('delivery.switchSuccessBody'),
      });
    },
    onError: (err) => {
      pendingModeId = null;
      liveMessage = t('delivery.switchFailedTitle');
      toast.error(t('delivery.switchFailedTitle'), { description: apiErrorMessage(err) });
    },
  }));

  // Server-backed → open the confirm dialog (a real key re-issue); otherwise it's a
  // local device-only presentation toggle.
  function chooseMode(modeId: string) {
    if (!serverBacked) {
      setConnectionModePref(modeId);
      return;
    }
    if (
      !shouldConfirmSwitch({
        serverBacked,
        disabled,
        busy: switchMode.isPending,
        selected,
        target: modeId,
      })
    )
      return;
    pendingModeId = modeId;
    switchModeOpen = true;
  }
</script>

<DeliveryPreference
  {modes}
  selected={pendingModeId ?? selected}
  {suggested}
  {serverBacked}
  busy={switchMode.isPending}
  onChoose={chooseMode}
  signup={signup && !serverBacked}
/>
{#if pendingModeId}
  <SwitchModeModal
    bind:open={switchModeOpen}
    targetLabel={modeLabel(pendingModeId)}
    {deviceCount}
    onCancel={() => {
      switchModeOpen = false;
      pendingModeId = null;
    }}
    onConfirm={() => switchMode.mutate()}
    busy={switchMode.isPending}
  />
{/if}
<div class="sr-only" role="status" aria-live="polite">{liveMessage}</div>
