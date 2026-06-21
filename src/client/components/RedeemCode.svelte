<script lang="ts">
  /**
   * Membership-code redemption box: an input + redeem mutation, shared by the
   * member account page and the new-account onboarding flow. The endpoint is
   * account-scoped (member session cookie), so it works anywhere the visitor is
   * signed in. Self-contained: it owns its own `role="status"` live region and
   * toasts, and invalidates account + me on success so the caller's tier-driven
   * UI updates. Callers pass copy via message keys (so it stays locale-reactive)
   * and may react to success via `onRedeemed`.
   */
  import { Button } from '@client/components/ui/button';
  import { t, normalizeDigits, type MessageKey } from '../lib/i18n/index.svelte';
  import { apiClient } from '../lib/api';
  import { RedeemCodeRequest, RedeemCodeResponse } from '../../shared/contracts/membershipCodes';
  import { queryKeys } from '../lib/queries';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  interface Props {
    /** Heading message key (default: the account-page wording). */
    titleKey?: MessageKey;
    /** Optional sub-line under the heading (e.g. gift-oriented onboarding copy). */
    descriptionKey?: MessageKey;
    /** Called after a successful redeem (e.g. to advance an onboarding step). */
    onRedeemed?: (result: { tierName: string; durationDays: number }) => void;
  }
  let { titleKey = 'account.redeemTitle', descriptionKey, onRedeemed }: Props = $props();

  const uid = $props.id();
  const qc = useQueryClient();
  let code = $state('');
  let liveMessage = $state('');

  const redeem = createMutation(() => ({
    mutationFn: () =>
      apiClient.post(
        '/api/v1/account/redeem-code',
        RedeemCodeRequest.parse({ code: code.trim() }),
        RedeemCodeResponse,
      ),
    onSuccess: (result) => {
      code = '';
      void qc.invalidateQueries({ queryKey: queryKeys.account });
      void qc.invalidateQueries({ queryKey: queryKeys.me });
      liveMessage = t('account.redeemSuccess', {
        tier: result.tierName,
        days: result.durationDays,
      });
      toast.success(
        t('account.redeemSuccess', { tier: result.tierName, days: result.durationDays }),
      );
      onRedeemed?.({ tierName: result.tierName, durationDays: result.durationDays });
    },
    onError: () => {
      // Generic, no oracle (matches the server). Don't echo a specific reason.
      liveMessage = t('account.redeemFailed');
      toast.error(t('account.redeemFailed'));
    },
  }));
</script>

<div class="rounded-xl border border-border bg-card p-4 sm:p-5">
  <div class="sr-only" role="status" aria-live="polite">{liveMessage}</div>
  <h3 id="{uid}-title" class="text-sm font-semibold">{t(titleKey)}</h3>
  {#if descriptionKey}
    <p class="mt-1 text-sm text-muted-foreground">{t(descriptionKey)}</p>
  {/if}
  <div class="mt-3 flex flex-col gap-2 sm:flex-row">
    <input
      id="{uid}-code"
      aria-labelledby="{uid}-title"
      aria-label={t('account.redeemAriaLabel')}
      inputmode="text"
      autocomplete="off"
      spellcheck="false"
      placeholder={t('account.redeemPlaceholder')}
      value={code}
      oninput={(e) =>
        (code = normalizeDigits((e.currentTarget as HTMLInputElement).value).toUpperCase())}
      onkeydown={(e) => {
        if (e.key === 'Enter' && code.trim() && !redeem.isPending) redeem.mutate();
      }}
      class="min-h-11 w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm tracking-wider focus:outline-none focus:ring-2 focus:ring-primary"
    />
    <Button
      onclick={() => redeem.mutate()}
      disabled={!code.trim() || redeem.isPending}
      class="min-h-11 shrink-0"
    >
      {redeem.isPending ? t('common.loading') : t('account.redeemSubmit')}
    </Button>
  </div>
</div>
