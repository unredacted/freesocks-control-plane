/**
 * What a guided setup run waits for, as the next step in plain words (pure;
 * unit-tested). One short sentence per need, ending in what to do, so a row
 * that shows a run stopped on the operator says what to do rather than only
 * that something waits. The Edges home rows (statusWords.ts) and the Servers
 * node pages (servers/lib/words.ts) read it; no heavy imports, so the Servers
 * chunk can take it.
 *
 * Exports:
 *   RUN_NEED_STEP           every run need (`need.code`) as its next step
 *   runNeedStep(code)       the same for any code (unknown or none: open its progress)
 */
import type { SetupRunNeed } from '../../../../../shared/contracts/edgeCodes';

export const RUN_NEED_STEP: Record<SetupRunNeed, string> = {
  account_untested: 'The provider account is not tested. Test it again, or choose another.',
  account_incompatible: 'The provider account cannot carry this node. Choose another.',
  maintenance: 'New work is paused for maintenance. Resume new work.',
  too_many_inbounds:
    'The node has more transports than one run protects. Pick the ones to protect.',
  use_manual_setup: 'This node is set up by hand. Give it a first address on its origin page.',
  choose_mode: 'The test account has no connection mode. Choose one.',
  provider_failed: 'The provider could not make the address. Try again, or choose another account.',
  address_unreachable: 'The new address cannot be reached. Check it again.',
  blocked_in: 'The new address is blocked in a country. Try another address.',
  coverage_incomplete: 'A transport got no address. Try again.',
  try_it: 'Test each new address.',
  test_account_used_up:
    'The test account is used up. Remove old test profiles from your clients, then try again.',
  review_changed: 'The backend Hosts changed. Review the change.',
  hide_failed: 'An old direct Host could not be hidden. Check again.',
  family_disabled: 'A client family is switched off. Turn it on.',
  rehearsal_failed: 'A member subscription did not work through the new address. Try again.',
  resilience_short: 'The backup address is at the same provider as the main one. Try again.',
  node_not_approved: 'Every address works. Approve go-live.',
  quarantined: 'Paused for safety. Check the backend, then choose which addresses to keep.',
};

export function runNeedStep(code: string | null | undefined): string {
  return (
    (code ? (RUN_NEED_STEP as Record<string, string>)[code] : undefined) ??
    'Open its progress to see what to do.'
  );
}
