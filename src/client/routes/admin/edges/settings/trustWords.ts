/** The settings page's suspicion counts (never an account). No em-dashes in this copy. */
import type { TrustSummary } from '@shared/contracts/edges';

export function trustCountsLine(s: TrustSummary): string {
  const accounts = (n: number) => `${n} ${n === 1 ? 'account' : 'accounts'}`;
  return `Suspected now: ${accounts(s.suspected)} (${accounts(s.withStrikes)} with a strike). Today: ${s.strikesToday} ${s.strikesToday === 1 ? 'strike' : 'strikes'}, ${accounts(s.demotionsToday)} moved to open addresses.`;
}
