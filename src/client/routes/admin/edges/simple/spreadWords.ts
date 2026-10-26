/**
 * The node page's "Spread members over the addresses" card and dialog
 * (`relays.edgePick`, docs/edges.md "Address enumeration"): what the legacy
 * pick does to a replacement's holders, and how many members the switch moves,
 * from the server's estimate over synthetic seats. No em-dashes in this copy.
 */
import type { EdgePickView } from '@shared/contracts/edges';

export const SPREAD_CARD = {
  title: 'Spread members over the addresses',
  body: 'Members who share an address here move together: when it is replaced, all of them get the new one, including an account a censor uses to find addresses. Spread, each member ranks the addresses their own way, so the members of a replaced address scatter over the others and the new one goes to a random few.',
  action: 'Spread members',
} as const;

export const SPREAD_CONFIRM = {
  title: 'Spread members over the addresses?',
  body: 'Members whose ranking differs are handed other addresses already in use at their next refresh, so everyone keeps working. After this, a new or replaced address moves only the members it takes.',
  label: 'Spread members',
} as const;

/** The estimate line for the dialog; null while it loads. */
export function spreadMovesWords(view: EdgePickView | null): string | null {
  if (!view) return null;
  if (view.sampled === 0) return 'No member is handed an address here yet, so nobody moves.';
  const pct = Math.round((100 * view.moved) / view.sampled);
  if (pct === 0) return 'Hardly any member gets a different address.';
  return `About ${pct}% of this node's members get at least one different address.`;
}
