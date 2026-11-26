/**
 * Splits admin copy into its first sentence and the rest, so a list can show
 * one sentence and keep the rest behind a "details" toggle.
 *
 *   splitLead('Ready. Front it to go live.') -> { lead: 'Ready.', rest: 'Front it to go live.' }
 *   splitLead('One sentence only.')          -> { lead: 'One sentence only.', rest: '' }
 *
 * A sentence ends at `.`, `!` or `?` followed by whitespace and an upper-case
 * letter or a digit, so "about 1.5 GB" and "e.g. this" never split. Leading
 * and trailing whitespace is dropped.
 */
export function splitLead(text: string): { lead: string; rest: string } {
  const t = text.trim();
  const m = /^(.+?[.!?])\s+(?=[A-Z0-9"'(])/su.exec(t);
  if (!m) return { lead: t, rest: '' };
  const lead = m[1]!;
  return { lead, rest: t.slice(m[0].length).trim() };
}
