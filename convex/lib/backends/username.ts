/**
 * User names FCP generates for a backend (pure; unit-tested).
 *
 * Remnawave's create-user contract takes a username of 3 to 36 characters from
 * `[A-Za-z0-9_-]` and answers 400 to anything else, so a generated name that
 * runs long fails the whole issue. Every name FCP makes is `<prefix><label>-<suffix>`:
 * the prefix says what the user is for, the suffix makes it unique, and the
 * label (a node, origin or tier name) is only there for a human reading the
 * panel. When the name would not fit, the label is cut, never the suffix.
 */
export const BACKEND_USERNAME_MAX = 36;
export const BACKEND_USERNAME_RE = /^[A-Za-z0-9_-]{3,36}$/;

/**
 * `<prefix><label>-<suffix>` within {@link BACKEND_USERNAME_MAX}. The label is
 * lower-cased with anything outside `[a-z0-9-]` replaced by `-`, then cut to
 * what is left after the prefix, the dash and the suffix; a label cut to
 * nothing drops its dash (`<prefix><suffix>`). The prefix and the suffix are
 * the caller's and must already be valid: a prefix ending in `-`, a suffix of
 * `[a-z0-9]`.
 */
export function boundedUsername(prefix: string, label: string, suffix: string): string {
  const clean = label
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/^-+/, '');
  const budget = BACKEND_USERNAME_MAX - prefix.length - 1 - suffix.length;
  const cut = budget > 0 ? clean.slice(0, budget).replace(/-+$/, '') : '';
  return cut ? `${prefix}${cut}-${suffix}` : `${prefix}${suffix}`;
}
