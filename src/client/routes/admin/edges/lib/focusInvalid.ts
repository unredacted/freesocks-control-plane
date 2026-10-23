/**
 * After a submit that found a problem: bring the first field marked
 * `aria-invalid="true"` under `root` into view and focus it (an option beside
 * its error, lib/options.ts `fieldProblem`). Returns whether one was found.
 *
 * Exports: focusFirstInvalid(root).
 */
export function focusFirstInvalid(root: ParentNode | null | undefined): boolean {
  const el = root?.querySelector<HTMLElement>('[aria-invalid="true"]');
  if (!el) return false;
  el.scrollIntoView({ block: 'center' });
  el.focus({ preventScroll: true });
  return true;
}
