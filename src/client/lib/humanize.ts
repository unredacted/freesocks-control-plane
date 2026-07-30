/**
 * 'my-new-mode' → 'My New Mode' — the raw-slug-never-renders backstop for
 * catalog entries with neither an admin label nor built-in i18n. Pure module
 * (no i18n import) so it stays unit-testable outside the svelte pipeline.
 */
export function humanizeSlug(slug: string): string {
  return slug
    .split('-')
    .filter(Boolean)
    .map((w) => w[0]!.toUpperCase() + w.slice(1))
    .join(' ');
}
