/**
 * The censorship-matrix editor's column set: every catalog mode (ENABLED OR
 * NOT — a temporarily-disabled mode's cells must stay editable, not silently
 * erased on the next save, which is exactly what the old publicConfig-derived
 * columns did) UNION any id still present in stored rows (a deleted mode's
 * cells stay visible so the operator can clear them deliberately). Catalog
 * order first, then stored-only ids in first-seen order.
 */
export function mergeMatrixColumns(
  catalogIds: readonly string[],
  storedRows: ReadonlyArray<{ cells: Record<string, unknown> }>,
): string[] {
  const out = [...catalogIds];
  const seen = new Set(out);
  for (const row of storedRows) {
    for (const id of Object.keys(row.cells)) {
      if (!seen.has(id)) {
        seen.add(id);
        out.push(id);
      }
    }
  }
  return out;
}
