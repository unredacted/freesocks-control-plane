/**
 * Entries a member render left out (docs/edges.md "Rendering"): on an
 * edge-required node, a retained entry on a covered transport at an address FCP
 * cannot place (neither an edge of the origin nor the node by an address it
 * knows) is withheld, since it may be the node by a name FCP never saw. The
 * render notes it on the origin (`edgeHostHides.noteWithheld`), which keeps the
 * direct-Host attention raised while renders keep doing so.
 */

/** How long a render's note keeps the origin's direct-Host attention raised. */
export const WITHHELD_ALERT_MS = 15 * 60_000;

/** A render notes what it left out at most this often per origin (each note is a write). */
export const WITHHELD_NOTE_EVERY_MS = 60_000;

/** Whether a note of withheld entries still raises the direct-Host attention. */
export function withheldFresh<T extends { at: number }>(
  note: T | undefined | null,
  now: number,
): note is T {
  return !!note && now - note.at < WITHHELD_ALERT_MS;
}

/** Whether a render that withheld entries should note it now (none noted in the last minute). */
export function withheldNoteDue(notedAt: number | null, now: number): boolean {
  return notedAt === null || now - notedAt >= WITHHELD_NOTE_EVERY_MS;
}
