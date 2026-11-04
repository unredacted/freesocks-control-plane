/**
 * Modes whose entries are XHTTP under REALITY (the built-in `freedom-xhttp`).
 * An app the client catalog marks `xhttp: false` can't connect on one: sing-box
 * has no XHTTP, and the panel leaves it out of the sing-box bodies Karing gets
 * too. The setup page leaves those apps out on these modes, and the app notice
 * (convex/lib/appNotice.ts) never names one. Zod-free: Convex imports it.
 */
export const XHTTP_MODE_IDS: ReadonlySet<string> = new Set(['freedom-xhttp']);

export function isXhttpMode(modeId: string | null | undefined): boolean {
  return !!modeId && XHTTP_MODE_IDS.has(modeId);
}
