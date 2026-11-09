/**
 * Each attention row's listener as the backend transport it is (its inbound
 * tag), so the admin names "Freedom WebSocket", never the role's listener key.
 * Pure but for the reader; unit-tested in listenerTags.test.ts. A row with no
 * listener, or one whose listener is no backend transport, gets null. The
 * listeners of a node are read once.
 */
export interface TaggableRow {
  relayId: string | null;
  listenerKey: string | null;
  listenerTag?: string | null;
}

export async function tagListeners(
  rows: TaggableRow[],
  listenersOf: (
    relayId: string,
  ) => Promise<readonly { listenerKey: string; panelBinding?: { inboundTag: string } }[]>,
): Promise<void> {
  const byRelay = new Map<string, Map<string, string>>();
  for (const row of rows) {
    if (!row.listenerKey || !row.relayId) {
      row.listenerTag = null;
      continue;
    }
    let tags = byRelay.get(row.relayId);
    if (!tags) {
      tags = new Map();
      for (const l of await listenersOf(row.relayId))
        if (l.panelBinding) tags.set(l.listenerKey, l.panelBinding.inboundTag);
      byRelay.set(row.relayId, tags);
    }
    row.listenerTag = tags.get(row.listenerKey) ?? null;
  }
}
