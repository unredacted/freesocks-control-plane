import { describe, expect, test } from 'vitest';
import { tagListeners, type TaggableRow } from './listenerTags';

describe('tagListeners', () => {
  test('names each row by its transport tag, reading a node once', async () => {
    const reads: string[] = [];
    const rows: TaggableRow[] = [
      { relayId: 'r1', listenerKey: 'freedomweb2hl30v' },
      { relayId: 'r1', listenerKey: 'manual' },
      { relayId: 'r1', listenerKey: null },
      { relayId: null, listenerKey: 'x' },
    ];
    await tagListeners(rows, async (relayId) => {
      reads.push(relayId);
      return [
        { listenerKey: 'freedomweb2hl30v', panelBinding: { inboundTag: 'FREEDOM_WEBSOCKET' } },
        { listenerKey: 'manual' },
      ];
    });
    expect(rows.map((r) => r.listenerTag)).toEqual(['FREEDOM_WEBSOCKET', null, null, null]);
    expect(reads).toEqual(['r1']);
  });
});
