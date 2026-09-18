/**
 * Test helper: a fake Remnawave panel at `panel.example` with a MUTABLE Host
 * table. It answers the three calls the direct-Host ledger, the restore
 * workflow and the fronted subscription route make:
 *
 *   GET   /api/hosts            the Host list (with `isDisabled`)
 *   PATCH /api/hosts            `{uuid, isDisabled}` (the hide / restore bit),
 *                               behaviour per `mode`: apply | ignore | fail
 *   GET   /sub/<shortUuid>      a link-list body built from the ENABLED Hosts
 *                               (one vless line per Host, remark = the Host's)
 *
 * so what members download follows the panel's own Host state end to end.
 * Not a test file itself. Every value is RFC 5737 / `*.example`.
 */
import { jsonRes, mockFetch, type FetchStub } from './mockFetch';

export interface PanelHostRow {
  uuid: string;
  remark: string;
  address: string;
  port: number;
  sni?: string | null;
  host?: string | null;
  isDisabled: boolean;
  inbound: { configProfileUuid: string; configProfileInboundUuid: string } | null;
}

export type PatchMode = 'apply' | 'ignore' | 'fail';

export const FAKE_USER_UUID = '11111111-2222-4333-8444-555555555555';
export const FAKE_REALITY_QS =
  'encryption=none&flow=xtls-rprx-vision&security=reality&sni=target.example&fp=chrome&pbk=PUBKEY&sid=abcd&type=tcp';

export interface FakeHostPanel {
  stub: FetchStub;
  hosts: PanelHostRow[];
  /** `PATCH /api/hosts` behaviour from now on. */
  setPatchMode: (mode: PatchMode) => void;
  /** Every `{uuid, isDisabled}` PATCH seen, in order. */
  patches: Array<{ uuid: string; isDisabled: boolean }>;
  /** Called BEFORE a PATCH is applied (async; a test asserts ordering here). */
  onPatch: (hook: ((p: { uuid: string; isDisabled: boolean }) => Promise<void>) | null) => void;
  /** Subscription-body fetches seen. */
  subFetches: () => number;
  find: (uuid: string) => PanelHostRow;
  body: () => string;
}

export function fakeHostPanel(initial: PanelHostRow[], mode: PatchMode = 'apply'): FakeHostPanel {
  const hosts = initial.map((h) => ({ ...h }));
  let patchMode = mode;
  let hook: ((p: { uuid: string; isDisabled: boolean }) => Promise<void>) | null = null;
  const patches: Array<{ uuid: string; isDisabled: boolean }> = [];
  let subFetches = 0;
  const body = () =>
    hosts
      .filter((h) => !h.isDisabled)
      .map((h) => `vless://${FAKE_USER_UUID}@${h.address}:${h.port}?${FAKE_REALITY_QS}#${h.remark}`)
      .join('\n');
  const stub = mockFetch(async (c) => {
    if (new URL(c.url).hostname !== 'panel.example') throw new Error(`unexpected ${c.url}`);
    if (c.path === '/api/hosts' && c.method === 'GET') return jsonRes({ response: hosts });
    if (c.path === '/api/hosts' && c.method === 'PATCH') {
      const b = c.body as { uuid: string; isDisabled?: boolean };
      if (typeof b.isDisabled !== 'boolean') return jsonRes({ message: 'bad request' }, 400);
      const p = { uuid: b.uuid, isDisabled: b.isDisabled };
      patches.push(p);
      if (hook) await hook(p);
      if (patchMode === 'fail') return jsonRes({ message: 'boom' }, 500);
      const h = hosts.find((x) => x.uuid === b.uuid);
      if (!h) return jsonRes({ message: 'not found' }, 404);
      if (patchMode === 'apply') h.isDisabled = b.isDisabled;
      return jsonRes({ response: h });
    }
    if (c.method === 'GET' && (c.path.startsWith('/sub/') || c.path.startsWith('/api/sub/'))) {
      subFetches++;
      return new Response(body(), { status: 200, headers: { 'content-type': 'text/plain' } });
    }
    return jsonRes({ message: 'not found' }, 404);
  });
  return {
    stub,
    hosts,
    setPatchMode: (m) => {
      patchMode = m;
    },
    patches,
    onPatch: (h) => {
      hook = h;
    },
    subFetches: () => subFetches,
    find: (uuid) => {
      const h = hosts.find((x) => x.uuid === uuid);
      if (!h) throw new Error(`fake panel: no Host ${uuid}`);
      return h;
    },
    body,
  };
}
