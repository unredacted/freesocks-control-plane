/**
 * THE POST-QUANTUM MATRIX: which app gets a post-quantum key exchange in
 * which connection mode (docs/client-compatibility.md § "Post-quantum key
 * exchange", the table between its `pq-matrix` markers, pinned to this file by
 * convex/pqKeyExchange.test.ts; print it with `bun tests/compat/pqMatrix.ts`).
 *
 * What post-quantum means differs by mode:
 *
 *   REALITY (privacy-reality, freedom-reality, freedom-xhttp)   the TLS 1.3
 *     key exchange of the REALITY handshake, end to end with the node: PQ when
 *     the server picks X25519MLKEM768, which it does whenever the client
 *     offers it (the node's Xray-core, v26.7.28) and X25519 otherwise.
 *   WebSocket behind a CDN (freedom-ws)   the TLS ends at the CDN, so the
 *     guarantee is the VLESS Encryption layer inside the stream
 *     (mlkem768x25519plus): the mode's encrypted twin, handed to a family by
 *     its `edge.render.clients.<family>.encryption` rule.
 *   Hysteria (privacy-hysteria)   the QUIC TLS key exchange. Not measured:
 *     the mode ships off, the taps here forward TCP only, and reading a QUIC
 *     handshake means removing its Initial packet protection first (keys any
 *     observer derives from the connection id), which nothing here does yet.
 *
 * Every `yes` and every pinned `no` below is an assertion in CI with the
 * pinned engines, so a regression (a body losing the Mihomo key share
 * option, a family rule turning plain) or an engine release that changes its
 * key exchange (sing-box learning X25519MLKEM768) fails a job and lands here:
 *   - `bun run test:integration:reality-keyshare`: every engine through a tap
 *     in front of the node's core and a later one, the group the server
 *     picked; Xray-core and Mihomo through a VLESS Encryption inbound, plain
 *     clients refused there, sing-box unable to hold the entry at all;
 *   - `bun run test:integration:edge-connection`: the REAL served bodies of
 *     the REALITY cells through the fake L4 edge (which reads the same
 *     handshake), and the WebSocket twin as each family is served it;
 *   - `bun run test` (convex/pqKeyExchange.test.ts): the parser, the family
 *     rules against this file, and the docs table.
 */
import { artifacts, clients } from './manifest';

/** The connection modes FCP ships (convex/lib/connectionModes.ts `DEFAULT_CONNECTION_MODES`). */
export const PQ_MODES = [
  { mode: 'privacy-reality', layer: 'reality', transport: 'raw' },
  { mode: 'freedom-reality', layer: 'reality', transport: 'raw' },
  { mode: 'freedom-xhttp', layer: 'reality', transport: 'xhttp' },
  { mode: 'freedom-ws', layer: 'vless-encryption', transport: 'ws' },
  { mode: 'privacy-hysteria', layer: 'quic', transport: 'hysteria' },
] as const;
export type PqMode = (typeof PQ_MODES)[number]['mode'];

/** The TLS group names convex/../docker/compat/tlsHello.ts `groupName` reports. */
export const PQ_GROUP = 'X25519MLKEM768';
export const CLASSIC_GROUP = 'x25519';

/** The engine inside an app: what decides its key exchange. */
export type PqEngine = 'xray' | 'mihomo' | 'singbox' | 'hiddify' | 'unverified';

export interface PqEngineFacts {
  label: string;
  /**
   * REALITY: the group the node's core picks for the body FCP serves this
   * engine (Mihomo: its Clash body, which asks for the key share; Xray: a
   * share link with the Host's `chrome` fingerprint; sing-box: its JSON).
   * Asserted against a real core; `null` = not run in CI.
   */
  reality: typeof PQ_GROUP | typeof CLASSIC_GROUP | null;
  /** Whether the body FCP serves it carries an XHTTP entry it can use (freedom-xhttp). */
  xhttp: boolean;
  /**
   * Whether it connects on a VLESS Encryption entry (asserted: Xray-core and
   * Mihomo through a real encrypted inbound; sing-box cannot hold one).
   * `null` = not run in CI.
   */
  vlessEncryption: boolean | null;
}

export const PQ_ENGINES: Record<PqEngine, PqEngineFacts> = {
  xray: {
    label: 'Xray-core v26.7.28, v26.10.21',
    reality: PQ_GROUP,
    xhttp: true,
    vlessEncryption: true,
  },
  mihomo: {
    label: `Mihomo v${artifacts.mihomo.version}`,
    reality: PQ_GROUP,
    xhttp: true,
    vlessEncryption: true,
  },
  singbox: {
    label: `sing-box v${artifacts.singbox.version}`,
    // common/tls/reality_client.go removes the X25519MLKEM768 share whatever
    // the configuration says (docs/client-compatibility.md § "REALITY client versions").
    reality: CLASSIC_GROUP,
    // The panel leaves XHTTP out of a sing-box body: sing-box has no XHTTP.
    xhttp: false,
    vlessEncryption: false,
  },
  hiddify: {
    // Its own sing-box fork (hiddify-sing-box): not the pinned sing-box.
    label: 'hiddify-sing-box (not run in CI)',
    reality: null,
    xhttp: true,
    vlessEncryption: null,
  },
  unverified: {
    label: 'own engine (not run in CI)',
    reality: null,
    xhttp: true,
    vlessEncryption: null,
  },
};

export interface PqApp {
  name: string;
  /** One User-Agent it sends (the family is read from it, convex/lib/edges/clientFamilies.ts). */
  userAgent: string;
  engine: PqEngine;
  /** What the app runs, where the engine's own label would claim more than CI shows. */
  engineLabel?: string;
}

/**
 * Every app of the catalog (manifest.ts `clients`, Outline aside: an Outline
 * key is Shadowsocks, no TLS and no VLESS), plus the two families the catalog
 * has no app for yet.
 */
const ENGINE_OF: Record<string, Pick<PqApp, 'engine' | 'engineLabel'>> = {
  'sing-box': { engine: 'singbox' },
  Hiddify: { engine: 'hiddify' },
  // Its own sing-box build: the body is sing-box JSON, the core is not the pinned one.
  Karing: { engine: 'unverified', engineLabel: 'own sing-box build (not run in CI)' },
  Anywhere: { engine: 'unverified' },
  v2rayNG: { engine: 'xray' },
  v2rayN: { engine: 'xray' },
  Clash: { engine: 'mihomo' },
  FlClash: { engine: 'mihomo' },
  'Clash Meta for Android': { engine: 'mihomo' },
  // Mihomo Party's new name (the catalog renamed it).
  'Clash Party': { engine: 'mihomo' },
  Throne: { engine: 'unverified' },
  Shadowrocket: { engine: 'unverified' },
};
export const PQ_APPS: PqApp[] = [
  ...clients
    .filter((c) => c.format !== 'outline')
    .map((c) => {
      const engine = ENGINE_OF[c.name];
      if (!engine) throw new Error(`pqMatrix: no engine for the catalogued app ${c.name}`);
      return { name: c.name, userAgent: c.userAgents[0]!, ...engine };
    }),
  { name: 'Happ', userAgent: 'Happ/1.0', engine: 'xray' },
  { name: 'Streisand', userAgent: 'Streisand/1.0', engine: 'xray' },
];

/** One cell: `yes` / `no` (each asserted), `n/a`, or `not measured`. */
export interface PqCell {
  pq: 'yes' | 'no' | 'n/a' | 'not measured';
  /** What the cell rests on, in a few words (the table's text). */
  how: string;
}

/**
 * An app's cell in one mode. `twin` = whether its family is handed the
 * encrypted entry (`edge.render.clients.<family>.encryption` is not `plain`).
 */
export function pqCell(app: PqApp, mode: PqMode, twin: boolean): PqCell {
  const e = PQ_ENGINES[app.engine];
  const m = PQ_MODES.find((x) => x.mode === mode)!;
  if (m.layer === 'quic') return { pq: 'not measured', how: 'QUIC, mode off' };
  if (m.layer === 'reality') {
    if (m.transport === 'xhttp' && !e.xhttp) return { pq: 'n/a', how: 'no XHTTP entry' };
    if (e.reality === null) return { pq: 'not measured', how: 'engine not run' };
    return e.reality === PQ_GROUP
      ? { pq: 'yes', how: PQ_GROUP }
      : { pq: 'no', how: e.reality === CLASSIC_GROUP ? 'X25519' : e.reality };
  }
  if (!twin) return { pq: 'no', how: 'plain entry, family rule' };
  if (e.vlessEncryption === null) return { pq: 'not measured', how: 'encrypted entry first' };
  return e.vlessEncryption
    ? { pq: 'yes', how: 'VLESS Encryption' }
    : // A family handed the twin whose engine cannot use it: the matrix test refuses this.
      { pq: 'no', how: 'cannot use the encrypted entry' };
}

export const PQ_HEADER = ['App', 'Family', 'Engine', ...PQ_MODES.map((m) => `\`${m.mode}\``)];

/** The rows of the docs table, as cell text. `familyOf` / `twinOf` come from the code. */
export function pqRows(
  familyOf: (ua: string) => string,
  twinOf: (family: string) => boolean,
): string[][] {
  return PQ_APPS.map((app) => {
    const family = familyOf(app.userAgent);
    return [
      app.name,
      `\`${family}\``,
      app.engineLabel ?? PQ_ENGINES[app.engine].label,
      ...PQ_MODES.map((m) => {
        const c = pqCell(app, m.mode, twinOf(family));
        return `${c.pq} (${c.how})`;
      }),
    ];
  });
}

/** The table as Markdown (prettier's alignment), for the docs. */
export function renderPqTable(rows: string[][]): string {
  const all = [PQ_HEADER, ...rows];
  const width = PQ_HEADER.map((_, i) => Math.max(3, ...all.map((r) => r[i]!.length)));
  const line = (r: string[]) => `| ${r.map((c, i) => c.padEnd(width[i]!)).join(' | ')} |`;
  return [
    line(PQ_HEADER),
    `| ${width.map((w) => '-'.repeat(w)).join(' | ')} |`,
    ...rows.map(line),
  ].join('\n');
}

if (import.meta.main) {
  const { classifyClient } = await import('../../convex/lib/edges/clientFamilies');
  const { defaultClientRule } = await import('../../convex/lib/edgeConfig');
  console.log(
    renderPqTable(
      pqRows(
        (ua) => classifyClient(ua).family,
        (f) => defaultClientRule(f as never).encryption !== 'plain',
      ),
    ),
  );
}
