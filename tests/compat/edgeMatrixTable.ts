/**
 * The supported matrix (manifest.ts `edgeMatrix`) as the table docs/edges.md
 * shows between its `edge-matrix` markers. convex/edgeMatrix.test.ts pins the
 * docs to it; print it with `bun tests/compat/edgeMatrixTable.ts`.
 */
import { edgeMatrix, type EdgeEngine, type EdgeMatrixCell } from './manifest';

const LABEL: Record<string, string> = {
  vless: 'VLESS',
  trojan: 'Trojan',
  shadowsocks: 'Shadowsocks',
  hysteria2: 'Hysteria 2',
  tuic: 'TUIC',
  raw: 'raw TCP',
  ws: 'WebSocket',
  httpupgrade: 'HTTP Upgrade',
  grpc: 'gRPC',
  xhttp: 'XHTTP',
  udp: 'UDP (QUIC)',
  none: 'none',
  tls: 'TLS',
  reality: 'REALITY',
  l4: 'L4',
  l7: 'L7',
};

const verdict = (c: EdgeMatrixCell, e: EdgeEngine) => (c.engines[e] === 'tested' ? 'yes' : 'no');
const outlineVerdict = (c: EdgeMatrixCell) =>
  c.outline === undefined ? 'n/a' : c.outline === 'tested' ? 'yes' : 'no';

function notes(c: EdgeMatrixCell): string {
  const reasons = [
    ...new Set(
      (['singbox', 'mihomo'] as const).flatMap((e) => {
        const v = c.engines[e];
        return v === 'tested' ? [] : [v.unsupported];
      }),
    ),
  ];
  const source =
    c.source === 'operator' ? "operator's profile" : c.source ? `mode \`${c.source.mode}\`` : null;
  const outline = c.outline === 'tested' ? 'Outline key: an Outline server' : null;
  return [source, outline, ...reasons].filter(Boolean).join('; ');
}

/** The rows of the docs table, as cell text. */
export function matrixRows(): string[][] {
  return edgeMatrix.map((c) => [
    LABEL[c.protocol]!,
    LABEL[c.streamTransport]!,
    LABEL[c.security]!,
    LABEL[c.layer]!,
    verdict(c, 'singbox'),
    verdict(c, 'mihomo'),
    outlineVerdict(c),
    notes(c),
  ]);
}

export const MATRIX_HEADER = [
  'Protocol',
  'Transport',
  'Security',
  'Layer',
  'sing-box',
  'Mihomo',
  'Outline key',
  'Notes',
];

/** The table as Markdown, for pasting when the docs drift. */
export function renderMatrixTable(): string {
  const line = (cells: string[]) => `| ${cells.join(' | ')} |`;
  return [
    line(MATRIX_HEADER),
    line(MATRIX_HEADER.map(() => '---')),
    ...matrixRows().map(line),
  ].join('\n');
}

if (import.meta.main) console.log(renderMatrixTable());
