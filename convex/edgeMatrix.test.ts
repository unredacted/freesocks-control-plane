// @vitest-environment node
import { readFileSync } from 'node:fs';
import { describe, expect, test } from 'vitest';
import { edgeCellKey, edgeMatrix, edgeMatrixUnsupported } from '../tests/compat/manifest';
import {
  MATRIX_HEADER as HEADER,
  matrixRows,
  renderMatrixTable as renderTable,
} from '../tests/compat/edgeMatrixTable';
import { LISTENER_COMBOS, comboKey, formatSupported, listenerCombo } from './lib/edges/protocols';
import { listenerLayers } from './lib/edges/layers';

/**
 * The supported matrix (tests/compat/manifest.ts `edgeMatrix`) against the
 * code and the docs: every combination of the listener catalogue appears once
 * per layer, a tested cell is one the code can actually serve (the layer rule
 * admits it, the renderer has a codec for the engine's format), and the table
 * in docs/edges.md "Supported matrix" is exactly the manifest's. The proof
 * that each tested cell connects is the edge-connection gate
 * (tests/edge-connection/member.integration.test.ts), which refuses a tested
 * cell it has no case for.
 */

/** The table between the markers in docs/edges.md, as cell text (alignment-free). */
function docsRows(): string[][] {
  const doc = readFileSync('docs/edges.md', 'utf8');
  const start = doc.indexOf('<!-- edge-matrix:start -->');
  const end = doc.indexOf('<!-- edge-matrix:end -->');
  if (start < 0 || end < start) throw new Error('docs/edges.md has no edge-matrix markers');
  return doc
    .slice(start, end)
    .split('\n')
    .filter((l) => l.trim().startsWith('|'))
    .map((l) =>
      l
        .trim()
        .replace(/^\||\|$/g, '')
        .split('|')
        .map((cell) => cell.trim()),
    )
    .filter((cells) => !cells.every((cell) => /^:?-+:?$/.test(cell)));
}

describe('the supported matrix', () => {
  test('lists every catalogued combination once per layer, and nothing else', () => {
    const keys = edgeMatrix.map(edgeCellKey);
    expect(new Set(keys).size).toBe(keys.length);
    const want = LISTENER_COMBOS.flatMap((c) =>
      (['l4', 'l7'] as const).map((layer) => edgeCellKey({ ...c, layer })),
    );
    expect([...keys].sort()).toEqual([...want].sort());
  });

  test('a tested cell is one the code serves: the layer admits it, the engine has a codec', () => {
    for (const c of edgeMatrix) {
      const tested = (['singbox', 'mihomo'] as const).filter((e) => c.engines[e] === 'tested');
      if (tested.length === 0) continue;
      const combo = listenerCombo(c)!;
      expect(combo, comboKey(c)).toBeTruthy();
      expect(c.source, `${edgeCellKey(c)} has no source`).not.toBeNull();
      // The most permissive origin the cell can have: an HTTPS origin with a
      // public certificate covering its name, accepting any Host (L7), or none (L4).
      const layers = listenerLayers({
        ...c,
        tlsNames: combo.usesSni ? [{ name: 'a.example', status: 'active' }] : [],
        originTransport:
          c.layer === 'l7'
            ? {
                scheme: 'https',
                certPublic: true,
                certNames: ['a.example'],
                acceptsHostHeader: 'any',
              }
            : null,
      }).layers;
      expect(layers, edgeCellKey(c)).toContain(c.layer);
      for (const e of tested)
        expect(
          formatSupported(c, e === 'singbox' ? 'singbox' : 'clash'),
          `${edgeCellKey(c)} ${e}`,
        ).toBe(true);
    }
  });

  test('an unsupported cell is one the code refuses at that layer, or has no codec for that engine', () => {
    for (const c of edgeMatrix) {
      const combo = listenerCombo(c)!;
      for (const e of ['singbox', 'mihomo'] as const) {
        if (c.engines[e] === 'tested') continue;
        const codec = formatSupported(c, e === 'singbox' ? 'singbox' : 'clash');
        const layers = listenerLayers({
          ...c,
          tlsNames: combo.usesSni ? [{ name: 'a.example', status: 'active' }] : [],
          originTransport: combo.isHttpTransport
            ? {
                scheme: 'https',
                certPublic: true,
                certNames: ['a.example'],
                acceptsHostHeader: 'any',
              }
            : null,
        }).layers;
        // A claim of "unsupported" must be true of the code, not merely untested.
        expect(!codec || !layers.includes(c.layer), `${edgeCellKey(c)} ${e}`).toBe(true);
      }
    }
  });

  test('an Outline key is a Shadowsocks cell, and proven only at L4', () => {
    for (const c of edgeMatrix) {
      if (c.outline === undefined) continue;
      expect(c.protocol, edgeCellKey(c)).toBe('shadowsocks');
      if (c.outline === 'tested') expect(c.layer).toBe('l4');
    }
    expect(edgeMatrix.some((c) => c.outline === 'tested')).toBe(true);
  });

  test('docs/edges.md shows exactly this matrix', () => {
    const rows = docsRows();
    expect(rows[0], `docs/edges.md has no matrix header; the table is:\n${renderTable()}`).toEqual(
      HEADER,
    );
    expect(rows.slice(1), `docs/edges.md drifted; the table is:\n${renderTable()}`).toEqual(
      matrixRows(),
    );
    const doc = readFileSync('docs/edges.md', 'utf8');
    for (const u of edgeMatrixUnsupported) expect(doc, u.what).toContain(u.what);
  });
});
