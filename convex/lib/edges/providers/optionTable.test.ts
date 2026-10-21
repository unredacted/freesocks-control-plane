import { readFileSync } from 'node:fs';
import { describe, expect, test } from 'vitest';
import { OPTION_TABLE_HEADING, renderOptionTable } from './optionTable';
import { tableRowCells } from './wireContract';

const DOC = new URL('../../../../docs/edges.md', import.meta.url);

function cellsOf(text: string): string[][] {
  return text
    .split('\n')
    .map(tableRowCells)
    .filter((row): row is string[] => row !== null);
}

function section(): string {
  const text = readFileSync(DOC, 'utf8');
  const start = text.indexOf(OPTION_TABLE_HEADING);
  expect(start).toBeGreaterThan(-1);
  const rest = text.slice(start + OPTION_TABLE_HEADING.length);
  const next = rest.search(/^#{2,3} /m);
  return next === -1 ? rest : rest.slice(0, next);
}

describe('provider option docs', () => {
  test('every option is a row in docs/edges.md, and every row is an option', () => {
    expect(cellsOf(section())).toEqual(cellsOf(renderOptionTable()));
  });

  test('the doc says nothing about which provider carries production traffic', () => {
    expect(section().toLowerCase()).not.toMatch(/\bproduction\b|\bin use\b|\bwe use\b/);
  });
});
