import { describe, expect, test } from 'vitest';
import { mergeMatrixColumns } from './matrixColumns';

describe('mergeMatrixColumns (the cell-erasure regression)', () => {
  test('catalog columns first, stored-only ids appended in first-seen order', () => {
    const cols = mergeMatrixColumns(
      ['freedom-ws', 'freedom-reality'],
      [
        { cells: { 'freedom-ws': 'available', 'old-mode': 'blocked' } },
        { cells: { 'other-old': 'partial', 'old-mode': 'partial' } },
      ],
    );
    expect(cols).toEqual(['freedom-ws', 'freedom-reality', 'old-mode', 'other-old']);
  });

  test('a DISABLED catalog mode keeps its column (the old publicConfig-derived set dropped it)', () => {
    // The admin catalog includes disabled modes; passing those ids through
    // means a save round-trips their stored cells instead of erasing them.
    const cols = mergeMatrixColumns(['freedom-reality'], [{ cells: {} }]);
    expect(cols).toEqual(['freedom-reality']);
  });

  test('empty everything is empty', () => {
    expect(mergeMatrixColumns([], [])).toEqual([]);
  });
});
