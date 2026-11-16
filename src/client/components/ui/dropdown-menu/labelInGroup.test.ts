import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

// bits-ui's GroupHeading (our DropdownMenu.Label) throws at render when it is
// not inside a DropdownMenu.Group, and the whole page falls to the error
// boundary the moment the menu opens. Every label must sit in a group.

const ROOT = join(__dirname, '..', '..', '..');

function svelteFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...svelteFiles(p));
    else if (name.endsWith('.svelte')) out.push(p);
  }
  return out;
}

/** Labels opened while no `<DropdownMenu.Group>` is open, by line number. */
function labelsOutsideGroup(source: string): number[] {
  const bad: number[] = [];
  let depth = 0;
  source.split('\n').forEach((line, i) => {
    const tags = line.matchAll(/<(\/?)DropdownMenu\.(Group|Label)\b[^>]*?(\/?)>/g);
    for (const [, close, kind, selfClose] of tags) {
      if (kind === 'Group') {
        if (close) depth = Math.max(0, depth - 1);
        else if (!selfClose) depth += 1;
      } else if (!close && depth === 0) {
        bad.push(i + 1);
      }
    }
  });
  return bad;
}

describe('dropdown menu labels', () => {
  it('finds a bare label and accepts a grouped one', () => {
    expect(labelsOutsideGroup('<DropdownMenu.Label>A</DropdownMenu.Label>')).toEqual([1]);
    expect(
      labelsOutsideGroup(
        '<DropdownMenu.Group>\n<DropdownMenu.Label>A</DropdownMenu.Label>\n</DropdownMenu.Group>',
      ),
    ).toEqual([]);
  });

  it('every DropdownMenu.Label in the client sits inside a DropdownMenu.Group', () => {
    const offenders = svelteFiles(ROOT).flatMap((f) =>
      labelsOutsideGroup(readFileSync(f, 'utf8')).map(
        (line) => `${f.slice(ROOT.length + 1)}:${line}`,
      ),
    );
    expect(offenders).toEqual([]);
  });
});
