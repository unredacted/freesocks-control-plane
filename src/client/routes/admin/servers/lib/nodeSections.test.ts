import { describe, expect, test } from 'vitest';
import {
  NODE_SECTIONS,
  ORIGIN_SECTIONS,
  SECTION_LABELS,
  detailsOpenFor,
  detailsSearch,
  joinSearch,
  parseSection,
  patchSearch,
} from './nodeSections';

describe('node page sections', () => {
  test('the bar, in order, and the shorter one of an origin added by hand', () => {
    expect(NODE_SECTIONS.map((s) => SECTION_LABELS[s])).toEqual([
      'Summary',
      'Addresses',
      'Transports',
      'SNIs',
      'Modes',
      'Activity',
      'Technical details',
    ]);
    expect(ORIGIN_SECTIONS).toEqual(['summary', 'addresses', 'activity', 'details']);
  });

  test('parseSection keeps only known sections', () => {
    expect(parseSection('snis')).toBe('snis');
    expect(parseSection('details')).toBe('details');
    expect(parseSection('nope')).toBeNull();
    expect(parseSection(null)).toBeNull();
  });

  test('the fold opens for section=details or any origin page param', () => {
    expect(detailsOpenFor('')).toBe(false);
    expect(detailsOpenFor('?section=summary&test=e1&run=r1')).toBe(false);
    expect(detailsOpenFor('?section=details')).toBe(true);
    expect(detailsOpenFor('?tab=listeners')).toBe(true);
    expect(detailsOpenFor('?edge=e1')).toBe(true);
    expect(detailsOpenFor('?rotation=r1')).toBe(true);
    expect(detailsOpenFor('?listener=main')).toBe(true);
    expect(detailsOpenFor('?edge=')).toBe(false);
  });
});

describe('the old origin details query on the node page', () => {
  test.each([
    ['', '?section=details'],
    ['?tab=overview', '?section=summary'],
    ['?tab=edges&edge=e1', '?section=details&tab=edges&edge=e1'],
    ['?tab=rotations&rotation=r1', '?section=details&tab=rotations&rotation=r1'],
    ['?tab=listeners&listener=main', '?section=details&tab=listeners&listener=main'],
    ['?tab=probes', '?section=details&tab=probes'],
    ['?tab=bogus', '?section=details'],
    ['?edge=e1&test=e2', '?section=details&edge=e1&test=e2'],
    ['?section=x&tab=overview&rotation=r1', '?section=summary&rotation=r1'],
  ])('%s -> %s', (from, to) => {
    expect(detailsSearch(from)).toBe(to);
  });

  test('joins onto a node page that already has a query', () => {
    expect(joinSearch('/admin/servers/nodes/u1?backend=a', '?section=details&tab=edges')).toBe(
      '/admin/servers/nodes/u1?backend=a&section=details&tab=edges',
    );
    expect(joinSearch('/admin/servers/origins/m', '?section=summary')).toBe(
      '/admin/servers/origins/m?section=summary',
    );
    expect(joinSearch('/x', '')).toBe('/x');
  });

  test('patchSearch sets, removes and keeps', () => {
    expect(patchSearch('/p', '?backend=a&section=snis', { run: 'r1', section: null })).toBe(
      '/p?backend=a&run=r1',
    );
    expect(patchSearch('/p', '', { front: null })).toBe('/p');
  });
});
