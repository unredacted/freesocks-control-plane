import { describe, expect, test } from 'vitest';
import {
  originHostname,
  originLabel,
  originMarker,
  planRecord,
  verifyResolution,
  originNameHeld,
} from './originDns';

const marker = originMarker('panel', 'node a');

describe('originLabel', () => {
  test('makes a DNS label of a node name', () => {
    expect(originLabel('node a')).toBe('node-a');
    expect(originLabel('Node_1.b')).toBe('node-1-b');
    expect(originLabel('--x--')).toBe('x');
    expect(originLabel('a'.repeat(70))).toBe('a'.repeat(63));
    expect(originLabel('___')).toBeNull();
    expect(originHostname('node-a', 'Origin.Example.')).toBe('node-a.origin.example');
  });
});

describe('planRecord', () => {
  const desired = { type: 'A' as const, name: 'node-a.origin.example', content: '203.0.113.7' };
  test('creates when nothing is at the name', () => {
    expect(planRecord([], desired, marker)).toEqual({ action: 'create' });
    expect(
      planRecord(
        [
          {
            id: '1',
            type: 'AAAA',
            name: desired.name,
            content: '2001:db8::1',
            proxied: false,
            comment: marker,
          },
        ],
        desired,
        marker,
      ),
    ).toEqual({ action: 'create' });
  });
  test('keeps its own record with the right content, replaces one with other content', () => {
    const mine = {
      id: '1',
      type: 'A',
      name: desired.name,
      content: '203.0.113.7',
      proxied: false,
      comment: marker,
    };
    expect(planRecord([mine], desired, marker)).toEqual({ action: 'keep', id: '1' });
    expect(planRecord([{ ...mine, content: '203.0.113.8' }], desired, marker)).toEqual({
      action: 'replace',
      deleteId: '1',
    });
  });
  test('never touches what it did not write', () => {
    const foreign = {
      id: '2',
      type: 'A',
      name: desired.name,
      content: '203.0.113.7',
      proxied: false,
    };
    expect(planRecord([foreign], desired, marker)).toEqual({
      action: 'conflict',
      reason: 'foreign',
    });
    expect(
      planRecord([{ ...foreign, type: 'CNAME', content: 'x.example' }], desired, marker),
    ).toEqual({ action: 'conflict', reason: 'cname' });
    expect(planRecord([{ ...foreign, comment: marker, proxied: true }], desired, marker)).toEqual({
      action: 'conflict',
      reason: 'proxied',
    });
    expect(
      planRecord(
        [
          { ...foreign, id: 'a', comment: marker },
          { ...foreign, id: 'b', comment: marker },
        ],
        desired,
        marker,
      ),
    ).toEqual({ action: 'conflict', reason: 'several' });
  });
});

describe('verifyResolution', () => {
  test('exactly the intended addresses per family', () => {
    expect(verifyResolution({ v4: ['203.0.113.7'], v6: [] }, { v4: '203.0.113.7' })).toBe(true);
    expect(
      verifyResolution({ v4: ['203.0.113.7', '203.0.113.8'], v6: [] }, { v4: '203.0.113.7' }),
    ).toBe(false);
    expect(
      verifyResolution({ v4: ['203.0.113.7'], v6: ['2001:db8::1'] }, { v4: '203.0.113.7' }),
    ).toBe(false);
    expect(
      verifyResolution(
        { v4: ['203.0.113.7'], v6: ['2001:DB8::1'] },
        { v4: '203.0.113.7', v6: '2001:db8::1' },
      ),
    ).toBe(true);
  });
});

describe('originNameHeld', () => {
  const node = (over: Partial<Parameters<typeof originNameHeld>[0]> = {}) => ({
    name: 'node-w',
    state: 'pending',
    delivery: { exposure: { everLive: false } },
    ...over,
  });
  test('a node that served nobody follows a zone move', () => {
    expect(originNameHeld(node(), new Set())).toBe(false);
    expect(originNameHeld(node(), new Set(['other']))).toBe(false);
  });
  test('live, fronted (under its name or a former one), adopted or retiring holds the name', () => {
    expect(originNameHeld(node({ delivery: { exposure: { everLive: true } } }), new Set())).toBe(
      true,
    );
    expect(originNameHeld(node(), new Set(['node-w']))).toBe(true);
    expect(originNameHeld(node({ formerNames: ['old-w'] }), new Set(['old-w']))).toBe(true);
    expect(originNameHeld(node({ adopted: { at: 1 } }), new Set())).toBe(true);
    expect(originNameHeld(node({ state: 'retiring' }), new Set())).toBe(true);
  });
});
