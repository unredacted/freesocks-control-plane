/**
 * Latency over the whole path (docs/edges.md): the distance math, the path
 * figure (measured member leg or estimate, plus the node's leg), and the bands.
 */
import { describe, expect, test } from 'vitest';
import { COUNTRY_POINTS, isCountryCode } from '../../../src/shared/countryPoints';
import {
  LATENCY,
  bandOf,
  bandsOf,
  countryPoint,
  greatCircleKm,
  pathFigure,
  type LatencyInputs,
} from './latency';

/** A node in the middle of the US (a map position, as `backendServers` holds it). */
const NODE = { lat: 40, lng: -100 };
const inputs = (measured: LatencyInputs['measured'] = {}): LatencyInputs => ({
  node: NODE,
  measured,
});
const at = (country: string, locationKey = `p1:${country.toLowerCase()}`) => ({
  layer: 'l4' as const,
  addresses: {},
  locationKey,
  memberPlace: { country },
});

describe('the country points', () => {
  test('every code is two capital letters with a point on the globe; CDN codes are none', () => {
    for (const [code, [lat, lng]] of Object.entries(COUNTRY_POINTS)) {
      expect(code).toMatch(/^[A-Z]{2}$/);
      expect(Math.abs(lat)).toBeLessThanOrEqual(90);
      expect(Math.abs(lng)).toBeLessThanOrEqual(180);
    }
    expect(Object.keys(COUNTRY_POINTS).length).toBeGreaterThan(240);
    for (const c of ['XX', 'T1', 'A1', 'A2', 'O1', 'EU', 'AP', 'ZZ', '', 'us'])
      expect(isCountryCode(c)).toBe(false);
    for (const c of ['US', 'DE', 'IR', 'RU', 'CN', 'JP', 'BR']) expect(isCountryCode(c)).toBe(true);
  });

  test('distances are about right', () => {
    const km = (a: string, b: string) => greatCircleKm(countryPoint(a)!, countryPoint(b)!);
    expect(km('DE', 'DE')).toBe(0);
    expect(km('DE', 'PL')).toBeGreaterThan(400);
    expect(km('DE', 'PL')).toBeLessThan(1000);
    expect(km('DE', 'US')).toBeGreaterThan(7000);
    expect(km('DE', 'US')).toBeLessThan(8500);
    expect(km('US', 'JP')).toBeGreaterThan(9000);
    expect(km('US', 'JP')).toBeLessThan(11500);
  });
});

describe('the whole path', () => {
  test('member leg from the map, plus the node leg', () => {
    // A member in Germany: through an address in the US, the node is next door;
    // through one near Germany but far from the node, the whole path is longer.
    const viaUS = pathFigure(at('US'), 'DE', inputs())!;
    const viaNear = pathFigure(at('GE'), 'DE', inputs())!;
    expect(viaUS.measured).toBe(false);
    expect(viaNear.ms).toBeGreaterThan(viaUS.ms);
    // A member in the US: the US address is the access network and a short hop.
    expect(pathFigure(at('US'), 'US', inputs())!.ms).toBeLessThan(LATENCY.accessMs + 15);
  });

  test('a measured member leg replaces the estimate; the node leg stays', () => {
    const measured = { 'p1:ge': { IR: 50 } };
    const f = pathFigure(at('GE'), 'IR', inputs(measured))!;
    const nodeLeg = Math.round(greatCircleKm(countryPoint('GE')!, NODE) * LATENCY.msPerKm);
    expect(f.measured).toBe(true);
    expect(Math.abs(f.ms - (50 + nodeLeg))).toBeLessThanOrEqual(1);
    // Another country at the same location is still estimated.
    expect(pathFigure(at('GE'), 'RU', inputs(measured))!.measured).toBe(false);
  });

  test('no figure: an L7 front, no place country, no node position, no such country', () => {
    expect(
      pathFigure({ layer: 'l7', addresses: { hostname: 'f.example' } }, 'DE', inputs()),
    ).toBeNull();
    expect(pathFigure({ addresses: { hostname: 'f.example' } }, 'DE', inputs())).toBeNull();
    expect(pathFigure({ layer: 'l4', addresses: {} }, 'DE', inputs())).toBeNull();
    expect(pathFigure(at('US'), 'DE', { node: null, measured: {} })).toBeNull();
    expect(pathFigure(at('US'), 'XX', inputs())).toBeNull();
  });
});

describe('bands', () => {
  test('near within 1.3x or 25 ms of the best, medium within 2x or 75 ms, far beyond', () => {
    expect(bandOf(100, 100)).toBe(0);
    expect(bandOf(130, 100)).toBe(0);
    expect(bandOf(131, 100)).toBe(1);
    expect(bandOf(200, 100)).toBe(1);
    expect(bandOf(201, 100)).toBe(2);
    // A short best path: the slack decides, not the ratio.
    expect(bandOf(35, 10)).toBe(0);
    expect(bandOf(36, 10)).toBe(1);
    expect(bandOf(85, 10)).toBe(1);
    expect(bandOf(86, 10)).toBe(2);
  });

  test('against the best candidate; no figure is near; no candidate figure, all near', () => {
    expect(bandsOf([100, 160, 300, null], [true, true, true, true])).toEqual([0, 1, 2, 0]);
    // The best path is not a candidate (blocked there): the next best is the yardstick.
    expect(bandsOf([10, 100, 300], [false, true, true])).toEqual([0, 0, 2]);
    expect(bandsOf([null, undefined], [true, true])).toEqual([0, 0]);
    expect(bandsOf([100, 400], [false, false])).toEqual([0, 0]);
  });
});
