import { describe, expect, it } from 'vitest';
import {
  REALITY_REFUSAL_CAUSES,
  realityClientRefusal,
  type RealityClientRefusal,
} from '../../shared/contracts/realityClients';
import { REALITY_TEST_ADVICE, realityRefusalWords } from './realityClientWords';

const of = (cause: RealityClientRefusal['cause'], over: Partial<RealityClientRefusal> = {}) => ({
  cause,
  refuses: ['singbox' as const, 'mihomo' as const],
  xrayVersion: '26.7.28',
  minClientVer: null,
  maxClientVer: null,
  ...over,
});

describe('realityRefusalWords', () => {
  it('names the families, why, and the one setting that lets them in', () => {
    const w = realityRefusalWords(
      realityClientRefusal({ minClientVer: null, maxClientVer: null }, '26.7.28')!,
    );
    expect(w.title).toBe(
      'Refuses sing-box (Hiddify, Karing) and Mihomo (Clash Verge, FlClash) clients',
    );
    expect(w.why).toMatch(
      /sets no minClientVer, and Xray 26\.7\.28 then lets in only Xray clients from 26\.3\.27 on/,
    );
    expect(w.fix).toMatch(/Add "minClientVer": "1\.8\.1" to the transport's realitySettings/);
  });

  it('an unknown Xray version only may refuse them', () => {
    const w = realityRefusalWords(of('core_unknown', { xrayVersion: null }));
    expect(w.title).toMatch(/^May refuse /);
    expect(w.why).toMatch(/could not read the node's Xray version.*26\.7\.11 to 26\.7\.28/);
  });

  it('bounds set too tight say what the clients send', () => {
    const min = realityRefusalWords(
      of('min_above', { refuses: ['singbox'], minClientVer: '1.8.2' }),
    );
    expect(min.title).toBe('Refuses sing-box (Hiddify, Karing) clients');
    expect(min.why).toBe('Its minClientVer is 1.8.2, above what they send (sing-box sends 1.8.1).');
    expect(min.fix).toMatch(/Set "minClientVer" to "1\.8\.1"/);
    const max = realityRefusalWords(
      of('max_below', { refuses: ['mihomo'], maxClientVer: '1.8.1' }),
    );
    expect(max.why).toBe('Its maxClientVer is 1.8.1, below what they send (Mihomo sends 1.8.2).');
    expect(max.fix).toMatch(/Remove "maxClientVer".*or raise it to 1\.8\.2 or above/);
  });

  it('has words for every cause, and no em-dash anywhere', () => {
    for (const cause of REALITY_REFUSAL_CAUSES) {
      const w = realityRefusalWords(of(cause, { minClientVer: '1.8.2', maxClientVer: '1.8.1' }));
      for (const s of [w.title, w.why, w.fix]) {
        expect(s.trim()).toBeTruthy();
        expect(s).not.toContain('—');
      }
    }
    expect(REALITY_TEST_ADVICE).not.toContain('—');
    expect(REALITY_TEST_ADVICE).toMatch(/sing-box or Mihomo/);
  });
});
