import { describe, expect, it } from 'vitest';
import {
  REALITY_REFUSAL_CAUSES,
  realityClientRefusal,
  type RealityClientRefusal,
} from '../../shared/contracts/realityClients';
import { REALITY_TEST_ADVICE, realityRefusalWords } from './realityClientWords';

const judged = (min: string | null, max: string | null, core: string | null) =>
  realityClientRefusal({ minClientVer: min, maxClientVer: max }, core)!;

describe('realityRefusalWords', () => {
  it('names the families, why, and the one setting that lets them in', () => {
    const w = realityRefusalWords(judged(null, null, '26.7.28'));
    expect(w.title).toBe(
      'Refuses sing-box (Hiddify, Karing) and Mihomo (Clash Verge, FlClash) clients',
    );
    expect(w.why).toMatch(
      /sets no minClientVer, and Xray 26\.7\.28 then lets in only Xray clients from 26\.3\.27 on/,
    );
    expect(w.fix).toMatch(/Add "minClientVer": "1\.8\.1" to the transport's realitySettings/);
  });

  it('a bound refusing one family names only that family, and the fix that lifts it', () => {
    const min = realityRefusalWords(judged('1.8.2', null, '26.6.27'));
    expect(min.title).toBe('Refuses sing-box (Hiddify, Karing) clients');
    expect(min.why).toMatch(
      /^Its minClientVer is 1\.8\.2, above what sing-box sends \(1\.8\.1\)\./,
    );
    expect(min.fix).toBe(
      'Set "minClientVer" to "1.8.1" in the transport\'s realitySettings in the backend.',
    );
    const max = realityRefusalWords(judged('1.0.0', '1.8.1', '26.6.27'));
    expect(max.title).toBe('Refuses Mihomo (Clash Verge, FlClash) clients');
    expect(max.why).toMatch(/^Its maxClientVer is 1\.8\.1, below what Mihomo sends \(1\.8\.2\)\./);
    // Never "add minClientVer" for an upper bound.
    expect(max.fix).not.toMatch(/Add "minClientVer"/);
    expect(max.fix).toMatch(/Remove "maxClientVer".*or raise it to 1\.8\.2 or above/);
  });

  it('opposite bounds give both reasons and both fixes', () => {
    const w = realityRefusalWords(judged('1.8.2', '1.8.1', '26.6.27'));
    expect(w.title).toMatch(/^Refuses sing-box .* and Mihomo .* clients$/);
    expect(w.why).toMatch(/minClientVer is 1\.8\.2, above what sing-box sends/);
    expect(w.why).toMatch(/maxClientVer is 1\.8\.1, below what Mihomo sends/);
    expect(w.fix).toMatch(/Set "minClientVer" to "1\.8\.1"/);
    expect(w.fix).toMatch(/Remove "maxClientVer"/);
  });

  it('from Xray 26.9.8 on, sing-box is refused and no transport setting is offered as the fix', () => {
    const w = realityRefusalWords(judged('1.8.1', null, '26.9.9'));
    expect(w.title).toBe('Refuses sing-box (Hiddify, Karing) clients');
    expect(w.why).toMatch(/From Xray 26\.9\.8 on \(this node runs 26\.9\.9\).*X25519MLKEM768/);
    expect(w.fix).toMatch(/^No setting of the transport lets sing-box in on this Xray/);
  });

  it('an unknown Xray version only may refuse them', () => {
    const w = realityRefusalWords(judged(null, null, null));
    expect(w.title).toMatch(/^May refuse /);
    expect(w.why).toMatch(/could not read the node's Xray version.*26\.7\.11 to 26\.7\.28/);
    const withMin = realityRefusalWords(judged('1.8.1', null, null));
    expect(withMin.title).toBe('May refuse sing-box (Hiddify, Karing) clients');
    expect(withMin.fix).toMatch(/Check the node's Xray version/);
  });

  it('has words for every cause, and no em-dash anywhere', () => {
    for (const cause of REALITY_REFUSAL_CAUSES) {
      const r: RealityClientRefusal = {
        refuses: ['singbox', 'mihomo'],
        reasons: [{ cause, families: ['singbox', 'mihomo'] }],
        xrayVersion: '26.7.28',
        minClientVer: '1.8.2',
        maxClientVer: '1.8.1',
      };
      const w = realityRefusalWords(r);
      for (const s of [w.title, w.why, w.fix]) {
        expect(s.trim()).toBeTruthy();
        expect(s).not.toContain('—');
      }
    }
    expect(REALITY_TEST_ADVICE).not.toContain('—');
    expect(REALITY_TEST_ADVICE).toMatch(/sing-box or Mihomo/);
  });
});
