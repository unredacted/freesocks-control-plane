import { describe, expect, test } from 'vitest';
import { clientCheckLine, clientCheckToast, engineWords } from './clientCheckWords';

const engines = (singbox: 'ok' | 'reality_refused', xray: 'ok' | 'timeout' = 'ok') => [
  {
    engine: 'sing-box' as const,
    code: singbox,
    engineVersion: '1.14.3',
    egress: singbox === 'ok' ? ('matched' as const) : null,
    excused: singbox !== 'ok',
  },
  {
    engine: 'xray' as const,
    code: xray,
    engineVersion: '26.10.21',
    egress: xray === 'ok' ? ('matched' as const) : null,
    excused: false,
  },
];

describe('client check words', () => {
  test('every client connected: no engine detail', () => {
    expect(engineWords(engines('ok'))).toBeNull();
    expect(
      clientCheckLine({
        at: '2026-10-25T00:00:00.000Z',
        verdict: 'passed',
        ok: true,
        engines: engines('ok'),
        control: false,
        by: 'admin',
        current: true,
      }),
    ).toBe("FCP's client check: Works.");
  });

  test('a refusal names the client and says when the check is out of date', () => {
    const line = clientCheckLine({
      at: '2026-10-25T00:00:00.000Z',
      verdict: 'passed_with_refusals',
      ok: true,
      engines: engines('reality_refused'),
      control: true,
      by: 'system',
      current: false,
    });
    expect(line).toContain('sing-box: Refused by REALITY; Xray: Connected');
    expect(line).toContain('check it again');
    expect(line).not.toContain('—');
  });

  test('toasts', () => {
    expect(clientCheckToast({ checked: false, code: 'busy' })).toMatchObject({
      tone: 'error',
      title: 'Not checked: Check client busy',
    });
    expect(
      clientCheckToast({
        checked: true,
        at: 0,
        verdict: 'address_failed',
        ok: false,
        engines: engines('reality_refused', 'timeout'),
        control: true,
        confirmed: false,
      }),
    ).toMatchObject({ tone: 'error', title: 'Does not work' });
    expect(
      clientCheckToast({
        checked: true,
        at: 0,
        verdict: 'passed',
        ok: true,
        engines: engines('ok'),
        control: false,
        confirmed: false,
      }).tone,
    ).toBe('success');
    expect(
      clientCheckToast({
        checked: true,
        at: 0,
        verdict: 'passed',
        ok: true,
        engines: engines('ok'),
        control: false,
        confirmed: true,
      }).body,
    ).toContain('now counts as tested');
  });
});
