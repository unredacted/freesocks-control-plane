import { afterEach, describe, expect, test, vi } from 'vitest';
import {
  resolveRoute,
  sanitizeCountryCode,
  sanitizeHostname,
  sanitizeIp,
  sanitizeLanguage,
  sanitizeReferrer,
  sanitizeRegionCode,
  sanitizeScreen,
  sanitizeUserAgent,
  sendUmamiEvent,
} from './umami';

const UUID = 'b1f0a2c4-1234-4abc-9def-0123456789ab';
const CFG = { umamiUrl: 'https://analytics.example.org', websiteId: UUID };

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('resolveRoute', () => {
  test('known member routes map to their static titles', () => {
    expect(resolveRoute('/')).toEqual({ url: '/', title: 'Home' });
    expect(resolveRoute('/get-account')).toEqual({ url: '/get-account', title: 'Get account' });
    expect(resolveRoute('/account')).toEqual({ url: '/account', title: 'Account' });
    expect(resolveRoute('/login')).toEqual({ url: '/login', title: 'Sign in' });
    expect(resolveRoute('/status')).toEqual({ url: '/status', title: 'Network status' });
  });

  test('anything off the allowlist buckets to /other (no free-form path leaks)', () => {
    expect(resolveRoute('/r/FSR-SECRET-CODE').url).toBe('/other');
    expect(resolveRoute('/account/123').url).toBe('/other');
    expect(resolveRoute('/account?tab=usage').url).toBe('/other');
    expect(resolveRoute('/admin')).toEqual({ url: '/other', title: 'Other' });
    expect(resolveRoute('../etc').url).toBe('/other');
    expect(resolveRoute('').url).toBe('/other');
    expect(resolveRoute(42).url).toBe('/other');
    expect(resolveRoute(undefined).url).toBe('/other');
    expect(resolveRoute(null).url).toBe('/other');
  });
});

describe('sanitizeReferrer', () => {
  test('external URLs reduce to origin only (never a path/query)', () => {
    expect(sanitizeReferrer('https://ref.example/secret-thread?t=1#frag')).toBe(
      'https://ref.example',
    );
    expect(sanitizeReferrer('http://ref.example/x')).toBe('http://ref.example');
  });

  test('in-app referrers must themselves be allowlisted routes', () => {
    expect(sanitizeReferrer('/get-account')).toBe('/get-account');
    expect(sanitizeReferrer('/r/FSR-SECRET-CODE')).toBe('');
  });

  test('junk falls to empty', () => {
    expect(sanitizeReferrer('')).toBe('');
    expect(sanitizeReferrer('javascript:alert(1)')).toBe('');
    expect(sanitizeReferrer('not a url')).toBe('');
    expect(sanitizeReferrer(42)).toBe('');
    expect(sanitizeReferrer(`https://a.example/${'x'.repeat(600)}`)).toBe('');
  });
});

describe('sanitizeScreen', () => {
  test('exact bucket match only (a real resolution is not a valid value)', () => {
    expect(sanitizeScreen('480x854')).toBe('480x854');
    expect(sanitizeScreen('834x1112')).toBe('834x1112');
    expect(sanitizeScreen('1920x1080')).toBe('1920x1080');
    expect(sanitizeScreen('1366x768')).toBe('');
    expect(sanitizeScreen('nope')).toBe('');
    expect(sanitizeScreen(42)).toBe('');
  });
});

describe('sanitizeLanguage', () => {
  test('primary subtag only', () => {
    expect(sanitizeLanguage('fa')).toBe('fa');
    expect(sanitizeLanguage('ZH')).toBe('zh');
    expect(sanitizeLanguage('en-GB')).toBe('');
    expect(sanitizeLanguage('not a lang')).toBe('');
    expect(sanitizeLanguage(42)).toBe('');
  });
});

describe('sanitizeHostname', () => {
  test('hostname charset, port stripped, lowercased', () => {
    expect(sanitizeHostname('FreeSocks.org')).toBe('freesocks.org');
    expect(sanitizeHostname('freesocks.org:443')).toBe('freesocks.org');
    expect(sanitizeHostname('evil host\r\nx')).toBe('');
    expect(sanitizeHostname('')).toBe('');
    expect(sanitizeHostname(null)).toBe('');
  });
});

describe('sanitizeUserAgent', () => {
  test('strips CR/LF and control chars (outbound-header injection hygiene)', () => {
    const out = sanitizeUserAgent('Mozilla/5.0\r\nX-Evil: 1 ');
    expect(out).not.toMatch(/[\r\n]/);
    expect(out).toBe('Mozilla/5.0X-Evil: 1');
  });

  test('falls back to the fixed relay UA (Umami drops UA-less events)', () => {
    expect(sanitizeUserAgent(null)).toBe('Mozilla/5.0 (compatible; FreeSocksRelay/1.0)');
    expect(sanitizeUserAgent('')).toBe('Mozilla/5.0 (compatible; FreeSocksRelay/1.0)');
    expect(sanitizeUserAgent('\r\n')).toBe('Mozilla/5.0 (compatible; FreeSocksRelay/1.0)');
  });

  test('caps length', () => {
    expect(sanitizeUserAgent('a'.repeat(500)).length).toBe(350);
  });
});

describe('sendUmamiEvent', () => {
  test('posts the exact Umami wire shape and forwards NO inbound headers', async () => {
    const spy = vi.fn().mockResolvedValue(new Response('ok'));
    vi.stubGlobal('fetch', spy);
    await sendUmamiEvent({
      cfg: CFG,
      input: {
        route: '/account',
        referrer: 'https://ref.example/secret?x=1',
        screen: '1920x1080',
        language: 'fa',
      },
      userAgent: 'TestUA/1.0',
      hostname: 'freesocks.org:443',
      clientIp: null,
      geo: null,
    });
    expect(spy).toHaveBeenCalledTimes(1);
    const [url, init] = spy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://analytics.example.org/api/send');
    expect(init.method).toBe('POST');
    // SSRF guard: the denylist ran against the configured host at save time,
    // so the relay must never follow a redirect off it.
    expect(init.redirect).toBe('manual');
    const headers = init.headers as Record<string, string>;
    expect(headers['content-type']).toBe('application/json');
    expect(headers['user-agent']).toBe('TestUA/1.0');
    expect(Object.keys(headers).sort()).toEqual(['content-type', 'user-agent']);
    expect(JSON.parse(init.body as string)).toEqual({
      type: 'event',
      payload: {
        website: UUID,
        hostname: 'freesocks.org',
        url: '/account',
        title: 'Account',
        referrer: 'https://ref.example',
        screen: '1920x1080',
        language: 'fa',
      },
    });
  });

  test('forwardIp: payload.ip appears only when a resolved IP is given (v2.17+ shape)', async () => {
    const spy = vi.fn().mockResolvedValue(new Response('ok'));
    vi.stubGlobal('fetch', spy);
    await sendUmamiEvent({
      cfg: CFG,
      input: { route: '/' },
      userAgent: 'UA',
      hostname: 'freesocks.org',
      clientIp: '203.0.113.7',
      geo: null,
    });
    const [, init] = spy.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string) as { payload: Record<string, string> };
    expect(body.payload.ip).toBe('203.0.113.7');
    // The IP rides in the payload, never in a header (CLIENT_IP_HEADER is
    // instance-global on Umami and unusable on a shared multi-site instance).
    const headers = init.headers as Record<string, string>;
    expect(Object.keys(headers).sort()).toEqual(['content-type', 'user-agent']);
    expect(headers['x-forwarded-for']).toBeUndefined();
    expect(headers['cookie']).toBeUndefined();
  });

  test('sanitizeIp: charset/length-checked; junk drops the field entirely', async () => {
    expect(sanitizeIp('203.0.113.7')).toBe('203.0.113.7');
    expect(sanitizeIp('2001:db8::1')).toBe('2001:db8::1');
    expect(sanitizeIp('evil\r\nheader')).toBe('');
    expect(sanitizeIp('not an ip')).toBe('');
    expect(sanitizeIp(null)).toBe('');
    const spy = vi.fn().mockResolvedValue(new Response('ok'));
    vi.stubGlobal('fetch', spy);
    await sendUmamiEvent({
      cfg: CFG,
      input: { route: '/' },
      userAgent: 'UA',
      hostname: null,
      clientIp: 'garbage value',
      geo: null,
    });
    const body = JSON.parse((spy.mock.calls[0] as [string, RequestInit])[1].body as string) as {
      payload: Record<string, string>;
    };
    expect(body.payload).not.toHaveProperty('ip');
  });

  test('a hostile body still produces only allowlisted values', async () => {
    const spy = vi.fn().mockResolvedValue(new Response('ok'));
    vi.stubGlobal('fetch', spy);
    await sendUmamiEvent({
      cfg: CFG,
      input: {
        route: '/steal?token=abc',
        referrer: '/r/FSR-CODE',
        screen: '1234x777',
        language: 'x'.repeat(50),
        extra: 'field',
        ip: '198.51.100.99', // a spoofed beacon-body ip must NEVER be forwarded
      },
      userAgent: 'UA\r\nX-Injected: 1',
      hostname: 'bad host',
      clientIp: null,
      geo: null,
    });
    const [, init] = spy.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string) as { payload: Record<string, string> };
    expect(body.payload.url).toBe('/other');
    expect(body.payload.title).toBe('Other');
    expect(body.payload.referrer).toBe('');
    expect(body.payload.screen).toBe('');
    expect(body.payload.language).toBe('');
    expect(body.payload.hostname).toBe('');
    expect(body.payload).not.toHaveProperty('extra');
    expect(body.payload).not.toHaveProperty('ip'); // clientIp arg is the ONLY source
    const headers = init.headers as Record<string, string>;
    expect(headers['user-agent']).not.toMatch(/[\r\n]/);
  });

  test('fail-soft: rejecting fetch, HTTP 500, and abort all resolve silently', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('boom')));
    await expect(
      sendUmamiEvent({
        cfg: CFG,
        input: { route: '/' },
        userAgent: 'UA',
        hostname: null,
        clientIp: null,
        geo: null,
      }),
    ).resolves.toBeUndefined();

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('err', { status: 500 })));
    await expect(
      sendUmamiEvent({
        cfg: CFG,
        input: { route: '/' },
        userAgent: 'UA',
        hostname: null,
        clientIp: null,
        geo: null,
      }),
    ).resolves.toBeUndefined();

    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(
        (_url: string, init: RequestInit) =>
          new Promise((_resolve, reject) => {
            init.signal?.addEventListener('abort', () => reject(new Error('aborted')));
          }),
      ),
    );
    await expect(
      sendUmamiEvent({
        cfg: CFG,
        input: { route: '/' },
        userAgent: 'UA',
        hostname: null,
        clientIp: null,
        geo: null,
      }),
    ).resolves.toBeUndefined();
  }, 10_000);

  test('unconfigured (blank url or id) sends nothing', async () => {
    const spy = vi.fn();
    vi.stubGlobal('fetch', spy);
    await sendUmamiEvent({
      cfg: { umamiUrl: '', websiteId: UUID },
      input: { route: '/' },
      userAgent: 'UA',
      hostname: null,
      clientIp: null,
      geo: null,
    });
    await sendUmamiEvent({
      cfg: { umamiUrl: 'https://a.example', websiteId: '' },
      input: { route: '/' },
      userAgent: 'UA',
      hostname: null,
      clientIp: null,
      geo: null,
    });
    expect(spy).not.toHaveBeenCalled();
  });

  test('null input (malformed beacon body) still sends a valid /other event', async () => {
    const spy = vi.fn().mockResolvedValue(new Response('ok'));
    vi.stubGlobal('fetch', spy);
    await sendUmamiEvent({
      cfg: CFG,
      input: null,
      userAgent: null,
      hostname: null,
      clientIp: null,
      geo: null,
    });
    const body = JSON.parse((spy.mock.calls[0] as [string, RequestInit])[1].body as string) as {
      payload: Record<string, string>;
    };
    expect(body.payload.url).toBe('/other');
  });
});

describe('coarse geo mode', () => {
  test('sanitizeCountryCode / sanitizeRegionCode', () => {
    expect(sanitizeCountryCode('us')).toBe('US');
    expect(sanitizeCountryCode(' IR ')).toBe('IR');
    expect(sanitizeCountryCode('XX')).toBe(''); // CF unknown sentinel
    expect(sanitizeCountryCode('T1')).toBe(''); // CF Tor sentinel
    expect(sanitizeCountryCode('USA')).toBe('');
    expect(sanitizeCountryCode('u\r\ns')).toBe('');
    expect(sanitizeCountryCode(null)).toBe('');
    expect(sanitizeRegionCode('mo')).toBe('MO');
    expect(sanitizeRegionCode('75')).toBe('75');
    expect(sanitizeRegionCode('evil header')).toBe('');
    expect(sanitizeRegionCode('a'.repeat(20))).toBe('');
    expect(sanitizeRegionCode(null)).toBe('');
  });

  test('sends country+region as geo headers, NEVER a city header, NEVER payload.ip', async () => {
    const spy = vi.fn().mockResolvedValue(new Response('ok'));
    vi.stubGlobal('fetch', spy);
    await sendUmamiEvent({
      cfg: CFG,
      input: { route: '/status' },
      userAgent: 'UA',
      hostname: 'freesocks.org',
      // Even if a caller passes an IP, coarse geo wins: payload.ip would make
      // Umami skip the geo headers entirely.
      clientIp: '203.0.113.7',
      geo: { country: 'ir', region: 'thr' },
    });
    const [, init] = spy.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers['cf-ipcountry']).toBe('IR');
    expect(headers['cf-region-code']).toBe('THR');
    expect(headers['cf-ipcity']).toBeUndefined();
    const body = JSON.parse(init.body as string) as { payload: Record<string, string> };
    expect(body.payload).not.toHaveProperty('ip');
  });

  test('junk/sentinel country drops BOTH geo headers (region never rides alone)', async () => {
    const spy = vi.fn().mockResolvedValue(new Response('ok'));
    vi.stubGlobal('fetch', spy);
    await sendUmamiEvent({
      cfg: CFG,
      input: { route: '/' },
      userAgent: 'UA',
      hostname: null,
      clientIp: null,
      geo: { country: 'XX', region: 'MO' },
    });
    const headers = (spy.mock.calls[0] as [string, RequestInit])[1].headers as Record<
      string,
      string
    >;
    expect(headers['cf-ipcountry']).toBeUndefined();
    expect(headers['cf-region-code']).toBeUndefined();
  });

  test('country without region sends the country header alone', async () => {
    const spy = vi.fn().mockResolvedValue(new Response('ok'));
    vi.stubGlobal('fetch', spy);
    await sendUmamiEvent({
      cfg: CFG,
      input: { route: '/' },
      userAgent: 'UA',
      hostname: null,
      clientIp: null,
      geo: { country: 'DE', region: null },
    });
    const headers = (spy.mock.calls[0] as [string, RequestInit])[1].headers as Record<
      string,
      string
    >;
    expect(headers['cf-ipcountry']).toBe('DE');
    expect(headers['cf-region-code']).toBeUndefined();
  });
});
