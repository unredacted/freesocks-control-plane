import { describe, expect, test } from 'vitest';
import { IMPORT_APPS } from './appLinks';

const URL_ = 'https://beta.freesocks.org/api/v1/sub/abc123';
const NAME = 'FreeSocks';
const ENC = 'https%3A%2F%2Fbeta.freesocks.org%2Fapi%2Fv1%2Fsub%2Fabc123';

function app(id: string) {
  const a = IMPORT_APPS.find((x) => x.id === id);
  if (!a) throw new Error(`no app ${id}`);
  return a;
}

describe('appLinks import deep-links', () => {
  test('Hiddify: raw URL in the path + name fragment (not percent-encoded)', () => {
    expect(app('hiddify').build(URL_, NAME)).toBe(`hiddify://import/${URL_}#FreeSocks`);
  });

  test('sing-box: percent-encoded url + name fragment', () => {
    expect(app('sing-box').build(URL_, NAME)).toBe(
      `sing-box://import-remote-profile?url=${ENC}#FreeSocks`,
    );
  });

  test('Karing: percent-encoded url + name query param', () => {
    expect(app('karing').build(URL_, NAME)).toBe(
      `karing://install-config?url=${ENC}&name=FreeSocks`,
    );
  });

  test('v2rayNG: install-sub host, percent-encoded url + name fragment', () => {
    expect(app('v2rayng').build(URL_, NAME)).toBe(`v2rayng://install-sub?url=${ENC}#FreeSocks`);
  });

  test('Clash: install-config, percent-encoded url + name query param', () => {
    expect(app('clash').build(URL_, NAME)).toBe(`clash://install-config?url=${ENC}&name=FreeSocks`);
  });

  test('Shadowrocket: sub:// + standard base64 of "url#name" (round-trips)', () => {
    const out = app('shadowrocket').build(URL_, NAME);
    expect(out.startsWith('sub://')).toBe(true);
    const decoded = atob(out.slice('sub://'.length));
    expect(decoded).toBe(`${URL_}#${NAME}`);
  });

  test('every app builds a non-empty scheme URL (no https)', () => {
    for (const a of IMPORT_APPS) {
      const link = a.build(URL_, NAME);
      expect(link).toMatch(/^[a-z0-9-]+:\/\//);
      expect(link.startsWith('https://')).toBe(false);
    }
  });
});
