import { describe, expect, test } from 'vitest';
import { buildImportLink, SCHEME_IDS } from './appLinks';

const URL_ = 'https://beta.freesocks.org/api/v1/sub/abc123';
const NAME = 'FreeSocks';
const ENC = 'https%3A%2F%2Fbeta.freesocks.org%2Fapi%2Fv1%2Fsub%2Fabc123';

describe('appLinks import deep-links (buildImportLink)', () => {
  test('Hiddify: raw URL in the path + name fragment', () => {
    expect(buildImportLink('hiddify', URL_, NAME)).toBe(`hiddify://import/${URL_}#FreeSocks`);
  });

  test('sing-box: percent-encoded url + name fragment', () => {
    expect(buildImportLink('sing-box', URL_, NAME)).toBe(
      `sing-box://import-remote-profile?url=${ENC}#FreeSocks`,
    );
  });

  test('Karing: percent-encoded url + name query param', () => {
    expect(buildImportLink('karing', URL_, NAME)).toBe(
      `karing://install-config?url=${ENC}&name=FreeSocks`,
    );
  });

  test('v2rayNG: install-sub host, percent-encoded url + name fragment', () => {
    expect(buildImportLink('v2rayng', URL_, NAME)).toBe(
      `v2rayng://install-sub?url=${ENC}#FreeSocks`,
    );
  });

  test('Clash: install-config, percent-encoded url + name query param', () => {
    expect(buildImportLink('clash', URL_, NAME)).toBe(
      `clash://install-config?url=${ENC}&name=FreeSocks`,
    );
  });

  test('Shadowrocket: sub:// + standard base64 of "url#name" (round-trips)', () => {
    const out = buildImportLink('shadowrocket', URL_, NAME)!;
    expect(out.startsWith('sub://')).toBe(true);
    expect(atob(out.slice('sub://'.length))).toBe(`${URL_}#${NAME}`);
  });

  test('null / unknown scheme → no deep link (manual / QR only)', () => {
    expect(buildImportLink(null, URL_, NAME)).toBeNull();
    expect(buildImportLink(undefined, URL_, NAME)).toBeNull();
    expect(buildImportLink('nope', URL_, NAME)).toBeNull();
  });

  test('every SCHEME_ID builds a non-https scheme URL', () => {
    for (const id of SCHEME_IDS) {
      const link = buildImportLink(id, URL_, NAME)!;
      expect(link).toMatch(/^[a-z0-9-]+:\/\//);
      expect(link.startsWith('https://')).toBe(false);
    }
  });
});
