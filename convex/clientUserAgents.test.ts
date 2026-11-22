import { describe, expect, test } from 'vitest';
import { appUserAgents, evidenceUrl } from '../tests/compat/userAgents';
import { clients } from '../tests/compat/manifest';
import { DEFAULT_CLIENTS } from './lib/clientCatalog';
import {
  ENCRYPTION_FLOORS,
  classifyClient,
  encryptionFloorOf,
  encryptionVersionOf,
  type SubscriptionFormat,
} from './lib/edges/clientFamilies';
import {
  normalizeSubscriptionUserAgent,
  remnawaveDefaultResponse,
  type RemnawaveResponseType,
} from './lib/backends/remnawaveUserAgent';

/** The body format of each panel response (CLASH is the legacy template: FCP answers the notice). */
const PANEL_FORMAT: Record<RemnawaveResponseType, SubscriptionFormat> = {
  MIHOMO: 'clash-yaml',
  STASH: 'clash-yaml',
  CLASH: 'clash-yaml',
  SINGBOX: 'singbox-json',
  XRAY_BASE64: 'links',
};

const rows = appUserAgents.flatMap((a) =>
  a.userAgents.map((ua) => [a.app, ua, a.family, a.format] as const),
);

describe('every app is recognised by the User-Agent it really sends', () => {
  test.each(rows)('%s: %s → %s / %s', (_app, ua, family, format) => {
    expect(classifyClient(ua)).toMatchObject({ family, expectedFormat: format });
  });

  test.each(rows)(
    '%s: the panel answers %s with a %s body of the family format',
    (_app, ua, _family, format) => {
      const response = remnawaveDefaultResponse(normalizeSubscriptionUserAgent(ua));
      // The legacy Clash template has no VLESS: a current app must never get it.
      expect(response).not.toBe('CLASH');
      expect(PANEL_FORMAT[response]).toBe(format);
    },
  );

  test('an app lands in `other` only with a stated reason, and every entry has evidence', () => {
    for (const a of appUserAgents) {
      expect(a.userAgents.length, a.app).toBeGreaterThan(0);
      expect(a.evidence.length, a.app).toBeGreaterThan(0);
      expect(a.notes.length, a.app).toBeGreaterThan(10);
      if (a.family === 'other') expect(a.other?.length ?? 0, a.app).toBeGreaterThan(20);
      else expect(a.other, a.app).toBeUndefined();
      for (const e of a.evidence) {
        if (e.kind === 'source') {
          expect(e.sha, a.app).toMatch(/^[0-9a-f]{40}$/);
          expect(e.line, a.app).toBeGreaterThan(0);
          expect(e.needle.trim().length, a.app).toBeGreaterThan(5);
        }
        if (e.kind === 'unconfirmed') expect(e.why.length, a.app).toBeGreaterThan(20);
        const url = evidenceUrl(e);
        if (url !== undefined) expect(url, a.app).toMatch(/^https:\/\//);
      }
    }
    expect(new Set(appUserAgents.map((a) => a.app)).size).toBe(appUserAgents.length);
  });
});

/**
 * Catalog apps whose User-Agent no source or developer states, each matched
 * by a name every reading of it agrees on (tests/compat/userAgents.ts says
 * why). A new one is added here only with that evidence written down.
 */
const UNCONFIRMED_CATALOG_APPS = new Set(['Karing', 'Shadowrocket']);

describe('the client catalog', () => {
  const enabled = DEFAULT_CLIENTS.filter((c) => c.enabled);

  test('every enabled app has its real User-Agent pinned, read from its source or its docs', () => {
    for (const c of enabled) {
      const entry = appUserAgents.find((a) => a.catalog === c.name);
      expect(entry, `${c.name} has no entry in tests/compat/userAgents.ts`).toBeDefined();
      const confirmed = entry!.evidence.some((e) => e.kind === 'source' || e.kind === 'docs');
      expect(
        confirmed || entry!.family === 'other' || UNCONFIRMED_CATALOG_APPS.has(c.name),
        `${c.name}: no confirmed User-Agent`,
      ).toBe(true);
    }
    // A catalog link is never stale.
    for (const a of appUserAgents)
      if (a.catalog)
        expect(
          DEFAULT_CLIENTS.some((c) => c.name === a.catalog),
          a.app,
        ).toBe(true);
  });

  test("the compat manifest's User-Agents include a real one of each app", () => {
    // The real-panel suite (tests/compat/clients.integration.test.ts) fetches
    // through FCP with the manifest's strings: at least one must be what the
    // app sends (every form is pinned offline above).
    for (const client of clients) {
      const entry = appUserAgents.find((a) => a.catalog === client.name);
      if (!entry || entry.family === 'other') continue;
      expect(
        client.userAgents.some((ua) => entry.userAgents.includes(ua)),
        `${client.name}: none of ${client.userAgents.join(', ')} is a real User-Agent`,
      ).toBe(true);
    }
  });
});

describe('every VLESS Encryption floor reads the User-Agent its app really sends', () => {
  test.each(ENCRYPTION_FLOORS.map((f) => [f.app, f] as const))('%s', (_name, f) => {
    const app = appUserAgents.find((a) => a.app === f.app || a.app.startsWith(`${f.app} `));
    expect(app, `${f.app} is not in tests/compat/userAgents.ts`).toBeDefined();
    // The row decides for the app's own User-Agents (a User-Agent it sends in
    // another app's name, like Prizrak-Box's `clash-verge/v2.3.0`, is that app's)...
    const own = app!.userAgents.filter((ua) => encryptionFloorOf(ua) === f);
    expect(own.length, `no User-Agent of ${f.app} reaches its row`).toBeGreaterThan(0);
    // ...and, where the app sends a version, reads it from every one of them.
    if (f.version)
      for (const ua of own)
        expect(encryptionVersionOf(f, ua), `no version read from ${ua}`).toBeDefined();
  });
});
