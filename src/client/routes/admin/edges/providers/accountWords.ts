/**
 * Provider-account state in words (pure; unit-tested).
 *
 * Exports:
 *   testWords(account, now?)        the credential-test state: label, tone, one detail line
 *   isTested(account)               the last test passed and nothing failed since
 *   settingLabel(key)               a settings key in words ('projectId' -> 'Project ID')
 *   settingRows(settings, names?)   KeyValue rows of the non-secret settings
 *   observedRows(observed)          KeyValue rows of what the last test saw (CAA in words)
 *   sharedCertificateWords(c)       the shared wildcard certificate: badge, tone, one line
 *   inventoryOwner(lb)              'fcp' | 'foreign' for an inventory resource
 */
import { codeLabel, type Tone } from '../../../../lib/edgeCodes';
import { displayValue } from '../lib/format';
import { relativeTime } from '../lib/time';
import type { KeyValueRow } from '../lib/types';

interface TestedLike {
  lastTestOkAt: string | null;
  lastTestError: string | null;
}

export const isTested = (a: TestedLike): boolean =>
  a.lastTestOkAt !== null && a.lastTestError === null;

export function testWords(
  a: TestedLike,
  now: number = Date.now(),
): { label: string; tone: Tone; detail: string } {
  if (a.lastTestError !== null) {
    return {
      label: 'Test failed',
      tone: 'danger',
      detail: `${codeLabel(a.lastTestError.replace(/^edge\./, ''))}${
        a.lastTestOkAt ? `. Last passed ${relativeTime(a.lastTestOkAt, now)}` : ''
      }`,
    };
  }
  if (a.lastTestOkAt !== null) {
    return {
      label: 'Tested',
      tone: 'success',
      detail: `Passed ${relativeTime(a.lastTestOkAt, now)}`,
    };
  }
  return { label: 'Never tested', tone: 'muted', detail: 'Run Test credentials' };
}

const ACRONYMS: Record<string, string> = {
  id: 'ID',
  dns: 'DNS',
  tls: 'TLS',
  ssl: 'SSL',
  ip: 'IP',
  url: 'URL',
  api: 'API',
};
/** Keys whose generated words would read badly. */
const SETTING_LABELS: Record<string, string> = {
  certificateScope: 'Certificates',
  domainModel: 'Domains',
  caa: 'CAA records',
  caaIssuer: 'CA as CAA names it',
  caaCertificate: 'Checked for',
  caaAt: 'Decided at',
};

/** Enumerated values in words, per key. */
const SETTING_VALUE_WORDS: Record<string, Record<string, string>> = {
  certificateScope: { wildcard: 'One wildcard for every front', per_host: 'One per front' },
  domainModel: {
    versionless: 'Its own domain, linked to the service',
    classic: 'A domain on the service version (classic)',
  },
  caa: {
    allows: 'Allow the certificate authority',
    no_records: 'None, so any certificate authority may issue',
    forbids: 'Forbid the certificate authority',
    unchecked: 'Not checked: the lookup failed',
  },
  caaCertificate: { wildcard: 'The shared wildcard', per_host: 'One name per front' },
};

export function settingLabel(key: string): string {
  if (SETTING_LABELS[key]) return SETTING_LABELS[key]!;
  const words = key
    .replace(/[_-]+/g, ' ')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(' ')
    .filter(Boolean)
    .map((w) => ACRONYMS[w.toLowerCase()] ?? w.toLowerCase());
  if (words.length === 0) return key;
  const first = words[0]!;
  words[0] = ACRONYMS[first.toLowerCase()] ?? first[0]!.toUpperCase() + first.slice(1);
  return words.join(' ');
}

/**
 * `names` maps an id-valued setting to a display name (the DNS account). The id
 * itself stays visible as the hint so it can still be matched at the provider.
 */
export function settingRows(
  settings: Record<string, unknown>,
  names: Record<string, string> = {},
): KeyValueRow[] {
  return Object.entries(settings)
    .filter(([, v]) => v !== null && v !== undefined && v !== '')
    .map(([k, v]) => {
      const text = displayValue(v);
      const named = typeof v === 'string' ? names[v] : undefined;
      const worded = typeof v === 'string' ? SETTING_VALUE_WORDS[k]?.[v] : undefined;
      if (worded) return { label: settingLabel(k), value: worded };
      return named
        ? { label: settingLabel(k), value: named, hint: text }
        : { label: settingLabel(k), value: text, mono: typeof v === 'string', copy: true };
    });
}

/** What the last credential test observed, in words where the values are enumerated. */
export function observedRows(observed: Record<string, string>): KeyValueRow[] {
  return Object.entries(observed).map(([k, v]) => {
    const worded = SETTING_VALUE_WORDS[k]?.[v];
    const tone: Tone | undefined =
      k === 'caa'
        ? v === 'forbids'
          ? 'danger'
          : v === 'unchecked'
            ? 'warning'
            : undefined
        : undefined;
    return {
      label: settingLabel(k),
      value: worded ?? v,
      ...(tone ? { tone } : {}),
      ...(worded ? {} : { mono: true }),
    };
  });
}

interface SharedCertificateLike {
  name: string;
  state: string;
  code: string | null;
  notAfter: string | null;
  checkedAt: string;
  edges: number;
}

/**
 * The account's shared wildcard certificate: a short badge, its tone and one
 * line (what it waits on, when it renews, how many fronts use it).
 */
export function sharedCertificateWords(
  c: SharedCertificateLike,
  now: number = Date.now(),
): { label: string; tone: Tone; detail: string } {
  const users =
    c.edges === 0
      ? 'No live front uses it yet.'
      : `${c.edges} live front${c.edges === 1 ? '' : 's'} use${c.edges === 1 ? 's' : ''} it.`;
  const checked = `Checked ${relativeTime(c.checkedAt, now)}.`;
  const waitsOn = c.code ? ` ${codeLabel(c.code)}.` : '';
  const expiry = c.notAfter ? new Date(c.notAfter).toISOString().slice(0, 10) : null;
  // A renewal that is late (it expires within a week, or has) outranks the state.
  if (c.code === 'certificate_expiring' && c.state !== 'failed')
    return {
      label: 'Renewal late',
      tone: 'danger',
      detail: `${expiry ? `Valid until ${expiry}, and not renewed yet. ` : 'Not renewed yet. '}${users} ${checked}`,
    };
  switch (c.state) {
    case 'issued':
      return {
        label: 'Issued',
        tone: 'success',
        detail: `${expiry ? `Valid until ${expiry}, renewed by the provider. ` : ''}${users} ${checked}`,
      };
    case 'renewing':
      return c.code
        ? {
            label: 'Renewal waiting',
            tone: 'warning',
            detail: `Still valid${expiry ? ` until ${expiry}` : ''}, its renewal waits on: ${codeLabel(c.code)}. ${users} ${checked}`,
          }
        : {
            label: 'Renewing',
            tone: 'info',
            detail: `Still valid while it renews. ${users} ${checked}`,
          };
    case 'failed':
      return {
        label: 'Failed',
        tone: 'danger',
        detail: `The provider gave up issuing it.${waitsOn} New fronts cannot get a certificate. ${checked}`,
      };
    case 'absent':
      return {
        label: 'Not ordered yet',
        tone: 'muted',
        detail: `The first new front orders it. ${checked}`,
      };
    case 'ambiguous':
      return {
        label: 'Not reusable',
        tone: 'warning',
        detail: `The wildcard is covered by a certificate this account would not order (another authority, or several). ${checked}`,
      };
    default:
      return {
        label: 'Waiting to issue',
        tone: c.code ? 'warning' : 'info',
        detail: `${c.code ? `Waiting on: ${codeLabel(c.code)}.` : 'Issuance usually takes a few minutes.'} ${users} ${checked}`,
      };
  }
}

export const inventoryOwner = (r: { unowned?: boolean | undefined }): 'fcp' | 'foreign' =>
  r.unowned === true ? 'foreign' : 'fcp';

interface LocationTrustLike {
  qualified: boolean;
  autoQualifyHold: boolean;
  qualification: { by: 'admin' | 'auto'; at: string; edgeId: string | null } | null;
}

/** A location's trust in words: the badge and one line on how it was taken. */
export function locationTrustWords(
  l: LocationTrustLike,
  now: number = Date.now(),
): { label: string; tone: Tone; detail: string } {
  if (l.qualified && l.qualification) {
    const when = relativeTime(l.qualification.at, now);
    return {
      label: 'Trusted',
      tone: 'success',
      detail:
        l.qualification.by === 'auto'
          ? `Trusted automatically, checked with a real session ${when}.`
          : l.qualification.edgeId
            ? `Tried with a real session by you ${when}.`
            : `Trusted by your override ${when}.`,
    };
  }
  if (l.qualified) return { label: 'Trusted', tone: 'success', detail: 'Trusted.' };
  if (l.autoQualifyHold)
    return {
      label: 'Not trusted',
      tone: 'warning',
      detail: 'Trust removed by hand: only an override trusts it again.',
    };
  return {
    label: 'Not trusted yet',
    tone: 'muted',
    detail: 'Its first tested address trusts it.',
  };
}
