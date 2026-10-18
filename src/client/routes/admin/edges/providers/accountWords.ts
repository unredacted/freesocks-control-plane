/**
 * Provider-account state in words (pure; unit-tested).
 *
 * Exports:
 *   testWords(account, now?)        the credential-test state: label, tone, one detail line
 *   isTested(account)               the last test passed and nothing failed since
 *   settingLabel(key)               a settings key in words ('projectId' -> 'Project ID')
 *   settingRows(settings, names?)   KeyValue rows of the non-secret settings
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
export function settingLabel(key: string): string {
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
      return named
        ? { label: settingLabel(k), value: named, hint: text }
        : { label: settingLabel(k), value: text, mono: typeof v === 'string', copy: true };
    });
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
