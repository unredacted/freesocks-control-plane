/**
 * Pure helpers for the probe reachability matrix (unit-tested).
 *
 * Exports:
 *   INTERNAL_COUNTRY                     the pseudo country of FCP's own connect check
 *   KIND_LABELS / KIND_ORDER             target kinds in words, in display order
 *   groupTargets(targets, filter?)       -> [{ kind, label, targets }] (empty groups dropped)
 *   targetDetail(target)                 the server's detail line in words
 *   verdictLabel(v) / verdictTone(v)     a verdict in words + badge tone
 *   matrixCell(target, country)          one cell: words, tone and a tooltip line
 *   countryTally(results)                a run's vantage results folded per country
 *   familyLabel(ipVersion)               'IPv4' | 'IPv6' | 'by name'
 *   PROBE_SKIP_COPY / parseSkipped(s)    a `skipped` entry ("<key>: <code>") in words
 *   skipNotes(skipped)                   key -> words, for the rows of the matrix
 */
import type { ProbeMatrixTarget, ProbeRunAdmin } from '../../../../../shared/contracts/edges';
import { codeLabel, publicationLabel, type Tone } from '../../../../lib/edgeCodes';
import { providerLabel } from '../lib/format';

export const INTERNAL_COUNTRY = 'XX';

export type ProbeKind = ProbeMatrixTarget['kind'];
export type Verdict = ProbeMatrixTarget['reachability']['byCountry'][number]['verdict'];

export const KIND_ORDER: readonly ProbeKind[] = ['edge', 'relay', 'custom'];
export const KIND_LABELS: Record<ProbeKind, string> = {
  edge: 'Edges',
  relay: 'Relay nodes',
  custom: 'Custom targets',
};
export const KIND_SINGULAR: Record<ProbeKind, string> = {
  edge: 'Edge',
  relay: 'Relay node',
  custom: 'Custom',
};

export interface TargetGroup {
  kind: ProbeKind;
  label: string;
  targets: ProbeMatrixTarget[];
}

export function groupTargets(
  targets: readonly ProbeMatrixTarget[],
  filter?: (targetKey: string) => boolean,
): TargetGroup[] {
  const kept = filter ? targets.filter((t) => filter(t.key)) : [...targets];
  return KIND_ORDER.map((kind) => ({
    kind,
    label: KIND_LABELS[kind],
    targets: kept.filter((t) => t.kind === kind),
  })).filter((g) => g.targets.length > 0);
}

/**
 * The matrix `detail` is "<publication> · <provider|adopted>" for an edge,
 * "scheduled" / "manual only" for a relay node and "host:port" for a custom target.
 */
export function targetDetail(t: Pick<ProbeMatrixTarget, 'kind' | 'detail'>): string {
  if (t.kind === 'relay') return t.detail === 'scheduled' ? 'Probed every round' : 'Relay node';
  if (t.kind !== 'edge') return t.detail;
  const [publication, provider] = t.detail.split(' · ');
  const words = [publication ? publicationLabel(publication) : ''];
  if (provider) words.push(provider === 'adopted' ? 'Imported' : providerLabel(provider));
  return words.filter(Boolean).join(', ');
}

const VERDICT_LABELS: Record<Verdict, string> = {
  reachable: 'Reachable',
  unreachable: 'Unreachable',
  mixed: 'Mixed',
  unknown: 'Unknown',
};
export const verdictLabel = (v: string): string => VERDICT_LABELS[v as Verdict] ?? 'Unknown';
export function verdictTone(v: string): Tone {
  if (v === 'reachable') return 'success';
  if (v === 'unreachable') return 'danger';
  if (v === 'mixed') return 'warning';
  return 'muted';
}

export interface MatrixCell {
  probed: boolean;
  label: string;
  tone: Tone;
  /** Extra paths in words ("IPv6 unreachable", "by name reachable"). */
  extras: string[];
  /** "2 ok, 1 failing vantages" (empty when never probed). */
  vantages: string;
  lastAt: string | null;
}

export function matrixCell(target: ProbeMatrixTarget, country: string): MatrixCell {
  const c = target.reachability.byCountry.find((x) => x.country === country);
  if (!c) {
    return {
      probed: false,
      label: 'Not probed',
      tone: 'muted',
      extras: [],
      vantages: '',
      lastAt: null,
    };
  }
  const extras: string[] = [];
  if (c.v6Verdict) extras.push(`IPv6 ${verdictLabel(c.v6Verdict).toLowerCase()}`);
  if (c.nameVerdict) extras.push(`by name ${verdictLabel(c.nameVerdict).toLowerCase()}`);
  return {
    probed: true,
    label: verdictLabel(c.verdict),
    tone: verdictTone(c.verdict),
    extras,
    vantages: `${c.okVantages} ok, ${c.failVantages} failing vantage${
      c.okVantages + c.failVantages === 1 ? '' : 's'
    }`,
    lastAt: c.lastAt,
  };
}

export const countryLabel = (country: string): string =>
  country === INTERNAL_COUNTRY ? 'FCP' : country;

export interface CountryTally {
  country: string;
  ok: number;
  fail: number;
}
export function countryTally(results: ProbeRunAdmin['results']): CountryTally[] {
  const by = new Map<string, CountryTally>();
  for (const r of results) {
    const cur = by.get(r.country) ?? { country: r.country, ok: 0, fail: 0 };
    if (r.ok) cur.ok++;
    else cur.fail++;
    by.set(r.country, cur);
  }
  return [...by.values()];
}

/** A run that dialled a hostname has no observed family: the vantage resolved the name. */
export const familyLabel = (ipVersion: 4 | 6 | null): string =>
  ipVersion === null ? 'by name' : `IPv${ipVersion}`;

export const PROBE_SOURCE_LABELS: Record<string, string> = {
  globalping: 'Globalping',
  checkhost: 'check-host.net',
  ripeatlas: 'RIPE Atlas',
  internal: 'FCP (internal)',
};
export const PROBE_CHECK_LABELS: Record<string, string> = {
  tcp: 'TCP connect',
  tls: 'TLS handshake',
  https: 'HTTP GET',
};
export const PROBE_RUN_STATUS_LABELS: Record<string, string> = {
  requested: 'Requested',
  running: 'Running',
  finished: 'Finished',
  failed: 'Failed',
  timeout: 'Timed out',
};
export const PROBE_TRIGGER_LABELS: Record<string, string> = {
  cron: 'Schedule',
  manual: 'Operator',
  detector: 'Block detector',
  qualification: 'Qualification',
};

/** Why a requested target was not probed, in words. */
export const PROBE_SKIP_COPY: Record<string, string> = {
  'probe.udp_unsupported': 'not probed (UDP)',
  'probe.budget_exhausted': 'not probed (the hourly probe budget is used up)',
  'probe.no_listeners': 'not probed (no listener port yet)',
  'edge.no_address': 'not probed (no address yet)',
  not_found: 'not probed (the target no longer exists)',
};

export function parseSkipped(entry: string): { key: string; code: string; words: string } {
  const at = entry.lastIndexOf(': ');
  const key = at === -1 ? entry : entry.slice(0, at);
  const code = at === -1 ? '' : entry.slice(at + 2).trim();
  const words =
    PROBE_SKIP_COPY[code] ??
    (code
      ? `not probed (${codeLabel(code.replace(/^(edge|probe)\./, '')).toLowerCase()})`
      : 'not probed');
  return { key, code, words };
}

export function skipNotes(skipped: readonly string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const s of skipped) {
    const p = parseSkipped(s);
    out[p.key] = p.words;
  }
  return out;
}

/** One toast line for a probe request's answer. */
export function probeRequestSummary(res: { runIds: string[]; skipped: string[] }): string {
  const runs = `${res.runIds.length} probe run${res.runIds.length === 1 ? '' : 's'} requested`;
  if (res.skipped.length === 0) return runs;
  const reasons = [...new Set(res.skipped.map((s) => parseSkipped(s).words))];
  return `${runs}. ${res.skipped.length} target${res.skipped.length === 1 ? '' : 's'} ${reasons.join('; ')}`;
}
