/**
 * FCP's own client check in words (docs/edges.md "FCP's own client check"): the
 * line under an address, and the toast after a check by hand. No em-dashes.
 */
import type {
  EdgeClientCheck,
  EdgeClientCheckOutcome,
} from '../../../../../shared/contracts/edges';
import { CLIENT_CHECK_COPY, CLIENT_CHECK_ENGINE_LABELS } from '../../../../lib/edgeCodes';

type Engines = EdgeClientCheck['engines'];

/** `sing-box: Refused by REALITY; Xray: Connected`, or null when every client connected. */
export function engineWords(engines: Engines): string | null {
  if (engines.every((e) => e.code === 'ok')) return null;
  return engines
    .map((e) => `${CLIENT_CHECK_ENGINE_LABELS[e.engine]}: ${CLIENT_CHECK_COPY[e.code].label}`)
    .join('; ');
}

/** The line under an address: what its newest check found, and whether it still applies. */
export function clientCheckLine(check: EdgeClientCheck | null): string | null {
  if (!check) return null;
  const engines = engineWords(check.engines);
  const stale = check.current === false ? ' The address changed since, check it again.' : '';
  return `FCP's client check: ${CLIENT_CHECK_COPY[check.verdict].label}${engines ? ` (${engines})` : ''}.${stale}`;
}

/** The toast after a check by hand: a verdict, or why none was reached. */
export function clientCheckToast(outcome: EdgeClientCheckOutcome): {
  tone: 'success' | 'warning' | 'error';
  title: string;
  body: string;
} {
  if (!outcome.checked) {
    const copy = CLIENT_CHECK_COPY[outcome.code];
    return { tone: 'error', title: `Not checked: ${copy.label}`, body: copy.explain };
  }
  const copy = CLIENT_CHECK_COPY[outcome.verdict];
  const engines = engineWords(outcome.engines);
  return {
    tone: outcome.ok ? (engines ? 'warning' : 'success') : 'error',
    title: copy.label,
    body: [copy.explain, engines ? `${engines}.` : '', copy.fix ?? ''].filter(Boolean).join(' '),
  };
}
