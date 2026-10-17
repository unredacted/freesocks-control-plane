/**
 * What keeps an "Import an existing front" from being sent, in words (pure;
 * unit-tested). From an account: the account and the resource. By address: a
 * front is ONE of the two (the server reads a hostname as an L7 front and an
 * IPv4 address as an L4 load balancer), so exactly one is given; a hostname
 * must be a DNS name and an address a public IPv4 literal.
 */
import { addressIssue } from '../forms/origin';
import { normalizeHostname } from '../lib/tags';

export interface ImportFrontForm {
  hasListener: boolean;
  source: 'account' | 'address';
  accountId: string;
  resourceId: string;
  hostname: string;
  ipv4: string;
  port: string;
}

export function importFrontIssues(f: ImportFrontForm): string[] {
  const out: string[] = [];
  if (!f.hasListener) out.push('Choose the listener this front forwards to.');
  const host = f.hostname.trim();
  const ip = f.ipv4.trim();
  if (f.source === 'account') {
    if (!f.accountId) out.push('Choose the account the resource lives in.');
    else if (!f.resourceId) out.push('Choose the resource.');
  } else if (host === '' && ip === '') {
    out.push('Give the hostname of a CDN front or the IPv4 address of a load balancer.');
  } else if (host !== '' && ip !== '') {
    out.push('Give either the hostname or the IPv4 address, not both.');
  }
  if (host !== '' && !normalizeHostname(host)) out.push('This is not a valid DNS name.');
  if (ip !== '') {
    const problem = /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)
      ? addressIssue(ip)
      : 'This is not a valid IPv4 address.';
    if (problem) out.push(problem);
  }
  if (f.port.trim() !== '') {
    const n = Number(f.port);
    if (!Number.isInteger(n) || n < 1 || n > 65535)
      out.push('The port is a number between 1 and 65535.');
  }
  return out;
}
