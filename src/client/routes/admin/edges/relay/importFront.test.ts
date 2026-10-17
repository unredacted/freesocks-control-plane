import { describe, expect, test } from 'vitest';
import { importFrontIssues, type ImportFrontForm } from './importFront';

const form = (over: Partial<ImportFrontForm> = {}): ImportFrontForm => ({
  hasListener: true,
  source: 'address',
  accountId: '',
  resourceId: '',
  hostname: '',
  ipv4: '',
  port: '',
  ...over,
});

describe('importFrontIssues', () => {
  test('by address: exactly one of the hostname and the IPv4 address', () => {
    expect(importFrontIssues(form({ hostname: 'front.example' }))).toEqual([]);
    expect(importFrontIssues(form({ ipv4: '198.51.100.10' }))).toEqual([]);
    expect(importFrontIssues(form())).toEqual([
      'Give the hostname of a CDN front or the IPv4 address of a load balancer.',
    ]);
    expect(importFrontIssues(form({ hostname: 'front.example', ipv4: '198.51.100.10' }))).toEqual([
      'Give either the hostname or the IPv4 address, not both.',
    ]);
  });
  test('a hostname is a DNS name, an address a public IPv4 literal', () => {
    expect(importFrontIssues(form({ hostname: 'not a name' }))).toEqual([
      'This is not a valid DNS name.',
    ]);
    expect(importFrontIssues(form({ hostname: 'localhost' }))).toEqual([
      'This is not a valid DNS name.',
    ]);
    expect(importFrontIssues(form({ ipv4: 'front.example' }))).toEqual([
      'This is not a valid IPv4 address.',
    ]);
    expect(importFrontIssues(form({ ipv4: '10.0.0.1' }))[0]).toMatch(/private or reserved/);
  });
  test('from an account: the account and the resource; the resource fills both fields', () => {
    expect(importFrontIssues(form({ source: 'account' }))).toEqual([
      'Choose the account the resource lives in.',
    ]);
    expect(importFrontIssues(form({ source: 'account', accountId: 'a1' }))).toEqual([
      'Choose the resource.',
    ]);
    expect(
      importFrontIssues(
        form({
          source: 'account',
          accountId: 'a1',
          resourceId: 'r1',
          hostname: 'front.example',
          ipv4: '198.51.100.10',
        }),
      ),
    ).toEqual([]);
  });
  test('the listener and the port', () => {
    expect(importFrontIssues(form({ hasListener: false, hostname: 'front.example' }))).toEqual([
      'Choose the listener this front forwards to.',
    ]);
    expect(importFrontIssues(form({ hostname: 'front.example', port: '70000' }))).toEqual([
      'The port is a number between 1 and 65535.',
    ]);
    for (const msg of importFrontIssues(form({ hostname: 'x', ipv4: 'y', port: '0' })))
      expect(msg).not.toMatch(/—/);
  });
});
