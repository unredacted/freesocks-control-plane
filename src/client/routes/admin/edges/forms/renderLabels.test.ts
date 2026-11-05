/** The preview's reason line "as a member in <country>" (pure). */
import { describe, expect, it } from 'vitest';
import { endpointWhy, orderedLine } from './renderLabels';

describe('the preview reason line', () => {
  it('is the tier alone without meant for or latency ordering', () => {
    expect(
      orderedLine('Iran', {
        primaryTier: 0,
        backupTier: 1,
        primaryWhy: { meantFor: true },
        backupWhy: { meantFor: false },
      }),
    ).toBe(
      'Addresses ordered for a member in Iran: the primary works there, at a location meant for it, the backup not known there.',
    );
  });

  it('adds the band and the whole path while latency ordering is on', () => {
    expect(
      endpointWhy(1, { meantFor: false, latency: { band: 'near', ms: 128, measured: false } }),
    ).toBe('not known there, near (about 128 ms over the whole path)');
    expect(
      endpointWhy(0, { meantFor: true, latency: { band: 'far', ms: 310, measured: true } }),
    ).toBe(
      'works there, at a location meant for it, far (about 310 ms over the whole path, timed from there)',
    );
    expect(
      endpointWhy(1, { meantFor: false, latency: { band: 'near', ms: null, measured: false } }),
    ).toBe('not known there, near (no distance known)');
    expect(endpointWhy(null, null)).toBeNull();
    expect(endpointWhy(1, { meantFor: true, audience: ['IR', 'RU'] })).toBe(
      'not known there, at a location meant for it, only for IR, RU',
    );
  });

  it('carries no em-dash', () => {
    const line = orderedLine('Germany', {
      primaryTier: 1,
      backupTier: 1,
      primaryWhy: { meantFor: false, latency: { band: 'near', ms: 128, measured: false } },
      backupWhy: { meantFor: false, latency: { band: 'medium', ms: 190, measured: false } },
    });
    expect(line).not.toMatch(/—/);
    expect(line).toContain('the backup not known there, medium distance (about 190 ms');
  });
});
