import { describe, expect, it, vi } from 'vitest';
import { parseMirrors } from '../../../src/server/lib/mirrors';
import { Logger } from '../../../src/server/lib/logger';

/**
 * `parseMirrors` is the load-bearing guard that prevents a single malformed
 * `subscription_mirrors` row from crashing every read path that touches the
 * affected user. These tests pin the must-never-throw contract.
 */

function silentLogger() {
  return new Logger('error');
}

describe('parseMirrors', () => {
  it('returns [] for null', () => {
    expect(parseMirrors(null, silentLogger())).toEqual([]);
  });

  it('returns [] for empty string', () => {
    expect(parseMirrors('', silentLogger())).toEqual([]);
  });

  it('parses a valid single-entry list', () => {
    const raw = JSON.stringify([{ provider: 'r2', publicUrl: 'https://r2.example.com/x' }]);
    expect(parseMirrors(raw, silentLogger())).toEqual([
      { provider: 'r2', publicUrl: 'https://r2.example.com/x' },
    ]);
  });

  it('preserves objectPath when present', () => {
    const raw = JSON.stringify([
      { provider: 'r2', publicUrl: 'https://r2.example.com/x', objectPath: 'sub/abc.txt' },
    ]);
    const result = parseMirrors(raw, silentLogger());
    expect(result[0]?.objectPath).toBe('sub/abc.txt');
  });

  it('preserves status when present', () => {
    const raw = JSON.stringify([
      { provider: 'r2', publicUrl: 'https://r2.example.com/x', status: 'failed' },
    ]);
    const result = parseMirrors(raw, silentLogger());
    expect(result[0]?.status).toBe('failed');
  });

  it('returns [] on malformed JSON (does not throw)', () => {
    const logger = silentLogger();
    const warn = vi.spyOn(logger, 'warn');
    expect(parseMirrors('{not json', logger)).toEqual([]);
    expect(warn).toHaveBeenCalledWith(
      'subscription_mirrors_parse_failed',
      expect.objectContaining({ error: expect.any(String) }),
    );
  });

  it('returns [] on schema-invalid JSON (does not throw)', () => {
    const logger = silentLogger();
    const warn = vi.spyOn(logger, 'warn');
    // Missing required `publicUrl` field.
    expect(parseMirrors(JSON.stringify([{ provider: 'r2' }]), logger)).toEqual([]);
    expect(warn).toHaveBeenCalledWith(
      'subscription_mirrors_schema_invalid',
      expect.objectContaining({ issues: expect.any(Array) }),
    );
  });

  it('returns [] when publicUrl is not a URL', () => {
    expect(
      parseMirrors(JSON.stringify([{ provider: 'r2', publicUrl: 'not-a-url' }]), silentLogger()),
    ).toEqual([]);
  });

  it('returns [] when top-level shape is not an array', () => {
    expect(parseMirrors(JSON.stringify({}), silentLogger())).toEqual([]);
    expect(parseMirrors(JSON.stringify('string'), silentLogger())).toEqual([]);
    expect(parseMirrors(JSON.stringify(42), silentLogger())).toEqual([]);
    expect(parseMirrors(JSON.stringify(null), silentLogger())).toEqual([]);
  });

  it('logs ctx values for traceability', () => {
    const logger = silentLogger();
    const warn = vi.spyOn(logger, 'warn');
    parseMirrors('garbage', logger, { subscriptionId: 42, userId: 7 });
    expect(warn).toHaveBeenCalledWith(
      'subscription_mirrors_parse_failed',
      expect.objectContaining({ subscriptionId: 42, userId: 7 }),
    );
  });
});
