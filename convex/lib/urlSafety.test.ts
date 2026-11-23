// @vitest-environment node
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { parse } from 'yaml';
import { COMPOSE_SERVICE_NAMES, checkInfraUrl } from './urlSafety';

const composeServices = (rel: string): string[] => {
  const doc = parse(readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8')) as {
    services: Record<string, unknown>;
  };
  return Object.keys(doc.services);
};

afterEach(() => vi.unstubAllEnvs());

describe('checkInfraUrl', () => {
  test('refuses every compose service name of the stack', () => {
    for (const name of COMPOSE_SERVICE_NAMES) {
      expect(checkInfraUrl(`http://${name}:3210/api`).ok, name).toBe(false);
      expect(checkInfraUrl(`https://${name.toUpperCase()}./`).ok, name).toBe(false);
    }
  });

  test('refuses Docker host aliases', () => {
    expect(checkInfraUrl('http://host.docker.internal:3000').ok).toBe(false);
    expect(checkInfraUrl('http://gateway.docker.internal').ok).toBe(false);
  });

  test('keeps allowing other single-label names, private addresses and FQDNs', () => {
    expect(checkInfraUrl('http://panel-mci1:3000').ok).toBe(true);
    expect(checkInfraUrl('http://10.0.0.5:3000').ok).toBe(true);
    expect(checkInfraUrl('https://panel.example.org').ok).toBe(true);
    // A name that only CONTAINS a service name is not a compose peer.
    expect(checkInfraUrl('https://backend.example.org').ok).toBe(true);
  });

  test('ALLOW_INTERNAL_BACKENDS lifts the compose-name deny too (dev)', () => {
    vi.stubEnv('ALLOW_INTERNAL_BACKENDS', 'true');
    expect(checkInfraUrl('http://backend:3210').ok).toBe(true);
  });

  test('the deny list covers every service in both compose files', () => {
    const services = new Set([
      ...composeServices('../../docker-compose.stack.yml'),
      ...composeServices('../../docker-compose.yml'),
    ]);
    const missing = [...services].filter((s) => !COMPOSE_SERVICE_NAMES.has(s));
    expect(missing).toEqual([]);
  });
});
