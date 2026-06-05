import { describe, expect, it } from 'vitest';
import { RemnawaveBackend } from '../../../src/server/providers/remnawave/backend';
import type { RemnawaveClient } from '../../../src/server/providers/remnawave/client';
import type {
  CreateUserInput,
  UpdateUserPatch,
} from '../../../src/server/providers/remnawave/types';

const userFixture = {
  uuid: '11111111-1111-4111-8111-111111111111',
  shortUuid: 'short-abc',
  subscriptionUuid: 'sub-uuid-1',
  username: 'u',
  status: 'ACTIVE' as const,
  trafficLimitBytes: 50_000_000_000,
  trafficLimitStrategy: 'MONTH' as const,
  usedTrafficBytes: 123,
  expireAt: '2026-12-31T00:00:00.000Z',
  hwidDeviceLimit: 1,
  subscriptionUrl: 'https://rw.example.com/short-abc',
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:00.000Z',
};

interface Calls {
  createUser: CreateUserInput[];
  updateUser: { uuid: string; patch: UpdateUserPatch }[];
  getUser: string[];
  listUserDevices: string[];
  deleteUser: string[];
  resetUserTraffic: string[];
}

function makeBackend(
  devices: { hwid: string; firstSeenAt?: string | null; lastSeenAt?: string | null }[] = [],
) {
  const calls: Calls = {
    createUser: [],
    updateUser: [],
    getUser: [],
    listUserDevices: [],
    deleteUser: [],
    resetUserTraffic: [],
  };
  const client = {
    createUser: async (input: CreateUserInput) => {
      calls.createUser.push(input);
      return userFixture;
    },
    getUser: async (uuid: string) => {
      calls.getUser.push(uuid);
      return userFixture;
    },
    updateUser: async (uuid: string, patch: UpdateUserPatch) => {
      calls.updateUser.push({ uuid, patch });
      return userFixture;
    },
    deleteUser: async (uuid: string) => {
      calls.deleteUser.push(uuid);
    },
    resetUserTraffic: async (uuid: string) => {
      calls.resetUserTraffic.push(uuid);
    },
    listUserDevices: async (uuid: string) => {
      calls.listUserDevices.push(uuid);
      return devices;
    },
  } as unknown as RemnawaveClient;
  return { backend: new RemnawaveBackend(client), calls };
}

const SQUAD_A = '22222222-2222-4222-8222-222222222222';
const SQUAD_B = '33333333-3333-4333-8333-333333333333';

describe('RemnawaveBackend', () => {
  it('issueUser maps the generic spec to CreateUserInput and returns the IssuedUser', async () => {
    const { backend, calls } = makeBackend();
    const out = await backend.issueUser({
      username: 'u1',
      trafficLimitBytes: 1000,
      trafficLimitStrategy: 'MONTH',
      expireAt: '2026-12-31T00:00:00.000Z',
      hwidDeviceLimit: 2,
      tag: 'free',
      description: 'd',
      remnawaveSquadUuid: SQUAD_A,
    });
    expect(calls.createUser[0]).toMatchObject({
      username: 'u1',
      trafficLimitBytes: 1000,
      activeInternalSquads: [SQUAD_A],
    });
    expect(out.backendUserId).toBe(userFixture.uuid);
    expect(out.backendShortId).toBe(userFixture.shortUuid);
    expect(out.subscriptionUrl).toBe(userFixture.subscriptionUrl);
  });

  it('issueUser omits activeInternalSquads when no squad is given', async () => {
    const { backend, calls } = makeBackend();
    await backend.issueUser({
      username: 'u2',
      trafficLimitBytes: null,
      trafficLimitStrategy: 'MONTH',
      expireAt: null,
      hwidDeviceLimit: null,
      tag: 'free',
      description: 'd',
      remnawaveSquadUuid: null,
    });
    expect(calls.createUser[0]!.activeInternalSquads).toBeUndefined();
  });

  it('updateUser clears the squad when remnawaveSquadUuid is explicitly null (Bug 14)', async () => {
    const { backend, calls } = makeBackend();
    await backend.updateUser('uuid-x', { remnawaveSquadUuid: null });
    expect(calls.updateUser[0]!.patch.activeInternalSquads).toEqual([]);
  });

  it('updateUser sets the squad when remnawaveSquadUuid is provided', async () => {
    const { backend, calls } = makeBackend();
    await backend.updateUser('uuid-x', { remnawaveSquadUuid: SQUAD_B });
    expect(calls.updateUser[0]!.patch.activeInternalSquads).toEqual([SQUAD_B]);
  });

  it('updateUser leaves activeInternalSquads untouched when the squad field is absent', async () => {
    const { backend, calls } = makeBackend();
    await backend.updateUser('uuid-x', { trafficLimitBytes: 5 });
    expect(calls.updateUser[0]!.patch).not.toHaveProperty('activeInternalSquads');
    expect(calls.updateUser[0]!.patch.trafficLimitBytes).toBe(5);
  });

  it('updateUser maps the common status to Remnawave ACTIVE/DISABLED', async () => {
    const { backend, calls } = makeBackend();
    await backend.updateUser('uuid-x', { status: 'disabled' });
    await backend.updateUser('uuid-x', { status: 'active' });
    expect(calls.updateUser[0]!.patch.status).toBe('DISABLED');
    expect(calls.updateUser[1]!.patch.status).toBe('ACTIVE');
  });

  it('getUser maps the Remnawave user + devices to the common UserState (null seen-at -> undefined)', async () => {
    const { backend } = makeBackend([
      { hwid: 'h1', firstSeenAt: null, lastSeenAt: '2026-01-02T00:00:00.000Z' },
    ]);
    const state = await backend.getUser('uuid-x');
    expect(state.status).toBe('active');
    expect(state.trafficLimitBytes).toBe(userFixture.trafficLimitBytes);
    expect(state.usedTrafficBytes).toBe(userFixture.usedTrafficBytes);
    expect(state.devices).toEqual([
      { hwid: 'h1', firstSeenAt: undefined, lastSeenAt: '2026-01-02T00:00:00.000Z' },
    ]);
  });

  it('delegates resetUserTraffic and deleteUser to the client', async () => {
    const { backend, calls } = makeBackend();
    await backend.resetUserTraffic('uuid-x');
    await backend.deleteUser('uuid-y');
    expect(calls.resetUserTraffic[0]).toBe('uuid-x');
    expect(calls.deleteUser[0]).toBe('uuid-y');
  });
});
