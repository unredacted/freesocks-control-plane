/**
 * `RemnawaveBackend` adapts `RemnawaveClient` to the generic
 * `ProxyBackendProvider` interface so higher-level services (subscription
 * delivery, propagation, account reads) don't need to know whether they're
 * talking to Remnawave or Outline.
 *
 * This is a thin translation layer — every method delegates to RemnawaveClient
 * after re-shaping the input/output to the common types in `providers/backend.ts`.
 * The native `RemnawaveClient` stays exported and usable for Remnawave-specific
 * paths that don't fit the abstraction (e.g. admin pages showing raw Remnawave
 * panel data).
 */
import type {
  BackendDevice,
  IssueUserSpec,
  IssuedUser,
  ProxyBackendProvider,
  SubscriptionContent,
  UpdateUserPatch,
  UserState,
} from '../backend';
import type { RemnawaveClient } from './client';
import type {
  CreateUserInput,
  RemnawaveUser,
  TrafficLimitStrategy,
  UpdateUserPatch as RemnaPatch,
} from './types';

export class RemnawaveBackend implements ProxyBackendProvider {
  readonly id = 'remnawave' as const;

  constructor(private readonly client: RemnawaveClient) {}

  async issueUser(spec: IssueUserSpec): Promise<IssuedUser> {
    const input: CreateUserInput = {
      username: spec.username,
      trafficLimitBytes: spec.trafficLimitBytes ?? undefined,
      trafficLimitStrategy: spec.trafficLimitStrategy ?? 'MONTH',
      expireAt: spec.expireAt ?? undefined,
      hwidDeviceLimit: spec.hwidDeviceLimit ?? undefined,
      tag: spec.tag,
      description: spec.description,
      activeInternalSquads: spec.remnawaveSquadUuid ? [spec.remnawaveSquadUuid] : undefined,
    };
    const user = await this.client.createUser(input);
    return {
      backendUserId: user.uuid,
      backendShortId: user.shortUuid,
      subscriptionUrl: user.subscriptionUrl,
      raw: user,
    };
  }

  async getUser(backendUserId: string): Promise<UserState> {
    const user = await this.client.getUser(backendUserId);
    const rawDevices = await this.client.listUserDevices(backendUserId);
    // Map the Remnawave HwidDevice shape (which has nullable firstSeen /
    // lastSeen fields) into the common BackendDevice shape (which uses
    // `undefined` for "unknown" rather than `null`).
    const devices: BackendDevice[] = rawDevices.map((d) => ({
      hwid: d.hwid,
      firstSeenAt: d.firstSeenAt ?? undefined,
      lastSeenAt: d.lastSeenAt ?? undefined,
    }));
    return remnawaveUserToState(user, devices);
  }

  async updateUser(backendUserId: string, patch: UpdateUserPatch): Promise<void> {
    const remnaPatch: RemnaPatch = {};
    if (patch.trafficLimitBytes !== undefined) {
      // Remnawave uses `null` for unlimited; our common type already matches.
      remnaPatch.trafficLimitBytes = patch.trafficLimitBytes;
    }
    if (patch.trafficLimitStrategy !== undefined) {
      remnaPatch.trafficLimitStrategy = patch.trafficLimitStrategy;
    }
    if (patch.expireAt !== undefined) {
      remnaPatch.expireAt = patch.expireAt;
    }
    if (patch.hwidDeviceLimit !== undefined) {
      remnaPatch.hwidDeviceLimit = patch.hwidDeviceLimit;
    }
    if (patch.description !== undefined) {
      remnaPatch.description = patch.description;
    }
    if (patch.tag !== undefined) {
      remnaPatch.tag = patch.tag;
    }
    if (patch.remnawaveSquadUuid !== undefined) {
      // Distinguish "absent" (skip — handled by the !== undefined guard) from
      // "present and null/empty" (clear the squad). An explicit null/'' sends
      // an empty squad set so an admin can actually unset a tier's squad.
      remnaPatch.activeInternalSquads = patch.remnawaveSquadUuid ? [patch.remnawaveSquadUuid] : [];
    }
    if (patch.status !== undefined) {
      remnaPatch.status = patch.status === 'active' ? 'ACTIVE' : 'DISABLED';
    }
    await this.client.updateUser(backendUserId, remnaPatch);
  }

  async resetUserTraffic(backendUserId: string): Promise<void> {
    await this.client.resetUserTraffic(backendUserId);
  }

  async deleteUser(backendUserId: string): Promise<void> {
    await this.client.deleteUser(backendUserId);
  }

  async fetchSubscriptionContent(
    backendShortId: string,
    ua?: string,
  ): Promise<SubscriptionContent> {
    return this.client.fetchSubscriptionContent(backendShortId, ua);
  }

  /** Escape hatch for code that legitimately needs the raw Remnawave client. */
  unsafeRawClient(): RemnawaveClient {
    return this.client;
  }
}

function remnawaveUserToState(user: RemnawaveUser, devices: BackendDevice[]): UserState {
  return {
    trafficLimitBytes: user.trafficLimitBytes,
    usedTrafficBytes: user.usedTrafficBytes,
    expireAt: user.expireAt,
    status:
      user.status === 'ACTIVE'
        ? 'active'
        : user.status === 'DISABLED'
          ? 'disabled'
          : user.status === 'LIMITED'
            ? 'limited'
            : user.status === 'EXPIRED'
              ? 'expired'
              : 'unknown',
    devices,
  };
}

// Re-export for callers that import the strategy enum via the adapter module.
export type { TrafficLimitStrategy };
