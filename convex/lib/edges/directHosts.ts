// STUB: merged with agent H (convex/lib/edges/directHosts.ts). The pure
// classifier per the PR A2 contract. This stub applies the contract's stated
// rule literally so the plan action typechecks and the setup tests can exercise
// consent by uuid; agent H's version replaces it at merge.
import type { BackendHost } from '../backends/types';
import { sameAddress } from './hosts';

export interface DirectHost {
  uuid: string;
  remark: string;
  inboundUuid: string;
  address: string;
  port: number;
  sni: string | null;
  host: string | null;
  isDisabled: boolean;
}

export interface DirectHostContext {
  originAddress: string;
  nodeInboundUuids: string[];
  fcpRemarks: string[];
  legacyHostUuids: string[];
  coveredInboundUuids: string[];
}

export function classifyDirectHosts(
  hosts: BackendHost[],
  ctx: DirectHostContext,
): { covered: DirectHost[]; uncovered: DirectHost[] } {
  const covered: DirectHost[] = [];
  const uncovered: DirectHost[] = [];
  for (const h of hosts) {
    if (h.isDisabled) continue;
    const inboundUuid = h.inbound?.configProfileInboundUuid ?? '';
    if (!inboundUuid || !ctx.nodeInboundUuids.includes(inboundUuid)) continue;
    if (!sameAddress(h.address, ctx.originAddress)) continue;
    if (ctx.fcpRemarks.includes(h.remark)) continue;
    if (ctx.legacyHostUuids.includes(h.uuid)) continue;
    const row: DirectHost = {
      uuid: h.uuid,
      remark: h.remark,
      inboundUuid,
      address: h.address,
      port: h.port,
      sni: h.sni ?? null,
      host: h.host ?? null,
      isDisabled: h.isDisabled,
    };
    (ctx.coveredInboundUuids.includes(inboundUuid) ? covered : uncovered).push(row);
  }
  return { covered, uncovered };
}
