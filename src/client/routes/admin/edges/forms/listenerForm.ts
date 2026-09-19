/**
 * The listener form's state and its projections (pure; unit-tested).
 *
 * The form edits strings; `toListenerSpec` builds the registration body and
 * `listenerFormIssues` mirrors the server's validation in words, so the
 * operator sees what is missing before a round trip. The server stays the
 * authority: anything it refuses still surfaces through the error copy.
 *
 * Exports:
 *   ListenerForm, emptyListenerForm(originKind), listenerFormFromAdmin(l)
 *   formCombo(form)                      the catalogue entry for the chosen combination
 *   listenerFormIssues(form, originKind) -> string[] (empty = valid)
 *   toListenerSpec(form)                 -> ListenerSpec body
 *   toDraftListener(form)                -> the triple (+ port, names) the setup draft carries
 */
import type { z } from 'zod';
import type { RelayListenerAdmin, SetupDraft } from '@shared/contracts/edges';
import {
  LISTENER_COMBOS,
  type ListenerCombo,
  type ListenerComboKey,
} from '@shared/contracts/edgeProtocolIds';
import type { ListenerSpecBody } from '@client/lib/edgesApi';
import { normalizeHostname } from '../lib/tags';
import type { OriginKind } from './origin';

export type MatchRuleChoice = 'auto' | 'address' | 'whole-body' | 'remark';

export interface ListenerForm {
  listenerKey: string;
  combo: ListenerComboKey;
  originPort: string;
  tlsNames: string[];
  targetAddress: string;
  targetPort: string;
  path: string;
  host: string;
  serviceName: string;
  /** XHTTP only: the mode the inbound serves. */
  xhttpMode: string;
  /** How a CDN front reaches this inbound; off = raw TCP to the inbound (L4 only). */
  frontable: boolean;
  scheme: 'http' | 'https';
  certPublic: boolean;
  certNames: string[];
  acceptsHostHeader: 'any' | 'names';
  bindPanel: boolean;
  inboundTag: string;
  configProfileUuid: string;
  configProfileInboundUuid: string;
  matchRule: MatchRuleChoice;
  remark: string;
  providerScope: string;
  deployed: boolean;
}

export type DraftListener = z.infer<typeof SetupDraft>['listeners'][number];

const DEFAULT_COMBO: ListenerComboKey = 'vless/raw/reality';

export function emptyListenerForm(originKind: OriginKind = 'panel-node'): ListenerForm {
  return {
    listenerKey: '',
    combo: originKind === 'backend-server' ? 'shadowsocks/raw/none' : DEFAULT_COMBO,
    originPort: originKind === 'backend-server' ? '' : '443',
    tlsNames: [],
    targetAddress: '',
    targetPort: '443',
    path: '',
    host: '',
    serviceName: '',
    xhttpMode: 'packet-up',
    frontable: false,
    scheme: 'https',
    certPublic: true,
    certNames: [],
    acceptsHostHeader: 'names',
    bindPanel: false,
    inboundTag: '',
    configProfileUuid: '',
    configProfileInboundUuid: '',
    matchRule: 'auto',
    remark: '',
    providerScope: '',
    deployed: true,
  };
}

export function listenerFormFromAdmin(l: RelayListenerAdmin): ListenerForm {
  return {
    listenerKey: l.listenerKey,
    combo: `${l.protocol}/${l.streamTransport}/${l.security}`,
    originPort: String(l.originPort),
    tlsNames: l.tlsNames.filter((n) => n.status === 'active').map((n) => n.name),
    targetAddress: l.realityTarget?.address ?? '',
    targetPort: l.realityTarget ? String(l.realityTarget.port) : '443',
    path: l.transportParams?.path ?? '',
    host: l.transportParams?.host ?? '',
    serviceName: l.transportParams?.serviceName ?? '',
    xhttpMode: l.transportParams?.mode ?? 'packet-up',
    frontable: l.originTransport !== null,
    scheme: l.originTransport?.scheme ?? 'https',
    certPublic: l.originTransport?.certPublic ?? true,
    certNames: l.originTransport?.certNames ?? [],
    acceptsHostHeader: l.originTransport?.acceptsHostHeader ?? 'names',
    bindPanel: l.panelBinding !== null,
    inboundTag: l.panelBinding?.inboundTag ?? '',
    configProfileUuid: l.panelBinding?.configProfileUuid ?? '',
    configProfileInboundUuid: l.panelBinding?.configProfileInboundUuid ?? '',
    matchRule: l.matchRule.kind,
    remark: l.matchRule.kind === 'remark' ? l.matchRule.remark : '',
    providerScope: l.providerScope?.provider ?? '',
    deployed: l.deployed,
  };
}

export function formCombo(form: Pick<ListenerForm, 'combo'>): ListenerCombo {
  return LISTENER_COMBOS.find((c) => c.key === form.combo) ?? LISTENER_COMBOS[0]!;
}

const KEY_RE = /^[a-z0-9]{1,16}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TAG_RE = /^[A-Z0-9_]+$/;

function portOf(raw: string): number | null {
  const n = Number(raw.trim());
  return raw.trim() !== '' && Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

/** A certificate name: a DNS name, optionally with one leading wildcard label. */
export function normalizeCertName(raw: string): string | null {
  const n = raw.trim().toLowerCase();
  if (n.startsWith('*.')) {
    const rest = normalizeHostname(n.slice(2));
    return rest ? `*.${rest}` : null;
  }
  return normalizeHostname(n);
}

export function listenerFormIssues(form: ListenerForm, originKind: OriginKind): string[] {
  const out: string[] = [];
  const combo = formCombo(form);
  if (!KEY_RE.test(form.listenerKey))
    out.push('The key is 1 to 16 lowercase letters or digits, for example "reality" or "ws1".');
  if (portOf(form.originPort) === null)
    out.push('The origin port is a number between 1 and 65535.');
  const l7Only = form.frontable && combo.isHttpTransport && form.scheme === 'http';
  if (combo.usesSni && form.tlsNames.length === 0 && !l7Only)
    out.push(`${combo.label} needs at least one server name.`);
  if (combo.needsTarget) {
    if (form.targetAddress.trim() === '') out.push('REALITY needs the target it impersonates.');
    if (portOf(form.targetPort) === null)
      out.push('The REALITY target port is a number between 1 and 65535.');
  }
  if (form.frontable && combo.isHttpTransport) {
    if (form.scheme === 'https' && form.certPublic && form.certNames.length === 0)
      out.push('A publicly trusted origin certificate must list the names it covers.');
  }
  const bind = form.bindPanel && originKind === 'panel-node';
  if (bind) {
    if (!TAG_RE.test(form.inboundTag))
      out.push('The inbound tag uses capital letters, digits and underscores only.');
    if (!UUID_RE.test(form.configProfileUuid)) out.push('The config profile id is a UUID.');
    if (!UUID_RE.test(form.configProfileInboundUuid)) out.push('The inbound id is a UUID.');
  }
  if (form.matchRule === 'remark') {
    if (!bind) out.push('Matching by remark needs the panel inbound to be bound.');
    if (form.remark.trim() === '') out.push('Enter the remark to match.');
  }
  return out;
}

export function toListenerSpec(form: ListenerForm, originKind: OriginKind): ListenerSpecBody {
  const combo = formCombo(form);
  const spec: ListenerSpecBody = {
    listenerKey: form.listenerKey.trim(),
    protocol: combo.protocol,
    streamTransport: combo.streamTransport,
    security: combo.security,
    originPort: portOf(form.originPort) ?? 0,
    deployed: form.deployed,
  };
  if (combo.usesSni && form.tlsNames.length > 0) spec.tlsNames = [...form.tlsNames];
  if (combo.needsTarget)
    spec.realityTarget = {
      address: form.targetAddress.trim(),
      port: portOf(form.targetPort) ?? 443,
    };
  if (combo.isHttpTransport) {
    const p: NonNullable<ListenerSpecBody['transportParams']> = {};
    if (combo.streamTransport === 'grpc') {
      if (form.serviceName.trim()) p.serviceName = form.serviceName.trim();
    } else {
      if (form.path.trim()) p.path = form.path.trim();
      if (form.host.trim()) p.host = form.host.trim();
      if (combo.streamTransport === 'xhttp') p.mode = form.xhttpMode;
    }
    if (Object.keys(p).length > 0) spec.transportParams = p;
    if (form.frontable)
      spec.originTransport = {
        scheme: form.scheme,
        certPublic: form.scheme === 'https' ? form.certPublic : false,
        certNames: form.scheme === 'https' ? [...form.certNames] : [],
        acceptsHostHeader: form.acceptsHostHeader,
      };
  }
  const bind = form.bindPanel && originKind === 'panel-node';
  if (bind)
    spec.panelBinding = {
      inboundTag: form.inboundTag.trim(),
      configProfileUuid: form.configProfileUuid.trim(),
      configProfileInboundUuid: form.configProfileInboundUuid.trim(),
    };
  if (form.matchRule === 'remark' && bind)
    spec.matchRule = { kind: 'remark', remark: form.remark.trim() };
  else if (form.matchRule === 'address' || form.matchRule === 'whole-body')
    spec.matchRule = { kind: form.matchRule };
  if (form.providerScope)
    spec.providerScope = {
      provider: form.providerScope as NonNullable<ListenerSpecBody['providerScope']>['provider'],
    };
  return spec;
}

export function toDraftListener(form: ListenerForm): DraftListener {
  const combo = formCombo(form);
  const port = portOf(form.originPort);
  const out: DraftListener = {
    protocol: combo.protocol,
    streamTransport: combo.streamTransport,
    security: combo.security,
  };
  if (port !== null) out.originPort = port;
  if (combo.usesSni && form.tlsNames.length > 0) out.tlsNames = [...form.tlsNames];
  if (combo.isHttpTransport && form.frontable)
    out.originTransport = {
      scheme: form.scheme,
      certPublic: form.scheme === 'https' ? form.certPublic : false,
      certNames: form.scheme === 'https' ? [...form.certNames] : [],
      acceptsHostHeader: form.acceptsHostHeader,
    };
  return out;
}
