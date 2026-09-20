/**
 * The guided setup, judged for ONE origin (or a draft before the origin row
 * exists) from a plain facts object the query gathers (`convex/edgeOperator.ts`).
 * Pure: no db, no clock beyond what the input carries, so the step logic is
 * unit-tested directly and the wizard renders exactly what this returns.
 *
 * Step ids and blocker codes are the shared vocabularies in
 * src/shared/contracts/edgeCodes.ts; the CMS maps every code to words.
 */
import type {
  SetupBlockerCode,
  SetupStepId,
  SetupStepStatus,
} from '../../../src/shared/contracts/edgeCodes';
import type { EdgeLayer } from './providers/capabilities';

export interface SetupBlocker {
  code: SetupBlockerCode;
  subject: string | null;
  detail: string | null;
}

export interface SetupStep {
  id: SetupStepId;
  status: SetupStepStatus;
  blockers: SetupBlocker[];
  warnings: SetupBlocker[];
  facts: Record<string, unknown>;
}

export interface SetupOriginFacts {
  kind: 'panel-node' | 'backend-server' | 'manual';
  /** The referenced backend server row exists (manual: true). */
  backendPresent: boolean;
  /** Health freshness of the backend server (null = manual / unknown). */
  backendHealthy: boolean | null;
  backendHostManagement: boolean;
  backendNodeInventory: boolean;
}

export interface SetupListenerFacts {
  key: string;
  label: string;
  validCombo: boolean;
  deployed: boolean;
  enabled: boolean;
  retired: boolean;
  layers: EdgeLayer[];
  excluded: Record<string, string>;
  needsTarget: boolean;
  hasTarget: boolean;
  usesSni: boolean;
  /** Names still active (L4 needs one unless the listener is L7-only by transport). */
  activeNames: number;
  l7Only: boolean;
  templateEdgeId: string | null;
}

export interface SetupAccountFacts {
  id: string;
  name: string;
  provider: string;
  layer: EdgeLayer;
  enabled: boolean;
  tested: boolean;
  testFailed: boolean;
  qualified: boolean;
  /** Qualified AND the effective template hash still matches. */
  qualificationCurrent: boolean;
  /** Listener keys of THIS origin/draft the account can front (layer + protocol). */
  frontsListeners: string[];
  dnsAccountMissing: boolean;
  zoneModeUnknown: boolean;
  zoneWebsocketsOff: boolean;
  /** A default template exists for the provider (or the compiled defaults apply) and validates. */
  templateOk: boolean;
  templateInvalid: boolean;
  defaultTemplateId: string | null;
}

export interface SetupEdgeFacts {
  id: string;
  listenerKey: string;
  layer: EdgeLayer;
  provider: string | null;
  accountId: string | null;
  status: string;
  publication: 'unpublished' | 'published' | 'draining';
  poolIndex: number | null;
  /** L7 only: a current, passing end-to-end proof. */
  frontQualification: { ok: boolean; current: boolean; code: string | null } | null;
  /** `checkPublishable` verdict for an unpublished active edge (null when not evaluated). */
  publishable: { ok: true } | { ok: false; code: string } | null;
}

export interface SetupRelayFacts {
  id: string;
  slug: string;
  enabled: boolean;
  deleting: boolean;
  quarantined: boolean;
  hostMode: 'fcp' | 'operator' | 'none';
  autoRotate: boolean;
  publishedCount: number;
  rotation: {
    id: string;
    kind: string;
    phase: string;
    terminal: boolean;
    outcome: string | null;
  } | null;
  /** The newest terminal rotation's outcome, for `provision_failed` after a failed bootstrap. */
  lastRotation: { kind: string; phase: string; outcome: string | null } | null;
  edges: SetupEdgeFacts[];
  /** A delivery binding covers members on this origin (edge-required). */
  deliveryRequired: boolean;
  /** The binding is deferred to go-live (a guided origin): members still get the raw body. */
  bindingDeferred?: boolean;
  connectionPlanCount: number;
  mirrorsUnvalidated: number;
  qualificationCredential: boolean;
  /** Whether the origin's backend can mint the L7 qualification credential at all. */
  credentialSupported: boolean;
}

export interface SetupRenderFacts {
  enabled: boolean;
  /** The default family's preview (null = not computed, e.g. fleet scope). */
  preview: {
    family: string;
    applied: boolean;
    reason: string | null;
    emitted: number;
    mismatched: number;
  } | null;
}

export interface SetupConfigFacts {
  edgeEnabled: boolean;
  autoRotate: boolean;
  l7AutoSelect: boolean;
  probeEnabled: boolean;
  probeSourcesOn: number;
  probeCountries: number;
}

export interface SetupInput {
  origin: SetupOriginFacts | null;
  listeners: SetupListenerFacts[];
  accounts: SetupAccountFacts[];
  relay: SetupRelayFacts | null;
  render: SetupRenderFacts;
  config: SetupConfigFacts;
}

export interface SetupResult {
  steps: SetupStep[];
  currentStep: SetupStepId | null;
  complete: boolean;
  /** The best candidates the wizard should pre-select. */
  context: {
    accountId: string | null;
    templateId: string | null;
    listenerKey: string | null;
    edgeId: string | null;
  };
}

const blocker = (
  code: SetupBlockerCode,
  subject: string | null = null,
  detail: string | null = null,
): SetupBlocker => ({ code, subject, detail });

/** Accounts that can front at least one usable listener of this origin. */
function compatibleAccounts(input: SetupInput): SetupAccountFacts[] {
  const usable = new Set(
    input.listeners.filter((l) => !l.retired && l.validCombo).map((l) => l.key),
  );
  return input.accounts.filter((a) => a.enabled && a.frontsListeners.some((k) => usable.has(k)));
}

export function computeSetupStatus(input: SetupInput): SetupResult {
  const steps: SetupStep[] = [];
  const relay = input.relay;
  const isManual = input.origin?.kind === 'manual';

  // 1. origin
  {
    const b: SetupBlocker[] = [];
    const w: SetupBlocker[] = [];
    const o = input.origin;
    if (!o) b.push(blocker('no_origin'));
    else if (o.kind !== 'manual') {
      if (!o.backendPresent) b.push(blocker('no_backend_server'));
      else {
        if (o.backendHealthy === false) b.push(blocker('backend_unreachable'));
        if (o.kind === 'panel-node' && !o.backendHostManagement)
          w.push(blocker('backend_no_host_management'));
        if (o.kind === 'panel-node' && !o.backendNodeInventory)
          w.push(blocker('backend_no_node_inventory'));
      }
    }
    steps.push({
      id: 'origin',
      status: b.length === 0 ? 'done' : 'blocked',
      blockers: b,
      warnings: w,
      facts: { kind: o?.kind ?? null },
    });
  }

  // 2. provider account (tested; of a layer the listeners allow)
  const compatible = compatibleAccounts(input);
  const tested = compatible.filter((a) => a.tested);
  const chosenAccount =
    tested.find((a) => a.qualificationCurrent) ??
    tested.find((a) => a.qualified) ??
    tested[0] ??
    null;
  {
    const b: SetupBlocker[] = [];
    const w: SetupBlocker[] = [];
    const enabledAccounts = input.accounts.filter((a) => a.enabled);
    if (enabledAccounts.length === 0) b.push(blocker('no_provider_account'));
    else if (compatible.length === 0 && input.listeners.length > 0)
      b.push(blocker('no_compatible_account'));
    else if (tested.length === 0) {
      for (const a of compatible)
        b.push(blocker(a.testFailed ? 'credentials_failed' : 'credentials_untested', a.name));
    }
    for (const a of tested) {
      if (a.dnsAccountMissing) b.push(blocker('dns_account_missing', a.name));
      if (a.zoneModeUnknown) w.push(blocker('zone_mode_unknown', a.name));
      if (a.zoneWebsocketsOff) w.push(blocker('zone_websockets_off', a.name));
    }
    const dnsBlocked = tested.length > 0 && tested.every((a) => a.dnsAccountMissing);
    steps.push({
      id: 'account',
      status: b.length === 0 || (tested.length > 0 && !dnsBlocked) ? 'done' : 'blocked',
      blockers: b,
      warnings: w,
      facts: {
        accounts: enabledAccounts.length,
        compatible: compatible.length,
        tested: tested.length,
        chosen: chosenAccount?.name ?? null,
      },
    });
  }

  // 3. template
  {
    const b: SetupBlocker[] = [];
    const a = chosenAccount;
    if (a) {
      if (a.templateInvalid) b.push(blocker('template_invalid', a.name));
      else if (!a.templateOk) b.push(blocker('no_default_template', a.provider));
    }
    steps.push({
      id: 'template',
      status: !a ? 'blocked' : b.length === 0 ? 'done' : 'blocked',
      blockers: !a ? [blocker('no_provider_account')] : b,
      warnings: [],
      facts: { provider: a?.provider ?? null, templateId: a?.defaultTemplateId ?? null },
    });
  }

  // 4. origin + listener
  const usableListeners = input.listeners.filter(
    (l) => !l.retired && l.validCombo && l.deployed && l.enabled,
  );
  const chosenListener =
    usableListeners.find((l) => l.layers.length > 0 && !l.templateEdgeId) ??
    usableListeners.find((l) => l.layers.length > 0) ??
    null;
  {
    const b: SetupBlocker[] = [];
    const w: SetupBlocker[] = [];
    if (!relay) b.push(blocker('no_relay'));
    else if (relay.deleting) b.push(blocker('relay_deleting', relay.slug));
    else {
      const live = input.listeners.filter((l) => !l.retired);
      if (live.length === 0) b.push(blocker('relay_without_listener', relay.slug));
      for (const l of live) {
        if (!l.validCombo) b.push(blocker('invalid_combination', l.key));
        if (!l.deployed) b.push(blocker('listener_not_deployed', l.key));
        if (!l.enabled) b.push(blocker('listener_disabled', l.key));
        if (l.needsTarget && !l.hasTarget) b.push(blocker('needs_target', l.key));
        if (l.usesSni && !l.l7Only && l.activeNames === 0) b.push(blocker('needs_names', l.key));
        if (l.excluded.l4 === 'no_udp_provider' && l.layers.length === 0)
          b.push(blocker('no_udp_provider', l.key));
      }
      if (relay.deliveryRequired && relay.publishedCount === 0)
        w.push(blocker('members_dark', relay.slug));
    }
    steps.push({
      id: 'relay',
      status: b.length === 0 && usableListeners.length > 0 ? 'done' : 'blocked',
      blockers: b,
      warnings: w,
      facts: {
        slug: relay?.slug ?? null,
        listeners: input.listeners.filter((l) => !l.retired).map((l) => l.key),
        chosenListener: chosenListener?.key ?? null,
      },
    });
  }

  // 5. first edge
  const activeEdges = relay?.edges.filter((e) => e.status === 'active') ?? [];
  const chosenEdge =
    activeEdges.find((e) => e.publication === 'published') ??
    activeEdges.find((e) => e.publishable?.ok) ??
    activeEdges[0] ??
    null;
  {
    const b: SetupBlocker[] = [];
    if (!relay) b.push(blocker('no_relay'));
    else if (activeEdges.length === 0) {
      if (relay.rotation && !relay.rotation.terminal) b.push(blocker('rotation_running'));
      else {
        b.push(blocker('no_edge', relay.slug));
        if (
          relay.lastRotation &&
          relay.lastRotation.kind === 'provision' &&
          relay.lastRotation.phase === 'failed'
        )
          b.push(blocker('provision_failed', relay.slug, relay.lastRotation.outcome));
        if (compatible.length === 0) b.push(blocker('no_compatible_account'));
      }
    }
    steps.push({
      id: 'edge',
      status: b.length === 0 ? 'done' : 'blocked',
      blockers: b,
      warnings: [],
      facts: {
        edges: activeEdges.length,
        rotating: !!relay?.rotation && !relay.rotation.terminal,
        chosenEdge: chosenEdge?.id ?? null,
      },
    });
  }

  // 6. qualification (the edge's account qualified + current; L7: a current proof)
  {
    const b: SetupBlocker[] = [];
    const e = chosenEdge;
    const acct = e?.accountId ? (input.accounts.find((a) => a.id === e.accountId) ?? null) : null;
    if (!e) b.push(blocker('no_edge'));
    else {
      if (acct) {
        if (!acct.qualified) b.push(blocker('account_unqualified', acct.name));
        else if (!acct.qualificationCurrent) b.push(blocker('qualification_stale', acct.name));
      }
      if (e.layer === 'l7') {
        if (relay && !relay.credentialSupported) b.push(blocker('credential_unsupported'));
        else if (relay && !relay.qualificationCredential)
          b.push(blocker('qualification_credential_missing', relay.slug));
        else if (!e.frontQualification) b.push(blocker('front_unqualified', e.id));
        else if (!e.frontQualification.ok)
          b.push(blocker('front_failed', e.id, e.frontQualification.code));
        else if (!e.frontQualification.current) b.push(blocker('front_unqualified', e.id));
      }
    }
    steps.push({
      id: 'qualification',
      status: b.length === 0 ? 'done' : 'blocked',
      blockers: b,
      warnings: [],
      facts: {
        accountId: acct?.id ?? null,
        accountName: acct?.name ?? null,
        layer: e?.layer ?? null,
      },
    });
  }

  // 7. publish (index 0 filled with an eligible edge; manual origins: a connection plan exists)
  {
    const b: SetupBlocker[] = [];
    const w: SetupBlocker[] = [];
    if (!relay) b.push(blocker('no_relay'));
    else if (relay.quarantined) b.push(blocker('quarantined', relay.slug));
    else if (relay.publishedCount === 0) {
      b.push(blocker('pool_empty', relay.slug));
      const candidates = activeEdges.filter((e) => e.publication === 'unpublished');
      const publishable = candidates.filter((e) => e.publishable?.ok);
      if (candidates.length > 0 && publishable.length === 0) {
        for (const e of candidates)
          if (e.publishable && !e.publishable.ok)
            b.push(blocker('no_publishable_edge', e.id, e.publishable.code));
      }
      if (relay.hostMode === 'operator') w.push(blocker('hosts_operator_managed', relay.slug));
    } else if (isManual && relay.connectionPlanCount === 0)
      b.push(blocker('no_publishable_edge', relay.slug));
    // A guided origin serves the raw body until its binding is claimed at go-live:
    // published edges reach nobody yet (never `members_dark`, which needs a binding).
    if (relay?.bindingDeferred) w.push(blocker('binding_deferred', relay.slug));
    steps.push({
      id: 'publish',
      status: b.length === 0 ? 'done' : 'blocked',
      blockers: b,
      warnings: w,
      facts: { published: relay?.publishedCount ?? 0, hostMode: relay?.hostMode ?? null },
    });
  }

  // 8. rendering (skipped for manual origins: nothing FCP serves maps to them)
  {
    const b: SetupBlocker[] = [];
    let status: SetupStepStatus = 'blocked';
    if (isManual) status = 'skipped';
    else if (!relay) b.push(blocker('no_relay'));
    else {
      if (!input.render.enabled) b.push(blocker('render_disabled'));
      if (!relay.enabled) b.push(blocker('relay_disabled', relay.slug));
      const p = input.render.preview;
      if (p) {
        if (!p.applied || p.emitted === 0)
          b.push(blocker('preview_not_applied', p.family, p.reason));
        if (p.mismatched > 0) b.push(blocker('entry_mismatch', p.family));
      }
      if (relay.mirrorsUnvalidated > 0)
        b.push(blocker('mirrors_unvalidated', relay.slug, String(relay.mirrorsUnvalidated)));
      status = b.length === 0 && relay.publishedCount > 0 ? 'done' : 'blocked';
    }
    steps.push({
      id: 'rendering',
      status,
      blockers: b,
      warnings: [],
      facts: {
        renderEnabled: input.render.enabled,
        preview: input.render.preview,
      },
    });
  }

  // 9. automation (optional: never blocks completion)
  {
    const w: SetupBlocker[] = [];
    const c = input.config;
    if (!c.probeEnabled) w.push(blocker('probes_disabled'));
    else {
      if (c.probeSourcesOn === 0) w.push(blocker('probe_sources_none'));
      if (c.probeCountries === 0) w.push(blocker('probe_countries_none'));
    }
    if (!c.edgeEnabled) w.push(blocker('edge_layer_disabled'));
    if (!c.autoRotate || (relay && !relay.autoRotate)) w.push(blocker('auto_rotate_off'));
    const l7Listeners = input.listeners.filter((l) => !l.retired && l.layers.includes('l7'));
    if (l7Listeners.length > 0 && !c.l7AutoSelect) w.push(blocker('l7_auto_select_blocked'));
    steps.push({
      id: 'automation',
      status: w.length === 0 ? 'done' : 'ready',
      blockers: [],
      warnings: w,
      facts: {
        probeEnabled: c.probeEnabled,
        edgeEnabled: c.edgeEnabled,
        autoRotate: c.autoRotate && (relay?.autoRotate ?? false),
      },
    });
  }

  // The current step = the first not done/skipped; it is `ready` when every
  // step before it is done (or skipped), else it stays blocked.
  let current: SetupStepId | null = null;
  for (const s of steps) {
    if (s.status === 'done' || s.status === 'skipped') continue;
    current = s.id;
    if (s.id !== 'automation') s.status = 'ready';
    break;
  }
  // Steps after the current one show their own blockers but are never "ready".
  const complete = steps.every(
    (s) => s.status === 'done' || s.status === 'skipped' || s.id === 'automation',
  );
  return {
    steps,
    currentStep: complete ? null : current,
    complete,
    context: {
      accountId: chosenAccount?.id ?? null,
      templateId: chosenAccount?.defaultTemplateId ?? null,
      listenerKey: chosenListener?.key ?? null,
      edgeId: chosenEdge?.id ?? null,
    },
  };
}
