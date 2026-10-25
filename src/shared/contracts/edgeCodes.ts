/**
 * The code vocabularies the edges admin surface speaks (docs/edges.md
 * § "Operations"). Pure tuples, no zod: the server types its refusals,
 * blockers and attention items against these, and the CMS keeps one
 * `{ label, explain, fix? }` entry per code (src/client/lib/edgeCodes.ts, pinned
 * by a test so a new server code never renders as a bare identifier).
 */

/** The guided setup, in order. Every step is judged for ONE relay (or a draft). */
export const SETUP_STEP_IDS = [
  'origin',
  'account',
  'template',
  'relay',
  'edge',
  'qualification',
  'publish',
  'rendering',
  'automation',
] as const;
export type SetupStepId = (typeof SETUP_STEP_IDS)[number];

/**
 * done = satisfied; ready = the next thing to do, nothing blocks it;
 * blocked = something earlier or external must change first;
 * skipped = not applicable to this relay (manual origins skip rendering).
 */
export const SETUP_STEP_STATUSES = ['done', 'ready', 'blocked', 'skipped'] as const;
export type SetupStepStatus = (typeof SETUP_STEP_STATUSES)[number];

/** Blockers and warnings a setup step can carry (`subject` names the thing: a slug, an account, a listener key). */
export const SETUP_BLOCKER_CODES = [
  // origin
  'no_origin',
  'no_backend_server',
  'backend_unreachable',
  'backend_no_host_management',
  'backend_no_node_inventory',
  // account
  'no_provider_account',
  'no_compatible_account',
  'credentials_untested',
  'credentials_failed',
  'dns_account_missing',
  'zone_mode_unknown',
  'zone_websockets_off',
  // template
  'no_default_template',
  'template_invalid',
  // relay + listener
  'no_relay',
  'relay_deleting',
  'relay_without_listener',
  'listener_not_deployed',
  'listener_disabled',
  'needs_target',
  'needs_names',
  'no_udp_provider',
  'invalid_combination',
  'members_dark',
  // a warning: a REALITY listener refuses sing-box or Mihomo clients (subject = listener key)
  'reality_refuses_clients',
  // publish (a guided relay whose binding is claimed at go-live)
  'binding_deferred',
  // first edge
  'no_edge',
  'rotation_running',
  'account_budget_exhausted',
  'account_capacity_reached',
  'provision_failed',
  // qualification
  'account_unqualified',
  'qualification_stale',
  'qualification_credential_missing',
  'credential_unsupported',
  'front_unqualified',
  'front_failed',
  // publish
  'pool_empty',
  'quarantined',
  'hosts_operator_managed',
  'no_publishable_edge',
  // rendering
  'render_disabled',
  'relay_disabled',
  'preview_not_applied',
  'entry_mismatch',
  'mirrors_unvalidated',
  // automation
  'probes_disabled',
  'probe_sources_none',
  'probe_countries_none',
  'edge_layer_disabled',
  'auto_rotate_off',
  'l7_auto_select_blocked',
] as const;
export type SetupBlockerCode = (typeof SETUP_BLOCKER_CODES)[number];

/** Operations a preflight can dry-run (the operation it predicts shares the validator). */
export const PREFLIGHT_KINDS = ['provision', 'publish', 'replace', 'test-provision'] as const;
export type PreflightKind = (typeof PREFLIGHT_KINDS)[number];

/**
 * Refusals `startRotation` throws (as `edge.<code>`), `checkPublishable`
 * verdicts, selection failures, and the plan-phase refusals that need no
 * adapter. Preflight returns them all; a start throws the first.
 */
export const PREFLIGHT_BLOCKER_CODES = [
  // start guards
  'maintenance',
  'not_found',
  'quarantined',
  'deleting',
  'busy',
  'auto_rotate_disabled',
  'concurrency',
  'target_not_published',
  'hosts_operator_managed',
  'cooldown',
  'daily_cap',
  'listener_not_found',
  'panel_op_running',
  'listener_unusable',
  'l7_auto_select_disabled',
  'l7_replacement_cap',
  'validation',
  // publishability (checkPublishable)
  'edge_not_active',
  'already_published',
  'no_address',
  'listener_retired',
  'listener_not_deployed',
  'listener_disabled',
  'listener_no_active_name',
  'provider_mismatch',
  'transport_not_carried',
  'protocol_not_carried',
  'layer_mismatch',
  'origin_tls_mismatch',
  'front_unqualified',
  'front_stale',
  'front_failed',
  'account_mismatch',
  'unverified_endpoint',
  'edge_unhealthy',
  // replace: no tested spare on the listener (L4)
  'no_verified_spare',
  // selection
  'no_compatible_listener',
  'no_compatible_layer',
  'no_account_for_layer',
  'no_account_for_provider',
  'no_qualified_account',
  'accounts_exhausted',
  'account_not_found',
  'account_disabled',
  'account_untested',
  'account_incompatible',
  // a DNS account named while it is set to DNS only
  'dns_account_not_fronting',
  'account_budget_exhausted',
  'account_capacity_reached',
  'template_not_found',
  'template_invalid',
  // plan phase (no adapter call)
  'dns_account_missing',
  'dns_account_disabled',
  'dns_zone_missing',
  'origin_transport_missing',
  'zone_mode_unknown',
  // an L7 front's certificate cannot be had (L7_CERTIFICATE_CODES)
  'caa_forbids_ca',
  'shared_certificate_failed',
  'shared_certificate_ambiguous',
  // the fleet guards on an automatic rotation (lib/edges/fleet.ts)
  'fleet_brake',
  'fleet_daily_cap',
  // selection on an enrolled node: nothing fits the shape it was approved for
  'outside_approved_shape',
  // a load balancer for a WebSocket node's transport (lib/edges/websocketNode.ts)
  'l4_not_for_websocket',
  // a load balancer for an origin it cannot forward to: a private address, or a name
  // (lib/edges/ip.ts l4OriginProblem)
  'origin_not_public',
  'origin_not_ip',
  // a Scaleway location with no Project id whose API key's default project is unknown
  'project_unresolved',
  // a load balancer size that takes only the provider's own servers (lib/edges/sizeCheck.ts)
  'size_not_multicloud',
  // the account would pass its monthly spend cap (convex/edgePlans.ts, the budget guard)
  'account_spend_cap_reached',
] as const;
export type PreflightBlockerCode = (typeof PREFLIGHT_BLOCKER_CODES)[number];

/**
 * Why an L7 front's certificate cannot be had, or what its issuance waits on
 * (docs/edges.md § "L7 edges"): the CAA preflight's refusal (the credential
 * test and planning), the codes a waiting issuance reports, mapped from the
 * provider's own authorization warnings, whose text is never kept, and an
 * account's shared certificate that failed to issue.
 */
export const L7_CERTIFICATE_CODES = [
  'caa_forbids_ca',
  'tls_caa_conflict',
  'tls_challenge_conflict',
  'tls_challenge_missing',
  'tls_authorization_failed',
  'tls_authorization_warning',
  'tls_failed',
  'shared_certificate_failed',
  // a shared certificate whose renewal is late: it expires within a week, or has
  'certificate_expiring',
  // the zone's wildcard is covered by a certificate the account would not order
  'shared_certificate_ambiguous',
  // a Cloudflare zone's edge certificate (`*.<zone>`) is still being issued, or none is on its way
  'edge_certificate_pending',
  'edge_certificate_missing',
] as const;
export type L7CertificateCode = (typeof L7_CERTIFICATE_CODES)[number];

export function isL7CertificateCode(code: unknown): code is L7CertificateCode {
  return (L7_CERTIFICATE_CODES as readonly unknown[]).includes(code);
}

/** Things that will not stop the operation but the operator should know. */
export const PREFLIGHT_WARNING_CODES = [
  'render_disabled',
  'edge_disabled',
  'probe_disabled',
  'mark_pepper_missing',
  'members_dark',
  'account_unqualified',
  'unpublished_result',
  'l7_manual_only',
] as const;
export type PreflightWarningCode = (typeof PREFLIGHT_WARNING_CODES)[number];

/**
 * Attention items. The server ranks them by its own list (`edgeOperator`
 * ATTENTION_RANK, pinned by a test to hold exactly these kinds); new kinds are
 * appended here.
 */
export const ATTENTION_KINDS = [
  'quarantine',
  'needs_operator',
  'host_unresolved',
  'members_dark',
  'direct_host_reappeared',
  'go_live_pending',
  'needs_test',
  'rotation_failed',
  'qualification_lapsed',
  'retest_needed',
  'block_suspected',
  'edge_unreachable',
  'pool_rebalance',
  'spare_untested',
  'pool_below_desired',
  'account_unqualified',
  'account_untested',
  'test_key_cleanup',
  'restore_in_progress',
  'maintenance_frozen',
  // Operations safety (docs/edges.md § "Operations safety").
  'fleet_brake',
  'fleet_rotation_cap',
  'rotation_stuck',
  'account_api_failing',
  'health_stale',
  'billable_idle',
  'delivery_refusals',
  'family_rule_disabled',
  'node_ready_to_protect',
  'node_awaiting_approval',
  'account_budget_unlimited',
  // A live node whose connection mode is turned off: no member can pick it.
  'node_mode_disabled',
  // Provider sets: a pick cooling after a burn; transports with no backup in another failure domain.
  'pick_cooling',
  'reduced_resilience',
  // Test block evidence is running on a test deployment (it can replace an edge for real).
  'block_simulated',
  // A probe source keeps giving no evidence (every country it alone covers reads "not known").
  'probe_source_failing',
  // Checks from each country: the country-wide guard holds new blocks there (an
  // outage or a probe problem, not a censor); a new address is blocked somewhere
  // before it was ever in use.
  'country_wide_failure',
  'new_edge_blocked_in',
  // An L7 front's certificate waits on something FCP cannot fix (a CAA record,
  // the validation record), or an account's shared certificate failed.
  'certificate_waiting',
  // The node's newest guided setup run failed and nothing replaced it (its sheet has Try again).
  'setup_run_failed',
  // Freedom modes only through edges: a node in a freedom mode's pool that is not behind a
  // live edge of its layer, so its freedom members are not handed it (`FREEDOM_WITHHELD_REASONS`).
  'freedom_node_withheld',
  // An account at its monthly spend cap: no new edge is created in it (docs/edges.md § "Plans and prices").
  'account_spend_cap',
  // A Host on a protected transport dials a front the operator built by hand (not the node,
  // not an edge): members no longer get it, so it can be deleted at its provider.
  'front_host_unused',
  // A protected REALITY transport refuses sing-box or Mihomo clients (no `minClientVer` on an
  // Xray that then refuses them, or bounds that leave them out; src/shared/contracts/realityClients.ts).
  'reality_refuses_clients',
] as const;
export type AttentionKind = (typeof ATTENTION_KINDS)[number];

export const ATTENTION_SEVERITIES = ['critical', 'warning', 'info'] as const;
export type AttentionSeverity = (typeof ATTENTION_SEVERITIES)[number];

/** The one action an attention item offers (the CMS maps each to a route or a call). */
export const ATTENTION_ACTIONS = [
  'resolve_quarantine',
  'resolve_operator',
  'look_at_host',
  'open_setup',
  'open_relay',
  'open_edge',
  'open_account',
  'open_settings',
  'publish',
  'provision',
  'qualify_front',
  'rotate',
  'test_credentials',
  'verify_endpoint',
  'thaw',
  'rebalance',
  'require_edges',
  // An enrolled node: start protecting it (the protect sheet), or open its page under Servers.
  'protect_node',
  'open_node',
  // The admin Connection modes page (turn a mode on).
  'open_modes',
  // The Probes page (its sources and the checks from each country).
  'open_probes',
  // A guided setup run's sheet (its progress, and Try again when it failed).
  'open_run',
] as const;
export type AttentionAction = (typeof ATTENTION_ACTIONS)[number];

/**
 * Why a node in a freedom mode's pool is withheld from that mode's members while freedom
 * modes are only served through edges (lib/edges/freedomDelivery.ts): FCP does not enroll it
 * and no edge covers it; it is enrolled and no edge covers it; an origin covers it but has no
 * live edge of the mode's layer; its mode is set up `direct` on its backend.
 */
export const FREEDOM_WITHHELD_REASONS = [
  'withheld_unmanaged',
  'withheld_unprotected',
  'withheld_no_edge',
  'withheld_direct_mode',
] as const;
export type FreedomWithheldReason = (typeof FREEDOM_WITHHELD_REASONS)[number];

/** Why a listener cannot be fronted by a layer (lib/edges/layers.ts). */
export const LAYER_EXCLUSION_CODES = [
  'protocol_not_http_transport',
  'l7_proof_unsupported',
  'host_header_rejected',
  'origin_plaintext',
  'no_server_names',
  'cert_not_public',
  'cert_name_uncovered',
  'no_udp_provider',
  'l4_not_for_websocket',
] as const;
export type LayerExclusionCode = (typeof LAYER_EXCLUSION_CODES)[number];

/** Why edge-required delivery answered 503 (edgeRender.ts / render.ts). */
export const DELIVERY_UNAVAILABLE_CODES = [
  'relay_missing',
  'relay_disabled',
  'render_disabled',
  'no_render_key',
  'empty_pool',
  'unsupported_format',
  'no_match',
  'ambiguous_match',
  'entry_mismatch',
  'leak_detected',
  // the node is not live; the policy moved during the render; the client's app family is off
  'node_gated',
  'policy_moved',
  'family_disabled',
  // the format's renderer could not rewrite the body for another reason
  'render_failed',
  // a freedom-family key at a node no live edge covers, while freedom modes are only served
  // through edges (`edge.freedom.edgesOnly`)
  'node_unprotected',
] as const;
export type DeliveryUnavailableCode = (typeof DELIVERY_UNAVAILABLE_CODES)[number];

/**
 * Published-pool refusals and notices (`edge.<code>` on the wire): reserved
 * allocation (`pool_reserved`), a full pool, a rebalance with nothing to
 * unpublish, a pool raised at registration (`pool_raised`, a warning), the
 * coverage cap (`listener_cap`: a ninth deployed, enabled listener;
 * `pool_below_coverage`: `desiredPublished` lowered under the coverage-listener
 * count), and the detector veto for a setup-owned relay.
 */
export const POOL_CODES = [
  'pool_full',
  'pool_reserved',
  'pool_raised',
  'listener_cap',
  'pool_below_coverage',
  'no_duplicate',
  'setup_owned',
  'not_live',
] as const;
export type PoolCode = (typeof POOL_CODES)[number];

/**
 * The restore workflow (`relays.restore`, convex/edgeRestore.ts): why it runs
 * and where it is. `cancel_setup` = a guided setup cancelled after publication
 * (relay retained, unbound); `release_requirement` = edge-required delivery
 * switched off (everything retained, re-activatable); `delete_relay` = a
 * `restore-direct` deletion of a guided relay (drained and removed at the end).
 */
export const RESTORE_PURPOSES = ['cancel_setup', 'release_requirement', 'delete_relay'] as const;
export type RestorePurpose = (typeof RESTORE_PURPOSES)[number];

export const RESTORE_PHASES = [
  'freeze',
  'settle',
  'verify_fcp_raw',
  'release_binding',
  'restore',
  'verify_direct',
  'finish',
] as const;
export type RestorePhase = (typeof RESTORE_PHASES)[number];

/** The direct-Host hide ledger's row states (`edgeHostHides.state`). */
export const HOST_HIDE_STATES = [
  'intended',
  'written',
  'confirmed',
  'unresolved',
  'released',
] as const;
export type HostHideState = (typeof HOST_HIDE_STATES)[number];

/**
 * Workflow refusals (`edge.<code>` on the wire): a second restore workflow, a
 * direct-Host hide or a pool / listener write while one runs.
 */
export const WORKFLOW_CODES = [
  'restore_in_progress',
  // guided setup runs: a reused relay whose node inbounds changed, a consent
  // withdrawal for a Host already hidden, an account switch after publication
  'plan_changed',
  'consent_withdrawn_hidden',
  'account_switch_late',
  // "Serve this node directly again" on a node whose members already get its direct address
  'not_edge_required',
  // "Protect again" (a re-protect run) on a node that is not live behind edges yet, or
  // that is not an enrolled node
  'reprotect_not_bound',
  'reprotect_not_enrolled',
  // ... served through more than one provider account, or with no room for the new addresses
  'reprotect_mixed_accounts',
  'reprotect_no_room',
  // provider sets: a pick switched after its addresses were published, a set
  // that leaves a transport uncovered or is too large, a removal that would uncover
  'pick_switch_late',
  'set_uncovered_listener',
  'set_too_large',
  'set_would_uncover',
] as const;
export type WorkflowCode = (typeof WORKFLOW_CODES)[number];

/**
 * The guided setup ("Autopilot") run stages, in order (convex/edgeSetupRuns.ts,
 * docs/edges.md § "Guided setup runs"). `try_it` is the per-endpoint operator
 * confirmation between verification and publication.
 */
export const SETUP_RUN_STAGES = [
  'prepare',
  'credential',
  'provision',
  'verify',
  'try_it',
  'publish',
  'hide_direct_hosts',
  'rehearse',
  'go_live',
  'done',
] as const;
export type SetupRunStage = (typeof SETUP_RUN_STAGES)[number];

/**
 * The machine's ten stages folded onto the four plain ones the operator sees
 * (`done` = 5, past the last). The one table both the CMS stage labels and the
 * server's origin status (`convex/lib/edges/originStatus.ts`) read, so a stage
 * never has two names: `publish` is where an enrolled node waits for its
 * go-live approval, so it belongs to "Going live" (4).
 */
export const SETUP_RUN_STAGE_STEP: Record<SetupRunStage, 1 | 2 | 3 | 4 | 5> = {
  prepare: 1,
  credential: 1,
  provision: 1,
  verify: 2,
  try_it: 3,
  publish: 4,
  hide_direct_hosts: 4,
  rehearse: 4,
  go_live: 4,
  done: 5,
};

/**
 * The most transports one guided run protects. A node with more frontable
 * transports is planned with `tooManyInbounds`; the operator then names up to
 * this many (`listenerKeys` on the plan and on the create).
 */
export const SETUP_RUN_MAX_LISTENERS = 8;

/**
 * running = a step is scheduled; waiting = a rotation / Host settle / probe
 * round is in flight; needs_you = an interruption (see `need`); done = live;
 * done_unbound = finished without the binding (the operator kept members on the
 * direct address); failed / cancelled = terminal, the relay stays setup-owned.
 */
export const SETUP_RUN_STATES = [
  'running',
  'waiting',
  'needs_you',
  'done',
  'done_unbound',
  'failed',
  'cancelled',
] as const;
export type SetupRunState = (typeof SETUP_RUN_STATES)[number];

/** Interruptions a run raises (`need.code`): one card, one sentence, one button each. */
export const SETUP_RUN_NEEDS = [
  'account_untested',
  'account_incompatible',
  'maintenance',
  'too_many_inbounds',
  'use_manual_setup',
  'choose_mode',
  'provider_failed',
  'address_unreachable',
  'coverage_incomplete',
  'try_it',
  'review_changed',
  'hide_failed',
  'family_disabled',
  'rehearsal_failed',
  'quarantined',
  // The node behind the relay is enrolled and its activation is not approved (docs/servers.md).
  'node_not_approved',
  // A member body's backup sits in its main address's failure domain although another is on offer.
  'resilience_short',
  // Per-country checks: the new address's first round finds it blocked in a checked country.
  'blocked_in',
  // The origin's test account is used up and its reset failed: no test link or proof can use it.
  'test_account_used_up',
] as const;
export type SetupRunNeed = (typeof SETUP_RUN_NEEDS)[number];

/**
 * Why a provider account, or one of its locations, cannot be offered by the
 * setup plan (`accounts[].reasons`, `accounts[].locations[].reasons`).
 */
export const SETUP_ACCOUNT_REASONS = [
  'account_untested',
  'account_disabled',
  'layer_mismatch',
  // The account could carry a transport whose origin did not answer the probe,
  // or whose address the probe refuses outright (private, or none at all).
  'origin_unreachable',
  'origin_not_public',
  // A load balancer for a node whose origin is a private address (the
  // management address a panel lists for a node FCP does not manage), or a
  // name (a load balancer forwards to an IP address).
  'origin_private',
  'origin_name',
  'origin_port_not_carried',
  'account_capacity_reached',
  'account_budget_exhausted',
  'provider_mismatch',
  'dns_zone_missing',
  'no_location',
  'location_disabled',
  'location_capacity_reached',
  // The zone's CAA records do not let the account's certificate authority issue;
  // the account's shared wildcard certificate failed to issue.
  'caa_forbids_ca',
  'shared_certificate_failed',
  'shared_certificate_ambiguous',
  // an L7 location (edgeSetupPlan placeProblemOf): its zone, its DNS account
  'location_check_failed',
  'dns_account_missing',
  'dns_account_disabled',
  'zone_mode_unknown',
  // A load balancer offered for a WebSocket node (lib/edges/websocketNode.ts).
  'l4_not_for_websocket',
  // A Scaleway location with no Project id whose API key's default project is unknown.
  'project_unresolved',
  // A load balancer size there that takes only the provider's own servers (lib/edges/sizeCheck.ts).
  'size_not_multicloud',
  // The account is at (or these addresses would pass) its monthly spend cap (convex/edgePlans.ts).
  'account_spend_cap_reached',
  // A load balancer address of a transport no test link can be made for (a set problem).
  'test_link_unavailable',
] as const;
export type SetupAccountReason = (typeof SETUP_ACCOUNT_REASONS)[number];

/**
 * Why a discovered panel inbound could not become a listener candidate
 * (lib/edges/inboundMapping.ts). `inactive` = the node does not serve it;
 * `tag` = the tag cannot be bound; `protocol` / `transport` / `security` =
 * outside the listener catalogue; `invalid` = a valid-looking combination the
 * registration validator still refused (detail carries the code).
 */
export const INBOUND_UNSUPPORTED_CODES = [
  'inactive',
  'loopback',
  'tag',
  'protocol',
  'transport',
  'security',
  'invalid',
] as const;
export type InboundUnsupportedCode = (typeof INBOUND_UNSUPPORTED_CODES)[number];

/**
 * Why an L4 endpoint's tick no longer counts (lib/edges/verification.ts
 * `verificationStaleReason`): the address, the listener or its configuration
 * moved, or (an enrolled node) only its REALITY key, short ids or clock bounds
 * did, so no client has proven the new key through that address.
 */
export const VERIFICATION_STALE_REASONS = ['verification_stale', 'reality_key_changed'] as const;
export type VerificationStaleReason = (typeof VERIFICATION_STALE_REASONS)[number];

/**
 * Notices a settings save answers with (`edge.<code>` in `warnings`), never
 * refusals: a drain that members' apps cannot outlive at the refresh hint
 * (`edge.updateIntervalHours`). `drain_below_refresh` = a replaced edge's drain
 * is under two refresh intervals; `burned_drain_below_refresh` = a burned
 * edge's drain is under one interval plus half an hour.
 */
export const SETTINGS_WARNING_CODES = [
  'drain_below_refresh',
  'burned_drain_below_refresh',
] as const;
export type SettingsWarningCode = (typeof SETTINGS_WARNING_CODES)[number];

/**
 * The one drain rule (the server answers with it as `warnings`, the settings
 * page and the origin dialog show it while typing): a replaced edge should
 * outlive two refresh intervals and a burned one an interval plus 30 minutes,
 * so members whose apps honour the hint move before the old address goes.
 * `originDrainMinutes` = an origin's own drain (then only that one is judged).
 */
export function drainWarningCodes(
  cfg: { drainMinutes: number; burnedDrainMinutes: number; updateIntervalHours: number },
  originDrainMinutes?: number,
): SettingsWarningCode[] {
  const minutes = cfg.updateIntervalHours * 60;
  const out: SettingsWarningCode[] = [];
  if ((originDrainMinutes ?? cfg.drainMinutes) < 2 * minutes) out.push('drain_below_refresh');
  if (originDrainMinutes === undefined && cfg.burnedDrainMinutes < minutes + 30)
    out.push('burned_drain_below_refresh');
  return out;
}

// --- checks from each country (docs/edges.md "Checks from each country") ---------------------

/** What one round says about an edge from one country (lib/edges/country/verdict.ts). */
export const COUNTRY_ROUND_RESULTS = ['proven', 'blocked', 'down', 'unknown'] as const;
export type CountryRoundResult = (typeof COUNTRY_ROUND_RESULTS)[number];

/** An edge's standing state in one country (its tracks combined, or the effective state). */
export const COUNTRY_TRACK_STATES = ['proven', 'blocked', 'unknown'] as const;
export type CountryTrackState = (typeof COUNTRY_TRACK_STATES)[number];

/** A provider location's grade in one country (lib/edges/country/group.ts `gradeOf`). */
export const COUNTRY_GROUP_GRADES = ['proven', 'blocked', 'mixed', 'unknown'] as const;
export type CountryGroupGrade = (typeof COUNTRY_GROUP_GRADES)[number];

/** Where an edge's effective state in a country comes from. */
export const COUNTRY_STATE_FROM = ['edge', 'group', 'mark'] as const;
export type CountryStateFrom = (typeof COUNTRY_STATE_FROM)[number];

/**
 * Every reason the server records on a round or a track (verdict.ts). The
 * admin words them in one place (routes/admin/edges/lib/statusWords.ts, pinned
 * by a test that reads the server's rules for the literals it writes).
 */
export const COUNTRY_REASONS = [
  'too_few',
  'no_evidence',
  'mixed',
  'controls_failed',
  'tls_unchecked',
  'tls_failed',
  'needs_repeat',
  'group_blocked',
  'country_wide',
  'expired',
  'handshake',
  'no_tcp_pairing',
  'recovered',
  'blocked',
  'never_reached',
] as const;
export type CountryReason = (typeof COUNTRY_REASONS)[number];

/**
 * Why a probe run could not measure (`probeRuns.error`, lib/edges/country/sourceHealth.ts
 * `failureCode`), plus `no_results` (it finished with nothing) and the bare run
 * statuses a run without a class falls back to.
 */
export const PROBE_FAILURE_CLASSES = [
  'auth',
  'rate_limited',
  'globalping_limit',
  'no_key',
  'no_vantages',
  'timeout',
  'service_error',
  'request_refused',
  'network',
  // FCP's own host has no route for the address family (no IPv6 on the host).
  'no_route',
  'error',
  'no_results',
  'failed',
] as const;
export type ProbeFailureClass = (typeof PROBE_FAILURE_CLASSES)[number];
