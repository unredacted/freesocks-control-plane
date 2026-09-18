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
] as const;
export type PreflightBlockerCode = (typeof PREFLIGHT_BLOCKER_CODES)[number];

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

/** Attention items, in the order the server ranks them (most urgent first). */
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
  'drift',
  'restore_in_progress',
  'maintenance_frozen',
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
] as const;
export type AttentionAction = (typeof ATTENTION_ACTIONS)[number];

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
] as const;
export type DeliveryUnavailableCode = (typeof DELIVERY_UNAVAILABLE_CODES)[number];

/**
 * Published-pool refusals and notices (`edge.<code>` on the wire): reserved
 * allocation (`pool_reserved`), a full pool, a rebalance with nothing to
 * unpublish, a pool raised at registration (`pool_raised`, a warning), and the
 * detector veto for a setup-owned relay.
 */
export const POOL_CODES = [
  'pool_full',
  'pool_reserved',
  'pool_raised',
  'no_duplicate',
  'setup_owned',
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
export const WORKFLOW_CODES = ['restore_in_progress'] as const;
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
] as const;
export type SetupRunNeed = (typeof SETUP_RUN_NEEDS)[number];

/** Why a provider account cannot be offered by the setup plan (`accounts[].reasons`). */
export const SETUP_ACCOUNT_REASONS = [
  'account_untested',
  'account_disabled',
  'layer_mismatch',
  'account_capacity_reached',
  'account_budget_exhausted',
  'provider_mismatch',
  'dns_zone_missing',
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
  'tag',
  'protocol',
  'transport',
  'security',
  'invalid',
] as const;
export type InboundUnsupportedCode = (typeof INBOUND_UNSUPPORTED_CODES)[number];
