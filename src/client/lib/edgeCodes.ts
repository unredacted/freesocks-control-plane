/**
 * Codes -> words for the Admin -> Edges section. The server speaks the code
 * vocabularies in `src/shared/contracts/edgeCodes.ts`; the CMS never shows an
 * operator a bare identifier. `edgeCodes.test.ts` pins that every tuple
 * literal has an entry and that no copy contains an em-dash or an API path.
 *
 * Exports:
 *   EDGE_CODE_COPY                  code -> { label, explain, fix? } (typed complete over
 *                                   every code tuple; extra server codes allowed)
 *   EDGE_REFUSAL_COPY               the refusal-code group of that table (mutation refusals,
 *                                   plus `throttled`), shown as explain + fix in error lines
 *   codeLabel / codeExplain / codeFix(code)   with a humanised fallback for unknown codes
 *   humanizeCode(code)              'l7_auto_select_blocked' -> 'L7 auto select blocked'
 *   ROTATION_PHASE_LABELS, phaseLabel
 *   EDGE_STATUS_LABELS, edgeStatusLabel, edgeStatusTone
 *   EDGE_HEALTH_LABELS, healthTone, PUBLICATION_LABELS, publicationTone
 *   HOST_STATE_LABELS, SETUP_STEP_TITLES, SETUP_STATUS_LABELS
 *   ATTENTION_ACTION_LABELS, severityTone
 *   auditActionLabel(action)        audit `action` -> short sentence (small map + fallback)
 *   Tone                            the badge tone union the components share
 */
import type {
  AttentionAction,
  AttentionKind,
  AttentionSeverity,
  DeliveryUnavailableCode,
  InboundUnsupportedCode,
  LayerExclusionCode,
  PreflightBlockerCode,
  PoolCode,
  PreflightWarningCode,
  SetupAccountReason,
  SetupBlockerCode,
  SetupRunNeed,
  SetupStepId,
  SetupStepStatus,
  SettingsWarningCode,
} from '../../shared/contracts/edgeCodes';
import { SETUP_RUN_STAGE_STEP } from '../../shared/contracts/edgeCodes';

export type Tone = 'neutral' | 'muted' | 'info' | 'success' | 'warning' | 'danger';

export interface CodeCopy {
  /** Two to five words, sentence case. */
  label: string;
  /** One sentence: what the code means. */
  explain: string;
  /** One sentence: what the operator can do about it (absent when nothing). */
  fix?: string;
}

type KnownCode =
  | SetupBlockerCode
  | PreflightBlockerCode
  | PreflightWarningCode
  | AttentionKind
  | LayerExclusionCode
  | DeliveryUnavailableCode
  | PoolCode
  | SettingsWarningCode;

const COPY = {
  // --- origin --------------------------------------------------------------------------
  no_origin: {
    label: 'No origin chosen',
    explain: 'The origin has no target yet: nothing tells FCP what the edges should dial.',
    fix: 'Pick a backend node, a backend server or describe the address by hand.',
  },
  no_backend_server: {
    label: 'Backend server missing',
    explain: 'The origin points at a backend server that is not registered any more.',
    fix: 'Register the backend server under Servers, or choose another origin.',
  },
  backend_unreachable: {
    label: 'Backend unreachable',
    explain:
      'The last health check of the origin backend failed, so its nodes and Hosts cannot be read.',
    fix: 'Check the backend server entry and its network path, then retry.',
  },
  backend_no_host_management: {
    label: 'Backend cannot manage Hosts',
    explain:
      'This backend type has no client-facing Host objects, so FCP cannot flip them for members.',
    fix: 'Members follow rotations through rendered subscriptions instead; nothing to change here.',
  },
  backend_no_node_inventory: {
    label: 'No node inventory',
    explain: 'The backend has not reported its node list yet, so a backend node cannot be picked.',
    fix: 'Refresh the node candidates or wait for the next health check.',
  },
  // --- account -------------------------------------------------------------------------
  no_provider_account: {
    label: 'No provider account',
    explain: 'No cloud or CDN account is registered, so nothing can provision an edge.',
    fix: 'Add a provider account under Providers.',
  },
  no_compatible_account: {
    label: 'No compatible account',
    explain: 'No enabled account can carry this listener on any layer it allows.',
    fix: 'Add an account of a matching provider, or change what the listener speaks.',
  },
  credentials_untested: {
    label: 'Credentials untested',
    explain: 'The account credentials have never passed a test call against the provider.',
    fix: 'Run Test credentials on the account.',
  },
  credentials_failed: {
    label: 'Credentials failed',
    explain: 'The last credential test against the provider was refused.',
    fix: 'Rotate the credentials on the account and test again.',
  },
  dns_account_missing: {
    label: 'DNS account missing',
    explain: 'This CDN provider needs another account to host DNS records for its hostnames.',
    fix: 'Add a DNS-capable account and name it in the CDN account settings.',
  },
  zone_mode_unknown: {
    label: 'Zone mode unknown',
    explain: 'The zone facts (TLS mode, WebSocket setting) have not been observed yet.',
    fix: 'Test the account credentials so the zone can be read.',
  },
  zone_websockets_off: {
    label: 'Zone has WebSockets off',
    explain:
      'The CDN zone refuses WebSocket upgrades, so a WebSocket listener cannot be fronted there.',
    fix: 'Turn WebSockets on in the zone at the provider, then re-test the account.',
  },
  // --- template ------------------------------------------------------------------------
  no_default_template: {
    label: 'No default template',
    explain: 'The account has no default edge template, so provisioning has no parameters to use.',
    fix: 'Create a template for the provider, or seed the compiled defaults under Templates.',
  },
  template_invalid: {
    label: 'Template invalid',
    explain: 'The template parameters do not pass the provider schema.',
    fix: 'Open the template under Templates and fix the flagged fields.',
  },
  // --- origin and listener --------------------------------------------------------------
  no_relay: {
    label: 'No origin yet',
    explain: 'The origin row does not exist: the origin has not been registered.',
    fix: 'Finish the origin step, or protect the node from Edges.',
  },
  relay_deleting: {
    label: 'Origin is deleting',
    explain: 'The origin is being torn down; new work on it is refused until the delete completes.',
  },
  relay_without_listener: {
    label: 'No listener',
    explain:
      'The origin has no listener, so nothing says which port and protocol edges should carry.',
    fix: 'Add a listener, or protect the node from Edges.',
  },
  listener_not_deployed: {
    label: 'Listener not deployed',
    explain: 'This listener is not marked as live on the node yet.',
    fix: 'Mark the listener deployed once the transport is up.',
  },
  listener_disabled: {
    label: 'Listener disabled',
    explain: 'The listener is switched off, so no edge can be published for it.',
    fix: 'Enable the listener.',
  },
  needs_target: {
    label: 'REALITY target missing',
    explain: 'A REALITY listener needs the address and port it impersonates.',
    fix: 'Set the REALITY target on the listener.',
  },
  needs_names: {
    label: 'Server names missing',
    explain: 'A listener that presents a name needs at least one active server name.',
    fix: 'Add server names to the listener.',
  },
  no_udp_provider: {
    label: 'No UDP-capable provider',
    explain: 'No provider adapter forwards UDP, so this listener cannot be fronted today.',
    fix: 'Use a TCP listener, or wait for a UDP-capable provider.',
  },
  invalid_combination: {
    label: 'Invalid combination',
    explain: 'The protocol, stream transport and security fields do not form a supported listener.',
    fix: 'Choose one of the catalogued combinations.',
  },
  members_dark: {
    label: 'Members dark',
    explain:
      'Subscriptions on this origin are edge-required but nothing can be served for them yet.',
    fix: 'Publish an edge and turn rendering on.',
  },
  binding_deferred: {
    label: 'Go-live pending',
    explain:
      'This origin was set up with its delivery binding deferred: members still receive the direct address until it goes live.',
    fix: 'Finish the guided setup so the origin goes live.',
  },
  // --- first edge ----------------------------------------------------------------------
  no_edge: {
    label: 'No edge yet',
    explain: 'The origin has no edge at all; nothing fronts the origin.',
    fix: 'Provision or import an edge.',
  },
  rotation_running: {
    label: 'Rotation running',
    explain: 'A rotation is in progress on this origin; wait for it to finish.',
  },
  account_budget_exhausted: {
    label: 'Daily budget spent',
    explain: 'The account has used its daily allocation budget.',
    fix: 'Raise the budget on the account or wait for the next UTC day.',
  },
  account_capacity_reached: {
    label: 'Account at capacity',
    explain: 'The account already runs its maximum number of live edges.',
    fix: 'Raise the live-edge cap on the account or destroy an edge you no longer need.',
  },
  provision_failed: {
    label: 'Provisioning failed',
    explain: 'The last provisioning run on this origin failed.',
    fix: 'Open the rotation for the failing step, then retry.',
  },
  // --- qualification -------------------------------------------------------------------
  account_unqualified: {
    label: 'Account not qualified',
    explain: 'The account has not yet proven it can carry traffic end to end.',
    fix: 'Run a test provision through the account, then mark it qualified.',
  },
  qualification_stale: {
    label: 'Qualification stale',
    explain: 'The account was qualified with a template that has since changed.',
    fix: 'Re-qualify the account with the current template.',
  },
  qualification_credential_missing: {
    label: 'Test credential missing',
    explain: 'No qualification credential exists for this origin, so a front cannot be proven.',
    fix: 'Mint the qualification credential on the origin.',
  },
  credential_unsupported: {
    label: 'Credential unsupported',
    explain: 'The origin backend cannot mint a test credential of the kind the proof needs.',
  },
  front_unqualified: {
    label: 'Front not proven',
    explain: 'The CDN front has no current end-to-end proof, so it cannot be published.',
    fix: 'Run Qualify front on the edge.',
  },
  front_failed: {
    label: 'Front proof failed',
    explain: 'The last end-to-end test through the CDN front failed.',
    fix: 'Check the listener transport and the zone settings, then qualify again.',
  },
  // --- publish -------------------------------------------------------------------------
  pool_empty: {
    label: 'Pool empty',
    explain: 'No edge is published for this origin.',
    fix: 'Publish an edge.',
  },
  quarantined: {
    label: 'Quarantined',
    explain:
      'A rotation left the backend Hosts in an uncertain state; the origin is frozen until resolved.',
    fix: 'Open the quarantine view and keep either the previous or the current binding.',
  },
  hosts_operator_managed: {
    label: 'Hosts operator-managed',
    explain: 'FCP never writes the backend Hosts for this origin, so it cannot flip them.',
    fix: 'Apply the addresses plan by hand, or hand Host ownership to FCP.',
  },
  no_publishable_edge: {
    label: 'Nothing publishable',
    explain: 'No standby edge meets the publish preconditions.',
    fix: 'Provision a new edge or fix the blocked one.',
  },
  // --- rendering -----------------------------------------------------------------------
  render_disabled: {
    label: 'Rendering off',
    explain:
      'FCP is not rewriting subscriptions, so edge-required members get an unavailable response.',
    fix: 'Turn rendering on under Settings.',
  },
  relay_disabled: {
    label: 'Origin disabled',
    explain: 'The origin is switched off; its members receive an unavailable response.',
    fix: 'Enable the origin.',
  },
  preview_not_applied: {
    label: 'Preview did not apply',
    explain: 'A render preview produced no rewritten entry for at least one listener.',
    fix: 'Check the listener match rule against the backend body.',
  },
  entry_mismatch: {
    label: 'Entry mismatch',
    explain: 'The template entry found in the body disagrees with what the listener declares.',
    fix: 'Align the listener fields with the backend transport, or fix the match rule.',
  },
  mirrors_unvalidated: {
    label: 'Mirrors not validated',
    explain: 'A storage mirror still holds a body that predates the current pool.',
    fix: 'Wait for the mirror refresh, or trigger one.',
  },
  // --- automation ----------------------------------------------------------------------
  probes_disabled: {
    label: 'Probes off',
    explain: 'Reachability probes are disabled; the detector sees reports and load only.',
    fix: 'Turn probes on under Settings.',
  },
  probe_sources_none: {
    label: 'No probe sources',
    explain: 'Every probe source is switched off.',
    fix: 'Enable at least one probe source under Settings.',
  },
  probe_countries_none: {
    label: 'No probe countries',
    explain: 'No country on the censored-country list has "Check edges from here" on.',
    fix: 'Turn it on for a country under Settings, Censored countries.',
  },
  edge_layer_disabled: {
    label: 'Edges switched off',
    explain: 'The edges master switch is off: the detector and the reconcile cron do nothing.',
    fix: 'Turn edges on under Settings.',
  },
  auto_rotate_off: {
    label: 'Auto-rotate off',
    explain: 'Automatic replacement is off globally or for this origin.',
    fix: 'Turn auto-rotate on under Settings and on the origin.',
  },
  l7_auto_select_blocked: {
    label: 'CDN auto-select off',
    explain:
      'Automatic selection of CDN front accounts is off, so replacements stay manual for them.',
    fix: 'Turn CDN auto-select on under Settings.',
  },
  // --- preflight: start guards ----------------------------------------------------------
  maintenance: {
    label: 'Maintenance freeze',
    explain: 'The maintenance switch is on: new edge work is not admitted.',
    fix: 'Thaw under Settings when the maintenance is over.',
  },
  not_found: {
    label: 'Not found',
    explain: 'The origin, edge or rotation named by the request does not exist.',
  },
  deleting: {
    label: 'Deleting',
    explain: 'The origin is being deleted; no new operation is accepted.',
  },
  busy: {
    label: 'Origin busy',
    explain: 'Another rotation is already running on this origin.',
  },
  auto_rotate_disabled: {
    label: 'Auto-rotate disabled',
    explain: 'The detector asked for a rotation but automatic replacement is off.',
    fix: 'Rotate by hand, or turn auto-rotate on.',
  },
  concurrency: {
    label: 'Too many rotations',
    explain: 'The fleet-wide limit on concurrent rotations is reached.',
    fix: 'Wait for a rotation to finish or raise the limit under Settings.',
  },
  target_not_published: {
    label: 'Target not published',
    explain: 'The edge to replace is not in the published pool.',
  },
  cooldown: {
    label: 'In cooldown',
    explain: 'The origin rotated recently and is inside its cooldown window.',
    fix: 'Wait for the cooldown, or force the rotation.',
  },
  daily_cap: {
    label: 'Daily cap reached',
    explain: 'The origin has already rotated as often as allowed today.',
    fix: 'Wait for the next UTC day, or raise the cap.',
  },
  listener_not_found: {
    label: 'Listener not found',
    explain: 'The listener key does not exist on this origin.',
  },
  panel_op_running: {
    label: 'A server change is running',
    explain:
      'Servers is updating the node this origin serves, and holds its listeners still meanwhile.',
    fix: 'Wait for the change under Servers to finish, then try again.',
  },
  listener_unusable: {
    label: 'Listener unusable',
    explain: 'The listener is retired, disabled or not deployed.',
  },
  l7_auto_select_disabled: {
    label: 'CDN auto-select disabled',
    explain: 'Automatic selection would pick a CDN front but that is switched off.',
    fix: 'Choose the account by hand, or turn CDN auto-select on.',
  },
  l7_replacement_cap: {
    label: 'CDN replacement cap',
    explain: 'The origin already replaced a same-provider CDN front as often as allowed today.',
  },
  validation: {
    label: 'Invalid request',
    explain: 'The request body did not pass validation.',
  },
  // --- preflight: publishability --------------------------------------------------------
  edge_not_active: {
    label: 'Edge not active',
    explain: 'Only an active edge can be published.',
  },
  already_published: {
    label: 'Already published',
    explain: 'The edge is already in the pool.',
  },
  no_address: {
    label: 'No address',
    explain: 'The edge has no address of its layer yet.',
  },
  listener_retired: {
    label: 'Listener retired',
    explain: 'The listener behind this edge is retired.',
  },
  listener_no_active_name: {
    label: 'No active server name',
    explain: 'The listener presents a name but every name is retired.',
    fix: 'Reactivate or add a server name.',
  },
  provider_mismatch: {
    label: 'Provider mismatch',
    explain: 'The listener is scoped to another provider than the edge.',
  },
  transport_not_carried: {
    label: 'Transport not carried',
    explain: 'The edge layer cannot carry the listener stream transport.',
  },
  protocol_not_carried: {
    label: 'Protocol not carried',
    explain: 'The edge layer cannot carry the listener protocol.',
  },
  layer_mismatch: {
    label: 'Layer mismatch',
    explain: 'The edge layer is not one the listener allows.',
  },
  origin_tls_mismatch: {
    label: 'Origin TLS mismatch',
    explain: 'The CDN front would dial the origin with a TLS mode the listener does not declare.',
  },
  front_stale: {
    label: 'Front proof stale',
    explain: 'The end-to-end proof of the CDN front has expired.',
    fix: 'Qualify the front again.',
  },
  account_mismatch: {
    label: 'Account mismatch',
    explain: 'The listener is scoped to another account than the edge.',
  },
  edge_unhealthy: {
    label: 'Edge unhealthy',
    explain: 'The edge health is offline or degraded.',
  },
  unverified_endpoint: {
    label: 'Address not yet tested',
    explain:
      'An address goes live only after you have tried it with a real session against its current configuration.',
    fix: 'Import the test link into a client, connect, then mark the address as working.',
  },
  no_verified_spare: {
    label: 'No tested spare',
    explain:
      'Replacing this address needs a spare you have already tested; a new address cannot go live untested.',
    fix: 'Create a spare address, test it, then replace.',
  },
  // --- preflight: selection -------------------------------------------------------------
  no_compatible_listener: {
    label: 'No compatible listener',
    explain: 'No listener on the origin can be fronted by any layer.',
  },
  no_compatible_layer: {
    label: 'No compatible layer',
    explain: 'The listener chain allows no edge layer.',
  },
  no_account_for_layer: {
    label: 'No account for layer',
    explain: 'No enabled account provides the layer the listener needs.',
    fix: 'Add an account of a matching provider.',
  },
  no_account_for_provider: {
    label: 'No account for provider',
    explain: 'The listener is scoped to a provider that has no enabled account.',
  },
  no_qualified_account: {
    label: 'No qualified account',
    explain: 'No enabled account is qualified for this layer.',
    fix: 'Qualify an account with a test provision.',
  },
  accounts_exhausted: {
    label: 'Accounts exhausted',
    explain: 'Every candidate account is out of budget or capacity.',
  },
  account_not_found: {
    label: 'Account not found',
    explain: 'The named account does not exist.',
  },
  location_not_found: {
    label: 'Location not found',
    explain: 'The named location does not exist on that account.',
  },
  location_disabled: {
    label: 'Location switched off',
    explain: 'The named location is switched off on its account.',
    fix: 'Switch it on from the provider page, or pick another location.',
  },
  location_capacity_reached: {
    label: 'Location full',
    explain: 'The location already runs as many addresses as its limit allows.',
    fix: 'Raise the limit on the location or pick another one.',
  },
  location_unreachable: {
    label: 'A location is not reachable',
    explain: 'The new credentials could not read one of the account locations in use.',
    fix: 'Use credentials that reach every location, or switch that location off first.',
  },
  placement_missing: {
    label: 'Address has no location',
    explain: 'FCP does not know which region this address was made in, so it will not act on it.',
    fix: 'Find it in the provider console and remove it there if it is unused.',
  },
  account_disabled: {
    label: 'Account disabled',
    explain: 'The named account is switched off.',
  },
  account_untested: {
    label: 'Account untested',
    explain: 'The named account has not passed a credential test.',
    fix: 'Run Test credentials on the account.',
  },
  account_incompatible: {
    label: 'Account incompatible',
    explain: 'The named account cannot carry this listener.',
  },
  template_not_found: {
    label: 'Template not found',
    explain: 'The named template does not exist.',
  },
  // --- preflight: plan phase ------------------------------------------------------------
  dns_account_disabled: {
    label: 'DNS account disabled',
    explain: 'The DNS account the CDN provider relies on is switched off.',
    fix: 'Enable the DNS account.',
  },
  dns_zone_missing: {
    label: 'DNS zone missing',
    explain: 'The account settings name no DNS zone for the hostnames.',
    fix: 'Set the zone in the account settings.',
  },
  origin_transport_missing: {
    label: 'Origin transport missing',
    explain: 'The listener does not declare how a CDN front should dial the origin.',
    fix: 'Edit the listener and turn on "A CDN front can reach this transport", or protect the node from Edges.',
  },
  // --- preflight warnings ---------------------------------------------------------------
  edge_disabled: {
    label: 'Edges switched off',
    explain: 'The master switch is off; the operation runs, but nothing automatic follows.',
  },
  probe_disabled: {
    label: 'Probes off',
    explain: 'The new edge will not be probed until probes are turned on.',
  },
  mark_pepper_missing: {
    label: 'Report pepper missing',
    explain:
      'The report-dedupe pepper is not set, so member reports carry no weight in the detector.',
    fix: 'Set the mark pepper environment variable on the backend.',
  },
  unpublished_result: {
    label: 'Result stays unpublished',
    explain: 'The edge will be provisioned as a standby and not published.',
  },
  l7_manual_only: {
    label: 'CDN fronts are manual',
    explain: 'CDN auto-select is off; this front will never be picked automatically.',
  },
  // --- attention kinds ------------------------------------------------------------------
  quarantine: {
    label: 'Quarantine',
    explain:
      'A rotation left the backend Hosts uncertain; the origin is frozen until you resolve it.',
    fix: 'Inspect the live Hosts and keep the previous or the current binding.',
  },
  needs_operator: {
    label: 'Needs an operator',
    explain: 'An edge ended in a state the machine cannot resolve on its own.',
    fix: 'Destroy, forget or reactivate the edge.',
  },
  host_unresolved: {
    label: 'Host unresolved',
    explain: 'A backend Host operation had an uncertain outcome and blocks further Host writes.',
    fix: 'Look at the listener Host and adopt or release the backend object.',
  },
  rotation_failed: {
    label: 'Rotation failed',
    explain: 'The last rotation on this origin ended in failure.',
    fix: 'Open the rotation to see the failing step.',
  },
  qualification_lapsed: {
    label: 'Front proof lapsed',
    explain: 'A published CDN front has lost its end-to-end proof.',
    fix: 'Qualify the front again.',
  },
  block_suspected: {
    label: 'Block suspected',
    explain: 'The detector suspects a censor is blocking a published edge.',
    fix: 'Rotate the edge, or wait for corroboration.',
  },
  block_simulated: {
    label: 'Test block running',
    explain:
      'Test block evidence is running on this deployment: the detector treats an address as blocked and can replace it for real.',
    fix: 'End the test on the origin page when you are done.',
  },
  edge_unreachable: {
    label: 'Edge unreachable',
    explain: 'Probes cannot reach a published edge from at least one country.',
  },
  probe_source_failing: {
    label: 'A probe source is failing',
    explain:
      'A reachability source has brought back nothing for hours. A failure is never read as a block, so the countries it alone covers read as not known.',
    fix: 'Check its credential and budget in Edges settings, Probes.',
  },
  country_wide_failure: {
    label: 'Failing from a whole country',
    explain:
      'Most addresses checked from this country failed at once. A censor does not block every provider together, an outage or a probe problem does, so FCP holds these as not known instead of blocked.',
    fix: 'Look at the probe sources on the Probes page, then check again later.',
  },
  new_edge_blocked_in: {
    label: 'New address blocked in a country',
    explain:
      'A spare address that was never in use is blocked from at least one censored country while it works from elsewhere. Members there could not use it.',
    fix: 'Replace the spare, or mark the country if you know better.',
  },
  pool_below_desired: {
    label: 'Pool below desired',
    explain: 'Fewer edges are published than the origin wants.',
    fix: 'Provision or publish an edge.',
  },
  go_live_pending: {
    label: 'Go-live pending',
    explain:
      'An edge is published for this origin but its delivery binding is still deferred, so members keep the direct address.',
    fix: 'Finish the guided setup to go live.',
  },
  pool_rebalance: {
    label: 'Make room for what is missing',
    explain:
      'A transport or a provider of this node has no published address, every pool slot is taken and the pool is at its cap.',
    fix: 'Rebalance: one redundant address goes back to standby so the missing one can be published.',
  },
  pick_cooling: {
    label: 'A location is cooling',
    explain:
      'An address in this location was just blocked here, so automatic work leaves the location alone for a while.',
  },
  reduced_resilience: {
    label: 'No backup elsewhere',
    explain:
      'Members on these transports get no backup at another provider: every location that carries them is one provider.',
    fix: 'Add a location of another provider to this node.',
  },
  needs_test: {
    label: 'Blocked and the spare is untested',
    explain:
      'The address on this node looks blocked and automatic replacement has no spare you have tested.',
    fix: 'Test the spare address with a real session, then replace.',
  },
  spare_untested: {
    label: 'Spare address untested',
    explain: 'A spare address exists but has not been tried with a real session yet.',
    fix: 'Test it once; automatic replacement can then use it.',
  },
  retest_needed: {
    label: 'Retest needed',
    explain:
      'The listener or the address changed since you tested it, so the test no longer counts.',
    fix: 'Test the address again against its current configuration.',
  },
  test_key_cleanup: {
    label: 'Test key not removed',
    explain: 'A temporary test key could not be removed from the server after several tries.',
    fix: 'Check the server, remove the key by hand if it is still there, then retry the cleanup.',
  },
  direct_host_reappeared: {
    label: 'Direct address back in the backend',
    explain:
      'A backend Host that hands out the node address itself was re-enabled or added on a protected node, so members on it are refused a body until it is hidden again.',
    fix: 'Hide it in the backend, or add it to the protected node so FCP hides it for you.',
  },
  restore_in_progress: {
    label: 'Restoring the direct address',
    explain:
      'FCP is settling its Host changes on this node, releasing edge-required delivery and putting the direct addresses back, one checked step at a time.',
    fix: 'Nothing yet. Open the node to watch it finish; other changes to it wait until then.',
  },
  maintenance_frozen: {
    label: 'Maintenance freeze on',
    explain: 'No new edge work is admitted while the maintenance switch is on.',
    fix: 'Thaw when the maintenance is over.',
  },
  // --- layer exclusions -----------------------------------------------------------------
  protocol_not_http_transport: {
    label: 'Not an HTTP transport',
    explain: 'A CDN front carries only WebSocket, HTTP Upgrade or gRPC streams.',
  },
  l7_proof_unsupported: {
    label: 'No CDN proof',
    explain: 'Only a VLESS HTTP-transport TLS listener has an authenticated end-to-end proof.',
  },
  host_header_rejected: {
    label: 'Host header rejected',
    explain:
      'The node accepts only its own names as the HTTP Host header, so the CDN hostname is refused.',
    fix: 'Let the transport accept any Host header, or add the edge names to the certificate.',
  },
  origin_plaintext: {
    label: 'Origin is plaintext',
    explain:
      'The origin speaks plaintext HTTP behind the CDN, so it cannot be reached directly on L4.',
  },
  no_server_names: {
    label: 'No server names',
    explain: 'The listener presents no certificate name, so a CDN front cannot dial it over TLS.',
  },
  cert_not_public: {
    label: 'Certificate not public',
    explain: 'The origin certificate is not publicly trusted, so a CDN front cannot verify it.',
    fix: 'Use a publicly trusted certificate on the node.',
  },
  cert_name_uncovered: {
    label: 'Name not on certificate',
    explain: 'An active server name is not covered by the origin certificate.',
    fix: 'Add the name to the certificate or retire it on the listener.',
  },
  // --- delivery unavailable -------------------------------------------------------------
  relay_missing: {
    label: 'Origin missing',
    explain: 'A delivery binding still covers this origin but the origin row is gone.',
    fix: 'Release the binding under Settings, or register the origin again.',
  },
  no_render_key: {
    label: 'No render key',
    explain: 'The subscription has no render key, so a stable assignment cannot be made.',
  },
  empty_pool: {
    label: 'Empty pool',
    explain: 'No edge is published, so nothing can be rendered for members.',
    fix: 'Publish an edge.',
  },
  unsupported_format: {
    label: 'Format unsupported',
    explain: 'The renderer has no codec for this client format and listener combination.',
  },
  no_match: {
    label: 'No template entry',
    explain: 'No entry in the backend body matched the listener match rule.',
    fix: 'Check the Host remark or the address match rule.',
  },
  ambiguous_match: {
    label: 'Ambiguous match',
    explain: 'More than one entry in the backend body matched the listener.',
    fix: 'Tighten the match rule or remove the duplicate Host.',
  },
  leak_detected: {
    label: 'Origin leak detected',
    explain: 'An outgoing entry still carried the origin address; the body was withheld.',
  },
  render_failed: {
    label: 'Could not rewrite',
    explain:
      'The body could not be rewritten in this format for a reason other than a missing or mismatched entry, so it was withheld.',
  },
  // --- extra server codes the components may meet (vetoes, host states) ------------------
  node_offline: {
    label: 'Node offline',
    explain: 'The origin node is offline, so the suspicion is an outage rather than a block.',
  },
  protocol_level_block: {
    label: 'Protocol-level block',
    explain:
      'Every edge suffers alike, which points at the protocol being blocked, not the address.',
  },
  country_scoped: {
    label: 'Routed around by country',
    explain:
      'The address is blocked only where the reports come from, and members there already get another address that works, so it is not replaced for everyone.',
  },
  country_wide: {
    label: 'Everything fails there at once',
    explain:
      'Every address fails from the countries the reports come from at the same time, which points at an outage or a probe problem, so nothing is replaced.',
  },
  no_load_signal: {
    label: 'No load signal',
    explain: 'This origin kind reports no user load, so the detector uses reports and probes only.',
  },
  // --- published pool (reserved allocation, capacity, rebalance) -------------------------
  pool_full: {
    label: 'Pool full',
    explain: 'Every published slot of this origin is taken.',
    fix: 'Raise the published edges wanted on the origin, or unpublish an edge first.',
  },
  pool_reserved: {
    label: 'Slot reserved',
    explain:
      'The free pool slots are held for listeners that have no published edge yet, so a second edge for an already covered listener cannot take one.',
    fix: 'Publish an edge for the uncovered listener first, or raise the published edges wanted.',
  },
  pool_raised: {
    label: 'Pool size raised',
    explain:
      'The published edges wanted were raised so every deployed listener has a slot of its own.',
  },
  listener_cap: {
    label: 'Listener cap reached',
    explain:
      'An origin can carry at most eight deployed, enabled listeners, one published slot each; this one would be the ninth.',
    fix: 'Retire or disable a listener you do not need, or register the listener on another origin.',
  },
  pool_below_coverage: {
    label: 'Pool below coverage',
    explain:
      'The published edges wanted cannot go below the number of deployed, enabled listeners: each needs a slot of its own.',
    fix: 'Retire or disable a listener first, then lower the published edges wanted.',
  },
  no_duplicate: {
    label: 'Nothing to rebalance',
    explain:
      'Every published edge is the template edge of its listener; there is no duplicate to unpublish.',
    fix: 'Raise the published edges wanted, or retire a listener you do not need.',
  },
  setup_owned: {
    label: 'Owned by a setup run',
    explain: 'A guided setup owns this origin, so automatic replacement leaves it alone.',
    fix: 'Finish or cancel the setup run.',
  },
  // A guided run's event: it parked at publish until the enrolled node is approved.
  publish_held: {
    label: 'Waiting for go-live approval',
    explain: 'Every address is tested. Going live waits for your approval of the node.',
    fix: 'Approve go-live.',
  },
  // --- operations safety: attention, the fleet guards, delivery refusals ------------------
  fleet_brake: {
    label: 'Automatic replacement held',
    explain:
      'Many nodes look blocked at once, which points at a block on a whole provider or protocol, so FCP holds every automatic replacement instead of burning addresses.',
    fix: 'Check the probes and the reports. It releases by itself once fewer nodes look blocked.',
  },
  fleet_rotation_cap: {
    label: 'Daily replacement cap reached',
    explain:
      'Automatic replacements across all nodes reached the cap for today, so more wait until tomorrow (UTC).',
    fix: 'Raise the fleet cap under Settings if these replacements are expected.',
  },
  fleet_daily_cap: {
    label: 'Fleet daily cap reached',
    explain: 'The cap on automatic replacements across all nodes is used up for today.',
    fix: 'Wait for tomorrow (UTC), or raise the cap under Settings.',
  },
  outside_approved_shape: {
    label: 'Outside the approved setup',
    explain:
      'No account or spare fits what this node was approved for, so nothing is published without a new review.',
    fix: 'Review the node and approve it again with the account it should use.',
  },
  rotation_stuck: {
    label: 'Replacement stuck',
    explain:
      'A rotation has been running for over an hour: a provider or the backend may not be answering.',
    fix: 'Open the node to see the step it is waiting on.',
  },
  account_api_failing: {
    label: 'Provider not answering',
    explain:
      'Several calls in a row to this provider account failed (timeouts, errors on its side or refused credentials), so new edges, health checks and clean-ups stall.',
    fix: 'Check the provider status and the account credentials, then test them.',
  },
  health_stale: {
    label: 'Health not refreshed',
    explain:
      'FCP could not refresh the health of some live edges of this account for over an hour.',
    fix: 'Open the account: the provider may be refusing the reads.',
  },
  billable_idle: {
    label: 'Paid for, serving nobody',
    explain:
      'Edges that cost money serve no member until you act: the node is paused for safety, or an edge waits for an operator.',
    fix: 'Resolve the pause or the edge, so the resources are used or removed.',
  },
  delivery_refusals: {
    label: 'Members refused',
    explain:
      'Members asked for their subscription in the last hour and got nothing usable. The reasons are counted.',
    fix: 'Look at the reasons: a switch that is off, an empty pool or a node that is not live.',
  },
  family_rule_disabled: {
    label: 'App family switched off',
    explain:
      'A client app family has its render rule off, so members using those apps get nothing from a protected node.',
    fix: 'Turn the family back on under Settings, unless that is intended.',
  },
  node_ready_to_protect: {
    label: 'Node ready to protect',
    explain:
      'An enrolled node meant to sit behind an edge is ready, and nothing protects it until you start.',
    fix: 'Start protecting it.',
  },
  node_awaiting_approval: {
    label: 'Waiting for your approval',
    explain: 'A node is tested and goes live only once you approve it.',
    fix: 'Open the node and approve go-live.',
  },
  node_mode_disabled: {
    label: 'Live node nobody can pick',
    explain:
      'A node is live, but the connection mode it serves is turned off, so no member is given it.',
    fix: 'Turn the mode on in Connection modes, unless that is intended.',
  },
  node_gated: {
    label: 'Node not live',
    explain:
      'The member is on a node that is not live yet, or is closed for maintenance, so nothing is handed out for it.',
  },
  policy_moved: {
    label: 'Changed while answering',
    explain:
      'The delivery policy changed while the answer was being built, so it was not sent. The next refresh gets the current one.',
  },
  account_budget_unlimited: {
    label: 'No daily spending limit',
    explain:
      'This provider account has a daily allocation budget of 0, which means no limit: a runaway loop could create billable resources without bound.',
    fix: 'Set a daily allocation budget on the account.',
  },
  reality_key_changed: {
    label: 'Node key changed',
    explain:
      'The node’s REALITY key (or its short ids or clock settings) changed since this address was tried, so nothing has proven the new key through it.',
    fix: 'Try the address again from a client with the new key.',
  },
  family_disabled: {
    label: 'App family off',
    explain:
      'The render rule for this client app family is off, so its members get nothing from a protected node.',
    fix: 'Turn the family on under Settings.',
  },
  // --- settings notices (a save answers with them; nothing was refused) ------------------
  drain_below_refresh: {
    label: 'Drain shorter than refreshes',
    explain:
      'A replaced address is removed before apps that check for a new one at the refresh interval have had two chances to do so.',
    fix: 'Keep the drain time at two refresh intervals or more, or shorten the refresh interval.',
  },
  burned_drain_below_refresh: {
    label: 'Burned drain too short',
    explain:
      'A burned address is removed before apps outside the blocking country that refresh at the interval have moved to the new one.',
    fix: 'Keep the burned drain time at one refresh interval plus 30 minutes or more.',
  },
} as const satisfies Record<KnownCode, CodeCopy> & Record<string, CodeCopy>;

// --- discovered transports that cannot become listeners --------------------------------------
// Why a backend transport found on the node was left out of the protection plan
// (`INBOUND_UNSUPPORTED_CODES`). Kept apart from the flat table above: these words are
// generic nouns, and a future status code with the same name must not inherit them.
export const INBOUND_UNSUPPORTED_COPY: Record<InboundUnsupportedCode, CodeCopy> = {
  inactive: {
    label: 'Not served by this node',
    explain: 'The transport is in the config profile but the node does not have it active.',
    fix: 'Enable it on the node in the backend if members should use it.',
  },
  loopback: {
    label: 'Reached only from inside the node',
    explain:
      'The transport listens on a loopback address, so a provider address cannot dial it directly. Something on the node (usually a TLS terminator) accepts outside connections and forwards to it.',
    fix: 'Add the listener with the port and transport the terminator exposes (Add listener on the origin), or make the transport listen publicly with TLS of its own.',
  },
  tag: {
    label: 'Tag cannot be bound',
    explain:
      'The transport tag uses characters a backend Host cannot bind to (letters, digits and underscores only).',
    fix: 'Rename the transport tag in the config profile.',
  },
  protocol: {
    label: 'Protocol not supported',
    explain:
      'Edges can carry VLESS, Trojan and Shadowsocks transports; this protocol is not one of them.',
  },
  transport: {
    label: 'Transport not supported',
    explain:
      'Edges can carry raw TCP, WebSocket, HTTP Upgrade, gRPC and XHTTP streams; this transport is not one of them.',
  },
  security: {
    label: 'Security layer not supported',
    explain:
      'Edges can carry REALITY, TLS and plain transports; this security setting is not one of them.',
  },
  invalid: {
    label: 'Transport cannot be described',
    explain:
      'The transport looks supported but its settings could not be turned into a listener (the detail names what).',
    fix: 'Check the port, the REALITY target and the server names in the config profile.',
  },
};

export function inboundUnsupportedCopy(code: string): CodeCopy {
  const known = (INBOUND_UNSUPPORTED_COPY as Record<string, CodeCopy>)[code];
  return (
    known ?? {
      label: humanizeCode(code),
      explain: `The transport was skipped: ${humanizeCode(code)}.`,
    }
  );
}

// --- refusal codes ---------------------------------------------------------------------------
// What a mutation is refused with (`edge.<code>` on the wire, keyed bare here) that no status
// vocabulary above carries. An error line shows these as `explain` + `fix` (lib/edgeErrors.ts),
// so both read as full sentences on their own. `throttled` words a rate-limited call (HTTP 429).
const REFUSAL_COPY = {
  host_adopt_required: {
    label: 'Hosts not adopted yet',
    explain: 'FCP can only take over the Hosts once it has adopted every one of them.',
    fix: 'Open the Listeners tab and use "Adopt a Host" on each listener that has a Host in the backend, then switch again.',
  },
  host_adopt_mismatch: {
    label: 'Host does not fit',
    explain: 'That Host does not fit this listener.',
    fix: 'Pick a Host that carries the transport of this listener and dials one of its published edges.',
  },
  listener_in_use: {
    label: 'Listener still in use',
    explain: 'Edges still use this listener.',
    fix: 'Destroy or delete those edges first (Edges tab), then try again.',
  },
  needs_rotation: {
    label: 'Needs a rotation',
    explain:
      'Publishing this edge would make it the first edge of its listener, which means writing the backend Host.',
    fix: 'Use Publish so the rotation machine does the switch.',
  },
  origin_address_locked: {
    label: 'Origin address locked',
    explain: 'Edges still dial this origin address.',
    fix: 'Drain or destroy every edge of the origin before changing it.',
  },
  match_rule_overlap: {
    label: 'Match rules overlap',
    explain: 'Another listener of this origin would match the same subscription entries.',
    fix: 'Give each listener its own match rule.',
  },
  node_already_bound: {
    label: 'Node already covered',
    explain: 'Another origin already covers this node.',
  },
  server_already_bound: {
    label: 'Backend server already covered',
    explain: 'Another origin already covers this backend server.',
  },
  throttled: {
    label: 'Asked too often',
    explain:
      'That was asked too often. This call reaches a backend or a provider, so it is limited.',
    fix: 'Wait a minute and try again.',
  },
  verification_stale: {
    label: 'Configuration changed',
    explain: 'The address or its listener changed since this test link was shown.',
    fix: 'Fetch the test link again and retest the address.',
  },
  l7_proof_required: {
    label: 'Proven automatically',
    explain: 'A CDN front is verified by its own end-to-end proof, not by hand.',
  },
  restore_in_progress: {
    label: 'Restore in progress',
    explain:
      'This node is putting its direct addresses back, so a second workflow, a new hide and pool changes wait.',
    fix: 'Let the restore finish (the node page shows its phase), then try again.',
  },
  plan_changed: {
    label: 'Node changed since setup',
    explain:
      'The transports on this node are not the ones the earlier setup created listeners for, so the run cannot resume safely.',
    fix: 'Remove protection from the node, then protect it again.',
  },
  consent_withdrawn_hidden: {
    label: 'Host already hidden',
    explain:
      'A host you removed from the approval was already hidden; the run never re-enables a host on its own.',
    fix: 'Keep it approved, or remove protection to put every host back.',
  },
  account_switch_late: {
    label: 'Account fixed after publish',
    explain: 'The account can only change while nothing is published for this node yet.',
    fix: 'Cancel the run and start again with the other account.',
  },
  test_link_no_match: {
    label: 'No entry for this transport',
    explain:
      'The test credential receives no single connection entry for this transport, so no test link can be built from it.',
    fix: 'Check that the node has exactly one enabled backend Host on this transport at its own address and port.',
  },
  test_link_render_failed: {
    label: 'Test link not rendered',
    explain: 'The candidate address could not be rendered into a connection for this transport.',
    fix: 'Check the listener names and the address, then fetch the test link again.',
  },
  use_manual_setup: {
    label: 'Set up by hand',
    explain: 'Outline servers with no members have no test credential path.',
    fix: 'Give its origin a first edge on its Origin details page, or protect it once it has members.',
  },
  choose_mode: {
    label: 'Choose a connection mode',
    explain: 'The node has no usable placement to mint the test credential on.',
    fix: 'Choose the connection mode whose placement covers this node.',
  },
  credential_unresolved: {
    label: 'Credential still settling',
    explain:
      'An earlier attempt to create the test credential may still land on the backend; FCP waits before creating another.',
    fix: 'Try again in a couple of minutes.',
  },
  node_unknown: {
    label: 'Node not in inventory',
    explain: 'The backend inventory has no node with this identifier.',
    fix: 'Refresh the node list, then try again.',
  },
  node_address_unknown: {
    label: 'Node address unknown',
    explain: 'The backend reports no address for this node, so its origin cannot be probed.',
    fix: 'Set the node address on the backend, then refresh the node list.',
  },
  keep_direct_enrolled: {
    label: 'Direct address not kept',
    explain:
      'This node is enrolled in Servers, so it goes live behind its new addresses only. Members cannot stay on the direct one.',
    fix: 'Protect it and hide the hosts the addresses cannot carry.',
  },
  not_edge_required: {
    label: 'Already direct',
    explain: 'Members of this node already receive its own address.',
  },
  simulator_disabled: {
    label: 'Test blocks are off',
    explain: 'This deployment does not accept test block evidence.',
    fix: 'Only a test deployment that sets EDGE_SIMULATOR_ALLOW accepts it.',
  },
  not_published: {
    label: 'Not in use',
    explain: 'Only an address members are given can be blocked for a test.',
  },
  simulation_active: {
    label: 'Test already running',
    explain: 'This address already has a test block running.',
    fix: 'End it first, or wait for it to expire.',
  },
  simulation_country: {
    label: 'Country not checked',
    explain: 'Addresses are not checked from that country, so a test block there would not count.',
    fix: 'Pick a country from the list, or turn its address checks on under Settings.',
  },
  simulation_origin_off: {
    label: 'Origin not watched',
    explain: 'The detector does not look at a disabled origin or one being deleted.',
    fix: 'Enable the origin first.',
  },
  simulation_needs_probes: {
    label: 'Probes are off',
    explain: 'A test block needs reachability probes on.',
    fix: 'Turn reachability probes on under Settings.',
  },
  simulation_limit: {
    label: 'Too many tests',
    explain: 'At most three test blocks run at once.',
    fix: 'End one first.',
  },
  simulation_ended: {
    label: 'Test ended',
    explain: 'The test block is no longer running.',
  },
  simulation_moved: {
    label: 'Address changed',
    explain: 'The test block no longer names an address in use.',
  },
  reprotect_not_bound: {
    label: 'Not live behind addresses yet',
    explain: 'Protect again is for a node whose members already connect through its addresses.',
    fix: 'Use Protect a node, or Go live if its addresses are ready.',
  },
  reprotect_not_enrolled: {
    label: 'Not an enrolled node',
    explain: 'Only a node the node role enrolled is protected again from here.',
    fix: 'Use Replace address on its addresses instead.',
  },
  reprotect_mixed_accounts: {
    label: 'More than one account',
    explain: 'This node is served through addresses from more than one provider account.',
    fix: 'Replace its addresses one at a time from Origin details instead.',
  },
  reprotect_no_room: {
    label: 'No room for new addresses',
    explain: 'The node already uses as many addresses as one origin may.',
    fix: 'Remove an address from Origin details first, then protect it again.',
  },
  // provider sets
  pick_switch_late: {
    label: 'Already in use',
    explain: 'That location already has a published address in this run, so it cannot be swapped.',
    fix: "Let the run finish, then change the node's locations.",
  },
  set_uncovered_listener: {
    label: 'A transport has no location',
    explain: "None of the picked locations can carry one of this node's transports.",
    fix: 'Add a location whose provider carries it.',
  },
  set_too_large: {
    label: 'Too many addresses',
    explain: 'These locations would need more addresses than one node can publish.',
    fix: 'Pick fewer locations.',
  },
  set_would_uncover: {
    label: 'Would leave members without',
    explain: 'Removing it would leave a transport without a tested address in another location.',
    fix: 'Publish a tested address elsewhere first, then remove it.',
  },
  // provider locations (where an account creates its addresses)
  no_location: {
    label: 'No location yet',
    explain: 'The account has no location to create addresses in.',
    fix: 'Add a location on the provider page.',
  },
  location_capacity: {
    label: 'Location full',
    explain: 'The location already runs as many addresses as its limit allows.',
    fix: 'Raise the limit on the location or pick another one.',
  },
  location_not_offered: {
    label: 'Not offered to this account',
    explain: 'The provider does not offer that region or zone to these credentials.',
    fix: 'Pick one from the list the provider returned.',
  },
  location_unchecked: {
    label: 'Location not checked',
    explain: 'The provider could not be asked whether it offers that place to this account.',
    fix: 'Try again in a moment.',
  },
  location_in_use: {
    label: 'Location still in use',
    explain: 'An address still lives in this location, or a protected node uses it.',
    fix: 'Remove or replace those addresses first.',
  },
  location_not_geographic: {
    label: 'No regions for this provider',
    explain: 'This provider is not tied to a region: its account has one location already.',
  },
  template_value_required: {
    label: 'Choose a value for this region',
    explain: 'The template leaves a value empty that this provider needs per region.',
    fix: 'Pick it for this location, or set it in the template.',
  },
  placement_on_location: {
    label: 'Region is set per location',
    explain: 'Where edges are created is part of a location, not of the account.',
    fix: 'Add a location on the provider page instead.',
  },
} as const satisfies Record<string, CodeCopy>;

export const EDGE_REFUSAL_COPY: Record<string, CodeCopy> = REFUSAL_COPY;

export const EDGE_CODE_COPY: Record<string, CodeCopy> = { ...COPY, ...REFUSAL_COPY };

const ACRONYMS: Record<string, string> = {
  l4: 'L4',
  l7: 'L7',
  dns: 'DNS',
  tls: 'TLS',
  sni: 'SNI',
  udp: 'UDP',
  tcp: 'TCP',
  cdn: 'CDN',
  id: 'ID',
  ip: 'IP',
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  http: 'HTTP',
  https: 'HTTPS',
  ws: 'WebSocket',
  grpc: 'gRPC',
  vless: 'VLESS',
  reality: 'REALITY',
};

/** `snake_case`, `dotted.path` or `kebab-case` -> words, first word capitalised. */
export function humanizeCode(code: string): string {
  const words = code
    .split(/[._\-\s]+/)
    .filter(Boolean)
    .map((w) => ACRONYMS[w.toLowerCase()] ?? w.toLowerCase());
  if (words.length === 0) return '';
  const first = words[0]!;
  words[0] = ACRONYMS[first.toLowerCase()] ?? first[0]!.toUpperCase() + first.slice(1);
  return words.join(' ');
}

export function codeLabel(code: string | null | undefined): string {
  if (!code) return '';
  return EDGE_CODE_COPY[code]?.label ?? humanizeCode(code);
}

export function codeExplain(code: string | null | undefined): string {
  if (!code) return '';
  return EDGE_CODE_COPY[code]?.explain ?? `The server reported ${humanizeCode(code)}.`;
}

export function codeFix(code: string | null | undefined): string | undefined {
  if (!code) return undefined;
  return EDGE_CODE_COPY[code]?.fix;
}

// --- rotation phases ----------------------------------------------------------------------

export const ROTATION_PHASE_LABELS: Record<string, string> = {
  select: 'Selecting',
  provisioning: 'Provisioning',
  verifying: 'Verifying',
  publishing: 'Publishing',
  host_flipping: 'Flipping Hosts',
  confirming: 'Confirming',
  finalizing: 'Finalizing',
  rolling_back: 'Rolling back',
  done: 'Done',
  failed: 'Failed',
  rolled_back: 'Rolled back',
  quarantined: 'Quarantined',
  cancelled: 'Cancelled',
};

export const phaseLabel = (phase: string): string =>
  ROTATION_PHASE_LABELS[phase] ?? humanizeCode(phase);
export function phaseTone(phase: string): Tone {
  if (phase === 'done') return 'success';
  if (phase === 'failed' || phase === 'quarantined') return 'danger';
  if (phase === 'rolled_back' || phase === 'cancelled' || phase === 'rolling_back')
    return 'warning';
  return 'info';
}

// --- edge statuses / health / publication ----------------------------------------------------

export const EDGE_STATUS_LABELS: Record<string, string> = {
  planning: 'Planning',
  provisioning: 'Provisioning',
  verifying: 'Verifying',
  active: 'Active',
  draining: 'Draining',
  destroying: 'Destroying',
  destroyed: 'Destroyed',
  failed: 'Failed',
  cancelled: 'Cancelled',
  quarantined: 'Quarantined',
  needs_operator: 'Needs operator',
};
export const edgeStatusLabel = (status: string): string =>
  EDGE_STATUS_LABELS[status] ?? humanizeCode(status);
export function edgeStatusTone(status: string): Tone {
  switch (status) {
    case 'active':
      return 'success';
    case 'planning':
    case 'provisioning':
    case 'verifying':
      return 'info';
    case 'draining':
    case 'destroying':
    case 'cancelled':
      return 'warning';
    case 'failed':
    case 'quarantined':
    case 'needs_operator':
      return 'danger';
    case 'destroyed':
      return 'muted';
    default:
      return 'neutral';
  }
}

export const EDGE_HEALTH_LABELS: Record<string, string> = {
  online: 'Online',
  offline: 'Offline',
  degraded: 'Degraded',
  unknown: 'Unknown',
};
export const healthLabel = (health: string): string =>
  EDGE_HEALTH_LABELS[health] ?? humanizeCode(health);
export function healthTone(health: string): Tone {
  switch (health) {
    case 'online':
      return 'success';
    case 'degraded':
      return 'warning';
    case 'offline':
      return 'danger';
    default:
      return 'muted';
  }
}

export const PUBLICATION_LABELS: Record<string, string> = {
  unpublished: 'Standby',
  published: 'Published',
  draining: 'Draining',
};
export const publicationLabel = (p: string): string => PUBLICATION_LABELS[p] ?? humanizeCode(p);
export function publicationTone(p: string): Tone {
  if (p === 'published') return 'success';
  if (p === 'draining') return 'warning';
  return 'info';
}

export const READINESS_LABELS: Record<string, string> = {
  ready: 'Ready',
  pending: 'Pending',
  failed: 'Failed',
  unknown: 'Unknown',
};
export function readinessTone(r: string): Tone {
  if (r === 'ready') return 'success';
  if (r === 'pending') return 'info';
  if (r === 'failed') return 'danger';
  return 'muted';
}

export const HOST_STATE_LABELS: Record<string, string> = {
  absent: 'No Host',
  creating: 'Creating',
  present: 'Present',
  deleting: 'Deleting',
  unresolved: 'Unresolved',
  ambiguous: 'Ambiguous',
};
export function hostStateTone(s: string): Tone {
  if (s === 'present') return 'success';
  if (s === 'creating' || s === 'deleting') return 'info';
  if (s === 'unresolved' || s === 'ambiguous') return 'danger';
  return 'muted';
}

// --- guided setup ------------------------------------------------------------------------------

export const SETUP_STEP_TITLES: Record<SetupStepId, string> = {
  origin: 'Origin',
  account: 'Provider account',
  template: 'Edge template',
  relay: 'Origin and listeners',
  edge: 'First edge',
  qualification: 'Qualification',
  publish: 'Publish',
  rendering: 'Rendering',
  automation: 'Automation',
};
export const SETUP_STEP_HINTS: Record<SetupStepId, string> = {
  origin: 'What the edges dial: a backend node, a backend server or an address.',
  account: 'A cloud or CDN account with tested credentials.',
  template: 'The provisioning parameters the account uses.',
  relay: 'The origin row and at least one deployed listener.',
  edge: 'One provisioned or imported edge.',
  qualification: 'Proof the account (and a CDN front) carries traffic end to end.',
  publish: 'At least one edge in the published pool.',
  rendering: 'Members receive rewritten subscriptions.',
  automation: 'Probes and the detector watch the origin.',
};
export const SETUP_STATUS_LABELS: Record<SetupStepStatus, string> = {
  done: 'Done',
  ready: 'Ready',
  blocked: 'Blocked',
  skipped: 'Not applicable',
};
export function setupStatusTone(s: SetupStepStatus): Tone {
  if (s === 'done') return 'success';
  if (s === 'ready') return 'info';
  if (s === 'blocked') return 'warning';
  return 'muted';
}

// --- attention -----------------------------------------------------------------------------

/**
 * The button labels the simple screens show (AttentionList `plain`): plain verbs,
 * never the Advanced terms (Thaw, Qualify front, Publish).
 */
export const PLAIN_ATTENTION_ACTION_LABELS: Record<AttentionAction, string> = {
  resolve_quarantine: 'Review the pause',
  resolve_operator: 'Look at the address',
  look_at_host: 'Look at the backend',
  open_setup: 'Resume protection',
  open_relay: 'Open the node',
  open_edge: 'Open the address',
  open_account: 'Open the account',
  open_settings: 'Open settings',
  publish: 'Put it in use',
  provision: 'Create an address',
  qualify_front: 'Check the address',
  rotate: 'Replace the address',
  test_credentials: 'Test the account',
  verify_endpoint: 'Test the address',
  thaw: 'Resume new work',
  rebalance: 'Make room',
  require_edges: 'Go live',
  protect_node: 'Protect the node',
  open_node: 'Review go-live',
  open_modes: 'Open Connection modes',
  open_probes: 'See the checks',
};

export const ATTENTION_ACTION_LABELS: Record<AttentionAction, string> = {
  resolve_quarantine: 'Resolve quarantine',
  resolve_operator: 'Resolve edge',
  look_at_host: 'Look at Host',
  open_setup: 'Resume setup',
  open_relay: 'Open origin',
  open_edge: 'Open edge',
  open_account: 'Open account',
  open_settings: 'Open settings',
  publish: 'Publish',
  provision: 'Provision',
  qualify_front: 'Qualify front',
  rotate: 'Rotate',
  test_credentials: 'Test credentials',
  verify_endpoint: 'Test the address',
  thaw: 'Thaw',
  rebalance: 'Make room',
  require_edges: 'Go live',
  protect_node: 'Protect node',
  open_node: 'Open node',
  open_modes: 'Connection modes',
  open_probes: 'Open probes',
};

export function severityTone(s: AttentionSeverity): Tone {
  if (s === 'critical') return 'danger';
  if (s === 'warning') return 'warning';
  return 'info';
}

// --- guided setup runs (Autopilot) -------------------------------------------------------------

/** The four plain stages a guided run shows, in order. */
export const SETUP_RUN_PLAIN_STAGES = [
  'Creating the address',
  'Checking from outside',
  'Checking it works',
  'Going live',
] as const;

/**
 * The machine's ten stages folded onto the four plain ones (`done` = 5, past
 * the last). Defined next to SETUP_RUN_STAGES in the shared contract (the
 * server's origin status reads the same table) and re-exported here.
 */
export { SETUP_RUN_STAGE_STEP };

/** One card per interruption: `explain` is the sentence, `fix` the button (secondary in parentheses). */
export const SETUP_RUN_NEED_COPY: Record<SetupRunNeed, CodeCopy> = {
  account_untested: {
    label: 'Account not tested',
    explain: 'The provider account has not passed a credential test yet.',
    fix: 'Test again (Choose another account).',
  },
  account_incompatible: {
    label: 'Account cannot front this node',
    explain: 'The provider account cannot carry every transport this node serves.',
    fix: 'Choose another account.',
  },
  maintenance: {
    label: 'New work is paused',
    explain: 'Edges are in maintenance, so the run cannot start new work.',
    fix: 'Resume new work.',
  },
  too_many_inbounds: {
    label: 'Too many transports',
    explain: 'The node serves more transports than one run protects.',
    fix: 'Pick the ones to protect.',
  },
  use_manual_setup: {
    label: 'Set up by hand',
    explain: 'Outline servers with no members are outside the guided setup.',
    fix: 'Open its origin and give it a first edge there.',
  },
  choose_mode: {
    label: 'Connection mode needed',
    explain: 'The test account needs a connection mode with a placement on this backend.',
    fix: 'Choose connection mode.',
  },
  provider_failed: {
    label: 'Provider step failed',
    explain: 'The provider could not create or publish the address (the detail names the step).',
    fix: 'Try again (Choose another account).',
  },
  address_unreachable: {
    label: 'Address unreachable',
    explain: 'The new address could not be reached from outside.',
    fix: 'Try another address (Go live anyway).',
  },
  blocked_in: {
    label: 'Blocked in a country',
    explain:
      'The new address is blocked from at least one censored country on its first check, while it works from elsewhere.',
    fix: 'Try another address (Go live anyway).',
  },
  coverage_incomplete: {
    label: 'Not every transport covered',
    explain: 'The published pool had no room for one of the listeners.',
    fix: 'Try again.',
  },
  try_it: {
    label: 'Try each address',
    explain:
      'Import each test link into a client (it uses a test account of its own), connect, load a page, then answer Works or Doesn’t work.',
    fix: 'Works (Doesn’t work).',
  },
  review_changed: {
    label: 'Hosts changed',
    explain: 'The backend now has unsupported Hosts the review did not show.',
    fix: 'Review the change.',
  },
  hide_failed: {
    label: 'Could not hide a Host',
    explain: 'The backend refused to hide one of the old direct Hosts.',
    fix: 'Check again (Hide them in the backend yourself).',
  },
  family_disabled: {
    label: 'Client family off',
    explain: 'Rendering is turned off for one client family, so its members would get nothing.',
    fix: 'Turn on for that family.',
  },
  rehearsal_failed: {
    label: 'Rehearsal failed',
    explain: 'A member body did not render through the new address (the detail names the case).',
    fix: 'Try again.',
  },
  resilience_short: {
    label: 'No backup elsewhere',
    explain:
      'A member would get the backup address from the same provider as the main one, although another provider is on offer.',
    fix: 'Try again. If it stays, check the render rules for that client family.',
  },
  node_not_approved: {
    label: 'Approve go-live',
    explain: 'Every address works. The node goes live for members once you approve it.',
    fix: 'Approve go-live.',
  },
  quarantined: {
    label: 'Paused for safety',
    explain: 'Replacing an address could not finish and paused this node.',
    fix: 'Check the backend, then keep the old or the new addresses.',
  },
};

export const SETUP_ACCOUNT_REASON_COPY: Record<SetupAccountReason, CodeCopy> = {
  account_untested: {
    label: 'Not tested',
    explain: 'The account has not passed a credential test.',
    fix: 'Test the credentials.',
  },
  account_disabled: { label: 'Disabled', explain: 'The account is disabled.' },
  layer_mismatch: {
    label: 'Cannot carry every transport',
    explain: 'The account fronts at a layer one of the transports cannot use.',
  },
  origin_port_not_carried: {
    label: 'Wrong port for gRPC',
    explain: 'A CDN passes gRPC only to a node listening on port 443.',
    fix: 'Move the gRPC transport to port 443.',
  },
  account_capacity_reached: {
    label: 'No room',
    explain: 'The account has fewer free edges than this node needs.',
    fix: 'Raise its edge limit or free an edge.',
  },
  account_budget_exhausted: {
    label: 'Daily budget used',
    explain: 'The account has fewer allocations left today than this node needs.',
    fix: 'Wait for tomorrow or raise the budget.',
  },
  provider_mismatch: {
    label: 'Other provider pinned',
    explain: 'A listener on this node is pinned to another provider.',
  },
  dns_zone_missing: {
    label: 'No DNS zone',
    explain: 'The CDN account names no DNS account for its hostnames.',
    fix: 'Set the DNS account on the provider.',
  },
  no_location: {
    label: 'No location yet',
    explain: 'The account has no location to create addresses in.',
    fix: 'Add a location to the account.',
  },
  location_disabled: {
    label: 'Location switched off',
    explain: 'This location is switched off on the account.',
    fix: 'Switch it on from the provider page.',
  },
  location_capacity_reached: {
    label: 'Location full',
    explain: 'This location has fewer free addresses than this node needs.',
    fix: 'Raise its limit or free an address there.',
  },
};

export function setupRunNeedCopy(code: string | null | undefined): CodeCopy {
  const known = code ? (SETUP_RUN_NEED_COPY as Record<string, CodeCopy>)[code] : undefined;
  return (
    known ?? {
      label: humanizeCode(code ?? ''),
      explain: `The run needs you: ${humanizeCode(code ?? 'something')}.`,
    }
  );
}

// --- audit actions (Timeline) ----------------------------------------------------------------

const AUDIT_ACTION_LABELS: Record<string, string> = {
  'relay.create': 'Origin created',
  'relay.registered': 'Origin registered by the node role',
  'relay.upsert': 'Origin registered',
  'relay.update': 'Origin settings changed',
  'relay.delete': 'Origin deleted',
  'relay.delivery.released': 'Delivery binding released',
  'relay.listener.upsert': 'Listener registered',
  'relay.listener.update': 'Listener changed',
  'relay.listener.retire': 'Listener retired',
  'relay.listener.name.retire': 'Server name retired',
  'relay.listener.name.reactivate': 'Server name reactivated',
  'relay.listener.sni_pick': 'Server name selection changed',
  'relay.host.created': 'Backend Host created',
  'relay.host.deleted': 'Backend Host deleted',
  'relay.host.adopted': 'Backend Host adopted',
  'relay.host.adopt_requested': 'Host adoption requested',
  'relay.host.released': 'Backend Host released',
  'relay.qualification_credential': 'Qualification credential changed',
  'edge.published': 'Edge published',
  'edge.unpublished': 'Edge unpublished',
  'edge.rotated': 'Edge replaced',
  'edge.burned': 'Edge burned',
  'edge.rolled_back': 'Rotation rolled back',
  'edge.rotation_failed': 'Rotation failed',
  'edge.quarantined': 'Origin quarantined',
  'edge.quarantine_resolved': 'Quarantine resolved',
  'edge.destroy': 'Edge destroy requested',
  'edge.destroyed': 'Edge destroyed',
  'edge.destroy_failed': 'Edge destroy failed',
  'edge.retry_destroy': 'Destroy retried',
  'edge.delete': 'Edge deleted',
  'edge.forget': 'Edge forgotten',
  'edge.reactivate': 'Edge reactivated',
  'edge.adopted': 'Edge imported',
  'edge.drift': 'Drift observed',
  'edge.orphan_suspected': 'Orphaned resource suspected',
  'edge.live.pulled': 'Live snapshot refreshed',
  'edge.block_suspected': 'Block suspected',
  'edge.block_cleared': 'Block suspicion cleared',
  'edge.block_simulation.started': 'Test block started',
  'edge.block_simulation.ended': 'Test block ended',
  'edge.delivery.binding_released': 'Delivery binding released',
  'edge.provider_account.create': 'Provider account created',
  'edge.provider_account.update': 'Provider account changed',
  'edge.provider_account.delete': 'Provider account deleted',
  'edge.provider_account.qualified': 'Account qualification changed',
  'edge.provider_account.credentials_rotated': 'Account credentials rotated',
  'edge.template.create': 'Template created',
  'edge.template.update': 'Template changed',
  'edge.template.delete': 'Template deleted',
  'admin.edge.provision': 'Provision requested',
  'admin.edge.test_provision': 'Test provision requested',
  'admin.edge.publish': 'Publish requested',
  'admin.edge.rotate': 'Rotation requested',
  'admin.edge.burn': 'Burn requested',
  'admin.edge.cancel': 'Cancel requested',
  'admin.edge.config.change': 'Edge settings changed',
  'admin.edge.render.change': 'Rendering settings changed',
  'admin.edge.probe.change': 'Probe settings changed',
  'admin.edge.maintenance': 'Maintenance switch changed',
  'admin.edge.reset': 'Edge tables reset',
  'edge.pool_expanded': 'Pool expanded for an uncovered listener',
  'edge.relay.rebalanced': 'Duplicate edge sent back to standby',
  'edge.automation.set': 'Automatic protection switched',
  'edge.setup_run.started': 'Guided setup started',
  'edge.setup_run.needs_operator': 'Guided setup needs you',
  'edge.setup_run.go_live': 'Guided setup went live',
  'edge.setup_run.finished': 'Guided setup finished',
  'edge.setup_run.cancelled': 'Guided setup cancelled',
  'edge.render.enabled_by_setup': 'Rendering turned on by a guided setup',
  'probe.requested': 'Probe requested',
  'probe.run': 'Probe run finished',
  'probe.verdict': 'Reachability verdict changed',
  'edge.country.state': 'Result from a country changed',
  'edge.country.mark': 'Marked for a country',
  'edge.country.check': 'Checked from every country',
  'probe.target.create': 'Probe target created',
  'probe.target.update': 'Probe target changed',
  'probe.target.delete': 'Probe target deleted',
};

export function auditActionLabel(action: string): string {
  const known = AUDIT_ACTION_LABELS[action];
  if (known) return known;
  // 'edge.foo_bar' -> 'Edge foo bar'; 'admin.edge.x' -> 'Edge x'.
  const stripped = action.replace(/^admin\./, '');
  return humanizeCode(stripped);
}

// --- plain words (the simple screens) ---------------------------------------------------------
// The home, node, providers and protect screens speak in plain words; the Advanced
// pages keep the technical terms. `PLAIN_WORDS` is the table (technical -> plain),
// `plainWords(text)` rewrites a technical sentence with it (whole words, case kept
// on the first letter), `plainAuditActionLabel` is the Timeline map of the node page,
// `RESTORE_PHASE_WORDS` the restore workflow's phases in words.

export const PLAIN_WORDS: Record<string, string> = {
  origin: 'protected node',
  origins: 'protected nodes',
  edge: 'address',
  edges: 'addresses',
  published: 'in use',
  standby: 'spare',
  standbys: 'spares',
  draining: 'retiring',
  rotate: 'replace address',
  rotation: 'address replacement',
  rotated: 'replaced',
  burn: 'replace now (blocked)',
  burned: 'replaced now (blocked)',
  provision: 'create address',
  provisioned: 'created',
  provisioning: 'creating an address',
  qualified: 'trusted',
  qualification: 'trust',
  quarantine: 'paused for safety',
  quarantined: 'paused for safety',
  'host flip': 'update the backend',
  listener: 'transport',
  listeners: 'transports',
  inbound: 'transport',
  inbounds: 'transports',
  rotations: 'address replacements',
  endpoint: 'address',
  endpoints: 'addresses',
  thaw: 'resume new work',
  // Whole fix phrases whose verb has no plain one-word swap (longest match wins).
  'run qualify front on the edge': 'check the address',
  'qualify the front again': 'check the address again',
  'publish an edge': 'put an address in use',
  'publish this edge': 'put this address in use',
  'provision or import an edge': 'create or import an address',
  'provision or publish an edge': 'create an address or put one in use',
  'provision a new edge': 'create a new address',
  'raise the published edges wanted': 'raise the number of addresses in use',
  'edge work': 'new work',
};

/** Rewrite a technical sentence in plain words (whole-word, longest match first). */
export function plainWords(text: string): string {
  const keys = Object.keys(PLAIN_WORDS).sort((a, b) => b.length - a.length);
  let out = text;
  for (const k of keys) {
    const re = new RegExp(`\\b${k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi');
    out = out.replace(re, (m) => {
      const plain = PLAIN_WORDS[k]!;
      return m[0] === m[0]!.toUpperCase() ? plain[0]!.toUpperCase() + plain.slice(1) : plain;
    });
  }
  return out;
}

/** The node page's timeline: the audit action in plain words. */
const PLAIN_AUDIT_LABELS: Record<string, string> = {
  'relay.create': 'Node added',
  'relay.registered': 'Node registered',
  'relay.upsert': 'Node registered',
  'relay.update': 'Settings changed',
  'relay.delete': 'Protection removed',
  'relay.host.created': 'Backend updated with the new address',
  'relay.host.deleted': 'Old address removed from the backend',
  'edge.published': 'Address in use',
  'edge.unpublished': 'Address taken out of use',
  'edge.rotated': 'Address replaced',
  'edge.burned': 'Address replaced (blocked)',
  'edge.rolled_back': 'Replacement rolled back',
  'edge.rotation_failed': 'Replacement failed',
  'edge.quarantined': 'Paused for safety',
  'edge.quarantine_resolved': 'Safety pause lifted',
  'edge.destroyed': 'Address destroyed',
  'edge.verified': 'Address tested with a real session',
  'edge.block_suspected': 'Address looks blocked',
  'edge.block_cleared': 'Address no longer looks blocked',
  'edge.block_simulation.started': 'Test block started',
  'edge.block_simulation.ended': 'Test block ended',
  'edge.host.hidden': 'Direct address hidden in the backend',
  'edge.host.restored': 'Direct address restored in the backend',
  'edge.relay.restore_started': 'Removing protection',
  'edge.setup_run.started': 'Protection started',
  'edge.setup_run.needs_operator': 'Protection needs you',
  'edge.setup_run.go_live': 'Protection live',
  'edge.setup_run.finished': 'Protection finished',
  'edge.setup_run.cancelled': 'Protection cancelled',
  'admin.edge.provision': 'Address requested',
  'admin.edge.test_provision': 'Test address requested',
  'admin.edge.rotate': 'Replacement requested',
  'admin.edge.burn': 'Replacement requested (blocked)',
  'probe.verdict': 'Reachability changed',
  'edge.country.state': 'Result from a country changed',
  'edge.country.mark': 'Marked for a country',
  'edge.country.check': 'Checked from every country',
};
export function plainAuditActionLabel(action: string): string {
  return PLAIN_AUDIT_LABELS[action] ?? plainWords(auditActionLabel(action));
}

/** The restore workflow (removing protection) phase, as the node page shows it. */
export const RESTORE_PHASE_WORDS: Record<string, string> = {
  freeze: 'Pausing changes on this node',
  settle: 'Waiting for the backend to settle',
  verify_fcp_raw: 'Checking what the backend serves',
  release_binding: 'Handing members the direct address',
  restore: 'Restoring the direct address in the backend',
  verify_direct: 'Checking the direct address works',
  finish: 'Finishing',
};
export const restorePhaseWords = (phase: string): string =>
  RESTORE_PHASE_WORDS[phase] ?? humanizeCode(phase);
