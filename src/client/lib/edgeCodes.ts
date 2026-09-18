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
 *   ROTATION_PHASE_LABELS, phaseLabel, isTerminalPhase
 *   EDGE_STATUS_LABELS, edgeStatusLabel, edgeStatusTone
 *   EDGE_HEALTH_LABELS, healthTone, PUBLICATION_LABELS, publicationTone
 *   HOST_STATE_LABELS, SETUP_STEP_TITLES, SETUP_STATUS_LABELS
 *   ATTENTION_ACTION_LABELS, attentionSeverityTone, severityTone
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
  SetupRunStage,
  SetupRunState,
  SetupStepId,
  SetupStepStatus,
} from '../../shared/contracts/edgeCodes';

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
  | PoolCode;

const COPY = {
  // --- origin --------------------------------------------------------------------------
  no_origin: {
    label: 'No origin chosen',
    explain: 'The relay has no origin yet: nothing tells FCP what the edges should dial.',
    fix: 'Pick a panel node, a backend server or describe the address by hand.',
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
    explain: 'The backend has not reported its node list yet, so a panel node cannot be picked.',
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
  // --- relay and listener --------------------------------------------------------------
  no_relay: {
    label: 'No relay yet',
    explain: 'The relay row does not exist: the origin has not been registered.',
    fix: 'Finish the origin step, or let the node role register it.',
  },
  relay_deleting: {
    label: 'Relay is deleting',
    explain: 'The relay is being torn down; new work on it is refused until the delete completes.',
  },
  relay_without_listener: {
    label: 'No listener',
    explain:
      'The relay has no listener, so nothing says which port and protocol edges should carry.',
    fix: 'Add a listener, or register the node with the role.',
  },
  listener_not_deployed: {
    label: 'Listener not deployed',
    explain: 'The node has not confirmed this listener is live yet.',
    fix: 'Run the node role, or mark the listener deployed once the inbound is up.',
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
      'This relay was set up with its delivery binding deferred: members still receive the direct address until it goes live.',
    fix: 'Finish the guided setup so the relay goes live.',
  },
  // --- first edge ----------------------------------------------------------------------
  no_edge: {
    label: 'No edge yet',
    explain: 'The relay has no edge at all; nothing fronts the origin.',
    fix: 'Provision or import an edge.',
  },
  rotation_running: {
    label: 'Rotation running',
    explain: 'A rotation is in progress on this relay; wait for it to finish.',
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
    explain: 'The last provisioning run on this relay failed.',
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
    explain: 'No qualification credential exists for this relay, so a front cannot be proven.',
    fix: 'Mint the qualification credential on the relay.',
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
    explain: 'No edge is published for this relay.',
    fix: 'Publish an edge.',
  },
  quarantined: {
    label: 'Quarantined',
    explain:
      'A rotation left the panel Hosts in an uncertain state; the relay is frozen until resolved.',
    fix: 'Open the quarantine view and keep either the previous or the current binding.',
  },
  hosts_operator_managed: {
    label: 'Hosts operator-managed',
    explain: 'FCP never writes the panel Hosts for this relay, so it cannot flip them.',
    fix: 'Apply the hosts plan by hand, or hand Host ownership to FCP.',
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
    label: 'Relay disabled',
    explain: 'The relay is switched off; its members receive an unavailable response.',
    fix: 'Enable the relay.',
  },
  preview_not_applied: {
    label: 'Preview did not apply',
    explain: 'A render preview produced no rewritten entry for at least one listener.',
    fix: 'Check the listener match rule against the panel body.',
  },
  entry_mismatch: {
    label: 'Entry mismatch',
    explain: 'The template entry found in the body disagrees with what the listener declares.',
    fix: 'Align the listener fields with the panel inbound, or fix the match rule.',
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
    explain: 'No country is configured for probing.',
    fix: 'Add countries under Settings.',
  },
  edge_layer_disabled: {
    label: 'Edges switched off',
    explain: 'The edges master switch is off: the detector and the reconcile cron do nothing.',
    fix: 'Turn edges on under Settings.',
  },
  auto_rotate_off: {
    label: 'Auto-rotate off',
    explain: 'Automatic replacement is off globally or for this relay.',
    fix: 'Turn auto-rotate on under Settings and on the relay.',
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
    explain: 'The relay, edge or rotation named by the request does not exist.',
  },
  deleting: {
    label: 'Deleting',
    explain: 'The relay is being deleted; no new operation is accepted.',
  },
  busy: {
    label: 'Relay busy',
    explain: 'Another rotation is already running on this relay.',
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
    explain: 'The relay rotated recently and is inside its cooldown window.',
    fix: 'Wait for the cooldown, or force the rotation.',
  },
  daily_cap: {
    label: 'Daily cap reached',
    explain: 'The relay has already rotated as often as allowed today.',
    fix: 'Wait for the next UTC day, or raise the cap.',
  },
  listener_not_found: {
    label: 'Listener not found',
    explain: 'The listener key does not exist on this relay.',
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
    explain: 'The relay already replaced a same-provider CDN front as often as allowed today.',
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
    explain: 'No listener on the relay can be fronted by any layer.',
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
    fix: 'Register the listener origin transport with the node role.',
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
    explain: 'A rotation left the panel Hosts uncertain; the relay is frozen until you resolve it.',
    fix: 'Inspect the live Hosts and keep the previous or the current binding.',
  },
  needs_operator: {
    label: 'Needs an operator',
    explain: 'An edge ended in a state the machine cannot resolve on its own.',
    fix: 'Destroy, forget or reactivate the edge.',
  },
  host_unresolved: {
    label: 'Host unresolved',
    explain: 'A panel Host operation had an uncertain outcome and blocks further Host writes.',
    fix: 'Look at the listener Host and adopt or release the panel object.',
  },
  rotation_failed: {
    label: 'Rotation failed',
    explain: 'The last rotation on this relay ended in failure.',
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
  edge_unreachable: {
    label: 'Edge unreachable',
    explain: 'Probes cannot reach a published edge from at least one country.',
  },
  pool_below_desired: {
    label: 'Pool below desired',
    explain: 'Fewer edges are published than the relay wants.',
    fix: 'Provision or publish an edge.',
  },
  go_live_pending: {
    label: 'Go-live pending',
    explain:
      'An edge is published for this relay but its delivery binding is still deferred, so members keep the direct address.',
    fix: 'Finish the guided setup to go live.',
  },
  pool_rebalance: {
    label: 'Make room for a listener',
    explain:
      'A deployed listener has no published edge, every pool slot is taken and the pool is at its cap.',
    fix: 'Rebalance: one duplicate edge goes back to standby so the listener can be published.',
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
  drift: {
    label: 'Drift',
    explain: 'What the provider reports differs from what FCP recorded for an edge.',
    fix: 'Open the edge and compare the live snapshot.',
  },
  direct_host_reappeared: {
    label: 'Direct address back in the panel',
    explain:
      'A panel Host that hands out the node address itself was re-enabled or added on a protected node, so members on it are refused a body until it is hidden again.',
    fix: 'Hide it in the panel, or add it to the protected node so FCP hides it for you.',
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
    fix: 'Let the inbound accept any Host header, or add the edge names to the certificate.',
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
    label: 'Relay missing',
    explain: 'A delivery binding still covers this origin but its relay row is gone.',
    fix: 'Release the binding under Settings, or register the relay again.',
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
    explain: 'No entry in the panel body matched the listener match rule.',
    fix: 'Check the Host remark or the address match rule.',
  },
  ambiguous_match: {
    label: 'Ambiguous match',
    explain: 'More than one entry in the panel body matched the listener.',
    fix: 'Tighten the match rule or remove the duplicate Host.',
  },
  leak_detected: {
    label: 'Origin leak detected',
    explain: 'An outgoing entry still carried the origin address; the body was withheld.',
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
  no_load_signal: {
    label: 'No load signal',
    explain: 'This origin kind reports no user load, so the detector uses reports and probes only.',
  },
  // --- published pool (reserved allocation, capacity, rebalance) -------------------------
  pool_full: {
    label: 'Pool full',
    explain: 'Every published slot of this relay is taken.',
    fix: 'Raise the published edges wanted on the relay, or unpublish an edge first.',
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
      'A relay can carry at most eight deployed, enabled listeners, one published slot each; this one would be the ninth.',
    fix: 'Retire or disable a listener you do not need, or register the listener on another relay.',
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
    explain: 'A guided setup owns this relay, so automatic replacement leaves it alone.',
    fix: 'Finish or cancel the setup run.',
  },
} as const satisfies Record<KnownCode, CodeCopy> & Record<string, CodeCopy>;

// --- discovered inbounds that cannot become listeners --------------------------------------
// Why a panel inbound found on the node was left out of the protection plan
// (`INBOUND_UNSUPPORTED_CODES`). Kept apart from the flat table above: these words are
// generic nouns, and a future status code with the same name must not inherit them.
export const INBOUND_UNSUPPORTED_COPY: Record<InboundUnsupportedCode, CodeCopy> = {
  inactive: {
    label: 'Not served by this node',
    explain: 'The inbound is in the config profile but the node does not have it active.',
    fix: 'Enable it on the node in the panel if members should use it.',
  },
  tag: {
    label: 'Tag cannot be bound',
    explain:
      'The inbound tag uses characters a panel Host cannot bind to (letters, digits and underscores only).',
    fix: 'Rename the inbound tag in the config profile.',
  },
  protocol: {
    label: 'Protocol not supported',
    explain:
      'Edges can carry VLESS, Trojan and Shadowsocks inbounds; this protocol is not one of them.',
  },
  transport: {
    label: 'Transport not supported',
    explain:
      'Edges can carry raw TCP, WebSocket, HTTP Upgrade and gRPC streams; this transport is not one of them.',
  },
  security: {
    label: 'Security layer not supported',
    explain:
      'Edges can carry REALITY, TLS and plain inbounds; this security setting is not one of them.',
  },
  invalid: {
    label: 'Inbound cannot be described',
    explain:
      'The inbound looks supported but its settings could not be turned into a listener (the detail names what).',
    fix: 'Check the port, the REALITY target and the server names in the config profile.',
  },
};

export function inboundUnsupportedCopy(code: string): CodeCopy {
  const known = (INBOUND_UNSUPPORTED_COPY as Record<string, CodeCopy>)[code];
  return (
    known ?? {
      label: humanizeCode(code),
      explain: `The inbound was skipped: ${humanizeCode(code)}.`,
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
    fix: 'Open the Listeners tab and use "Adopt a Host" on each listener that has a Host in the panel, then switch again.',
  },
  host_adopt_mismatch: {
    label: 'Host does not fit',
    explain: 'That Host does not fit this listener.',
    fix: 'Pick a Host that carries the inbound of this listener and dials one of its published edges.',
  },
  listener_in_use: {
    label: 'Listener still in use',
    explain: 'Edges still use this listener.',
    fix: 'Destroy or delete those edges first (Edges tab), then try again.',
  },
  needs_rotation: {
    label: 'Needs a rotation',
    explain:
      'Publishing this edge would make it the first edge of its listener, which means writing the panel Host.',
    fix: 'Use Publish so the rotation machine does the switch.',
  },
  origin_address_locked: {
    label: 'Origin address locked',
    explain: 'Edges still dial this origin address.',
    fix: 'Drain or destroy every edge of the relay before changing it.',
  },
  match_rule_overlap: {
    label: 'Match rules overlap',
    explain: 'Another listener of this relay would match the same subscription entries.',
    fix: 'Give each listener its own match rule.',
  },
  node_already_bound: {
    label: 'Node already covered',
    explain: 'Another relay already covers this node.',
  },
  server_already_bound: {
    label: 'Backend server already covered',
    explain: 'Another relay already covers this backend server.',
  },
  throttled: {
    label: 'Asked too often',
    explain: 'That was asked too often. This call reaches a panel or a provider, so it is limited.',
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
      'The inbounds on this node are not the ones the earlier setup created listeners for, so the run cannot resume safely.',
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
    label: 'No entry for this inbound',
    explain:
      'The test credential receives no single connection entry for this inbound, so no test link can be built from it.',
    fix: 'Check that the node has exactly one enabled panel Host on this inbound at its own address and port.',
  },
  test_link_render_failed: {
    label: 'Test link not rendered',
    explain: 'The candidate address could not be rendered into a connection for this inbound.',
    fix: 'Check the listener names and the address, then fetch the test link again.',
  },
  use_manual_setup: {
    label: 'Use manual setup',
    explain: 'Outline servers with no members have no test credential path.',
    fix: 'Use the manual setup for this server, or rehearse once it has members.',
  },
  choose_mode: {
    label: 'Choose a connection mode',
    explain: 'The node has no usable placement to mint the test credential on.',
    fix: 'Choose the connection mode whose placement covers this node.',
  },
  credential_unresolved: {
    label: 'Credential still settling',
    explain:
      'An earlier attempt to create the test credential may still land on the panel; FCP waits before creating another.',
    fix: 'Try again in a couple of minutes.',
  },
  node_unknown: {
    label: 'Node not in inventory',
    explain: 'The panel inventory has no node with this identifier.',
    fix: 'Refresh the node list, then try again.',
  },
  node_address_unknown: {
    label: 'Node address unknown',
    explain: 'The panel reports no address for this node, so its origin cannot be probed.',
    fix: 'Set the node address on the panel, then refresh the node list.',
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
const TERMINAL_PHASES = new Set(['done', 'failed', 'rolled_back', 'quarantined', 'cancelled']);

export const phaseLabel = (phase: string): string =>
  ROTATION_PHASE_LABELS[phase] ?? humanizeCode(phase);
export const isTerminalPhase = (phase: string): boolean => TERMINAL_PHASES.has(phase);
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
  standby: 'Standby',
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
    case 'standby':
      return 'info';
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
  relay: 'Relay and listeners',
  edge: 'First edge',
  qualification: 'Qualification',
  publish: 'Publish',
  rendering: 'Rendering',
  automation: 'Automation',
};
export const SETUP_STEP_HINTS: Record<SetupStepId, string> = {
  origin: 'What the edges dial: a panel node, a backend server or an address.',
  account: 'A cloud or CDN account with tested credentials.',
  template: 'The provisioning parameters the account uses.',
  relay: 'The relay row and at least one deployed listener.',
  edge: 'One provisioned or imported edge.',
  qualification: 'Proof the account (and a CDN front) carries traffic end to end.',
  publish: 'At least one edge in the published pool.',
  rendering: 'Members receive rewritten subscriptions.',
  automation: 'Probes and the detector watch the relay.',
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

export const ATTENTION_ACTION_LABELS: Record<AttentionAction, string> = {
  resolve_quarantine: 'Resolve quarantine',
  resolve_operator: 'Resolve edge',
  look_at_host: 'Look at Host',
  open_setup: 'Resume setup',
  open_relay: 'Open relay',
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
};

export function severityTone(s: AttentionSeverity): Tone {
  if (s === 'critical') return 'danger';
  if (s === 'warning') return 'warning';
  return 'info';
}
export const attentionSeverityTone = severityTone;

// --- guided setup runs (Autopilot) -------------------------------------------------------------

/** The four plain stages the progress view shows, mapped from the machine's ten. */
export const SETUP_RUN_STAGE_LABELS: Record<SetupRunStage, string> = {
  prepare: 'Creating the address',
  credential: 'Creating the address',
  provision: 'Creating the address',
  verify: 'Checking from outside',
  try_it: 'Checking it works',
  publish: 'Going live',
  hide_direct_hosts: 'Going live',
  rehearse: 'Going live',
  go_live: 'Going live',
  done: 'Live',
};

export const SETUP_RUN_STATE_LABELS: Record<SetupRunState, string> = {
  running: 'Working',
  waiting: 'Waiting',
  needs_you: 'Needs you',
  done: 'Live',
  done_unbound: 'Finished without going live',
  failed: 'Stopped',
  cancelled: 'Cancelled',
};

export function setupRunStateTone(s: SetupRunState): Tone {
  if (s === 'done') return 'success';
  if (s === 'needs_you') return 'warning';
  if (s === 'failed') return 'danger';
  if (s === 'cancelled' || s === 'done_unbound') return 'muted';
  return 'info';
}

/** One card per interruption: `explain` is the sentence, `fix` the button (secondary in parentheses). */
export const SETUP_RUN_NEED_COPY: Record<SetupRunNeed, CodeCopy> = {
  account_untested: {
    label: 'Account not tested',
    explain: 'The provider account has not passed a credential test yet.',
    fix: 'Test again (Choose another account).',
  },
  account_incompatible: {
    label: 'Account cannot front this node',
    explain: 'The provider account cannot carry every inbound this node serves.',
    fix: 'Choose another account.',
  },
  maintenance: {
    label: 'New work is paused',
    explain: 'Edges are in maintenance, so the run cannot start new work.',
    fix: 'Resume new work.',
  },
  too_many_inbounds: {
    label: 'Too many inbounds',
    explain: 'The node serves more frontable inbounds than a guided run protects.',
    fix: 'Use manual setup.',
  },
  use_manual_setup: {
    label: 'Manual setup needed',
    explain: 'Outline servers with no members are outside the guided setup.',
    fix: 'Use manual setup.',
  },
  choose_mode: {
    label: 'Connection mode needed',
    explain: 'The test account needs a connection mode with a placement on this panel.',
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
  coverage_incomplete: {
    label: 'Not every inbound covered',
    explain: 'The published pool had no room for one of the listeners.',
    fix: 'Try again.',
  },
  try_it: {
    label: 'Try each address',
    explain:
      'Import each test link into a client (it uses a test account of its own), connect, load a page, then tick Works.',
    fix: 'Continue (One of them does not work).',
  },
  review_changed: {
    label: 'Hosts changed',
    explain: 'The panel now has unsupported Hosts the review did not show.',
    fix: 'Review the change.',
  },
  hide_failed: {
    label: 'Could not hide a Host',
    explain: 'The panel refused to hide one of the old direct Hosts.',
    fix: 'Check again (Hide them in the panel yourself).',
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
  quarantined: {
    label: 'Paused for safety',
    explain: 'A rotation could not converge and paused the relay.',
    fix: 'Review.',
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
    label: 'Cannot carry every inbound',
    explain: 'The account fronts at a layer one of the inbounds cannot use.',
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
  'relay.create': 'Relay created',
  'relay.registered': 'Relay registered by the node role',
  'relay.upsert': 'Relay registered',
  'relay.update': 'Relay settings changed',
  'relay.delete': 'Relay deleted',
  'relay.delivery.released': 'Delivery binding released',
  'relay.listener.upsert': 'Listener registered',
  'relay.listener.update': 'Listener changed',
  'relay.listener.retire': 'Listener retired',
  'relay.listener.name.retire': 'Server name retired',
  'relay.listener.name.reactivate': 'Server name reactivated',
  'relay.host.created': 'Panel Host created',
  'relay.host.deleted': 'Panel Host deleted',
  'relay.host.adopted': 'Panel Host adopted',
  'relay.host.adopt_requested': 'Host adoption requested',
  'relay.host.released': 'Panel Host released',
  'relay.qualification_credential': 'Qualification credential changed',
  'edge.published': 'Edge published',
  'edge.unpublished': 'Edge unpublished',
  'edge.rotated': 'Edge replaced',
  'edge.burned': 'Edge burned',
  'edge.rolled_back': 'Rotation rolled back',
  'edge.rotation_failed': 'Rotation failed',
  'edge.quarantined': 'Relay quarantined',
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
