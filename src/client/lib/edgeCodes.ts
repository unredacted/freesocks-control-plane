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
 *   EDGE_HEALTH_LABELS, healthTone  the PROVIDER's own check of the node behind an edge
 *   outsideReachOf, OUTSIDE_REACH_LABELS, outsideReachTone   reachability from outside (probes)
 *   PUBLICATION_LABELS, publicationTone
 *   failedRunLabel(facts, plain), providerAnswerWords(facts)   a failed run by its kind, the provider's words
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
  FreedomWithheldReason,
  InboundUnsupportedCode,
  L7CertificateCode,
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
  ClientCheckEngine,
  ClientCheckSessionCode,
  ClientCheckUncheckedCode,
  ClientCheckVerdict,
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
  /**
   * Refusals only: the server's message names the specific reason (which
   * state of a zone, which DNS account check), so an error line shows it in
   * place of `fix` (lib/edgeErrors.ts); `fix` stays the fallback.
   */
  reasonFromServer?: boolean;
}

type KnownCode =
  | SetupBlockerCode
  | PreflightBlockerCode
  | PreflightWarningCode
  | AttentionKind
  | LayerExclusionCode
  | DeliveryUnavailableCode
  | PoolCode
  | SettingsWarningCode
  | L7CertificateCode
  | FreedomWithheldReason;

const COPY = {
  // --- origin --------------------------------------------------------------------------
  no_origin: {
    label: 'No origin chosen',
    explain: 'The origin has no target, so FCP does not know what the edges should dial.',
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
    explain: 'This backend type has no Hosts for FCP to flip.',
    fix: 'Nothing to change. Members follow rotations through their subscriptions.',
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
  // credential test answers (an adapter's short codes)
  token_rejected: {
    label: 'Token rejected',
    explain:
      'The provider rejected this token. Cloudflare rejected it as both a user and an account API token. Gandi rejected it as a personal access token, or it lacks DNS permissions.',
    fix: 'Check that the token is active, not expired, and has the permissions the account form lists. Cloudflare takes user and account API tokens. Gandi takes personal access tokens only.',
  },
  token_not_active: {
    label: 'Token not active',
    explain: 'The provider knows this token, but it is disabled or expired.',
    fix: 'Enable the token or roll a new one in the provider dashboard, then test again.',
  },
  name_zone_unreachable: {
    label: 'Zone not reachable',
    explain: "The DNS account that holds this hostname's zone is gone or has no token.",
    fix: 'Restore the DNS account, or remove the records by hand and press Dismiss.',
  },
  name_taken: {
    label: 'Hostname already taken',
    explain: 'A record FCP did not write sits at this hostname, so FCP leaves it alone.',
    fix: 'Remove that record if it is stray, or give the address a new hostname.',
  },
  name_dns_refused: {
    label: 'DNS provider refused',
    explain:
      'The DNS provider refused to change the records, usually because the token cannot edit the zone.',
    fix: 'Give the DNS account a token that can edit this zone. FCP retries by itself.',
  },
  name_dns_rate_limited: {
    label: 'DNS provider busy',
    explain: 'The DNS provider asked FCP to slow down.',
    fix: 'Nothing to do. FCP retries on its next pass.',
  },
  name_dns_unreachable: {
    label: 'DNS provider did not answer',
    explain: 'The call to the DNS provider timed out or failed.',
    fix: 'FCP retries on its next pass. Look into it only if it lasts.',
  },
  dns_account_missing: {
    label: 'DNS account missing',
    explain:
      'This CDN front needs a DNS account for its records, and its location names none that still exists.',
    fix: 'On the provider page, add a location that names a DNS account.',
  },
  no_zones: {
    label: 'No DNS zone reached',
    explain: 'The token reaches no DNS zone.',
    fix: 'Give the token access to at least one zone, then test again.',
  },
  zone_mode_unknown: {
    label: 'Zone mode unknown',
    explain: "FCP has not read the zone's TLS mode and WebSocket setting yet.",
    fix: 'Check the location again on the provider page.',
  },
  zone_websockets_off: {
    label: 'Zone has WebSockets off',
    explain: 'The CDN zone refuses WebSocket upgrades, so it cannot front a WebSocket listener.',
    fix: 'Turn WebSockets on for the zone at the provider, then test the account again.',
  },
  // a CDN location's zone check (what the provider said about the zone)
  zone_unreadable: {
    label: 'Zone unreadable',
    explain: 'The key cannot read that zone.',
    fix: 'Give the key read access to the zone, then check the location again.',
  },
  zone_name_mismatch: {
    label: 'Zone name changed',
    explain: "The zone's name changed at the provider.",
    fix: 'Refresh the list of zones and pick it again.',
  },
  zone_ssl_off: {
    label: 'Zone encryption off',
    explain: "The zone's encryption mode is off, so a front there cannot serve HTTPS.",
    fix: 'Set Flexible, Full or Full (strict) on the zone at the provider, then check the location again.',
  },
  header_rule_forbidden: {
    label: 'Header rule refused',
    explain:
      "Cloudflare refused the Transform Rule that strips the member's address. Either the token cannot edit Transform Rules or the zone has no rules left.",
    fix: 'Grant the token "Transform Rules: Edit" on the zone or free a rule, then delete this front and build it again.',
  },
  zone_paused: {
    label: 'Zone paused',
    explain: 'The zone is paused at the provider.',
    fix: 'Resume the zone at the provider, then check the location again.',
  },
  zone_not_active: {
    label: 'Zone not active yet',
    explain:
      "The zone is not active at the provider yet, so records written there are never served. For Gandi, the domain's name servers must be Gandi LiveDNS.",
    fix: "Finish setting up the zone at the provider, then check the location again. For Gandi, point the domain's name servers at LiveDNS.",
  },
  zone_flattens_cnames: {
    label: 'Zone flattens every CNAME',
    explain:
      "The zone flattens every CNAME, so the certificate authority never sees the validation record the front's certificate needs.",
    fix: 'At the DNS provider, set CNAME flattening to the zone apex only, then check the location again.',
  },
  tls_configuration_missing: {
    label: 'TLS configuration not found',
    explain: 'The Fastly key does not see that TLS configuration.',
    fix: 'Pick one the key can see, or leave it empty for the default.',
  },
  location_check_failed: {
    label: 'Location check refused',
    explain: "This location's last check refused it, so no new address is planned there.",
    fix: 'Check it again from the provider page.',
  },
  // --- template ------------------------------------------------------------------------
  no_default_template: {
    label: 'No default template',
    explain: 'The account has no default edge template, so provisioning has no parameters.',
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
    explain: 'The origin has not been registered yet.',
    fix: 'Finish the origin step, or front the node from Edges.',
  },
  relay_deleting: {
    label: 'Origin is deleting',
    explain: 'The origin is being deleted, so new work on it is refused.',
  },
  relay_without_listener: {
    label: 'No listener',
    explain: 'The origin has no listener, so edges have no port or protocol to carry.',
    fix: 'Add a listener, or front the node from Edges.',
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
    label: 'SNIs missing',
    explain: 'A listener that presents an SNI needs at least one active SNI.',
    fix: 'Add SNIs to the listener.',
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
  reality_refuses_clients: {
    label: 'REALITY refuses sing-box or Mihomo',
    explain:
      'A REALITY transport here refuses sing-box or Mihomo clients, while Xray clients get through.',
    fix: 'Make the change each reason names. The warning clears within a few minutes.',
  },
  client_refused: {
    label: 'A client cannot get through',
    explain:
      "FCP's check with real sing-box and Xray clients could not get one of them through an address in use.",
    fix: 'If the same client fails through every address, fix the transport, such as its REALITY minClientVer. Otherwise replace the address and check again.',
  },
  // The verdicts an attention row names as its reason (`client_refused`): the
  // same words as CLIENT_CHECK_COPY, which the check's own line and toast use.
  passed_with_refusals: {
    label: 'Works like the others',
    explain:
      'At least one client connected, and the ones that did not are refused through the other addresses too.',
  },
  address_failed: {
    label: 'Does not work',
    explain:
      "A client did not get through this address, though it gets through the transport's other addresses where there are any.",
  },
  egress_mismatch: {
    label: 'Reaches another node',
    explain:
      'A client connected, but its traffic left from another node, so the load balancer forwards somewhere else.',
  },
  node_unreachable: {
    label: 'Node not reached',
    explain: 'No client got through this address or through the other addresses of the transport.',
  },
  client_check_unavailable: {
    label: 'Check client not answering',
    explain:
      'The client-check service did not answer its last health check, so no address can be checked with a real client.',
    fix: 'Make sure the edge-client-check container is running with the same EDGE_CLIENT_CHECK_SECRET as the deployment.',
  },
  // Each reason (a setup-status warning's detail; the attention row words the verdict itself).
  reality_min_above: {
    label: 'Its minClientVer is too high',
    explain:
      "The transport's minClientVer is above what sing-box (1.8.1) or Mihomo (1.8.2) sends, so the server refuses them.",
    fix: 'Set "minClientVer" to "1.8.1" in the transport\'s realitySettings in the backend.',
  },
  reality_core_default: {
    label: 'No minClientVer set',
    explain:
      'With no minClientVer, Xray 26.7.11 to 26.7.28 let in only Xray clients from 26.3.27 on, so sing-box and Mihomo are refused.',
    fix: 'Add "minClientVer": "1.8.1" to the transport\'s realitySettings in the backend.',
  },
  reality_max_below: {
    label: 'Its maxClientVer is too low',
    explain:
      "The transport's maxClientVer is below what Mihomo (1.8.2) or sing-box (1.8.1) sends, so the server refuses them.",
    fix: 'Remove "maxClientVer" from the transport\'s realitySettings in the backend, or raise it to 1.8.2 or above.',
  },
  reality_core_key_share: {
    label: 'sing-box lacks a key share',
    explain:
      'From Xray 26.9.8 on, REALITY refuses a Client Hello without an X25519MLKEM768 key share, which sing-box never sends, whatever the transport sets.',
    fix: 'Run the node on Xray 26.7.28 or earlier with "minClientVer": "1.8.1", or give sing-box members another node.',
  },
  reality_core_unknown: {
    label: 'Node Xray version unknown',
    explain:
      "FCP could not read the node's Xray version, so it cannot tell whether sing-box and Mihomo get in.",
    fix: 'Check the node\'s Xray version in the backend, and set "minClientVer": "1.8.1" in the transport\'s realitySettings if it has none.',
  },
  members_dark: {
    label: 'Members get nothing',
    explain: 'Members of this origin need an edge, and none can be served yet.',
    fix: 'Publish an edge and turn rendering on.',
  },
  binding_deferred: {
    label: 'Go-live pending',
    explain: 'This origin has not gone live, so members still get the direct address.',
    fix: 'Finish the guided setup to go live.',
  },
  // --- first edge ----------------------------------------------------------------------
  no_edge: {
    label: 'No edge yet',
    explain: 'The origin has no edge, so nothing fronts it.',
    fix: 'Provision or import an edge.',
  },
  rotation_running: {
    label: 'Rotation running',
    explain: 'A rotation is running on this origin. Wait for it to finish.',
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
    explain: 'A rotation left the backend Hosts in an unknown state, so the origin is frozen.',
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
    explain: 'The origin is switched off, so its members get an unavailable response.',
    fix: 'Enable the origin.',
  },
  no_family_carries: {
    label: 'No app carries this node',
    explain:
      'No app FCP serves can carry a live listener of this node, so no sample subscription was checked.',
    fix: 'Check that the node has a deployed, enabled listener.',
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
    explain: 'Reachability probes are off, so the detector sees only reports and load.',
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
    fix: 'Turn it on for a country under Servers, Countries: open the country, then Checks from here.',
  },
  edge_layer_disabled: {
    label: 'Edges switched off',
    explain: 'The edges master switch is off, so the detector and the reconcile cron do nothing.',
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
    explain:
      'The maintenance switch is on, so no new edge job starts. Jobs already running finish.',
    fix: 'Thaw under Settings when the maintenance is over.',
  },
  not_found: {
    label: 'Not found',
    explain: 'The origin, edge or rotation named by the request does not exist.',
  },
  deleting: {
    label: 'Deleting',
    explain: 'The origin is being deleted, so no new operation is accepted.',
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
    explain: "Servers is updating this origin's node and holds its listeners until it finishes.",
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
    label: 'No active SNI',
    explain: 'Every SNI of this listener is retired.',
    fix: 'Reactivate or add an SNI.',
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
    label: 'Provider check failing',
    explain:
      "The provider's own check of the node behind this address is failing or partly failing.",
  },
  unverified_endpoint: {
    label: 'Address not yet tested',
    explain:
      'An address goes live only once you test its current configuration with a real session.',
    fix: 'Import the test link into a client, connect, then mark the address as working.',
  },
  no_verified_spare: {
    label: 'No tested spare',
    explain:
      "Replacing this address needs a spare you have tested, unless FCP's own client check is on and can make and check one.",
    fix: "Create and test a spare, or turn on FCP's client check in Edges settings.",
  },
  no_assigned_location: {
    label: 'No location for it',
    explain:
      "FCP makes and checks a replacement itself only in this node's locations, and none can take this one. Each is switched off, untrusted by hand, full or at its spending cap.",
    fix: 'Add a location to this node, or free one up, then replace.',
  },
  // The code an older build stored for the same refusal (`relays.suspicion.lastRotateError`
  // keeps it until another rotation overwrites it): the same words.
  no_ticked_location: {
    label: 'No location for it',
    explain:
      "FCP makes and checks a replacement itself only in this node's locations, and none can take this one. Each is switched off, untrusted by hand, full or at its spending cap.",
    fix: 'Add a location to this node, or free one up, then replace.',
  },
  replacement_reblocked: {
    label: 'Replacement blocked again',
    explain:
      'This replacement looked blocked again soon after going into use, so FCP stopped replacing it. A member may have leaked it, or the network now blocks this whole provider.',
    fix: 'Check whether other sites on this provider fail from that country too. If they do, a new address will not help; if not, check who receives this transport. Then resume automatic replacement on the node page.',
  },
  fresh_name_blocked: {
    label: 'New hostname blocked before use',
    explain:
      'A new hostname on this CDN was blocked in a country before anyone got it, so the network there blocks the whole CDN. FCP pauses automatic replacement for that country, keeps the address in use, and tries one new hostname when the pause ends.',
    fix: 'Nothing to replace. Members in that country need another way in, such as a load balancer address or another mode.',
  },
  cdn_refused: {
    label: 'CDN refused in a country',
    explain:
      "This CDN's reference site fails from that country but works elsewhere, so the network there blocks the whole CDN. FCP keeps the address in use until the reference site gets through.",
    fix: 'Nothing to replace. Members in that country need another way in, such as a load balancer address or another mode.',
  },
  // --- FCP's own client check in a replacement (rotation events and outcomes) ---------------
  client_check: {
    label: "FCP's client check",
    explain: 'FCP checked the new address with its own sing-box and Xray clients.',
  },
  client_check_failed: {
    label: "Failed FCP's client check",
    explain:
      "FCP's clients did not get through the new address as they do through the one in use, so it was removed unused. The next automatic try waits an hour.",
    fix: 'Check the node and the provider location, or replace by hand.',
  },
  client_check_unconfirmed: {
    label: 'Checked but not confirmed',
    explain:
      "FCP's clients got through, but the check cannot replace your test. The location is no longer one of this node's locations or you untrusted it, or the client check is off.",
    fix: 'Test the address yourself, then put it in use.',
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
  locations_refused: {
    label: 'Locations refused recently',
    explain:
      'Every location that could take this refused to create an address for this node in the last few hours, so automatic work waits.',
    fix: 'Fix the quota or setting the provider named and add an address there by hand, or add another location.',
  },
  // A rotation event: the run's create was refused for good, so the node's automatic work keeps out of the location.
  location_held: {
    label: 'Location held',
    explain:
      "The provider refused this create for good, so this node's automatic work skips the location for 6 hours.",
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
  dns_account_not_fronting: {
    label: 'DNS account, not a front',
    explain:
      'This is a DNS-only account. It holds the records for L7 fronts and carries no member traffic.',
    fix: 'Pick an edge provider account, or set this account to DNS and fronting on its page.',
  },
  template_not_found: {
    label: 'Template not found',
    explain: 'The named template does not exist.',
  },
  // --- preflight: plan phase ------------------------------------------------------------
  dns_account_disabled: {
    label: 'DNS account disabled',
    explain: 'The DNS account this front writes its records through is switched off.',
    fix: 'Switch the DNS account on from its provider page.',
  },
  dns_zone_missing: {
    label: 'DNS zone missing',
    explain: 'This location names no DNS zone.',
    fix: 'Add a location in one of the zones the account reaches.',
  },
  origin_transport_missing: {
    label: 'Origin transport missing',
    explain: 'The listener does not declare how a CDN front should dial the origin.',
    fix: 'Edit the listener and turn on "A CDN front can reach this transport", or front the node from Edges.',
  },
  origin_cert_not_public: {
    label: 'Origin certificate not public',
    explain:
      'A front that dials the origin over TLS needs a publicly trusted certificate on the origin.',
    fix: 'Give the origin a publicly trusted certificate, or let the front dial it over plain HTTP.',
  },
  origin_cert_name_uncovered: {
    label: 'Origin hostname not on certificate',
    explain:
      'Over TLS the front dials the origin by a hostname its certificate must cover, never by IP address.',
    fix: 'Address the origin by a hostname on its certificate, or add the hostname to the certificate.',
  },
  origin_port_unsupported: {
    label: 'Origin port not supported',
    explain:
      'This front cannot dial the origin on that port. Fastly dials only 443 over TLS or 80 over plain HTTP, CloudFront 80, 443 or 1024 and up.',
    fix: 'Move the origin listener to a port this front dials.',
  },
  origin_not_a_name: {
    label: 'Origin is an IP address',
    explain: 'A CloudFront front dials its origin by hostname, never by IP address.',
    fix: 'Give the node a hostname, the one on its certificate for TLS, and register the origin by it.',
  },
  retest_required: {
    label: 'Test again',
    explain: 'A certificate setting of this account changed since the last test.',
    fix: 'Test the account again.',
  },
  // --- an L7 front's certificate (L7_CERTIFICATE_CODES) ---------------------------------
  caa_forbids_ca: {
    label: 'CAA forbids the CA',
    explain: "The zone's CAA records do not allow the account's certificate authority to issue.",
    fix: "Allow the authority under issue, or issuewild for the shared wildcard, then test again. Certainly is certainly.com, Let's Encrypt letsencrypt.org, GlobalSign globalsign.com, and a Cloudflare zone uses letsencrypt.org, pki.goog or ssl.com.",
  },
  edge_certificate_missing: {
    label: 'No edge certificate',
    explain:
      'The zone has no certificate for its first-level subdomains, so a front there cannot serve HTTPS.',
    fix: 'Turn on Universal SSL for the zone at the provider, or order a wildcard certificate, then check the location again.',
  },
  edge_certificate_pending: {
    label: 'Edge certificate on its way',
    explain: "The zone's certificate for its first-level subdomains is still being issued.",
    fix: 'Nothing to do. The front carries on once it is issued.',
  },
  domain_not_activated: {
    label: 'Hostname not activated yet',
    explain:
      'The certificate is issued, but the provider has not activated it for the front\'s hostname, so it answers "unknown domain".',
    fix: 'Usually nothing, as the front carries on once it is activated. If it times out, replace the front.',
  },
  tls_caa_conflict: {
    label: 'Certificate blocked by CAA',
    explain: "The zone's CAA records stop the provider's certificate authority from issuing.",
    fix: "Allow the account's authority (certainly.com, letsencrypt.org or globalsign.com) in the zone's CAA records. Issuance resumes by itself.",
  },
  tls_challenge_conflict: {
    label: 'Validation record conflict',
    explain:
      'Other records sit at the validation hostname, so the provider cannot validate the certificate.',
    fix: 'Remove the other records at that hostname. Issuance resumes by itself.',
  },
  tls_challenge_missing: {
    label: 'Validation record missing',
    explain: "The certificate's DNS validation record is missing or wrong.",
    fix: 'Check the validation record in the DNS zone, or replace the front so FCP writes it again.',
  },
  tls_authorization_failed: {
    label: 'Hostname validation failed',
    explain: "The provider could not validate the certificate's hostname.",
    fix: 'Check the zone’s CAA records and the validation record, then replace the front.',
  },
  tls_authorization_warning: {
    label: 'Certificate warning',
    explain: 'The provider reports a certificate validation problem FCP does not recognise.',
    fix: 'Open the certificate at the provider to read the warning.',
  },
  tls_failed: {
    label: 'Certificate failed',
    explain: 'The provider gave up issuing the certificate.',
    fix: 'Fix what it waited on, then retry the certificate at the provider or replace the front.',
  },
  certificate_expiring: {
    label: 'Certificate renewal late',
    explain:
      "The account's shared wildcard certificate expires within a week, or already has, and was not renewed.",
    fix: 'Fix what the account page says it waits on, such as a CAA or validation record. The provider then renews it.',
  },
  shared_certificate_ambiguous: {
    label: 'Wildcard not reusable',
    explain:
      "Another certificate this account would not order already covers the zone's wildcard, so a new front cannot share it.",
    fix: "Remove that certificate at the provider, match the account's settings to it, or switch to one certificate per front.",
  },
  shared_certificate_failed: {
    label: 'Shared certificate failed',
    explain:
      "The account's shared wildcard certificate failed to issue, so a new front cannot get one.",
    fix: 'Fix what the account page says it waited on and retry at the provider, or switch to one certificate per front.',
  },
  // --- preflight warnings ---------------------------------------------------------------
  edge_disabled: {
    label: 'Edges switched off',
    explain: 'The master switch is off, so this runs but nothing automatic follows.',
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
    explain: 'CDN auto-select is off, so this front is never picked automatically.',
  },
  // --- attention kinds ------------------------------------------------------------------
  quarantine: {
    label: 'Quarantine',
    explain:
      'A rotation left the backend Hosts in an unknown state, so the origin is frozen until you resolve it.',
    fix: 'Inspect the live Hosts and keep the previous or the current binding.',
  },
  needs_operator: {
    label: 'Address stuck',
    explain: 'An edge ended in a state FCP cannot resolve on its own.',
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
      'A test block is running, and the detector may really replace the address it treats as blocked.',
    fix: 'End the test on the origin page when you are done.',
  },
  edge_unreachable: {
    label: 'Edge unreachable',
    explain: 'Probes cannot reach a published edge from at least one country.',
  },
  probe_source_failing: {
    label: 'A probe source is failing',
    explain:
      'A reachability source has returned nothing for hours, so countries only it covers read as not known.',
    fix: 'Check its credential and budget in Edges settings, Probes.',
  },
  country_wide_failure: {
    label: 'Failing from a whole country',
    explain:
      'Most addresses checked from this country failed at once, which points at an outage or a probe problem, so FCP reads them as not known.',
    fix: 'Look at the probe sources on the Probes page, then check again later.',
  },
  new_edge_blocked_in: {
    label: 'Spare blocked in a country',
    explain:
      'A spare that was never in use is blocked from a censored country but works from elsewhere.',
    fix: 'Replace the spare, or mark the country if you know better.',
  },
  certificate_waiting: {
    label: 'Certificate waiting',
    explain:
      "A front's certificate waits on a change outside FCP, such as a CAA or validation record in the DNS zone.",
    fix: 'Open it to see what the certificate waits on.',
  },
  setup_run_failed: {
    label: 'Setup stopped',
    explain: 'The guided setup for this node stopped before it finished. Its run says why.',
    fix: 'Open the run and try again, or remove fronting to start over.',
  },
  pool_below_desired: {
    label: 'Pool below desired',
    explain: 'Fewer edges are published than the origin wants.',
    fix: 'Provision or publish an edge.',
  },
  go_live_pending: {
    label: 'Go-live pending',
    explain:
      'An edge is published but this origin has not gone live, so members keep the direct address.',
    fix: 'Finish the guided setup to go live.',
  },
  pool_rebalance: {
    label: 'Make room in the pool',
    explain:
      'A transport or provider of this node has no published address, and the pool is full at its cap.',
    fix: 'Rebalance to send one redundant address back to standby and publish the missing one.',
  },
  pick_cooling: {
    label: 'A location is cooling',
    explain:
      'An address in this location was just blocked here, so automatic work leaves the location alone for a while.',
  },
  reduced_resilience: {
    label: 'No backup elsewhere',
    explain:
      'Members on these transports have no backup at another provider, because every location carrying them is at one provider.',
    fix: 'Add a location of another provider to this node.',
  },
  needs_test: {
    label: 'Blocked, spare untested',
    explain:
      "This node's address looks blocked. Automatic replacement has no tested spare, and FCP's client check cannot make one because it is off or not answering, or no location of this node can take one.",
    fix: "Turn on FCP's client check and add a location to this node, or test the spare with a real session, then replace.",
  },
  auto_replace_held: {
    label: 'Automatic replacement held',
    explain:
      'A replacement was blocked again soon after going into use, so FCP stopped replacing this transport. A member may have leaked it, or the network now blocks this whole provider.',
    fix: 'Check whether other sites on this provider fail from that country too. If they do, leave it held, since a new address will not help. If not, check who receives this transport, then resume automatic replacement on the node page.',
  },
  meant_for_blocked: {
    label: 'Location blocked for its country',
    explain:
      'This location is set for a country, but its checks show it blocked there, so members there get other addresses until it works again.',
    fix: 'Pick another location for that country on the account page, or mark this one if the checks are wrong.',
  },
  audience_only_left: {
    label: 'Only contained addresses left',
    explain:
      'Every address this transport has in use is limited to some countries, so members elsewhere or with no country get none.',
    fix: 'Put an address for everyone in use on this transport, in a location not limited to some countries.',
  },
  audience_idle: {
    label: 'Contained addresses unused',
    explain:
      'This node has country-only addresses in use, but ordering by country is off, so nobody gets them.',
    fix: 'Turn ordering by country back on under Settings, or switch those locations back to everyone.',
  },
  audience_pool_down: {
    label: 'Country on shared addresses',
    explain:
      "This country's own addresses for this transport on this node are all blocked there or cannot be handed out. Its members get shared addresses until one of theirs works, and their reports still never replace a shared address.",
    fix: "Replace the country's own address now or wait for tomorrow's budget, or stop the country's own addresses on this node.",
  },
  country_defaults_waiting: {
    label: 'Country defaults waiting',
    explain:
      "A country's default picks are not on this node yet. It first needs the rendezvous walk, ordering by country, room in its pool, or room for more locations (six at most). Members there keep the shared addresses meanwhile.",
    fix: 'Switch the node to the rendezvous walk on its page (members move once), turn on ordering by country, or opt the node out of that country.',
  },
  audience_stale_keys: {
    label: 'Keys not moved to own addresses',
    explain:
      "Some keys of this country on this node have not refreshed since it moved to its own addresses. They keep the shared addresses, which this country's reports no longer replace.",
    fix: 'Most move at their next refresh. Members who never refresh need to update their subscription in the app.',
  },
  location_short: {
    label: 'Location short of addresses',
    explain:
      'This location holds fewer addresses of a transport than it is set to. Upkeep publishes a spare there first, then buys one, unless something below holds it back.',
    fix: 'Clear what holds it back, add a spare address there, or lower the count on the node page.',
  },
  location_refused: {
    label: 'A location refused an address',
    explain:
      "The provider refused to create an address here over a quota or a setting, so this node's automatic work uses another location for a while.",
    fix: "Read the provider's reason on the failed run and fix the quota or setting. An address you add there by hand lifts the hold.",
  },
  open_lane_empty: {
    label: 'No open address',
    explain:
      "This node's open addresses, the ones new and suspected accounts get, are all gone, so those members get nothing until one is replaced.",
    fix: 'Wait for the next open address, add one, or raise the open addresses wanted on the node.',
  },
  audience_budget: {
    label: 'Country budget used',
    explain:
      "This country's own addresses on this node were replaced as often as today's budget allows. They never use the replacements kept for everyone's addresses.",
    fix: 'They are replaced again tomorrow (UTC). Replace one by hand, or raise the budget under Settings or on the node.',
  },
  open_lane_budget: {
    label: 'Open address budget used',
    explain:
      "Open addresses were replaced as often as today's budget allows. They never use the replacements kept for trusted addresses.",
    fix: 'They are replaced again tomorrow (UTC). Raise the budget under Settings if needed.',
  },
  lanes_need_spread: {
    label: 'Spread members first',
    explain:
      "Trusted addresses stay out of reach only if members of a blocked address scatter, so spread members over this node's addresses first.",
  },
  single_address: {
    label: 'Only one address in use',
    explain:
      'Only one address is in use where more are wanted, so a block leaves members with nothing for the 10 to 15 minutes a replacement takes.',
    fix: 'Put a second address in use. If one is enough, set Published edges wanted to 1.',
  },
  spare_untested: {
    label: 'Spare address untested',
    explain: 'A spare address exists but has not been tried with a real session yet.',
    fix: 'Test it once, and automatic replacement can then use it.',
  },
  retest_needed: {
    label: 'Retest needed',
    explain:
      'The listener or the address changed since you tested it, so the test no longer counts.',
    fix: 'Test the address again against its current configuration.',
  },
  address_name_stuck: {
    label: 'Address hostname stuck',
    explain:
      "FCP failed several times to create, move or remove a load balancer address's hostname, and one it was removing may still point at a released address.",
    fix: 'Open the address and remove its records in the DNS zone by hand if they are still there, then press Dismiss, or press New hostname.',
  },
  test_key_cleanup: {
    label: 'Test key not removed',
    explain: 'A temporary test key could not be removed from the server after several tries.',
    fix: 'Check the server, remove the key by hand if it is still there, then retry the cleanup.',
  },
  direct_host_reappeared: {
    label: 'Direct address reappeared',
    explain:
      "A backend Host handing out a fronted node's own address was re-enabled or added. Until it is hidden, members get no body or one without that entry.",
    fix: 'Hide it in the backend, or add it to the fronted node so FCP hides it for you.',
  },
  front_host_unused: {
    label: 'Old front no longer used',
    explain:
      'A backend Host on a fronted node dials a front FCP did not build, such as a hand-made load balancer. Members no longer get it, but apps not refreshed since go-live still use it.',
    fix: 'Once its traffic stops, delete the front at its provider and its Host in the backend. Members whose app stops connecting should update their subscription.',
  },
  restore_in_progress: {
    label: 'Restoring the direct address',
    explain: 'FCP is putting the direct addresses back on this node, one checked step at a time.',
    fix: 'Nothing yet. Open the node to watch it. Other changes to it wait until it finishes.',
  },
  maintenance_frozen: {
    label: 'Maintenance freeze on',
    explain:
      'No new edge job starts while the maintenance switch is on. Jobs already running finish.',
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
      'The node accepts only its own hostnames in the Host header, so the CDN hostname is refused.',
    fix: 'Let the transport accept any Host header, or add the edge hostnames to the certificate.',
  },
  origin_plaintext: {
    label: 'Origin is plaintext',
    explain:
      'The origin speaks plaintext HTTP behind the CDN, so it cannot be reached directly on L4.',
  },
  no_server_names: {
    label: 'No SNIs',
    explain: 'The listener has no SNI, so a CDN front cannot dial it over TLS.',
  },
  cert_not_public: {
    label: 'Certificate not public',
    explain: 'The origin certificate is not publicly trusted, so a CDN front cannot verify it.',
    fix: 'Use a publicly trusted certificate on the node.',
  },
  cert_name_uncovered: {
    label: 'SNI not on certificate',
    explain: 'An active SNI is not covered by the origin certificate.',
    fix: 'Add the SNI to the certificate or retire it on the listener.',
  },
  project_unresolved: {
    label: 'No project to create in',
    explain:
      "This Scaleway location has no Project id, and the API key's default project could not be read.",
    fix: 'Set the Project id on the location, or let the key read its own details in IAM and test the account again.',
  },
  size_not_multicloud: {
    label: 'Size takes Scaleway servers only',
    explain: 'This size only accepts servers hosted at Scaleway.',
    fix: "Set the location's size, or the node's own size option, to a multi-cloud one such as LB-GP-L or LB-GP-XL.",
  },
  origin_not_public: {
    label: 'Address is not public',
    explain:
      "The node's address is private, loopback or reserved, so a provider's load balancer cannot reach it.",
    fix: "Give the node's public IP address.",
  },
  origin_not_ip: {
    label: 'Address is a hostname',
    explain: 'A load balancer forwards to an IP address, never to a hostname.',
    fix: "Give the node's public IP address.",
  },
  l4_not_for_websocket: {
    label: 'No load balancer for WebSocket',
    explain:
      "A load balancer cannot front a WebSocket node, because members would send the node's own hostname, which certificate logs expose.",
    fix: 'Use a CDN.',
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
  no_entries: {
    label: 'App gets no connection',
    explain:
      "The panel served this app no connection because its format cannot carry the node's protocol, such as VLESS on an old Clash app or XHTTP on sing-box.",
    fix: 'Members need an app that supports the mode, such as a Mihomo (Clash Meta) app. Where FCP can tell, it sends the app a notice instead.',
  },
  // Counted beside the refusals: the app got the notice config in place of a connection.
  app_notice: {
    label: 'App too old: notice sent',
    explain:
      'The app cannot speak this mode, so FCP served a config whose entries tell the member to install a current app, and their account page says so for a week.',
  },
  // A preview's per-listener note: the family's format has no way to carry the listener.
  family_cannot_carry: {
    label: 'App cannot carry this listener',
    explain:
      'This app cannot speak what the listener speaks, such as XHTTP on sing-box, so the panel gives it no entry.',
    fix: 'Members on such an app need one that speaks it, such as a Mihomo (Clash Meta) app.',
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
    explain: 'An outgoing entry still carried the origin address, so the body was withheld.',
  },
  render_failed: {
    label: 'Could not rewrite',
    explain:
      'The body could not be rewritten in this format for another reason, so it was withheld.',
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
  own_pool: {
    label: 'Country on its own addresses',
    explain:
      'Every report of this block comes from countries on their own addresses on this node, so the shared address is not replaced for them.',
  },
  outside_audience: {
    label: 'Blocked only outside its countries',
    explain:
      'This address is only for some countries, and every block report comes from elsewhere, so it is not replaced.',
  },
  country_scoped: {
    label: 'Routed around by country',
    explain:
      'Members where the reports come from already get another working address, so this one is not replaced for everyone.',
  },
  // Probe evidence for an address blocked since its first check (sustained unreachability).
  never_reached: {
    label: 'Never reached from there',
    explain:
      "Checks from several networks in that country have never reached this address over hours, while the node's other addresses get through, so it counts as blocked there.",
    fix: 'Replace it, or mark the country if you know better.',
  },
  country_wide: {
    label: 'Everything fails there at once',
    explain:
      'Every address fails at once from the reporting countries, which points at an outage or a probe problem, so nothing is replaced.',
  },
  no_load_signal: {
    label: 'No load signal',
    explain: 'This origin kind reports no user load, so the detector uses reports and probes only.',
  },
  // A load balancer applies each change after the call answers (Scaleway): every step waits for it.
  lb_busy: {
    label: 'Load balancer still applying',
    explain:
      'The load balancer was still applying an earlier change, so nothing was sent yet. The step runs again once it is ready.',
  },
  lb_unusable: {
    label: 'Load balancer unusable',
    explain:
      'The load balancer is stuck in an error, lock, stopped or deleting state and will not apply anything. What was built is kept.',
    fix: "Look at the load balancer in the provider's console, then delete this address and try again.",
  },
  lb_settle_timeout: {
    label: 'Load balancer never finished',
    explain:
      'The load balancer was still applying a change 15 minutes after it was sent. What was built is kept.',
    fix: "Look at the load balancer in the provider's console, then delete this address and try again.",
  },
  // A guided run's run event: an unreachable new address was saved again at its provider once.
  reapplied: {
    label: 'Saved the address again',
    explain:
      'The new address was unreachable from outside, so FCP saved its configuration again unchanged and is checking it afresh.',
  },
  // A provider refused a create for good (a 4xx such as a validation error): retrying cannot help.
  create_refused: {
    label: 'Create refused',
    explain:
      "The provider refused to create this with FCP's settings, so a retry would fail the same way, and this node's automatic work uses another location for a while.",
    fix: "Read the provider's reason and fix the quota, location or template setting it names. Delete the address afterwards if FCP did not remove it.",
  },
  // A provider refused the arguments of an address allocation (a 400): retrying cannot help.
  ip_allocation_refused: {
    label: 'Address allocation refused',
    explain:
      'The provider refused the request for a new address, so a retry would fail the same way.',
    fix: "Check the location's Project id, and that the API key may create addresses in that project, then try again.",
  },
  // Why a node's transports have no backup at another provider (`reduced_resilience`).
  one_group: {
    label: 'One provider',
    explain: 'Every location that carries these transports is at one provider.',
    fix: "Add a location of another provider to this node: another provider's load balancer works for these transports.",
  },
  second_cdn_needed: {
    label: 'Needs a second CDN',
    explain:
      'Only a CDN can front these transports, and every location that carries them is at one CDN.',
    fix: 'Add a second CDN account, at a provider other than the one in use, and a zone of it to this node.',
  },
  version_invalid: {
    label: 'Configuration refused',
    explain:
      'The provider refused the configuration FCP generated for this front, so it never went live and a retry would fail the same way.',
    fix: "Open the front's service at the provider, where its draft version shows why, then delete the front.",
  },
  // CloudFront answers (the adapter's short codes and AWS exception names).
  alias_in_use: {
    label: 'Front hostname taken',
    explain: 'Another CloudFront distribution, in any AWS account, already serves this hostname.',
    fix: 'Delete this front and front the node again to get a new hostname.',
  },
  distribution_disabled: {
    label: 'Distribution disabled',
    explain:
      'The front’s CloudFront distribution was disabled outside FCP, so it carries no member traffic.',
    fix: 'Enable it again at the provider, or delete the front and build a new one.',
  },
  origin_request_policies_full: {
    label: 'No room in the policies',
    explain:
      'Every origin request policy FCP may use in this AWS account serves 100 distributions, and the account is at its limit of 20 policies.',
    fix: 'Delete fronts this account no longer needs, or remove custom origin request policies nothing uses.',
  },
  certificate_listing_truncated: {
    label: 'Too many certificates',
    explain:
      'The AWS account has more ACM certificates than FCP reads at once, so it cannot tell whether the zone has its wildcard and orders none.',
    fix: 'Delete certificates nothing uses in us-east-1, then try again.',
  },
  distribution_shared: {
    label: 'Distribution serves other hostnames',
    explain:
      'This CloudFront distribution serves other hostnames too, and FCP deletes what it imports.',
    fix: "Import a distribution that serves only this front's hostname.",
  },
  invalid_viewer_certificate: {
    label: 'Certificate refused',
    explain:
      "CloudFront refused the front's certificate: it is not issued yet or does not cover the front's hostname.",
    fix: 'Check the zone’s shared certificate on the account page, then try again.',
  },
  invalid_client_token_id: {
    label: 'Access key unknown',
    explain: 'AWS does not know this access key id: it was deleted, or never existed.',
    fix: 'Create an access key for the IAM user and enter both halves again.',
  },
  signature_does_not_match: {
    label: 'Secret key wrong',
    explain: 'AWS knows the access key id, but the secret access key does not belong to it.',
    fix: 'Enter the secret that was shown with this access key, or create a new key.',
  },
  unrecognized_client_exception: {
    label: 'Access key unknown',
    explain: 'ACM does not recognise this access key.',
    fix: 'Create an access key for the IAM user and enter both halves again.',
  },
  access_denied: {
    label: 'Not allowed',
    explain: 'The IAM user may not call every CloudFront action FCP uses.',
    fix: 'Add the CloudFront actions the account form lists to the IAM user’s policy, then test again.',
  },
  access_denied_exception: {
    label: 'Not allowed',
    explain: 'The IAM user may not call every ACM action FCP uses in us-east-1.',
    fix: 'Add the ACM actions the account form lists to the IAM user’s policy, then test again.',
  },
  // --- published pool (reserved allocation, capacity, rebalance) -------------------------
  pool_full: {
    label: 'Pool full',
    explain: 'Every pool slot of this origin is taken.',
    fix: 'Raise the published edges wanted on the origin, or unpublish an edge first.',
  },
  pool_reserved: {
    label: 'Slot held',
    explain:
      'The free pool slots are held for a listener with no published edge, or a location in the provider set with nothing published, so this edge stays a standby.',
    fix: 'Replace a published edge with it, publish an edge where one is missing, or remove that location from the provider set.',
  },
  location_untrusted: {
    label: 'Missing location not trusted yet',
    explain:
      'The free pool slots are held for a location with no tested address, where upkeep adds none, so an address elsewhere stays a spare.',
    fix: 'Add a spare in that location and test it, and it goes into use.',
  },
  pool_raised: {
    label: 'Pool size raised',
    explain:
      'The published edges wanted were raised so every deployed listener has a slot of its own.',
  },
  listener_cap: {
    label: 'Listener cap reached',
    explain:
      'An origin can carry at most eight deployed, enabled listeners, and this would be the ninth.',
    fix: 'Retire or disable a listener you do not need, or register the listener on another origin.',
  },
  pool_below_coverage: {
    label: 'Pool below coverage',
    explain:
      'The published edges wanted cannot go below the number of deployed, enabled listeners.',
    fix: 'Retire or disable a listener first, then lower the published edges wanted.',
  },
  no_duplicate: {
    label: 'Nothing to rebalance',
    explain:
      "Every published edge is its listener's template edge, so there is no duplicate to unpublish.",
    fix: 'Raise the published edges wanted, or retire a listener you do not need.',
  },
  setup_owned: {
    label: 'Owned by a setup run',
    explain: 'A guided setup owns this origin, so automatic replacement leaves it alone.',
    fix: 'Finish or cancel the setup run.',
  },
  not_live: {
    label: 'Not live yet',
    explain:
      'No setup run is working on this origin, but it never went live, so automatic replacement leaves it alone.',
    fix: 'Go live from the node page, or front it again.',
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
      'Many nodes look blocked at once, which points at a provider or protocol block, so FCP holds all automatic replacement.',
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
      'A rotation has run for over an hour, so a provider or the backend may not be answering.',
    fix: 'Open the node to see the step it is waiting on.',
  },
  account_api_failing: {
    label: 'Provider not answering',
    explain:
      'Several calls in a row to this provider account failed, so new edges, health checks and clean-ups stall.',
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
      'Paid edges serve no member until you act, because the node is paused for safety or an edge waits for you.',
    fix: 'Resolve the pause or the edge so the resources are used or removed.',
  },
  delivery_refusals: {
    label: 'Members refused',
    explain:
      'Members fetched their subscription in the last hour and got nothing usable, counted by reason.',
    fix: 'Check the reasons: a switch that is off, an empty pool or a node not live. An app with no connection needs another app, not another address.',
  },
  family_rule_disabled: {
    label: 'App family switched off',
    explain:
      'A client app family has its render rule off, so members using those apps get nothing from a fronted node.',
    fix: 'Turn the family back on under Settings, unless that is intended.',
  },
  node_ready_to_protect: {
    label: 'Node ready to front',
    explain: 'An enrolled node is ready, and nothing fronts it until you start.',
    fix: 'Start fronting it.',
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
  node_unprotected: {
    label: 'Node not fronted',
    explain:
      'The member is on a freedom mode and their node is not fronted, so nothing is handed out for it.',
    fix: 'Front the node.',
  },
  // --- freedom modes only through edges (a node held back from a freedom mode's members) ---
  freedom_node_withheld: {
    label: 'Freedom node held back',
    explain: 'This freedom-mode node has no live edge, and freedom members only get fronted nodes.',
  },
  withheld_unmanaged: {
    label: 'Not enrolled or fronted',
    explain: 'FCP does not manage this node and nothing fronts it.',
    fix: "Front the node, or take it out of the freedom mode's groups.",
  },
  withheld_unprotected: {
    label: 'Not fronted yet',
    explain: 'The node is enrolled, but nothing fronts it.',
    fix: 'Front the node.',
  },
  withheld_no_edge: {
    label: 'No live edge',
    explain: 'The node is fronted, but none of its edges of the kind the mode needs is live.',
    fix: 'Publish a tested edge on the node.',
  },
  withheld_direct_mode: {
    label: 'Mode set up direct',
    explain:
      "The node's mode is in the freedom family, but its backend sets it up direct, so nothing fronts its nodes.",
    fix: 'Move the mode to another family, or move its members to a fronted mode.',
  },
  policy_moved: {
    label: 'Changed while answering',
    explain:
      'The delivery policy changed while the answer was being built, so it was not sent. The next refresh gets the current one.',
  },
  account_spend_cap: {
    label: 'Monthly spend cap reached',
    explain:
      "This account's monthly estimate has reached the spend cap set on it, so FCP creates no new edge in it.",
    fix: 'Raise the cap on the account, or remove edges it no longer needs.',
  },
  account_spend_cap_reached: {
    label: 'Over the monthly spend cap',
    explain: 'A new edge here would take the account past the monthly spend cap set on it.',
    fix: 'Raise the cap on the account, pick another account, or remove an edge.',
  },
  // a transport scoped to a network (docs/edges.md "Networks")
  off_network: {
    label: 'Not on the transport’s network',
    explain:
      "This transport's SNIs are sites on one network, so only addresses on that network may front it, and this one is not or its network is unknown.",
    fix: 'Pick a location on that network, or set the location’s network on its provider account.',
  },
  sni_family_thin: {
    label: 'Few SNIs in a list',
    explain:
      'An SNI list a port uses has fewer than three active SNIs that pass their cover site check, so it runs out fast.',
    fix: "Open the list and find more SNIs in its cover site's certificate, certificate logs or sites on its network.",
  },
  edge_off_network: {
    label: 'Address off its network',
    explain:
      'An address in use on a network-scoped transport is not on that network, so its SNI and address point at two networks.',
    fix: 'Replace the address with one from a location on the network.',
  },
  list_address_left: {
    label: 'Address left a country list',
    explain:
      "A country's list of what works held this address and its newest version does not, so members there may no longer reach it.",
    fix: 'Open the address and replace it with one the list holds, or press Seen it if the list is wrong.',
  },
  network_no_ranges: {
    label: 'Network has no ranges',
    explain:
      "The transport's network has no address ranges now, so no address in use can be shown to be on it.",
    fix: 'Read the network’s ranges again, check its ASNs, or add ranges by hand.',
  },
  // a price read (`plansError` on a location)
  plan_list_unreadable: {
    label: 'Plan list unreadable',
    explain:
      "The provider's load balancer plan list could not be read, so no size or price was taken.",
    fix: 'Refresh prices later. The location keeps the plans and prices it read before.',
  },
  schema_mismatch: {
    label: 'Answer not understood',
    explain: "The provider's answer was not in the shape FCP reads, so nothing was taken from it.",
  },
  account_budget_unlimited: {
    label: 'No daily spending limit',
    explain:
      'A daily allocation budget of 0 means no limit, so a runaway loop could create billable resources without bound.',
    fix: 'Set a daily allocation budget on the account.',
  },
  reality_key_changed: {
    label: 'Node key changed',
    explain:
      "The node's REALITY key or its settings changed since this address was tried, so the new key is unproven through it.",
    fix: 'Try the address again from a client with the new key.',
  },
  family_disabled: {
    label: 'App family off',
    explain:
      'The render rule for this client app family is off, so its members get nothing from a fronted node.',
    fix: 'Turn the family on under Settings.',
  },
  // --- settings notices (a save answers with them; nothing was refused) ------------------
  drain_below_refresh: {
    label: 'Drain shorter than refreshes',
    explain:
      'A replaced address is removed before apps that refresh at the interval get two chances to move.',
    fix: 'Keep the drain time at two refresh intervals or more, or shorten the refresh interval.',
  },
  burned_drain_below_refresh: {
    label: 'Burned drain too short',
    explain:
      'A burned address is removed before apps outside the blocking country have refreshed to the new one.',
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
    label: 'Reached only inside the node',
    explain:
      'The transport listens on loopback, so a provider address cannot dial it. Something on the node, usually a TLS terminator, forwards outside connections to it.',
    fix: 'Add the listener with the port and transport the terminator exposes, or make the transport listen publicly with its own TLS.',
  },
  tag: {
    label: 'Tag cannot be bound',
    explain:
      'The transport tag has characters a backend Host cannot bind to. Only letters, digits and underscores work.',
    fix: 'Rename the transport tag in the config profile.',
  },
  protocol: {
    label: 'Protocol not supported',
    explain: 'Edges carry only VLESS, Trojan and Shadowsocks.',
  },
  transport: {
    label: 'Transport not supported',
    explain: 'Edges carry only raw TCP, WebSocket, HTTP Upgrade, gRPC and XHTTP streams.',
  },
  security: {
    label: 'Security layer not supported',
    explain: 'Edges carry only REALITY, TLS and plain transports.',
  },
  invalid: {
    label: 'Transport cannot be described',
    explain:
      'The transport looks supported, but its settings could not become a listener. The detail says why.',
    fix: 'Check the port, the REALITY target and the SNIs in the config profile.',
  },
};

// --- FCP's own client check ------------------------------------------------------------------
// What one check of an address found (docs/edges.md "FCP's own client check"): the
// verdict, each engine's session, or why no verdict was reached. Kept apart from the
// flat table: `timeout`, `refused` and `busy` are generic words elsewhere.
export const CLIENT_CHECK_ENGINE_LABELS: Record<ClientCheckEngine, string> = {
  'sing-box': 'sing-box',
  xray: 'Xray',
  mihomo: 'Mihomo',
};

export const CLIENT_CHECK_COPY: Record<
  ClientCheckVerdict | ClientCheckSessionCode | ClientCheckUncheckedCode,
  CodeCopy
> = {
  passed: {
    label: 'Works',
    explain: 'Every client connected through this address and came out of the node.',
  },
  passed_with_refusals: {
    label: 'Works like the others',
    explain:
      "At least one client connected, and the others are refused through the transport's other addresses too, so the node refuses them, not this address.",
  },
  address_failed: {
    label: 'Does not work',
    explain:
      "A client did not get through this address, though it gets through the transport's other addresses where there are any.",
    fix: 'Replace the address, or check it again in a few minutes if it was just created.',
  },
  egress_mismatch: {
    label: 'Reaches another node',
    explain:
      'A client connected, but its traffic left from another node, so the load balancer forwards somewhere else.',
    fix: "Check the address's forwarding target at the provider, then check it again.",
  },
  node_unreachable: {
    label: 'Node not reached',
    explain:
      "No client got through this address or the transport's other addresses, so the check cannot tell the address from the node.",
    fix: 'Check that the node is up and its transport answers, then check again.',
  },
  ok: { label: 'Connected', explain: 'The client connected and fetched the egress page.' },
  reality_refused: {
    label: 'Refused by REALITY',
    explain:
      'REALITY sent this client to its target instead of letting it in. It refuses this client version, or the key or SNI does not match.',
    fix: 'For sing-box, set minClientVer to 1.8.1 in the transport and keep the node on Xray 26.7.28 or older.',
  },
  tls_failed: {
    label: 'TLS failed',
    explain: 'The TLS handshake through the address failed.',
  },
  timeout: { label: 'Timed out', explain: 'Nothing answered through the address in time.' },
  refused: { label: 'Connection refused', explain: 'The address refused the connection.' },
  reset: { label: 'Connection dropped', explain: 'The connection was closed during the session.' },
  unreachable: { label: 'No route', explain: 'There is no route to the address.' },
  egress_unreadable: {
    label: 'Egress page unreadable',
    explain: 'The client connected, but the egress page did not answer with an address.',
  },
  config_refused: {
    label: 'Client refused the settings',
    explain: 'The client would not start with the settings built from the test link.',
  },
  session_failed: { label: 'Session failed', explain: 'The session failed for another reason.' },
  not_configured: {
    label: 'Not set up',
    explain: 'This deployment has no client-check service (EDGE_CLIENT_CHECK_SECRET is not set).',
  },
  unavailable: {
    label: 'Check client not answering',
    explain: 'The client-check service did not answer.',
  },
  unauthorized: {
    label: 'Secrets differ',
    explain: "The client-check service refused the request: its secret is not the deployment's.",
  },
  busy: { label: 'Check client busy', explain: 'Another check was running. Try again.' },
  link_unavailable: {
    label: 'No test link',
    explain: 'The test link of this address could not be built, so there was nothing to check.',
  },
  no_engine: {
    label: 'No client for this transport',
    explain: 'Neither sing-box nor Xray speaks this transport as the test link describes it.',
  },
  not_l4: {
    label: 'Checked by its proof',
    explain: 'A CDN front is checked by its own end-to-end proof, not by this check.',
  },
  out_of_time: {
    label: 'Ran out of time',
    explain:
      'The check took too long to run every client, from slow sessions or another check ahead of it.',
    fix: 'Check again in a minute.',
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
  freedom_confirm_required: {
    label: 'Confirm what it closes',
    explain: 'Turning this on would stop handing some members their node.',
    fix: 'Look at what it closes, then confirm.',
  },
  host_adopt_required: {
    label: 'Hosts not adopted yet',
    explain: 'FCP can only take over the Hosts once it has adopted every one of them.',
    fix: 'On the Listeners tab, use "Adopt a Host" on each listener with a backend Host, then switch again.',
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
    explain: "Publishing this as its listener's first edge means writing the backend Host.",
    fix: 'Use Publish so the rotation does the switch.',
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
  mode_groups_unknown: {
    label: 'Mode groups not read yet',
    explain: "FCP could not read the panel's mode groups yet, so it makes no test account.",
    fix: 'It retries by itself. If it keeps waiting, check that the panel answers.',
  },
  no_group_holds_transports: {
    label: 'A transport in no group',
    explain:
      "A transport this fronting covers is in no mode group on the panel, so FCP's test account cannot reach it.",
    fix: 'Put the transport in a mode group on the panel, or choose the mode whose group the test account should use.',
  },
  origin_deleting: {
    label: 'Old fronting still going',
    explain: "The node's earlier fronting is still being removed.",
    fix: 'Wait until it is gone from the Edges page, then front the node again.',
  },
  test_link_unavailable: {
    label: 'New address cannot be tested',
    explain:
      "No Host dials the node at its own address, and FCP cannot build this transport's entry from the node.",
    fix: "Add a Host at the node's own address for this transport, or pick a CDN location.",
  },
  server_already_bound: {
    label: 'Backend server already covered',
    explain: 'Another origin already covers this backend server.',
  },
  throttled: {
    label: 'Asked too often',
    explain: 'That was asked too often, and this call is rate limited.',
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
      'This node is putting its direct addresses back, so new workflows, hides and pool changes wait.',
    fix: 'Let the restore finish, then try again.',
  },
  restore_not_running: {
    label: 'Nothing to skip',
    explain: 'No removal is running on this node any more, so there is no direct check to skip.',
    fix: 'Refresh the node page to see where it stands.',
  },
  restore_not_held_at_direct: {
    label: 'Not at the direct check',
    explain: 'Only a removal held at the direct check can skip it.',
    fix: 'Wait until the node page shows the removal at the direct check, then try again.',
  },
  plan_changed: {
    label: 'Node changed since setup',
    explain:
      'The transports on this node differ from the ones the earlier setup made listeners for, so the run cannot resume safely.',
    fix: 'Remove fronting from the node, then front it again.',
  },
  consent_withdrawn_hidden: {
    label: 'Host already hidden',
    explain:
      'A host you removed from the approval was already hidden, and the run never re-enables a host by itself.',
    fix: 'Keep it approved, or remove fronting to put every host back.',
  },
  account_switch_late: {
    label: 'Account fixed after publish',
    explain: 'The account can only change while nothing is published for this node yet.',
    fix: 'Cancel the run and start again with the other account.',
  },
  test_link_no_match: {
    label: 'No entry for this transport',
    explain:
      'The test credential gets no single entry for this transport, so no test link can be built.',
    fix: 'Check that the node has exactly one enabled backend Host on this transport at its own address and port.',
  },
  test_link_render_failed: {
    label: 'Test link not rendered',
    explain: 'The candidate address could not be rendered into a connection for this transport.',
    fix: 'Check the listener SNIs and the address, then fetch the test link again.',
  },
  use_manual_setup: {
    label: 'Set up by hand',
    explain: 'Outline servers with no members have no test credential path.',
    fix: 'Give its origin a first edge on its Origin details page, or front it once it has members.',
  },
  choose_mode: {
    label: 'Choose a connection mode',
    explain: 'The node has no usable placement to mint the test credential on.',
    fix: 'Choose the connection mode whose placement covers this node.',
  },
  test_account_used_up: {
    label: 'Test account used up',
    explain:
      'The test account is used up and could not be reset, so no test link can be made with it. A test profile left connected in a client uses it up.',
    fix: 'Remove old test profiles from your clients, then try again.',
  },
  credential_unresolved: {
    label: 'Credential still settling',
    explain:
      'An earlier try to create the test credential may still land, so FCP waits before creating another.',
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
      'This node is enrolled in Servers, so it goes live behind its new addresses only and members cannot stay on the direct one.',
    fix: 'Front it and hide the hosts the addresses cannot carry.',
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
    explain: 'Front again is for a node whose members already connect through its addresses.',
    fix: 'Use Front a node, or Go live if its addresses are ready.',
  },
  reprotect_not_enrolled: {
    label: 'Not an enrolled node',
    explain: 'Only a node the node role enrolled is fronted again from here.',
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
    fix: 'Remove an address from Origin details first, then front it again.',
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
  location_options_needed: {
    label: 'Location options needed',
    explain:
      'A region was picked, but the account names no project or private network to use there.',
    fix: 'Open Change options and choose them.',
  },
  location_in_use: {
    label: 'Location still in use',
    explain: 'An address still lives in this location, or a fronted node uses it.',
    fix: 'Remove or replace those addresses first.',
  },
  shared_certificate_in_use: {
    label: 'Certificate still in use',
    explain: 'Live fronts in this zone still use its shared certificate.',
    fix: 'Replace or remove those fronts first.',
  },
  shared_certificate_present: {
    label: 'Shared certificate still there',
    explain:
      'The account still has a shared certificate at the provider, which nothing could remove after the account is gone.',
    fix: 'Remove it with its zone under Locations on the account page, or delete it at the provider and test the account again.',
  },
  shared_certificate_not_ours: {
    label: 'Certificate not ordered by FCP',
    explain:
      'FCP found and reused this wildcard certificate, and removes only certificates its own fronts ordered.',
    fix: 'Remove it at the provider if nothing else uses it, then test the account again.',
  },
  template_value_required: {
    label: 'Region value needed',
    explain: 'The template leaves a value empty that this provider needs per region.',
    fix: 'Pick it for this location, or set it in the template.',
  },
  placement_on_location: {
    label: 'Region is set per location',
    explain: 'Where edges are created is part of a location, not of the account.',
    fix: 'Add a location on the provider page instead.',
  },
  // a CDN location (a DNS zone) and what an import must match there
  location_unusable: {
    label: 'Zone cannot be used',
    explain: 'The provider reached that zone, but it cannot be used now.',
    fix: 'Fix the zone at the provider, then add the location again.',
    reasonFromServer: true,
  },
  dns_account_unusable: {
    label: 'DNS account cannot be used',
    explain: 'That DNS account cannot hold the records of this location.',
    fix: 'Pick a DNS account that can host DNS records and is switched on.',
    reasonFromServer: true,
  },
  hostname_not_in_zone: {
    label: 'Hostname outside the zone',
    explain: 'The hostname is not in the zone of the picked location.',
    fix: 'Pick the location whose zone holds the hostname.',
  },
  // "Doesn't work" / "Try another address" when no new address could be made now.
  replacement_cannot_start: {
    label: 'No new address now',
    explain: 'No new address can be created now, so this one was kept and nothing was removed.',
    fix: "Check the account's daily budget and limits and that new work is not paused, then try again.",
    reasonFromServer: true,
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

/** A provider's own numeric error code (`1000`, `9109`) or an HTTP status, never shown bare. */
const PROVIDER_NUMBER = /^\d{3,6}$/;

export function codeLabel(code: string | null | undefined): string {
  if (!code) return '';
  if (!EDGE_CODE_COPY[code] && PROVIDER_NUMBER.test(code)) return `Provider error ${code}`;
  return EDGE_CODE_COPY[code]?.label ?? humanizeCode(code);
}

export function codeExplain(code: string | null | undefined): string {
  if (!code) return '';
  if (!EDGE_CODE_COPY[code] && PROVIDER_NUMBER.test(code))
    return `The provider refused the call with its own error code ${code}.`;
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

/**
 * An edge's `health` is the PROVIDER's own check of the node behind it (a load
 * balancer's backend health check), never whether members can reach the
 * address: a new load balancer once answered every connection with a reset
 * while its backend check passed. The words say whose check it is;
 * reachability from outside has its own words (`outsideReachOf`).
 */
export const EDGE_HEALTH_LABELS: Record<string, string> = {
  online: 'Provider check passing',
  offline: 'Provider check failing',
  degraded: 'Provider check partly failing',
  unknown: 'No provider check',
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

/** Whether an address answers from outside, from the probes (`outsideReachOf`). */
export type OutsideReach = 'reachable' | 'unreachable' | 'partly' | 'unchecked';

/**
 * An address's reachability from outside, from its probe summary
 * (`EdgeAdmin.reachability`, fresh evidence only, FCP's own vantage
 * included): every checked place reaches it, none does, some do, or nothing
 * checked it lately. A place with no verdict (`unknown`) is left out.
 */
export function outsideReachOf(
  reachability: { byCountry: ReadonlyArray<{ verdict: string }> } | null | undefined,
): OutsideReach {
  const verdicts = (reachability?.byCountry ?? [])
    .map((c) => c.verdict)
    .filter((v) => v !== 'unknown');
  if (verdicts.length === 0) return 'unchecked';
  if (verdicts.every((v) => v === 'reachable')) return 'reachable';
  if (verdicts.every((v) => v === 'unreachable')) return 'unreachable';
  return 'partly';
}
export const OUTSIDE_REACH_LABELS: Record<OutsideReach, string> = {
  reachable: 'Reachable from outside',
  unreachable: 'Unreachable from outside',
  partly: 'Reachable from some places',
  unchecked: 'Not checked from outside',
};
export function outsideReachTone(reach: string): Tone {
  switch (reach) {
    case 'reachable':
      return 'success';
    case 'unreachable':
      return 'danger';
    case 'partly':
      return 'warning';
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
  open_setup: 'Resume fronting',
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
  protect_node: 'Front the node',
  open_node: 'Review go-live',
  open_modes: 'Open Connection modes',
  open_probes: 'See the checks',
  open_run: 'Open the run',
  find_names: 'Find SNIs',
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
  protect_node: 'Front node',
  open_node: 'Open node',
  open_modes: 'Connection modes',
  open_probes: 'Open probes',
  open_run: 'Open run',
  find_names: 'Find SNIs',
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
    explain: 'The node serves more transports than one run fronts.',
    fix: 'Pick the ones to front.',
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
    explain: 'The provider could not create or publish the address. The detail names the step.',
    fix: 'Try again (Choose another account).',
  },
  address_unreachable: {
    label: 'Address unreachable',
    explain:
      'The new address was unreachable from outside, even after FCP saved its configuration again where the provider allows.',
    fix: 'Check again (Try another address, Go live anyway).',
  },
  blocked_in: {
    label: 'Blocked in a country',
    explain:
      'The new address is blocked from a censored country on its first check but works from elsewhere.',
    fix: 'Try another address (Use it anyway, Check again).',
  },
  coverage_incomplete: {
    label: 'Not every transport covered',
    explain: 'The published pool had no room for one of the listeners.',
    fix: 'Try again.',
  },
  try_it: {
    label: 'Try each address',
    explain:
      "Import each test link into a client, connect, load a page, then answer Works or Doesn't work.",
    fix: 'Works (Doesn’t work).',
  },
  test_account_used_up: {
    label: 'Test account used up',
    explain:
      'The test account is used up and could not be reset, so its test links will not connect. A test profile left connected in a client uses it up.',
    fix: 'Remove old test profiles from your clients, then try again.',
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
    explain: 'A member body did not render through the new address. The detail names the case.',
    fix: 'Try again.',
  },
  resilience_short: {
    label: 'No backup elsewhere',
    explain:
      'A member would get a backup address from the same provider as the main one, though another provider is available.',
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
  origin_unreachable: {
    label: 'Could not reach the origin',
    explain:
      'The node did not answer the check of its WebSocket or HTTP transport, which is usually a passing network fault.',
    fix: 'Check again in a moment.',
  },
  origin_not_public: {
    label: 'Origin address is not public',
    explain:
      "The node's address or hostname leads to no public address, so no CDN can reach its WebSocket or HTTP transport.",
    fix: 'Give the node a public address or point its hostname at one, then plan again.',
  },
  origin_private: {
    label: 'Node address is private',
    explain:
      'The panel lists a private address for this node, so a load balancer at a provider cannot reach it.',
    fix: "Give the node's public IP address on the first step.",
  },
  origin_name: {
    label: 'Node address is a hostname',
    explain:
      'The panel lists a hostname for this node, and a load balancer forwards only to an IP address.',
    fix: "Give the node's public IP address on the first step.",
  },
  test_link_unavailable: {
    label: 'New address cannot be tested',
    explain:
      "No Host dials the node at its own address, and FCP cannot build this transport's entry from the node, so a new address here cannot be tested.",
    fix: "Add a Host at the node's own address for this transport, or pick a CDN location.",
  },
  origin_port_not_carried: {
    label: 'Wrong port for gRPC',
    explain: 'A CDN passes gRPC only to a node listening on port 443.',
    fix: 'Move the gRPC transport to port 443.',
  },
  host_header_rejected: {
    label: 'Node takes only its hostname',
    explain:
      "The node answers only to its own hostname as the Host, and this CDN's fronts send theirs instead.",
    fix: "Pick a CDN that sends the node's hostname, or let the node answer any Host.",
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
  account_spend_cap_reached: {
    label: 'Spend cap reached',
    explain: 'These addresses would take the account past the monthly spend cap set on it.',
    fix: 'Raise the cap on the account, or pick another location.',
  },
  off_network: {
    label: 'Not on the transport’s network',
    explain:
      "This account's transports here have SNIs on one network, and this place is not on it or its network is unknown.",
    fix: 'Pick a location on that network, or set this location’s network on its provider account.',
  },
  provider_mismatch: {
    label: 'Other provider pinned',
    explain: 'A listener on this node is pinned to another provider.',
  },
  dns_zone_missing: {
    label: 'No DNS zone',
    explain: 'This location names no DNS zone.',
    fix: 'Add a location in one of the zones the account reaches.',
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
  caa_forbids_ca: {
    label: 'CAA forbids its CA',
    explain: 'The zone’s CAA records do not let this account’s certificate authority issue.',
    fix: 'Allow it in the CAA records and check the zone again, or choose another authority for this node.',
  },
  shared_certificate_failed: {
    label: 'Shared certificate failed',
    explain: 'The wildcard certificate this account’s fronts share in this zone failed to issue.',
    fix: 'Open the account to see why, then retry the certificate.',
  },
  shared_certificate_ambiguous: {
    label: 'Wildcard not reusable',
    explain: 'The zone’s wildcard is covered by a certificate this account would not order.',
    fix: 'Open the account to see it, or switch it to one certificate per front.',
  },
  location_check_failed: {
    label: 'Zone check refused',
    explain: "This zone's last check refused it.",
    fix: 'Check it again from the provider page.',
  },
  dns_account_missing: {
    label: 'DNS account gone',
    explain: 'The DNS account this front writes its records through no longer exists.',
    fix: 'Add a location that names another DNS account.',
  },
  dns_account_disabled: {
    label: 'DNS account switched off',
    explain: 'The DNS account this front writes its records through is switched off.',
    fix: 'Switch it on from its provider page.',
  },
  zone_mode_unknown: {
    label: 'Zone mode not read',
    explain: "The zone's encryption mode was never read.",
    fix: 'Check the zone again from the provider page.',
  },
  project_unresolved: {
    label: 'No project',
    explain:
      "This location names no Project id and the API key's default project could not be read.",
    fix: 'Set the Project id on this location.',
  },
  size_not_multicloud: {
    label: 'Size takes Scaleway servers only',
    explain: 'This size only accepts servers hosted at Scaleway.',
    fix: "Set this location's size to a multi-cloud one, such as LB-GP-L or LB-GP-XL.",
  },
  l4_not_for_websocket: {
    label: 'Not for a WebSocket node',
    explain:
      "A load balancer cannot front a WebSocket node, because members would send the node's own hostname.",
    fix: 'Use a CDN account.',
  },
};

export function setupRunNeedCopy(code: string | null | undefined): CodeCopy {
  const known = code ? (SETUP_RUN_NEED_COPY as Record<string, CodeCopy>)[code] : undefined;
  return (
    known ?? {
      label: humanizeCode(code ?? ''),
      explain: `The run stopped: ${humanizeCode(code ?? 'unknown')}. Open it to see what to do.`,
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
  'edge.restore.direct_skipped': 'Direct check skipped to finish the delete',
  'relay.listener.upsert': 'Listener registered',
  'relay.listener.update': 'Listener changed',
  'relay.listener.retire': 'Listener retired',
  'relay.listener.name.retire': 'SNI retired',
  'relay.listener.name.reactivate': 'SNI reactivated',
  'relay.listener.sni_pick': 'SNI selection changed',
  'edge.sni.names.accepted': 'New SNIs proven on the node',
  'edge.sni.names.tested': "New SNIs tested by FCP's client check",
  'relay.edge_pick': 'Address selection changed',
  'relay.lanes': 'Address lanes changed',
  'edge.lane_retired': 'Old open address retired',
  'edge.drain_hold.started': 'Replaced front kept up for apps that have not refreshed',
  'edge.drain_hold.released': 'Replaced front let go',
  'relay.host.created': 'Backend Host created',
  'relay.host.deleted': 'Backend Host deleted',
  'relay.host.adopted': 'Backend Host adopted',
  'relay.host.adopt_requested': 'Host adoption requested',
  'relay.host.released': 'Backend Host released',
  'relay.qualification_credential': 'Qualification credential changed',
  'relay.qualification_reset': 'Test account reset',
  'edge.published': 'Edge published',
  'edge.unpublished': 'Edge unpublished',
  'edge.publish_held': 'Edge kept as a standby',
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
  'edge.provider_account.cost_changed': 'Account cost settings changed',
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
  'admin.edge.limits_raised': 'Account limits raised to the new defaults',
  'edge.pool_expanded': 'Pool expanded for an uncovered listener',
  'edge.relay.rebalanced': 'Duplicate edge sent back to standby',
  'edge.automation.set': 'Automatic replacement switched',
  'edge.setup_run.started': 'Guided setup started',
  'edge.setup_run.needs_operator': 'Guided setup waiting for you',
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

/**
 * A failed run named by what it was: adding a spare or a new address is no
 * replacement, and putting a spare in use is neither (`kind` / `spare` of the
 * `edge.rotation_failed` payload or the `rotation_failed` attention facts).
 * Null for a replace, or when the kind is not known: the plain label stands.
 */
export function failedRunLabel(
  facts: unknown,
  plain: boolean,
): { label: string; explain: string } | null {
  if (!facts || typeof facts !== 'object') return null;
  const f = facts as Record<string, unknown>;
  if (f['kind'] === 'provision')
    return f['spare'] === false
      ? plain
        ? {
            label: 'Adding an address failed',
            explain: 'A new address for this fronted node could not be created.',
          }
        : {
            label: 'Provision failed',
            explain: 'A new edge for this origin could not be created.',
          }
      : plain
        ? {
            label: 'Adding a spare failed',
            explain: 'A new spare address for this fronted node could not be created.',
          }
        : {
            label: 'Standby provision failed',
            explain: 'A new standby edge for this origin could not be created.',
          };
  if (f['kind'] === 'publish')
    return plain
      ? {
          label: 'Putting an address in use failed',
          explain: 'A spare address of this fronted node could not be put in use.',
        }
      : {
          label: 'Publish failed',
          explain: 'A standby edge of this origin could not be published.',
        };
  return null;
}

/** The provider's own words behind a failure (redacted by the server), as a sentence; null when it said none. */
export function providerAnswerWords(facts: unknown): string | null {
  if (!facts || typeof facts !== 'object') return null;
  const a = (facts as Record<string, unknown>)['answer'];
  if (typeof a !== 'string' || a.trim() === '') return null;
  const t = a.trim();
  return `The provider answered: ${t}${/[.!?]$/.test(t) ? '' : '.'}`;
}

export function auditActionLabel(action: string, payload?: unknown): string {
  if (action === 'edge.rotation_failed') {
    const run = failedRunLabel(payload, false);
    if (run) return run.label;
  }
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
  origin: 'fronted node',
  origins: 'fronted nodes',
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
  'published edges wanted': 'addresses wanted in use',
  'the transport of this listener': 'this transport',
  'edge work': 'new work',
};

// A verb swapped for "<verb> address" keeps its own object ("Rotate the
// credentials" is "Replace the credentials", never "Replace address the ...").
const VERB_OBJECT = /\b(replace|create) address (the|this|that|an?|its|one)\b/gi;

// "In use" and "paused for safety" follow their noun in English ("an address in
// use", never "a in use address"): a plain phrase spliced in front of one of
// these nouns is moved behind it.
const AFTER_NOUN =
  /\b(in use|paused for safety) (CDN fronts?|fronts?|address(?:es)?|fronted nodes?|spares?|transports?)\b/gi;
// The article before a plain word whose first sound differs from the word it
// replaced ("a published edge", "an origin").
const AN_WORDS = new Set(['address', 'addresses', 'update']);
const A_WORDS = new Set([
  'fronted',
  'spare',
  'spares',
  'retiring',
  'replace',
  'replaced',
  'create',
  'created',
  'creating',
  'trusted',
  'trust',
  'paused',
  'transport',
  'transports',
  'resume',
  'check',
  'put',
  'raise',
  'new',
]);

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
  out = out.replace(VERB_OBJECT, '$1 $2');
  out = out.replace(AFTER_NOUN, (m, phrase: string, noun: string) => {
    const head = m[0] === m[0]!.toUpperCase() ? noun[0]!.toUpperCase() + noun.slice(1) : noun;
    return `${head} ${phrase.toLowerCase()}`;
  });
  return out.replace(/\b(a|an)(\s+)([a-z]+)/gi, (m, article: string, gap: string, word: string) => {
    const w = word.toLowerCase();
    const want = AN_WORDS.has(w) ? 'an' : A_WORDS.has(w) ? 'a' : null;
    if (!want || want === article.toLowerCase()) return m;
    const cased = article[0] === 'A' ? want[0]!.toUpperCase() + want.slice(1) : want;
    return `${cased}${gap}${word}`;
  });
}

/** The node page's timeline: the audit action in plain words. */
const PLAIN_AUDIT_LABELS: Record<string, string> = {
  'relay.create': 'Node added',
  'relay.registered': 'Node registered',
  'relay.upsert': 'Node registered',
  'relay.update': 'Settings changed',
  'relay.delete': 'Fronting removed',
  'relay.edge_pick': 'Members spread over the addresses',
  'relay.lanes': 'Trusted addresses changed',
  'edge.lane_retired': 'Old open address taken out of use',
  'edge.drain_hold.started': 'Old address kept up for apps that have not refreshed',
  'edge.drain_hold.released': 'Old address no longer kept up',
  'relay.host.created': 'Backend updated with the new address',
  'relay.host.deleted': 'Old address removed from the backend',
  'edge.published': 'Address in use',
  'edge.unpublished': 'Address taken out of use',
  'edge.publish_held': 'Address kept as a spare',
  'edge.rotated': 'Address replaced',
  'edge.burned': 'Address replaced (blocked)',
  'edge.rolled_back': 'Replacement rolled back',
  'edge.rotation_failed': 'Replacement failed',
  'edge.quarantined': 'Paused for safety',
  'edge.quarantine_resolved': 'Safety pause lifted',
  'edge.destroyed': 'Address destroyed',
  'edge.verified': 'Address tested with a real session',
  'edge.client_check': "Address checked with FCP's client",
  'edge.sni.names.accepted': 'New SNIs given to members',
  'edge.sni.names.tested': "FCP's client check tested new SNIs",
  'edge.auto_replace_held': 'Automatic replacement held',
  'edge.fresh_name_blocked': 'New hostname blocked before use',
  'edge.cdn_refused': 'CDN refused in a country',
  'edge.auto_replace_resumed': 'Automatic replacement resumed',
  'edge.block_suspected': 'Address looks blocked',
  'edge.block_cleared': 'Address no longer looks blocked',
  'edge.block_simulation.started': 'Test block started',
  'edge.block_simulation.ended': 'Test block ended',
  'edge.host.hidden': 'Direct address hidden in the backend',
  'edge.host.restored': 'Direct address restored in the backend',
  'edge.render.withheld': 'Unplaced entry left out for members',
  'edge.relay.restore_started': 'Removing fronting',
  'edge.restore.direct_skipped': 'Removal finished without restoring direct',
  'edge.relay.restore_finished': 'Direct address steps finished',
  'edge.setup_run.started': 'Fronting started',
  'edge.setup_run.needs_operator': 'Fronting waiting for you',
  'edge.setup_run.go_live': 'Fronting live',
  'edge.setup_run.finished': 'Fronting finished',
  'edge.setup_run.cancelled': 'Fronting cancelled',
  'admin.edge.provision': 'Address requested',
  'admin.edge.test_provision': 'Test address requested',
  'admin.edge.rotate': 'Replacement requested',
  'admin.edge.burn': 'Replacement requested (blocked)',
  'probe.verdict': 'Reachability changed',
  'edge.country.state': 'Result from a country changed',
  'edge.country.mark': 'Marked for a country',
  'edge.country.check': 'Checked from every country',
};
export function plainAuditActionLabel(action: string, payload?: unknown): string {
  if (action === 'edge.rotation_failed') {
    const run = failedRunLabel(payload, true);
    if (run) return run.label;
  }
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

/**
 * "Skip restoring direct" (`POST relays/{id}/restore/skip-direct`): a node
 * removal held at the direct check. Offered only there, once the check has
 * held (an attempt counted), and never for a restore that keeps the node.
 */
export function skipDirectOffered(
  restore: { purpose: string; phase: string; attempt: number } | null | undefined,
): boolean {
  return (
    !!restore &&
    restore.purpose === 'delete_relay' &&
    restore.phase === 'verify_direct' &&
    restore.attempt > 0
  );
}

/** The note under the step, the button and its confirm. */
export const SKIP_DIRECT = {
  button: 'Skip restoring direct',
  title: 'Skip restoring direct?',
  body: "The removal finishes without the node's direct address. Members on this node then keep no direct entry, so their apps cannot reach it until the backend gives them one again. Its provider addresses are retired as usual.",
  confirm: 'Skip and finish removal',
  done: 'Direct check skipped. The removal finishes now.',
} as const;

/** Why the direct check holds, from the restore's last error (`<code>:<group>`). */
export function skipDirectHeldWords(lastError: string | null | undefined): string {
  const code = (lastError ?? '').split(':')[0] ?? '';
  const goneForGood =
    "It is checked again every few minutes. If the node's direct address is gone for good, skip restoring direct.";
  if (code === 'no_direct_entry')
    return 'Held: the backend gives members of this node no direct address, so this check cannot pass. Put one back in the backend and the removal finishes by itself, or skip restoring direct.';
  if (code === 'fetch_failed' || code === 'unreadable_body')
    return `Held: a member's subscription could not be read from the backend. ${goneForGood}`;
  return `Held: ${code ? humanizeCode(code) : 'the check did not pass'}. ${goneForGood}`;
}
