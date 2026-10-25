/**
 * Audit-log payload allowlist (M3). The audit table's `payload` is `v.any()`, so
 * a careless future caller could persist a raw request body, and admins with
 * `admin:audit:read` would then be able to read it (free-text, account numbers,
 * future PII). To make that impossible by construction rather than by review,
 * every audit write goes through `writeAuditLog`, which projects the payload
 * down to an explicit per-action key allowlist.
 *
 * Fail-closed: an action with no allowlist entry stores NO payload at all (a
 * one-time console.warn names the action so the author registers it here). The
 * action name is never secret, so logging it is safe. Curated, no-payload
 * actions (admin.login, transitions, etc.) are simply absent from the map; they
 * never pass a payload, so they never warn.
 *
 * Pure helpers live here so both write paths share them: the `audit.record`
 * mutation (called from actions) and the in-mutation direct inserts (lifecycle /
 * freeTier / adminApi, which cannot `ctx.runMutation` another mutation).
 */
import type { MutationCtx } from '../_generated/server';

export type AuditActorType = 'system' | 'admin' | 'member' | 'anonymous' | 'webhook';

export interface AuditEntry {
  actorType: AuditActorType;
  action: string;
  actorId?: string;
  targetType?: string;
  targetId?: string;
  payload?: unknown;
  requestId?: string;
}

/**
 * The only payloads any audit write is allowed to persist, keyed by action.
 * Add an entry (with the exact, curated key set) when a new action needs to
 * record structured context. Keys absent here are dropped before insert; an
 * action absent here drops its payload entirely. Keep these to non-secret,
 * scalar context: never an account number, token, secret, or apiUrl.
 */
export const AUDIT_PAYLOAD_ALLOWLIST: Readonly<Record<string, readonly string[]>> = {
  'subscription.switch_backend': ['fromBackend', 'toBackend', 'fromTier', 'toTier'],
  // Member switches connection mode (transport) within a backend. `inPlace` marks
  // an in-place mode group re-point (existing key kept) vs a re-issue fallback.
  'subscription.switch_mode': ['fromMode', 'toMode', 'inPlace'],
  // Member moves their key to a different server, keeping their mode. `reason` is
  // a bounded enum the member picked (never free text); `fromNode` is the node
  // name they left — operator infrastructure, already shown to the member, and
  // the whole point of the record. Never a placement/mode group uuid.
  'subscription.switch_server': ['reason', 'inPlace', 'movedPlacement', 'movedNodePin', 'fromNode'],
  // Member reported a connection problem (nothing changed about their key).
  // Reason enum + backend only — the consented geo lives in the UNLINKED
  // issueReports table, never against the user here.
  'subscription.issue_reported': ['reason', 'backend'],
  // Member revokes one HWID device (truncated identifier only, never the full hwid).
  'subscription.device_revoke': ['hwidPrefix'],
  // A key was issued with no placement (no Remnawave pool bound anywhere) — a
  // bring-up misconfiguration signal. `requestedMode` is a non-secret mode id.
  'subscription.issued_without_placement': ['requestedMode'],
  // Issuance-saga compensation couldn't delete the freshly-minted backend user
  // (bounded retries exhausted): an ORPHAN proxy account exists backend-side with
  // no local row. The operator's manual cleanup queue. backendUserId is the
  // backend-side account id (non-secret; needed to find + delete the orphan).
  'subscription.compensation_failed': ['backend', 'backendUserId'],
  // The post-issuance tombstone of a superseded key failed past the bounded
  // retry — TWO live keys exist until an operator deletes the old one.
  'subscription.tombstone_failed': ['backendUserId'],
  // A tombstoned sub exhausted its sweep backoff (permanently-dead backend):
  // the local row was marked deleted so the sweep moves on, but the backend
  // key may still exist — the operator's manual cleanup queue.
  'subscription.tombstone_abandoned': ['backend', 'backendUserId', 'attempts'],
  // The donation fleet re-cap finished INCOMPLETE (a backend was down mid-run or
  // the page cap hit): the applied marker was deliberately NOT set, so the next
  // hourly run re-pushes. Surfaced because the start-of-run heartbeat alone
  // would make the cron look healthy.
  'donation.bonus_partial': ['effective', 'failedChunks', 'exhausted'],
  // Epoch rotation gap: epochs exist but none is currently valid while
  // FS_MANIFEST_SK is set (≥3 consecutive failed rotates) — clients are
  // silently falling back to the static key.
  'hpke.epoch_gap': ['lastNotAfter'],
  'membership.tier_change': ['fromTierId', 'toTierId', 'reason'],
  'user.create.free': ['ipCountry', 'asn'],
  // W2: admin retunes a rate-limit policy.
  'settings.ratelimit_change': ['policyKey', 'max', 'windowMs', 'enabled'],
  // HPKE verification channels (non-secret URLs + the show/hide toggle).
  'admin.verification.change': [
    'showPanel',
    'releaseUrl',
    'onionAddress',
    'sourceUrl',
    'extensionUrl',
  ],
  // Site chrome: the announcement banner (toggle + text) + footer repo link
  // (toggle + https URL). All non-secret, operator-typed presentation values.
  'admin.site.change': [
    'bannerEnabled',
    'bannerText',
    'repoEnabled',
    'repoUrl',
    'tosUrl',
    'privacyUrl',
    'supportEmail',
    'heroTitle',
    'heroSubtitle',
    'heroTitles',
  ],
  // Analytics origin config. Booleans + presence/hash flags ONLY: the Umami
  // host is an apiUrl-class value (and an exfiltration target if repointed) and
  // the website id is a correlatable UUID, so neither is ever persisted here.
  // `umamiUrlHash` (truncated sha-256 of the cleaned URL, '' when unset) makes
  // a repoint DETECTABLE in the trail without recording the host itself.
  // `ipHeader` is a non-secret header NAME (cf-connecting-ip etc.) — auditing
  // it makes an IP-trust widening visible in the trail. `geoMode` records the
  // full-IP vs coarse-location choice (a privacy-posture change worth a trail).
  // Operator alerts (convex/alerts.ts): booleans only; never the URL, topic or token.
  'admin.alerts.change': ['enabled', 'urlChanged', 'topicSet', 'tokenSet'],
  'admin.analytics.change': [
    'enabled',
    'forwardIp',
    'ipHeader',
    'geoMode',
    'umamiUrlHash',
    'hasWebsiteId',
  ],
  // Diagnostics (member issue telemetry) config change: all knobs are
  // non-secret booleans + a header NAME + a retention number, so the full new
  // state goes in the trail (a collection-posture change should be visible).
  'admin.diagnostics.change': [
    'enabled',
    'cloudflareEnabled',
    'collectCountry',
    'collectCity',
    'collectAsn',
    'asnHeader',
    'retentionDays',
  ],
  // Member opt-in passkeys: enroll / revoke (device label is a non-secret display
  // string; the credential id / public key are never logged). Login is audited as
  // `account.login.passkey` with NO payload (like `account.login.account_id`).
  'account.passkey.register': ['deviceLabel'],
  'account.passkey.revoke': ['deviceLabel'],
  // W4: admin mints / revokes membership codes (never the code/hash itself).
  'membership_code.mint': ['count', 'tierId', 'durationDays'],
  'membership_code.revoke': ['codeId'],
  'membership_code.redeem': ['tierId', 'durationDays'],
  // Billing: self-service membership purchases + donations (never payer PII).
  'billing.checkout.created': ['processor', 'months', 'kind', 'quantity', 'donationCents'],
  'billing.order.paid': [
    'processor',
    'tierSlug',
    'durationDays',
    'amountCents',
    'kind',
    'quantity',
    'donationCents',
  ],
  'billing.config.update': ['key'],
  // Grant refused by the defense-in-depth cross-checks (amount/ref mismatch) —
  // amounts + verdicts only, never payer data.
  'billing.grant_refused': [
    'processor',
    'reason',
    'expectedMinor',
    'reportedMinor',
    'reportedCurrency',
    'refMatched',
  ],
  // Refund/reversal-class event seen for an ALREADY-PAID order: the operator's
  // chargeback action queue (membership is not auto-revoked).
  'billing.refund_seen': ['processor', 'amountCents', 'reportedMinor'],
  // A second paid event with a different payment id for an already-paid order:
  // the buyer paid twice on one invoice. The operator's refund-review queue.
  'billing.overpayment_seen': ['processor', 'amountCents', 'reportedMinor'],
  // A payment that arrived SHORT of the invoice (e.g. an exchange took its
  // withdrawal fee out of the amount sent). `_accepted` = within the
  // underpayment tolerance, granted; `_seen` = beyond it (or unmeasurable), the
  // order is held as `underpaid` for the operator. paidPermille = the fraction
  // delivered x1000 in the paid asset (null when unmeasurable).
  'billing.underpayment_seen': [
    'processor',
    'expectedMinor',
    'reportedMinor',
    'paidPermille',
    'tolerancePct',
  ],
  'billing.underpayment_accepted': [
    'processor',
    'expectedMinor',
    'reportedMinor',
    'paidPermille',
    'tolerancePct',
  ],
  // The operator resolved an order from Admin → Billing: granted a held
  // underpaid (or stuck pending/confirming/expired) order, or dismissed an
  // underpaid one. Order facts only, never the gift codes.
  'admin.billing.order_granted': ['processor', 'fromStatus', 'kind', 'amountCents', 'paidPermille'],
  'admin.billing.underpaid_dismissed': ['processor', 'amountCents', 'paidPermille'],
  'billing.settle_detail_unavailable': ['processor'],
  // A referral's pending/converted reward was voided (refund, referee lapse,
  // program disabled, cap, referrer gone).
  'referral.void': ['reason', 'referrerUserId'],
  // Referral lifecycle: code bound at account creation, first paid grant
  // converted, referrer bonus vested. Non-secret ids/day counts only.
  'referral.bound': ['referrerUserId'],
  'referral.converted': ['referrerUserId', 'refereeBonusDays'],
  'referral.rewarded': ['referrerUserId', 'refereeUserId', 'referrerBonusDays'],
  // Referral-program config from the admin billing card — the payload is the
  // written key→value map; all five values are validated booleans/integers.
  'referral.config.update': [
    'referral.enabled',
    'referral.refereeBonusDays',
    'referral.referrerBonusDays',
    'referral.vestingDays',
    'referral.maxRewardsPerMonth',
  ],
  // A webhook claim whose grant threw (retryable only until the sender gives
  // up) — surfaced on the admin billing page as money-at-risk.
  'billing.webhook.grant_failed': ['source'],
  // Multi-admin onboarding: invite minted / redeemed (username is a non-secret
  // admin label, never the invite token).
  'admin.invite.created': ['username'],
  'admin.invite.redeemed': ['username'],
  // Automation-token mint (bootstrap via `convex run`); never the token/secret.
  'admin.automation_token.mint': ['name', 'scopeCount', 'boundaryServers', 'boundaryNodes'],
  // Human-admin API-token mint / revoke from the CMS; never the token/secret.
  'admin.token.mint': ['name', 'scopeCount', 'subjectType', 'boundaryServers', 'boundaryNodes'],
  'admin.token.revoke': ['name'],
  // Admin tier lifecycle from the CMS (the by-slug IaC path audits separately).
  'admin.tier.create': ['slug', 'backend'],
  'admin.tier.update': ['slug'],
  'admin.tier.delete': ['slug'],
  // PATCH /admin/settings flipped a key (e.g. devices.enforcementEnabled) —
  // the key NAME only, never the value (some values are secret-adjacent).
  'admin.settings.change': ['key'],
  // The censored-country list (lib/censoredCountries.ts): the country CODES added,
  // removed or re-flagged (comma-joined; infrastructure configuration, never a
  // member's country) and the new length.
  'censorship.countries.update': ['added', 'removed', 'flagsChanged', 'count'],
  // The keys the list replaced, deleted once it is stored (key names only) and put back for a rollback.
  'censorship.legacy_keys.retire': ['keys', 'count'],
  'censorship.legacy_keys.restore': ['keys', 'count'],
  'censorship.legacy_keys.changed': ['keys', 'count'],
  // Admin -> Status: the availability matrix's row count and the load-band
  // thresholds (operator configuration of the public status page).
  'status.page.update': ['censorshipRows', 'busyAt', 'crowdedAt'],
  // By-id backend-server CRUD from the CMS (the by-slug IaC path audits
  // separately); never the config secret / apiUrl.
  'admin.backend_server.create': ['slug', 'backend'],
  'admin.backend_server.update': ['slug'],
  // Mirror-provider CRUD (repointing endpoint/bucket/publicUrl silently
  // redirects member subscription mirrors — must be traceable). Name only.
  'admin.mirror_provider.create': ['name'],
  'admin.mirror_provider.update': ['name'],
  'admin.mirror_provider.delete': ['name'],
  'admin.mirror_provider.upsert': ['name', 'created'],
  // Clients-catalog edits (the member-facing app list — a malicious/broken
  // entry silently changes what members download). Name only.
  'admin.client.create': ['name'],
  'admin.client.update': ['name'],
  'admin.client.delete': ['name'],
  'admin.client.upsert': ['name', 'created'],
  // Idempotent backend-server upsert by slug (Ansible / IaC); never the config secret.
  'admin.backend_server.upsert': ['slug', 'backend', 'created'],
  // Slug-addressed backend-server delete (migrate / IaC).
  'admin.backend_server.delete': ['slug'],
  // What was left of a removed backend server, cleared (counts only).
  'admin.backend_server.purge': ['rows', 'more'],
  // Admin grant/extend of a membership from the Users page.
  'admin.user.grant_membership': ['tierId', 'durationDays'],
  // Idempotent tier upsert by slug (Ansible / IaC). Node placement is bound
  // separately per connection mode (admin.remnawave.mode_placement.update).
  'admin.tier.upsert': ['slug', 'backend', 'created'],
  // Admin CRUD on the DB-driven connection-mode catalog (slug only — copy and
  // flags are non-secret but noisy; the row itself is the record).
  'admin.connection_mode.create': ['slug'],
  'admin.connection_mode.update': ['slug'],
  'admin.connection_mode.delete': ['slug'],
  'admin.connection_mode_family.create': ['slug'],
  'admin.connection_mode_family.update': ['slug'],
  'admin.connection_mode_family.delete': ['slug'],
  // Admin/IaC binds a mode's placement pool on one backend. `poolBound` /
  // `boundCount` are booleans/counts — the config contents (mode group UUIDs) are
  // NEVER logged (only which mode's pool + whether/how many it's bound to).
  'admin.backend.mode_placement.update': ['backend', 'modeSlug', 'poolBound', 'boundCount'],
  // Admin enforced the no-client-IP-logging posture on the Remnawave config
  // profiles (Xray log/policy). Counts only — no config content is logged.
  'admin.remnawave.logging_hardened': ['instances', 'profilesChanged', 'profilesTotal'],
  // Server management: which switches moved, never a value from a backend.
  'servers.config.update': ['changedKeys'],
  'servers.host.create': ['backendSlug', 'label', 'outcome', 'code'],
  'servers.host.update': ['backendSlug', 'label', 'outcome', 'code'],
  'servers.host.delete': ['backendSlug', 'label', 'outcome', 'code'],
  'servers.host.reorder': ['backendSlug', 'label', 'outcome', 'code'],
  'servers.squad.create': ['backendSlug', 'label', 'outcome', 'code'],
  'servers.squad.update': ['backendSlug', 'label', 'outcome', 'code'],
  'servers.squad.delete': ['backendSlug', 'label', 'outcome', 'code'],
  'servers.node.create': ['backendSlug', 'label', 'outcome', 'code'],
  'servers.node.update': ['backendSlug', 'label', 'outcome', 'code'],
  'servers.node.delete': ['backendSlug', 'label', 'outcome', 'code'],
  'servers.node.enable': ['backendSlug', 'label', 'outcome', 'code'],
  'servers.node.disable': ['backendSlug', 'label', 'outcome', 'code'],
  'servers.node.restart': ['backendSlug', 'label', 'outcome', 'code'],
  'servers.profile.patch': ['backendSlug', 'label', 'outcome', 'code'],
  'servers.profile.foreign_edit_seen': ['backendSlug', 'label'],
  // The bootstrap contract v2 (docs/servers.md "Node lifecycle"): setting up
  // or adopting a backend, an enrolled node's ladder, its retirement. Names
  // and stages only.
  'servers.setup.started': ['backendSlug', 'generation', 'adopt'],
  'servers.setup.changed': ['backendSlug', 'generation', 'change', 'originZone', 'addedModes'],
  'servers.setup.finished': ['backendSlug', 'state', 'code', 'step'],
  'servers.setup.group_renamed': ['backendSlug', 'from', 'to'],
  'servers.setup.templates_installed': ['backendSlug', 'templates', 'written'],
  'servers.node.registered': ['backendSlug', 'name', 'mode'],
  'servers.node.adopted': ['backendSlug', 'name', 'mode', 'addresses'],
  'servers.profile.transition': ['backendSlug', 'closed', 'held', 'acknowledged'],
  'servers.profile.transition_released': ['backendSlug', 'held'],
  'servers.node.settings': ['backendSlug', 'name', 'change'],
  'servers.node.direct_confirmed': ['backendSlug', 'name'],
  'servers.node.approved': ['backendSlug', 'name', 'mode'],
  'servers.node.live': ['backendSlug', 'name', 'mode'],
  'servers.node.drift': ['backendSlug', 'name', 'kind', 'wasLive'],
  'servers.node.maintenance_started': ['backendSlug', 'name'],
  'servers.node.maintenance_finished': ['backendSlug', 'name'],
  'servers.node.retire_requested': ['backendSlug', 'name', 'stage'],
  'servers.node.retire_decided': ['backendSlug', 'name', 'disposition'],
  'servers.node.retire_rejected': ['backendSlug', 'name'],
  'servers.node.retired': ['backendSlug', 'name', 'confirmedBy'],
  // A port change staged until every node's firewall lets the port in
  // (docs/servers.md "Firewall acknowledgement"): the profile name, the port and
  // counts; `by` is who confirmed (the node role, or an admin).
  'servers.port_change.staged': ['backendSlug', 'label', 'port', 'nodes'],
  'servers.port_change.confirmed': ['backendSlug', 'label', 'by', 'nodes', 'port'],
  'servers.port_change.cancelled': ['backendSlug', 'label'],
  'servers.port_change.admitted': ['backendSlug', 'label', 'outcome', 'code'],
  // A node rename (docs/servers.md "Renaming a node"): the two names only.
  'servers.node.rename_started': ['backendSlug', 'from', 'to'],
  'servers.node.renamed': ['backendSlug', 'from', 'to'],
  'servers.node.rename_failed': ['backendSlug', 'from', 'to', 'code'],
  'servers.node.rename_retried': ['backendSlug', 'from', 'to'],
  // Operator-run 2.x→3.x key-id remap on one upgraded backend (counts only).
  'admin.remnawave.user_ids_migrated': [
    'panelVersion',
    'remapped',
    'missing',
    'failed',
    'conflicts',
  ],
  // Admin changes the brand theme (preset + optional hue override).
  'admin.theme.change': ['preset', 'hue'],
  // W3-8: admin lifecycle — deactivate/reactivate an admin, revoke a passkey
  // (username + device label are non-secret display strings).
  'admin.admin.deactivate': ['username'],
  'admin.admin.reactivate': ['username'],
  'admin.passkey.revoke': ['deviceLabel'],

  // --- origin edges (provider-managed load balancers). Payloads carry slugs,
  // provider ids, edge/rotation ids, counts and codes ONLY: never an address,
  // handle, template body, probe token or provider credential.
  // `frontsTraffic` for a DNS provider's account only: DNS and fronting (true) or DNS only.
  'edge.provider_account.create': ['name', 'provider', 'frontsTraffic'],
  'edge.provider_account.update': ['name', 'provider'],
  // The account's certificate option defaults changed: which keys, with the
  // values of choices, numbers and switches only (lib/edges/providers/options.ts).
  'edge.provider_account.options_changed': ['name', 'provider', 'changes'],
  // A deploy moved option defaults kept under settings into `optionDefaults`.
  'edge.provider_account.options_migrated': ['name', 'provider', 'keys'],
  // A DNS account switched between DNS only and DNS and fronting, with how
  // many of its edges exist (they are kept either way).
  'edge.provider_account.fronting_changed': ['name', 'provider', 'frontsTraffic', 'liveEdges'],
  // A deploy turned the retired deployment-wide switch into the account's own choice.
  'edge.provider_account.fronting_migrated': ['name', 'provider', 'frontsTraffic'],
  // What the operator says the account costs (convex/edgePlans.ts): amounts and a currency, never the note.
  'edge.provider_account.cost_changed': [
    'name',
    'provider',
    'paid',
    'perEdgeMonthly',
    'currency',
    'monthlyCap',
  ],
  'edge.provider_account.delete': ['name', 'provider'],
  'edge.provider_account.upsert': ['name', 'provider', 'created'],
  // Trust is per location: `placeKey` names it (the provider's region id).
  'edge.provider_account.qualified': [
    'name',
    'provider',
    'qualified',
    'edgeId',
    'endpointEvidence',
    'placeKey',
  ],
  // The L7 auto-trust rule (lib/edges/autoQualify.ts): ids only, never the endpoint.
  'edge.provider_account.auto_qualified': [
    'name',
    'provider',
    'qualified',
    'edgeId',
    'endpointEvidence',
    'placeKey',
  ],
  // An account's locations (docs/edges.md § "Provider accounts and locations").
  'edge.location.created': ['name', 'provider', 'placeKey'],
  'edge.location.updated': ['name', 'provider', 'placeKey', 'enabled'],
  // Networks (docs/edges.md "Networks"): slugs and counts, never a range or an address.
  'edge.location.network': ['placeKey', 'network'],
  'edge.network.create': ['slug', 'asns'],
  'edge.network.update': ['slug', 'asns', 'manualPrefixes'],
  'edge.network.delete': ['slug'],
  'edge.location.removed': ['name', 'provider', 'placeKey'],
  // The one-time move of accounts' fixed locations into locations: counts only.
  'edge.locations.migrated': ['accounts', 'edges', 'runs', 'reviews', 'relays'],
  // A CDN account's zone moved from its settings onto its location: counts only.
  'edge.locations.l7_migrated': ['moved', 'created', 'incomplete', 'edgesDiffer'],
  // An operator confirmed an L4 endpoint (lib/edges/verification.ts): never the address.
  'edge.verified': ['relaySlug', 'edgeId', 'listenerKey', 'method'],
  // FCP's own client check of one address (edgeClientCheck.ts): codes only, never an
  // address or an egress IP. `engines` = `sing-box:ok xray:reality_refused`.
  'edge.client_check': ['relaySlug', 'edgeId', 'verdict', 'by', 'control', 'engines'],
  // Automatic replacement of a transport held (a replacement blocked again soon
  // after going into use) and lifted by the operator.
  'edge.auto_replace_held': ['relaySlug', 'listenerKey', 'code', 'edgeId'],
  'edge.auto_replace_resumed': ['relaySlug', 'lifted'],
  // The system's `partial` rung moved (lib/edges/verifyRung.ts): the word only, never the address.
  'edge.verification.rung': ['relaySlug', 'edgeId', 'listenerKey', 'rung'],
  // Rotation keeps the qualification: booleans only, never a key or identifier.
  'edge.provider_account.shared_certificate_removed': [
    'name',
    'provider',
    'locationId',
    'certificate',
    'removed',
  ],
  'edge.provider_account.credentials_rotated': [
    'name',
    'provider',
    'credentialsChanged',
    'identifiersChanged',
    'qualifiedKept',
  ],
  'edge.template.create': ['provider', 'name'],
  'edge.template.update': ['provider', 'name'],
  'edge.template.delete': ['provider', 'name'],
  'edge.profile.create': ['slug', 'provider'],
  'edge.profile.update': ['slug', 'provider'],
  'edge.profile.delete': ['slug', 'provider'],
  'edge.profile.qualified': ['slug', 'provider', 'tlsOk', 'authOk'],
  'edge.profile.sni.retire': ['profileSlug', 'count'],
  'edge.profile.sni.reactivate': ['profileSlug', 'count'],
  'relay.create': ['slug', 'bindingDeferred', 'poolRaised'],
  // `changed` = names of the fields the write touched (never their values);
  // the three booleans are the operator-owned knob flips, when they changed.
  'relay.update': ['slug', 'changed', 'autoRotate', 'hostMode', 'enabled'],
  // Booleans only: the credential itself never reaches the audit log.
  'relay.qualification_credential': ['slug', 'minted', 'revoked', 'replaced', 'adopted'],
  // The account kept usable before a test (relayQualification.keepUsable): booleans only.
  'relay.qualification_reset': ['slug', 'reset', 'failed', 'reenabled', 'nearCap'],
  // Temporary test credentials (edgeTestCredentials.ts): booleans + counts only.
  'edge.test_credential': ['relaySlug', 'purpose', 'issued', 'removed', 'failed', 'attempts'],
  // `restore` = the delete entered the restore workflow first (a guided origin).
  'relay.delete': ['slug', 'force', 'disposition', 'restore'],
  // The direct-Host hide ledger + restore workflow (edgeHostHides.ts /
  // edgeRestore.ts): counts, remarks, phases and purposes; never an address.
  'edge.host.hidden': ['relaySlug', 'count', 'remarks', 'runId', 'rehidden'],
  'edge.host.restored': ['relaySlug', 'count', 'remarks'],
  'edge.host.reappeared': ['relaySlug', 'count', 'remarks'],
  // A member render left out entries it could not place (edgeHostHides.noteWithheld).
  'edge.render.withheld': ['relaySlug', 'count', 'remarks'],
  'edge.relay.restore_started': ['relaySlug', 'purpose'],
  'edge.relay.restore_finished': ['relaySlug', 'purpose', 'hidesRestored'],
  'relay.upsert': ['slug', 'created', 'changed'],
  // Coverage: a full pool expanded (within the cap) for an uncovered listener; a
  // rebalance unpublished a duplicate back to standby. Counts and ids only.
  'edge.pool_expanded': ['relaySlug', 'from', 'to', 'blocked'],
  'edge.relay.rebalanced': ['relaySlug', 'edgeId', 'poolIndex', 'epoch'],
  // A node's provider set edited by hand: counts only (never location names).
  'edge.relay.providers_changed': ['relaySlug', 'added', 'removed', 'drained', 'picks', 'run'],
  // The automation switch: the one boolean it was set to.
  'edge.automation.set': ['on'],
  // Freedom modes only through edges (freedomDelivery.setEdgesOnly): what it was set to,
  // whether members were affected and the admin confirmed it, how many nodes it withholds.
  'edge.freedom.edges_only': ['on', 'confirmed', 'withheldNodes', 'affected'],
  // Guided setup runs (edgeSetupRuns.ts): slugs, run ids, stage / code words
  // and counts only; never an address, a Host uuid or a test link.
  'edge.setup_run.started': [
    'relaySlug',
    'runId',
    'stage',
    // `reprotect` for a live node protected again (absent on a first protection).
    'kind',
    // `replace_all` or `add` for a re-protect.
    'mode',
    'listeners',
    'accountName',
    'provider',
    // The provider set: how many picks, how many (transport, pick) addresses.
    'picks',
    'targets',
    'approvedHides',
    'keepDirect',
  ],
  'edge.setup_run.needs_operator': ['relaySlug', 'runId', 'stage', 'code'],
  'edge.setup_run.go_live': ['relaySlug', 'runId', 'listeners', 'renderEnabled'],
  'edge.setup_run.finished': ['relaySlug', 'runId', 'outcome', 'stage', 'code', 'verdicts'],
  'edge.setup_run.cancelled': ['relaySlug', 'runId', 'stage', 'disposition'],
  'edge.render.enabled_by_setup': ['relaySlug', 'runId', 'affectedRelays'],
  'edge.adopted': ['slug', 'edgeId', 'managed', 'publication', 'refused', 'shared', 'verified'],
  'relay.slot.upsert': ['relaySlug', 'slotKey', 'created'],
  'relay.slot.retire': ['relaySlug', 'slotKey'],
  'edge.published': ['relaySlug', 'edgeId', 'poolIndex', 'epoch', 'rotationId'],
  'edge.unpublished': ['relaySlug', 'edgeId', 'poolIndex', 'epoch', 'rotationId'],
  // A publish the pool refused (reserved allocation or a full pool): the edge stays a standby.
  'edge.publish_held': ['relaySlug', 'edgeId', 'code', 'rotationId'],
  'edge.destroyed': ['relaySlug', 'provider', 'edgeId'],
  'edge.destroy_failed': ['relaySlug', 'provider', 'edgeId', 'attempts'],
  'edge.delete': ['relaySlug', 'edgeId', 'force', 'drainEndedEarly'],
  // Operator resolutions of a parked (`needs_operator`) edge.
  'edge.destroy': ['relaySlug', 'edgeId', 'provider'],
  'edge.forget': ['relaySlug', 'edgeId', 'provider'],
  'edge.reactivate': ['relaySlug', 'edgeId', 'provider'],
  'edge.retry_destroy': ['relaySlug', 'edgeId', 'provider'],
  'edge.burned': ['relaySlug', 'trigger', 'edgeId', 'rotationId'],
  'edge.rotated': [
    'relaySlug',
    'trigger',
    'kind',
    'fromProvider',
    'toProvider',
    'fromEdgeId',
    'toEdgeId',
    'poolIndex',
    'hostsFlipped',
    'durationMs',
    'rotationId',
  ],
  // `answer`: the provider's redacted, scrubbed words on the refusal (no address, no name).
  'edge.rotation_failed': [
    'relaySlug',
    'trigger',
    'kind',
    'spare',
    'phase',
    'outcome',
    'step',
    'code',
    'answer',
    'rotationId',
  ],
  'edge.rolled_back': ['relaySlug', 'hosts'],
  'edge.quarantined': ['relaySlug', 'rotationId', 'reason'],
  'edge.quarantine_resolved': ['relaySlug', 'keep', 'rotationId', 'reason'],
  'edge.drift': ['relaySlug', 'edgeId', 'mismatched', 'total'],
  'edge.orphan_suspected': ['provider', 'name', 'step'],
  'edge.block_suspected': [
    'relaySlug',
    'hintLevel',
    'score',
    'reporters',
    'topCountry',
    'scope',
    'autoRotate',
    'simulated',
  ],
  'edge.block_cleared': ['relaySlug', 'reason'],
  // Test block evidence on a test deployment (edgeSimulations.ts): the country,
  // the simulated reporters and the duration; why it ended.
  'edge.block_simulation.started': ['relaySlug', 'country', 'reporters', 'minutes'],
  'edge.block_simulation.ended': ['relaySlug', 'reason'],
  // The fleet brake (lib/edges/fleet.ts): counts and the threshold only.
  'edge.fleet_brake': ['engaged', 'suspected', 'evaluated', 'threshold'],
  'probe.run': ['targetKey', 'source', 'trigger'],
  'probe.verdict': ['targetKey', 'source', 'country', 'ipVersion', 'verdict'],
  // Per-country checks of edges (edgeCountry.ts): slugs, countries and states, never an address.
  'edge.country.state': ['relaySlug', 'country', 'track', 'state', 'reason'],
  'edge.country.mark': ['scope', 'country', 'state', 'count'],
  'edge.country.check': ['relaySlug'],
  'probe.requested': ['targets', 'runs', 'sources'],
  'probe.target.create': ['label'],
  'probe.target.update': ['label'],
  'probe.target.delete': ['label'],
  'edge.live.pulled': ['edgeId', 'accountId'],
  'admin.edge.config.change': ['changedKeys'],
  'admin.edge.maintenance': ['frozen', 'reason'],
  // The explicit bootstrap provision from a tested but unqualified account.
  'admin.edge.test_provision': ['slug', 'listenerKey', 'accountName', 'provider', 'rotationId'],
  // An operator-created backend Host taken over for a listener (hostMode handoff).
  'relay.host.adopt_requested': ['relaySlug', 'listenerKey'],
  'edge.delivery.binding_released': ['relaySlug', 'backendServerId'],
  'relay.listener.upsert': ['relaySlug', 'listenerKey', 'created'],
  'relay.listener.retire': ['relaySlug', 'listenerKey'],
  'relay.listener.update': ['relaySlug', 'listenerKey', 'enabled'],
  'relay.listener.name.retire': ['relaySlug', 'listenerKey', 'count', 'everywhere'],
  'relay.listener.name.reactivate': ['relaySlug', 'listenerKey', 'count'],
  'relay.listener.sni_pick': ['relaySlug', 'listenerKey', 'version', 'reason'],
  // Server-name families: slugs and COUNTS only, never a hostname.
  'edge.sni.config.update': ['changedKeys'],
  'edge.sni.family.create': ['slug', 'targetKind', 'network'],
  'edge.sni.family.update': ['slug', 'network'],
  'edge.sni.family.delete': ['slug', 'nameCount'],
  'edge.sni.names.import': ['slug', 'added', 'rejected'],
  'edge.sni.names.retire': ['slug', 'count', 'listeners', 'skipped'],
  'edge.sni.names.reactivate': ['slug', 'count'],
  'edge.sni.names.burn': ['slug', 'count', 'listeners', 'skipped'],
  'edge.sni.names.recheck': ['slug', 'count'],
  'edge.sni.inbound.bind': ['slug', 'backendSlug', 'inboundTag', 'imported', 'notImported'],
  'edge.sni.inbound.unbind': ['slug', 'backendSlug', 'inboundTag'],
  'edge.sni.names.country': ['slug', 'country', 'state', 'count'],
  'edge.sni.names.accepted': ['relaySlug', 'listenerKey', 'generation', 'count', 'witness'],
  // Checks from inside a country: slugs, the country, the source and counts, never a name or an address.
  'edge.sni.vantage.batch': ['country', 'source', 'targetKind', 'count', 'trigger'],
  'edge.sni.vantage.request': ['slug', 'country', 'count', 'batches'],
  'edge.sni.vantage.apply': ['slug', 'country', 'proven', 'blocked'],
  'edge.sni.vantage.auto_apply': ['slug', 'country', 'state', 'count', 'held'],
  'relay.host.created': ['relaySlug', 'listenerKey', 'discovered'],
  'relay.host.deleted': ['relaySlug', 'listenerKey'],
  // A Host the ledger called present was gone from the backend on re-observation.
  'relay.host.lost': ['relaySlug', 'listenerKey'],
  'relay.host.adopted': ['relaySlug', 'listenerKey'],
  'relay.host.released': ['relaySlug', 'listenerKey'],
  'relay.delivery.released': ['relaySlug'],
  'admin.edge.reset': ['phase', 'deleted'],
  // Operator-run raise of accounts still on an old default limit pair
  // (`edgeProviderAccounts.raiseOldDefaultLimits`): the limits before and after.
  'admin.edge.limits_raised': [
    'name',
    'provider',
    'fromMaxLiveEdges',
    'maxLiveEdges',
    'fromDailyAllocationBudget',
    'dailyAllocationBudget',
  ],
  'admin.edge.render.change': ['changedKeys'],
  'admin.edge.probe.change': ['changedKeys'],
  // `forceGeoEvidence` records that an operator waived the affected-country
  // evidence gate for this run (a boolean; the transport proof is never waived).
  'admin.edge.rotate': ['slug', 'trigger', 'force', 'forceGeoEvidence', 'rotationId', 'optionKeys'],
  'admin.edge.burn': ['slug', 'trigger', 'force', 'forceGeoEvidence', 'rotationId', 'optionKeys'],
  'admin.edge.provision': ['slug', 'trigger', 'forceGeoEvidence', 'rotationId', 'optionKeys'],
  'admin.edge.publish': ['slug', 'trigger', 'forceGeoEvidence', 'rotationId', 'edgeId'],
  'admin.edge.cancel': ['slug', 'rotationId', 'deferred'],
};

/**
 * Project an audit payload to its action's allowlisted keys. Returns `undefined`
 * (store nothing) when there is no payload, the payload is not a plain object,
 * or the action is unregistered. Shallow by design: allowlisted values are
 * curated scalars, so there is no nested structure to recurse into.
 */
export function sanitizeAuditPayload(
  action: string,
  payload: unknown,
): Record<string, unknown> | undefined {
  if (payload === undefined || payload === null) return undefined;
  if (typeof payload !== 'object' || Array.isArray(payload)) {
    console.warn(`[audit] dropping non-object payload for action "${action}"`);
    return undefined;
  }
  const allow = AUDIT_PAYLOAD_ALLOWLIST[action];
  if (!allow) {
    console.warn(`[audit] dropping payload for unregistered action "${action}"`);
    return undefined;
  }
  const src = payload as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of allow) {
    if (key in src && src[key] !== undefined) out[key] = src[key];
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/**
 * The single blessed way to write the audit log: sanitizes the payload, then
 * inserts. Never `ctx.db.insert('auditLog', ...)` directly, or the allowlist is
 * bypassed.
 */
export async function writeAuditLog(ctx: MutationCtx, entry: AuditEntry): Promise<void> {
  const { payload, ...rest } = entry;
  await ctx.db.insert('auditLog', {
    ...rest,
    payload: sanitizeAuditPayload(entry.action, payload),
  });
}
