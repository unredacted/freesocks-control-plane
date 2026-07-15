# Billing — self-service membership purchases

FreeSocks members can buy a fixed-term **FreeSocks membership** (the single paid
tier: unlimited bandwidth + devices) by paying with **Bitcoin** (on-chain or
Lightning, settled to the org's own **BTCPay Server** — no intermediary), crypto
(Bitcoin, Monero, Zcash + many coins, via **NOWPayments**), card (**Stripe**), or
**PayPal**. Every rail is a full-page **redirect to a processor-hosted page** —
the strict CSP forbids an embedded payment SDK, and a redirect is also the
lower-PCI-scope option.

This is additive to the two pre-existing entitlement paths: the generic
`/api/webhooks/billing` HMAC seam (`convex/webhooks.ts`) and admin-minted
redemption codes (`convex/membershipCodes.ts`). All three converge on the same
core: `lifecycle.applyMembership`.

## Architecture

```
SPA UpgradeMembership ──POST /api/v1/billing/checkout──▶ billing.createCheckout
        │                                                      │ (binds order→userId, opaque ref)
        │ window.location = redirectUrl                        ▼
        ▼                                            processor.createCheckout (hosted invoice)
  processor-hosted page ──pay──▶ processor ──webhook──▶ /api/webhooks/<processor>
        │                                                      │
        │ redirect back: /account?order=<ref>                  ▼ billing.ingestEvent
        ▼                                              verify sig → dedupe → applyEvent
  SPA polls GET /api/v1/billing/order/<ref>                    │ (single grant on 'paid')
        └────────────── until paid/failed/expired ◀────── applyMembership(max(now,expiry)+days)
```

- **Adapters** — `convex/lib/processors/{types,nowpayments,btcpay,stripe,paypal}.ts`:
  pure HTTP modules (config injected, no env/Convex access) mirroring the proxy
  backends. Each exposes `createCheckout()` and `verifyAndParse()`; errors never
  capture the API key or full URL.
- **Domain** — `convex/billing.ts`: `createCheckout` (action), `ingestEvent`
  (action), the serializable `applyEvent` (single-grant), `getOrderStatus`
  (userId-scoped). Plain V8 actions — `fetch` + `crypto.subtle`, no `"use node"`.
- **Catalog + toggles** — the `billing.*` keys in `appSettings`, resolved by
  `convex/lib/billingConfig.ts` (compiled defaults, fail-safe, structured
  validation), edited via the admin **Billing** page (`PATCH
/api/v1/admin/billing/config`) — not the generic settings PATCH. Exposed
  publicly (prices only) through `publicConfig.get`.
- **Credentials** — processor API keys/secrets + the public base URL live in the
  same `appSettings` table under `billing.secret.*` (the same trust model as the
  proxy-backend secrets in `backendServers.config`): **set them in Admin →
  Billing → Processor credentials** (write-only — the API never returns a secret,
  only set/not-set booleans). Each field falls back to its env var
  (`NOWPAYMENTS_API_KEY`, …) when the DB row is unset, so an env-configured deploy
  keeps working; `resolveProcessorSecrets` (internal-only) reads DB-then-env.
- **Orders** — the `billingOrders` table: one row per checkout, bound to the
  member's `userId`. Swept by `retention.expireStalePendingOrders` (pending >48h
  → expired) and `retention.sweepBillingOrders` (terminal > 365d → deleted).

## The PII invariant

**FreeSocks stores zero payer PII.** The member's identity is bound to the order
**server-side** via an unguessable `opaqueRef` (`randomHex(16)`); only that ref is
sent to the processor (as its `order_id` / `client_reference_id` / `custom_id`).
The processor-hosted page may collect a payer email **on its side** for its own
receipts — FreeSocks never receives or persists it. The deduped
`webhookEvents.payload` is the adapter's **redacted summary** (status + amount +
ids), enforced by an allowlist, and is covered by a test that asserts a
`customer_email` in the raw IPN never lands in storage.

## Order lifecycle

`pending` → (`confirming`) → `paid` | `failed` | `expired`

- `pending`: checkout created, no terminal webhook yet.
- `confirming`: crypto mempool/confirmation wait (can be minutes) — the SPA keeps
  polling. Non-terminal.
- `paid`: a confirmed-payment webhook flipped it. The grant happens **exactly
  once** — `applyEvent` re-reads `status==='paid'` and no-ops, so duplicate/raced
  webhooks can't double-extend membership. Membership is extended to
  `max(now, currentExpiry) + durationDays` (where `durationDays = round(months ×
30.44)` → 1/3/6/12 mo = 30/91/183/365 d).
- `failed`/`expired`: terminal, no grant. Abandoned `pending`/`confirming` orders
  are swept to `expired` after `BILLING_PENDING_TTL_HOURS` (default 48). A LATE
  paid webhook (a slow crypto confirmation landing after the sweep) still grants —
  `expired → paid` is deliberately allowed so money is never silently lost (tested).

### Grant cross-checks (defense-in-depth, 2026-07-16)

Beyond the signature layer, a `paid` webhook must match the order it grants —
`applyEvent` refuses and audits (`billing.grant_refused`) when:

- the event's **checkout id** (invoice / session / order id, per rail) differs
  from the `processorRef` FCP itself stored at checkout. This closes the
  shared-store forged-invoice path: an invoice someone else minted on the same
  BTCPay store / Stripe account with a victim's `orderRef` in its metadata can
  never grant, because its id isn't the one FCP created.
- the event's **reported amount** undershoots the order (1-cent tolerance) or
  its currency differs. NOWPayments reports the fiat `price_amount`; Stripe the
  session `amount_total`; PayPal the capture/order money object. BTCPay's settle
  event carries no amount — its checkout-id binding is the guard there.

A refusal never advances the order (the REAL invoice's webhook can still grant).

### Failure visibility

- A webhook claim whose grant **threw** stays retryable via the sender's
  redelivery — but senders give up (Stripe ~3 days). `markEventFailed` audits
  (`billing.webhook.grant_failed`) and **Admin → Billing** shows a money-at-risk
  warning (count + recent failed events): a claim stuck `failed` past the retry
  window is a paid-but-ungranted order to grant manually.
- A **refund/reversal-class** event for an already-paid order is audited
  (`billing.refund_seen`; PayPal `PAYMENT.CAPTURE.REFUNDED`/`REVERSED`,
  NOWPayments `refunded`). Membership is NOT auto-revoked — the operator decides
  (see "Refunds").

## Gift purchases

A signed-in member can buy membership for **other people** instead of extending
their own. The checkout takes an `orderKind` (`'self'` — the default — or `'gift'`)
and, for a gift, a `quantity` of **1–50** codes (`MAX_GIFT_QUANTITY`,
`convex/billing.ts`). The charged amount scales by quantity
(`duration.amountCents * quantity`); the payer-PII invariant is unchanged (the
order still stores no payer identity).

Flow (gift):

1. The buyer's client pre-generates `quantity` CSPRNG codes and posts only their
   **hashes** with the checkout; the processor redirect/IPN is identical to a self
   purchase.
2. On the **paid** webhook, the grant action mints `quantity` single-use
   redemption codes (`redemptionCodes`, **hash-only**, bound to the buyer) — the
   same table admin-minted membership codes use — and stashes the **plaintexts**
   in a **transient `giftReveal` buffer** on the order row.
3. The buyer polls the order, sees each plaintext code **once** (the
   `GiftRevealModal`), and acknowledges saving them, which clears the buffer. The
   **`billing-gift-reveal-sweep`** cron (hourly) clears any un-acknowledged buffer
   after its window, so plaintext gift codes never linger at rest.
4. Recipients redeem a code exactly like an admin-minted membership code (Account
   → redeem), extending their own membership by the purchased duration.

Gift codes are bearer credentials (anyone holding one can redeem it), so the
reveal-once + sweep design keeps the plaintext out of long-term storage. The buyer
manages their codes from the `GiftCodes` panel.

## Donations

A supporter can add a donation on top of a membership checkout, or give standalone
(`kind: 'donation'`, no membership) — both on `/account` and `/get-account`, and a
member can donate again anytime. The donation rides the SAME processor charge as a
membership (one `amountCents = price + donation`), so no adapter changes are needed;
a donation-only order carries no tier (`billingOrders.tierId` is optional) and grants
nothing. The donated amount is stored on the order (`donationCents`), shown in the
admin billing log, and included in the `billing.order.paid` audit payload. A member's
first settled donation stamps `users.firstDonatedAt`, which drives a persistent donor
badge on the account.

**Donations fund a monthly free-user bandwidth bonus.** All donations in a calendar
month accumulate into a shared pool (`appState` key `donation:freeBonus`); every free
user's monthly cap becomes `base + min(monthlyBonusCapGb, monthDonatedUSD ×
bonusGbPerUsd)` for that month, then resets to base next month. On a settled donation
the grant path records it (`lib/donationBonus.recordDonation`) and schedules
`donations.applyFreeBonus`, which re-caps the active free fleet via Remnawave
`POST /api/users/bulk/update` (≤500 uuids/chunk); the hourly `donation-bonus-reconcile`
cron is the backstop and performs the month-roll reset. The apply is idempotent (it
only pushes when the effective bonus differs from what was last pushed). New/refreshed
free keys pick up the current bonus at issuance via `resolveTrafficLimitBytes`.

**Config** (`billing.donation.*`, admin-editable under Admin → Billing → Donations,
shipped in `publicConfig`): `enabled`, `suggestedAmountsCents` (preset chips),
`minAmountCents` (standalone floor), `bonusGbPerUsd` (rate), `monthlyBonusCapGb` (cap).
All are placeholders until an operator sets real values — like the membership prices.

**Impact surfaces.** `recordDonation` also upserts a bounded per-month ledger
(`appState` key `donation:history`, capped at 24 months: cumulative `donatedCents` +
the month's `bonusGb` frozen at write time), so a month roll no longer discards the
prior month. The daily user-counts reconcile additionally tallies `freeActive`
(active users on default-free tiers) into `stats:userCounts`. `publicConfig`
`billing.donation` projects `freeUsersHelped` + a last-12-months `history` of
`{month, bonusGb}` — **GB and user counts only; dollar amounts are never public**
(the current month is synthesized live from the accumulator). `getAccountView`
returns the member's own `donatedCentsTotal`/`donationCount` (summed from their paid
orders). The SPA renders these as dithered charts (`DitherChart.svelte`, a
dependency-free Bayer-ordered-dither canvas — no chart library, CSP-safe): the
account Membership tab's impact panel (`MemberImpact.svelte`, every membership
state, with a personal-contribution block for donors) and a home-page impact
section, both gated on donations being enabled and non-empty history.

## NOWPayments setup (crypto rail — ship first)

1. Create a NOWPayments account; generate an **API key** and an **IPN secret**.
2. Set the Convex env (`bunx convex env set`):
   - `NOWPAYMENTS_API_KEY` — invoice creation.
   - `NOWPAYMENTS_IPN_SECRET` — IPN HMAC-SHA512 verification. While unset,
     `/api/webhooks/nowpayments` answers a distinct `503 billing.not_configured`.
   - `NOWPAYMENTS_API_URL` — optional; defaults to `https://api.nowpayments.io`.
     Point at `https://api-sandbox.nowpayments.io` for sandbox testing.
   - `PUBLIC_BASE_URL` — the deployment's public origin (e.g.
     `https://beta.freesocks.org`); the backend builds the absolute IPN +
     success/cancel URLs from it.
3. In Admin → **Billing**: set real prices for the durations, enable the
   **Crypto (NOWPayments)** rail, then flip **Billing enabled** on.
4. **IPN auth:** the callback signature is `HMAC-SHA512` of the **key-sorted**
   JSON body, compared against the `x-nowpayments-sig` header
   (`convex/lib/processors/nowpayments.ts:verifyAndParse`). Status mapping:
   `finished`→paid, `confirming`/`confirmed`/`sending`/`partially_paid`→confirming,
   `waiting`→pending, `failed`/`refunded`→failed, `expired`→expired.
5. **Sandbox:** `api-sandbox.nowpayments.io` + the IPN simulator lets you drive a
   payment to `finished` without real funds.
6. **Per-coin minimums (a PRICING constraint).** NOWPayments enforces a minimum
   payment amount per coin that floats with network fees, and **XMR's is among
   the highest.** We send a **USD-priced** invoice and the payer picks the coin on
   the hosted page, so we cannot pre-check the floor — a too-low amount fails
   there with "Crypto amount … is less than minimal". Therefore the **cheapest
   duration must be priced high enough to clear XMR's minimum** (test it; leave
   headroom), or XMR payers can't buy that option. This is the real lower bound on
   membership pricing, not an app limit.

### USD off-ramp (operational, not code)

No hosted processor cleanly does "accept Monero **and** auto-deposit USD to a US
bank." The supported pattern for the nonprofit is **two-step**:

1. Configure NOWPayments to **auto-convert** incoming crypto to **USDC**,
   delivered to a wallet the org controls (non-custodial).
2. Move USDC to a **US-regulated exchange business/nonprofit account**
   (Coinbase or Kraken) → sell 1:1 to USD → **free ACH** to the US bank.

Pre-launch checklist (see also the launch plan):

- Get **written confirmation** from NOWPayments that a US 501(c)(3) may use the
  non-custodial merchant flow (their ToS restricts US persons; the non-custodial
  flow routes funds straight to your wallet, but confirm in writing).
- Open the Coinbase/Kraken nonprofit account (EIN + 501(c)(3) letter), confirm
  USDC deposit + free USD ACH.
- Re-check XMR support quarterly (MiCA/AMLR pressure on privacy coins is moving).

## BTCPay Server setup (self-hosted Bitcoin rail — on-chain + Lightning)

Unlike the hosted rails, BTCPay runs on the **operator's own server**: payments
settle directly to the org's node/wallet with no intermediary, no third-party
ToS, and no off-ramp dependency for the Bitcoin leg. Invoices are created via
the Greenfield API; the payer gets BTCPay's hosted checkout page (on-chain
address + Lightning invoice side by side).

1. On your BTCPay Server: create (or reuse) a **store**, connect the wallet
   and/or Lightning node, and note the **store ID** (Store Settings → General).
2. Create a **restricted API key** (Account → Manage API keys) scoped to just
   `btcpay.store.cancreateinvoice` for that store — the control plane only ever
   creates invoices.
3. Register a **store webhook** (Store Settings → Webhooks): URL
   `https://<PUBLIC_BASE_URL host>/api/webhooks/btcpay`, a strong random
   secret, and the invoice events (settled/processing/expired/invalid — "send
   all events" also works; non-invoice events are acked and ignored).
4. Set the Convex env (`bunx convex env set`) or paste the values into Admin →
   Billing → Processor credentials:
   - `BTCPAY_API_URL` — your BTCPay origin, e.g. `https://pay.example.org`.
   - `BTCPAY_STORE_ID` — the store id from step 1.
   - `BTCPAY_API_KEY` — the restricted key from step 2.
   - `BTCPAY_WEBHOOK_SECRET` — the webhook secret from step 3. While unset,
     `/api/webhooks/btcpay` answers a distinct `503 billing.not_configured`.
   - `PUBLIC_BASE_URL` — required for any rail (return URL construction).
5. In Admin → **Billing**: enable the **Bitcoin (BTCPay)** rail.
6. **Webhook auth:** the `BTCPay-Sig` header is `sha256=<hex>` = HMAC-SHA256 of
   the raw body with the webhook secret
   (`convex/lib/processors/btcpay.ts:verifyAndParse`). Our opaque order ref
   rides in the invoice's `metadata.orderId` and is echoed on every event.
   Status mapping: `InvoiceSettled`→paid;
   `InvoiceProcessing`/`InvoiceReceivedPayment`/`InvoicePaymentSettled`→confirming;
   `InvoiceCreated`→pending; `InvoiceExpired`→expired; `InvoiceInvalid`→failed.
7. **Minimum term:** `btcpayMinMonths` (Admin → Billing) defaults to **1** —
   Lightning has no meaningful floor. If you run on-chain-only, consider raising
   it (or your store's BTCPay policy) so fees don't dwarf small payments.
8. **Redelivery:** BTCPay retries failed webhook deliveries and offers manual
   redelivery per event in the store's webhook UI — combined with the
   per-(invoice, event-type) dedupe id, replays are safe.

## Stripe setup (Phase 2)

Hosted **Checkout Session** via redirect (never Stripe.js/Elements — CSP). Env:
`STRIPE_API_KEY`, `STRIPE_WEBHOOK_SECRET`. Webhook verifies the `Stripe-Signature`
header (timestamp + `v1` HMAC-SHA256 over `${t}.${body}`). Event
`checkout.session.completed` → paid. One-time payments only (no auto-renew
subscriptions in v1). No Stripe SDK — plain `fetch` keeps the code in the V8
isolate.

## PayPal setup (Phase 3)

Orders API v2 via redirect. Env: `PAYPAL_CLIENT_ID`, `PAYPAL_SECRET`,
`PAYPAL_WEBHOOK_ID`, `PAYPAL_API_BASE` (sandbox vs live). Webhook authenticity is
verified via PayPal's `POST /v1/notifications/verify-webhook-signature`.
**Operational risk:** PayPal has a documented history of freezing
VPN/circumvention-adjacent merchants with 180-day holds — enable it last, sweep
the balance frequently, and treat the account as expendable.

## Refunds

- **Unredeemed / not-yet-paid:** nothing to do; the order expires.
- **NOWPayments (non-custodial):** there is no processor-side refund button —
  refunds are sent manually from the org wallet. Build it into ops.
- **Already-granted membership:** downgrade via the lifecycle seam (admin tier
  change / `setMembership`); the audit log records it. In-app refund issuance is
  out of scope for v1.

## Rate limits

- `billing.checkout` — 10/hr per member (each call creates a hosted invoice).
- `webhook.nowpayments.ip` — 120/min per IP (one payment fires several IPNs).
- `webhook.btcpay.ip` — 120/min per IP (several invoice events per payment).

Both are admin-tunable in Admin → Rate limits (no deploy).

## Tests

`convex/billing.test.ts` (domain) + the billing blocks in `convex/http.test.ts`
(routes): HMAC-SHA512 vector, checkout order binding, finished→single grant,
dedupe, confirming-no-grant, bad-signature rejection, unknown-ref ACK, payload
redaction, userId-scoped polling, and the route 401/429/503/400/200/413 matrix.
