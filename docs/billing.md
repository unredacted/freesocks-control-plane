# Billing — self-service membership purchases

FreeSocks members can buy a fixed-term **FreeSocks membership** (the single paid
tier: unlimited bandwidth + devices) by paying with crypto (Monero + many coins,
via **NOWPayments**), card (**Stripe**), or **PayPal**. Every rail is a full-page
**redirect to a processor-hosted page** — the strict CSP forbids an embedded
payment SDK, and a redirect is also the lower-PCI-scope option.

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

- **Adapters** — `convex/lib/processors/{types,nowpayments,stripe,paypal}.ts`:
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
  are swept to `expired` after `BILLING_PENDING_TTL_HOURS` (default 48).

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

Both are admin-tunable in Admin → Rate limits (no deploy).

## Tests

`convex/billing.test.ts` (domain) + the billing blocks in `convex/http.test.ts`
(routes): HMAC-SHA512 vector, checkout order binding, finished→single grant,
dedupe, confirming-no-grant, bad-signature rejection, unknown-ref ACK, payload
redaction, userId-scoped polling, and the route 401/429/503/400/200/413 matrix.
