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

`pending` → (`confirming`) → `paid` | `failed` | `expired` | `underpaid`

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
- `underpaid`: the money arrived but short of the price by more than the
  underpayment tolerance (see below). Nothing is granted, and the sweep never
  expires it: it waits on Admin → Billing for the operator to grant or dismiss.
  It outranks `expired`, so a short payment landing on an already-swept order
  is still held. A refund/reversal (`failed`) closes it, and a late
  out-of-order partial event can't reopen a `failed` order. A top-up payment (a
  later full `paid` event on the same invoice) grants it.

### Underpayments (exchange withdrawal fees)

The common short payment is not price movement: the payer sends from an
exchange that takes its flat withdrawal fee **out of** the amount it sends (the
two reports that prompted this were short by exactly 2 TRX and exactly 0.2 XTZ).
Price movement can't cause it, because the processors judge the coins received
against the coins quoted. So:

- **Tolerance.** `underpaymentTolerancePct` (Admin → Billing, 0 to 10, default
  **5**) is how far short a crypto payment may arrive and still grant. It is
  measured in the **paid coin** (`actually_paid / pay_amount` on NOWPayments,
  `totalPaid / amount` from the invoice's payment methods on BTCPay), so rate
  drift doesn't count against the payer. 5% covers a flat fee on the cheapest
  crypto term ($14, 3 months); the worst a deliberate underpayer gains is 5%.
- **Within the tolerance** the order grants as usual and is audited
  `billing.underpayment_accepted` (with `paidPermille` and `tolerancePct`); the
  order records `paidRatio`. The membership or gift is delivered in full, but a
  donation (standalone or riding along) is credited only for the share that
  arrived (`floor(donationCents x paidRatio)`), written back as the order's
  `donationCents` so a later refund unwinds exactly that.
- **Beyond it**, or when the shortfall can't be measured (amounts missing), the
  order is held as `underpaid` and audited `billing.underpayment_seen`. The
  member's return page tells them the payment arrived short and to contact
  support with their Support ID (the donate page says it will be reviewed).
- **Resolving by hand.** Admin → Billing shows a banner and an `underpaid`
  filter. Each held order offers **Grant** (deliver what it bought, exactly the
  grant a full payment gets) and **Dismiss** (close it as `failed` once you have
  refunded or settled it another way). Dismissal is terminal: it stamps
  `dismissedAt`, and any later payment event for that order is refused and
  audited `billing.grant_refused` (`reason: dismissed`). **Grant** is also offered on a
  `pending` / `confirming` / `expired` order, for a payment the processor shows
  but FCP never saw settle (a webhook that never arrived, or a short payment
  from before the tolerance existed); never on `paid` or `failed`. A gift
  order's codes go to the **buyer's own account**, exactly as for a normal
  purchase: the grant stores them in the order's one-time reveal, and the
  buyer's `/account` opens it on their next visit (see "Gift purchases"). The
  operator never sees them, so the grant response carries order facts only.
  Route: `POST /api/v1/admin/billing/orders/{id}/grant|dismiss`
  (`admin:users:write`, and a passkey admin session only, like code minting: a
  gift grant mints transferable codes, so an `fsv1_` token gets 403); audited
  `admin.billing.order_granted` / `admin.billing.underpaid_dismissed`. A held
  order keeps the best `paidRatio` measured so far (a further short payment
  raises it).
- **Prevention.** Checkout shows a note on the crypto rails: an exchange may take
  its withdrawal fee out of the amount it sends, so add the fee.

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
  event carries no amount, so the adapter **re-reads the invoice** on settle to
  recover one (needs `btcpay.store.canviewinvoices` — see the BTCPay setup
  section); when that read is unavailable the checkout-id binding is the only
  guard left, and the grant is audited as `billing.settle_detail_unavailable`.

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
   `GiftRevealModal`), and acknowledges saving them, which clears the buffer. If
   the codes were minted after the buyer left the return page (a slow crypto
   confirmation, a top-up, an operator's grant), the account view carries the
   order as `pendingGiftOrderRef` (`billing.pendingGiftReveal`) and `/account`
   opens the same reveal on their next visit. The
   **`billing-gift-reveal-sweep`** cron (hourly) clears any un-acknowledged buffer
   `BILLING_GIFT_REVEAL_TTL_HOURS` (default 24) after **payment** (`paidAt`, not
   order creation), so plaintext gift codes never linger at rest and a late
   payment still gets its full window.
4. Recipients redeem a code exactly like an admin-minted membership code (Account
   → redeem), extending their own membership by the purchased duration.

Gift codes are bearer credentials (anyone holding one can redeem it), so the
reveal-once + sweep design keeps the plaintext out of long-term storage. The buyer
manages their codes from the `GiftCodes` backend.

## Referral rewards

The referral program (`convex/referrals.ts`) is billing-adjacent, not a rail: it
never touches a processor. Every member has a shareable `FSR-XXXX-XXXX` code; a
new account that signs up with it (`POST /api/v1/account` takes an optional
`referralCode`, surfaced as `referralApplied`) binds to the referrer (one
referrer per referee, stored in the `referrals` table).

Rewards vest ONLY on the referee's **first paid-tier grant** — and the trigger is
deliberately rail-agnostic: a settled order on ANY processor, a gift/redemption
code redemption, or an admin grant all count, because they all flow through the
single `applyMembership` entitlement seam (which schedules
`referrals.maybeConvert`; grants made BY referral rewards — `reason
'referral.*'` — deliberately do NOT cascade, so no multi-level reward chains
appear without real money). On conversion:

- the **referee** gets `referral.refereeBonusDays` added to the just-granted
  membership, immediately;
- the **referrer's** `referral.referrerBonusDays` **vests** after
  `referral.vestingDays` — checked at vest time, the referee must still be a
  live member (kills buy-and-vanish self-referrals) — bounded per calendar
  month by `referral.maxRewardsPerMonth`. The reward tier is the deployment's
  membership tier (`billing.membership.tierSlug`); if it can't be resolved the
  reward voids with an audit, never a crash.

Config lives in the `referral.*` appSettings namespace (Admin → Billing →
"Referral program" card, `/api/v1/admin/referrals/config`; default ON — unlike
the rails it needs no external keys/prices to function). The public knobs
(`enabled` + the bonus-days numbers for honest copy) ride `publicConfig.referrals`;
the member's share link + stats are on the Account page
(`GET /api/v1/account/referrals`, rate-limited `account.referrals`). All
transitions audit (`referral.bound/converted/rewarded/void`, with `voidReason`).

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
account Membership tab's impact backend (`MemberImpact.svelte`, every membership
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
   `finished`/`partially_paid`→paid, `confirming`/`confirmed`/`sending`→confirming,
   `waiting`→pending, `failed`/`refunded`→failed, `expired`→expired. A paid
   event whose `actually_paid` is below `pay_amount` (or lacks either) is
   flagged as an underpayment and decided against the tolerance (see
   "Underpayments" above). Set NOWPayments' own **Payment covering** (dashboard,
   0 to 10%) to the same value as `underpaymentTolerancePct` so its dashboard
   agrees with FCP; FCP decides from the amounts either way, so marking a short
   payment `finished` in their dashboard does not by itself grant it.
   **HMAC-mismatch postback fallback:** the verifier's canonicalization is a
   reconstruction of NOWPayments' serializer (PHP escaping, `N.0` float combos)
   and cannot cover every number rendering, so a mismatched IPN that carries a
   `payment_id` is re-verified by fetching that payment straight from
   `GET /v1/payment/{id}` (api key) and building the event from the
   AUTHORITATIVE response — the IPN body is discarded. A postback logs a
   `[billing] nowpayments IPN HMAC mismatch … verified via API postback`
   warning; if you see it recur, check the IPN secret first.
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
   delivered to a wallet the org controls (non-custodial). In the NOWPayments
   dashboard (Store Settings → Outcome Wallet) make the USDC wallet the **only**
   outcome wallet: a coin that has its own wallet is paid out in that coin, and
   a coin with none goes to the first wallet entered. NOWPayments charges 1%
   without an exchange and 1.5% when one is needed, plus network fees on both
   the deposit and the payout leg.
2. Move USDC to a **business account at a US-regulated exchange** (Coinbase
   Business or Kraken) → sell USDC for USD → **ACH** to the org's US bank
   account (the bank account name must match the exchange account name).
   Neither exchange has a separate nonprofit account type, and the conversion
   is not free on either: Coinbase Business says USDC to USD conversion is
   subject to a fee, and Kraken Pro charges 0.20% on stablecoin pairs at the
   lowest volume tier. Kraken ACH withdrawal is free; Coinbase's Business ACH
   page states no fee. Read the live fee screen before relying on a number.

Pre-launch checklist (see also the launch plan):

- Get **written permission** from NOWPayments before relying on it. Its Terms of
  Service (section 15.1) say the services are not rendered to residents or
  citizens of the United States and carve out neither nonprofits nor the
  non-custodial flow, and it can end an account at any time without reasons.
  Until NOWPayments confirms in writing that a US-organized 501(c)(3) may use
  it, treat the rail as not permitted, and give accurate entity and business
  details in every registration or question.
- Open the exchange business account and confirm USDC deposit, the USDC to USD
  sell fee and the USD ACH withdrawal on the live account:
  - **Coinbase Business** is listed for C corporations and LLCs, so ask whether a
    nonprofit corporation qualifies, and get Coinbase's written consent for
    accepting donations for a nonprofit (its Prohibited & Conditional Use
    Policy). It asks for ID for the applicant, the control person and each 25%
    owner, filed formation documents, a business bank statement under 90 days
    old, the EIN and W-9, and a description of the business.
  - **Kraken** offers a business account with an NGO business type. It asks for
    formation documents, proof of operating address under 3 months old, IDs for
    beneficial owners, controllers and every account accessor, two AML
    questionnaires and source of funds. ACH needs a US-registered account and
    is not offered to New York residents; ask whether that applies to a
    business.
  - Neither application lists the IRS determination letter. Keep it ready.
- Re-check XMR support quarterly (MiCA/AMLR pressure on privacy coins is moving).

## BTCPay Server setup (self-hosted Bitcoin rail — on-chain + Lightning)

Unlike the hosted rails, BTCPay runs on the **operator's own server**: payments
settle directly to the org's node/wallet with no intermediary and no third-party
ToS. It is also the only rail whose checkout page loads **zero third-party
subresources** — the payer reaches exactly one host, ours — which is why it is
the primary rail for censored regions. Converting what it receives into USD is a
separate job with no BTCPay-native support; see "USD off-ramp" above (it covers
only the NOWPayments leg) and `docs/btcpay-server-runbook.md` section 8.

**Minimum server version: BTCPay 2.4.2** (with NBXplorer ≥ 2.6.10). Everything
below 2.4.2, release candidates included, has an actively-exploited LND macaroon
disclosure bug with confirmed fund theft. Provisioning, upgrades and the key
inventory live in **`docs/btcpay-server-runbook.md`**. Invoices are created via
the Greenfield API; the payer gets BTCPay's hosted checkout page (on-chain
address + Lightning invoice side by side).

1. On your BTCPay Server: create (or reuse) a **store**, connect the wallet
   and/or Lightning node, and note the **store ID** (Store Settings → General).
2. Create a **restricted API key** (Account → Manage API keys) for that store
   with **both** of these permissions:
   - `btcpay.store.cancreateinvoice` — creating the invoice.
   - `btcpay.store.canviewinvoices` — reading it back. **Not optional.** On every
     `InvoiceSettled` the adapter re-reads the invoice to recover the amount and
     the settle state, and its payment methods to measure what was actually
     paid, because the webhook carries neither
     (`convex/lib/processors/btcpay.ts:invoiceDetail` / `invoicePaidRatio`).
     Without this permission those reads 403 and **the settle grants with the
     amount + underpayment checks disabled**: an invoice settled short (by a
     looser store default, or marked settled by hand) could then grant. The same permission
     backs the Admin → Billing credential probe. When the read fails, the grant
     is audited as `billing.settle_detail_unavailable`; if you see that action,
     this is why.

   Do **not** reuse this key for the off-ramp agent — that one needs payout and
   Lightning permissions the control plane must never hold. See
   `docs/btcpay-server-runbook.md` for the full key inventory.

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

   Underpayments: on `InvoiceSettled` the adapter measures the paid fraction from
   the invoice's payment methods (`totalPaid / amount`); a short settle is
   decided against the tolerance like NOWPayments (see "Underpayments" above).
   When the payment methods can't be read, `additionalStatus: PaidPartial` is
   the fallback signal and holds the order (no ratio, never grants). An
   `InvoiceExpired` with `partiallyPaid: true` (money arrived, BTCPay never
   accepted it, possibly unconfirmed) is always held as `underpaid`, never
   granted. This is what step 2's `canviewinvoices` permission makes possible.

7. **Minimum term:** `btcpayMinMonths` (Admin → Billing) defaults to **1** —
   Lightning has no meaningful floor. If you run on-chain-only, consider raising
   it (or your store's BTCPay policy) so fees don't dwarf small payments.
8. **Checkout behavior** (Admin → Billing, all three admin-editable without a
   deploy). BTCPay's own defaults are tuned for a payer who already holds
   bitcoin; ours are not, so these override them per invoice:
   - **Invoice expiry** — default **90 min** (BTCPay's own default is 15, which
     expires before someone in a censored region can acquire crypto and send it).
   - **Late-payment monitoring** — default **1440 min**. How long past expiry
     BTCPay keeps watching, so a late payment isn't money the payer already sent
     into a dead invoice.
   - **Default payment method** — blank unless the store offers more than
     Bitcoin. Checkout v2 shows one unified BIP21 QR for on-chain + Lightning,
     but any non-Bitcoin chain reintroduces a payer-facing coin selector, and
     this decides where it lands (e.g. `BTC-LN`).

   - **Payment tolerance** — not a separate BTCPay knob: every invoice is created
     with `checkout.paymentTolerance` = the billing `underpaymentTolerancePct`,
     so BTCPay settles (after its confirmations) exactly the payments FCP would
     grant. FCP still re-measures the shortfall on settle and checks it against
     the CURRENT tolerance, so a looser store default or a since-lowered
     setting can't grant more than FCP allows.

9. **Verify before going live:** Admin → Billing → **Test connection** on the
   BTCPay rail (`POST /api/v1/admin/billing/test-connection`) checks **both**
   permissions from step 2, and creates nothing:
   - `GET /stores/{storeId}/invoices?take=1` — the API URL, key, store id and
     `canviewinvoices` in one call. A key scoped per an older runbook fails here
     instead of passing and then 403-ing at settle time.
   - `POST /stores/{storeId}/invoices` with a deliberately **unbindable** body —
     `cancreateinvoice`, without minting an invoice. BTCPay authorizes before it
     binds the body, so a key without the permission answers 403 while a key with
     it answers 400 and nothing is created.

   Run it after any credential change. Two deliberate non-goals: it does not read
   `GET /stores/{storeId}` (that needs `canviewstoresettings`, a third permission
   the control plane never uses) and it does not read the key's own permission
   list (`GET /api/v1/api-keys/current` needs the **server-level**
   `btcpay.server.canmanageusers`). Either would mean over-granting the key that
   lives on the public host. The two permissions in step 2 are all this rail
   needs — and all it should have.

   On an unexpected status from the create probe the check **passes**: only a 403
   proves the permission is absent, and a missing `cancreateinvoice` fails loudly
   and harmlessly at checkout (the member sees an error, nothing is granted),
   whereas a false failure would block a correctly-configured operator.

10. **Redelivery:** BTCPay retries failed webhook deliveries and offers manual
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
