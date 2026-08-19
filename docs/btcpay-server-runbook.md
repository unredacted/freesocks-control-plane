# BTCPay Server runbook (provisioning, keys, upgrades)

The **server** side of the self-hosted Bitcoin rail. FCP's half — invoice creation,
webhook verification, the admin config — is `docs/billing.md` § "BTCPay Server setup";
this file is the machine that runs BTCPay itself.

Why this rail matters: BTCPay's checkout page loads **zero third-party subresources**
(fonts are bundled, no analytics, the payment WebSocket is built from
`window.location.host`), so the payer reaches exactly one host — ours. Every other rail
sends them to a domain we don't control, which for users in censored regions is
frequently a domain that does not load. It is also the only rail with no third-party
terms of service to be offboarded from.

> **Minimum version: 2.4.2, with NBXplorer ≥ 2.6.10.** Everything below 2.4.2 —
> release candidates included — carries an unauthenticated LND `.macaroon`
> disclosure bug that was **actively exploited with confirmed fund theft**
> ([advisory](https://blog.btcpayserver.org/security-advisory-btcpay-server-2-4-2/)).
> Do not stand up an older version "just to test".

## 1. Host

Run BTCPay on a **dedicated host**. Do **not** add it to `docker-compose.stack.yml`.

The control plane is a public web service with a large attack surface; BTCPay holds
wallet keys and (later) an exchange API key. Co-locating them means one web
compromise reaches the money. Keep them on separate machines with no shared secrets.

Use the standard [`btcpayserver-docker`](https://github.com/btcpayserver/btcpayserver-docker)
deployment. Sizing depends on which chains you enable — see §5.

## 2. Hostname

`pay.freesocks.org`. Point an A/AAAA record at the host before first boot so the TLS
cert can issue.

```sh
BTCPAY_HOST=pay.freesocks.org
```

Four things that bite here, in the order people hit them:

- **`checkoutLink` comes from `BTCPAY_HOST`, not the store's "Store URL" setting.** FCP
  redirects the payer to whatever `checkoutLink` the API returns
  (`convex/lib/processors/btcpay.ts` → `InvoiceResponse.checkoutLink`). If it points at
  the wrong hostname, fix `BTCPAY_HOST` — changing store settings will not help. **Test
  this first**, before anything else: create an invoice and look at the returned link.
- **Behind a reverse proxy**, also set `BTCPAY_ADDITIONAL_HOSTS` to the serving domain,
  and make sure the proxy forwards `X-Forwarded-Proto`. Get that header wrong and BTCPay
  emits `http://` links on an HTTPS site, which breaks the redirect and trips
  mixed-content blocking.
- **Leave `BTCPAY_ROOTPATH` alone.** It is only for subdirectory hosting
  (`example.com/btcpay/`), and a value without a trailing slash triggers a known
  bad-post-login-redirect bug. On a dedicated hostname you never need it.
- **The hostname is not secret.** The moment Let's Encrypt issues a cert, the exact name
  is published to public Certificate Transparency logs. Don't treat `pay.` as obscurity.

### A note on the subdomain choice

`pay.freesocks.org` shares a parent with a domain that has **4 confirmed blocks in Iran**
across ~1,000 OONI probes. Iranian filtering matches by name per-AS, and whether it
matches parent domains is unmeasured, so the payment host may or may not share the main
domain's fate. This was a deliberate call for operational simplicity and user
recognizability. If payment reachability degrades, the mitigation is a **separate apex
domain** (not another subdomain) swapped in via `BTCPAY_API_URL` in Admin → Billing.

## 3. Store and wallet

1. Create a store. Note the **store ID** (Store Settings → General).
2. Connect an on-chain wallet and/or a Lightning node.
3. **Wallet posture.** Above modest balances, prefer **watch-only + hardware signing**.
   The trade-off is explicit: a watch-only store cannot run BTCPay's automated on-chain
   payout processor, so sweeps to the exchange stay manual. That is an acceptable price,
   and arguably the right default — an automated hot wallet on an internet-facing host is
   exactly what the 2.4.2 advisory drained.
4. Set the store's **Checkout Appearance** to match the invoice defaults FCP sends
   (Admin → Billing): 90-minute expiry, and whichever payment methods you enable in §5.

## 4. API keys — three of them, never fewer

Create these as **separate** keys (Account → Manage API keys), each scoped to the one
store. The whole point is that a leak of one does not become a leak of the others.

| Consumer                                     | Permissions                                                                                         | Why exactly these                                                                               |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| **FCP control plane**                        | `btcpay.store.cancreateinvoice`, `btcpay.store.canviewinvoices`                                     | Creates invoices, and reads them back on settle. The read-back is **not optional** — see below. |
| **Off-ramp agent** (future, `ops/autosell/`) | `btcpay.store.canmanagepayouts`, `btcpay.store.canuselightningnode`, `btcpay.store.canviewinvoices` | Moves funds to the exchange. The control plane must never hold payout or Lightning permissions. |
| **Human operator**                           | the master key                                                                                      | Never used by software.                                                                         |

**Why the control-plane key needs `canviewinvoices`.** A BTCPay `InvoiceSettled` webhook
carries neither the amount nor the settle state, so the adapter re-reads the invoice
(`invoiceDetail` in `convex/lib/processors/btcpay.ts`) to run two guards: the amount
cross-check, and the `PaidPartial` check that refuses to grant on a part-paid invoice
settled under a store tolerance. Without the permission, that read 403s and returns
`null` — **and the settle still grants**, with both guards silently disabled.

That failure is now audited as `billing.settle_detail_unavailable`, and the Admin →
Billing **Test connection** probe fails on an under-scoped key. If you see either, this
is the cause. (Documentation before 2026-08 advised invoice-create only; installs built
from it are under-scoped.)

**Two permissions is the whole list — resist adding a third.** The probe reads
`GET /stores/{storeId}/invoices?take=1`, which validates the URL, key, store id and
`canviewinvoices` in one call, precisely so it tests what the runtime uses and nothing
more. Reading `GET /stores/{storeId}` would need `canviewstoresettings` as well, which
the control plane never uses — granting it just to satisfy a probe would widen the blast
radius of the key that lives on the public host.

## 5. Chains

Enable these in waves, verifying each with a canary deposit before raising limits.
The operational facts per chain:

| Asset                                      | How                                                                                    | Cost                                                                                                                                                                                                                   |
| ------------------------------------------ | -------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| BTC on-chain + Lightning                   | Native (`BTCPAYGEN_CRYPTO1="btc"`)                                                     | Baseline. One unified BIP21 QR at checkout, no coin selector.                                                                                                                                                          |
| USDT (TRON / ERC20 / Polygon)              | [Tether USDt plugin](https://github.com/btcpayserver-tether/BTCPayServer.Plugins.USDt) | **No node** — a JSON-RPC endpoint per chain (e.g. TronGrid) is enough. Plugin is **0.x, flagged pre-release**; min BTCPay 2.3.7. Verify whether it derives a fresh address per invoice before trusting reconciliation. |
| Monero                                     | [Monero plugin](https://github.com/btcpay-monero/btcpayserver-monero-plugin)           | Needs **both** `monerod` and `monero-wallet-rpc`. Significant disk and RAM; put chain data on separate storage. Community guidance is explicit that this is not for non-advanced operators.                            |
| Native altcoins (LTC, DOGE, DASH, LBTC, …) | `BTCPAYGEN_CRYPTO2..9`, max 9                                                          | **A full node per chain**, plus an NBXplorer instance each. Disk and RAM scale linearly.                                                                                                                               |
| Zcash                                      | Plugin                                                                                 | ~10 months stale as of 2026-08. Check it has caught up before enabling.                                                                                                                                                |

Two things to internalize:

- **`USDT-BEP20` is not available at any price.** The Tether plugin does TRON, ERC20 and
  Polygon only. BEP20 is the chain Iranian exchanges actually have enabled (Nobitex and
  Wallex have both suspended TRC20), so Iran has **no BTCPay path** — that traffic goes
  to NOWPayments or is reconciled by hand.
- **Adding the first non-Bitcoin chain costs checkout UX.** Checkout v2 deliberately
  removed the tabbed payment-method picker in favor of one BIP21 QR, which only works
  within Bitcoin. A USDT address cannot share that URI, so the payer gets a coin selector
  back. The first non-BTC chain is the expensive step; each one after is cheap. Mitigate
  with the **Default payment method** field in Admin → Billing.
- **Any non-BTC rail can be removed from under you.** BTCPay's stated policy is that
  unmaintained altcoin integrations get deleted — Monero and Zcash were both moved out of
  core in 2.1.0. See §7.

## 6. Backups

Back up, and test a restore before the store handles real money:

- The **wallet seed / xpub** — offline, off-host, on paper or metal. Nothing else here
  matters if this is lost.
- **Lightning channel state** (`static channel backup` for LND). Channel state is not
  reconstructible from the seed.
- The **BTCPay Postgres database** (invoices, store config, webhook secrets). Losing it
  loses the audit trail even though the coins survive.

## 7. Upgrades

1. **Check every installed plugin's max supported version first.** Plugins pin a
   compatibility ceiling and a core upgrade past it disables them. Live example: the
   Strike plugin advertises support to **v2.3.6** against a 2.4.2 target.
2. Read the changelog for breaking changes. Relevant recent ones: **2.4.2** disabled
   Greenfield **Basic authentication** by default 5 minutes after account creation — FCP
   is unaffected because it authenticates with `Authorization: token <key>`, but any
   Basic-auth integration breaks. **2.4.0** dropped LNBank and Lightning Charge backends.
   **2.1.0** moved Monero and Zcash out of core into plugins. **2.0.0** removed the
   experimental custodian/exchange feature entirely.
3. Upgrade, then re-run Admin → Billing → **Test connection** and put a real invoice
   through end to end.

### After running any version below 2.4.2

Patching stops new access; it does **not** invalidate credentials already stolen. If the
host ever ran a vulnerable version with LND reachable, assume compromise:

- **Rotate LND macaroons.** (2.4.2 regenerates them on standard installs — confirm it
  did on yours.)
- **Move funds out of any BTCPay-generated on-chain hot wallet.**
- Audit node activity for unfamiliar peers, unexpected channel closures, and payments you
  did not make.

## 8. Off-ramp

Getting received crypto into USD is a **separate service** — there is nothing to enable
in BTCPay. Its Custodian Accounts framework and Kraken plugin were **removed in 2.0.0**,
API endpoints included, and `btcTransmuter` (which had a sell-on-invoice-settled trigger)
is an archived repository. Any guide describing either is describing software that no
longer ships.

The intended design is an agent under `ops/autosell/` running **on this host**, with a
trade-only exchange key, batched sweeps, and a **manual** fiat withdrawal so that no
withdraw-capable key exists anywhere. Until it ships, sweeping and selling are done by
hand; the runbook for both will be `docs/finance-offramp.md`.

## 9. Bring-up checklist

- [ ] Dedicated host, not the FCP stack
- [ ] BTCPay ≥ 2.4.2, NBXplorer ≥ 2.6.10
- [ ] DNS for `pay.freesocks.org` resolves; TLS cert issued
- [ ] `BTCPAY_HOST` set; `BTCPAY_ROOTPATH` untouched; `X-Forwarded-Proto` forwarded if proxied
- [ ] **An invoice's `checkoutLink` points at `pay.freesocks.org`**
- [ ] Store created, wallet and/or Lightning node connected, wallet posture decided
- [ ] Seed, channel backup, and database backups taken **and a restore tested**
- [ ] Three separate API keys created with the permissions in §4
- [ ] Store webhook registered → `https://<PUBLIC_BASE_URL host>/api/webhooks/btcpay`
- [ ] FCP configured (Admin → Billing) and **Test connection** passes
- [ ] Rail enabled; a real invoice paid end to end from `/account`
- [ ] `billing.settle_detail_unavailable` does **not** appear in the audit log afterwards
- [ ] Canary swept and sold by hand, all the way to the bank, before raising any limits
