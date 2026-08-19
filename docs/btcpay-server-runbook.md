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
deployment.

**Sizing.** Driven almost entirely by how much of the Bitcoin chain you keep. The
`opt-save-storage*` fragments set Bitcoin Core's `prune` in MiB:

| Fragment               | `prune=` | Blocks kept | Lightning-safe?            | Disk to provision |
| ---------------------- | -------- | ----------- | -------------------------- | ----------------- |
| _(none)_               | off      | all         | yes                        | 1 TB+, growing    |
| `opt-save-storage`     | 100000   | ~1 year     | yes                        | ~200 GB           |
| `opt-save-storage-s`   | 50000    | ~6 months   | yes (BTCPay's own example) | ~150 GB           |
| `opt-save-storage-xs`  | 25000    | ~3 months   | marginal                   | ~100 GB           |
| `opt-save-storage-xxs` | 5000     | ~2 weeks    | **no**                     | ~60 GB            |

The fragments' own comments warn that a pruned node's Lightning implementation
"won't be able to see channel created \<window\> since the time you start it", so do
not go below `-s` while running Lightning. **Recommendation: `opt-save-storage`**
(~1 year) — one notch above BTCPay's example, because the marginal disk is far
cheaper than a Lightning channel we cannot see. Add ~2 GB RAM per extra chain, and
put chain data on its own volume.

**Ports that must be reachable:** `80` and `443` (ACME + the checkout page) and
**`9735`** for Lightning. Nothing else. `9735` is easy to forget and its absence
looks like "Lightning just doesn't get channels" rather than a firewall problem.

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

## 2a. Install

Per the [official Docker guide](https://docs.btcpayserver.org/Docker/), with three
deliberate deviations noted below. DNS for `pay.freesocks.org` must resolve to this host
**before** you run it, or ACME cannot issue.

```sh
sudo su -
mkdir -p /root/BTCPayServer && cd /root/BTCPayServer
git clone https://github.com/btcpayserver/btcpayserver-docker
cd btcpayserver-docker

export BTCPAY_HOST="pay.freesocks.org"
export NBITCOIN_NETWORK="mainnet"
export BTCPAYGEN_CRYPTO1="btc"
export BTCPAYGEN_REVERSEPROXY="nginx"
export BTCPAYGEN_LIGHTNING="clightning"
export BTCPAYGEN_ADDITIONAL_FRAGMENTS="opt-save-storage"
export LETSENCRYPT_EMAIL="ops@freesocks.org"
export BTCPAY_ENABLE_SSH=false

. ./btcpay-setup.sh -i
exit
```

Then browse to `https://pay.freesocks.org`, create the admin account **immediately**
(the first account to register becomes admin — an exposed, un-registered instance is
a free admin account for whoever finds it first), and enable 2FA on it.

### The three deviations from BTCPay's example, and why

1. **`BTCPAY_ENABLE_SSH=false`** (BTCPay's example sets it `true`). That flag "gives
   BTCPay Server SSH access to the host by allowing it to edit `authorized_keys`",
   which turns any web-layer compromise of BTCPay into host access. On a box holding
   wallet keys that trade is bad on its own terms, and 2.4.2 was precisely a
   web-reachable pre-auth bug in this software. Cost: updates are a manual `btcpay-update.sh`
   over SSH instead of a button in the UI (§7). Worth it.
2. **`clightning`, not `lnd`.** Both are supported and CLN is BTCPay's own example.
   The deciding factor is that the actively-exploited 2.4.2 bug was an **LND macaroon**
   disclosure; per the advisory, CLN and Eclair users were not exposed to that class.
   Choosing the implementation that was not the blast radius is free here.
3. **`opt-save-storage`, not `-s`.** One notch more retained chain (~1 year vs ~6
   months) for ~50 GB, because a pruned window shorter than a channel's age makes that
   channel invisible to the node. See §1.

If the hostname ever has to change, use the bundled `changedomain.sh` — and **disable
2FA/U2F first**, since the domain is part of the WebAuthn origin and you will otherwise
lock yourself out.

## 3. Store and wallet

1. Create a store. Note the **store ID** (Store Settings → General).
2. Connect an on-chain wallet and/or a Lightning node.
3. **Wallet posture.** Above modest balances, prefer **watch-only + hardware signing**.
   The trade-off is explicit: a watch-only store cannot run BTCPay's automated on-chain
   payout processor, so sweeps to the exchange stay manual. That is an acceptable price,
   and arguably the right default — an automated hot wallet on an internet-facing host is
   exactly what the 2.4.2 advisory drained. **In this posture BTCPay only ever holds the
   xpub, which cannot spend — so the signing seed is backed up from the hardware device,
   not from BTCPay. See §6.1; getting this wrong loses the funds.**

   Note the scope: this applies to the **on-chain** wallet only. A Lightning node holds
   channel funds in keys it must be able to sign with unattended — there is no watch-only
   Lightning. So the honest posture is a watch-only on-chain wallet holding the bulk, plus
   a deliberately small Lightning balance treated as hot-wallet money, swept to the
   exchange often (§8).

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

**Two permissions is the whole list — resist adding a third.** The probe checks both of
them and nothing else: a `GET /stores/{storeId}/invoices?take=1` for `canviewinvoices`,
and a `POST` of a deliberately unbindable invoice body for `cancreateinvoice` (BTCPay
authorizes before binding, so a key without the permission 403s and no invoice is
created). It deliberately avoids `GET /stores/{storeId}` (needs
`canviewstoresettings`) and `GET /api/v1/api-keys/current` (needs the **server-level**
`btcpay.server.canmanageusers`) — granting either just to satisfy a probe would widen
the blast radius of the key that lives on the public host.

## 5. Chains

Enable these in waves, verifying each with a canary deposit before raising limits.

**Two different mechanisms, and conflating them wastes a day.** A `BTCPAYGEN_CRYPTO*`
fragment spins up that chain's **daemon** containers; a **plugin** supplies the
**payment method** BTCPay can invoice in. Some coins need one, some need both, and a
fragment existing in the repo does not mean the coin works — Monero and Zcash were moved
out of core in 2.1.0, so their fragments now provide only the daemons that their plugins
talk to. The `BTCPAYGEN_CRYPTO*` slots cap at **9**.

Verified against the fragment directory and plugin registry on 2026-08-19:

| Asset                                                                                                                        | Fragment                                   | Plugin                                                                          | Reality                                                                                                                                                                                                                |
| ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **BTC on-chain + Lightning**                                                                                                 | `btc`                                      | —                                                                               | Native, first-class. One unified BIP21 QR, no coin selector.                                                                                                                                                           |
| **USDT** — TRON / ERC20 / Polygon                                                                                            | none needed                                | [Tether USDt](https://github.com/btcpayserver-tether/BTCPayServer.Plugins.USDt) | **No node** — a JSON-RPC endpoint per chain (e.g. TronGrid) suffices. Plugin is **0.x, flagged pre-release**; min BTCPay 2.3.7. Confirm whether it derives a fresh address per invoice before trusting reconciliation. |
| **Monero**                                                                                                                   | `monero` (`monerod` + `monero-wallet-rpc`) | [Monero](https://github.com/btcpay-monero/btcpayserver-monero-plugin)           | Actively maintained plugin, heavy daemons. Community guidance is explicit this is not for non-advanced operators. Put chain data on its own volume.                                                                    |
| **Litecoin, Dogecoin, Dash, Groestlcoin, Liquid, Monacoin, Viacoin, Bitcore, Feathercoin, Trezarcoin, Bitcoin Gold, Decred** | one each                                   | —                                                                               | **A full node + NBXplorer per chain.** Disk and RAM scale linearly. Thin order books make the off-ramp manual.                                                                                                         |
| **Zcash**                                                                                                                    | `zcash` / `zcash-fullnode`                 | Zcash Support                                                                   | Plugin ~10 months stale as of 2026-08. Verify it has caught up before enabling.                                                                                                                                        |
| **Ethereum (native ETH)**                                                                                                    | `ethereum` exists                          | **none**                                                                        | Treat as **unsupported**. The fragment is vestigial — EVM payment support was removed and no payment-method plugin exists. USDT-on-ERC20 goes through the Tether plugin instead, which is a different thing.           |
| **USDT-BEP20**                                                                                                               | —                                          | —                                                                               | **Impossible.** See below.                                                                                                                                                                                             |

BTCPay's own Docker guide warns that going beyond its supported set means changes to
NBitcoin, NBXplorer and BTCPay core plus custom images — i.e. not an ops task at all.

Three things to internalize:

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

Back up all four of these, and test a restore before the store handles real money.

> **A seed and an xpub are NOT alternatives.** An xpub (or wallet descriptor)
> recreates a **watch-only** wallet: BTCPay can see balances and derive receive
> addresses, but nobody can **spend**. Only the signing seed recovers spend access.
> This matters most under the §3 watch-only posture that this runbook recommends,
> because there BTCPay never holds the seed at all — so "back up what BTCPay has"
> gets you the xpub and a wallet you can watch your own funds sit in, forever.

1. **The signing wallet's recovery seed** — the hardware device's BIP39 phrase, or the
   12 words BTCPay showed you if you let it generate a hot wallet. **Offline, off-host,
   on paper or metal. Never on the server, never in the password manager the server can
   reach.** This is the only artifact that recovers the ability to spend. Store
   alongside it, because a seed alone may not be enough:
   - the **BIP39 passphrase**, if the device uses one (a seed with a passphrase derives
     a completely different wallet — a forgotten passphrase loses the funds as surely as
     a lost seed);
   - the **derivation path** BTCPay was configured with, if it is not the default.

   Losing this while the hardware device still works is survivable — move the funds to a
   new wallet immediately. Losing it _and_ the device is unrecoverable, and no BTCPay
   backup changes that.

2. **The wallet descriptor or xpub** — a separate artifact, and a BTCPay _recovery_
   convenience rather than a fund backup. It restores the store's watching
   configuration without re-deriving from the seed, which makes a rebuild faster and
   avoids re-exposing the seed to a machine. Useful; not sufficient.

3. **Lightning channel state** (`static channel backup` for LND). Not reconstructible
   from the seed, and note what an SCB actually does: it lets you force-close channels
   to recover your balance, not resume operating them. Re-export it whenever channels
   change.

4. **The BTCPay Postgres database** (invoices, store config, webhook secrets). Losing
   it loses the audit trail and the store setup even though the coins survive — and for
   a nonprofit the invoice history is an accounting record, not just convenience.

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
3. Upgrade over SSH (the UI's update button is unavailable by design — §2a):

   ```sh
   sudo su -
   cd /root/BTCPayServer/btcpayserver-docker
   . ./btcpay-update.sh
   ```

4. Then re-run Admin → Billing → **Test connection** and put a real invoice through end
   to end.

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
- [ ] Disk sized per §1 (~200 GB for `opt-save-storage`), chain data on its own volume
- [ ] Ports 80, 443 **and 9735** reachable
- [ ] BTCPay ≥ 2.4.2, NBXplorer ≥ 2.6.10
- [ ] `BTCPAY_ENABLE_SSH=false`; Lightning is `clightning`, not `lnd`
- [ ] Admin account registered immediately after first boot, with 2FA enabled
- [ ] DNS for `pay.freesocks.org` resolves; TLS cert issued
- [ ] `BTCPAY_HOST` set; `BTCPAY_ROOTPATH` untouched; `X-Forwarded-Proto` forwarded if proxied
- [ ] **An invoice's `checkoutLink` points at `pay.freesocks.org`**
- [ ] Store created, wallet and/or Lightning node connected, wallet posture decided
- [ ] **Signing seed** backed up offline (plus passphrase / derivation path if used) —
      NOT just the xpub, which cannot spend
- [ ] Wallet descriptor/xpub, Lightning channel backup, and Postgres backup taken
- [ ] A restore actually **tested**, not just taken
- [ ] Three separate API keys created with the permissions in §4
- [ ] Store webhook registered → `https://<PUBLIC_BASE_URL host>/api/webhooks/btcpay`
- [ ] FCP configured (Admin → Billing) and **Test connection** passes
- [ ] Rail enabled; a real invoice paid end to end from `/account`
- [ ] `billing.settle_detail_unavailable` does **not** appear in the audit log afterwards
- [ ] Canary swept and sold by hand, all the way to the bank, before raising any limits
