# FreeSocks Control Plane

[![CI](https://github.com/unredacted/freesocks-control-plane/actions/workflows/ci.yml/badge.svg)](https://github.com/unredacted/freesocks-control-plane/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

[FreeSocks](https://freesocks.org) gives free proxy access to people in countries where the
Internet is heavily censored. This repository is the software that runs the service: the
website, accounts, key handout, payments and the admin console. The proxy servers themselves
live elsewhere; this app creates and manages the keys people use to connect to them.

Anyone can run their own copy. It is built to be self-hosted from start to finish, with no
outside services required.

## What people can do

- **Get an account without giving anything away.** No email, phone number or password. A
  visitor solves a short puzzle that runs in their browser and gets a random 32-digit
  account number. That number is the only way back into the account, so the site makes
  them save it before moving on.
- **Get a connection key.** One click creates a key that works with common proxy apps. The
  site recommends apps for each platform and shows a QR code.
- **Choose how they connect.** Pick a server location, or let the service choose the least
  busy one. Pick a mode suited to getting past blocking, or one suited to privacy.
- **Fix things themselves.** Replace a key, move to another server, change their account
  number, remove a device, add a passkey for quicker sign-in, or report that a connection
  isn't working.
- **Check the network.** A public status page shows which locations are up, how busy they
  are, where each mode is known to work, and any ongoing incidents.
- **Support the service.** Buy a membership (Bitcoin, other cryptocurrencies, card or
  PayPal), redeem a membership code, refer a friend, or donate. Donations add extra monthly
  bandwidth for every free user.

The site is available in English, Persian, Arabic, Russian and Chinese.

## What operators can do

Operators manage everything from an admin console that only accepts passkeys. From there they
can:

- add proxy servers and choose which ones new keys go to
- set up plans (free, member, and any others) and what each one allows
- look up and help users by their support ID, which is safe to share
- create membership codes, configure payments, and see revenue
- edit the status page, recommended apps, site banner, theme and rate limits
- set up storage mirrors, so people can still fetch their keys if the main site is blocked
- read user problem reports and a full audit log
- create API tokens with limited permissions for automation

Server setup can also be automated with the companion Ansible role,
[ansible-role-freesocks](https://github.com/unredacted/ansible-role-freesocks).

## How it protects people

- **No stored IP addresses.** The app, the web server and the puzzle service are all set up
  to keep no visitor IPs, not even scrambled ones. See [privacy.md](docs/privacy.md).
- **No personal details.** Accounts have no name, email or phone. Account numbers are stored
  in a form that can't be turned back into the number. Payments happen on the payment
  provider's own page, and FCP keeps nothing about who paid.
- **Nothing loaded from other sites.** Fonts, scripts and the puzzle all come from the same
  server as the page, so no third party sees who visits.
- **Protection from the middle.** When turned on, the browser encrypts its requests so that
  only the backend can read them, and ties each sign-in to a key that never leaves the
  device. A CDN or proxy in between can't read the traffic or reuse a stolen cookie. See
  [threat-model-cdn-blinding.md](docs/threat-model-cdn-blinding.md).
- **Replaceable entry points.** Servers can sit behind front addresses that FCP creates,
  tests from the affected countries, and swaps out when one gets blocked. This is called
  **Edges** and is off until an operator sets it up. See [edges.md](docs/edges.md).
- **Idle accounts are paused, not deleted.** A free key that hasn't been used for a while is
  taken back, but the account stays. Signing in again brings it back.

## How it works

```
 Website:     browser ──► web server (Caddy) ──► Convex backend ──► database
                              │
                              └── serves the website files

 Connecting:  proxy app ──► edge (optional) ──► proxy server
```

- **Backend:** [Convex](https://convex.dev), self-hosted in Docker. It holds the database,
  the API the website calls, and the scheduled jobs (expiring memberships, health checks,
  cleanup). All backend code is in [`convex/`](convex/).
- **Website:** a Svelte app built into plain static files ([`src/client/`](src/client/)).
  A web server hands out those files and passes `/api` requests to the backend.
- **Proxy servers:** FCP talks to proxy software through a common interface. Two are
  supported: [Remnawave](https://remna.st), which runs Xray and is shown to users as
  "Xray", and [Outline](https://getoutline.org) (Shadowsocks), which ships turned off. See
  [backends.md](docs/backends.md).
- **Puzzle:** [Cap](https://trycap.dev), a self-hosted proof-of-work check, stops bots
  from creating accounts without tracking anyone.

## Run it locally

You need [Bun](https://bun.sh) (the version is pinned in `package.json`) and Docker with
Compose v2. Use Bun only; `bun.lock` is the only lockfile.

```bash
# 1. Start the backend in Docker
cp .env.docker.example .env.docker
bun install
bun run selfhost:up        # backend + its dashboard
bun run selfhost:env       # writes .env.local so the CLI can reach the backend

# 2. Give the backend its settings (once)
for k in SESSION_SIGNING_KEY ADMIN_SESSION_SIGNING_KEY ADMIN_BOOTSTRAP_SECRET IP_HASH_SALT ACCOUNT_ID_PEPPER; do
  bunx convex env set "$k" "$(openssl rand -hex 32)"
done
bunx convex env set ENVIRONMENT development
bunx convex env set CAP_DEV_BYPASS true            # skip the puzzle in local dev
bunx convex env set WEBAUTHN_RP_ID localhost
bunx convex env set WEBAUTHN_ORIGIN http://localhost:5173

# 3. Run the backend code and the website (reloads on change)
bun run dev

# 4. In another terminal, load the default plans and settings (safe to repeat)
bunx convex run seed:seedCutover '{}'
```

Open the website at http://localhost:5173 and the Convex dashboard at http://localhost:6791.
To create the first admin, go to `/admin` and enter your `ADMIN_BOOTSTRAP_SECRET`
(`bunx convex env get ADMIN_BOOTSTRAP_SECRET`).

If the website says it can't reach the server, the Docker backend has stopped: run
`bun run selfhost:up` again. To start over with an empty database, run
`docker compose --env-file .env.docker down -v`.

## Run it in production

Production runs as a single Docker Compose stack ([`docker-compose.stack.yml`](docker-compose.stack.yml)):
Postgres, the Convex backend, Caddy (HTTPS and the website), the Cap puzzle service, backups,
and a one-time job that deploys the code and loads the defaults. In short:

```bash
cp .env.beta.example .env.beta
cp .env.convex.example .env.convex
bun run bootstrap          # fills in every secret that can be generated
# edit both files to add your domain, puzzle keys and any payment keys
docker compose -f docker-compose.stack.yml --env-file .env.beta up -d --build
```

Then open `/admin`, register your passkey, and add a proxy server. The full guide, including
updates, backups and rollback, is [beta-deploy.md](docs/beta-deploy.md). Every setting and
secret is explained in [secrets.md](docs/secrets.md) and
[convex-self-hosting.md](docs/convex-self-hosting.md).

## Checks

Every change must pass these. CI runs the same ones.

```bash
bun run test                  # unit and backend tests, no running server needed
bun run typecheck
bun run convex:bundle-check   # the backend code will bundle the way a deploy does
bun run lint                  # `bun run format` fixes formatting
bun run build
```

Two larger suites run in Docker against throwaway servers:

```bash
bun run test:integration:remnawave   # FCP against a real Remnawave panel
bun run test:compat                  # real proxy apps import and use FCP's keys
```

See [client-compatibility.md](docs/client-compatibility.md) for what the second one proves.

## Where things are

| Path                    | What's there                                                                   |
| ----------------------- | ------------------------------------------------------------------------------ |
| `convex/`               | The whole backend: data model, API routes, scheduled jobs                      |
| `convex/lib/`           | Shared backend helpers, proxy-server adapters, payment adapters                |
| `src/client/`           | The website, including the admin console under `routes/admin/`                 |
| `src/shared/contracts/` | The shape of every API response, shared by both sides                          |
| `messages/`             | Translations, one file per language                                            |
| `docker/`, `Caddyfile`  | Images and web server config for the production stack                          |
| `scripts/`              | Setup, key generation and test runners                                         |
| `tests/compat/`         | The client compatibility suite                                                 |
| `verifier-extension/`   | Early browser extension that checks the website hasn't been changed in transit |

## Documentation

| Read this                                                         | To learn about                                       |
| ----------------------------------------------------------------- | ---------------------------------------------------- |
| [project-inventory.md](docs/project-inventory.md)                 | Every feature, what's finished, and what's left      |
| [beta-deploy.md](docs/beta-deploy.md)                             | Running the full stack on a server                   |
| [convex-self-hosting.md](docs/convex-self-hosting.md)             | The backend, its settings, and the web server setup  |
| [secrets.md](docs/secrets.md)                                     | Every secret: who creates it and how to change it    |
| [backends.md](docs/backends.md)                                   | How FCP talks to proxy servers, and adding a new one |
| [outline-setup.md](docs/outline-setup.md)                         | Adding an Outline server                             |
| [servers.md](docs/servers.md)                                     | Viewing and managing what runs on a proxy server     |
| [edges.md](docs/edges.md)                                         | Replaceable front addresses for proxy servers        |
| [billing.md](docs/billing.md)                                     | Memberships, payments, donations and referrals       |
| [btcpay-server-runbook.md](docs/btcpay-server-runbook.md)         | Running the BTCPay server for Bitcoin payments       |
| [privacy.md](docs/privacy.md)                                     | What is never stored, and how to keep it that way    |
| [account-number-design.md](docs/account-number-design.md)         | How account-number sign-in works                     |
| [threat-model-cdn-blinding.md](docs/threat-model-cdn-blinding.md) | Encryption between the browser and the backend       |
| [oob-verification.md](docs/oob-verification.md)                   | Checking the website you got is the one we built     |
| [client-compatibility.md](docs/client-compatibility.md)           | Testing real proxy apps against FCP                  |

## Contributing

Code, docs, translations, and testing from inside censored networks all help. Start with
[CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report security problems privately, as described in [SECURITY.md](SECURITY.md). Please don't
open a public issue: people in high-risk places depend on this software.

## License

[AGPL-3.0-or-later](LICENSE). If you run a modified version as a public service, you must
offer its source code to the people who use it.
