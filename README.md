# FreeSocks Control Plane (FCP)

This is the (control plane) code behind [FreeSocks](https://freesocks.org) a service that provides free, open & uncensored Outline (Shadowsocks) proxies to people in countries experiencing a high level of Internet censorship.

The FreeSocks Control Plane (FCP) utilizes [Cloudflare Workers](https://workers.cloudflare.com/) and is written in JavaScript. This repository allows you to stand up your own FreeSocks-like Outline access key distribution platform, and provides insight into how FreeSocks works.

The FreeSocks Control Plane consists of 2 components:

- GET Worker (src/get.js) - distributes Outline access keys to users.
- DELETE Worker (src/delete.js) - deletes access keys that have not been used after a defined number of days.

## Prerequisites

- A Cloudflare account with access to the Workers platform.
- The creation of several Workers KV namespaces, which are to be defined in the `wrangler.toml` environment variables.
- A zone on Cloudflare to be used for the FreeSocks Control Plane.
- Cloudflare [wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/).
- Ensure you are logged in to Cloudflare with [wrangler](https://developers.cloudflare.com/workers/wrangler/commands/#login)

## Defining environment variables

Check `wrangler-example.toml` for example variables.

Make a copy of `wrangler-example.toml` to `wrangler.toml` then edit them depending on your requirements.

Set sensitive variables with `wrangler secret`.

Set required secrets:

```
# For get.js
wrangler secret put TURNSTILE_SITE_KEY
wrangler secret put TURNSTILE_SECRET_KEY

# For delete.js
wrangler secret put SECRET_AUTH_TOKEN
wrangler secret put VAR_CF_ACCESS_CLIENT_ID
wrangler secret put VAR_CF_ACCESS_CLIENT_SECRET
```

## How to deploy

To deploy the FCP, you can run:

```
wrangler deploy
```

## Updating your FCP code

1. Check for breaking changes since you last deployed your Worker, and fix if needed.
2. Pull the latest code from the repository's directory you have on your system:

```
git pull
```

Deploy the Worker:

```
wrangler deploy
```
