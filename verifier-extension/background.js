// Probe the served HTML against the hash pinned in the store-delivered extension.
// The probe does not observe the document or resources executed in the tab.
import { PINNED } from './pinned.js';

// MUST stay byte-identical to scripts/gen-verifier-pin.mjs `normalizeIndexHtml`.
// Caddy templates a per-request CSP nonce into <meta name="csp-nonce">, so the
// served index.html hash changes every request; canonicalize that one tag before
// hashing so the served page matches the pinned hash. Preserve its SRI metadata.
function normalizeIndexHtml(html) {
  return html.replace(/<meta name="csp-nonce"[^>]*>/, '<meta name="csp-nonce" content="">');
}

async function sha384Hex(str) {
  const d = await crypto.subtle.digest('SHA-384', new TextEncoder().encode(str));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function setBadge(text, title, bad) {
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color: bad ? '#cc0000' : '#0a7d00' });
  chrome.action.setTitle({ title: `FreeSocks verifier: ${title}` });
}

let warned = false;
function warnOnce(message) {
  if (warned) return;
  warned = true;
  chrome.notifications.create('fs-verify-fail', {
    type: 'basic',
    iconUrl: 'icon.png',
    title: 'FreeSocks: HTML probe does NOT match the published build',
    message,
    priority: 2,
  });
}

async function verify() {
  try {
    const res = await fetch(`${PINNED.origin}/index.html`, { cache: 'no-store' });
    if (!res.ok) return setBadge('?', `could not fetch index.html (${res.status})`, false);
    const got = await sha384Hex(normalizeIndexHtml(await res.text()));
    if (got === PINNED.indexSha384) {
      warned = false;
      setBadge('HTML', 'fetched HTML matches the pinned build', false);
    } else {
      setBadge('!', 'served index.html does NOT match the pinned build', true);
      warnOnce(
        'The fetched HTML differs from the build published out of band. Do not enter your account number; verify via the .onion mirror.',
      );
    }
  } catch (e) {
    setBadge('?', `verification error: ${String(e)}`, false);
  }
}

const host = new URL(PINNED.origin).hostname;
chrome.webNavigation.onCompleted.addListener(
  (d) => {
    if (d.frameId === 0) void verify();
  },
  { url: [{ hostEquals: host }] },
);
