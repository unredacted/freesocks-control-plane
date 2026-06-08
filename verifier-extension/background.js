// FreeSocks bundle verifier (CDN-blinding Phase 4, MEGA model). When the app
// origin loads, fetch the served index.html and compare its SHA-384 against the
// hash pinned inside this store-delivered extension. index.html carries SRI for
// every script/style, so a match means the whole served bundle equals the
// reproducible, out-of-band-published build; a mismatch means the CDN served
// something else (active tamper) and the user is warned.
//
// This is a scaffold (v0.1). Limitation: it fetches index.html itself, so a
// sophisticated active CDN could in principle serve a clean file to this fetch
// and a tampered one to the page. Verifying the exact executed resources (or a
// native app) is the stronger sibling; see README.md.
import { PINNED } from './pinned.js';

async function sha384Hex(buf) {
  const d = await crypto.subtle.digest('SHA-384', buf);
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
    title: 'FreeSocks: served app does NOT match the published build',
    message,
    priority: 2,
  });
}

async function verify() {
  try {
    const res = await fetch(`${PINNED.origin}/index.html`, { cache: 'no-store' });
    if (!res.ok) return setBadge('?', `could not fetch index.html (${res.status})`, false);
    const got = await sha384Hex(await res.arrayBuffer());
    if (got === PINNED.indexSha384) {
      warned = false;
      setBadge('OK', 'served bundle matches the pinned, reproducible build', false);
    } else {
      setBadge('!', 'served index.html does NOT match the pinned build', true);
      warnOnce(
        'The served bundle differs from the build published out of band. Do not enter your account number; verify via the .onion mirror.',
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
