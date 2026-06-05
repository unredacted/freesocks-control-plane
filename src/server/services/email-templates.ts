/**
 * Inline transactional email templates. Plain-text + minimal HTML so they
 * render in any client and survive aggressive email-rewriting proxies.
 *
 * Each template returns `{ subject, text, html }`. The `params` are typed
 * per-template so callers can't pass the wrong shape.
 *
 * Templates are intentionally short and link-light — anti-censorship users
 * are often on filtered networks where image/link-heavy emails get blocked
 * or flagged.
 */

interface RenderedEmail {
  subject: string;
  text: string;
  html: string;
}

export interface WelcomeParams {
  displayName?: string;
  tierName: string;
  accountUrl: string; // https://app.freesocks.org/account
}

export function renderWelcome(params: WelcomeParams): RenderedEmail {
  const greeting = params.displayName ? `Hi ${params.displayName},` : 'Hi,';
  const subject = `Welcome to FreeSocks · your ${params.tierName} tier is active`;
  const text = `${greeting}

Your FreeSocks ${params.tierName} subscription is active. You can grab your subscription URL at:

${params.accountUrl}

Sign in there with the same Authentik account you used to sign up. Paste the subscription URL into your client (Outline, Sing-Box, Clash, V2RayN — any modern Shadowsocks/VLESS/Trojan client) and you're connected.

If something doesn't work, reply to this email and we'll help.

— FreeSocks
`;
  const html = `<!doctype html><html><body style="font-family:system-ui,sans-serif;line-height:1.5;max-width:540px;margin:0 auto;padding:20px;">
<p>${greeting}</p>
<p>Your FreeSocks <strong>${escapeHtml(params.tierName)}</strong> subscription is active. Get your subscription URL at <a href="${escapeHtml(params.accountUrl)}">${escapeHtml(params.accountUrl)}</a>.</p>
<p>Sign in with the same Authentik account you used to sign up. Paste the subscription URL into your client (Outline, Sing-Box, Clash, V2RayN — any modern Shadowsocks/VLESS/Trojan client) and you're connected.</p>
<p>If something doesn't work, reply to this email and we'll help.</p>
<p>— FreeSocks</p>
</body></html>`;
  return { subject, text, html };
}

export interface GraceWarningParams {
  displayName?: string;
  graceEndsAt: string; // ISO date
  renewUrl: string;
}

export function renderGraceWarning(params: GraceWarningParams): RenderedEmail {
  const greeting = params.displayName ? `Hi ${params.displayName},` : 'Hi,';
  const date = new Date(params.graceEndsAt).toLocaleDateString();
  const subject = `Your FreeSocks subscription is in its grace period`;
  const text = `${greeting}

Your FreeSocks membership lapsed on our records. You're in a grace period until ${date} — your subscription still works during this time.

Renew to keep your benefits: ${params.renewUrl}

If you'd like to keep using FreeSocks at the free tier instead, no action is needed; your account will be moved to the free tier when the grace period ends.

— FreeSocks
`;
  const html = `<!doctype html><html><body style="font-family:system-ui,sans-serif;line-height:1.5;max-width:540px;margin:0 auto;padding:20px;">
<p>${greeting}</p>
<p>Your FreeSocks membership lapsed on our records. You're in a grace period until <strong>${escapeHtml(date)}</strong> — your subscription still works during this time.</p>
<p><a href="${escapeHtml(params.renewUrl)}">Renew your membership</a> to keep your benefits.</p>
<p>If you'd like to keep using FreeSocks at the free tier instead, no action is needed; your account will be moved to the free tier when the grace period ends.</p>
<p>— FreeSocks</p>
</body></html>`;
  return { subject, text, html };
}

export interface DisabledParams {
  displayName?: string;
  renewUrl: string;
  freeTierKeyUrl: string; // https://app.freesocks.org/get-key
}

export function renderDisabled(params: DisabledParams): RenderedEmail {
  const greeting = params.displayName ? `Hi ${params.displayName},` : 'Hi,';
  const subject = `Your FreeSocks paid subscription has ended`;
  const text = `${greeting}

Your FreeSocks paid subscription has ended (the grace period has elapsed). Your paid-tier subscription URL is no longer active.

If you want to keep using FreeSocks:

  • Free tier (anonymous, no account): ${params.freeTierKeyUrl}
  • Renew your paid membership: ${params.renewUrl}

If your renewal payment goes through, your existing account is restored automatically — you don't lose any history.

— FreeSocks
`;
  const html = `<!doctype html><html><body style="font-family:system-ui,sans-serif;line-height:1.5;max-width:540px;margin:0 auto;padding:20px;">
<p>${greeting}</p>
<p>Your FreeSocks paid subscription has ended (the grace period has elapsed). Your paid-tier subscription URL is no longer active.</p>
<p>If you want to keep using FreeSocks:</p>
<ul>
  <li>Free tier (anonymous, no account): <a href="${escapeHtml(params.freeTierKeyUrl)}">${escapeHtml(params.freeTierKeyUrl)}</a></li>
  <li>Renew your paid membership: <a href="${escapeHtml(params.renewUrl)}">${escapeHtml(params.renewUrl)}</a></li>
</ul>
<p>If your renewal payment goes through, your existing account is restored automatically — you don't lose any history.</p>
<p>— FreeSocks</p>
</body></html>`;
  return { subject, text, html };
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
