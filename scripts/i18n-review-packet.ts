/**
 * Generate per-locale native-review packets (translation-review/<locale>.md).
 *
 * For each non-English locale, emits every message key grouped by namespace
 * with the English source next to the current translation, flagging keys that
 * are MISSING (the app shows English until translated). Reviewers edit the
 * right-hand column (or write corrections inline); the operator applies them
 * to messages/<locale>.json and re-runs this script to refresh the packets.
 *
 * Run: `bun run i18n:review` (or `bun run scripts/i18n-review-packet.ts`).
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const LOCALES: { code: string; name: string; rtl: boolean }[] = [
  { code: 'fa', name: 'Persian (فارسی)', rtl: true },
  { code: 'ar', name: 'Arabic (العربية)', rtl: true },
  { code: 'ru', name: 'Russian (Русский)', rtl: false },
  { code: 'zh', name: 'Chinese (中文)', rtl: false },
];

/** Where each namespace appears, so a reviewer has product context without
 *  running the app. Keep short; unknown namespaces get a generic line. */
const NAMESPACE_CONTEXT: Record<string, string> = {
  common: 'Shared buttons/labels (copy, download, close, working…) used across every page.',
  nav: 'The site header: navigation buttons, menu, language/theme controls.',
  home: 'The public landing page: hero, feature sections, impact section, FAQ intros.',
  hero: 'The subscription panel: the key/URL block, traffic + expiry stats, QR, status callouts.',
  get: 'The /get-account sign-up flow: create account (step 1) and create subscription (step 2).',
  reveal:
    'The save-your-account-number modal (the 32-digit sign-in number is shown ONCE; users must download it and paste it back to verify). The single most safety-critical copy in the product.',
  login: 'The sign-in page (account number + optional passkey).',
  account: 'The signed-in /account dashboard: connection, membership, codes, security tabs.',
  delivery:
    'The connection-mode picker: "Beat censorship" (for censored countries) vs "Maximum privacy" (for open internet), plus the switch-confirmation dialog.',
  setup: 'The "set up your app" section: recommended VPN clients per platform, install steps.',
  upgrade: 'The paid-membership purchase panel (payment method, duration, totals).',
  donate: 'The donation card + amount picker (donations add bandwidth for all free users).',
  impact: 'The donation-impact panel: bandwidth donated, free users helped, charts.',
  gift: 'Gift membership codes: buying, revealing (show-once), and redeeming.',
  renew: 'Expiring/expired membership callouts and renewal prompts.',
  tiers: 'The plan-comparison cards (Free vs Membership limits).',
  usage: 'The 30-day usage trend under the traffic stats.',
  mirror: 'The "trouble connecting? try a mirror" fallback flow.',
  rawconfig: 'The raw-configuration viewer (privacy mode delivers config text, not a URL).',
  regen: 'The regenerate-subscription confirmation dialog.',
  switch: 'The switch-backend confirmation dialog.',
  passkey: 'Optional passkey (Face ID / fingerprint) sign-in management.',
  deviceRevoke: 'The disconnect-a-device confirmation dialog.',
  e2ee: 'The HPKE/E2EE "encrypted to this server" badge + verification panel.',
  captcha: 'The proof-of-work human check widget states.',
  support: 'The support-ID line (a non-secret handle for contacting support).',
  error: 'API error messages shown to members.',
  faq: 'The landing-page FAQ (questions + answers).',
  footer: 'The site footer (nonprofit line, terms/privacy links).',
  app: 'App-level chrome (skip link, page titles).',
  qr: 'QR-code helper labels.',
};

const REVIEW_HEADER = (
  name: string,
  code: string,
  rtl: boolean,
  missing: number,
  total: number,
) => `# FreeSocks translation review — ${name}

Generated from \`messages/en.json\` (source of truth) vs \`messages/${code}.json\`.
**${missing} of ${total} strings are missing** (the app currently shows English for
those); the rest are first-pass machine translations that need a native speaker's
review.

## How to review

- Fix anything that reads unnatural, wrong, or machine-translated. Earlier MT
  passes produced real errors (e.g. "Xray" rendered as "X-ray", "proxy" as
  "malware") — please be suspicious.
- **Keep untranslated:** product/protocol names (FreeSocks, Unredacted, Xray,
  VLESS, Outline, HPKE, QR), app names (Hiddify, Karing, sing-box…), and
  placeholders in braces like \`{count}\`, \`{amount}\`, \`{label}\` (keep them
  exactly, including braces; you may move them within the sentence).
- Tone: plain, calm, and direct — much of the audience is under internet
  censorship and possibly at risk; avoid alarmist or bureaucratic phrasing.
  The \`reveal.*\` strings are the most safety-critical: losing the 32-digit
  number permanently locks the user out, and the copy must make that unmissable.
${rtl ? '- This locale renders right-to-left; word order matters more than punctuation.\n' : ''}
- Edit the **"${name}" column** (or add a correction below a row). Rows marked
  ⚠️ MISSING have no translation yet.

`;

/** ICU-plural messages are stored as `[ { selectors, match: {variant: text} } ]`
 *  (inlang message-format). Render each variant as its own row —
 *  `key [countPlural=one]` — so reviewers see/translate every plural form. */
function pluralVariants(v: unknown): Record<string, string> | null {
  if (!Array.isArray(v) || v.length === 0) return null;
  const first = v[0] as Record<string, unknown> | undefined;
  if (!first || typeof first !== 'object' || !first.match || typeof first.match !== 'object') {
    return null;
  }
  const out: Record<string, string> = {};
  for (const [variant, text] of Object.entries(first.match as Record<string, unknown>)) {
    out[variant] = String(text);
  }
  return out;
}

function flatten(obj: unknown, prefix = ''): Record<string, string> {
  const out: Record<string, string> = {};
  if (!obj || typeof obj !== 'object') return out;
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    if (k.startsWith('$')) continue; // $schema
    const key = prefix ? `${prefix}.${k}` : k;
    const variants = pluralVariants(v);
    if (variants) {
      for (const [variant, text] of Object.entries(variants)) out[`${key} [${variant}]`] = text;
    } else if (v && typeof v === 'object' && !Array.isArray(v)) {
      Object.assign(out, flatten(v, key));
    } else {
      out[key] = String(v);
    }
  }
  return out;
}

const esc = (s: string) => s.replaceAll('|', '\\|').replaceAll('\n', '<br>');

const root = process.cwd();
const en = flatten(JSON.parse(readFileSync(join(root, 'messages/en.json'), 'utf8')));
const outDir = join(root, 'translation-review');
mkdirSync(outDir, { recursive: true });

for (const { code, name, rtl } of LOCALES) {
  const loc = flatten(JSON.parse(readFileSync(join(root, `messages/${code}.json`), 'utf8')));
  const keys = Object.keys(en);
  const missing = keys.filter((k) => !(k in loc)).length;

  let md = REVIEW_HEADER(name, code, rtl, missing, keys.length);

  const namespaces = [...new Set(keys.map((k) => k.split('.')[0]!))];
  for (const ns of namespaces) {
    const nsKeys = keys.filter((k) => k === ns || k.startsWith(`${ns}.`));
    const nsMissing = nsKeys.filter((k) => !(k in loc)).length;
    md += `\n## \`${ns}\` — ${NAMESPACE_CONTEXT[ns] ?? 'Miscellaneous strings.'}`;
    md += nsMissing ? ` *(${nsMissing} missing)*\n\n` : '\n\n';
    md += `| Key | English | ${name} |\n| --- | --- | --- |\n`;
    for (const k of nsKeys) {
      const cur = loc[k];
      md += `| \`${k}\` | ${esc(en[k]!)} | ${cur === undefined ? '⚠️ **MISSING**' : esc(cur)} |\n`;
    }
  }
  writeFileSync(join(outDir, `${code}.md`), md);
  console.log(`wrote translation-review/${code}.md (${missing}/${keys.length} missing)`);
}
