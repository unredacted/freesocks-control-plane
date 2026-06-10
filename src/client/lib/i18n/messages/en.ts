/**
 * English message catalog — the SOURCE OF TRUTH. Every key the app uses is
 * defined here; other locales are Partial<Messages> merged over this, so a
 * missing translation falls back to English rather than showing a key.
 *
 * Values are strings, or functions for interpolation. Keep the high-stakes
 * strings (reveal warnings, login, errors, setup guidance) precise — those are
 * the ones flagged for native-speaker review.
 */
type Msg = string | ((p: Record<string, string | number>) => string);

export const en = {
  // --- common ---
  'common.copy': 'Copy',
  'common.copied': 'Copied to clipboard',
  'common.copyFailed': 'Copy failed — select the text and copy it manually',
  'common.download': 'Download',
  'common.print': 'Print',
  'common.cancel': 'Cancel',
  'common.close': 'Close',
  'common.retry': 'Retry',
  'common.loading': 'Loading…',
  'common.language': 'Language',

  // --- nav / header ---
  'nav.getAccount': 'Get a free account',
  'nav.signIn': 'Sign in',
  'nav.account': 'My account',

  // --- captcha widget ---
  'captcha.initial': "I'm human",
  'captcha.verifying': 'Verifying…',
  'captcha.solved': 'Verified',
  'captcha.error': 'Check failed — retry',

  // --- reveal-once account number (THE highest-stakes moment) ---
  'reveal.title': 'Save your account number now',
  'reveal.subtitle':
    'This 32-digit number is the ONLY way to sign in again. There is no email or password to recover it. If you lose it, your account is gone for good.',
  'reveal.cannotRecover': 'We cannot recover it for you — not even support can.',
  'reveal.saveHint': 'Save it in a password manager, or write it down somewhere safe and private.',
  'reveal.confirmCheckbox': 'I have saved my account number somewhere safe',
  'reveal.done': "I've saved it",
  'reveal.downloadFilename': 'freesocks-account-number.txt',
  'reveal.leaveWarning':
    'Your account number is still on screen. If you leave now without saving it, you will not be able to sign in again.',

  // --- support id ---
  'support.label': 'Support ID',
  'support.hint':
    'Share this if you contact us. It is NOT your sign-in number and grants no access.',

  // --- login ---
  'login.title': 'Sign in with your account number',
  'login.subtitle':
    "Enter the 32-digit account number you saved. It's the only way to sign in — there's no email or password to recover.",
  'login.label': 'Account number',
  'login.show': 'Show',
  'login.hide': 'Hide',
  'login.submit': 'Sign in',
  'login.submitting': 'Signing in…',
  'login.noAccount': "Don't have an account number yet?",
  'login.getOne': 'Get a free account',
  'login.failed': 'Sign-in failed',

  // --- account page: membership states ---
  'account.title': 'Your account',
  'account.tierLabel': 'Your plan',
  'account.statusActive': 'Active',
  'account.statusGrace': 'Expiring soon',
  'account.statusDisabled': 'Expired',
  'account.regenerate': 'Create a new key',
  'account.switchBackend': 'Switch server type',
  'account.rotate': 'Change account number',
  'account.signOut': 'Sign out',
  'account.redeemTitle': 'Have a membership code?',
  'account.redeemPlaceholder': 'FSM-XXXX-XXXX-XXXX',
  'account.redeemSubmit': 'Redeem code',
  'account.redeemSuccess': (p: Record<string, string | number>) =>
    `Redeemed — you're now on ${p.tier} for ${p.days} more days.`,
  'account.redeemFailed': 'That code is not valid, or has already been used.',

  // --- renew / donate callouts (P1-13) ---
  'renew.expiringTitle': 'Your membership is expiring soon',
  'renew.expiredTitle': 'Your membership has expired',
  'renew.body':
    'FreeSocks is community-funded — donations keep it running. To renew your membership, donate or contact us for a membership code.',
  'renew.donate': 'Donate',
  'renew.contact': 'Contact us',
  'renew.haveCode': 'Have a membership code? Redeem it above.',

  // --- errors (shown inline / as toasts) ---
  'error.offline': 'You appear to be offline. Check your connection and try again.',
  'error.rateLimited': 'Too many attempts. Please wait a minute and try again.',
  'error.backendUnavailable':
    'No proxy server is available right now. Your account is safe — try creating your key again in a few minutes.',
  'error.generic': 'Something went wrong. Please try again.',
  'error.captchaFailed': 'The human check failed. Please complete it and try again.',

  // --- per-platform setup guidance (P1-14) ---
  'setup.title': 'Set up your proxy app',
  'setup.intro': 'Copy your subscription link above, then add it to a compatible app:',
  'setup.android': 'Android',
  'setup.ios': 'iPhone / iPad',
  'setup.windows': 'Windows',
  'setup.desktop': 'macOS / Linux',
  'setup.step.install': 'Install the app',
  'setup.step.import': 'Open it, add a subscription / profile, and paste your link',
  'setup.step.connect': 'Select a server and connect',
  'setup.qrHint': 'Or scan this QR code with your phone to transfer the link.',
} satisfies Record<string, Msg>;

export type MessageKey = keyof typeof en;
export type Messages = Record<MessageKey, Msg>;
