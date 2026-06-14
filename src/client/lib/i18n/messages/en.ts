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
  'common.working': 'Working…',
  'common.reload': 'Reload',
  'common.language': 'Language',
  'common.deviceCount': (p: Record<string, string | number>) =>
    p.count === 1 ? '1 device' : `${p.count} devices`,

  // --- nav / header ---
  'nav.getAccount': 'Get a free account',
  'nav.signIn': 'Sign in',
  'nav.account': 'My account',

  // --- captcha widget ---
  'captcha.initial': "I'm human",
  'captcha.verifying': 'Verifying…',
  'captcha.solved': 'Verified',
  'captcha.error': 'Check failed — retry',
  'captcha.failedTitle': "Couldn't complete the human check.",
  'captcha.failedBody':
    'The check runs entirely in your browser. If it failed, your browser may be blocking the worker it needs, or the network dropped the request.',
  'captcha.failedTip1': 'Try disabling browser extensions',
  'captcha.failedTip2': 'Try a different network or a private/incognito window',
  'captcha.failedTip3': 'Make sure JavaScript and WebAssembly are enabled',

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
  'login.success': 'Signed in',

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
  'account.redeemAriaLabel': 'Membership code',
  'account.switchTo': (p: Record<string, string | number>) => `Switch to ${p.label}`,
  'account.devicesTitle': 'Connected devices',
  'account.lastSeen': (p: Record<string, string | number>) => `Last seen ${p.date}`,
  'account.noSubTitle': 'No subscription yet',
  'account.noSubBody':
    'Create your first subscription to get a URL you can use in any compatible VPN client.',
  'account.createSub': 'Create subscription',
  'account.creating': 'Creating…',
  'account.rotateTitle': 'Rotate your account number?',
  'account.rotateBody':
    'A new 32-digit number is generated and shown once. Your current number stops working immediately. Anyone who has it loses access. Do this if your number may have leaked.',
  'account.rotateConfirm': 'Yes, rotate',
  'account.rotating': 'Rotating…',
  'account.rotateFailedTitle': 'Could not change the account number',
  'account.freeTierTitle': "You're on the free tier",
  'account.freeTierBody':
    'A FreeSocks membership unlocks unlimited devices and bandwidth. Donations also keep free accounts funded.',
  'account.refreshMembership': 'Already paid? Refresh membership',
  'account.refreshing': 'Refreshing…',
  'account.regenSuccessTitle': 'New subscription URL generated',
  'account.regenSuccessBody':
    'Re-import it on each of your devices. The old URL works for 24 more hours.',
  'account.regenFailedTitle': 'Could not create a new key',
  'account.switchSuccessTitle': (p: Record<string, string | number>) => `Switched to ${p.tier}`,
  'account.switchSuccessBodyGrace':
    'Re-import the new subscription URL on each device. The old subscription works for 24 more hours.',
  'account.switchSuccessBody': 'Re-import the new subscription URL on each device.',
  'account.switchFailedTitle': 'Could not switch server type',
  'account.refreshWelcome': (p: Record<string, string | number>) => `Welcome to ${p.tier}`,
  'account.refreshNoneTitle': 'No active membership found yet',
  'account.refreshNoneBody': 'If you just paid, give it a moment and try again.',
  'account.refreshFailedTitle': 'Could not refresh membership',
  'account.graceTitle': 'Your account is in a grace period',
  'account.graceBody':
    'Your membership has lapsed, so this account will be limited soon. Renew — donate or redeem a membership code below — to keep your plan.',
  'account.disabledTitle': 'Your account is currently disabled',
  'account.disabledBody':
    'New keys and changes are paused on this account. Redeem a membership code below to reactivate it, or contact support and share your Support ID.',

  // --- subscription hero (the key/URL card) ---
  'hero.titleDefault': 'Your subscription',
  'hero.eyebrowAccessKey': 'Your access key',
  'hero.urlLabelSubscription': 'Subscription URL',
  'hero.urlLabelAccessKey': 'Access key',
  'hero.tierLine': (p: Record<string, string | number>) => `Tier ${p.tier}`,
  'hero.viaLine': (p: Record<string, string | number>) => `via ${p.backend}`,
  'hero.copyUrl': 'Copy URL',
  'hero.copiedShort': 'Copied',
  'hero.qrShow': 'QR',
  'hero.qrHide': 'Hide',
  'hero.scanPhone': 'Scan with your phone',
  'hero.scanOther': 'Scan with another device',
  'hero.scanFallback': 'Scan the fallback on another device',
  'hero.fallbackLabel': 'Fallback URL',
  'hero.fallbackHint': 'Use this if the main URL gets blocked',
  'hero.fallbackQrAria': 'Show fallback URL QR code',
  'hero.downloaded': (p: Record<string, string | number>) => `Downloaded ${p.filename}`,
  'hero.traffic': 'Traffic',
  'hero.unlimited': 'Unlimited',
  'hero.configBelowNote':
    "Your full configuration is below — add the servers by hand. For privacy, the auto-updating subscription link isn't shown here (your app would fetch it through a CDN).",
  'hero.usedSoFar': (p: Record<string, string | number>) => `${p.amount} used so far`,
  'hero.leftThisPeriod': (p: Record<string, string | number>) => `${p.amount} left this period.`,
  'hero.nearlyOut': (p: Record<string, string | number>) =>
    `Nearly out, only ${p.amount} left this period.`,
  'hero.expires': 'Expires',
  'hero.noExpiry': 'No expiry',
  'hero.expiresToday': 'Expires today',
  'hero.daysRemaining': (p: Record<string, string | number>) =>
    p.count === 1 ? '1 day remaining' : `${p.count} days remaining`,
  'hero.expiredDaysAgo': (p: Record<string, string | number>) =>
    p.count === 1 ? 'Expired 1 day ago' : `Expired ${p.count} days ago`,

  // --- regenerate confirmation modal ---
  'regen.title': 'Regenerate subscription?',
  'regen.body': (p: Record<string, string | number>) =>
    `Your current subscription URL (ending …${p.suffix}) will be replaced with a new one. The old URL becomes read-only for 24 hours, then is deleted.`,
  'regen.point1': 'Your current key remains usable for the next 24 hours',
  'regen.point2': "You'll need to re-import the new URL in each of your devices",
  'regen.pointDevices': (p: Record<string, string | number>) =>
    p.count === 1
      ? 'You currently have 1 connected device — it will need the new URL'
      : `You currently have ${p.count} connected devices — they will all need the new URL`,
  'regen.confirm': 'Regenerate',
  'regen.working': 'Regenerating…',

  // --- switch-backend confirmation modal ---
  'switch.title': (p: Record<string, string | number>) => `Switch to ${p.to}?`,
  'switch.body': (p: Record<string, string | number>) =>
    `Your current ${p.from} subscription will be replaced with a new ${p.to} one. The old subscription stays usable for 24 hours so you can re-import on every device before it stops working.`,
  'switch.point1': (p: Record<string, string | number>) =>
    `A new subscription URL is issued on the ${p.to} backend`,
  'switch.point2': (p: Record<string, string | number>) =>
    `The current ${p.from} URL keeps working for 24 hours, then is deleted`,
  'switch.point3': "You'll need to re-import the new URL in each VPN client you use",
  'switch.pointDevices': (p: Record<string, string | number>) =>
    p.count === 1
      ? 'You currently have 1 connected device — re-import on it'
      : `You currently have ${p.count} connected devices — re-import on all of them`,
  'switch.confirm': (p: Record<string, string | number>) => `Switch to ${p.to}`,
  'switch.working': 'Switching…',

  // --- get-account flow ---
  'get.badge': 'Free account',
  'get.title': 'Get a FreeSocks account',
  'get.introTwoSteps':
    'Two quick steps: solve the human-check to create a free account, then create your subscription.',
  'get.step1Title': 'Create your account',
  'get.chooseBackend': 'Choose a backend',
  'get.backendAria': 'Backend',
  'get.backendMultiProtocol': 'Multi-protocol (VLESS, Trojan, Shadowsocks)',
  'get.backendShadowsocks': 'Shadowsocks via Outline',
  'get.createAccount': 'Create my account',
  'get.freeAccountNote':
    'Free accounts are valid for 30 days and limited to one device. No email or password.',
  'get.accountReady': 'Your account is ready.',
  'get.step2Title': 'Create your subscription',
  'get.step2Intro':
    'Create a proxy subscription to get a URL you can paste into any compatible VPN client.',
  'get.manageHintPrefix': 'Manage this subscription anytime from',
  'get.manageLinkLabel': 'your account',
  'get.subErrorSafePrefix': 'Your account is safe. You can create the subscription later from',
  'get.subErrorSafeSuffix': 'once a server is available.',
  'get.createSubToastTitle': 'Subscription created',
  'get.createSubToastBody': 'Copy the URL into your VPN client, or scan the QR code.',
  'get.createAccountFailedTitle': 'Could not create account',
  'get.createSubFailedTitle': 'Could not create subscription',
  'get.haveAccountPrefix': 'Already have an account?',
  'get.lostNumberHint': 'Lost your account number before saving it? You can switch to a new one —',
  'get.lostNumberLinkLabel': 'change it from your account page',
  'get.upsellTitle': 'Want unlimited?',
  'get.upsellBody':
    'Upgrade to a FreeSocks membership any time for unlimited bandwidth and devices.',

  // --- tier comparison (free-tier dashboard) ---
  'tiers.title': 'Tiers',
  'tiers.subtitle': 'What each tier includes.',
  'tiers.yourTier': 'Your tier',
  'tiers.gbPerMonth': (p: Record<string, string | number>) => `${p.gb} GB / month`,
  'tiers.validity30': '30-day key',
  'tiers.validityContinuous': 'Continuous',
  'tiers.mirrors': 'Mirror URLs',
  'tiers.comingSoon': 'Coming soon',
  'tiers.comingSoonTitle': 'Membership signup is coming soon',
  'tiers.upgradeCta': 'Upgrade',

  // --- member impact / funding card ---
  'impact.title': 'Donations support Unredacted',
  'impact.body':
    'Unredacted is a US 501(c)(3) nonprofit. FreeSocks is one of the projects it runs. Donations fund the work. See what that work is on the Unredacted site.',
  'impact.membershipSoon': 'Membership (coming soon)',

  // --- misc chrome ---
  'qr.ariaLabel': 'QR code for the subscription URL',
  'app.notFound': 'Not found',
  'app.goHome': 'Go home',
  'footer.operatedPrefix': 'Operated by',
  'footer.operatedSuffix': ', a US 501(c)(3) nonprofit',
  'footer.apiDocs': 'API docs',

  // --- renew / donate callouts (P1-13) ---
  'renew.expiringTitle': 'Your membership is expiring soon',
  'renew.expiredTitle': 'Your membership has expired',
  'renew.body':
    'FreeSocks is community-funded — donations keep it running. To renew your membership, donate or contact us for a membership code.',
  'renew.donate': 'Donate',
  'renew.contact': 'Contact us',
  'renew.haveCode': 'Have a membership code? Redeem it above.',

  // --- membership upgrade / purchase (billing) ---
  'upgrade.title': 'Upgrade to a FreeSocks membership',
  'upgrade.extendTitle': 'Extend your membership',
  'upgrade.subtitle': 'Unlimited bandwidth and devices. Choose a length and how to pay.',
  'upgrade.durationLabel': 'Membership length',
  'upgrade.cryptoMinNote': (p: Record<string, string | number>) =>
    `Crypto payments start at ${p.months} months — shorter terms fall below the network minimum. Pick another method for shorter terms.`,
  'upgrade.months': (p: Record<string, string | number>) =>
    p.count === 1 ? '1 month' : `${p.count} months`,
  'upgrade.perMonth': (p: Record<string, string | number>) => `${p.price}/mo`,
  'upgrade.save': (p: Record<string, string | number>) => `save ${p.pct}%`,
  'upgrade.methodLabel': 'Payment method',
  'upgrade.payNowpayments': 'Cryptocurrency',
  'upgrade.payNowpaymentsHint': 'Monero, Bitcoin & more',
  'upgrade.payStripe': 'Card',
  'upgrade.payStripeHint': 'Credit or debit card',
  'upgrade.payPaypal': 'PayPal',
  'upgrade.payPaypalHint': 'PayPal balance or card',
  'upgrade.total': (p: Record<string, string | number>) => `Total ${p.price}`,
  'upgrade.continue': 'Continue to payment',
  'upgrade.starting': 'Starting checkout…',
  'upgrade.startFailed': 'Could not start checkout',
  'upgrade.noStoreNote': 'We never store your email or payment details.',
  'upgrade.confirmingTitle': 'Confirming your payment…',
  'upgrade.confirmingBody':
    'Crypto can take a few minutes to confirm. You can leave this page — your membership activates automatically.',
  'upgrade.paidTitle': 'Membership active',
  'upgrade.paidBody': 'Thank you! Your membership is now active.',
  'upgrade.failedTitle': 'Payment not completed',
  'upgrade.failedBody':
    'Your payment did not go through, or the checkout expired. You can try again.',

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

  // --- opt-in subscription mirrors (the "trouble connecting?" fallback) ---
  'mirror.disclosure': 'Trouble connecting?',
  'mirror.explainer':
    "If your normal subscription link won't connect where you are, add a mirror link below. It serves the same key from a different host that may not be blocked.",
  'mirror.addedLabel': 'Your mirror links',
  'mirror.addToAppHint': 'Add each one as an extra subscription in your app, then try connecting.',
  'mirror.regionLabel': 'Your region',
  'mirror.regionGlobal': 'Global (any region)',
  'mirror.regionNotStored': "Used only to pick a nearby mirror — it isn't stored.",
  'mirror.getButton': 'Get a mirror link',
  'mirror.tryAnother': 'Try another mirror',
  'mirror.working': 'Working…',
  'mirror.capped': "You've added the maximum number of mirrors.",
  'mirror.exhausted': 'No more mirrors are available for your region right now.',
  'mirror.noSubscription': 'Create your key first, then you can add a mirror.',
  'mirror.removeAll': 'Remove all mirrors',
  'mirror.errorToast': "Couldn't add a mirror",
  'mirror.removedToast': 'Mirrors removed',

  // --- raw config viewer (E2EE-preserving manual setup) ---
  'rawconfig.disclosure': 'Show raw configuration',
  'rawconfig.title': 'Your configuration',
  'rawconfig.explainer':
    'Your full proxy configuration, fetched over an encrypted channel so it never crosses a CDN in plain text. Copy it into your app by hand instead of using a subscription link.',
  'rawconfig.addHint': 'Paste these server entries into your proxy app manually.',

  // --- delivery preference (privacy vs. evade censorship) ---
  'delivery.title': 'What matters most to you?',
  'delivery.subtitle': 'Pick a focus — saved on this device only, and you can change it anytime.',
  'delivery.evadeTitle': 'Stay connected',
  'delivery.evadeBody':
    "Best when sites are blocked where you are. We'll surface backup links that are harder to block.",
  'delivery.privacyTitle': 'Maximize privacy',
  'delivery.privacyBody':
    "Best for the strongest confidentiality. We'll prefer setup that keeps your config off third-party servers.",
  'delivery.recommended': 'Recommended',
} satisfies Record<string, Msg>;

export type MessageKey = keyof typeof en;
export type Messages = Record<MessageKey, Msg>;
