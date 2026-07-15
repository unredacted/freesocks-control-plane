# FreeSocks translation review — Persian (فارسی)

Generated from `messages/en.json` (source of truth) vs `messages/fa.json`.
**185 of 647 strings are missing** (the app currently shows English for
those); the rest are first-pass machine translations that need a native speaker's
review.

## How to review

- Fix anything that reads unnatural, wrong, or machine-translated. Earlier MT
  passes produced real errors (e.g. "Xray" rendered as "X-ray", "proxy" as
  "malware") — please be suspicious.
- **Keep untranslated:** product/protocol names (FreeSocks, Unredacted, Xray,
  VLESS, Outline, HPKE, QR), app names (Hiddify, Karing, sing-box…), and
  placeholders in braces like `{count}`, `{amount}`, `{label}` (keep them
  exactly, including braces; you may move them within the sentence).
- Tone: plain, calm, and direct — much of the audience is under internet
  censorship and possibly at risk; avoid alarmist or bureaucratic phrasing.
  The `reveal.*` strings are the most safety-critical: losing the 32-digit
  number permanently locks the user out, and the copy must make that unmissable.
- This locale renders right-to-left; word order matters more than punctuation.

- Edit the **"Persian (فارسی)" column** (or add a correction below a row). Rows marked
  ⚠️ MISSING have no translation yet.


## `faq` — The landing-page FAQ (questions + answers). *(4 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `faq.title` | Frequently asked questions | سوالات متداول |
| `faq.subtitle` | Answers to common questions. | به سوالات اولیه پاسخ داده شد. هنوز گیر کرده‌اید؟ با شناسه پشتیبانی خود تماس بگیرید. |
| `faq.tabGeneral` | General | ⚠️ **MISSING** |
| `faq.tabThreat` | What we protect you from | ⚠️ **MISSING** |
| `faq.contactPrefix` | For anything else, email | ⚠️ **MISSING** |
| `faq.contactSuffix` | and include your Support ID. | ⚠️ **MISSING** |
| `faq.q1.question` | What is FreeSocks? | فری‌ساکس چیست؟ |
| `faq.q1.answer` | A free VPN service that helps people in heavily-censored regions reach the open internet. It's operated by Unredacted, a US 501(c)(3) nonprofit. | یک سرویس پروکسی رایگان که به مردم در مناطق به شدت سانسور شده کمک می‌کند تا به اینترنت آزاد دسترسی پیدا کنند. این سرویس توسط Unredacted، یک سازمان غیرانتفاعی 501(c)(3) ایالات متحده، اداره می‌شود. |
| `faq.q2.question` | Is it really free? | آیا واقعاً رایگان است؟ |
| `faq.q2.answer` | Yes. A free account gives you a working VPN. A paid FreeSocks membership lifts the limits and helps fund free access for others. | بله. یک حساب کاربری رایگان به شما یک پروکسی فعال می‌دهد. عضویت پولی FreeSocks محدودیت‌ها را برمی‌دارد و به تأمین مالی دسترسی رایگان برای دیگران کمک می‌کند. |
| `faq.q3.question` | Do I need to give an email or password? | آیا باید ایمیل یا رمز عبور بدهم؟ |
| `faq.q3.answer` | No. You pass a one-time human check and we generate a 32-digit account number - that's your only credential. We never ask for an email, phone number, or name. | خیر. شما یک بررسی انسانی یک‌باره را با موفقیت پشت سر می‌گذارید و ما یک شماره حساب ۳۲ رقمی تولید می‌کنیم - این تنها مدرک شناسایی شماست. ما هرگز ایمیل، شماره تلفن یا نام شما را درخواست نمی‌کنیم. |
| `faq.q4.question` | What if I lose my account number? | اگر شماره حسابم را گم کنم چه می‌شود؟ |
| `faq.q4.answer` | It's the only way back into your account and we can't recover it (we store only a hashed version), so save it in a password manager when you create it. If you lose it, just create a new free account. | این تنها راه بازگشت به حساب کاربری شماست و ما نمی‌توانیم آن را بازیابی کنیم (ما فقط یک نسخه هش شده را ذخیره می‌کنیم)، بنابراین هنگام ایجاد آن، آن را در یک مدیر رمز عبور ذخیره کنید. اگر آن را گم کردید، کافیست یک حساب کاربری رایگان جدید ایجاد کنید. |
| `faq.q5.question` | How do I connect? | چگونه وصل شوم؟ |
| `faq.q5.answer` | Create a subscription, copy its link (or scan the QR code), and add it to a compatible app. Your account page lists the recommended app for each platform (Android, iPhone, Windows, macOS / Linux). | یک اشتراک ایجاد کنید، لینک آن را کپی کنید (یا کد QR را اسکن کنید) و آن را به یک برنامه سازگار مانند v2rayNG، Hiddify یا Streisand اضافه کنید. صفحه حساب شما برنامه‌های پیشنهادی برای هر پلتفرم را فهرست می‌کند. |
| `faq.q6.question` | What do you log about me? | چه چیزی در مورد من ثبت می‌کنی؟ |
| `faq.q6.answer` | As little as possible: only a hashed version of your account number - never your email, name, or IP address - and no logs of the sites you visit or the traffic you send. | تا حد امکان کم: فقط یک نسخه هش شده از شماره حساب شما - هرگز ایمیل یا نام شما - و هیچ گزارشی از سایت‌هایی که بازدید می‌کنید یا ترافیکی که ارسال می‌کنید، ثبت نشود. |
| `faq.q7.question` | The link is blocked where I am. What can I do? | لینک در جایی که من هستم مسدود شده است. چه کاری می‌توانم انجام دهم؟ |
| `faq.q7.answer` | On your account page, open "Trouble connecting?" to get a mirror link served from a different host that may not be blocked. You can also set your delivery preference to favor staying connected. | در صفحه حساب کاربری خود، گزینه «مشکل در اتصال؟» را باز کنید تا لینک آینه‌ای از میزبان دیگری که ممکن است مسدود نباشد، دریافت کنید. همچنین می‌توانید ترجیح خود را برای دریافت لینک به صورت «در ارتباط ماندن» تنظیم کنید. |
| `faq.q8.question` | Can I buy a membership for someone else? | آیا می‌توانم برای شخص دیگری عضویت خریداری کنم؟ |
| `faq.q8.answer` | Yes - on your account page use "Buy codes to share" to purchase membership codes you can give to friends or family. Each one works on any account and doesn't affect yours. | بله - در صفحه حساب کاربری خود از گزینه «خرید کد برای اشتراک‌گذاری» برای خرید کدهای عضویتی که می‌توانید به دوستان یا خانواده بدهید استفاده کنید. هر کدام از این کدها روی هر حسابی کار می‌کنند و روی حساب شما تأثیری ندارند. |
| `faq.q9.question` | Can I pay anonymously? | آیا می‌توانم به صورت ناشناس پرداخت کنم؟ |
| `faq.q9.answer` | Yes. You can pay with cryptocurrency - Bitcoin, or Monero and Zcash for the most privacy - with no account, email, or card. Your membership activates automatically once the payment confirms. | بله. شما می‌توانید با ارز دیجیتال - بیت‌کوین، یا مونرو و زی‌کش برای بیشترین حریم خصوصی - بدون نیاز به حساب، ایمیل یا کارت پرداخت کنید. عضویت شما پس از تأیید پرداخت، به‌طور خودکار فعال می‌شود. |

## `threat` — Miscellaneous strings. *(15 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `threat.subtitle` | An honest look at what this service can and cannot do. Security tools that overpromise get people hurt, so here is exactly where the lines are. | ⚠️ **MISSING** |
| `threat.q1.question` | What does FreeSocks protect me from? | ⚠️ **MISSING** |
| `threat.q1.answer` | FreeSocks tunnels your traffic through an encrypted VPN connection, so your ISP, mobile carrier, school, or workplace network cannot see which sites you visit or block them. It is built for getting past censorship and for keeping the network you are on from watching what you do. | ⚠️ **MISSING** |
| `threat.q2.question` | What does FreeSocks NOT protect me from? | ⚠️ **MISSING** |
| `threat.q2.answer` | It does not make you anonymous to sites you sign in to: if you log in to an account, that site knows who you are. It cannot protect a device that is already compromised (spyware, a managed work profile, someone with physical access). And a powerful adversary that can watch traffic at many points on the internet may still correlate patterns. If your safety depends on strong anonymity, use Tor and follow specialist guidance for your situation. | ⚠️ **MISSING** |
| `threat.q3.question` | Can FreeSocks see my traffic? | ⚠️ **MISSING** |
| `threat.q3.answer` | Your traffic exits through our servers, so treat us like any exit: sites you use over HTTPS (almost all of the modern web) stay encrypted end to end and we cannot read their contents. We configure our servers to keep no connection logs, no visited-site logs, and no source IPs, and the control plane never stores your IP address at all. | ⚠️ **MISSING** |
| `threat.q4.question` | What happens if a FreeSocks server is seized or compromised? | ⚠️ **MISSING** |
| `threat.q4.answer` | There is nothing identifying on it. Servers hold no names, emails, IPs, or traffic history, because we never collect those in the first place. Access keys can be revoked and reissued quickly, and we can rotate infrastructure without losing accounts. | ⚠️ **MISSING** |
| `threat.q5.question` | Can my government or ISP tell that I am using FreeSocks? | ⚠️ **MISSING** |
| `threat.q5.answer` | Sometimes censors can detect that circumvention traffic is in use even when they cannot read it. Our transports are designed to look like ordinary encrypted web traffic, and Internet Freedom Mode routes through infrastructure that is expensive to block. Still, whether use is detectable, and what the consequences are, varies by country. Weigh your local risk. | ⚠️ **MISSING** |
| `threat.q6.question` | Why should I believe any of this? | ⚠️ **MISSING** |
| `threat.q6.answer` | The control plane is open source, so anyone can read exactly what it stores and check that there is no place a name, email, or IP address could even go. Claims that depend on server configuration (like disabled logging) are documented and enforced by the same code. You still have to trust the operator for the parts you cannot see, as with every VPN; our approach is to minimize what there is to trust. | ⚠️ **MISSING** |
| `threat.q7.question` | Do payments link my identity to my browsing? | ⚠️ **MISSING** |
| `threat.q7.answer` | Membership is optional, and payment is handled by outside processors: we never store the payer's name, email, or address, and an order is tied to your account only through an opaque reference. Cryptocurrency options (including Monero) exist for people who do not want a card trail at all. | ⚠️ **MISSING** |

## `common` — Shared buttons/labels (copy, download, close, working…) used across every page.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `common.copy` | Copy | کپی |
| `common.copied` | Copied to clipboard | در کلیپ‌بورد کپی شد |
| `common.copyFailed` | Copy failed - select the text and copy it manually | کپی نشد - متن را انتخاب و دستی کپی کنید |
| `common.download` | Download | دانلود |
| `common.cancel` | Cancel | لغو |
| `common.close` | Close | بستن |
| `common.retry` | Retry | تلاش دوباره |
| `common.loading` | Loading… | در حال بارگذاری… |
| `common.working` | Working… | در حال انجام… |
| `common.reload` | Reload | بارگذاری مجدد |
| `common.language` | Language | زبان |
| `common.deviceCount [countPlural=one]` | 1 device | 1 دستگاه |
| `common.deviceCount [countPlural=other]` | {count} devices | {count} دستگاه |

## `nav` — The site header: navigation buttons, menu, language/theme controls. *(3 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `nav.getAccount` | Get a free account | دریافت حساب رایگان |
| `nav.signIn` | Sign in | ورود |
| `nav.account` | My account | حساب من |
| `nav.menu` | Menu | ⚠️ **MISSING** |
| `nav.theme` | Theme | ⚠️ **MISSING** |
| `nav.home` | FreeSocks home | ⚠️ **MISSING** |

## `captcha` — The proof-of-work human check widget states.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `captcha.initial` | I'm human | من انسان هستم |
| `captcha.verifying` | Verifying… | در حال بررسی… |
| `captcha.solved` | Verified | تأیید شد |
| `captcha.error` | Check failed - retry | بررسی ناموفق بود - دوباره تلاش کنید |
| `captcha.failedTitle` | Couldn't complete the human check. | بررسی انسانی کامل نشد. |
| `captcha.failedBody` | The check runs on your device and didn't finish. This is usually a network problem, not something you did wrong. | این بررسی روی دستگاه شما اجرا می‌شود و کامل نشد. معمولاً این یک مشکل شبکه است، نه اشتباه شما. |
| `captcha.failedTip1` | Wait a moment, then try again | کمی صبر کنید و دوباره تلاش کنید |
| `captcha.failedTip2` | Try a different network - or a VPN if sites are blocked where you are | شبکهٔ دیگری را امتحان کنید - یا اگر سایت‌ها در منطقهٔ شما مسدودند، از یک VPN/پراکسی استفاده کنید |
| `captcha.failedTip3` | Still stuck? Try a private/incognito window or turn off browser extensions | هنوز مشکل دارید؟ یک پنجرهٔ ناشناس باز کنید یا افزونه‌های مرورگر را غیرفعال کنید |

## `reveal` — The save-your-account-number modal (the 32-digit sign-in number is shown ONCE; users must download it and paste it back to verify). The single most safety-critical copy in the product. *(8 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `reveal.title` | Save your account number now | شمارهٔ حساب خود را همین حالا ذخیره کنید |
| `reveal.subtitle` | This 32-digit number is the ONLY way to sign in again. There is no email or password to recover it. If you lose it, your account is gone for good. | این شمارهٔ ۳۲ رقمی تنها راه ورود دوباره است. هیچ ایمیل یا رمز عبوری برای بازیابی آن وجود ندارد. اگر آن را گم کنید، حسابتان برای همیشه از دست می‌رود. |
| `reveal.cannotRecover` | We cannot recover it for you - not even support can. | ما نمی‌توانیم آن را برایتان بازیابی کنیم - حتی پشتیبانی هم نمی‌تواند. |
| `reveal.saveHint` | Save it in a password manager, or write it down somewhere safe and private. | آن را در یک مدیر رمز عبور ذخیره کنید یا در جایی امن و خصوصی یادداشت کنید. |
| `reveal.downloadRequired` | Download your account number to continue. Keep the file somewhere safe. | ⚠️ **MISSING** |
| `reveal.continue` | Continue | ⚠️ **MISSING** |
| `reveal.verifyTitle` | Confirm you saved it | ⚠️ **MISSING** |
| `reveal.verifySubtitle` | Your account number is now hidden. Enter or paste it from the copy you just saved to confirm you can sign in later. | ⚠️ **MISSING** |
| `reveal.verifyPlaceholder` | Paste your 32-digit account number | ⚠️ **MISSING** |
| `reveal.verifyMismatch` | That doesn't match your account number. Check the copy you saved, or go back to see it again. | ⚠️ **MISSING** |
| `reveal.back` | Back | ⚠️ **MISSING** |
| `reveal.done` | I've saved it | ذخیره کردم |
| `reveal.savedConfirmed` | Account number saved and verified | ⚠️ **MISSING** |
| `reveal.downloadFilename` | freesocks-account-number.txt | شماره حساب freesocks.txt |
| `reveal.leaveWarning` | Your account number is still on screen. If you leave now without saving it, you will not be able to sign in again. | شمارهٔ حساب شما هنوز روی صفحه است. اگر اکنون بدون ذخیره‌کردن خارج شوید، دیگر نمی‌توانید وارد شوید. |

## `support` — The support-ID line (a non-secret handle for contacting support). *(2 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `support.label` | Support ID | شناسهٔ پشتیبانی |
| `support.hint` | Share this if you contact us. It is NOT your sign-in number and grants no access. | اگر با ما تماس گرفتید این را به اشتراک بگذارید. این شمارهٔ ورود شما نیست و دسترسی‌ای نمی‌دهد. |
| `support.emailUs` | Email us: | ⚠️ **MISSING** |
| `support.getAccountLine` | Questions or problems? Email us at | ⚠️ **MISSING** |

## `login` — The sign-in page (account number + optional passkey). *(1 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `login.title` | Sign in with your account number | با شمارهٔ حساب خود وارد شوید |
| `login.subtitle` | Enter the 32-digit account number you saved. It's the only way to sign in - there's no email or password to recover. | شمارهٔ حساب ۳۲ رقمی‌ای را که ذخیره کرده‌اید وارد کنید. این تنها راه ورود است - ایمیل یا رمز عبوری برای بازیابی وجود ندارد. |
| `login.label` | Account number | شمارهٔ حساب |
| `login.show` | Show | نمایش |
| `login.hide` | Hide | پنهان |
| `login.submit` | Sign in | ورود |
| `login.submitting` | Signing in… | در حال ورود… |
| `login.noAccount` | Don't have an account number yet? | هنوز شمارهٔ حساب ندارید؟ |
| `login.getOne` | Get a free account | دریافت حساب رایگان |
| `login.failed` | Sign-in failed | ورود ناموفق بود |
| `login.success` | Signed in | وارد شدید |
| `login.sessionExpired` | Please sign in again - your session may have ended. | لطفاً دوباره وارد شوید - ممکن است نشست شما پایان یافته باشد. |
| `login.digitProgress` | {count} of {total} digits entered | {count} از {total} رقم وارد شده است |
| `login.or` | or | ⚠️ **MISSING** |

## `passkey` — Optional passkey (Face ID / fingerprint) sign-in management. *(20 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `passkey.title` | Passkeys | ⚠️ **MISSING** |
| `passkey.desc` | Sign in with Face ID, Touch ID, a security key, or your password manager - no account number to type. | ⚠️ **MISSING** |
| `passkey.warning` | Heads-up: a passkey saved on your phone or in your browser may sync to your Apple or Google account, which can link this anonymous account to that identity. Use a hardware security key, or skip passkeys, if that matters to you. | ⚠️ **MISSING** |
| `passkey.unsupported` | This device or browser doesn't support passkeys. | ⚠️ **MISSING** |
| `passkey.none` | No passkeys yet. Your account number still signs you in. | ⚠️ **MISSING** |
| `passkey.add` | Add a passkey | ⚠️ **MISSING** |
| `passkey.adding` | Adding… | ⚠️ **MISSING** |
| `passkey.added` | Passkey added | ⚠️ **MISSING** |
| `passkey.addFailed` | Couldn't add the passkey | ⚠️ **MISSING** |
| `passkey.remove` | Remove | ⚠️ **MISSING** |
| `passkey.removed` | Passkey removed | ⚠️ **MISSING** |
| `passkey.removeFailed` | Couldn't remove the passkey | ⚠️ **MISSING** |
| `passkey.deviceLabelLabel` | Device name (optional) | ⚠️ **MISSING** |
| `passkey.deviceLabelPlaceholder` | e.g. My phone | ⚠️ **MISSING** |
| `passkey.addedOn` | Added {date} | ⚠️ **MISSING** |
| `passkey.lastUsed` | last used {date} | ⚠️ **MISSING** |
| `passkey.signIn` | Sign in with a passkey | ⚠️ **MISSING** |
| `passkey.signingIn` | Authenticating… | ⚠️ **MISSING** |
| `passkey.signInFailed` | Passkey sign-in failed | ⚠️ **MISSING** |
| `passkey.notNow` | Not now | ⚠️ **MISSING** |

## `account` — The signed-in /account dashboard: connection, membership, codes, security tabs. *(1 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `account.title` | Your account | حساب شما |
| `account.tierLabel` | Your plan | پلن شما |
| `account.statusActive` | Active | فعال |
| `account.statusGrace` | Expiring soon | به‌زودی منقضی می‌شود |
| `account.statusDisabled` | Disabled | منقضی شده |
| `account.regenerate` | Create a new key | ساخت کلید جدید |
| `account.switchBackend` | Switch server type | تغییر نوع سرور |
| `account.rotate` | Change account number | تغییر شمارهٔ حساب |
| `account.signOut` | Sign out | خروج |
| `account.redeemTitle` | Have a membership code? | کد عضویت دارید؟ |
| `account.redeemPlaceholder` | FSM-XXXX-XXXX-XXXX | FSM-XXXX-XXXX-XXXX |
| `account.redeemSubmit` | Redeem code | استفاده از کد |
| `account.redeemSuccess` | Redeemed - you're now on {tier} for {days} more days. | استفاده شد - اکنون {days} روز دیگر در {tier} هستید. |
| `account.redeemFailed` | That code is not valid, or has already been used. | این کد معتبر نیست یا قبلاً استفاده شده است. |
| `account.redeemAriaLabel` | Membership code | کد عضویت |
| `account.switchTo` | Switch to {label} | تغییر به {label} |
| `account.devicesTitle` | Connected devices | دستگاه‌های متصل |
| `account.lastSeen` | Last seen {date} | آخرین اتصال {date} |
| `account.noSubTitle` | No subscription yet | هنوز اشتراکی ندارید |
| `account.noSubBody` | Create your first subscription to get a URL you can use in any compatible VPN client. | اولین اشتراک خود را بسازید تا لینکی دریافت کنید که در هر برنامهٔ VPN سازگار قابل استفاده است. |
| `account.createSub` | Create subscription | ساخت اشتراک |
| `account.creating` | Creating… | در حال ساخت… |
| `account.rotateTitle` | Change your account number? | شمارهٔ حساب تغییر کند؟ |
| `account.rotateBody` | A new 32-digit number is generated and shown once. Your current number stops working immediately. Anyone who has it loses access. Do this if your number may have leaked. | یک شمارهٔ ۳۲ رقمی جدید ساخته و فقط یک بار نمایش داده می‌شود. شمارهٔ فعلی بلافاصله از کار می‌افتد و هر کسی که آن را دارد دسترسی‌اش را از دست می‌دهد. اگر فکر می‌کنید شماره‌تان لو رفته این کار را انجام دهید. |
| `account.rotateConfirm` | Yes, change it | بله، تغییر بده |
| `account.rotating` | Rotating… | در حال تغییر… |
| `account.rotateFailedTitle` | Could not change the account number | تغییر شمارهٔ حساب ناموفق بود |
| `account.refreshMembership` | Already paid? Check for my membership | قبلاً پرداخت کرده‌اید؟ عضویتم را بررسی کن |
| `account.memberActiveTitle` | Membership active | عضویت فعال |
| `account.memberActiveExpiry` | Active until {date} | فعال تا {date} |
| `account.membershipNudge.title` | Go unlimited with a membership | با عضویت نامحدود شوید |
| `account.membershipNudge.body` | Unlimited bandwidth and devices. | پهنای باند و دستگاه‌های نامحدود. |
| `account.membershipNudge.bodyNoDevices` | Unlimited bandwidth. | ⚠️ **MISSING** |
| `account.membershipNudge.cta` | View membership | مشاهده عضویت |
| `account.tab.connection` | Connection | اتصال |
| `account.tab.membership` | Membership | عضویت |
| `account.tab.codes` | Codes & gifts | کدها و هدایا |
| `account.tab.security` | Security | امنیت |
| `account.refreshing` | Refreshing… | در حال به‌روزرسانی… |
| `account.regenSuccessTitle` | New subscription URL generated | لینک اشتراک جدید ساخته شد |
| `account.regenSuccessBody` | Re-import it on each of your devices. The old URL works for 24 more hours. | آن را دوباره در همهٔ دستگاه‌هایتان وارد کنید. لینک قبلی تا ۲۴ ساعت دیگر کار می‌کند. |
| `account.regenFailedTitle` | Could not create a new key | ساخت کلید جدید ناموفق بود |
| `account.switchSuccessTitle` | Switched to {tier} | به {tier} تغییر کرد |
| `account.switchSuccessBodyGrace` | Re-import the new subscription URL on each device. The old subscription works for 24 more hours. | لینک اشتراک جدید را در همهٔ دستگاه‌ها وارد کنید. اشتراک قبلی تا ۲۴ ساعت دیگر کار می‌کند. |
| `account.switchSuccessBody` | Re-import the new subscription URL on each device. | لینک اشتراک جدید را در همهٔ دستگاه‌ها وارد کنید. |
| `account.switchFailedTitle` | Could not switch server type | تغییر نوع سرور ناموفق بود |
| `account.refreshWelcome` | Welcome to {tier} | به {tier} خوش آمدید |
| `account.refreshNoneTitle` | No active membership found yet | هنوز عضویت فعالی یافت نشد |
| `account.refreshNoneBody` | If you just paid, give it a moment and try again. | اگر همین حالا پرداخت کرده‌اید، کمی صبر کنید و دوباره امتحان کنید. |
| `account.refreshFailedTitle` | Could not refresh membership | به‌روزرسانی عضویت ناموفق بود |
| `account.graceTitle` | Your account is in a grace period | حساب شما در مهلت ارفاقی است |
| `account.graceBody` | Your membership has lapsed, so this account will be limited soon. Renew - donate or redeem a membership code below - to keep your plan. | عضویت شما به پایان رسیده و این حساب به‌زودی محدود می‌شود. برای حفظ پلن خود تمدید کنید - کمک مالی کنید یا کد عضویت را در پایین وارد کنید. |
| `account.disabledTitle` | Your account is currently disabled | حساب شما در حال حاضر غیرفعال است |
| `account.disabledBody` | New keys and changes are paused on this account. Redeem a membership code below to reactivate it, or contact support and share your Support ID. | ساخت کلید جدید و تغییرات در این حساب متوقف شده است. برای فعال‌سازی دوباره، کد عضویت را در پایین وارد کنید یا با پشتیبانی تماس بگیرید و شناسهٔ پشتیبانی خود را اعلام کنید. |
| `account.rotateHint` | Replace your 32-digit account number if it may have leaked - or, if you never saved it, rotate now to get a fresh one you can save. The old one stops working immediately. | اگر شماره حساب ۳۲ رقمی شما لو رفته باشد، آن را تغییر دهید. شماره قبلی فوراً از کار می‌افتد. |
| `account.keyActionsHint` | These change your VPN connection only - your 32-digit account number stays the same. | این‌ها فقط اتصال پروکسی شما را تغییر می‌دهند - شماره حساب ۳۲ رقمی شما ثابت می‌ماند. |
| `account.section.connection.title` | Your connection | ارتباط شما |
| `account.section.connection.desc` | Your VPN key, setup help, and connected devices. | کلید پروکسی شما، راهنمای راه‌اندازی و دستگاه‌های متصل. |
| `account.section.membership.title` | Membership | عضویت |
| `account.section.membership.desc` | Your plan, and how to upgrade or extend it. | طرح شما و نحوه ارتقا یا تمدید آن. |
| `account.section.codes.title` | Codes & gifts | کدها و هدایا |
| `account.section.codes.desc` | Redeem a membership code, or buy codes to share with others. | یک کد عضویت را بازخرید کنید، یا کدهایی را برای اشتراک‌گذاری با دیگران خریداری کنید. |
| `account.section.security.title` | Account & security | حساب کاربری و امنیت |
| `account.section.security.desc` | Your support ID and account-number controls. | کنترل‌های شناسه پشتیبانی و شماره حساب شما. |
| `account.deviceRevoke` | Revoke | لغو |
| `account.deviceRevokedTitle` | Device revoked | دستگاه باطل شد |
| `account.deviceRevokedBody` | The slot is free. That device loses access until it re-imports your subscription. | اسلات خالی است. آن دستگاه تا زمانی که اشتراک شما را دوباره وارد نکند، دسترسی خود را از دست می‌دهد. |
| `account.deviceRevokeFailedTitle` | Couldn't revoke the device | نتوانستم دستگاه را باطل کنم |

## `hero` — The subscription panel: the key/URL block, traffic + expiry stats, QR, status callouts. *(8 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `hero.titleDefault` | Your subscription | اشتراک شما |
| `hero.eyebrowAccessKey` | Your access key | کلید دسترسی شما |
| `hero.urlLabelSubscription` | Subscription URL | لینک اشتراک |
| `hero.urlLabelAccessKey` | Access key | کلید دسترسی |
| `hero.tierLine` | Plan {tier} | سطح {tier} |
| `hero.viaLine` | via {backend} | از طریق {backend} |
| `hero.copyUrl` | Copy URL | کپی لینک |
| `hero.copiedShort` | Copied | کپی شد |
| `hero.qrShow` | QR | QR |
| `hero.qrHide` | Hide | پنهان |
| `hero.scanPhone` | Scan with your phone | با تلفن خود اسکن کنید |
| `hero.scanOther` | Scan with another device | با دستگاه دیگری اسکن کنید |
| `hero.importTitle` | Add to your app | افزودن به برنامه |
| `hero.importPlain` | Plain link | پیوند ساده |
| `hero.importOpen` | Open in {app} | باز کردن در {app} |
| `hero.importScan` | Scan to add to {app} | برای افزودن به {app} اسکن کنید |
| `hero.importOpenHint` | Tap to import on this device, or scan the code from your phone. | برای وارد کردن روی همین دستگاه ضربه بزنید، یا کد را با گوشی خود اسکن کنید. |
| `hero.scanFallback` | Scan the fallback on another device | لینک جایگزین را با دستگاه دیگری اسکن کنید |
| `hero.fallbackLabel` | Fallback URL | لینک جایگزین |
| `hero.fallbackHint` | Use this if the main URL gets blocked | اگر لینک اصلی مسدود شد از این استفاده کنید |
| `hero.fallbackQrAria` | Show fallback URL QR code | نمایش کد QR لینک جایگزین |
| `hero.downloaded` | Downloaded {filename} | {filename} دانلود شد |
| `hero.traffic` | Traffic | ترافیک |
| `hero.unlimited` | Unlimited | نامحدود |
| `hero.configBelowNote` | Your full configuration is below - add the servers by hand. For privacy, the auto-updating subscription link isn't shown by default (your app would fetch it through a CDN). | ⚠️ **MISSING** |
| `hero.showUrlAnyway` | Show the subscription link anyway | ⚠️ **MISSING** |
| `hero.urlDangerBody` | This link works in any app, but the app then downloads your configuration through a third-party CDN in plain text - the CDN operator can see your server details and that you use FreeSocks. That is exactly what this focus avoids. Use it only if your app cannot import the configuration below. | ⚠️ **MISSING** |
| `hero.usedSoFar` | {amount} used so far | {amount} مصرف شده |
| `hero.leftThisPeriod` | {amount} left this period. | {amount} از این دوره باقی مانده. |
| `hero.nearlyOut` | Nearly out, only {amount} left this period. | رو به اتمام - فقط {amount} از این دوره باقی مانده. |
| `hero.expires` | Expires | انقضا |
| `hero.noExpiry` | No expiry | بدون انقضا |
| `hero.expiresToday` | Expires today | امروز منقضی می‌شود |
| `hero.daysRemaining [countPlural=one]` | 1 day remaining | 1 روز باقی مانده |
| `hero.daysRemaining [countPlural=other]` | {count} days remaining | {count} روز باقی مانده |
| `hero.expiredDaysAgo [countPlural=one]` | Expired 1 day ago | 1 روز پیش منقضی شد |
| `hero.expiredDaysAgo [countPlural=other]` | Expired {count} days ago | {count} روز پیش منقضی شد |
| `hero.nodeOnline` | Node online | ⚠️ **MISSING** |
| `hero.nodeOffline` | Node offline | ⚠️ **MISSING** |
| `hero.nodeUnknown` | Node status unknown | ⚠️ **MISSING** |
| `hero.nodeOnlineHint` | The server behind your config is up and responding. If you still can't connect, your network or ISP is likely filtering it - try another connection mode or location. | ⚠️ **MISSING** |
| `hero.nodeOfflineBody` | The server behind your config is currently offline. This is on our side, not your network. Try again in a few minutes, or create a new config (optionally in a different location). | ⚠️ **MISSING** |
| `hero.keyLimited` | You've used all your data for this period. It resets automatically, or you can upgrade for more. | شما تمام داده‌های خود را برای این مدت استفاده کرده‌اید. به‌طور خودکار بازنشانی می‌شود، یا می‌توانید برای اطلاعات بیشتر ارتقا دهید. |
| `hero.keyExpired` | This key has expired. Renew your membership or create a new key to reconnect. | این کلید منقضی شده است. عضویت خود را تمدید کنید یا برای اتصال مجدد، کلید جدیدی ایجاد کنید. |
| `hero.keyDisabled` | This key is currently disabled. If your membership lapsed, renew it; otherwise contact support with your support ID. | این کلید در حال حاضر غیرفعال است. اگر عضویت شما منقضی شده است، آن را تمدید کنید؛ در غیر این صورت با شناسه پشتیبانی خود با پشتیبانی تماس بگیرید. |
| `hero.resetsInDays [countPlural=one]` | Resets in 1 day | ۱ روز دیگه ریست میشه |
| `hero.resetsInDays [countPlural=other]` | Resets in {count} days | مقدار را در {count} روز تنظیم مجدد می‌کند |

## `location` — Miscellaneous strings. *(4 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `location.pickerLabel` | Server location | ⚠️ **MISSING** |
| `location.auto` | Automatic (least busy) | ⚠️ **MISSING** |
| `location.offline` | offline | ⚠️ **MISSING** |
| `location.pickerHint` | Where your config's server is. Automatic picks the least busy location; pick one yourself if it works better on your network. | ⚠️ **MISSING** |

## `usage` — The 30-day usage trend under the traffic stats.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `usage.show` | Show usage trend | نمایش روند استفاده |
| `usage.title` | Usage (last 30 days) | میزان استفاده (30 روز گذشته) |
| `usage.total` | {amount} used in the last 30 days | {amount} در 30 روز گذشته استفاده شده است |
| `usage.unavailable` | Usage isn't available right now. | امکان استفاده در حال حاضر وجود ندارد. |
| `usage.none` | No usage recorded yet. | هنوز هیچ استفاده‌ای ثبت نشده است. |

## `regen` — The regenerate-subscription confirmation dialog.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `regen.title` | Create a new subscription URL? | اشتراک از نو ساخته شود؟ |
| `regen.body` | Your current subscription URL (ending …{suffix}) will be replaced with a new one. The old URL becomes read-only for 24 hours, then is deleted. | لینک اشتراک فعلی شما (با پایان …{suffix}) با لینک جدیدی جایگزین می‌شود. لینک قبلی ۲۴ ساعت فقط‌خواندنی می‌ماند و سپس حذف می‌شود. |
| `regen.point1` | Your current key remains usable for the next 24 hours | کلید فعلی شما تا ۲۴ ساعت آینده قابل استفاده می‌ماند |
| `regen.point2` | You'll need to re-import the new URL in each of your devices | باید لینک جدید را در هر یک از دستگاه‌هایتان دوباره وارد کنید |
| `regen.pointDevices [countPlural=one]` | You currently have 1 connected device - it will need the new URL | اکنون 1 دستگاه متصل دارید - همگی به لینک جدید نیاز دارند |
| `regen.pointDevices [countPlural=other]` | You currently have {count} connected devices - they will all need the new URL | اکنون {count} دستگاه متصل دارید - همگی به لینک جدید نیاز دارند |
| `regen.confirm` | Create new URL | ساخت دوباره |
| `regen.working` | Creating… | در حال ساخت… |

## `switch` — The switch-backend confirmation dialog.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `switch.title` | Switch to {to}? | تغییر به {to}؟ |
| `switch.body` | Your current {from} subscription will be replaced with a new {to} one. The old subscription stays usable for 24 hours so you can re-import on every device before it stops working. | اشتراک فعلی {from} شما با اشتراک جدید {to} جایگزین می‌شود. اشتراک قبلی ۲۴ ساعت قابل استفاده می‌ماند تا پیش از قطع شدن، لینک جدید را روی همهٔ دستگاه‌ها وارد کنید. |
| `switch.point1` | A new subscription URL is issued on the {to} backend | یک لینک اشتراک جدید روی بک‌اند {to} صادر می‌شود |
| `switch.point2` | The current {from} URL keeps working for 24 hours, then is deleted | لینک فعلی {from} تا ۲۴ ساعت کار می‌کند و سپس حذف می‌شود |
| `switch.point3` | You'll need to re-import the new URL in each VPN client you use | باید لینک جدید را در هر برنامهٔ VPN که استفاده می‌کنید دوباره وارد کنید |
| `switch.pointDevices [countPlural=one]` | You currently have 1 connected device - re-import on it | اکنون 1 دستگاه متصل دارید - روی همهٔ آن‌ها دوباره وارد کنید |
| `switch.pointDevices [countPlural=other]` | You currently have {count} connected devices - re-import on all of them | اکنون {count} دستگاه متصل دارید - روی همهٔ آن‌ها دوباره وارد کنید |
| `switch.confirm` | Switch to {to} | تغییر به {to} |
| `switch.working` | Switching… | در حال تغییر… |

## `get` — The /get-account sign-up flow: create account (step 1) and create subscription (step 2). *(4 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `get.badge` | Free account | حساب رایگان |
| `get.title` | Get a FreeSocks account | دریافت حساب فری‌ساکس |
| `get.introTwoSteps` | Two quick steps: solve the human-check to create a free account, then create your subscription. | دو مرحلهٔ سریع: بررسی انسانی را انجام دهید تا حساب رایگان ساخته شود، سپس اشتراک خود را بسازید. |
| `get.step1Title` | Create your account | حساب خود را بسازید |
| `get.chooseBackend` | Choose a connection type | نوع اتصال را انتخاب کنید |
| `get.backendAria` | Connection type | نوع اتصال |
| `get.backendMultiProtocol` | VLESS (Xray) | VLESS (Xray) |
| `get.backendShadowsocks` | Shadowsocks via Outline | Shadowsocks از طریق Outline |
| `get.createAccount` | Create my account | ساخت حساب من |
| `get.freeAccountNote` | Free accounts are valid for {days} days and limited to {devices}. No email or password. | حساب‌های رایگان {days} روز اعتبار دارند و به {devices} محدودند. بدون ایمیل یا رمز عبور. |
| `get.freeAccountNoteNoDevices` | Free accounts are valid for {days} days. No email or password. | ⚠️ **MISSING** |
| `get.accountReady` | Your account is ready | حساب شما آماده است. |
| `get.nextStepHint` | One step left - your account can't connect to anything until you create your subscription. | ⚠️ **MISSING** |
| `get.nextStepCta` | Next: create your subscription | ⚠️ **MISSING** |
| `get.nextStepBadge` | Next step | ⚠️ **MISSING** |
| `get.step2Title` | Create your subscription | اشتراک خود را بسازید |
| `get.step2Intro` | Create a subscription to get a URL you can paste into any compatible VPN client. | یک اشتراک پروکسی بسازید تا لینکی دریافت کنید که می‌توانید در هر برنامهٔ VPN سازگار جای‌گذاری کنید. |
| `get.manageHintPrefix` | Manage this subscription anytime from | این اشتراک را هر زمان مدیریت کنید از |
| `get.manageLinkLabel` | your account | حساب شما |
| `get.subErrorSafePrefix` | Your account is safe. You can create the subscription later from | حساب شما امن است. بعداً می‌توانید اشتراک را بسازید از |
| `get.subErrorSafeSuffix` | once a server is available. | وقتی سروری در دسترس شد. |
| `get.createSubToastTitle` | Subscription created | اشتراک ساخته شد |
| `get.createSubToastBody` | Copy the URL into your VPN client, or scan the QR code. | لینک را در برنامهٔ VPN خود کپی کنید یا کد QR را اسکن کنید. |
| `get.createAccountFailedTitle` | Could not create account | ساخت حساب ناموفق بود |
| `get.createSubFailedTitle` | Could not create subscription | ساخت اشتراک ناموفق بود |
| `get.haveAccountPrefix` | Already have an account? | از قبل حساب دارید؟ |
| `get.lostNumberHint` | Lost your account number before saving it? You can switch to a new one - | شمارهٔ حساب را پیش از ذخیره گم کردید؟ می‌توانید شمارهٔ جدیدی بگیرید - |
| `get.lostNumberLinkLabel` | change it from your account page | از صفحهٔ حساب خود آن را تغییر دهید |
| `get.upsellTitle` | Want unlimited? | نامحدود می‌خواهید؟ |
| `get.upsellBody` | Upgrade to a FreeSocks membership any time for unlimited bandwidth and devices. | هر زمان خواستید به عضویت FreeSocks ارتقا دهید تا پهنای باند و دستگاه‌های نامحدود داشته باشید. |
| `get.redeemTitle` | Got a gift code? | کد هدیه گرفتی؟ |
| `get.redeemBody` | Redeem it now to upgrade your new account instantly. | همین حالا آن را بازخرید کنید تا فوراً حساب جدید خود را ارتقا دهید. |

## `tiers` — The plan-comparison cards (Free vs Membership limits).

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `tiers.title` | Tiers | سطح‌ها |
| `tiers.subtitle` | What each tier includes. | هر سطح چه چیزهایی دارد. |
| `tiers.yourTier` | Your plan | سطح شما |
| `tiers.gbPerMonth` | {gb} GB / month | {gb} گیگابایت / ماه |
| `tiers.mirrors` | Mirror URLs | لینک‌های آینه |
| `tiers.upgradeCta` | Upgrade | ارتقا |

## `impact` — The donation-impact panel: bandwidth donated, free users helped, charts. *(16 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `impact.title` | Donations support Unredacted | کمک‌های مالی از Unredacted پشتیبانی می‌کنند |
| `impact.body` | Unredacted is a US 501(c)(3) nonprofit. FreeSocks is one of the projects it runs. Donations fund the work. See what that work is on the Unredacted site. | Unredacted یک سازمان غیرانتفاعی 501(c)(3) آمریکایی است. فری‌ساکس یکی از پروژه‌های آن است. کمک‌های مالی هزینهٔ این کار را تأمین می‌کنند. جزئیات را در سایت Unredacted ببینید. |
| `impact.collectiveTitle` | Donation impact | ⚠️ **MISSING** |
| `impact.collectiveBody` | Donations made through FreeSocks raise every free user's monthly bandwidth for the month they're given. This is what the community's donations are doing right now. | ⚠️ **MISSING** |
| `impact.bonusThisMonth` | GB added this month | ⚠️ **MISSING** |
| `impact.bonusThisMonthDetail` | on top of every free account's monthly allowance | ⚠️ **MISSING** |
| `impact.usersHelped` | free accounts reached | ⚠️ **MISSING** |
| `impact.usersHelpedDetail` | active free users whose allowance the bonus raises | ⚠️ **MISSING** |
| `impact.historyTitle` | Bandwidth added per month | ⚠️ **MISSING** |
| `impact.chartAria` | Bandwidth added to every free user by donations, month by month over the last {n} months | ⚠️ **MISSING** |
| `impact.yourContribution` | Your contribution | ⚠️ **MISSING** |
| `impact.yourGiven` | You've given {amount} | ⚠️ **MISSING** |
| `impact.yourGb` | That's about {gb} GB of extra bandwidth for free users | ⚠️ **MISSING** |
| `impact.yourCount [countPlural=one]` | across 1 donation | ⚠️ **MISSING** |
| `impact.yourCount [countPlural=other]` | across {count} donations | ⚠️ **MISSING** |
| `impact.empty` | No donations yet this month - the first one starts the counter. | ⚠️ **MISSING** |
| `impact.externalNote` | This counter tracks donations made through FreeSocks only. Gifts made directly at unredacted.org/donate support Unredacted's wider work, but don't add bandwidth here. | ⚠️ **MISSING** |
| `impact.aboutUnredacted` | About Unredacted | ⚠️ **MISSING** |

## `donate` — The donation card + amount picker (donations add bandwidth for all free users). *(18 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `donate.addTitle` | Add a donation | ⚠️ **MISSING** |
| `donate.addSubtitle` | Chip in to help keep FreeSocks free for everyone. | ⚠️ **MISSING** |
| `donate.standaloneTitle` | Donate to FreeSocks | ⚠️ **MISSING** |
| `donate.standaloneSubtitle` | FreeSocks is free for everyone, funded by donations. Give any amount to help keep it running - a donation also raises this month's bandwidth for every free user. | ⚠️ **MISSING** |
| `donate.amountLabel` | Amount | ⚠️ **MISSING** |
| `donate.none` | No thanks | ⚠️ **MISSING** |
| `donate.custom` | Custom | ⚠️ **MISSING** |
| `donate.customPlaceholder` | Other amount | ⚠️ **MISSING** |
| `donate.impact` | Adds about {gb} GB to every free user this month | ⚠️ **MISSING** |
| `donate.bonusActive` | Donations this month have added {gb} GB to every free user's monthly allowance. | ⚠️ **MISSING** |
| `donate.minNote` | Minimum {amount} | ⚠️ **MISSING** |
| `donate.give` | Donate {amount} | ⚠️ **MISSING** |
| `donate.giving` | Starting… | ⚠️ **MISSING** |
| `donate.startFailed` | Couldn't start the donation | ⚠️ **MISSING** |
| `donate.badge` | Donor | ⚠️ **MISSING** |
| `donate.badgeTooltip` | Thank you for supporting FreeSocks | ⚠️ **MISSING** |
| `donate.thanksTitle` | You're a FreeSocks donor | ⚠️ **MISSING** |
| `donate.thanksBody` | Thank you - your support helps keep FreeSocks free for everyone. | ⚠️ **MISSING** |

## `qr` — QR-code helper labels.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `qr.ariaLabel` | QR code for the subscription URL | کد QR لینک اشتراک |
| `qr.failed` | Couldn't generate the QR code. | کد QR ایجاد نشد. |

## `app` — App-level chrome (skip link, page titles).

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `app.skipToContent` | Skip to content | رفتن به محتوا |
| `app.notFound` | Not found | یافت نشد |
| `app.goHome` | Go home | بازگشت به خانه |
| `app.adminLoadFailedTitle` | Couldn't load the admin console | نتوانستم کنسول مدیریت را بارگیری کنم |
| `app.adminLoadFailedBody` | The network request for this section failed. Reload to retry. | درخواست شبکه برای این بخش ناموفق بود. برای تلاش مجدد، دوباره بارگیری کنید. |

## `footer` — The site footer (nonprofit line, terms/privacy links). *(8 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `footer.operatedPrefix` | Operated by | اداره‌شده توسط |
| `footer.operatedSuffix` | , a US 501(c)(3) nonprofit | ، یک سازمان غیرانتفاعی 501(c)(3) آمریکایی |
| `footer.viewSource` | View source | ⚠️ **MISSING** |
| `footer.terms` | Terms of Service | ⚠️ **MISSING** |
| `footer.privacy` | Privacy Policy | ⚠️ **MISSING** |
| `footer.transparency` | Transparency Report | ⚠️ **MISSING** |
| `footer.socialX` | FreeSocks on X | ⚠️ **MISSING** |
| `footer.socialMastodon` | FreeSocks on Mastodon | ⚠️ **MISSING** |
| `footer.socialBluesky` | FreeSocks on Bluesky | ⚠️ **MISSING** |
| `footer.support` | Support | ⚠️ **MISSING** |

## `renew` — Expiring/expired membership callouts and renewal prompts.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `renew.expiringTitle` | Your membership is expiring soon | عضویت شما به‌زودی منقضی می‌شود |
| `renew.expiredTitle` | Your membership has expired | عضویت شما منقضی شده است |
| `renew.body` | FreeSocks is community-funded - donations keep it running. To renew your membership, donate or contact us for a membership code. | فری‌ساکس با کمک‌های مردمی اداره می‌شود. برای تمدید عضویت، کمک مالی کنید یا برای دریافت کد عضویت با ما تماس بگیرید. |
| `renew.donate` | Donate | کمک مالی |
| `renew.contact` | Contact us | تماس با ما |
| `renew.lapsedBody` | You're on the free tier now. Renew below to restore your membership. | اکنون در طرح رایگان هستید. برای بازگرداندن عضویت خود، از پایین تمدید کنید. |
| `renew.renewCta` | Renew membership | تمدید عضویت |

## `upgrade` — The paid-membership purchase panel (payment method, duration, totals). *(4 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `upgrade.title` | Upgrade to a FreeSocks membership | به عضویت FreeSocks ارتقا دهید |
| `upgrade.extendTitle` | Extend your membership | عضویت خود را تمدید کنید |
| `upgrade.subtitle` | Unlimited bandwidth and devices. Choose a length and how to pay. | پهنای باند و دستگاه‌های نامحدود. مدت و روش پرداخت را انتخاب کنید. |
| `upgrade.subtitleNoDevices` | Unlimited bandwidth. Choose a length and how to pay. | ⚠️ **MISSING** |
| `upgrade.durationLabel` | Membership length | مدت عضویت |
| `upgrade.cryptoMinNote` | Crypto payments start at {months} months - shorter terms fall below the network minimum. Pick another method for shorter terms. | پرداخت رمزارزی از {months} ماه شروع می‌شود - مدت‌های کوتاه‌تر کمتر از حداقل شبکه هستند. برای مدت کوتاه‌تر روش دیگری انتخاب کنید. |
| `upgrade.months [countPlural=one]` | 1 month | 1 ماه |
| `upgrade.months [countPlural=other]` | {count} months | {count} ماه |
| `upgrade.perMonth` | {price}/mo | {price}/ماه |
| `upgrade.fromPerMonth` | From {price}/month | ⚠️ **MISSING** |
| `upgrade.benefitsShort` | Unlimited bandwidth and devices | ⚠️ **MISSING** |
| `upgrade.benefitsShortNoDevices` | Unlimited bandwidth | ⚠️ **MISSING** |
| `upgrade.save` | save {pct}% | {pct}٪ صرفه‌جویی |
| `upgrade.methodLabel` | Payment method | روش پرداخت |
| `upgrade.payNowpayments` | Cryptocurrency | ارز دیجیتال |
| `upgrade.payNowpaymentsHint` | Bitcoin, Monero, Zcash & more | بیت‌کوین، مونرو و بیشتر |
| `upgrade.payNowpaymentsBadge` | Private | خصوصی |
| `upgrade.cryptoPrivacyNote` | No account, email, or card needed - pay privately. Monero and Zcash offer the most privacy. | بدون نیاز به حساب، ایمیل یا کارت - پرداخت خصوصی. مونرو و زی‌کش بیشترین حریم خصوصی را ارائه می‌دهند. |
| `upgrade.payBtcpay` | Bitcoin | بیت‌کوین |
| `upgrade.payBtcpayHint` | On-chain or Lightning | روی زنجیره یا لایتنینگ |
| `upgrade.payBtcpayBadge` | No intermediary | بدون واسطه |
| `upgrade.payStripe` | Card | کارت |
| `upgrade.payStripeHint` | Credit or debit card | کارت اعتباری یا نقدی |
| `upgrade.payPaypal` | PayPal | پی‌پال |
| `upgrade.payPaypalHint` | PayPal balance or card | موجودی پی‌پال یا کارت |
| `upgrade.total` | Total {price} | مجموع {price} |
| `upgrade.continue` | Continue to payment | ادامه به پرداخت |
| `upgrade.starting` | Starting checkout… | در حال شروع پرداخت… |
| `upgrade.startFailed` | Could not start checkout | شروع پرداخت ممکن نشد |
| `upgrade.noStoreNote` | We never see your card or wallet, and store no payment details. | ما هرگز ایمیل یا اطلاعات پرداخت شما را ذخیره نمی‌کنیم. |
| `upgrade.confirmingTitle` | Confirming your payment… | در حال تأیید پرداخت شما… |
| `upgrade.confirmingBody` | Crypto can take a few minutes to confirm. You can leave this page - your membership activates automatically. | تأیید ارز دیجیتال ممکن است چند دقیقه طول بکشد. می‌توانید این صفحه را ترک کنید - عضویت شما به‌طور خودکار فعال می‌شود. |
| `upgrade.paidTitle` | Membership active | عضویت فعال شد |
| `upgrade.paidBody` | Thank you! Your membership is now active. | متشکریم! عضویت شما اکنون فعال است. |
| `upgrade.failedTitle` | Payment not completed | پرداخت کامل نشد |
| `upgrade.failedBody` | Your payment did not go through, or the checkout expired. You can try again. | پرداخت شما انجام نشد یا مهلت پرداخت به پایان رسید. می‌توانید دوباره تلاش کنید. |

## `gift` — Gift membership codes: buying, revealing (show-once), and redeeming.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `gift.title` | Buy codes to share | خرید کد برای اشتراک گذاری |
| `gift.subtitle` | Purchase membership codes to give to friends or family. Each works on any account and never touches yours. | کدهای عضویت را برای هدیه دادن به دوستان یا خانواده خریداری کنید. هر کدام روی هر حسابی کار می‌کند و هرگز با حساب شما کاری ندارد. |
| `gift.quantityLabel` | How many | چند تا؟ |
| `gift.buy` | Buy codes | خرید کد |
| `gift.starting` | Starting checkout… | شروع تسویه حساب… |
| `gift.startFailed` | Could not start checkout | پرداخت شروع نشد |
| `gift.boughtTitle` | Codes you've bought | کدهایی که خریداری کرده‌اید |
| `gift.boughtEmpty` | You haven't bought any codes yet. | شما هنوز هیچ کدی نخریده‌اید. |
| `gift.statusAvailable` | Available | موجود است |
| `gift.statusRedeemed` | Redeemed | بازخرید شده |
| `gift.statusRevoked` | Revoked | لغو شد |
| `gift.redeemedOn` | Redeemed {date} | بازخرید شده {date} |
| `gift.copyAll` | Copy all | همه را کپی کنید |
| `gift.reveal.title` | Save these codes now | همین حالا این کدها را ذخیره کنید |
| `gift.reveal.body` | Copy and share each code. For security we show them only once - afterwards you will see only a prefix. | هر کد را کپی و به اشتراک بگذارید. برای امنیت، ما آنها را فقط یک بار نشان می‌دهیم - پس از آن فقط یک پیشوند خواهید دید. |
| `gift.reveal.ack` | I have saved these codes | من این کدها را ذخیره کرده‌ام |
| `gift.reveal.saved` | I've saved them | من آنها را ذخیره کرده‌ام |
| `gift.reveal.leaveWarning` | Your codes are still on screen. If you leave now without saving them, you will not be able to see them again. | کدهای شما هنوز روی صفحه هستند. اگر بدون ذخیره کردن آنها از صفحه خارج شوید، دیگر نمی‌توانید آنها را ببینید. |

## `error` — API error messages shown to members.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `error.offline` | You appear to be offline. Check your connection and try again. | به نظر می‌رسد آفلاین هستید. اتصال خود را بررسی و دوباره تلاش کنید. |
| `error.rateLimited` | Too many attempts. Please wait a minute and try again. | تلاش‌های زیاد. لطفاً یک دقیقه صبر کنید و دوباره تلاش کنید. |
| `error.backendUnavailable` | No VPN server is available right now. Your account is safe - try creating your key again in a few minutes. | در حال حاضر هیچ سرور پروکسی در دسترس نیست. حساب شما امن است - چند دقیقه دیگر دوباره کلید بسازید. |
| `error.generic` | Something went wrong. Please try again. | مشکلی پیش آمد. لطفاً دوباره تلاش کنید. |
| `error.captchaFailed` | The human check failed. Please complete it and try again. | بررسی انسانی ناموفق بود. لطفاً آن را کامل کنید و دوباره تلاش کنید. |
| `error.captchaUnconfigured` | The service is temporarily unavailable. Please try again in a few minutes. | سرویس موقتاً در دسترس نیست. لطفاً چند دقیقه دیگر دوباره تلاش کنید. |
| `error.renderTitle` | Something went wrong | چیزی اشتباه پیش رفت |
| `error.renderBody` | The page failed to render. This is a bug in the app, and refreshing usually fixes it. If it keeps happening, please report it. | صفحه نمایش داده نشد. این یک اشکال در برنامه است و معمولاً با رفرش کردن برطرف می‌شود. اگر این مشکل ادامه پیدا کرد، لطفاً آن را گزارش دهید. |
| `error.reloadPage` | Reload page | صفحه را دوباره بارگذاری کنید |
| `error.tryAgain` | Try again | دوباره امتحان کنید |
| `error.sessionExpired` | Your session has ended. Please sign in again. | جلسه شما به پایان رسیده است. لطفاً دوباره وارد شوید. |
| `error.invalidAccountId` | That account number wasn't recognized. Check it and try again. | آن شماره حساب شناسایی نشد. آن را بررسی کنید و دوباره امتحان کنید. |
| `error.codeInvalid` | That code can't be redeemed. Check it for typos and try again. | این کد قابل استفاده نیست. آن را از نظر غلط املایی بررسی کنید و دوباره امتحان کنید. |
| `error.changeInProgress` | Another change is already in progress - try again in a moment. | تغییر دیگری در حال انجام است - چند لحظه دیگر دوباره امتحان کنید. |
| `error.backendDisabled` | That option is currently unavailable. | اون گزینه فعلا در دسترس نیست. |
| `error.noPeerTier` | Switching isn't available for your plan yet. | هنوز امکان تغییر طرح برای شما فراهم نشده است. |
| `error.deviceNotFound` | That device is no longer on your account. | آن دستگاه دیگر در حساب شما نیست. |
| `error.deviceUnsupported` | Your current server type doesn't support removing individual devices. | نوع سرور فعلی شما از حذف دستگاه‌های جداگانه پشتیبانی نمی‌کند. |
| `error.billing` | The payment service couldn't process this. Please try again later. | سرویس پرداخت نتوانست این را پردازش کند. لطفاً بعداً دوباره امتحان کنید. |
| `error.serverError` | The server had a problem handling this. Please try again in a few minutes. | سرور در مدیریت این مشکل داشت. لطفاً چند دقیقه دیگر دوباره امتحان کنید. |

## `setup` — The "set up your app" section: recommended VPN clients per platform, install steps. *(26 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `setup.title` | Set up your VPN app | برنامهٔ پروکسی خود را تنظیم کنید |
| `setup.install` | Install | نصب |
| `setup.noApps` | No recommended apps for this platform yet - use any compatible client and add your subscription manually. | ⚠️ **MISSING** |
| `setup.openSource` | Open source | ⚠️ **MISSING** |
| `setup.proprietary` | Proprietary | ⚠️ **MISSING** |
| `setup.easeEasy` | Easy to use | ⚠️ **MISSING** |
| `setup.easeAdvanced` | Advanced | ⚠️ **MISSING** |
| `setup.viewSource` | Source | ⚠️ **MISSING** |
| `setup.intro` | Copy your subscription link above, then add it to a compatible app: | لینک اشتراک بالا را کپی کنید، سپس آن را به یک برنامهٔ سازگار اضافه کنید: |
| `setup.android` | Android | اندروید |
| `setup.ios` | iPhone / iPad | آیفون / آی‌پد |
| `setup.windows` | Windows | ویندوز |
| `setup.desktop` | macOS / Linux | مک / لینوکس |
| `setup.step.install` | Install the app | برنامه را نصب کنید |
| `setup.step.import` | Open it, add a subscription / profile, and paste your link | آن را باز کنید، یک اشتراک/پروفایل اضافه کنید و لینک خود را جای‌گذاری کنید |
| `setup.step.importConfig` | Open it, choose to add servers manually, and enter the configuration shown below | آن را باز کنید، گزینه افزودن دستی سرورها را انتخاب کنید و پیکربندی نشان داده شده در زیر را وارد کنید. |
| `setup.step.connect` | Select a server and connect | یک سرور انتخاب کنید و متصل شوید |
| `setup.noDeviceLimit` | no device limit | بدون محدودیت دستگاه |
| `setup.hwidNote` | On a device-limited plan, turn on "device identification" (HWID) in the app's settings so your device is recognized. | در طرح‌های محدود به دستگاه، «شناسایی دستگاه» (HWID) را در تنظیمات برنامه فعال کنید تا دستگاه شما شناسایی شود. |
| `setup.deviceCompatibleTitle` | Works with your device limit | ⚠️ **MISSING** |
| `setup.deviceIncompatibleTitle` | Not recommended for your plan | ⚠️ **MISSING** |
| `setup.deviceIncompatibleNote` | These apps don't identify your device, so each launch can use up a device slot - or fail to connect on a device-limited plan. Prefer an app above. | ⚠️ **MISSING** |
| `setup.linkKind.play` | Google Play | ⚠️ **MISSING** |
| `setup.linkKind.appStore` | App Store | ⚠️ **MISSING** |
| `setup.linkKind.github` | GitHub | ⚠️ **MISSING** |
| `setup.linkKind.apk` | APK | ⚠️ **MISSING** |
| `setup.linkKind.website` | Website | ⚠️ **MISSING** |
| `setup.clientDesc.hiddify` | The easiest all-round choice: one-tap import, a clean interface, and builds for every platform. | ⚠️ **MISSING** |
| `setup.clientDesc.karing` | Feature-rich and honors your plan's device limit. Slightly busier than Hiddify, but works well everywhere. | ⚠️ **MISSING** |
| `setup.clientDesc.anywhere` | A polished, easy client for Apple devices only: iPhone, iPad, Apple TV, and Mac. No Android, Windows, or Linux version. | ⚠️ **MISSING** |
| `setup.clientDesc.singBox` | The reference app for the sing-box core. Powerful but minimal, so it's best if you are comfortable with technical settings. | ⚠️ **MISSING** |
| `setup.clientDesc.v2rayng` | A long-standing, lightweight Android client with one-tap import. More utilitarian than Hiddify, but dependable. | ⚠️ **MISSING** |
| `setup.clientDesc.v2rayn` | A powerful desktop app for advanced users. Import is manual, and links using encryption "none" can need a manual tweak. Prefer Hiddify if that sounds fiddly. | ⚠️ **MISSING** |
| `setup.clientDesc.clash` | Clash Verge, a popular desktop app with strong routing rules. Some versions reject VLESS subscription links; if yours won't import, use Hiddify or v2rayN instead. | ⚠️ **MISSING** |
| `setup.clientDesc.flclash` | A clean, cross-platform Clash-family app. Import by pasting your subscription link (no one-tap import). | ⚠️ **MISSING** |
| `setup.clientDesc.mihomoParty` | A friendly desktop app for the Clash (mihomo) core. Paste your subscription link to import. | ⚠️ **MISSING** |
| `setup.clientDesc.throne` | An advanced desktop client that honors your plan's device limit, with solid Linux support. Expect manual setup. | ⚠️ **MISSING** |
| `setup.clientDesc.shadowrocket` | A paid, closed-source iOS app that is popular and reliable. Worth using if you already own it; the open-source apps above do the same job for free. | ⚠️ **MISSING** |
| `setup.clientDesc.outline` | The simplest experience there is: paste your access key and connect. Only works with Outline (Shadowsocks) access keys. | ⚠️ **MISSING** |

## `mirror` — The "trouble connecting? try a mirror" fallback flow.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `mirror.disclosure` | Trouble connecting? | مشکل در اتصال دارید؟ |
| `mirror.explainer` | If your normal subscription link won't connect where you are, add a mirror link below. It serves the same key from a different host that may not be blocked. | اگر لینک اشتراک معمولی شما در محل شما وصل نمی‌شود، یک لینک آینه از پایین اضافه کنید. همان کلید را از میزبانی دیگر که ممکن است مسدود نباشد ارائه می‌دهد. |
| `mirror.addedLabel` | Your mirror links | لینک‌های آینهٔ شما |
| `mirror.addToAppHint` | Add each one as an extra subscription in your app, then try connecting. | هر کدام را به‌عنوان یک اشتراک اضافی در برنامه‌تان وارد کنید و سپس اتصال را امتحان کنید. |
| `mirror.regionLabel` | Your region | منطقهٔ شما |
| `mirror.regionGlobal` | Global (any region) | جهانی (هر منطقه) |
| `mirror.regionNotStored` | Used only to pick a nearby mirror - it isn't stored. | فقط برای انتخاب یک آینهٔ نزدیک استفاده می‌شود - ذخیره نمی‌شود. |
| `mirror.getButton` | Get a mirror link | دریافت لینک آینه |
| `mirror.tryAnother` | Try another mirror | امتحان آینهٔ دیگر |
| `mirror.working` | Working… | در حال انجام… |
| `mirror.capped` | You've added the maximum number of mirrors. | به حداکثر تعداد آینه‌ها رسیده‌اید. |
| `mirror.exhausted` | No more mirrors are available for your region right now. | در حال حاضر آینهٔ دیگری برای منطقهٔ شما موجود نیست. |
| `mirror.noSubscription` | Create your key first, then you can add a mirror. | ابتدا کلید خود را بسازید، سپس می‌توانید آینه اضافه کنید. |
| `mirror.removeAll` | Remove all mirrors | حذف همهٔ آینه‌ها |
| `mirror.errorToast` | Couldn't add a mirror | افزودن آینه ممکن نشد |
| `mirror.removedToast` | Mirrors removed | آینه‌ها حذف شدند |

## `rawconfig` — The raw-configuration viewer (privacy mode delivers config text, not a URL).

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `rawconfig.disclosure` | Show raw configuration | نمایش پیکربندی خام |
| `rawconfig.title` | Your configuration | پیکربندی شما |
| `rawconfig.explainer` | Your full VPN configuration, fetched over an encrypted channel so it never crosses a CDN in plain text. Copy it into your app by hand instead of using a subscription link. | پیکربندی کامل پروکسی شما، که از طریق یک کانال رمزگذاری‌شده دریافت می‌شود تا هرگز به‌صورت متن ساده از CDN عبور نکند. به‌جای استفاده از لینک اشتراک، آن را دستی در برنامه‌تان وارد کنید. |
| `rawconfig.addHint` | Paste these server entries into your VPN app manually. | این ورودی‌های سرور را به‌صورت دستی در برنامهٔ پروکسی خود وارد کنید. |

## `delivery` — The connection-mode picker: "Beat censorship" (for censored countries) vs "Maximum privacy" (for open internet), plus the switch-confirmation dialog. *(6 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `delivery.title` | What matters most to you? | چه چیزی برایتان مهم‌تر است؟ |
| `delivery.subtitle` | Pick a focus. It's saved on this device only, and you can change it anytime. | یک اولویت انتخاب کنید - فقط روی همین دستگاه ذخیره می‌شود و هر زمان می‌توانید تغییرش دهید. |
| `delivery.subtitleServer` | Pick a focus. Changing it moves your existing key to the matching servers - your subscription URL stays the same. | یک نقطه تمرکز انتخاب کنید. تغییر آن، کلید شما را برای سرورهای منطبق دوباره صادر می‌کند؛ کلید فعلی شما به مدت ۲۴ ساعت کار می‌کند. |
| `delivery.subtitleSignup` | Pick a focus. It's saved to your account, and your first key uses it - you can change it anytime. | یک نقطه تمرکز انتخاب کنید. در حساب شما ذخیره می‌شود و اولین کلید شما از آن استفاده می‌کند - هر زمان می‌توانید تغییرش دهید. |
| `delivery.evadeTitle` | Internet Freedom Mode | ⚠️ **MISSING** |
| `delivery.evadeAudience` | For censored countries | ⚠️ **MISSING** |
| `delivery.evadeBody` | Pick this if websites, apps, or VPNs are blocked where you are. Built to keep working under censorship, with backup links that are harder to block. | ⚠️ **MISSING** |
| `delivery.privacyTitle` | Privacy Mode | ⚠️ **MISSING** |
| `delivery.privacyAudience` | For open internet | ⚠️ **MISSING** |
| `delivery.privacyBody` | Pick this if the internet is mostly open where you are. The strongest confidentiality - your configuration stays off third-party servers - but it is easier for censors to block. | ⚠️ **MISSING** |
| `delivery.recommended` | Recommended | پیشنهادی |
| `delivery.unavailable` | Not available yet | هنوز موجود نیست |
| `delivery.confirmTitle` | Switch to "{label}"? | به " {label} "تغییر دهید؟ |
| `delivery.confirmBody` | This moves your existing key to the {label} servers, keeping the same subscription URL. Your apps keep working and pick up the new servers on their next refresh. | این کلید پروکسی شما را برای سرورهای {label} دوباره صادر می‌کند. کلید فعلی شما به مدت ۲۴ ساعت کار می‌کند، بنابراین می‌توانید ابتدا در هر دستگاه دوباره وارد کنید. |
| `delivery.confirmPoint1` | Your key moves to the {label} servers - same subscription URL, nothing to re-import | یک URL اشتراک جدید برای سرورهای {label} صادر می‌شود. |
| `delivery.confirmPoint2` | Takes effect within a minute - reconnect in your app if it doesn't refresh on its own | کلید فعلی شما به مدت ۲۴ ساعت کار می‌کند، سپس حذف می‌شود |
| `delivery.confirmPoint3` | Using the raw config? Copy the new one after switching | شما باید URL جدید را در هر کلاینت VPN که استفاده می‌کنید، دوباره وارد کنید. |
| `delivery.confirmPointDevices [countPlural=one]` | Your 1 connected device will reconnect to the new servers | شما در حال حاضر یک دستگاه متصل دارید؛ دوباره آن را وارد کنید |
| `delivery.confirmPointDevices [countPlural=other]` | Your {count} connected devices will reconnect to the new servers | شما در حال حاضر {count} دستگاه متصل دارید؛ همه آنها را دوباره وارد کنید |
| `delivery.confirm` | Switch focus | تغییر فوکوس |
| `delivery.working` | Switching… | سوئیچینگ… |
| `delivery.switchSuccessTitle` | Switched to "{label}" | به " {label} " تغییر یافت. |
| `delivery.switchSuccessBodyGrace` | Re-import the new subscription URL on each device. Your old key works for 24 more hours. | آدرس اینترنتی اشتراک جدید را در هر دستگاه دوباره وارد کنید. کلید قدیمی شما 24 ساعت دیگر کار می‌کند. |
| `delivery.switchSuccessBody` | Same subscription URL - your apps will pick up the new servers on their next refresh. | آدرس اینترنتی اشتراک جدید را در هر دستگاه دوباره وارد کنید. |
| `delivery.switchFailedTitle` | Could not switch focus | نتوانستم فوکوس را تغییر دهم |

## `home` — The public landing page: hero, feature sections, impact section, FAQ intros. *(37 missing)*

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `home.trust.nonprofit` | Run by a US 501(c)(3) nonprofit | ⚠️ **MISSING** |
| `home.trust.openSource` | Open source | ⚠️ **MISSING** |
| `home.trust.noLogs` | No traffic logs | ⚠️ **MISSING** |
| `home.network.title` | Network status | ⚠️ **MISSING** |
| `home.network.offline` | offline | ⚠️ **MISSING** |
| `home.network.srOnline` | online | ⚠️ **MISSING** |
| `home.network.srOffline` | offline | ⚠️ **MISSING** |
| `home.network.note` | Checked every 10 minutes | ⚠️ **MISSING** |
| `home.quicknav.label` | Jump to a section | ⚠️ **MISSING** |
| `home.quicknav.privacy` | What we store | ⚠️ **MISSING** |
| `home.quicknav.threat` | Threat model | ⚠️ **MISSING** |
| `home.quicknav.faq` | FAQ | ⚠️ **MISSING** |
| `home.quicknav.impact` | Donation impact | ⚠️ **MISSING** |
| `home.sections.features` | Features | ⚠️ **MISSING** |
| `home.sections.privacy` | Privacy | ⚠️ **MISSING** |
| `home.sections.how` | Getting started | ⚠️ **MISSING** |
| `home.sections.membership` | Membership | ⚠️ **MISSING** |
| `home.sections.impact` | Impact | ⚠️ **MISSING** |
| `home.sections.faq` | FAQ | ⚠️ **MISSING** |
| `home.sections.about` | About | ⚠️ **MISSING** |
| `home.impact.title` | Donations at work | ⚠️ **MISSING** |
| `home.impact.body` | Every donation made through FreeSocks raises the monthly bandwidth of every free account for that month. This is what donors have added so far - you could add to it too. | ⚠️ **MISSING** |
| `home.impact.cta` | Make a donation | ⚠️ **MISSING** |
| `home.impact.chartAria` | Bandwidth added to every free user by donations, month by month | ⚠️ **MISSING** |
| `home.hero.title` | A free VPN for people in censored countries & around the world | ⚠️ **MISSING** |
| `home.hero.subtitle` | FreeSocks is made for people whose internet is censored, and works as a privacy-respecting VPN anywhere else. Signing up takes one quick human check. We never ask for an email or a password. Your subscription URL works in most modern VPN apps, and a membership gets you {limits}. | ⚠️ **MISSING** |
| `home.hero.impactNote` | Donations made through FreeSocks directly power free users: every donation buys real bandwidth for people in censored countries, that same month. | ⚠️ **MISSING** |
| `home.hero.impactLink` | See the impact | ⚠️ **MISSING** |
| `home.cta.getMembership` | Get a membership | عضویت بگیرید |
| `home.freeCard.title` | Free tier | سطح رایگان |
| `home.freeCard.badge` | What you get | آنچه به دست می‌آورید |
| `home.freeCard.urlTitle` | Xray subscription URL | آدرس اشتراک Xray |
| `home.freeCard.urlBody` | Xray-powered VLESS. Paste into any compatible client. | Xray-powered VLESS. Paste into any compatible client. |
| `home.freeCard.membershipLine` | A FreeSocks membership gives you {limits}. | عضویت در FreeSocks به شما {limits} می‌دهد. |
| `home.freeCard.noAuthTitle` | No email or password | بدون ایمیل یا رمز عبور |
| `home.freeCard.noAuthBody` | One human-check. Save your account number to sign in. No email collected. | یک بررسی انسانی. شماره حساب خود را برای ورود ذخیره کنید. هیچ ایمیلی جمع‌آوری نمی‌شود. |
| `home.freeCard.footnote` | Numbers reflect the current free-tier configuration. Solve the check to get yours. | اعداد نشان‌دهنده‌ی پیکربندی فعلیِ ردیف آزاد هستند. برای دریافت چک، آن را حل کنید. |
| `home.freeCard.upsellTitle` | Want unlimited? | نامحدود میخوای؟ |
| `home.freeCard.upsellBody` | Get {limits} - and help keep FreeSocks free for others. | دریافت کنید {limits} - و به رایگان نگه داشتن FreeSocks برای دیگران کمک کنید. |
| `home.freeCard.fromPerMonth` | from {price}/mo | از {price} /mo |
| `home.freeCard.cryptoNote` | Crypto accepted - Bitcoin, Monero, Zcash and more | ⚠️ **MISSING** |
| `home.features.title` | What FreeSocks is | فری‌ساکس چیست؟ |
| `home.features.noAuth.title` | No email or password | بدون ایمیل یا رمز عبور |
| `home.features.noAuth.body` | One human-check and you are in. We mint a 32-digit account number you save to sign back in. No email collected. | با یک بررسی انسانی، حساب شما فعال می‌شود. ما یک شماره حساب ۳۲ رقمی ایجاد می‌کنیم که برای ورود مجدد ذخیره می‌کنید. هیچ ایمیلی جمع‌آوری نمی‌شود. |
| `home.features.mirrors.title` | Mirror URLs | URL های آینه ای |
| `home.features.mirrors.body` | Subscriptions are mirrored across multiple providers so a single block does not cut you off. | اشتراک‌ها در چندین ارائه‌دهنده منعکس می‌شوند، بنابراین یک بلوک واحد شما را از دسترسی محروم نمی‌کند. |
| `home.features.protocols.title` | Standard protocols | پروتکل‌های استاندارد |
| `home.features.protocols.body` | Xray-powered VLESS. Works in most VPN clients. | Xray-powered VLESS. Works in most VPN clients. |
| `home.privacy.title` | What we store | آنچه ما ذخیره می‌کنیم |
| `home.privacy.subtitle` | FreeSocks is built to know as little about you as possible. | FreeSocks طوری ساخته شده که تا حد امکان اطلاعات کمی در مورد شما داشته باشد. |
| `home.privacy.point1` | We store only a hashed version of your account number - never the number itself. | ما فقط یک نسخه هش شده از شماره حساب شما را ذخیره می‌کنیم - هرگز خود شماره را ذخیره نمی‌کنیم. |
| `home.privacy.point2` | No email, phone number, or name. We never ask for them. | نه ایمیلی، نه شماره تلفنی، نه اسمی. ما هرگز از آنها چیزی نمی‌پرسیم. |
| `home.privacy.point3` | No logs of the sites you visit or the traffic you send - and we don't store your IP address, on our servers or the VPN nodes. | هیچ گزارشی از سایت‌هایی که بازدید می‌کنید یا ترافیکی که ارسال می‌کنید، ثبت نمی‌شود. |
| `home.privacy.point4` | We store no payment details - you pay on the provider's own page, and the provider never sees your account or VPN subscription. | ما هیچ جزئیات پرداختی را ذخیره نمی‌کنیم - شما در صفحه خود ارائه‌دهنده پرداخت می‌کنید و ارائه‌دهنده هرگز حساب یا اشتراک پروکسی شما را نمی‌بیند. |
| `home.how.title` | How it works | چگونه کار می‌کند؟ |
| `home.how.cta` | Try it now | همین حالا امتحان کنید |
| `home.how.s1.title` | Create a free account | ایجاد حساب کاربری رایگان |
| `home.how.s1.body` | Solve a quick human-check. You get a 32-digit account number to save: it is how you sign back in. | یک بررسی سریع انسانی را حل کنید. شما یک شماره حساب ۳۲ رقمی برای ذخیره دریافت می‌کنید: این روشی است که شما دوباره وارد سیستم می‌شوید. |
| `home.how.s2.title` | Create your subscription | اشتراک خود را ایجاد کنید |
| `home.how.s2.body` | Once you are signed in, create a subscription URL, with a QR code for handoff to a phone. | پس از ورود به سیستم، یک URL اشتراک به همراه یک کد QR برای انتقال به تلفن ایجاد کنید. |
| `home.how.s3.title` | Paste it into a VPN client | آن را در یک کلاینت VPN قرار دهید |
| `home.how.s3.body` | Add the URL as a subscription in any compatible client. | URL را به عنوان اشتراک در هر کلاینت سازگار اضافه کنید. |
| `home.membership.title` | Membership | عضویت |
| `home.membership.lead` | Free covers the basics. | رایگان اصول اولیه را پوشش می‌دهد. |
| `home.membership.descriptionFallback` | A FreeSocks membership lifts every limit. | عضویت در FreeSocks هر محدودیتی را از بین می‌برد. |
| `home.membership.payNote` | Pay privately with Bitcoin, Monero, or Zcash - or use a card or PayPal. | با ارز دیجیتال (بیت‌کوین، مونرو و موارد دیگر)، کارت یا پی‌پال پرداخت کنید. |
| `home.about.title` | About FreeSocks | ⚠️ **MISSING** |
| `home.about.bodyPrefix` | FreeSocks is operated by | FreeSocks توسط ... اداره می‌شود. |
| `home.about.bodySuffix` | , a US 501(c)(3) nonprofit. | ⚠️ **MISSING** |
| `home.about.body2` | Most VPNs assume you can pay for a subscription and safely hand over an email address. In much of the world neither is true, so FreeSocks asks for neither. Anyone can get a working key in about a minute and keep it for as long as they use it. | ⚠️ **MISSING** |
| `home.about.siteLink` | unredacted.org | unredacted.org |
| `home.about.openSource` | The code that runs this service is published for anyone to inspect, audit, or run themselves. | ⚠️ **MISSING** |
| `home.about.viewSourceCta` | View the source | ⚠️ **MISSING** |
| `home.about.fact2Title` | Open source | ⚠️ **MISSING** |
| `home.about.fact3Title` | Donation funded | ⚠️ **MISSING** |
| `home.about.fact3Body` | Free accounts are paid for by donations and memberships. There are no ads and nothing is sold. | ⚠️ **MISSING** |
| `home.limits.unlimitedBoth` | unlimited bandwidth and devices | پهنای باند و دستگاه‌های نامحدود |
| `home.limits.unlimitedBandwidth` | unlimited bandwidth | پهنای باند نامحدود |
| `home.limits.unlimitedDevices` | unlimited devices | دستگاه‌های نامحدود |
| `home.limits.bandwidthAndDevices` | {bandwidth} and {devices} | {bandwidth} و {devices} |
| `home.limits.upToDevices [countPlural=one]` | up to 1 device | تا ۱ دستگاه |
| `home.limits.upToDevices [countPlural=other]` | up to {count} devices | تا {count} دستگاه |

## `e2ee` — The HPKE/E2EE "encrypted to this server" badge + verification panel.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `e2ee.badgeActiveTitle` | Encrypted to this server with HPKE. Click to verify. | با HPKE در این سرور رمزگذاری شده است. برای تأیید کلیک کنید. |
| `e2ee.badgeWarnTitle` | Couldn't verify the encryption key. Click to verify out-of-band before entering your account number. | کلید رمزگذاری تأیید نشد. قبل از وارد کردن شماره حساب خود، برای تأیید خارج از باند، کلیک کنید. |
| `e2ee.badgeActiveTitleAdmin` | Sensitive member and admin actions are HPKE-encrypted on this deployment. Click for details. | اقدامات حساس اعضا و مدیران در این پیاده‌سازی با HPKE رمزگذاری شده‌اند. برای جزئیات بیشتر کلیک کنید. |
| `e2ee.badgeWarnTitleAdmin` | Couldn't verify this deployment's encryption key. Click for details and out-of-band verification. | کلید رمزگذاری این استقرار تأیید نشد. برای جزئیات و تأیید خارج از باند کلیک کنید. |
| `e2ee.badgeOff` | TLS | TLS |
| `e2ee.badgeOffTitle` | Standard TLS only. Extra HPKE body encryption isn't enabled on this deployment. | فقط TLS استاندارد. رمزگذاری بدنه اضافی HPKE در این پیاده‌سازی فعال نیست. |
| `e2ee.bannerWarn` | Couldn't verify the encryption key | کلید رمزگذاری قابل تأیید نیست |
| `e2ee.bannerWarnDetail` | Don't enter your account number yet - verify this connection out-of-band first. | هنوز شماره حساب خود را وارد نکنید - ابتدا این اتصال را خارج از باند تأیید کنید. |
| `e2ee.verify` | Verify | تأیید |
| `e2ee.verifyTitle` | Verify this connection | این ارتباط را تأیید کنید |
| `e2ee.verifyIntro` | FreeSocks seals your account number and VPN key to this server with HPKE, so a compromised CDN can't read them. These fingerprints identify the keys your browser is using - compare them against the values published out-of-band to be sure they haven't been swapped. | FreeSocks شماره حساب و کلید پروکسی شما را با HPKE به این سرور متصل می‌کند، بنابراین یک CDN آسیب‌پذیر نمی‌تواند آنها را بخواند. این اثر انگشت‌ها کلیدهایی را که مرورگر شما استفاده می‌کند شناسایی می‌کنند - آنها را با مقادیر منتشر شده خارج از باند مقایسه کنید تا مطمئن شوید که آنها جابجا نشده‌اند. |
| `e2ee.protectHeading` | What this protects | این از چه چیزی محافظت می‌کند؟ |
| `e2ee.protectScope` | Your account number and key are encrypted to this server with HPKE, so the network and any CDN in front of it can't read them. | شماره حساب و کلید شما با HPKE برای این سرور رمزگذاری شده‌اند، بنابراین شبکه و هر CDN مقابل آن نمی‌تواند آنها را بخواند. |
| `e2ee.protectServerReads` | FreeSocks itself can read them to set up your account, so this protects you from the network in between, not from the server. | خود FreeSocks می‌تواند آنها را بخواند تا حساب شما را تنظیم کند، بنابراین این شما را از شبکه بین آنها محافظت می‌کند، نه از سرور. |
| `e2ee.protectTunnel` | It's separate from your VPN connection, which is encrypted on its own. | این جدا از اتصال VPN شماست که به خودی خود رمزگذاری شده است. |
| `e2ee.protectAdmin` | On the admin dashboard, sensitive actions - creating API tokens, invites, and membership codes, and uploading backend, billing, or storage credentials - are HPKE-encrypted to this server too. Routine reads and settings use TLS, your passkey, and proof-of-possession. | در داشبورد مدیریت، اقدامات حساس - ایجاد توکن‌های API، دعوت‌نامه‌ها و کدهای عضویت، و آپلود اعتبارنامه‌های backend، صورتحساب یا ذخیره‌سازی - نیز توسط HPKE در این سرور رمزگذاری می‌شوند. خواندن‌ها و تنظیمات معمول از TLS، کلید عبور شما و اثبات مالکیت استفاده می‌کنند. |
| `e2ee.fingerprintsHeading` | Key fingerprints | اثر انگشت کلید |
| `e2ee.fpHpke` | Server key (HPKE / X-Wing) | کلید سرور (HPKE / X-Wing) |
| `e2ee.fpKid` | Key id | شناسه کلید |
| `e2ee.fpManifest` | Manifest key (Ed25519) | کلید مانیفست (Ed25519) |
| `e2ee.fpManifestPq` | Manifest key (ML-DSA-65, post-quantum) | کلید مانیفست (ML-DSA-65، پسا کوانتومی) |
| `e2ee.fpSuite` | Cipher suite | مجموعه رمز |
| `e2ee.copy` | Copy | کپی |
| `e2ee.copied` | Copied | کپی شده |
| `e2ee.attestationHeading` | Live server attestation | تأیید سرور زنده |
| `e2ee.attestationOk` | Verified - the server is attesting a valid key signed by the manifest key your app trusts. | تأیید شده - سرور در حال تأیید یک کلید معتبر است که توسط کلید مانیفست مورد اعتماد برنامه شما امضا شده است. |
| `e2ee.attestationEpoch` | Current key {kid}, expires {expiry}. | کلید فعلی {kid} , منقضی می‌شود {expiry} . |
| `e2ee.attestationFail` | Could not verify the server's current key - a network problem, or a CDN tampering with the key endpoint. Verify out-of-band before continuing. | کلید فعلی سرور تأیید نشد - مشکل شبکه یا دستکاری CDN در نقطه پایانی کلید. قبل از ادامه، خارج از باند تأیید کنید. |
| `e2ee.attestationUnreachable` | The live key check is temporarily unavailable. Your connection still uses the verified key built into the app. | بررسی کلید زنده موقتاً در دسترس نیست. اتصال شما هنوز از کلید تأیید شده‌ی داخلی برنامه استفاده می‌کند. |
| `e2ee.attestationUnconfigured` | Live key checking isn't set up on this build. | بررسی کلید زنده در این نسخه راه‌اندازی نشده است. |
| `e2ee.compareHeading` | How to verify | نحوه تأیید |
| `e2ee.compareBody` | Compare the fingerprints above against the values published through a channel this server doesn't control. They must match. | اثر انگشت‌های بالا را با مقادیر منتشر شده از طریق کانالی که این سرور کنترل نمی‌کند مقایسه کنید. آنها باید مطابقت داشته باشند. |
| `e2ee.channelRelease` | Signed release notes | یادداشت‌های انتشار امضا شده |
| `e2ee.channelSource` | Source code (rebuild to compare) | کد منبع (برای مقایسه بازسازی کنید) |
| `e2ee.channelOnion` | Tor mirror | آینه تور |
| `e2ee.dnsHeading` | Verify via DNS | از طریق DNS تأیید کنید |
| `e2ee.dnsBody` | Look the pin up yourself in a terminal, through your own DNS resolver - a path that doesn't run through this site or its CDN. The answer should contain the same fingerprints shown above. (If it returns nothing, the operator may not have published the record yet; use the signed release instead.) | خودتان در ترمینال، از طریق DNS resolver خودتان - مسیری که از این سایت یا CDN آن عبور نمی‌کند - پین را جستجو کنید. پاسخ باید حاوی همان اثر انگشت‌های نشان داده شده در بالا باشد. (اگر چیزی برنگرداند، ممکن است اپراتور هنوز رکورد را منتشر نکرده باشد؛ به جای آن از نسخه امضا شده استفاده کنید.) |
| `e2ee.dnsCommand` | Run this in a terminal | این را در ترمینال اجرا کنید |
| `e2ee.dnsExpected` | It should return | باید برگردد. |
| `e2ee.dnsCaveat` | Independent only if your DNS isn't run by the same company as the CDN; a DNSSEC-validating resolver is best. For full assurance, confirm the same values in the signed release too. | فقط در صورتی مستقل عمل کنید که DNS شما توسط همان شرکت CDN اداره نشود؛ یک تحلیلگر اعتبارسنجی DNSSEC بهترین گزینه است. برای اطمینان کامل، مقادیر مشابه را در نسخه امضا شده نیز تأیید کنید. |
| `e2ee.verifierExtension` | A verifier browser extension that re-checks this build on every visit is planned, but not available yet. | یک افزونه مرورگر تأییدکننده که این نسخه را در هر بازدید دوباره بررسی کند، برنامه‌ریزی شده است، اما هنوز در دسترس نیست. |
| `e2ee.verifierExtensionInstall` | Install the verifier extension - it re-checks this build against the published one on every visit (the strongest protection against a tampered page). | افزونه‌ی تأییدکننده را نصب کنید - این افزونه در هر بازدید، این نسخه را با نسخه منتشر شده مقایسه می‌کند (قوی‌ترین محافظت در برابر صفحه‌ی دستکاری‌شده). |
| `e2ee.caveat` | This in-page check is a convenience. A tampered page could lie about its own status, so the real proof comes from comparing these values somewhere outside this server, such as the DNS lookup above or a published release. | این بررسی درون صفحه‌ای یک مزیت است. یک صفحه دستکاری‌شده می‌تواند در مورد وضعیت خود دروغ بگوید، بنابراین اثبات واقعی از مقایسه این مقادیر در جایی خارج از این سرور، مانند جستجوی DNS در بالا یا یک نسخه منتشر شده، حاصل می‌شود. |
| `e2ee.close` | Close | بستن |

## `deviceRevoke` — The disconnect-a-device confirmation dialog.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `deviceRevoke.title` | Revoke this device? | این دستگاه را باطل کنیم؟ |
| `deviceRevoke.body` | The device ending …{suffix} will be disconnected and its slot freed. It can reconnect later by re-importing your subscription URL. | دستگاهی که به ... {suffix} ختم می‌شود، قطع شده و اسلات آن آزاد می‌شود. می‌تواند بعداً با وارد کردن مجدد URL اشتراک شما دوباره متصل شود. |
| `deviceRevoke.confirm` | Revoke device | لغو دستگاه |
| `deviceRevoke.working` | Revoking… | لغو… |
