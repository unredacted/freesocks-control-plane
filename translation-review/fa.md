# FreeSocks translation review — Persian (فارسی)

Generated from `messages/en.json` (source of truth) vs `messages/fa.json`.
**0 of 768 strings are missing** (the app currently shows English for
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


## `faq` — The landing-page FAQ (questions + answers).

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `faq.title` | Frequently asked questions | سوالات متداول |
| `faq.subtitle` | Answers to common questions. | به سوالات اولیه پاسخ داده شد. هنوز گیر کرده‌اید؟ با شناسه پشتیبانی خود تماس بگیرید. |
| `faq.tabGeneral` | General | عمومی |
| `faq.tabThreat` | What we protect you from | از چه چیزی از شما محافظت می‌کنیم |
| `faq.contactPrefix` | For anything else, email | برای هر مورد دیگر، ایمیل بزنید به |
| `faq.contactSuffix` | and include your Support ID. | و شناسهٔ پشتیبانی خود را ذکر کنید. |
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
| `faq.q10.question` | Do you own your servers, or rent them? | سرورهایتان متعلق به خودتان است یا اجاره‌ای هستند؟ |
| `faq.q10.answer` | We own our hardware and run it ourselves. Plenty of VPN companies rent theirs from datacenters or cloud hosts, which puts the machine your traffic passes through in someone else's hands - they can be pressured to hand it over, or just quietly copy what is on it. That is a line we are not willing to cross, so we buy and run our own equipment instead. It costs more and we grow slower because of it, but it is the only way the privacy promises on this page actually mean anything. | ما سخت‌افزار خودمان را داریم و خودمان آن را اداره می‌کنیم. بسیاری از شرکت‌های VPN سرورهایشان را از دیتاسنترها یا میزبان‌های ابری اجاره می‌کنند، و این یعنی ماشینی که ترافیک شما از آن عبور می‌کند در دست دیگری است - می‌توان به آن‌ها فشار آورد تا آن را تحویل دهند، یا بی‌سروصدا آنچه روی آن است را کپی کنند. این خطی است که ما حاضر نیستیم از آن عبور کنیم، به همین دلیل تجهیزات خودمان را می‌خریم و خودمان اداره می‌کنیم. این کار هزینهٔ بیشتری دارد و به خاطرش کندتر رشد می‌کنیم، اما تنها راهی است که وعده‌های حریم خصوصی این صفحه واقعاً معنا پیدا کنند. |

## `threat` — Miscellaneous strings.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `threat.subtitle` | An honest look at what this service can and cannot do. Security tools that overpromise get people hurt, so here is exactly where the lines are. | نگاهی صادقانه به آنچه این سرویس می‌تواند و نمی‌تواند انجام دهد. ابزارهای امنیتی که بیش از حد وعده می‌دهند به مردم آسیب می‌زنند، پس اینجا دقیقاً می‌گوییم مرزها کجاست. |
| `threat.q1.question` | What does FreeSocks protect me from? | فری‌ساکس از من در برابر چه چیزی محافظت می‌کند؟ |
| `threat.q1.answer` | FreeSocks tunnels your traffic through an encrypted VPN connection, so your ISP, mobile carrier, school, or workplace network cannot see which sites you visit or block them. It is built for getting past censorship and for keeping the network you are on from watching what you do. | فری‌ساکس ترافیک شما را از طریق یک اتصال رمزگذاری‌شدهٔ VPN تونل می‌کند، پس ارائه‌دهندهٔ اینترنت، اپراتور موبایل، مدرسه یا شبکهٔ محل کار شما نمی‌تواند ببیند به چه سایت‌هایی سر می‌زنید یا آن‌ها را مسدود کند. این سرویس برای عبور از سانسور ساخته شده و برای اینکه شبکه‌ای که به آن وصل هستید نتواند کارتان را زیر نظر بگیرد. |
| `threat.q2.question` | What does FreeSocks NOT protect me from? | فری‌ساکس از من در برابر چه چیزهایی محافظت نمی‌کند؟ |
| `threat.q2.answer` | It does not make you anonymous to sites you sign in to: if you log in to an account, that site knows who you are. It cannot protect a device that is already compromised (spyware, a managed work profile, someone with physical access). And a powerful adversary that can watch traffic at many points on the internet may still correlate patterns. If your safety depends on strong anonymity, use Tor and follow specialist guidance for your situation. | اگر وارد یک حساب کاربری شوید، شما را ناشناس نگه نمی‌دارد: وقتی در یک سایت وارد حسابتان می‌شوید، آن سایت می‌داند شما کی هستید. همچنین نمی‌تواند از دستگاهی که از قبل آلوده شده محافظت کند (جاسوس‌افزار، پروفایل مدیریت‌شدهٔ کاری، یا کسی که دسترسی فیزیکی دارد). و یک دشمن قدرتمند که بتواند ترافیک را در نقاط زیادی از اینترنت زیر نظر بگیرد، شاید هنوز بتواند الگوها را به هم پیوند بزند. اگر امنیت شما به ناشناسی قوی بستگی دارد، از تور استفاده کنید و راهنمایی‌های تخصصی مخصوص وضعیت خود را دنبال کنید. |
| `threat.q3.question` | Can FreeSocks see my traffic? | آیا فری‌ساکس می‌تواند ترافیک من را ببیند؟ |
| `threat.q3.answer` | Your traffic exits through our servers, so treat us like any exit: sites you use over HTTPS (almost all of the modern web) stay encrypted end to end and we cannot read their contents. We configure our servers to keep no connection logs, no visited-site logs, and no source IPs, and the control plane never stores your IP address at all. | ترافیک شما از سرورهای ما خارج می‌شود، پس ما را مثل هر نقطهٔ خروجی دیگری در نظر بگیرید: سایت‌هایی که با HTTPS استفاده می‌کنید (تقریباً همهٔ وب امروزی) از ابتدا تا انتها رمزگذاری می‌مانند و ما نمی‌توانیم محتوایشان را بخوانیم. ما سرورهایمان را طوری پیکربندی می‌کنیم که هیچ گزارش اتصال، هیچ گزارش سایت‌های بازدیدشده و هیچ IP مبدأیی نگه ندارند، و بخش مدیریت سرویس اصلاً آدرس IP شما را ذخیره نمی‌کند. |
| `threat.q4.question` | What happens if a FreeSocks server is seized or compromised? | اگر یک سرور فری‌ساکس توقیف یا به خطر بیفتد چه اتفاقی می‌افتد؟ |
| `threat.q4.answer` | There is nothing identifying on it. Servers hold no names, emails, IPs, or traffic history, because we never collect those in the first place. Access keys can be revoked and reissued quickly, and we can rotate infrastructure without losing accounts. | هیچ چیز شناسایی‌کننده‌ای روی آن نیست. سرورها نه نام، نه ایمیل، نه IP و نه تاریخچهٔ ترافیکی نگه می‌دارند، چون ما از همان اول این‌ها را جمع نمی‌کنیم. کلیدهای دسترسی را می‌توان سریع باطل و دوباره صادر کرد، و می‌توانیم زیرساخت را بدون از دست دادن حساب‌ها جابه‌جا کنیم. |
| `threat.q5.question` | Can my government or ISP tell that I am using FreeSocks? | آیا دولت یا ارائه‌دهندهٔ اینترنت من می‌تواند بفهمد از فری‌ساکس استفاده می‌کنم؟ |
| `threat.q5.answer` | Sometimes censors can detect that circumvention traffic is in use even when they cannot read it. Our transports are designed to look like ordinary encrypted web traffic, and Internet Freedom Mode routes through infrastructure that is expensive to block. Still, whether use is detectable, and what the consequences are, varies by country. Weigh your local risk. | گاهی سانسورکنندگان می‌توانند تشخیص دهند که ترافیک عبور از سانسور در جریان است، حتی وقتی نمی‌توانند آن را بخوانند. روش‌های انتقال ما طوری طراحی شده‌اند که شبیه ترافیک عادی رمزگذاری‌شدهٔ وب به نظر برسند، و حالت آزادی اینترنت از زیرساختی عبور می‌کند که مسدود کردنش گران است. با این حال، اینکه استفاده قابل تشخیص باشد یا نه، و عواقبش چیست، از کشوری به کشور دیگر فرق می‌کند. خطر محلی خود را بسنجید. |
| `threat.q6.question` | Why should I believe any of this? | چرا باید به این حرف‌ها باور کنم؟ |
| `threat.q6.answer` | The control plane is open source, so anyone can read exactly what it stores and check that there is no place a name, email, or IP address could even go. Claims that depend on server configuration (like disabled logging) are documented and enforced by the same code. You still have to trust the operator for the parts you cannot see, as with every VPN; our approach is to minimize what there is to trust. | کد مدیریت سرویس متن‌باز است، پس هر کسی می‌تواند دقیقاً ببیند چه چیزی ذخیره می‌شود و بررسی کند که اصلاً جایی برای نام، ایمیل یا آدرس IP وجود ندارد. ادعاهایی که به پیکربندی سرور بستگی دارند (مثل غیرفعال بودن ثبت گزارش) مستند هستند و توسط همان کد اعمال می‌شوند. برای بخش‌هایی که نمی‌توانید ببینید، باز هم باید به اپراتور اعتماد کنید، مثل هر VPN دیگری؛ رویکرد ما این است که آنچه باید به آن اعتماد کنید را به حداقل برسانیم. |
| `threat.q7.question` | Do payments link my identity to my browsing? | آیا پرداخت‌ها هویت من را به گشت‌وگذارم پیوند می‌زنند؟ |
| `threat.q7.answer` | Membership is optional, and payment is handled by outside processors: we never store the payer's name, email, or address, and an order is tied to your account only through an opaque reference. Cryptocurrency options (including Monero) exist for people who do not want a card trail at all. | عضویت اختیاری است و پرداخت توسط پردازشگرهای بیرونی انجام می‌شود: ما هرگز نام، ایمیل یا آدرس پرداخت‌کننده را ذخیره نمی‌کنیم، و یک سفارش فقط از طریق یک مرجع مات به حساب شما گره می‌خورد. گزینه‌های رمزارزی (از جمله مونرو) برای کسانی هست که اصلاً نمی‌خواهند ردی از کارت باقی بماند. |

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

## `nav` — The site header: navigation buttons, menu, language/theme controls.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `nav.getAccount` | Get a free account | دریافت حساب رایگان |
| `nav.signIn` | Sign in | ورود |
| `nav.account` | My account | حساب من |
| `nav.menu` | Menu | منو |
| `nav.theme` | Theme | پوسته |
| `nav.home` | FreeSocks home | خانهٔ فری‌ساکس |

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

## `reveal` — The save-your-account-number modal (the 32-digit sign-in number is shown ONCE; users must download it and paste it back to verify). The single most safety-critical copy in the product.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `reveal.title` | Save your account number now | شمارهٔ حساب خود را همین حالا ذخیره کنید |
| `reveal.subtitle` | This 32-digit number is the ONLY way to sign in again. There is no email or password to recover it. If you lose it, your account is gone for good. | این شمارهٔ ۳۲ رقمی تنها راه ورود دوباره است. هیچ ایمیل یا رمز عبوری برای بازیابی آن وجود ندارد. اگر آن را گم کنید، حسابتان برای همیشه از دست می‌رود. |
| `reveal.cannotRecover` | We cannot recover it for you - not even support can. | ما نمی‌توانیم آن را برایتان بازیابی کنیم - حتی پشتیبانی هم نمی‌تواند. |
| `reveal.saveHint` | Save it in a password manager, or write it down somewhere safe and private. | آن را در یک مدیر رمز عبور ذخیره کنید یا در جایی امن و خصوصی یادداشت کنید. |
| `reveal.downloadRequired` | Download your account number to continue. Keep the file somewhere safe. | برای ادامه، شمارهٔ حساب خود را دانلود کنید. فایل را در جایی امن نگه دارید. |
| `reveal.continue` | Continue | ادامه |
| `reveal.verifyTitle` | Confirm you saved it | تأیید کنید که آن را ذخیره کرده‌اید |
| `reveal.verifySubtitle` | Your account number is now hidden. Enter or paste it from the copy you just saved to confirm you can sign in later. | شمارهٔ حساب شما اکنون پنهان است. آن را از رونوشتی که همین حالا ذخیره کرده‌اید وارد یا جای‌گذاری کنید تا مطمئن شویم بعداً می‌توانید وارد شوید. |
| `reveal.verifyPlaceholder` | Paste your 32-digit account number | شمارهٔ حساب ۳۲ رقمی خود را جای‌گذاری کنید |
| `reveal.verifyMismatch` | That doesn't match your account number. Check the copy you saved, or go back to see it again. | این با شمارهٔ حساب شما مطابقت ندارد. رونوشتی که ذخیره کرده‌اید را بررسی کنید، یا برگردید تا دوباره ببینید. |
| `reveal.back` | Back | بازگشت |
| `reveal.done` | I've saved it | ذخیره کردم |
| `reveal.savedConfirmed` | Account number saved and verified | شمارهٔ حساب ذخیره و تأیید شد |
| `reveal.downloadFilename` | freesocks-account-number.txt | شماره حساب freesocks.txt |
| `reveal.leaveWarning` | Your account number is still on screen. If you leave now without saving it, you will not be able to sign in again. | شمارهٔ حساب شما هنوز روی صفحه است. اگر اکنون بدون ذخیره‌کردن خارج شوید، دیگر نمی‌توانید وارد شوید. |

## `support` — The support-ID line (a non-secret handle for contacting support).

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `support.label` | Support ID | شناسهٔ پشتیبانی |
| `support.hint` | Share this if you contact us. It is NOT your sign-in number and grants no access. | اگر با ما تماس گرفتید این را به اشتراک بگذارید. این شمارهٔ ورود شما نیست و دسترسی‌ای نمی‌دهد. |
| `support.copyAria` | Copy your support ID | کپی شناسهٔ پشتیبانی |
| `support.emailUs` | Email us: | به ما ایمیل بزنید: |
| `support.getAccountLine` | Questions or problems? Email us at | سؤال یا مشکلی دارید؟ به ما ایمیل بزنید: |

## `login` — The sign-in page (account number + optional passkey).

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
| `login.or` | or | یا |

## `passkey` — Optional passkey (Face ID / fingerprint) sign-in management.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `passkey.title` | Passkeys | کلیدهای عبور |
| `passkey.desc` | Sign in with Face ID, Touch ID, a security key, or your password manager - no account number to type. | با Face ID، Touch ID، یک کلید امنیتی یا مدیر رمز عبورتان وارد شوید - بدون نیاز به تایپ شمارهٔ حساب. |
| `passkey.warning` | Heads-up: a passkey saved on your phone or in your browser may sync to your Apple or Google account, which can link this anonymous account to that identity. Use a hardware security key, or skip passkeys, if that matters to you. | توجه: کلید عبوری که روی گوشی یا در مرورگرتان ذخیره شود ممکن است با حساب Apple یا Google شما همگام شود، و این می‌تواند این حساب ناشناس را به آن هویت پیوند بزند. اگر این برایتان مهم است، از یک کلید امنیتی سخت‌افزاری استفاده کنید یا از کلید عبور صرف‌نظر کنید. |
| `passkey.unsupported` | This device or browser doesn't support passkeys. | این دستگاه یا مرورگر از کلید عبور پشتیبانی نمی‌کند. |
| `passkey.none` | No passkeys yet. Your account number still signs you in. | هنوز کلید عبوری ندارید. شمارهٔ حساب شما همچنان شما را وارد می‌کند. |
| `passkey.add` | Add a passkey | افزودن کلید عبور |
| `passkey.adding` | Adding… | در حال افزودن… |
| `passkey.added` | Passkey added | کلید عبور اضافه شد |
| `passkey.addFailed` | Couldn't add the passkey | کلید عبور اضافه نشد |
| `passkey.remove` | Remove | حذف |
| `passkey.removed` | Passkey removed | کلید عبور حذف شد |
| `passkey.removeFailed` | Couldn't remove the passkey | کلید عبور حذف نشد |
| `passkey.deviceLabelLabel` | Device name (optional) | نام دستگاه (اختیاری) |
| `passkey.deviceLabelPlaceholder` | e.g. My phone | مثلاً گوشی من |
| `passkey.addedOn` | Added {date} | اضافه شده در {date} |
| `passkey.lastUsed` | last used {date} | آخرین استفاده {date} |
| `passkey.signIn` | Sign in with a passkey | ورود با کلید عبور |
| `passkey.signingIn` | Authenticating… | در حال احراز هویت… |
| `passkey.signInFailed` | Passkey sign-in failed | ورود با کلید عبور ناموفق بود |
| `passkey.notNow` | Not now | فعلاً نه |

## `account` — The signed-in /account dashboard: connection, membership, codes, security tabs.

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
| `account.noSubTitle` | No key yet | هنوز اشتراکی ندارید |
| `account.noSubBody` | Create your key to get a link you can use in any compatible VPN app. | اولین اشتراک خود را بسازید تا لینکی دریافت کنید که در هر برنامهٔ VPN سازگار قابل استفاده است. |
| `account.createSub` | Get my key | ساخت اشتراک |
| `account.creating` | Creating your key… | در حال ساخت… |
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
| `account.membershipNudge.bodyNoDevices` | Unlimited bandwidth. | پهنای باند نامحدود. |
| `account.membershipNudge.cta` | View membership | مشاهده عضویت |
| `account.tab.connection` | Connection | اتصال |
| `account.tab.membership` | Membership | عضویت |
| `account.tab.gifts` | Gifts & referrals | هدیه و معرفی |
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
| `account.section.gifts.title` | Gifts & referrals | هدیه و معرفی |
| `account.section.gifts.desc` | Redeem a code, buy codes to share, and invite people you trust. | کد را بازخرید کنید، کد بخرید تا با دیگران بدهید، و آشنایان خود را دعوت کنید. |
| `account.section.codes.title` | Codes & gifts | کدها و هدایا |
| `account.section.codes.desc` | Redeem a membership code, or buy codes to share with others. | یک کد عضویت را بازخرید کنید، یا کدهایی را برای اشتراک‌گذاری با دیگران خریداری کنید. |
| `account.section.security.title` | Account & security | حساب کاربری و امنیت |
| `account.section.security.desc` | Your support ID and account-number controls. | کنترل‌های شناسه پشتیبانی و شماره حساب شما. |
| `account.deviceRevoke` | Revoke | لغو |
| `account.deviceRevokedTitle` | Device revoked | دستگاه باطل شد |
| `account.deviceRevokedBody` | The slot is free. That device loses access until it re-imports your subscription. | اسلات خالی است. آن دستگاه تا زمانی که اشتراک شما را دوباره وارد نکند، دسترسی خود را از دست می‌دهد. |
| `account.deviceRevokeFailedTitle` | Couldn't revoke the device | نتوانستم دستگاه را باطل کنم |

## `hero` — The subscription panel: the key/URL block, traffic + expiry stats, QR, status callouts.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `hero.titleDefault` | Your key | اشتراک شما |
| `hero.eyebrowAccessKey` | FreeSocks Access Pass | کلید دسترسی شما |
| `hero.urlLabelSubscription` | Your link | لینک اشتراک |
| `hero.urlLabelAccessKey` | Access key | کلید دسترسی |
| `hero.tierLine` | Plan {tier} | سطح {tier} |
| `hero.viaLine` | via {backend} | از طریق {backend} |
| `hero.copyUrl` | Copy link | کپی لینک |
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
| `hero.fallbackLabel` | Fallback link | لینک جایگزین |
| `hero.fallbackHint` | Use this if the main link gets blocked | اگر لینک اصلی مسدود شد از این استفاده کنید |
| `hero.fallbackQrAria` | Show fallback link QR code | نمایش کد QR لینک جایگزین |
| `hero.downloaded` | Downloaded {filename} | {filename} دانلود شد |
| `hero.traffic` | Traffic | ترافیک |
| `hero.unlimited` | Unlimited | نامحدود |
| `hero.configBelowNote` | Your full configuration is below - add the servers by hand. For privacy, the auto-updating subscription link isn't shown by default (your app would fetch it through a CDN). | پیکربندی کامل شما در پایین است - سرورها را دستی اضافه کنید. برای حفظ حریم خصوصی، لینک اشتراک خودبه‌روزشونده به‌طور پیش‌فرض نشان داده نمی‌شود (برنامهٔ شما آن را از طریق یک CDN دریافت می‌کرد). |
| `hero.showUrlAnyway` | Show the subscription link anyway | با این حال لینک اشتراک را نشان بده |
| `hero.urlDangerBody` | This link works in any app, but the app then downloads your configuration through a third-party CDN in plain text - the CDN operator can see your server details and that you use FreeSocks. That is exactly what this focus avoids. Use it only if your app cannot import the configuration below. | این لینک در هر برنامه‌ای کار می‌کند، اما برنامه بعداً پیکربندی شما را به‌صورت متن ساده از طریق یک CDN شخص ثالث دانلود می‌کند - اپراتور CDN می‌تواند جزئیات سرور شما و اینکه از فری‌ساکس استفاده می‌کنید را ببیند. این دقیقاً همان چیزی است که این حالت از آن دوری می‌کند. فقط اگر برنامهٔ شما نمی‌تواند پیکربندی پایین را وارد کند از آن استفاده کنید. |
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
| `hero.nodeOnline` | Node online | گره آنلاین است |
| `hero.nodeOffline` | Node offline | گره آفلاین است |
| `hero.nodeUnknown` | Node status unknown | وضعیت گره نامشخص است |
| `hero.nodeStatusLink` | Network status | وضعیت شبکه |
| `hero.nodeOnlineHint` | The server behind your config is up and responding. If you still can't connect, your network or ISP is likely filtering it - try another connection mode or location. | سرور پشت پیکربندی شما روشن است و پاسخ می‌دهد. اگر هنوز وصل نمی‌شوید، احتمالاً شبکه یا ارائه‌دهندهٔ اینترنت شما آن را فیلتر می‌کند - حالت اتصال یا مکان دیگری را امتحان کنید. |
| `hero.nodeOfflineBody` | The server behind your config is currently offline. This is on our side, not your network. Try again in a few minutes, or create a new config (optionally in a different location). | سرور پشت پیکربندی شما فعلاً آفلاین است. این مشکل از سمت ماست، نه شبکهٔ شما. چند دقیقهٔ دیگر دوباره امتحان کنید، یا یک پیکربندی جدید بسازید (در صورت تمایل در مکانی دیگر). |
| `hero.keyLimited` | You've used all your data for this period. It resets automatically, or you can upgrade for more. | شما تمام داده‌های خود را برای این مدت استفاده کرده‌اید. به‌طور خودکار بازنشانی می‌شود، یا می‌توانید برای اطلاعات بیشتر ارتقا دهید. |
| `hero.keyExpired` | This key has expired. Renew your membership or create a new key to reconnect. | این کلید منقضی شده است. عضویت خود را تمدید کنید یا برای اتصال مجدد، کلید جدیدی ایجاد کنید. |
| `hero.keyDisabled` | This key is currently disabled. If your membership lapsed, renew it; otherwise contact support with your support ID. | این کلید در حال حاضر غیرفعال است. اگر عضویت شما منقضی شده است، آن را تمدید کنید؛ در غیر این صورت با شناسه پشتیبانی خود با پشتیبانی تماس بگیرید. |
| `hero.resetsInDays [countPlural=one]` | Resets in 1 day | ۱ روز دیگه ریست میشه |
| `hero.resetsInDays [countPlural=other]` | Resets in {count} days | مقدار را در {count} روز تنظیم مجدد می‌کند |

## `location` — Miscellaneous strings.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `location.pickerLabel` | Server location | مکان سرور |
| `location.auto` | Automatic (least busy) | خودکار (خلوت‌ترین) |
| `location.offline` | offline | آفلاین |
| `location.pickerHint` | Where your config's server is. Automatic picks the least busy location; pick one yourself if it works better on your network. | محل سرور پیکربندی شما. حالت خودکار خلوت‌ترین مکان را انتخاب می‌کند؛ اگر مکان دیگری روی شبکهٔ شما بهتر کار می‌کند، خودتان انتخابش کنید. |

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

## `get` — The /get-account sign-up flow: create account (step 1) and create subscription (step 2).

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `get.badge` | Free account | حساب رایگان |
| `get.title` | Get a FreeSocks account | دریافت حساب فری‌ساکس |
| `get.progressAria` | Sign-up progress | پیشرفت ثبت‌نام |
| `get.progress.step1` | Create account | ساخت حساب |
| `get.progress.step2` | Save your number | ذخیرهٔ شماره |
| `get.progress.step3` | Get connected | اتصال |
| `get.step1Title` | Create your account | حساب خود را بسازید |
| `get.chooseBackend` | Choose a connection type | نوع اتصال را انتخاب کنید |
| `get.backendAria` | Connection type | نوع اتصال |
| `get.backendMultiProtocol` | VLESS (Xray) | VLESS (Xray) |
| `get.backendShadowsocks` | Shadowsocks via Outline | Shadowsocks از طریق Outline |
| `get.createAccount` | Create my account | ساخت حساب من |
| `get.freeAccountNote` | Free accounts are valid for {days} days and limited to {devices}. No email or password. | حساب‌های رایگان {days} روز اعتبار دارند و به {devices} محدودند. بدون ایمیل یا رمز عبور. |
| `get.freeAccountNoteNoDevices` | Free accounts are valid for {days} days. No email or password. | حساب‌های رایگان {days} روز اعتبار دارند. بدون ایمیل یا رمز عبور. |
| `get.step3Title` | Get your key | کلید خود را دریافت کنید |
| `get.step3Intro` | Your key is what connects your app to the VPN. Create it, then add it to your app. | کلید شما چیزی است که برنامه‌تان را به VPN وصل می‌کند. آن را بسازید، سپس به برنامه‌تان اضافه‌اش کنید. |
| `get.manageHintPrefix` | Manage your key anytime from | این اشتراک را هر زمان مدیریت کنید از |
| `get.manageLinkLabel` | your account | حساب شما |
| `get.subErrorSafePrefix` | Your account is safe. You can create your key later from | حساب شما امن است. بعداً می‌توانید اشتراک را بسازید از |
| `get.subErrorSafeSuffix` | once a server is available. | وقتی سروری در دسترس شد. |
| `get.createSubToastTitle` | Your key is ready | اشتراک ساخته شد |
| `get.createSubToastBody` | Copy the link into your VPN app, or scan the QR code. | لینک را در برنامهٔ VPN خود کپی کنید یا کد QR را اسکن کنید. |
| `get.createAccountFailedTitle` | Could not create account | ساخت حساب ناموفق بود |
| `get.createSubFailedTitle` | Could not create your key | ساخت اشتراک ناموفق بود |
| `get.haveAccountPrefix` | Already have an account? | از قبل حساب دارید؟ |
| `get.lostNumberHint` | Lost your account number before saving it? You can switch to a new one - | شمارهٔ حساب را پیش از ذخیره گم کردید؟ می‌توانید شمارهٔ جدیدی بگیرید - |
| `get.lostNumberLinkLabel` | change it from your account page | از صفحهٔ حساب خود آن را تغییر دهید |
| `get.redeemPrompt` | Have a gift code? Redeem it before creating your key. | کد هدیه دارید؟ پیش از ساخت کلید آن را بازخرید کنید. |
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

## `impact` — The donation-impact panel: bandwidth donated, free users helped, charts.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `impact.title` | Donations support Unredacted | کمک‌های مالی از Unredacted پشتیبانی می‌کنند |
| `impact.body` | Unredacted is a US 501(c)(3) nonprofit. FreeSocks is one of the projects it runs. Donations fund the work. See what that work is on the Unredacted site. | Unredacted یک سازمان غیرانتفاعی 501(c)(3) آمریکایی است. فری‌ساکس یکی از پروژه‌های آن است. کمک‌های مالی هزینهٔ این کار را تأمین می‌کنند. جزئیات را در سایت Unredacted ببینید. |
| `impact.collectiveTitle` | Donation impact | اثر کمک‌های مالی |
| `impact.collectiveBody` | Donations made through FreeSocks raise every free user's monthly bandwidth for the month they're given. This is what the community's donations are doing right now. | کمک‌های مالی که از طریق فری‌ساکس انجام می‌شود، پهنای باند ماهانهٔ هر کاربر رایگان را برای همان ماه افزایش می‌دهد. این همان کاری است که کمک‌های جامعه همین حالا دارد انجام می‌دهد. |
| `impact.bonusThisMonth` | GB added this month | گیگابایت اضافه‌شده این ماه |
| `impact.bonusThisMonthDetail` | on top of every free account's monthly allowance | علاوه بر سهمیهٔ ماهانهٔ هر حساب رایگان |
| `impact.usersHelped` | free accounts reached | حساب‌های رایگان تحت پوشش |
| `impact.usersHelpedDetail` | active free users whose allowance the bonus raises | کاربران فعال رایگان که سهمیه‌شان با این پاداش افزایش می‌یابد |
| `impact.historyTitle` | Bandwidth added per month | پهنای باند اضافه‌شده در هر ماه |
| `impact.chartAria` | Bandwidth added to every free user by donations, month by month over the last {n} months | پهنای باندی که کمک‌های مالی در {n} ماه گذشته ماه‌به‌ماه به هر کاربر رایگان اضافه کرده است |
| `impact.yourContribution` | Your contribution | سهم شما |
| `impact.yourGiven` | You've given {amount} | شما {amount} کمک کرده‌اید |
| `impact.yourGb` | That's about {gb} GB of extra bandwidth for free users | یعنی حدود {gb} گیگابایت پهنای باند اضافی برای کاربران رایگان |
| `impact.yourCount [countPlural=one]` | across 1 donation | در 1 کمک مالی |
| `impact.yourCount [countPlural=other]` | across {count} donations | در {count} کمک مالی |
| `impact.empty` | No donations yet this month - the first one starts the counter. | هنوز این ماه کمکی نشده است - اولین کمک شمارنده را روشن می‌کند. |
| `impact.externalNote` | This counter tracks donations made through FreeSocks only. Gifts made directly at unredacted.org/donate support Unredacted's wider work, but don't add bandwidth here. | این شمارنده فقط کمک‌هایی را دنبال می‌کند که از طریق فری‌ساکس انجام می‌شود. هدیه‌هایی که مستقیماً در unredacted.org/donate داده می‌شوند از کار گسترده‌تر Unredacted حمایت می‌کنند، اما اینجا پهنای باندی اضافه نمی‌کنند. |
| `impact.aboutUnredacted` | About Unredacted | دربارهٔ Unredacted |

## `donate` — The donation card + amount picker (donations add bandwidth for all free users).

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `donate.addTitle` | Add a donation | افزودن کمک مالی |
| `donate.addSubtitle` | Chip in to help keep FreeSocks free for everyone. | کمک کنید تا فری‌ساکس برای همه رایگان بماند. |
| `donate.standaloneTitle` | Donate to FreeSocks | کمک مالی به فری‌ساکس |
| `donate.standaloneSubtitle` | FreeSocks is free for everyone, funded by donations. Give any amount to help keep it running - a donation also raises this month's bandwidth for every free user. | فری‌ساکس برای همه رایگان است و با کمک‌های مالی اداره می‌شود. هر مبلغی بدهید تا به ادامهٔ کارش کمک کنید - یک کمک مالی، پهنای باند این ماه هر کاربر رایگان را هم افزایش می‌دهد. |
| `donate.amountLabel` | Amount | مبلغ |
| `donate.none` | No thanks | نه، ممنون |
| `donate.custom` | Custom | دلخواه |
| `donate.customPlaceholder` | Other amount | مبلغ دیگر |
| `donate.impact` | Adds about {gb} GB to every free user this month | این ماه حدود {gb} گیگابایت به سهمیهٔ هر کاربر رایگان اضافه می‌کند |
| `donate.bonusActive` | Donations this month have added {gb} GB to every free user's monthly allowance. | کمک‌های این ماه {gb} گیگابایت به سهمیهٔ ماهانهٔ هر کاربر رایگان اضافه کرده است. |
| `donate.minNote` | Minimum {amount} | حداقل {amount} |
| `donate.give` | Donate {amount} | کمک {amount} |
| `donate.giving` | Starting… | در حال شروع… |
| `donate.startFailed` | Couldn't start the donation | شروع کمک مالی ممکن نشد |
| `donate.badge` | Donor | اهداکننده |
| `donate.badgeTooltip` | Thank you for supporting FreeSocks | از حمایت شما از فری‌ساکس سپاسگزاریم |
| `donate.thanksTitle` | You're a FreeSocks donor | شما یک اهداکنندهٔ فری‌ساکس هستید |
| `donate.thanksBody` | Thank you - your support helps keep FreeSocks free for everyone. | سپاسگزاریم - حمایت شما کمک می‌کند فری‌ساکس برای همه رایگان بماند. |

## `referral` — Miscellaneous strings.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `referral.fieldLabel` | Referral code (optional) | کد معرف (اختیاری) |
| `referral.fieldHint` | Have a code from a friend? You each get bonus membership days when you upgrade. | کدی از یک دوست دارید؟ وقتی ارتقا دهید، هر دوی شما روزهای اضافی عضویت می‌گیرید. |
| `referral.fieldPlaceholder` | FSR-XXXX-XXXX | FSR-XXXX-XXXX |
| `referral.applied` | Referral applied — bonus days are yours when you upgrade. | کد معرف اعمال شد - وقتی ارتقا دهید، روزهای اضافی مال شماست. |
| `referral.cardTitle` | Referrals | معرفی دوستان |
| `referral.cardBody` | Share your link. When someone signs up with it and becomes a member, you each get bonus days — theirs right away, yours after {vestingDays} days. | لینک خود را به اشتراک بگذارید. وقتی کسی با آن ثبت‌نام کند و عضو شود، هر دوی شما روزهای اضافی می‌گیرید - روزهای او بلافاصله، روزهای شما پس از {vestingDays} روز. |
| `referral.copyLink` | Copy invite link | کپی لینک دعوت |
| `referral.codeLabel` | Your code | کد شما |
| `referral.statsInvited` | Signed up | ثبت‌نام کرده‌اند |
| `referral.statsConverted` | Became members | عضو شده‌اند |
| `referral.statsPending` | Not yet members | هنوز عضو نشده‌اند |
| `referral.statsDays` | Bonus days earned | روزهای اضافی به‌دست‌آمده |

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

## `footer` — The site footer (nonprofit line, terms/privacy links).

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `footer.operatedPrefix` | Operated by | اداره‌شده توسط |
| `footer.operatedSuffix` | , a US 501(c)(3) nonprofit | ، یک سازمان غیرانتفاعی 501(c)(3) آمریکایی |
| `footer.viewSource` | View source | مشاهدهٔ کد منبع |
| `footer.terms` | Terms of Service | شرایط استفاده |
| `footer.privacy` | Privacy Policy | سیاست حریم خصوصی |
| `footer.transparency` | Transparency Report | گزارش شفافیت |
| `footer.socialX` | FreeSocks on X | فری‌ساکس در X |
| `footer.socialMastodon` | FreeSocks on Mastodon | فری‌ساکس در ماستودون |
| `footer.socialBluesky` | FreeSocks on Bluesky | فری‌ساکس در بلوسکای |
| `footer.support` | Support | پشتیبانی |

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

## `upgrade` — The paid-membership purchase panel (payment method, duration, totals).

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `upgrade.title` | Upgrade to a FreeSocks membership | به عضویت FreeSocks ارتقا دهید |
| `upgrade.extendTitle` | Extend your membership | عضویت خود را تمدید کنید |
| `upgrade.subtitle` | Unlimited bandwidth and devices. Choose a length and how to pay. | پهنای باند و دستگاه‌های نامحدود. مدت و روش پرداخت را انتخاب کنید. |
| `upgrade.subtitleNoDevices` | Unlimited bandwidth. Choose a length and how to pay. | پهنای باند نامحدود. مدت و روش پرداخت را انتخاب کنید. |
| `upgrade.compareBandwidth` | Bandwidth per month | پهنای باند در ماه |
| `upgrade.compareDevices` | Devices | دستگاه‌ها |
| `upgrade.durationLabel` | Membership length | مدت عضویت |
| `upgrade.cryptoMinNote` | Crypto payments start at {months} months - shorter terms fall below the network minimum. Pick another method for shorter terms. | پرداخت رمزارزی از {months} ماه شروع می‌شود - مدت‌های کوتاه‌تر کمتر از حداقل شبکه هستند. برای مدت کوتاه‌تر روش دیگری انتخاب کنید. |
| `upgrade.months [countPlural=one]` | 1 month | 1 ماه |
| `upgrade.months [countPlural=other]` | {count} months | {count} ماه |
| `upgrade.perMonth` | {price}/mo | {price}/ماه |
| `upgrade.fromPerMonth` | From {price}/month | از {price} در ماه |
| `upgrade.benefitsShort` | Unlimited bandwidth and devices | پهنای باند و دستگاه‌های نامحدود |
| `upgrade.benefitsShortNoDevices` | Unlimited bandwidth | پهنای باند نامحدود |
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
| `error.modeUnavailable` | Your current connection mode is no longer available. Switch to another mode first, then try again. | حالت اتصال فعلی شما دیگر در دسترس نیست. ابتدا به حالت دیگری تغییر دهید، سپس دوباره امتحان کنید. |

## `setup` — The "set up your app" section: recommended VPN clients per platform, install steps.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `setup.title` | Set up your VPN app | برنامهٔ پروکسی خود را تنظیم کنید |
| `setup.install` | Install | نصب |
| `setup.noApps` | No recommended apps for this platform yet - use any compatible client and add your subscription manually. | هنوز برنامهٔ پیشنهادی برای این پلتفرم نیست - از هر کلاینت سازگاری استفاده کنید و اشتراک خود را دستی اضافه کنید. |
| `setup.openSource` | Open source | متن‌باز |
| `setup.recommended` | Recommended | پیشنهادی |
| `setup.proprietary` | Proprietary | اختصاصی |
| `setup.easeEasy` | Easy to use | آسان برای استفاده |
| `setup.easeAdvanced` | Advanced | پیشرفته |
| `setup.viewSource` | Source | کد منبع |
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
| `setup.deviceCompatibleTitle` | Works with your device limit | با محدودیت دستگاه شما سازگار است |
| `setup.deviceIncompatibleTitle` | Not recommended for your plan | برای پلن شما پیشنهاد نمی‌شود |
| `setup.deviceIncompatibleNote` | These apps don't identify your device, so each launch can use up a device slot - or fail to connect on a device-limited plan. Prefer an app above. | این برنامه‌ها دستگاه شما را شناسایی نمی‌کنند، پس هر اجرا می‌تواند یک اسلات دستگاه را مصرف کند - یا در یک پلن محدود به دستگاه وصل نشود. یک برنامه از بالا را ترجیح دهید. |
| `setup.linkKind.play` | Google Play | Google Play |
| `setup.linkKind.appStore` | App Store | App Store |
| `setup.linkKind.github` | GitHub | GitHub |
| `setup.linkKind.apk` | APK | APK |
| `setup.linkKind.website` | Website | وب‌سایت |
| `setup.clientDesc.hiddify` | The easiest all-round choice: one-tap import, a clean interface, and builds for every platform. | آسان‌ترین انتخاب همه‌کاره: واردکردن با یک ضربه، رابط تمیز و نسخه برای هر پلتفرم. |
| `setup.clientDesc.karing` | Feature-rich and honors your plan's device limit. Slightly busier than Hiddify, but works well everywhere. | پرامکانات و به محدودیت دستگاه پلن شما احترام می‌گذارد. کمی شلوغ‌تر از Hiddify است، اما همه‌جا خوب کار می‌کند. |
| `setup.clientDesc.anywhere` | A polished, easy client for Apple devices only: iPhone, iPad, Apple TV, and Mac. No Android, Windows, or Linux version. | کلاینتی صیقل‌خورده و آسان فقط برای دستگاه‌های اپل: آیفون، آی‌پد، Apple TV و مک. نسخهٔ اندروید، ویندوز یا لینوکس ندارد. |
| `setup.clientDesc.singBox` | The reference app for the sing-box core. Powerful but minimal, so it's best if you are comfortable with technical settings. | برنامهٔ مرجع برای هستهٔ sing-box. قدرتمند اما مینیمال است، پس اگر با تنظیمات فنی راحتید بهترین است. |
| `setup.clientDesc.v2rayng` | A long-standing, lightweight Android client with one-tap import. More utilitarian than Hiddify, but dependable. | کلاینت اندرویدی قدیمی و سبک با واردکردن با یک ضربه. کاربردی‌تر از Hiddify است، اما قابل اعتماد. |
| `setup.clientDesc.v2rayn` | A powerful desktop app for advanced users. Import is manual, and links using encryption "none" can need a manual tweak. Prefer Hiddify if that sounds fiddly. | برنامهٔ دسکتاپی قدرتمند برای کاربران پیشرفته. واردکردن دستی است، و لینک‌هایی با رمزگذاری "none" ممکن است به تنظیم دستی نیاز داشته باشند. اگر این پیچیده به نظر می‌رسد، Hiddify را ترجیح دهید. |
| `setup.clientDesc.clash` | Clash Verge, a popular desktop app with strong routing rules. Some versions reject VLESS subscription links; if yours won't import, use Hiddify or v2rayN instead. | Clash Verge، یک برنامهٔ دسکتاپی محبوب با قوانین مسیریابی قوی. برخی نسخه‌ها لینک‌های اشتراک VLESS را نمی‌پذیرند؛ اگر وارد نشد، به‌جای آن از Hiddify یا v2rayN استفاده کنید. |
| `setup.clientDesc.flclash` | A clean, cross-platform Clash-family app. Import by pasting your subscription link (no one-tap import). | برنامه‌ای تمیز و چندسکویی از خانوادهٔ Clash. با جای‌گذاری لینک اشتراک وارد کنید (واردکردن با یک ضربه ندارد). |
| `setup.clientDesc.mihomoParty` | A friendly desktop app for the Clash (mihomo) core. Paste your subscription link to import. | برنامهٔ دسکتاپی دوستانه برای هستهٔ Clash (mihomo). برای واردکردن، لینک اشتراک خود را جای‌گذاری کنید. |
| `setup.clientDesc.throne` | An advanced desktop client that honors your plan's device limit, with solid Linux support. Expect manual setup. | کلاینت دسکتاپی پیشرفته‌ای که به محدودیت دستگاه پلن شما احترام می‌گذارد و پشتیبانی خوبی از لینوکس دارد. منتظر راه‌اندازی دستی باشید. |
| `setup.clientDesc.shadowrocket` | A paid, closed-source iOS app that is popular and reliable. Worth using if you already own it; the open-source apps above do the same job for free. | برنامهٔ iOS پولی و بسته‌متنی که محبوب و قابل اعتماد است. اگر از قبل آن را دارید ارزش استفاده دارد؛ برنامه‌های متن‌باز بالا همان کار را رایگان انجام می‌دهند. |
| `setup.clientDesc.outline` | The simplest experience there is: paste your access key and connect. Only works with Outline (Shadowsocks) access keys. | ساده‌ترین تجربه‌ای که هست: کلید دسترسی خود را جای‌گذاری کنید و وصل شوید. فقط با کلیدهای دسترسی Outline (Shadowsocks) کار می‌کند. |

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

## `delivery` — The connection-mode picker: "Beat censorship" (for censored countries) vs "Maximum privacy" (for open internet), plus the switch-confirmation dialog.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `delivery.title` | What matters most to you? | چه چیزی برایتان مهم‌تر است؟ |
| `delivery.subtitle` | Pick a focus. It's saved on this device only, and you can change it anytime. | یک اولویت انتخاب کنید - فقط روی همین دستگاه ذخیره می‌شود و هر زمان می‌توانید تغییرش دهید. |
| `delivery.subtitleServer` | Pick a focus. Changing it moves your existing key to the matching servers - your subscription URL stays the same. | یک نقطه تمرکز انتخاب کنید. تغییر آن، کلید شما را برای سرورهای منطبق دوباره صادر می‌کند؛ کلید فعلی شما به مدت ۲۴ ساعت کار می‌کند. |
| `delivery.subtitleSignup` | Pick a focus. It's saved to your account, and your first key uses it - you can change it anytime. | یک نقطه تمرکز انتخاب کنید. در حساب شما ذخیره می‌شود و اولین کلید شما از آن استفاده می‌کند - هر زمان می‌توانید تغییرش دهید. |
| `delivery.evadeTitle` | Internet Freedom Mode | حالت آزادی اینترنت |
| `delivery.evadeAudience` | For censored countries | برای کشورهای سانسورشده |
| `delivery.evadeBody` | Pick this if websites, apps, or VPNs are blocked where you are. Built to keep working under censorship, with backup links that are harder to block. | اگر سایت‌ها، برنامه‌ها یا VPNها در جایی که هستید مسدودند، این را انتخاب کنید. برای این ساخته شده که زیر سانسور به کار ادامه دهد، با لینک‌های پشتیبانی که مسدود کردنشان سخت‌تر است. |
| `delivery.privacyTitle` | Privacy Mode | حالت حریم خصوصی |
| `delivery.privacyAudience` | For open internet | برای اینترنت آزاد |
| `delivery.privacyBody` | Pick this if the internet is mostly open where you are. The strongest confidentiality - your configuration stays off third-party servers - but it is easier for censors to block. | اگر اینترنت در جایی که هستید بیشتر آزاد است، این را انتخاب کنید. قوی‌ترین محرمانگی - پیکربندی شما از سرورهای شخص ثالث دور می‌ماند - اما مسدود کردنش برای سانسورکنندگان آسان‌تر است. |
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

## `home` — The public landing page: hero, feature sections, impact section, FAQ intros.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `home.trust.nonprofit` | Run by a US 501(c)(3) nonprofit | اداره‌شده توسط یک سازمان غیرانتفاعی 501(c)(3) آمریکایی |
| `home.trust.openSource` | Open source | متن‌باز |
| `home.trust.noLogs` | No traffic logs | بدون گزارش ترافیک |
| `home.network.title` | Network status | وضعیت شبکه |
| `home.network.offline` | offline | آفلاین |
| `home.network.srOnline` | online | آنلاین |
| `home.network.srOffline` | offline | آفلاین |
| `home.network.note` | Checked every 10 minutes | هر ۱۰ دقیقه بررسی می‌شود |
| `home.network.link` | Live status | وضعیت زنده |
| `home.quicknav.label` | Jump to a section | پرش به یک بخش |
| `home.quicknav.privacy` | What we store | آنچه ذخیره می‌کنیم |
| `home.quicknav.threat` | Threat model | مدل تهدید |
| `home.quicknav.faq` | FAQ | سوالات متداول |
| `home.quicknav.impact` | Donation impact | اثر کمک‌های مالی |
| `home.sections.features` | Features | ویژگی‌ها |
| `home.sections.privacy` | Privacy | حریم خصوصی |
| `home.sections.how` | Getting started | شروع به کار |
| `home.sections.membership` | Membership | عضویت |
| `home.sections.impact` | Impact | اثر |
| `home.sections.faq` | FAQ | سوالات متداول |
| `home.sections.about` | About | درباره |
| `home.sections.globe` | The map | نقشه |
| `home.globe.title` | Voices from behind the firewall | صداهایی از پشت دیوار آتشین |
| `home.globe.body` | Every day, people behind national firewalls use FreeSocks to read, share, and publish - and to be heard. | هر روز مردم پشت دیوارهای آتشین ملی با FreeSocks می‌خوانند، به اشتراک می‌گذارند، منتشر می‌کنند — و شنیده می‌شوند. |
| `home.globe.aria` | A rotating globe: labels with voices from censored countries | کره‌ای چرخان: برچسب‌هایی با صداهایی از کشورهای سانسورشده |
| `home.globe.voices.ir.place` | Tehran, Iran | تهران، ایران |
| `home.globe.voices.ir.l1` | They filter the internet; they can't filter the truth. | اینترنت را فیلتر می‌کنند؛ حقیقت را نمی‌توانند فیلتر کنند. |
| `home.globe.voices.ir.l2` | My report on the protests reached the world. | گزارش من دربارهٔ اعتراض‌ها به جهان رسید. |
| `home.globe.voices.ir.l3` | My students read what the state calls lies. | شاگردانم آنچه را دولت دروغ می‌خواند می‌خوانند. |
| `home.globe.voices.cn.place` | Beijing, China | پکن، چین |
| `home.globe.voices.cn.l1` | History should not be a banned word. | تاریخ نباید کلمه‌ای ممنوع باشد. |
| `home.globe.voices.cn.l2` | I shared what happened in my city - and it stayed up. | آنچه در شهرم گذشت را به اشتراک گذاشتم — و باقی ماند. |
| `home.globe.voices.cn.l3` | I archived the deleted posts before they vanished. | پست‌های حذف‌شده را پیش از نابودیشان بایگانی کردم. |
| `home.globe.voices.ru.place` | Moscow, Russia | مسکو، روسیه |
| `home.globe.voices.ru.l1` | The truth should not need a permit. | حقیقت نباید به مجوز نیاز داشته باشد. |
| `home.globe.voices.ru.l2` | Independent journalism is not a crime. | روزنامه‌نگاری مستقل جرم نیست. |
| `home.globe.voices.ru.l3` | A blocked newspaper still gets read. | روزنامهٔ مسدودشده همچنان خوانده می‌شود. |
| `home.globe.voices.tm.place` | Ashgabat, Turkmenistan | عشق‌آباد، ترکمنستان |
| `home.globe.voices.tm.l1` | A whole country, almost offline - and still heard. | یک کشور کامل، تقریباً آفلاین — و با این حال شنیده‌شده. |
| `home.globe.voices.tm.l2` | They control the media, not my voice. | رسانه‌ها را کنترل می‌کنند، نه صدایم را. |
| `home.globe.voices.tm.l3` | Silence is the law here; we whisper anyway. | سکوت این‌جا قانون است؛ ما با این حال پچ‌پچ می‌کنیم. |
| `home.globe.voices.cu.place` | Havana, Cuba | هاوانا، کوبا |
| `home.globe.voices.cu.l1` | My voice travels farther than I ever will. | صدای من خیلی دورتر از خودم می‌رسد. |
| `home.globe.voices.cu.l2` | We document what the state denies. | آنچه دولت انکار می‌کند را ثبت می‌کنیم. |
| `home.globe.voices.cu.l3` | Independent voices, hand to hand, screen to screen. | صداهای مستقل، دست به دست، صفحه به صفحه. |
| `home.globe.voices.by.place` | Minsk, Belarus | مینسک، بلاروس |
| `home.globe.voices.by.l1` | When they shut us down, we still spoke. | وقتی خاموشمان کردند، باز هم سخن گفتیم. |
| `home.globe.voices.by.l2` | Free elections are not extremism. | انتخابات آزاد افراطی‌گری نیست. |
| `home.globe.voices.by.l3` | They banned our flag; not our voice. | پرچممان را ممنوع کردند؛ صدایمان را نه. |
| `home.globe.voices.mm.place` | Yangon, Myanmar | یانگون، میانمار |
| `home.globe.voices.mm.l1` | The blackout did not silence us. | قطعی اینترنت ساکتمان نکرد. |
| `home.globe.voices.mm.l2` | Evidence of the crackdown got out. | شواهد سرکوب بیرون رفت. |
| `home.globe.voices.mm.l3` | When the towers fell silent, the story did not. | وقتی برج‌ها خاموش شدند، قصه خاموش نشد. |
| `home.globe.voices.ve.place` | Caracas, Venezuela | کاراکاس، ونزوئلا |
| `home.globe.voices.ve.l1` | We count the votes they won't. | رأی‌هایی را می‌شماریم که آن‌ها نمی‌شمارند. |
| `home.globe.voices.ve.l2` | Hunger is not a state secret. | گرسنگی راز دولتی نیست. |
| `home.globe.voices.ve.l3` | The queue for food is long; the truth is longer. | صف نان طولانی است؛ حقیقت طولانی‌تر. |
| `home.globe.voices.vn.place` | Hanoi, Vietnam | هانوی، ویتنام |
| `home.globe.voices.vn.l1` | Writing about corruption is not a crime. | نوشتن دربارهٔ فساد جرم نیست. |
| `home.globe.voices.vn.l2` | My blog outlived the block. | وبلاگم از مسدودیت جان سالم به در برد. |
| `home.globe.voices.vn.l3` | One article they deleted reached thousands. | همان یک مقاله‌ای که حذف کردند به هزاران نفر رسید. |
| `home.globe.voices.pk.place` | Karachi, Pakistan | کراچی، پاکستان |
| `home.globe.voices.pk.l1` | During the shutdown, witnesses still spoke. | در زمان قطعی، شاهدان همچنان سخن گفتند. |
| `home.globe.voices.pk.l2` | Silencing journalists won't hide the story. | ساکت‌کردن روزنامه‌نگاران خبر را پنهان نمی‌کند. |
| `home.globe.voices.pk.l3` | The channel went dark; the reporting did not. | شبکه تاریک شد؛ خبرنگاری نشد. |
| `home.globe.voices.eg.place` | Cairo, Egypt | قاهره، مصر |
| `home.globe.voices.eg.l1` | They jailed the bloggers, not the words. | وبلاگ‌نویسان را زندانی کردند، نه کلمات را. |
| `home.globe.voices.eg.l2` | The protest was documented anyway. | اعتراض به هر حال ثبت شد. |
| `home.globe.voices.eg.l3` | From a small screen, a big story. | از یک صفحهٔ کوچک، قصه‌ای بزرگ. |
| `home.globe.voices.sa.place` | Riyadh, Saudi Arabia | ریاض، عربستان سعودی |
| `home.globe.voices.sa.l1` | Speaking is not a crime. | حرف زدن جرم نیست. |
| `home.globe.voices.sa.l2` | Her voice reached beyond the wall. | صدای او از پس دیوار بیرون رفت. |
| `home.globe.voices.sa.l3` | She asked a question the kingdom bans. | او پرسشی پرسید که پادشاهی ممنوع می‌کند. |
| `home.globe.voices.et.place` | Addis Ababa, Ethiopia | آدیس‌آبابا، اتیوپی |
| `home.globe.voices.et.l1` | The shutdown hid nothing. | قطعی اینترنت هیچ‌چیز را پنهان نکرد. |
| `home.globe.voices.et.l2` | Witnesses still found a way out. | شاهدان باز هم راهی بیرون پیدا کردند. |
| `home.globe.voices.et.l3` | The dead were counted, despite the blackout. | کشته‌ها شمرده شدند، با وجود قطعی. |
| `home.globe.voices.tr.place` | Istanbul, Turkey | استانبول، ترکیه |
| `home.globe.voices.tr.l1` | Blocking the site won't block the story. | مسدودکردن سایت، خبر را مسدود نمی‌کند. |
| `home.globe.voices.tr.l2` | Journalism continues, court order or not. | روزنامه‌نگاری ادامه دارد، با حکم دادگاه هم. |
| `home.globe.voices.tr.l3` | An arrested anchor cannot sign off the news. | مجری دستگیرشده نمی‌تواند خبر را تمام کند. |
| `home.globe.voices.az.place` | Baku, Azerbaijan | باکو، آذربایجان |
| `home.globe.voices.az.l1` | They call reporting extremism. | آن‌ها به گزارش‌گری می‌گویند افراطی‌گری. |
| `home.globe.voices.az.l2` | The investigation was published anyway. | تحقیق به هر حال منتشر شد. |
| `home.globe.voices.az.l3` | They froze our accounts, not our work. | حساب‌هایمان را مسدود کردند، نه کارمان را. |
| `home.globe.voices.uz.place` | Tashkent, Uzbekistan | تاشکند، ازبکستان |
| `home.globe.voices.uz.l1` | A closed internet is not a quiet one. | اینترنت بسته، اینترنت ساکتی نیست. |
| `home.globe.voices.uz.l2` | The world still heard what happened here. | جهان باز هم شنید که این‌جا چه گذشت. |
| `home.globe.voices.uz.l3` | The squares are watched; the words still move. | میدان‌ها تحت نظرند؛ کلمات با این حال می‌گردند. |
| `home.impact.title` | Donations at work | کمک‌های مالی در حال کار |
| `home.impact.body` | Every donation made through FreeSocks raises the monthly bandwidth of every free account for that month. This is what donors have added so far - you could add to it too. | هر کمک مالی که از طریق فری‌ساکس انجام شود، پهنای باند ماهانهٔ هر حساب رایگان را برای همان ماه افزایش می‌دهد. این چیزی است که اهداکنندگان تا الان اضافه کرده‌اند - شما هم می‌توانید به آن اضافه کنید. |
| `home.impact.cta` | Make a donation | کمک مالی کنید |
| `home.impact.chartAria` | Bandwidth added to every free user by donations, month by month | پهنای باندی که کمک‌های مالی ماه‌به‌ماه به هر کاربر رایگان اضافه می‌کند |
| `home.hero.variants.freedom` | A VPN for Internet Freedom | یک VPN برای آزادی اینترنت |
| `home.hero.variants.dissidents` | A VPN for dissidents | یک VPN برای مخالفان |
| `home.hero.variants.privacy` | A VPN for privacy | یک VPN برای حریم خصوصی |
| `home.hero.variants.world` | A VPN for the world | یک VPN برای جهان |
| `home.hero.subtitle` | FreeSocks is made for people whose internet is censored, and works as a privacy-respecting VPN anywhere else. Signing up takes one quick human check. We never ask for an email or a password. Your subscription URL works in most modern VPN apps, and a membership gets you {limits}. | فری‌ساکس برای کسانی ساخته شده که اینترنتشان سانسور می‌شود، و در هر جای دیگر هم به‌عنوان یک VPN محترم به حریم خصوصی کار می‌کند. ثبت‌نام فقط یک بررسی سریع انسانی می‌خواهد. ما هرگز ایمیل یا رمز عبور نمی‌خواهیم. لینک اشتراک شما در بیشتر برنامه‌های مدرن VPN کار می‌کند، و یک عضویت به شما {limits} می‌دهد. |
| `home.hero.impactNote` | Donations made through FreeSocks directly power free users: every donation buys real bandwidth for people in censored countries, that same month. | کمک‌هایی که از طریق فری‌ساکس انجام می‌شود مستقیماً کاربران رایگان را تقویت می‌کند: هر کمک، همان ماه برای مردم در کشورهای سانسورشده پهنای باند واقعی می‌خرد. |
| `home.hero.impactLink` | See the impact | اثرش را ببینید |
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
| `home.freeCard.cryptoNote` | Crypto accepted - Bitcoin, Monero, Zcash and more | رمزارز پذیرفته می‌شود - بیت‌کوین، مونرو، زی‌کش و بیشتر |
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
| `home.about.title` | About FreeSocks | دربارهٔ فری‌ساکس |
| `home.about.bodyPrefix` | FreeSocks is operated by | FreeSocks توسط ... اداره می‌شود. |
| `home.about.bodySuffix` | , a US 501(c)(3) nonprofit. | ، یک سازمان غیرانتفاعی 501(c)(3) آمریکایی. |
| `home.about.body2` | Most VPNs assume you can pay for a subscription and safely hand over an email address. In much of the world neither is true, so FreeSocks asks for neither. Anyone can get a working key in about a minute and keep it for as long as they use it. | بیشتر VPNها فرض می‌کنند می‌توانید برای اشتراک پول بدهید و بی‌خطر یک آدرس ایمیل تحویل دهید. در بیشتر جهان هیچ‌کدام درست نیست، پس فری‌ساکس هیچ‌کدام را نمی‌خواهد. هر کسی می‌تواند در حدود یک دقیقه یک کلید کارکرده بگیرد و تا وقتی از آن استفاده می‌کند نگهش دارد. |
| `home.about.siteLink` | unredacted.org | unredacted.org |
| `home.about.openSource` | The code that runs this service is published for anyone to inspect, audit, or run themselves. | کدی که این سرویس را اجرا می‌کند منتشر شده تا هر کسی بتواند آن را بررسی، حسابرسی یا خودش اجرا کند. |
| `home.about.viewSourceCta` | View the source | مشاهدهٔ کد منبع |
| `home.about.fact2Title` | Open source | متن‌باز |
| `home.about.fact3Title` | Donation funded | با کمک‌های مالی اداره می‌شود |
| `home.about.fact3Body` | Free accounts are paid for by donations and memberships. There are no ads and nothing is sold. | هزینهٔ حساب‌های رایگان با کمک‌های مالی و عضویت‌ها پرداخت می‌شود. تبلیغاتی نیست و چیزی فروخته نمی‌شود. |
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

## `status` — Miscellaneous strings.

| Key | English | Persian (فارسی) |
| --- | --- | --- |
| `status.title` | Network status | وضعیت شبکه |
| `status.updated` | Updated {time} | به‌روزرسانی‌شده {time} |
| `status.overallOk` | All locations are operating normally | همهٔ مکان‌ها عادی کار می‌کنند |
| `status.overallPartial` | Some locations are having issues | برخی مکان‌ها مشکل دارند |
| `status.overallMajor` | A major outage is in progress | یک قطعی بزرگ در جریان است |
| `status.locationsTitle` | Locations | مکان‌ها |
| `status.nodesUp` | {online} of {total} nodes up | {online} از {total} گره فعال است |
| `status.online` | Online | آنلاین |
| `status.offline` | Offline | آفلاین |
| `status.srOnline` | online | آنلاین |
| `status.srOffline` | offline | آفلاین |
| `status.loadQuiet` | Quiet | خلوت |
| `status.loadBusy` | Busy | شلوغ |
| `status.loadCrowded` | Crowded | بسیار شلوغ |
| `status.loadUnknown` | Load unknown | بار نامشخص |
| `status.matrixTitle` | Availability in censored regions | دسترسی‌پذیری در مناطق سانسورشده |
| `status.matrixBody` | How well each connection mode works from specific countries, based on reports we receive. "Partial" means some networks or times of day block it. | هر حالت اتصال از کشورهای مشخص چقدر خوب کار می‌کند، بر اساس گزارش‌هایی که دریافت می‌کنیم. «جزئی» یعنی برخی شبکه‌ها یا برخی ساعت‌های روز آن را مسدود می‌کنند. |
| `status.matrixAvailable` | Available | در دسترس |
| `status.matrixPartial` | Partial | جزئی |
| `status.matrixBlocked` | Blocked | مسدود |
| `status.matrixEmpty` | No country data published yet. | هنوز داده‌ای برای کشوری منتشر نشده است. |
| `status.incidentsTitle` | Incidents | حوادث |
| `status.incidentsNone` | No incidents in the last 30 days. | در 30 روز گذشته حادثه‌ای نبوده است. |
| `status.incidentsOngoing` | Ongoing | در جریان |
| `status.incidentsResolved` | Resolved {time} | حل‌شده {time} |
| `status.incidentsStarted` | Started {time} | شروع‌شده {time} |
| `status.incidentsGlobal` | All locations | همهٔ مکان‌ها |
| `status.incidentsPast` | Past incidents | حوادث گذشته |
| `status.report` | Report a problem | گزارش مشکل |
