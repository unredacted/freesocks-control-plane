# FreeSocks translation review — Arabic (العربية)

Generated from `messages/en.json` (source of truth) vs `messages/ar.json`.
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

- Edit the **"Arabic (العربية)" column** (or add a correction below a row). Rows marked
  ⚠️ MISSING have no translation yet.


## `faq` — The landing-page FAQ (questions + answers).

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `faq.title` | Frequently asked questions | الأسئلة الشائعة |
| `faq.subtitle` | Answers to common questions. | تمت الإجابة على الأسئلة الأساسية. هل ما زلت تواجه مشكلة؟ تواصل معنا عبر رقم تعريف الدعم الخاص بك. |
| `faq.tabGeneral` | General | عام |
| `faq.tabThreat` | What we protect you from | ممَّ نحميك |
| `faq.contactPrefix` | For anything else, email | لأي استفسار آخر، راسلنا على |
| `faq.contactSuffix` | and include your Support ID. | واذكر معرّف الدعم الخاص بك. |
| `faq.q1.question` | What is FreeSocks? | ما هو FreeSocks؟ |
| `faq.q1.answer` | A free VPN service that helps people in heavily-censored regions reach the open internet. It's operated by Unredacted, a US 501(c)(3) nonprofit. | خدمة بروكسي مجانية تساعد الأشخاص في المناطق الخاضعة لرقابة مشددة على الوصول إلى الإنترنت المفتوح. وتديرها منظمة "أنريداكتد"، وهي منظمة أمريكية غير ربحية مسجلة بموجب المادة 501(c)(3). |
| `faq.q2.question` | Is it really free? | هل هو مجاني حقاً؟ |
| `faq.q2.answer` | Yes. A free account gives you a working VPN. A paid FreeSocks membership lifts the limits and helps fund free access for others. | نعم. يمنحك الحساب المجاني خادم وكيل فعال. أما عضوية FreeSocks المدفوعة فتزيل القيود وتساعد في تمويل الوصول المجاني للآخرين. |
| `faq.q3.question` | Do I need to give an email or password? | هل أحتاج إلى إدخال بريد إلكتروني أو كلمة مرور؟ |
| `faq.q3.answer` | No. You pass a one-time human check and we generate a 32-digit account number - that's your only credential. We never ask for an email, phone number, or name. | لا. أنت تجتاز فحصًا بشريًا لمرة واحدة، ونقوم بإنشاء رقم حساب مكون من 32 رقمًا - وهذا هو بيانات اعتمادك الوحيدة. لا نطلب منك أبدًا بريدًا إلكترونيًا أو رقم هاتف أو اسمًا. |
| `faq.q4.question` | What if I lose my account number? | ماذا لو فقدت رقم حسابي؟ |
| `faq.q4.answer` | It's the only way back into your account and we can't recover it (we store only a hashed version), so save it in a password manager when you create it. If you lose it, just create a new free account. | هذه هي الطريقة الوحيدة لاستعادة حسابك، ولا يمكننا استعادته (نحتفظ فقط بنسخة مشفرة منه)، لذا احفظه في مدير كلمات المرور عند إنشائه. إذا فقدته، فما عليك سوى إنشاء حساب مجاني جديد. |
| `faq.q5.question` | How do I connect? | كيف يمكنني الاتصال؟ |
| `faq.q5.answer` | Create a subscription, copy its link (or scan the QR code), and add it to a compatible app. Your account page lists the recommended app for each platform (Android, iPhone, Windows, macOS / Linux). | أنشئ اشتراكًا، وانسخ رابطه (أو امسح رمز الاستجابة السريعة ضوئيًا)، وأضفه إلى تطبيق متوافق مثل v2rayNG أو Hiddify أو Streisand. ستجد في صفحة حسابك قائمة بالتطبيقات الموصى بها لكل منصة. |
| `faq.q6.question` | What do you log about me? | ماذا تسجل عني؟ |
| `faq.q6.answer` | As little as possible: only a hashed version of your account number - never your email, name, or IP address - and no logs of the sites you visit or the traffic you send. | بأقل قدر ممكن: نسخة مشفرة فقط من رقم حسابك - وليس بريدك الإلكتروني أو اسمك أبدًا - ولا سجلات للمواقع التي تزورها أو حركة المرور التي ترسلها. |
| `faq.q7.question` | The link is blocked where I am. What can I do? | الرابط محظور في منطقتي. ماذا أفعل؟ |
| `faq.q7.answer` | On your account page, open "Trouble connecting?" to get a mirror link served from a different host that may not be blocked. You can also set your delivery preference to favor staying connected. | في صفحة حسابك، افتح "هل تواجه مشكلة في الاتصال؟" للحصول على رابط بديل من خادم آخر قد لا يكون محظورًا. يمكنك أيضًا ضبط تفضيلات التسليم لديك لتفضيل البقاء متصلاً. |
| `faq.q8.question` | Can I buy a membership for someone else? | هل يمكنني شراء عضوية لشخص آخر؟ |
| `faq.q8.answer` | Yes - on your account page use "Buy codes to share" to purchase membership codes you can give to friends or family. Each one works on any account and doesn't affect yours. | نعم، يمكنك استخدام خيار "شراء رموز للمشاركة" في صفحة حسابك لشراء رموز عضوية يمكنك إهداؤها لأصدقائك أو عائلتك. كل رمز منها يعمل على أي حساب ولا يؤثر على حسابك. |
| `faq.q9.question` | Can I pay anonymously? | هل يمكنني الدفع بشكل مجهول؟ |
| `faq.q9.answer` | Yes. You can pay with cryptocurrency - Bitcoin, or Monero and Zcash for the most privacy - with no account, email, or card. Your membership activates automatically once the payment confirms. | نعم. يمكنك الدفع بالعملات الرقمية - بيتكوين، أو مونيرو وزيكاش لأقصى درجات الخصوصية - دون الحاجة إلى حساب أو بريد إلكتروني أو بطاقة. يتم تفعيل عضويتك تلقائيًا بمجرد تأكيد الدفع. |
| `faq.q10.question` | Do you own your servers, or rent them? | هل تملكون خوادمكم أم تستأجرونها؟ |
| `faq.q10.answer` | We own our hardware and run it ourselves. Plenty of VPN companies rent theirs from datacenters or cloud hosts, which puts the machine your traffic passes through in someone else's hands - they can be pressured to hand it over, or just quietly copy what is on it. That is a line we are not willing to cross, so we buy and run our own equipment instead. It costs more and we grow slower because of it, but it is the only way the privacy promises on this page actually mean anything. | نملك أجهزتنا ونشغّلها بأنفسنا. كثير من شركات VPN تستأجر خوادمها من مراكز بيانات أو مزوّدي استضافة سحابية، فيصبح الجهاز الذي تمرّ عبره بياناتك في يد طرف آخر - يمكن الضغط عليه لتسليمه، أو نسخ ما عليه بصمت. هذا خطّ لا نقبل تجاوزه، لذلك نشتري معداتنا ونشغّلها بأنفسنا. يكلّفنا ذلك أكثر وينمو عملنا ببطء بسببه، لكنه الطريقة الوحيدة التي تجعل وعود الخصوصية في هذه الصفحة تعني شيئًا حقًا. |

## `threat` — Miscellaneous strings.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `threat.subtitle` | An honest look at what this service can and cannot do. Security tools that overpromise get people hurt, so here is exactly where the lines are. | نظرة صادقة على ما تستطيع هذه الخدمة فعله وما لا تستطيع. أدوات الأمان التي تَعِد بأكثر مما تقدّمه تُلحق الضرر بالناس، لذلك نحدد هنا موضع الخطوط بدقة. |
| `threat.q1.question` | What does FreeSocks protect me from? | ممَّ يحميني FreeSocks؟ |
| `threat.q1.answer` | FreeSocks tunnels your traffic through an encrypted VPN connection, so your ISP, mobile carrier, school, or workplace network cannot see which sites you visit or block them. It is built for getting past censorship and for keeping the network you are on from watching what you do. | يمرّر FreeSocks بياناتك عبر اتصال VPN مشفّر، فلا يستطيع مزوّد خدمة الإنترنت أو مشغّل الهاتف المحمول أو شبكة المدرسة أو العمل رؤية المواقع التي تزورها أو حجبها. صُمّم لتجاوز الرقابة ولمنع الشبكة التي تتصل منها من مراقبة ما تفعله. |
| `threat.q2.question` | What does FreeSocks NOT protect me from? | ممَّ لا يحميني FreeSocks؟ |
| `threat.q2.answer` | It does not make you anonymous to sites you sign in to: if you log in to an account, that site knows who you are. It cannot protect a device that is already compromised (spyware, a managed work profile, someone with physical access). And a powerful adversary that can watch traffic at many points on the internet may still correlate patterns. If your safety depends on strong anonymity, use Tor and follow specialist guidance for your situation. | لا يجعلك مجهولًا لدى المواقع التي تسجّل الدخول إليها: إذا سجّلت الدخول إلى حساب، فذلك الموقع يعرف من أنت. ولا يمكنه حماية جهاز مخترق أصلًا (برمجيات تجسس، أو ملف عمل مُدار، أو شخص لديه وصول فعلي إلى جهازك). كما أن خصمًا قويًا يراقب حركة المرور في نقاط كثيرة من الإنترنت قد يظل قادرًا على ربط الأنماط ببعضها. إذا كانت سلامتك تعتمد على إخفاء هوية قوي، فاستخدم Tor واتبع إرشادات المتخصصين المناسبة لحالتك. |
| `threat.q3.question` | Can FreeSocks see my traffic? | هل يستطيع FreeSocks رؤية بياناتي؟ |
| `threat.q3.answer` | Your traffic exits through our servers, so treat us like any exit: sites you use over HTTPS (almost all of the modern web) stay encrypted end to end and we cannot read their contents. We configure our servers to keep no connection logs, no visited-site logs, and no source IPs, and the control plane never stores your IP address at all. | تخرج بياناتك عبر خوادمنا، لذا تعامل معنا كأي نقطة خروج: المواقع التي تستخدمها عبر HTTPS (وهي غالبية الويب الحديث) تبقى مشفّرة من الطرف إلى الطرف ولا نستطيع قراءة محتواها. نضبط خوادمنا بحيث لا تحتفظ بأي سجلات اتصال ولا سجلات للمواقع المُزارة ولا عناوين IP المصدر، ولا تخزّن منظومة التحكم عنوان IP الخاص بك إطلاقًا. |
| `threat.q4.question` | What happens if a FreeSocks server is seized or compromised? | ماذا يحدث إذا صودر أحد خوادم FreeSocks أو اختُرق؟ |
| `threat.q4.answer` | There is nothing identifying on it. Servers hold no names, emails, IPs, or traffic history, because we never collect those in the first place. Access keys can be revoked and reissued quickly, and we can rotate infrastructure without losing accounts. | لا يوجد عليه ما يكشف هوية أحد. لا تحتفظ الخوادم بأسماء أو بريد إلكتروني أو عناوين IP أو سجل تصفح، لأننا لا نجمعها أصلًا. ويمكن إلغاء مفاتيح الوصول وإعادة إصدارها بسرعة، كما يمكننا تدوير البنية التحتية دون فقدان الحسابات. |
| `threat.q5.question` | Can my government or ISP tell that I am using FreeSocks? | هل تستطيع حكومتي أو مزوّد الإنترنت معرفة أنني أستخدم FreeSocks؟ |
| `threat.q5.answer` | Sometimes censors can detect that circumvention traffic is in use even when they cannot read it. Our transports are designed to look like ordinary encrypted web traffic, and Internet Freedom Mode routes through infrastructure that is expensive to block. Still, whether use is detectable, and what the consequences are, varies by country. Weigh your local risk. | يمكن للرقيب أحيانًا اكتشاف استخدام حركة مرور لتجاوز الحجب حتى دون قراءتها. صُمّمت بروتوكولات النقل لدينا لتبدو كحركة ويب مشفّرة عادية، ويوجّه وضع حرية الإنترنت الاتصال عبر بنية تحتية يكلّف حجبها الكثير. ومع ذلك، فإن إمكانية اكتشاف الاستخدام وعواقبه تختلف من بلد إلى آخر. قدِّر المخاطر في بلدك بنفسك. |
| `threat.q6.question` | Why should I believe any of this? | لماذا أصدّق أيًّا من هذا؟ |
| `threat.q6.answer` | The control plane is open source, so anyone can read exactly what it stores and check that there is no place a name, email, or IP address could even go. Claims that depend on server configuration (like disabled logging) are documented and enforced by the same code. You still have to trust the operator for the parts you cannot see, as with every VPN; our approach is to minimize what there is to trust. | منظومة التحكم مفتوحة المصدر، فيستطيع أي شخص الاطلاع على ما تخزّنه بالضبط والتأكد من عدم وجود أي مكان يمكن أن يذهب إليه اسم أو بريد إلكتروني أو عنوان IP. أما الادعاءات التي تعتمد على إعداد الخوادم (مثل تعطيل السجلات) فهي موثّقة ويفرضها الكود نفسه. ويظل عليك أن تثق بالمشغّل في الأجزاء التي لا يمكنك رؤيتها، كما هو الحال مع كل خدمة VPN؛ ونهجنا هو تقليل ما يتطلب الثقة إلى أدنى حد. |
| `threat.q7.question` | Do payments link my identity to my browsing? | هل تربط المدفوعات هويتي بتصفحي؟ |
| `threat.q7.answer` | Membership is optional, and payment is handled by outside processors: we never store the payer's name, email, or address, and an order is tied to your account only through an opaque reference. Cryptocurrency options (including Monero) exist for people who do not want a card trail at all. | العضوية اختيارية، وتعالج المدفوعات جهات دفع خارجية: لا نخزّن أبدًا اسم الدافع أو بريده الإلكتروني أو عنوانه، ولا يرتبط الطلب بحسابك إلا عبر مرجع مبهَم. وتتوفر خيارات العملات المشفّرة (بما فيها مونيرو) لمن لا يريد أي أثر لبطاقة على الإطلاق. |

## `common` — Shared buttons/labels (copy, download, close, working…) used across every page.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `common.copy` | Copy | نسخ |
| `common.copied` | Copied to clipboard | تم النسخ إلى الحافظة |
| `common.copyFailed` | Copy failed - select the text and copy it manually | فشل النسخ - حدّد النص وانسخه يدويًا |
| `common.download` | Download | تنزيل |
| `common.cancel` | Cancel | إلغاء |
| `common.close` | Close | إغلاق |
| `common.retry` | Retry | إعادة المحاولة |
| `common.loading` | Loading… | جارٍ التحميل… |
| `common.working` | Working… | جارٍ التنفيذ… |
| `common.reload` | Reload | إعادة التحميل |
| `common.language` | Language | اللغة |
| `common.deviceCount [countPlural=one]` | 1 device | جهاز واحد |
| `common.deviceCount [countPlural=other]` | {count} devices | {count} أجهزة |

## `nav` — The site header: navigation buttons, menu, language/theme controls.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `nav.getAccount` | Get a free account | احصل على حساب مجاني |
| `nav.signIn` | Sign in | تسجيل الدخول |
| `nav.account` | My account | حسابي |
| `nav.menu` | Menu | القائمة |
| `nav.theme` | Theme | المظهر |
| `nav.home` | FreeSocks home | الصفحة الرئيسية لـ FreeSocks |

## `captcha` — The proof-of-work human check widget states.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `captcha.initial` | I'm human | أنا إنسان |
| `captcha.verifying` | Verifying… | جارٍ التحقق… |
| `captcha.solved` | Verified | تم التحقق |
| `captcha.error` | Check failed - retry | فشل التحقق - أعد المحاولة |
| `captcha.failedTitle` | Couldn't complete the human check. | تعذّر إكمال التحقق البشري. |
| `captcha.failedBody` | The check runs on your device and didn't finish. This is usually a network problem, not something you did wrong. | يجري هذا التحقق على جهازك ولم يكتمل. عادةً ما تكون هذه مشكلة في الشبكة، وليست خطأً منك. |
| `captcha.failedTip1` | Wait a moment, then try again | انتظر لحظة ثم حاول مرة أخرى |
| `captcha.failedTip2` | Try a different network - or a VPN if sites are blocked where you are | جرّب شبكة أخرى - أو استخدم VPN/بروكسي إذا كانت المواقع محجوبة في منطقتك |
| `captcha.failedTip3` | Still stuck? Try a private/incognito window or turn off browser extensions | ما زالت المشكلة قائمة؟ جرّب نافذة تصفح خاص أو عطّل إضافات المتصفح |

## `reveal` — The save-your-account-number modal (the 32-digit sign-in number is shown ONCE; users must download it and paste it back to verify). The single most safety-critical copy in the product.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `reveal.title` | Save your account number now | احفظ رقم حسابك الآن |
| `reveal.subtitle` | This 32-digit number is the ONLY way to sign in again. There is no email or password to recover it. If you lose it, your account is gone for good. | هذا الرقم المكوّن من 32 خانة هو الطريقة الوحيدة لتسجيل الدخول مرة أخرى. لا يوجد بريد إلكتروني أو كلمة مرور لاستعادته. إذا فقدته، فسيضيع حسابك نهائيًا. |
| `reveal.cannotRecover` | We cannot recover it for you - not even support can. | لا يمكننا استعادته لك - ولا حتى الدعم الفني. |
| `reveal.saveHint` | Save it in a password manager, or write it down somewhere safe and private. | احفظه في مدير كلمات المرور، أو اكتبه في مكان آمن وخاص. |
| `reveal.downloadRequired` | Download your account number to continue. Keep the file somewhere safe. | نزّل رقم حسابك للمتابعة. احتفظ بالملف في مكان آمن. |
| `reveal.continue` | Continue | متابعة |
| `reveal.verifyTitle` | Confirm you saved it | أكّد أنك حفظته |
| `reveal.verifySubtitle` | Your account number is now hidden. Enter or paste it from the copy you just saved to confirm you can sign in later. | رقم حسابك مخفي الآن. أدخله أو الصقه من النسخة التي حفظتها للتو للتأكد من أنك تستطيع تسجيل الدخول لاحقًا. |
| `reveal.verifyPlaceholder` | Paste your 32-digit account number | الصق رقم حسابك المكوّن من 32 خانة |
| `reveal.verifyMismatch` | That doesn't match your account number. Check the copy you saved, or go back to see it again. | هذا لا يطابق رقم حسابك. تحقق من النسخة التي حفظتها، أو عُد لرؤيته مرة أخرى. |
| `reveal.back` | Back | رجوع |
| `reveal.done` | I've saved it | لقد حفظته |
| `reveal.savedConfirmed` | Account number saved and verified | تم حفظ رقم الحساب والتحقق منه |
| `reveal.downloadFilename` | freesocks-account-number.txt | freesocks-account-number.txt |
| `reveal.leaveWarning` | Your account number is still on screen. If you leave now without saving it, you will not be able to sign in again. | رقم حسابك ما زال على الشاشة. إذا غادرت الآن دون حفظه، فلن تتمكن من تسجيل الدخول مرة أخرى. |

## `support` — The support-ID line (a non-secret handle for contacting support).

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `support.label` | Support ID | معرّف الدعم |
| `support.hint` | Share this if you contact us. It is NOT your sign-in number and grants no access. | شارك هذا إذا تواصلت معنا. إنه ليس رقم تسجيل دخولك ولا يمنح أي وصول. |
| `support.copyAria` | Copy your support ID | انسخ معرّف الدعم |
| `support.emailUs` | Email us: | راسلنا عبر البريد: |
| `support.getAccountLine` | Questions or problems? Email us at | أسئلة أو مشكلات؟ راسلنا عبر البريد على |

## `login` — The sign-in page (account number + optional passkey).

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `login.title` | Sign in with your account number | سجّل الدخول برقم حسابك |
| `login.subtitle` | Enter the 32-digit account number you saved. It's the only way to sign in - there's no email or password to recover. | أدخل رقم الحساب المكوّن من 32 خانة الذي حفظته. إنها الطريقة الوحيدة لتسجيل الدخول - لا يوجد بريد إلكتروني أو كلمة مرور للاستعادة. |
| `login.label` | Account number | رقم الحساب |
| `login.show` | Show | إظهار |
| `login.hide` | Hide | إخفاء |
| `login.submit` | Sign in | تسجيل الدخول |
| `login.submitting` | Signing in… | جارٍ تسجيل الدخول… |
| `login.noAccount` | Don't have an account number yet? | ليس لديك رقم حساب بعد؟ |
| `login.getOne` | Get a free account | احصل على حساب مجاني |
| `login.failed` | Sign-in failed | فشل تسجيل الدخول |
| `login.success` | Signed in | تم تسجيل الدخول |
| `login.sessionExpired` | Please sign in again - your session may have ended. | يرجى تسجيل الدخول مرة أخرى - ربما انتهت جلستك. |
| `login.digitProgress` | {count} of {total} digits entered | {count} من {total} رقمًا تم إدخالها |
| `login.or` | or | أو |

## `passkey` — Optional passkey (Face ID / fingerprint) sign-in management.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `passkey.title` | Passkeys | مفاتيح المرور |
| `passkey.desc` | Sign in with Face ID, Touch ID, a security key, or your password manager - no account number to type. | سجّل الدخول عبر Face ID أو Touch ID أو مفتاح أمان أو مدير كلمات المرور - دون كتابة رقم الحساب. |
| `passkey.warning` | Heads-up: a passkey saved on your phone or in your browser may sync to your Apple or Google account, which can link this anonymous account to that identity. Use a hardware security key, or skip passkeys, if that matters to you. | تنبيه: مفتاح المرور المحفوظ على هاتفك أو في متصفحك قد يُزامَن مع حساب Apple أو Google لديك، مما قد يربط هذا الحساب المجهول بتلك الهوية. استخدم مفتاح أمان فعليًا، أو تجاوز مفاتيح المرور، إذا كان ذلك يهمّك. |
| `passkey.unsupported` | This device or browser doesn't support passkeys. | هذا الجهاز أو المتصفح لا يدعم مفاتيح المرور. |
| `passkey.none` | No passkeys yet. Your account number still signs you in. | لا مفاتيح مرور بعد. ما زال بإمكانك تسجيل الدخول برقم حسابك. |
| `passkey.add` | Add a passkey | إضافة مفتاح مرور |
| `passkey.adding` | Adding… | جارٍ الإضافة… |
| `passkey.added` | Passkey added | تمت إضافة مفتاح المرور |
| `passkey.addFailed` | Couldn't add the passkey | تعذّرت إضافة مفتاح المرور |
| `passkey.remove` | Remove | إزالة |
| `passkey.removed` | Passkey removed | تمت إزالة مفتاح المرور |
| `passkey.removeFailed` | Couldn't remove the passkey | تعذّرت إزالة مفتاح المرور |
| `passkey.deviceLabelLabel` | Device name (optional) | اسم الجهاز (اختياري) |
| `passkey.deviceLabelPlaceholder` | e.g. My phone | مثال: هاتفي |
| `passkey.addedOn` | Added {date} | أُضيف {date} |
| `passkey.lastUsed` | last used {date} | آخر استخدام {date} |
| `passkey.signIn` | Sign in with a passkey | تسجيل الدخول بمفتاح مرور |
| `passkey.signingIn` | Authenticating… | جارٍ التحقق… |
| `passkey.signInFailed` | Passkey sign-in failed | فشل تسجيل الدخول بمفتاح المرور |
| `passkey.notNow` | Not now | ليس الآن |

## `account` — The signed-in /account dashboard: connection, membership, codes, security tabs.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `account.title` | Your account | حسابك |
| `account.tierLabel` | Your plan | خطتك |
| `account.statusActive` | Active | نشط |
| `account.statusGrace` | Expiring soon | ينتهي قريبًا |
| `account.statusDisabled` | Disabled | منتهٍ |
| `account.regenerate` | Create a new key | إنشاء مفتاح جديد |
| `account.switchBackend` | Switch server type | تغيير نوع الخادم |
| `account.rotate` | Change account number | تغيير رقم الحساب |
| `account.signOut` | Sign out | تسجيل الخروج |
| `account.redeemTitle` | Have a membership code? | لديك رمز عضوية؟ |
| `account.redeemPlaceholder` | FSM-XXXX-XXXX-XXXX | FSM-XXXX-XXXX-XXXX |
| `account.redeemSubmit` | Redeem code | استخدام الرمز |
| `account.redeemSuccess` | Redeemed - you're now on {tier} for {days} more days. | تم الاستخدام - أنت الآن على {tier} لمدة {days} يومًا إضافيًا. |
| `account.redeemFailed` | That code is not valid, or has already been used. | هذا الرمز غير صالح أو تم استخدامه من قبل. |
| `account.redeemAriaLabel` | Membership code | رمز العضوية |
| `account.switchTo` | Switch to {label} | التبديل إلى {label} |
| `account.devicesTitle` | Connected devices | الأجهزة المتصلة |
| `account.lastSeen` | Last seen {date} | آخر اتصال {date} |
| `account.noSubTitle` | No key yet | لا يوجد اشتراك بعد |
| `account.noSubBody` | Create your key to get a link you can use in any compatible VPN app. | أنشئ اشتراكك الأول للحصول على رابط يمكنك استخدامه في أي تطبيق VPN متوافق. |
| `account.createSub` | Get my key | إنشاء اشتراك |
| `account.creating` | Creating your key… | جارٍ الإنشاء… |
| `account.rotateTitle` | Change your account number? | تغيير رقم الحساب؟ |
| `account.rotateBody` | A new 32-digit number is generated and shown once. Your current number stops working immediately. Anyone who has it loses access. Do this if your number may have leaked. | سيتم إنشاء رقم جديد من 32 خانة وعرضه مرة واحدة فقط. يتوقف رقمك الحالي عن العمل فورًا، ويفقد أي شخص يملكه إمكانية الوصول. افعل هذا إذا كان رقمك قد تسرّب. |
| `account.rotateConfirm` | Yes, change it | نعم، غيّره |
| `account.rotating` | Rotating… | جارٍ التغيير… |
| `account.rotateFailedTitle` | Could not change the account number | تعذّر تغيير رقم الحساب |
| `account.refreshMembership` | Already paid? Check for my membership | دفعت بالفعل؟ تحقّق من عضويتي |
| `account.memberActiveTitle` | Membership active | العضوية نشطة |
| `account.memberActiveExpiry` | Active until {date} | نشطة حتى {date} |
| `account.membershipNudge.title` | Go unlimited with a membership | احصل على اشتراك غير محدود |
| `account.membershipNudge.body` | Unlimited bandwidth and devices. | نطاق ترددي وأجهزة غير محدودة. |
| `account.membershipNudge.bodyNoDevices` | Unlimited bandwidth. | نطاق ترددي غير محدود. |
| `account.membershipNudge.cta` | View membership | عرض العضوية |
| `account.tab.connection` | Connection | الاتصال |
| `account.tab.membership` | Membership | العضوية |
| `account.tab.gifts` | Gifts & referrals | الهدايا والإحالات |
| `account.tab.security` | Security | الأمان |
| `account.refreshing` | Refreshing… | جارٍ التحديث… |
| `account.regenSuccessTitle` | New subscription URL generated | تم إنشاء رابط اشتراك جديد |
| `account.regenSuccessBody` | Re-import it on each of your devices. The old URL works for 24 more hours. | أعد استيراده على كل أجهزتك. يظل الرابط القديم يعمل لمدة 24 ساعة إضافية. |
| `account.regenFailedTitle` | Could not create a new key | تعذّر إنشاء مفتاح جديد |
| `account.switchSuccessTitle` | Switched to {tier} | تم التبديل إلى {tier} |
| `account.switchSuccessBodyGrace` | Re-import the new subscription URL on each device. The old subscription works for 24 more hours. | أعد استيراد رابط الاشتراك الجديد على كل جهاز. يظل الاشتراك القديم يعمل لمدة 24 ساعة إضافية. |
| `account.switchSuccessBody` | Re-import the new subscription URL on each device. | أعد استيراد رابط الاشتراك الجديد على كل جهاز. |
| `account.switchFailedTitle` | Could not switch server type | تعذّر تبديل نوع الخادم |
| `account.refreshWelcome` | Welcome to {tier} | مرحبًا بك في {tier} |
| `account.refreshNoneTitle` | No active membership found yet | لم يتم العثور على عضوية نشطة بعد |
| `account.refreshNoneBody` | If you just paid, give it a moment and try again. | إذا كنت قد دفعت للتو، فانتظر لحظة وحاول مرة أخرى. |
| `account.refreshFailedTitle` | Could not refresh membership | تعذّر تحديث العضوية |
| `account.graceTitle` | Your account is in a grace period | حسابك في فترة سماح |
| `account.graceBody` | Your membership has lapsed, so this account will be limited soon. Renew - donate or redeem a membership code below - to keep your plan. | انتهت عضويتك، وسيُقيَّد هذا الحساب قريبًا. جدّد - تبرّع أو استخدم رمز عضوية بالأسفل - للحفاظ على خطتك. |
| `account.disabledTitle` | Your account is currently disabled | حسابك معطّل حاليًا |
| `account.disabledBody` | New keys and changes are paused on this account. Redeem a membership code below to reactivate it, or contact support and share your Support ID. | المفاتيح الجديدة والتغييرات متوقفة على هذا الحساب. استخدم رمز عضوية بالأسفل لإعادة تفعيله، أو تواصل مع الدعم وشارك معرّف الدعم الخاص بك. |
| `account.rotateHint` | Replace your 32-digit account number if it may have leaked - or, if you never saved it, rotate now to get a fresh one you can save. The old one stops working immediately. | استبدل رقم حسابك المكون من 32 رقماً إذا كان قد تم تسريبه. سيتوقف الرقم القديم عن العمل فوراً. |
| `account.keyActionsHint` | These change your VPN connection only - your 32-digit account number stays the same. | هذه التغييرات لا تُغير سوى اتصال البروكسي الخاص بك - سيبقى رقم حسابك المكون من 32 رقمًا كما هو. |
| `account.section.connection.title` | Your connection | اتصالك |
| `account.section.connection.desc` | Your VPN key, setup help, and connected devices. | مفتاح البروكسي الخاص بك، ومساعدة الإعداد، والأجهزة المتصلة. |
| `account.section.membership.title` | Membership | عضوية |
| `account.section.membership.desc` | Your plan, and how to upgrade or extend it. | خطتك، وكيفية ترقيتها أو توسيعها. |
| `account.section.gifts.title` | Gifts & referrals | الهدايا والإحالات |
| `account.section.gifts.desc` | Redeem a code, buy codes to share, and invite people you trust. | استبدل رمزًا، أو اشترِ رموزًا لتشاركها، وادعُ من تثق بهم. |
| `account.section.codes.title` | Codes & gifts | رموز وهدايا |
| `account.section.codes.desc` | Redeem a membership code, or buy codes to share with others. | استخدم رمز العضوية، أو اشترِ رموزًا لمشاركتها مع الآخرين. |
| `account.section.security.title` | Account & security | الحساب والأمان |
| `account.section.security.desc` | Your support ID and account-number controls. | عناصر التحكم الخاصة بمعرف الدعم ورقم الحساب. |
| `account.deviceRevoke` | Revoke | إلغاء |
| `account.deviceRevokedTitle` | Device revoked | تم إلغاء الجهاز |
| `account.deviceRevokedBody` | The slot is free. That device loses access until it re-imports your subscription. | الفتحة مجانية. سيفقد هذا الجهاز إمكانية الوصول حتى يعيد استيراد اشتراكك. |
| `account.deviceRevokeFailedTitle` | Couldn't revoke the device | تعذر إلغاء الجهاز |

## `hero` — The subscription panel: the key/URL block, traffic + expiry stats, QR, status callouts.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `hero.titleDefault` | Your key | اشتراكك |
| `hero.eyebrowAccessKey` | FreeSocks Access Pass | مفتاح الوصول الخاص بك |
| `hero.urlLabelSubscription` | Your link | رابط الاشتراك |
| `hero.urlLabelAccessKey` | Access key | مفتاح الوصول |
| `hero.tierLine` | Plan {tier} | الفئة {tier} |
| `hero.viaLine` | via {backend} | عبر {backend} |
| `hero.copyUrl` | Copy link | نسخ الرابط |
| `hero.copiedShort` | Copied | تم النسخ |
| `hero.qrShow` | QR | QR |
| `hero.qrHide` | Hide | إخفاء |
| `hero.scanPhone` | Scan with your phone | امسحه بهاتفك |
| `hero.scanOther` | Scan with another device | امسحه بجهاز آخر |
| `hero.importTitle` | Add to your app | أضف إلى تطبيقك |
| `hero.importPlain` | Plain link | رابط عادي |
| `hero.importOpen` | Open in {app} | فتح في {app} |
| `hero.importScan` | Scan to add to {app} | امسح للإضافة إلى {app} |
| `hero.importOpenHint` | Tap to import on this device, or scan the code from your phone. | اضغط للاستيراد على هذا الجهاز، أو امسح الرمز من هاتفك. |
| `hero.scanFallback` | Scan the fallback on another device | امسح الرابط الاحتياطي بجهاز آخر |
| `hero.fallbackLabel` | Fallback link | رابط احتياطي |
| `hero.fallbackHint` | Use this if the main link gets blocked | استخدم هذا إذا حُجب الرابط الرئيسي |
| `hero.fallbackQrAria` | Show fallback link QR code | عرض رمز QR للرابط الاحتياطي |
| `hero.downloaded` | Downloaded {filename} | تم تنزيل {filename} |
| `hero.traffic` | Traffic | البيانات |
| `hero.unlimited` | Unlimited | غير محدود |
| `hero.configBelowNote` | Your full configuration is below - add the servers by hand. For privacy, the auto-updating subscription link isn't shown by default (your app would fetch it through a CDN). | إعدادك الكامل بالأسفل - أضف الخوادم يدويًا. حفاظًا على الخصوصية، لا يُعرض رابط الاشتراك المتجدد تلقائيًا افتراضيًا (لأن تطبيقك سيجلبه عبر شبكة CDN). |
| `hero.showUrlAnyway` | Show the subscription link anyway | أظهر رابط الاشتراك رغم ذلك |
| `hero.urlDangerBody` | This link works in any app, but the app then downloads your configuration through a third-party CDN in plain text - the CDN operator can see your server details and that you use FreeSocks. That is exactly what this focus avoids. Use it only if your app cannot import the configuration below. | يعمل هذا الرابط في أي تطبيق، لكن التطبيق ينزّل إعدادك بعدها عبر شبكة CDN خارجية كنصّ صريح - فيستطيع مشغّل الشبكة رؤية تفاصيل خادمك ومعرفة أنك تستخدم FreeSocks. وهذا بالضبط ما يتجنبه هذا التركيز. استخدمه فقط إذا كان تطبيقك لا يستطيع استيراد الإعداد بالأسفل. |
| `hero.usedSoFar` | {amount} used so far | {amount} مستخدمة حتى الآن |
| `hero.leftThisPeriod` | {amount} left this period. | {amount} متبقية لهذه الفترة. |
| `hero.nearlyOut` | Nearly out, only {amount} left this period. | أوشكت على النفاد - تبقّى {amount} فقط لهذه الفترة. |
| `hero.expires` | Expires | تاريخ الانتهاء |
| `hero.noExpiry` | No expiry | بلا انتهاء |
| `hero.expiresToday` | Expires today | ينتهي اليوم |
| `hero.daysRemaining [countPlural=one]` | 1 day remaining | يوم واحد متبقٍ |
| `hero.daysRemaining [countPlural=other]` | {count} days remaining | {count} أيام متبقية |
| `hero.expiredDaysAgo [countPlural=one]` | Expired 1 day ago | انتهى منذ يوم واحد |
| `hero.expiredDaysAgo [countPlural=other]` | Expired {count} days ago | انتهى منذ {count} أيام |
| `hero.nodeOnline` | Node online | العقدة متصلة |
| `hero.nodeOffline` | Node offline | العقدة غير متصلة |
| `hero.nodeUnknown` | Node status unknown | حالة العقدة غير معروفة |
| `hero.nodeStatusLink` | Network status | حالة الشبكة |
| `hero.nodeOnlineHint` | The server behind your config is up and responding. If you still can't connect, your network or ISP is likely filtering it - try another connection mode or location. | الخادم الذي يقف خلف إعدادك يعمل ويستجيب. إذا كنت ما زلت غير قادر على الاتصال، فمن المرجح أن شبكتك أو مزوّد الإنترنت يحجبه - جرّب وضع اتصال أو موقعًا آخر. |
| `hero.nodeOfflineBody` | The server behind your config is currently offline. This is on our side, not your network. Try again in a few minutes, or create a new config (optionally in a different location). | الخادم الذي يقف خلف إعدادك متوقف حاليًا. المشكلة من جهتنا، وليست من شبكتك. أعد المحاولة بعد بضع دقائق، أو أنشئ إعدادًا جديدًا (ويمكنك اختيار موقع مختلف). |
| `hero.keyLimited` | You've used all your data for this period. It resets automatically, or you can upgrade for more. | لقد استنفدت جميع بياناتك لهذه الفترة. ستتم إعادة ضبطها تلقائيًا، أو يمكنك الترقية للحصول على المزيد. |
| `hero.keyExpired` | This key has expired. Renew your membership or create a new key to reconnect. | انتهت صلاحية هذا المفتاح. جدد عضويتك أو أنشئ مفتاحًا جديدًا لإعادة الاتصال. |
| `hero.keyDisabled` | This key is currently disabled. If your membership lapsed, renew it; otherwise contact support with your support ID. | هذا المفتاح معطل حاليًا. إذا انتهت صلاحية عضويتك، فقم بتجديدها؛ وإلا فاتصل بالدعم الفني باستخدام رقم تعريف الدعم الخاص بك. |
| `hero.resetsInDays [countPlural=one]` | Resets in 1 day | تتم إعادة التعيين في يوم واحد |
| `hero.resetsInDays [countPlural=other]` | Resets in {count} days | يُعاد ضبطه في {count} يومًا |

## `location` — Miscellaneous strings.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `location.pickerLabel` | Server location | موقع الخادم |
| `location.auto` | Automatic (least busy) | تلقائي (الأقل ازدحامًا) |
| `location.offline` | offline | غير متصل |
| `location.pickerHint` | Where your config's server is. Automatic picks the least busy location; pick one yourself if it works better on your network. | أين يقع خادم إعدادك. الخيار التلقائي يختار الموقع الأقل ازدحامًا؛ واختر بنفسك موقعًا يعمل بشكل أفضل على شبكتك. |

## `usage` — The 30-day usage trend under the traffic stats.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `usage.show` | Show usage trend | عرض اتجاه الاستخدام |
| `usage.title` | Usage (last 30 days) | الاستخدام (آخر 30 يومًا) |
| `usage.total` | {amount} used in the last 30 days | {amount} مستخدمة في آخر 30 يومًا |
| `usage.unavailable` | Usage isn't available right now. | الاستخدام غير متاح حاليًا. |
| `usage.none` | No usage recorded yet. | لم يتم تسجيل أي استخدام حتى الآن. |

## `regen` — The regenerate-subscription confirmation dialog.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `regen.title` | Create a new subscription URL? | إعادة إنشاء الاشتراك؟ |
| `regen.body` | Your current subscription URL (ending …{suffix}) will be replaced with a new one. The old URL becomes read-only for 24 hours, then is deleted. | سيُستبدل رابط اشتراكك الحالي (المنتهي بـ …{suffix}) برابط جديد. يصبح الرابط القديم للقراءة فقط لمدة 24 ساعة ثم يُحذف. |
| `regen.point1` | Your current key remains usable for the next 24 hours | يظل مفتاحك الحالي قابلاً للاستخدام خلال الـ 24 ساعة القادمة |
| `regen.point2` | You'll need to re-import the new URL in each of your devices | ستحتاج إلى إعادة استيراد الرابط الجديد على كل جهاز من أجهزتك |
| `regen.pointDevices [countPlural=one]` | You currently have 1 connected device - it will need the new URL | لديك حاليًا جهاز واحد متصل - سيحتاج إلى الرابط الجديد |
| `regen.pointDevices [countPlural=other]` | You currently have {count} connected devices - they will all need the new URL | لديك حاليًا {count} أجهزة متصلة - ستحتاج كلها إلى الرابط الجديد |
| `regen.confirm` | Create new URL | إعادة الإنشاء |
| `regen.working` | Creating… | جارٍ الإنشاء… |

## `switch` — The switch-backend confirmation dialog.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `switch.title` | Switch to {to}? | التبديل إلى {to}؟ |
| `switch.body` | Your current {from} subscription will be replaced with a new {to} one. The old subscription stays usable for 24 hours so you can re-import on every device before it stops working. | سيُستبدل اشتراكك الحالي على {from} باشتراك جديد على {to}. يظل الاشتراك القديم يعمل لمدة 24 ساعة حتى تعيد الاستيراد على كل جهاز قبل توقفه. |
| `switch.point1` | A new subscription URL is issued on the {to} backend | يُصدر رابط اشتراك جديد على خادم {to} |
| `switch.point2` | The current {from} URL keeps working for 24 hours, then is deleted | يظل رابط {from} الحالي يعمل لمدة 24 ساعة ثم يُحذف |
| `switch.point3` | You'll need to re-import the new URL in each VPN client you use | ستحتاج إلى إعادة استيراد الرابط الجديد في كل تطبيق VPN تستخدمه |
| `switch.pointDevices [countPlural=one]` | You currently have 1 connected device - re-import on it | لديك حاليًا جهاز واحد متصل - أعد الاستيراد عليه |
| `switch.pointDevices [countPlural=other]` | You currently have {count} connected devices - re-import on all of them | لديك حاليًا {count} أجهزة متصلة - أعد الاستيراد عليها كلها |
| `switch.confirm` | Switch to {to} | التبديل إلى {to} |
| `switch.working` | Switching… | جارٍ التبديل… |

## `get` — The /get-account sign-up flow: create account (step 1) and create subscription (step 2).

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `get.badge` | Free account | حساب مجاني |
| `get.title` | Get a FreeSocks account | احصل على حساب FreeSocks |
| `get.progressAria` | Sign-up progress | تقدّم إنشاء الحساب |
| `get.progress.step1` | Create account | إنشاء الحساب |
| `get.progress.step2` | Save your number | حفظ رقمك |
| `get.progress.step3` | Get connected | الاتصال |
| `get.step1Title` | Create your account | أنشئ حسابك |
| `get.chooseBackend` | Choose a connection type | اختر نوع الخادم |
| `get.backendAria` | Connection type | نوع الخادم |
| `get.backendMultiProtocol` | VLESS (Xray) | VLESS (Xray) |
| `get.backendShadowsocks` | Shadowsocks via Outline | Shadowsocks عبر Outline |
| `get.createAccount` | Create my account | إنشاء حسابي |
| `get.freeAccountNote` | Free accounts are valid for {days} days and limited to {devices}. No email or password. | الحسابات المجانية صالحة لمدة {days} يومًا ومحدودة بـ {devices}. بلا بريد إلكتروني أو كلمة مرور. |
| `get.freeAccountNoteNoDevices` | Free accounts are valid for {days} days. No email or password. | الحسابات المجانية صالحة لمدة {days} يومًا. بلا بريد إلكتروني أو كلمة مرور. |
| `get.step3Title` | Get your key | احصل على مفتاحك |
| `get.step3Intro` | Your key is what connects your app to the VPN. Create it, then add it to your app. | مفتاحك هو ما يربط تطبيقك بشبكة VPN. أنشئه، ثم أضفه إلى تطبيقك. |
| `get.manageHintPrefix` | Manage your key anytime from | أدر هذا الاشتراك في أي وقت من |
| `get.manageLinkLabel` | your account | حسابك |
| `get.subErrorSafePrefix` | Your account is safe. You can create your key later from | حسابك آمن. يمكنك إنشاء الاشتراك لاحقًا من |
| `get.subErrorSafeSuffix` | once a server is available. | عندما يتوفر خادم. |
| `get.createSubToastTitle` | Your key is ready | تم إنشاء الاشتراك |
| `get.createSubToastBody` | Copy the link into your VPN app, or scan the QR code. | انسخ الرابط في تطبيق VPN لديك، أو امسح رمز QR. |
| `get.createAccountFailedTitle` | Could not create account | تعذّر إنشاء الحساب |
| `get.createSubFailedTitle` | Could not create your key | تعذّر إنشاء الاشتراك |
| `get.haveAccountPrefix` | Already have an account? | لديك حساب بالفعل؟ |
| `get.lostNumberHint` | Lost your account number before saving it? You can switch to a new one - | فقدت رقم حسابك قبل حفظه؟ يمكنك التبديل إلى رقم جديد - |
| `get.lostNumberLinkLabel` | change it from your account page | غيّره من صفحة حسابك |
| `get.redeemPrompt` | Have a gift code? Redeem it before creating your key. | لديك رمز هدية؟ استخدمه قبل إنشاء مفتاحك. |
| `get.redeemTitle` | Got a gift code? | هل لديك رمز هدية؟ |
| `get.redeemBody` | Redeem it now to upgrade your new account instantly. | استردها الآن لترقية حسابك الجديد فوراً. |

## `tiers` — The plan-comparison cards (Free vs Membership limits).

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `tiers.title` | Tiers | الفئات |
| `tiers.subtitle` | What each tier includes. | ما تتضمنه كل فئة. |
| `tiers.yourTier` | Your plan | فئتك |
| `tiers.gbPerMonth` | {gb} GB / month | {gb} غيغابايت / شهر |
| `tiers.mirrors` | Mirror URLs | روابط بديلة |
| `tiers.upgradeCta` | Upgrade | ترقية |

## `impact` — The donation-impact panel: bandwidth donated, free users helped, charts.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `impact.title` | Donations support Unredacted | التبرعات تدعم Unredacted |
| `impact.body` | Unredacted is a US 501(c)(3) nonprofit. FreeSocks is one of the projects it runs. Donations fund the work. See what that work is on the Unredacted site. | Unredacted منظمة أمريكية غير ربحية 501(c)(3). وFreeSocks أحد مشاريعها. التبرعات تموّل هذا العمل. اطّلع على تفاصيله في موقع Unredacted. |
| `impact.collectiveTitle` | Donation impact | أثر التبرعات |
| `impact.collectiveBody` | Donations made through FreeSocks raise every free user's monthly bandwidth for the month they're given. This is what the community's donations are doing right now. | التبرعات عبر FreeSocks ترفع النطاق الترددي الشهري لكل مستخدم مجاني في الشهر الذي تُقدَّم فيه. هذا ما تحققه تبرعات المجتمع الآن. |
| `impact.bonusThisMonth` | GB added this month | غيغابايت مضافة هذا الشهر |
| `impact.bonusThisMonthDetail` | on top of every free account's monthly allowance | فوق الحصة الشهرية لكل حساب مجاني |
| `impact.usersHelped` | free accounts reached | حسابات مجانية مستفيدة |
| `impact.usersHelpedDetail` | active free users whose allowance the bonus raises | مستخدمو الباقة المجانية النشطون الذين ترفع الإضافة حصتهم |
| `impact.historyTitle` | Bandwidth added per month | النطاق الترددي المُضاف شهريًا |
| `impact.chartAria` | Bandwidth added to every free user by donations, month by month over the last {n} months | النطاق الترددي الذي أضافته التبرعات لكل مستخدم مجاني، شهرًا بشهر خلال آخر {n} أشهر |
| `impact.yourContribution` | Your contribution | مساهمتك |
| `impact.yourGiven` | You've given {amount} | لقد تبرعت بـ {amount} |
| `impact.yourGb` | That's about {gb} GB of extra bandwidth for free users | أي نحو {gb} غيغابايت من النطاق الترددي الإضافي للمستخدمين المجانيين |
| `impact.yourCount [countPlural=one]` | across 1 donation | عبر تبرع واحد |
| `impact.yourCount [countPlural=other]` | across {count} donations | عبر {count} تبرعات |
| `impact.empty` | No donations yet this month - the first one starts the counter. | لا تبرعات بعد هذا الشهر - أول تبرع يشغّل العدّاد. |
| `impact.externalNote` | This counter tracks donations made through FreeSocks only. Gifts made directly at unredacted.org/donate support Unredacted's wider work, but don't add bandwidth here. | يتتبع هذا العدّاد التبرعات المقدَّمة عبر FreeSocks فقط. التبرعات المباشرة على unredacted.org/donate تدعم عمل Unredacted الأوسع، لكنها لا تضيف نطاقًا تردديًا هنا. |
| `impact.aboutUnredacted` | About Unredacted | عن Unredacted |

## `donate` — The donation card + amount picker (donations add bandwidth for all free users).

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `donate.addTitle` | Add a donation | أضف تبرعًا |
| `donate.addSubtitle` | Chip in to help keep FreeSocks free for everyone. | ساهم للمساعدة في إبقاء FreeSocks مجانيًا للجميع. |
| `donate.standaloneTitle` | Donate to FreeSocks | تبرّع لـ FreeSocks |
| `donate.standaloneSubtitle` | FreeSocks is free for everyone, funded by donations. Give any amount to help keep it running - a donation also raises this month's bandwidth for every free user. | FreeSocks مجاني للجميع وتموله التبرعات. تبرّع بأي مبلغ للمساعدة في استمراره - كما يرفع التبرع النطاق الترددي لهذا الشهر لكل مستخدم مجاني. |
| `donate.amountLabel` | Amount | المبلغ |
| `donate.none` | No thanks | لا شكرًا |
| `donate.custom` | Custom | مخصص |
| `donate.customPlaceholder` | Other amount | مبلغ آخر |
| `donate.impact` | Adds about {gb} GB to every free user this month | يضيف نحو {gb} غيغابايت لكل مستخدم مجاني هذا الشهر |
| `donate.bonusActive` | Donations this month have added {gb} GB to every free user's monthly allowance. | أضافت تبرعات هذا الشهر {gb} غيغابايت إلى الحصة الشهرية لكل مستخدم مجاني. |
| `donate.minNote` | Minimum {amount} | الحد الأدنى {amount} |
| `donate.give` | Donate {amount} | تبرّع بـ {amount} |
| `donate.giving` | Starting… | جارٍ البدء… |
| `donate.startFailed` | Couldn't start the donation | تعذّر بدء التبرع |
| `donate.badge` | Donor | متبرع |
| `donate.badgeTooltip` | Thank you for supporting FreeSocks | شكرًا لدعمك FreeSocks |
| `donate.thanksTitle` | You're a FreeSocks donor | أنت الآن من متبرعي FreeSocks |
| `donate.thanksBody` | Thank you - your support helps keep FreeSocks free for everyone. | شكرًا لك - دعمك يساعد في إبقاء FreeSocks مجانيًا للجميع. |

## `referral` — Miscellaneous strings.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `referral.fieldLabel` | Referral code (optional) | رمز الإحالة (اختياري) |
| `referral.fieldHint` | Have a code from a friend? You each get bonus membership days when you upgrade. | لديك رمز من صديق؟ يحصل كلٌّ منكما على أيام عضوية إضافية عند الترقية. |
| `referral.fieldPlaceholder` | FSR-XXXX-XXXX | FSR-XXXX-XXXX |
| `referral.applied` | Referral applied — bonus days are yours when you upgrade. | تم تطبيق الإحالة - أيامك الإضافية بانتظارك عند الترقية. |
| `referral.cardTitle` | Referrals | الإحالات |
| `referral.cardBody` | Share your link. When someone signs up with it and becomes a member, you each get bonus days — theirs right away, yours after {vestingDays} days. | شارك رابطك. عندما يسجّل شخص عبره ويصبح عضوًا، يحصل كلٌّ منكما على أيام إضافية - أيامه فورًا، وأيامك بعد {vestingDays} يومًا. |
| `referral.copyLink` | Copy invite link | نسخ رابط الدعوة |
| `referral.codeLabel` | Your code | رمزك |
| `referral.statsInvited` | Signed up | سجّلوا |
| `referral.statsConverted` | Became members | أصبحوا أعضاء |
| `referral.statsPending` | Not yet members | ليسوا أعضاء بعد |
| `referral.statsDays` | Bonus days earned | الأيام الإضافية المكتسبة |

## `qr` — QR-code helper labels.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `qr.ariaLabel` | QR code for the subscription URL | رمز QR لرابط الاشتراك |
| `qr.failed` | Couldn't generate the QR code. | تعذر إنشاء رمز الاستجابة السريعة (QR code). |

## `app` — App-level chrome (skip link, page titles).

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `app.skipToContent` | Skip to content | تخطَّ إلى المحتوى |
| `app.notFound` | Not found | غير موجود |
| `app.goHome` | Go home | العودة إلى الرئيسية |
| `app.adminLoadFailedTitle` | Couldn't load the admin console | تعذر تحميل لوحة تحكم المسؤول |
| `app.adminLoadFailedBody` | The network request for this section failed. Reload to retry. | فشل طلب الشبكة لهذا القسم. أعد تحميل الصفحة للمحاولة مرة أخرى. |

## `footer` — The site footer (nonprofit line, terms/privacy links).

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `footer.operatedPrefix` | Operated by | يديره |
| `footer.operatedSuffix` | , a US 501(c)(3) nonprofit | ، منظمة أمريكية غير ربحية 501(c)(3) |
| `footer.viewSource` | View source | عرض المصدر |
| `footer.terms` | Terms of Service | شروط الخدمة |
| `footer.privacy` | Privacy Policy | سياسة الخصوصية |
| `footer.transparency` | Transparency Report | تقرير الشفافية |
| `footer.socialX` | FreeSocks on X | FreeSocks على X |
| `footer.socialMastodon` | FreeSocks on Mastodon | FreeSocks على Mastodon |
| `footer.socialBluesky` | FreeSocks on Bluesky | FreeSocks على Bluesky |
| `footer.support` | Support | الدعم |

## `renew` — Expiring/expired membership callouts and renewal prompts.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `renew.expiringTitle` | Your membership is expiring soon | عضويتك على وشك الانتهاء |
| `renew.expiredTitle` | Your membership has expired | انتهت عضويتك |
| `renew.body` | FreeSocks is community-funded - donations keep it running. To renew your membership, donate or contact us for a membership code. | FreeSocks مموّل من المجتمع - التبرعات تبقيه يعمل. لتجديد عضويتك، تبرّع أو تواصل معنا للحصول على رمز عضوية. |
| `renew.donate` | Donate | تبرّع |
| `renew.contact` | Contact us | تواصل معنا |
| `renew.lapsedBody` | You're on the free tier now. Renew below to restore your membership. | أنت الآن على الباقة المجانية. جدِّد من الأسفل لاستعادة عضويتك. |
| `renew.renewCta` | Renew membership | تجديد العضوية |

## `upgrade` — The paid-membership purchase panel (payment method, duration, totals).

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `upgrade.title` | Upgrade to a FreeSocks membership | الترقية إلى عضوية FreeSocks |
| `upgrade.extendTitle` | Extend your membership | مدّد عضويتك |
| `upgrade.subtitle` | Unlimited bandwidth and devices. Choose a length and how to pay. | نطاق ترددي وأجهزة غير محدودة. اختر المدة وطريقة الدفع. |
| `upgrade.subtitleNoDevices` | Unlimited bandwidth. Choose a length and how to pay. | نطاق ترددي غير محدود. اختر المدة وطريقة الدفع. |
| `upgrade.compareBandwidth` | Bandwidth per month | النطاق الترددي شهريًا |
| `upgrade.compareDevices` | Devices | الأجهزة |
| `upgrade.durationLabel` | Membership length | مدة العضوية |
| `upgrade.cryptoMinNote` | Crypto payments start at {months} months - shorter terms fall below the network minimum. Pick another method for shorter terms. | تبدأ مدفوعات العملات المشفّرة من {months} أشهر - المدد الأقصر أقل من الحد الأدنى للشبكة. اختر طريقة أخرى للمدد الأقصر. |
| `upgrade.months [countPlural=one]` | 1 month | 1 شهر |
| `upgrade.months [countPlural=other]` | {count} months | {count} شهر |
| `upgrade.perMonth` | {price}/mo | {price}/شهر |
| `upgrade.fromPerMonth` | From {price}/month | ابتداءً من {price}/شهر |
| `upgrade.benefitsShort` | Unlimited bandwidth and devices | نطاق ترددي وأجهزة غير محدودة |
| `upgrade.benefitsShortNoDevices` | Unlimited bandwidth | نطاق ترددي غير محدود |
| `upgrade.save` | save {pct}% | وفّر {pct}٪ |
| `upgrade.methodLabel` | Payment method | طريقة الدفع |
| `upgrade.payNowpayments` | Cryptocurrency | العملات المشفرة |
| `upgrade.payNowpaymentsHint` | Bitcoin, Monero, Zcash & more | البيتكوين ومونيرو والمزيد |
| `upgrade.payNowpaymentsBadge` | Private | خاص |
| `upgrade.cryptoPrivacyNote` | No account, email, or card needed - pay privately. Monero and Zcash offer the most privacy. | لا حاجة لحساب أو بريد إلكتروني أو بطاقة ائتمان - ادفع بسرية تامة. يوفر كل من مونيرو وزيكاش أعلى مستويات الخصوصية. |
| `upgrade.payBtcpay` | Bitcoin | بيتكوين |
| `upgrade.payBtcpayHint` | On-chain or Lightning | على السلسلة أو لايتنينغ |
| `upgrade.payBtcpayBadge` | No intermediary | بدون وسيط |
| `upgrade.payStripe` | Card | بطاقة |
| `upgrade.payStripeHint` | Credit or debit card | بطاقة ائتمان أو خصم |
| `upgrade.payPaypal` | PayPal | باي بال |
| `upgrade.payPaypalHint` | PayPal balance or card | رصيد باي بال أو بطاقة |
| `upgrade.total` | Total {price} | الإجمالي {price} |
| `upgrade.continue` | Continue to payment | المتابعة إلى الدفع |
| `upgrade.starting` | Starting checkout… | جارٍ بدء الدفع… |
| `upgrade.startFailed` | Could not start checkout | تعذّر بدء الدفع |
| `upgrade.noStoreNote` | We never see your card or wallet, and store no payment details. | لا نخزّن أبدًا بريدك الإلكتروني أو تفاصيل الدفع. |
| `upgrade.confirmingTitle` | Confirming your payment… | جارٍ تأكيد دفعتك… |
| `upgrade.confirmingBody` | Crypto can take a few minutes to confirm. You can leave this page - your membership activates automatically. | قد يستغرق تأكيد العملات المشفرة بضع دقائق. يمكنك مغادرة هذه الصفحة - ستُفعّل عضويتك تلقائيًا. |
| `upgrade.paidTitle` | Membership active | العضوية مفعّلة |
| `upgrade.paidBody` | Thank you! Your membership is now active. | شكرًا لك! عضويتك مفعّلة الآن. |
| `upgrade.failedTitle` | Payment not completed | لم يكتمل الدفع |
| `upgrade.failedBody` | Your payment did not go through, or the checkout expired. You can try again. | لم تتم عملية الدفع، أو انتهت صلاحية الجلسة. يمكنك المحاولة مرة أخرى. |

## `gift` — Gift membership codes: buying, revealing (show-once), and redeeming.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `gift.title` | Buy codes to share | اشترِ رموزًا للمشاركة |
| `gift.subtitle` | Purchase membership codes to give to friends or family. Each works on any account and never touches yours. | اشترِ رموز عضوية لتوزيعها على الأصدقاء أو العائلة. كل رمز يعمل على أي حساب ولا يؤثر على حسابك الخاص. |
| `gift.quantityLabel` | How many | كم عدد |
| `gift.buy` | Buy codes | رموز الشراء |
| `gift.starting` | Starting checkout… | بدء عملية الدفع… |
| `gift.startFailed` | Could not start checkout | تعذر بدء عملية الدفع |
| `gift.boughtTitle` | Codes you've bought | الرموز التي اشتريتها |
| `gift.boughtEmpty` | You haven't bought any codes yet. | لم تقم بشراء أي رموز حتى الآن. |
| `gift.statusAvailable` | Available | متاح |
| `gift.statusRedeemed` | Redeemed | تم الاسترداد |
| `gift.statusRevoked` | Revoked | ملغى |
| `gift.redeemedOn` | Redeemed {date} | تم الاسترداد {date} |
| `gift.copyAll` | Copy all | انسخ الكل |
| `gift.reveal.title` | Save these codes now | احفظ هذه الرموز الآن |
| `gift.reveal.body` | Copy and share each code. For security we show them only once - afterwards you will see only a prefix. | انسخ كل رمز وشاركه. لأسباب أمنية، نعرضه مرة واحدة فقط - بعد ذلك سترى بادئة فقط. |
| `gift.reveal.ack` | I have saved these codes | لقد حفظت هذه الرموز |
| `gift.reveal.saved` | I've saved them | لقد احتفظت بها |
| `gift.reveal.leaveWarning` | Your codes are still on screen. If you leave now without saving them, you will not be able to see them again. | لا تزال رموزك معروضة على الشاشة. إذا غادرت الآن دون حفظها، فلن تتمكن من رؤيتها مرة أخرى. |

## `error` — API error messages shown to members.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `error.offline` | You appear to be offline. Check your connection and try again. | يبدو أنك غير متصل. تحقق من اتصالك وأعد المحاولة. |
| `error.rateLimited` | Too many attempts. Please wait a minute and try again. | محاولات كثيرة جدًا. انتظر دقيقة وأعد المحاولة. |
| `error.backendUnavailable` | No VPN server is available right now. Your account is safe - try creating your key again in a few minutes. | لا يوجد خادم وكيل متاح حاليًا. حسابك آمن - حاول إنشاء مفتاحك مرة أخرى بعد دقائق. |
| `error.generic` | Something went wrong. Please try again. | حدث خطأ ما. يرجى المحاولة مرة أخرى. |
| `error.captchaFailed` | The human check failed. Please complete it and try again. | فشل التحقق البشري. أكمله وأعد المحاولة. |
| `error.captchaUnconfigured` | The service is temporarily unavailable. Please try again in a few minutes. | الخدمة غير متاحة مؤقتًا. يرجى المحاولة مرة أخرى بعد بضع دقائق. |
| `error.renderTitle` | Something went wrong | حدث خطأ ما |
| `error.renderBody` | The page failed to render. This is a bug in the app, and refreshing usually fixes it. If it keeps happening, please report it. | لم يتم تحميل الصفحة. هذا خلل في التطبيق، وعادةً ما يُحلّ بتحديث الصفحة. إذا استمرّ حدوث ذلك، يُرجى الإبلاغ عنه. |
| `error.reloadPage` | Reload page | إعادة تحميل الصفحة |
| `error.tryAgain` | Try again | حاول ثانية |
| `error.sessionExpired` | Your session has ended. Please sign in again. | انتهت جلستك. يرجى تسجيل الدخول مرة أخرى. |
| `error.invalidAccountId` | That account number wasn't recognized. Check it and try again. | لم يتم التعرف على رقم الحساب. يرجى التحقق منه والمحاولة مرة أخرى. |
| `error.codeInvalid` | That code can't be redeemed. Check it for typos and try again. | لا يمكن استخدام هذا الرمز. تحقق من وجود أخطاء إملائية وحاول مرة أخرى. |
| `error.changeInProgress` | Another change is already in progress - try again in a moment. | هناك تغيير آخر جارٍ بالفعل - حاول مرة أخرى بعد قليل. |
| `error.backendDisabled` | That option is currently unavailable. | هذا الخيار غير متاح حاليًا. |
| `error.noPeerTier` | Switching isn't available for your plan yet. | لا تتوفر خدمة التبديل لخطة اشتراكك حتى الآن. |
| `error.deviceNotFound` | That device is no longer on your account. | لم يعد هذا الجهاز مرتبطًا بحسابك. |
| `error.deviceUnsupported` | Your current server type doesn't support removing individual devices. | نوع الخادم الحالي لديك لا يدعم إزالة الأجهزة الفردية. |
| `error.billing` | The payment service couldn't process this. Please try again later. | لم تتمكن خدمة الدفع من معالجة هذه العملية. يرجى المحاولة مرة أخرى لاحقاً. |
| `error.serverError` | The server had a problem handling this. Please try again in a few minutes. | واجه الخادم مشكلة في معالجة هذا الطلب. يرجى المحاولة مرة أخرى بعد بضع دقائق. |
| `error.modeUnavailable` | Your current connection mode is no longer available. Switch to another mode first, then try again. | وضع الاتصال الحالي لم يعد متاحًا. بدّل إلى وضع آخر أولًا، ثم أعد المحاولة. |

## `setup` — The "set up your app" section: recommended VPN clients per platform, install steps.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `setup.title` | Set up your VPN app | إعداد تطبيق الوكيل |
| `setup.install` | Install | تثبيت |
| `setup.noApps` | No recommended apps for this platform yet - use any compatible client and add your subscription manually. | لا توجد تطبيقات موصى بها لهذه المنصة بعد - استخدم أي عميل متوافق وأضف اشتراكك يدويًا. |
| `setup.openSource` | Open source | مفتوح المصدر |
| `setup.recommended` | Recommended | موصى به |
| `setup.proprietary` | Proprietary | مغلق المصدر |
| `setup.easeEasy` | Easy to use | سهل الاستخدام |
| `setup.easeAdvanced` | Advanced | متقدم |
| `setup.viewSource` | Source | المصدر |
| `setup.intro` | Copy your subscription link above, then add it to a compatible app: | انسخ رابط الاشتراك بالأعلى، ثم أضفه إلى تطبيق متوافق: |
| `setup.android` | Android | أندرويد |
| `setup.ios` | iPhone / iPad | آيفون / آيباد |
| `setup.windows` | Windows | ويندوز |
| `setup.desktop` | macOS / Linux | ماك / لينكس |
| `setup.step.install` | Install the app | ثبّت التطبيق |
| `setup.step.import` | Open it, add a subscription / profile, and paste your link | افتحه، أضف اشتراكًا/ملفًا شخصيًا، والصق رابطك |
| `setup.step.importConfig` | Open it, choose to add servers manually, and enter the configuration shown below | افتحه، واختر إضافة الخوادم يدويًا، وأدخل التكوين الموضح أدناه. |
| `setup.step.connect` | Select a server and connect | اختر خادمًا واتصل |
| `setup.noDeviceLimit` | no device limit | لا يوجد حد للأجهزة |
| `setup.hwidNote` | On a device-limited plan, turn on "device identification" (HWID) in the app's settings so your device is recognized. | في حال الاشتراك في باقة محدودة الأجهزة، قم بتشغيل "تحديد الجهاز" (HWID) في إعدادات التطبيق حتى يتم التعرف على جهازك. |
| `setup.deviceCompatibleTitle` | Works with your device limit | متوافق مع حد الأجهزة في خطتك |
| `setup.deviceIncompatibleTitle` | Not recommended for your plan | غير موصى به لخطتك |
| `setup.deviceIncompatibleNote` | These apps don't identify your device, so each launch can use up a device slot - or fail to connect on a device-limited plan. Prefer an app above. | هذه التطبيقات لا تُعرّف جهازك، لذا قد يستهلك كل تشغيل خانة جهاز - أو يفشل الاتصال في باقة محدودة الأجهزة. فضّل تطبيقًا من الأعلى. |
| `setup.linkKind.play` | Google Play | Google Play |
| `setup.linkKind.appStore` | App Store | App Store |
| `setup.linkKind.github` | GitHub | GitHub |
| `setup.linkKind.apk` | APK | APK |
| `setup.linkKind.website` | Website | الموقع الإلكتروني |
| `setup.clientDesc.hiddify` | The easiest all-round choice: one-tap import, a clean interface, and builds for every platform. | الخيار الأسهل عمومًا: استيراد بلمسة واحدة، وواجهة نظيفة، وإصدارات لكل منصة. |
| `setup.clientDesc.karing` | Feature-rich and honors your plan's device limit. Slightly busier than Hiddify, but works well everywhere. | غني بالميزات ويحترم حد الأجهزة في خطتك. أكثر ازدحامًا قليلًا من Hiddify، لكنه يعمل جيدًا في كل مكان. |
| `setup.clientDesc.anywhere` | A polished, easy client for Apple devices only: iPhone, iPad, Apple TV, and Mac. No Android, Windows, or Linux version. | عميل أنيق وسهل لأجهزة Apple فقط: آيفون وآيباد وApple TV وماك. لا توجد نسخة لأندرويد أو ويندوز أو لينكس. |
| `setup.clientDesc.singBox` | The reference app for the sing-box core. Powerful but minimal, so it's best if you are comfortable with technical settings. | التطبيق المرجعي لنواة sing-box. قوي لكنه بسيط، لذا يناسبك إن كنت مرتاحًا للإعدادات التقنية. |
| `setup.clientDesc.v2rayng` | A long-standing, lightweight Android client with one-tap import. More utilitarian than Hiddify, but dependable. | عميل أندرويد عريق وخفيف مع استيراد بلمسة واحدة. أكثر عمليةً وأقل أناقة من Hiddify، لكنه يعتمد عليه. |
| `setup.clientDesc.v2rayn` | A powerful desktop app for advanced users. Import is manual, and links using encryption "none" can need a manual tweak. Prefer Hiddify if that sounds fiddly. | تطبيق سطح مكتب قوي للمستخدمين المتقدمين. الاستيراد يدوي، والروابط التي تستخدم تشفير "none" قد تحتاج إلى تعديل يدوي. فضّل Hiddify إذا بدا ذلك معقدًا. |
| `setup.clientDesc.clash` | Clash Verge, a popular desktop app with strong routing rules. Some versions reject VLESS subscription links; if yours won't import, use Hiddify or v2rayN instead. | Clash Verge تطبيق سطح مكتب شائع بقواعد توجيه قوية. بعض الإصدارات ترفض روابط اشتراك VLESS؛ إذا لم يستورد رابطك، استخدم Hiddify أو v2rayN بدلًا منه. |
| `setup.clientDesc.flclash` | A clean, cross-platform Clash-family app. Import by pasting your subscription link (no one-tap import). | تطبيق نظيف من عائلة Clash يعمل عبر المنصات. الاستيراد بلصق رابط اشتراكك (لا يوجد استيراد بلمسة واحدة). |
| `setup.clientDesc.mihomoParty` | A friendly desktop app for the Clash (mihomo) core. Paste your subscription link to import. | تطبيق سطح مكتب ودود لنواة Clash (mihomo). الصق رابط اشتراكك للاستيراد. |
| `setup.clientDesc.throne` | An advanced desktop client that honors your plan's device limit, with solid Linux support. Expect manual setup. | عميل سطح مكتب متقدم يحترم حد الأجهزة في خطتك، مع دعم جيد للينكس. توقّع إعدادًا يدويًا. |
| `setup.clientDesc.shadowrocket` | A paid, closed-source iOS app that is popular and reliable. Worth using if you already own it; the open-source apps above do the same job for free. | تطبيق iOS مدفوع ومغلق المصدر، شائع وموثوق. يستحق الاستخدام إن كنت تملكه أصلًا؛ وتطبيقات المصدر المفتوح بالأعلى تؤدي المهمة نفسها مجانًا. |
| `setup.clientDesc.outline` | The simplest experience there is: paste your access key and connect. Only works with Outline (Shadowsocks) access keys. | أبسط تجربة ممكنة: الصق مفتاح الوصول واتصل. يعمل فقط مع مفاتيح وصول Outline (Shadowsocks). |

## `mirror` — The "trouble connecting? try a mirror" fallback flow.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `mirror.disclosure` | Trouble connecting? | تواجه مشكلة في الاتصال؟ |
| `mirror.explainer` | If your normal subscription link won't connect where you are, add a mirror link below. It serves the same key from a different host that may not be blocked. | إذا كان رابط الاشتراك العادي لا يتصل في مكانك، أضِف رابط مرآة أدناه. يقدّم المفتاح نفسه من مضيف آخر قد لا يكون محجوبًا. |
| `mirror.addedLabel` | Your mirror links | روابط المرآة الخاصة بك |
| `mirror.addToAppHint` | Add each one as an extra subscription in your app, then try connecting. | أضِف كل رابط كاشتراك إضافي في تطبيقك ثم حاول الاتصال. |
| `mirror.regionLabel` | Your region | منطقتك |
| `mirror.regionGlobal` | Global (any region) | عالمي (أي منطقة) |
| `mirror.regionNotStored` | Used only to pick a nearby mirror - it isn't stored. | يُستخدم فقط لاختيار مرآة قريبة - ولا يتم تخزينه. |
| `mirror.getButton` | Get a mirror link | احصل على رابط مرآة |
| `mirror.tryAnother` | Try another mirror | جرّب مرآة أخرى |
| `mirror.working` | Working… | جارٍ التنفيذ… |
| `mirror.capped` | You've added the maximum number of mirrors. | لقد أضفت الحد الأقصى من المرايا. |
| `mirror.exhausted` | No more mirrors are available for your region right now. | لا تتوفر مرايا أخرى لمنطقتك حاليًا. |
| `mirror.noSubscription` | Create your key first, then you can add a mirror. | أنشئ مفتاحك أولًا، ثم يمكنك إضافة مرآة. |
| `mirror.removeAll` | Remove all mirrors | إزالة كل المرايا |
| `mirror.errorToast` | Couldn't add a mirror | تعذّر إضافة مرآة |
| `mirror.removedToast` | Mirrors removed | تمت إزالة المرايا |

## `rawconfig` — The raw-configuration viewer (privacy mode delivers config text, not a URL).

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `rawconfig.disclosure` | Show raw configuration | إظهار الإعداد الخام |
| `rawconfig.title` | Your configuration | إعدادك |
| `rawconfig.explainer` | Your full VPN configuration, fetched over an encrypted channel so it never crosses a CDN in plain text. Copy it into your app by hand instead of using a subscription link. | إعداد الوكيل الكامل الخاص بك، يُجلب عبر قناة مشفّرة بحيث لا يمر أبدًا عبر شبكة CDN كنص عادي. انسخه يدويًا إلى تطبيقك بدلًا من استخدام رابط الاشتراك. |
| `rawconfig.addHint` | Paste these server entries into your VPN app manually. | الصق إدخالات الخوادم هذه في تطبيق الوكيل يدويًا. |

## `delivery` — The connection-mode picker: "Beat censorship" (for censored countries) vs "Maximum privacy" (for open internet), plus the switch-confirmation dialog.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `delivery.title` | What matters most to you? | ما الأهم بالنسبة لك؟ |
| `delivery.subtitle` | Pick a focus. It's saved on this device only, and you can change it anytime. | اختر أولوية - تُحفظ على هذا الجهاز فقط، ويمكنك تغييرها في أي وقت. |
| `delivery.subtitleServer` | Pick a focus. Changing it moves your existing key to the matching servers - your subscription URL stays the same. | اختر مجال تركيز. سيؤدي تغييره إلى إعادة إصدار مفتاحك للخوادم المطابقة؛ وسيظل مفتاحك الحالي يعمل لمدة 24 ساعة. |
| `delivery.subtitleSignup` | Pick a focus. It's saved to your account, and your first key uses it - you can change it anytime. | اختر مجال تركيز. يُحفظ في حسابك، ويستخدمه مفتاحك الأول - ويمكنك تغييره في أي وقت. |
| `delivery.evadeTitle` | Internet Freedom Mode | وضع حرية الإنترنت |
| `delivery.evadeAudience` | For censored countries | للبلدان الخاضعة للرقابة |
| `delivery.evadeBody` | Pick this if websites, apps, or VPNs are blocked where you are. Built to keep working under censorship, with backup links that are harder to block. | اختر هذا إذا كانت المواقع أو التطبيقات أو خدمات VPN محجوبة في مكانك. مصمم ليظل يعمل تحت الرقابة، مع روابط احتياطية يصعب حجبها. |
| `delivery.privacyTitle` | Privacy Mode | وضع الخصوصية |
| `delivery.privacyAudience` | For open internet | للإنترنت المفتوح |
| `delivery.privacyBody` | Pick this if the internet is mostly open where you are. The strongest confidentiality - your configuration stays off third-party servers - but it is easier for censors to block. | اختر هذا إذا كان الإنترنت مفتوحًا في الغالب في مكانك. أقوى سرّية - إذ يبقى إعدادك بعيدًا عن خوادم الأطراف الثالثة - لكنه أسهل على الرقيب في الحجب. |
| `delivery.recommended` | Recommended | موصى به |
| `delivery.unavailable` | Not available yet | غير متوفر بعد |
| `delivery.confirmTitle` | Switch to "{label}"? | التبديل إلى " {label} "? |
| `delivery.confirmBody` | This moves your existing key to the {label} servers, keeping the same subscription URL. Your apps keep working and pick up the new servers on their next refresh. | يُعيد هذا إصدار مفتاح الوكيل الخاص بك لخوادم {label} . سيظل مفتاحك الحالي فعالاً لمدة 24 ساعة، لذا يمكنك إعادة استيراده على كل جهاز أولاً. |
| `delivery.confirmPoint1` | Your key moves to the {label} servers - same subscription URL, nothing to re-import | تم إصدار عنوان URL جديد للاشتراك لخوادم {label} |
| `delivery.confirmPoint2` | Takes effect within a minute - reconnect in your app if it doesn't refresh on its own | يستمر مفتاحك الحالي بالعمل لمدة 24 ساعة، ثم يتم حذفه. |
| `delivery.confirmPoint3` | Using the raw config? Copy the new one after switching | ستحتاج إلى إعادة استيراد عنوان URL الجديد في كل عميل VPN تستخدمه |
| `delivery.confirmPointDevices [countPlural=one]` | Your 1 connected device will reconnect to the new servers | لديك حاليًا جهاز واحد متصل؛ أعد الاستيراد عليه |
| `delivery.confirmPointDevices [countPlural=other]` | Your {count} connected devices will reconnect to the new servers | لديك حاليًا {count} جهازًا متصلًا؛ أعد الاستيراد على جميعها |
| `delivery.confirm` | Switch focus | تغيير التركيز |
| `delivery.working` | Switching… | جارٍ التبديل… |
| `delivery.switchSuccessTitle` | Switched to "{label}" | تم التبديل إلى " {label} " |
| `delivery.switchSuccessBodyGrace` | Re-import the new subscription URL on each device. Your old key works for 24 more hours. | أعد استيراد رابط الاشتراك الجديد على كل جهاز. سيظل مفتاحك القديم صالحًا لمدة 24 ساعة إضافية. |
| `delivery.switchSuccessBody` | Same subscription URL - your apps will pick up the new servers on their next refresh. | أعد استيراد رابط الاشتراك الجديد على كل جهاز. |
| `delivery.switchFailedTitle` | Could not switch focus | تعذر تغيير التركيز |

## `home` — The public landing page: hero, feature sections, impact section, FAQ intros.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `home.trust.nonprofit` | Run by a US 501(c)(3) nonprofit | تديره منظمة أمريكية غير ربحية 501(c)(3) |
| `home.trust.openSource` | Open source | مفتوح المصدر |
| `home.trust.noLogs` | No traffic logs | لا سجلات لحركة المرور |
| `home.network.title` | Network status | حالة الشبكة |
| `home.network.offline` | offline | غير متصل |
| `home.network.srOnline` | online | متصل |
| `home.network.srOffline` | offline | غير متصل |
| `home.network.note` | Checked every 10 minutes | يُفحص كل 10 دقائق |
| `home.network.link` | Live status | الحالة المباشرة |
| `home.quicknav.label` | Jump to a section | انتقل إلى قسم |
| `home.quicknav.privacy` | What we store | ما نخزنه |
| `home.quicknav.threat` | Threat model | نموذج التهديدات |
| `home.quicknav.faq` | FAQ | الأسئلة الشائعة |
| `home.quicknav.impact` | Donation impact | أثر التبرعات |
| `home.sections.features` | Features | الميزات |
| `home.sections.privacy` | Privacy | الخصوصية |
| `home.sections.how` | Getting started | البداية |
| `home.sections.membership` | Membership | العضوية |
| `home.sections.impact` | Impact | الأثر |
| `home.sections.faq` | FAQ | الأسئلة الشائعة |
| `home.sections.about` | About | حول |
| `home.sections.globe` | The map | الخريطة |
| `home.globe.title` | Voices from behind the firewall | أصوات من خلف الجدار الناري |
| `home.globe.body` | Every day, people behind national firewalls use FreeSocks to read, share, and publish - and to be heard. | كل يوم، يستخدم الناس خلف الجدران النارية الوطنية FreeSocks للقراءة والمشاركة والنشر — وليُسمع صوتهم. |
| `home.globe.aria` | A rotating globe: labels with voices from censored countries | كرة أرضية دوارة: ملصقات تحمل أصواتًا من دول خاضعة للرقابة |
| `home.globe.voices.ir.place` | Tehran, Iran | طهران، إيران |
| `home.globe.voices.ir.l1` | They filter the internet; they can't filter the truth. | يحجبون الإنترنت؛ لكنهم لا يستطيعون حجب الحقيقة. |
| `home.globe.voices.ir.l2` | My report on the protests reached the world. | تقريري عن الاحتجاجات وصل إلى العالم. |
| `home.globe.voices.ir.l3` | My students read what the state calls lies. | طلابي يقرأون ما تسميه الدولة أكاذيب. |
| `home.globe.voices.cn.place` | Beijing, China | بكين، الصين |
| `home.globe.voices.cn.l1` | History should not be a banned word. | لا ينبغي أن يكون التاريخ كلمة محظورة. |
| `home.globe.voices.cn.l2` | I shared what happened in my city - and it stayed up. | شاركت ما حدث في مدينتي — وبقي منشورًا. |
| `home.globe.voices.cn.l3` | I archived the deleted posts before they vanished. | أرشفت المنشورات المحذوفة قبل اختفائها. |
| `home.globe.voices.ru.place` | Moscow, Russia | موسكو، روسيا |
| `home.globe.voices.ru.l1` | The truth should not need a permit. | الحقيقة لا ينبغي أن تحتاج إلى تصريح. |
| `home.globe.voices.ru.l2` | Independent journalism is not a crime. | الصحافة المستقلة ليست جريمة. |
| `home.globe.voices.ru.l3` | A blocked newspaper still gets read. | الصحيفة المحجوبة ما زالت تُقرأ. |
| `home.globe.voices.tm.place` | Ashgabat, Turkmenistan | عشق آباد، تركمانستان |
| `home.globe.voices.tm.l1` | A whole country, almost offline - and still heard. | بلد كامل، شبه منقطع عن الإنترنت — ومع ذلك مسموع. |
| `home.globe.voices.tm.l2` | They control the media, not my voice. | يتحكمون في الإعلام، لا في صوتي. |
| `home.globe.voices.tm.l3` | Silence is the law here; we whisper anyway. | الصمت قانون هنا؛ ومع ذلك نتهامس. |
| `home.globe.voices.cu.place` | Havana, Cuba | هافانا، كوبا |
| `home.globe.voices.cu.l1` | My voice travels farther than I ever will. | صوتي يسافر أبعد مما سأصل إليه يومًا. |
| `home.globe.voices.cu.l2` | We document what the state denies. | نوثق ما تنكره الدولة. |
| `home.globe.voices.cu.l3` | Independent voices, hand to hand, screen to screen. | أصوات مستقلة، من يد إلى يد، ومن شاشة إلى شاشة. |
| `home.globe.voices.by.place` | Minsk, Belarus | مينسك، بيلاروس |
| `home.globe.voices.by.l1` | When they shut us down, we still spoke. | حين أوقفونا، واصلنا الكلام. |
| `home.globe.voices.by.l2` | Free elections are not extremism. | الانتخابات الحرة ليست تطرفًا. |
| `home.globe.voices.by.l3` | They banned our flag; not our voice. | حظروا علمنا؛ لا صوتنا. |
| `home.globe.voices.mm.place` | Yangon, Myanmar | يانغون، ميانمار |
| `home.globe.voices.mm.l1` | The blackout did not silence us. | انقطاع الإنترنت لم يُسكتنا. |
| `home.globe.voices.mm.l2` | Evidence of the crackdown got out. | أدلة القمع خرجت إلى العلن. |
| `home.globe.voices.mm.l3` | When the towers fell silent, the story did not. | حين صمتت الأبراج، لم تصمت الحكاية. |
| `home.globe.voices.ve.place` | Caracas, Venezuela | كاراكاس، فنزويلا |
| `home.globe.voices.ve.l1` | We count the votes they won't. | نحن نُحصي الأصوات التي لا يحصونها. |
| `home.globe.voices.ve.l2` | Hunger is not a state secret. | الجوع ليس سرًّا من أسرار الدولة. |
| `home.globe.voices.ve.l3` | The queue for food is long; the truth is longer. | طابور الخبز طويل؛ والحقيقة أطول. |
| `home.globe.voices.vn.place` | Hanoi, Vietnam | هانوي، فيتنام |
| `home.globe.voices.vn.l1` | Writing about corruption is not a crime. | الكتابة عن الفساد ليست جريمة. |
| `home.globe.voices.vn.l2` | My blog outlived the block. | مدونتي نجت من الحجب. |
| `home.globe.voices.vn.l3` | One article they deleted reached thousands. | مقال واحد حذفوه وصل إلى الآلاف. |
| `home.globe.voices.pk.place` | Karachi, Pakistan | كراتشي، باكستان |
| `home.globe.voices.pk.l1` | During the shutdown, witnesses still spoke. | أثناء القطيعة، ظل الشهود يتكلمون. |
| `home.globe.voices.pk.l2` | Silencing journalists won't hide the story. | إسكات الصحفيين لن يخفي القصة. |
| `home.globe.voices.pk.l3` | The channel went dark; the reporting did not. | القناة أظلمت؛ الصحافة لم تُظلم. |
| `home.globe.voices.eg.place` | Cairo, Egypt | القاهرة، مصر |
| `home.globe.voices.eg.l1` | They jailed the bloggers, not the words. | سجنوا المدونين، لا الكلمات. |
| `home.globe.voices.eg.l2` | The protest was documented anyway. | وُثّقت الاحتجاجات رغم كل شيء. |
| `home.globe.voices.eg.l3` | From a small screen, a big story. | من شاشة صغيرة، قصة كبيرة. |
| `home.globe.voices.sa.place` | Riyadh, Saudi Arabia | الرياض، السعودية |
| `home.globe.voices.sa.l1` | Speaking is not a crime. | الكلام ليس جريمة. |
| `home.globe.voices.sa.l2` | Her voice reached beyond the wall. | صوتها وصل إلى ما وراء الجدار. |
| `home.globe.voices.sa.l3` | She asked a question the kingdom bans. | سألت سؤالًا تحظره المملكة. |
| `home.globe.voices.et.place` | Addis Ababa, Ethiopia | أديس أبابا، إثيوبيا |
| `home.globe.voices.et.l1` | The shutdown hid nothing. | القطيعة لم تُخفِ شيئًا. |
| `home.globe.voices.et.l2` | Witnesses still found a way out. | الشهود وجدوا طريقًا للخارج. |
| `home.globe.voices.et.l3` | The dead were counted, despite the blackout. | أُحصي القتلى، رغم الانقطاع. |
| `home.globe.voices.tr.place` | Istanbul, Turkey | إسطنبول، تركيا |
| `home.globe.voices.tr.l1` | Blocking the site won't block the story. | حجب الموقع لن يحجب القصة. |
| `home.globe.voices.tr.l2` | Journalism continues, court order or not. | الصحافة مستمرة، بأمر المحكمة أو بدونه. |
| `home.globe.voices.tr.l3` | An arrested anchor cannot sign off the news. | مذيع معتقل لا يستطيع إنهاء النشرة. |
| `home.globe.voices.az.place` | Baku, Azerbaijan | باكو، أذربيجان |
| `home.globe.voices.az.l1` | They call reporting extremism. | يسمون الصحافة تطرفًا. |
| `home.globe.voices.az.l2` | The investigation was published anyway. | نُشر التحقيق رغم كل شيء. |
| `home.globe.voices.az.l3` | They froze our accounts, not our work. | جمّدوا حساباتنا، لا عملنا. |
| `home.globe.voices.uz.place` | Tashkent, Uzbekistan | طشقند، أوزبكستان |
| `home.globe.voices.uz.l1` | A closed internet is not a quiet one. | الإنترنت المغلق ليس إنترنت صامتًا. |
| `home.globe.voices.uz.l2` | The world still heard what happened here. | وسمع العالم بما جرى هنا. |
| `home.globe.voices.uz.l3` | The squares are watched; the words still move. | الساحات مراقبة؛ والكلمات تتحرك رغم ذلك. |
| `home.impact.title` | Donations at work | التبرعات تُحدث فرقًا |
| `home.impact.body` | Every donation made through FreeSocks raises the monthly bandwidth of every free account for that month. This is what donors have added so far - you could add to it too. | كل تبرع عبر FreeSocks يرفع النطاق الترددي الشهري لكل حساب مجاني في ذلك الشهر. هذا ما أضافه المتبرعون حتى الآن - ويمكنك الإضافة إليه أيضًا. |
| `home.impact.cta` | Make a donation | قدّم تبرعًا |
| `home.impact.chartAria` | Bandwidth added to every free user by donations, month by month | النطاق الترددي الذي أضافته التبرعات لكل مستخدم مجاني، شهرًا بشهر |
| `home.hero.variants.freedom` | A VPN for Internet Freedom | شبكة VPN من أجل حرية الإنترنت |
| `home.hero.variants.dissidents` | A VPN for dissidents | شبكة VPN للمعارضين |
| `home.hero.variants.privacy` | A VPN for privacy | شبكة VPN للخصوصية |
| `home.hero.variants.world` | A VPN for the world | شبكة VPN للعالم |
| `home.hero.subtitle` | FreeSocks is made for people whose internet is censored, and works as a privacy-respecting VPN anywhere else. Signing up takes one quick human check. We never ask for an email or a password. Your subscription URL works in most modern VPN apps, and a membership gets you {limits}. | صُمّم FreeSocks للأشخاص الذين يخضع إنترنتهم للرقابة، ويعمل كشبكة VPN تحترم الخصوصية في أي مكان آخر. إنشاء الحساب يتطلب تحققًا بشريًا سريعًا واحدًا. لا نطلب أبدًا بريدًا إلكترونيًا أو كلمة مرور. يعمل رابط اشتراكك في معظم تطبيقات VPN الحديثة، وتمنحك العضوية {limits}. |
| `home.hero.impactNote` | Donations made through FreeSocks directly power free users: every donation buys real bandwidth for people in censored countries, that same month. | التبرعات عبر FreeSocks تدعم المستخدمين المجانيين مباشرة: كل تبرع يشتري نطاقًا تردديًا حقيقيًا للناس في البلدان الخاضعة للرقابة، في الشهر نفسه. |
| `home.hero.impactLink` | See the impact | اطّلع على الأثر |
| `home.cta.getMembership` | Get a membership | احصل على عضوية |
| `home.freeCard.title` | Free tier | المستوى المجاني |
| `home.freeCard.badge` | What you get | ما ستحصل عليه |
| `home.freeCard.urlTitle` | Xray subscription URL | رابط الاشتراك في خدمة الأشعة السينية |
| `home.freeCard.urlBody` | Xray-powered VLESS. Paste into any compatible client. | Xray-powered VLESS. Paste into any compatible client. |
| `home.freeCard.membershipLine` | A FreeSocks membership gives you {limits}. | تمنحك عضوية FreeSocks {limits} . |
| `home.freeCard.noAuthTitle` | No email or password | لا حاجة إلى بريد إلكتروني أو كلمة مرور |
| `home.freeCard.noAuthBody` | One human-check. Save your account number to sign in. No email collected. | عملية تحقق بشرية واحدة. احفظ رقم حسابك لتسجيل الدخول. لم يتم جمع أي بريد إلكتروني. |
| `home.freeCard.footnote` | Numbers reflect the current free-tier configuration. Solve the check to get yours. | الأرقام تعكس إعدادات المستوى المجاني الحالية. حلّ الاختبار للحصول على إعداداتك. |
| `home.freeCard.upsellTitle` | Want unlimited? | هل تريد اشتراكاً غير محدود؟ |
| `home.freeCard.upsellBody` | Get {limits} - and help keep FreeSocks free for others. | احصل على {limits} - وساعد في إبقاء FreeSocks مجانيًا للآخرين. |
| `home.freeCard.fromPerMonth` | from {price}/mo | من {price} /شهرياً |
| `home.freeCard.cryptoNote` | Crypto accepted - Bitcoin, Monero, Zcash and more | نقبل العملات المشفّرة - بيتكوين ومونيرو وزيكاش والمزيد |
| `home.features.title` | What FreeSocks is | ما هو FreeSocks؟ |
| `home.features.noAuth.title` | No email or password | لا حاجة إلى بريد إلكتروني أو كلمة مرور |
| `home.features.noAuth.body` | One human-check and you are in. We mint a 32-digit account number you save to sign back in. No email collected. | بمجرد التحقق البشري، ستتمكن من الدخول. سنقوم بإنشاء رقم حساب مكون من 32 رقمًا يمكنك حفظه لتسجيل الدخول مرة أخرى. لا يتم جمع أي بريد إلكتروني. |
| `home.features.mirrors.title` | Mirror URLs | روابط النسخ الاحتياطية |
| `home.features.mirrors.body` | Subscriptions are mirrored across multiple providers so a single block does not cut you off. | يتم نسخ الاشتراكات عبر مزودين متعددين، لذا فإن حظرًا واحدًا لن يقطع الخدمة عنك. |
| `home.features.protocols.title` | Standard protocols | البروتوكولات القياسية |
| `home.features.protocols.body` | Xray-powered VLESS. Works in most VPN clients. | Xray-powered VLESS. Works in most VPN clients. |
| `home.privacy.title` | What we store | ما نخزنه |
| `home.privacy.subtitle` | FreeSocks is built to know as little about you as possible. | تم تصميم FreeSocks بحيث لا يعرف عنك إلا أقل قدر ممكن. |
| `home.privacy.point1` | We store only a hashed version of your account number - never the number itself. | نحن نخزن فقط نسخة مشفرة من رقم حسابك - وليس الرقم نفسه أبدًا. |
| `home.privacy.point2` | No email, phone number, or name. We never ask for them. | لا نطلب البريد الإلكتروني أو رقم الهاتف أو الاسم. لا نطلبها مطلقاً. |
| `home.privacy.point3` | No logs of the sites you visit or the traffic you send - and we don't store your IP address, on our servers or the VPN nodes. | لا يتم تسجيل المواقع التي تزورها أو حركة البيانات التي ترسلها. |
| `home.privacy.point4` | We store no payment details - you pay on the provider's own page, and the provider never sees your account or VPN subscription. | لا نقوم بتخزين أي تفاصيل دفع - أنت تدفع على صفحة المزود الخاصة، ولا يرى المزود حسابك أو اشتراكك في خدمة البروكسي. |
| `home.how.title` | How it works | كيف يعمل؟ |
| `home.how.cta` | Try it now | جربها الآن |
| `home.how.s1.title` | Create a free account | أنشئ حسابًا مجانيًا |
| `home.how.s1.body` | Solve a quick human-check. You get a 32-digit account number to save: it is how you sign back in. | قم بإجراء فحص سريع للتأكد من هوية المستخدم. ستحصل على رقم حساب مكون من 32 رقمًا لحفظه: هذه هي طريقة تسجيل الدخول مرة أخرى. |
| `home.how.s2.title` | Create your subscription | أنشئ اشتراكك |
| `home.how.s2.body` | Once you are signed in, create a subscription URL, with a QR code for handoff to a phone. | بمجرد تسجيل الدخول، قم بإنشاء رابط اشتراك، مع رمز الاستجابة السريعة (QR) لتسليمه إلى الهاتف. |
| `home.how.s3.title` | Paste it into a VPN client | الصقها في برنامج عميل VPN |
| `home.how.s3.body` | Add the URL as a subscription in any compatible client. | أضف عنوان URL كاشتراك في أي عميل متوافق. |
| `home.membership.title` | Membership | عضوية |
| `home.membership.lead` | Free covers the basics. | يغطي البرنامج المجاني الأساسيات. |
| `home.membership.descriptionFallback` | A FreeSocks membership lifts every limit. | عضوية FreeSocks ترفع كل الحدود. |
| `home.membership.payNote` | Pay privately with Bitcoin, Monero, or Zcash - or use a card or PayPal. | ادفع باستخدام العملات المشفرة (بيتكوين ومونيرو وغيرها)، أو البطاقة، أو باي بال. |
| `home.about.title` | About FreeSocks | حول FreeSocks |
| `home.about.bodyPrefix` | FreeSocks is operated by | يتم تشغيل FreeSocks بواسطة |
| `home.about.bodySuffix` | , a US 501(c)(3) nonprofit. | ، منظمة أمريكية غير ربحية 501(c)(3). |
| `home.about.body2` | Most VPNs assume you can pay for a subscription and safely hand over an email address. In much of the world neither is true, so FreeSocks asks for neither. Anyone can get a working key in about a minute and keep it for as long as they use it. | معظم خدمات VPN تفترض أنك تستطيع الدفع مقابل اشتراك وتسليم بريدك الإلكتروني بأمان. في معظم أنحاء العالم لا يصحّ أيٌّ منهما، لذلك لا يطلب FreeSocks أيًّا منهما. يمكن لأي شخص الحصول على مفتاح يعمل في نحو دقيقة والاحتفاظ به ما دام يستخدمه. |
| `home.about.siteLink` | unredacted.org | unredacted.org |
| `home.about.openSource` | The code that runs this service is published for anyone to inspect, audit, or run themselves. | الكود الذي يشغّل هذه الخدمة منشور ليطّلع عليه أي شخص أو يدقّقه أو يشغّله بنفسه. |
| `home.about.viewSourceCta` | View the source | اطّلع على المصدر |
| `home.about.fact2Title` | Open source | مفتوح المصدر |
| `home.about.fact3Title` | Donation funded | ممول بالتبرعات |
| `home.about.fact3Body` | Free accounts are paid for by donations and memberships. There are no ads and nothing is sold. | تموَّل الحسابات المجانية من التبرعات والعضويات. لا إعلانات ولا شيء يُباع. |
| `home.limits.unlimitedBoth` | unlimited bandwidth and devices | نطاق ترددي وأجهزة غير محدودة |
| `home.limits.unlimitedBandwidth` | unlimited bandwidth | نطاق ترددي غير محدود |
| `home.limits.unlimitedDevices` | unlimited devices | أجهزة غير محدودة |
| `home.limits.bandwidthAndDevices` | {bandwidth} and {devices} | {bandwidth} و {devices} |
| `home.limits.upToDevices [countPlural=one]` | up to 1 device | جهاز واحد كحد أقصى |
| `home.limits.upToDevices [countPlural=other]` | up to {count} devices | يصل عدد الأجهزة إلى {count} جهازًا |

## `e2ee` — The HPKE/E2EE "encrypted to this server" badge + verification panel.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `e2ee.badgeActiveTitle` | Encrypted to this server with HPKE. Click to verify. | تم تشفير البيانات على هذا الخادم باستخدام HPKE. انقر للتحقق. |
| `e2ee.badgeWarnTitle` | Couldn't verify the encryption key. Click to verify out-of-band before entering your account number. | تعذر التحقق من مفتاح التشفير. انقر للتحقق خارج النطاق قبل إدخال رقم حسابك. |
| `e2ee.badgeActiveTitleAdmin` | Sensitive member and admin actions are HPKE-encrypted on this deployment. Click for details. | يتم تشفير الإجراءات الحساسة للأعضاء والمسؤولين باستخدام بروتوكول HPKE في هذا النظام. انقر هنا للاطلاع على التفاصيل. |
| `e2ee.badgeWarnTitleAdmin` | Couldn't verify this deployment's encryption key. Click for details and out-of-band verification. | تعذر التحقق من مفتاح تشفير هذا النشر. انقر هنا للاطلاع على التفاصيل والتحقق خارج النطاق. |
| `e2ee.badgeOff` | TLS | TLS |
| `e2ee.badgeOffTitle` | Standard TLS only. Extra HPKE body encryption isn't enabled on this deployment. | بروتوكول TLS القياسي فقط. تشفير بيانات HPKE الإضافي غير مُفعّل في هذا الإصدار. |
| `e2ee.bannerWarn` | Couldn't verify the encryption key | تعذر التحقق من مفتاح التشفير |
| `e2ee.bannerWarnDetail` | Don't enter your account number yet - verify this connection out-of-band first. | لا تُدخل رقم حسابك الآن - تحقق من هذا الاتصال خارج النطاق أولاً. |
| `e2ee.verify` | Verify | يؤكد |
| `e2ee.verifyTitle` | Verify this connection | تحقق من هذا الاتصال |
| `e2ee.verifyIntro` | FreeSocks seals your account number and VPN key to this server with HPKE, so a compromised CDN can't read them. These fingerprints identify the keys your browser is using - compare them against the values published out-of-band to be sure they haven't been swapped. | يقوم FreeSocks بتشفير رقم حسابك ومفتاح الوكيل لهذا الخادم باستخدام HPKE، مما يمنع أي شبكة توصيل محتوى (CDN) مخترقة من قراءتهما. تُحدد هذه البصمات المفاتيح التي يستخدمها متصفحك - قارنها بالقيم المنشورة خارج النطاق للتأكد من عدم استبدالها. |
| `e2ee.protectHeading` | What this protects | ما يحميه هذا |
| `e2ee.protectScope` | Your account number and key are encrypted to this server with HPKE, so the network and any CDN in front of it can't read them. | يتم تشفير رقم حسابك ومفتاحك على هذا الخادم باستخدام HPKE، لذلك لا يمكن للشبكة وأي شبكة توصيل محتوى (CDN) أمامها قراءتهما. |
| `e2ee.protectServerReads` | FreeSocks itself can read them to set up your account, so this protects you from the network in between, not from the server. | يمكن لبرنامج FreeSocks نفسه قراءة هذه البيانات لإعداد حسابك، لذا فإن هذا يحميك من الشبكة الوسيطة، وليس من الخادم. |
| `e2ee.protectTunnel` | It's separate from your VPN connection, which is encrypted on its own. | وهو منفصل عن اتصال VPN الخاص بك، والذي يتم تشفيره بشكل مستقل. |
| `e2ee.protectAdmin` | On the admin dashboard, sensitive actions - creating API tokens, invites, and membership codes, and uploading backend, billing, or storage credentials - are HPKE-encrypted to this server too. Routine reads and settings use TLS, your passkey, and proof-of-possession. | في لوحة تحكم المسؤول، تُشفّر الإجراءات الحساسة - مثل إنشاء رموز API، ودعوات المستخدمين، ورموز العضوية، وتحميل بيانات اعتماد الواجهة الخلفية، والفواتير، والتخزين - باستخدام بروتوكول HPKE على هذا الخادم أيضًا. أما عمليات القراءة والإعدادات الروتينية فتستخدم بروتوكول TLS، وكلمة المرور الخاصة بك، وإثبات الملكية. |
| `e2ee.fingerprintsHeading` | Key fingerprints | بصمات المفاتيح |
| `e2ee.fpHpke` | Server key (HPKE / X-Wing) | مفتاح الخادم (HPKE / X-Wing) |
| `e2ee.fpKid` | Key id | معرف المفتاح |
| `e2ee.fpManifest` | Manifest key (Ed25519) | مفتاح البيان (Ed25519) |
| `e2ee.fpManifestPq` | Manifest key (ML-DSA-65, post-quantum) | مفتاح البيان (ML-DSA-65، ما بعد الكم) |
| `e2ee.fpSuite` | Cipher suite | مجموعة التشفير |
| `e2ee.copy` | Copy | ينسخ |
| `e2ee.copied` | Copied | تم النسخ |
| `e2ee.attestationHeading` | Live server attestation | مصادقة الخادم المباشر |
| `e2ee.attestationOk` | Verified - the server is attesting a valid key signed by the manifest key your app trusts. | تم التحقق - يقوم الخادم بالتصديق على مفتاح صالح موقع بواسطة مفتاح البيان الذي يثق به تطبيقك. |
| `e2ee.attestationEpoch` | Current key {kid}, expires {expiry}. | المفتاح الحالي {kid} , تنتهي صلاحيته {expiry} . |
| `e2ee.attestationFail` | Could not verify the server's current key - a network problem, or a CDN tampering with the key endpoint. Verify out-of-band before continuing. | تعذر التحقق من مفتاح الخادم الحالي - إما بسبب مشكلة في الشبكة، أو بسبب تلاعب شبكة توصيل المحتوى (CDN) بنقطة نهاية المفتاح. يرجى التحقق من المفتاح خارج النطاق قبل المتابعة. |
| `e2ee.attestationUnreachable` | The live key check is temporarily unavailable. Your connection still uses the verified key built into the app. | خاصية التحقق من المفتاح المباشر غير متاحة مؤقتًا. لا يزال اتصالك يستخدم المفتاح المُتحقق منه والمدمج في التطبيق. |
| `e2ee.attestationUnconfigured` | Live key checking isn't set up on this build. | لم يتم إعداد خاصية التحقق المباشر من المفاتيح في هذه النسخة. |
| `e2ee.compareHeading` | How to verify | كيفية التحقق |
| `e2ee.compareBody` | Compare the fingerprints above against the values published through a channel this server doesn't control. They must match. | قارن البصمات المذكورة أعلاه بالقيم المنشورة عبر قناة لا يتحكم بها هذا الخادم. يجب أن تتطابق. |
| `e2ee.channelRelease` | Signed release notes | ملاحظات الإفراج الموقعة |
| `e2ee.channelSource` | Source code (rebuild to compare) | شفرة المصدر (أعد بناءها للمقارنة) |
| `e2ee.channelOnion` | Tor mirror | مرآة تور |
| `e2ee.dnsHeading` | Verify via DNS | التحقق عبر نظام أسماء النطاقات (DNS) |
| `e2ee.dnsBody` | Look the pin up yourself in a terminal, through your own DNS resolver - a path that doesn't run through this site or its CDN. The answer should contain the same fingerprints shown above. (If it returns nothing, the operator may not have published the record yet; use the signed release instead.) | ابحث عن رمز التعريف بنفسك في سطر الأوامر، عبر خادم DNS الخاص بك - مسار لا يمر عبر هذا الموقع أو شبكة توصيل المحتوى الخاصة به. يجب أن تحتوي الإجابة على نفس بصمات الأصابع الموضحة أعلاه. (إذا لم تُظهر أي نتيجة، فقد لا يكون المشغل قد نشر السجل بعد؛ استخدم الإصدار الموقّع بدلاً من ذلك.) |
| `e2ee.dnsCommand` | Run this in a terminal | قم بتشغيل هذا الأمر في نافذة طرفية. |
| `e2ee.dnsExpected` | It should return | ينبغي أن يعود |
| `e2ee.dnsCaveat` | Independent only if your DNS isn't run by the same company as the CDN; a DNSSEC-validating resolver is best. For full assurance, confirm the same values in the signed release too. | مستقل فقط إذا لم تكن خدمة نظام أسماء النطاقات (DNS) مُدارة من قِبل نفس الشركة التي تُدير شبكة توصيل المحتوى (CDN)؛ ويُفضّل استخدام مُحلِّل أسماء نطاقات يدعم التحقق من صحة DNSSEC. ولضمان كامل، تأكد من صحة القيم نفسها في الإصدار المُوقَّع أيضًا. |
| `e2ee.verifierExtension` | A verifier browser extension that re-checks this build on every visit is planned, but not available yet. | من المخطط إطلاق إضافة متصفح للتحقق تعيد فحص هذا الإصدار في كل زيارة، ولكنها غير متاحة بعد. |
| `e2ee.verifierExtensionInstall` | Install the verifier extension - it re-checks this build against the published one on every visit (the strongest protection against a tampered page). | قم بتثبيت ملحق التحقق - فهو يعيد فحص هذا الإصدار مقابل الإصدار المنشور في كل زيارة (أقوى حماية ضد التلاعب بالصفحة). |
| `e2ee.caveat` | This in-page check is a convenience. A tampered page could lie about its own status, so the real proof comes from comparing these values somewhere outside this server, such as the DNS lookup above or a published release. | يُعدّ هذا الفحص داخل الصفحة إجراءً مُريحًا. قد تُضلل الصفحة المُعدّلة بشأن حالتها، لذا فإنّ الدليل الحقيقي يأتي من مُقارنة هذه القيم في مكانٍ خارج هذا الخادم، مثل البحث في نظام أسماء النطاقات (DNS) المذكور أعلاه أو إصدارٍ منشور. |
| `e2ee.close` | Close | يغلق |

## `deviceRevoke` — The disconnect-a-device confirmation dialog.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `deviceRevoke.title` | Revoke this device? | هل تريد إلغاء هذا الجهاز؟ |
| `deviceRevoke.body` | The device ending …{suffix} will be disconnected and its slot freed. It can reconnect later by re-importing your subscription URL. | سيتم فصل الجهاز الذي ينتهي بـ ... {suffix} وسيتم تحرير خانته. ويمكن إعادة الاتصال به لاحقًا عن طريق إعادة استيراد رابط اشتراكك. |
| `deviceRevoke.confirm` | Revoke device | إلغاء الجهاز |
| `deviceRevoke.working` | Revoking… | إلغاء… |

## `status` — Miscellaneous strings.

| Key | English | Arabic (العربية) |
| --- | --- | --- |
| `status.title` | Network status | حالة الشبكة |
| `status.updated` | Updated {time} | آخر تحديث {time} |
| `status.overallOk` | All locations are operating normally | جميع المواقع تعمل بشكل طبيعي |
| `status.overallPartial` | Some locations are having issues | بعض المواقع تواجه مشكلات |
| `status.overallMajor` | A major outage is in progress | هناك انقطاع كبير جارٍ |
| `status.locationsTitle` | Locations | المواقع |
| `status.nodesUp` | {online} of {total} nodes up | {online} من {total} عقدة متصلة |
| `status.online` | Online | متصل |
| `status.offline` | Offline | غير متصل |
| `status.srOnline` | online | متصل |
| `status.srOffline` | offline | غير متصل |
| `status.loadQuiet` | Quiet | هادئ |
| `status.loadBusy` | Busy | مزدحم |
| `status.loadCrowded` | Crowded | مزدحم جدًا |
| `status.loadUnknown` | Load unknown | الازدحام غير معروف |
| `status.matrixTitle` | Availability in censored regions | التوفر في المناطق الخاضعة للرقابة |
| `status.matrixBody` | How well each connection mode works from specific countries, based on reports we receive. "Partial" means some networks or times of day block it. | مدى جودة عمل كل وضع اتصال من بلدان محددة، استنادًا إلى البلاغات التي تصلنا. "جزئي" يعني أن بعض الشبكات أو أوقات اليوم تحجبه. |
| `status.matrixAvailable` | Available | متاح |
| `status.matrixPartial` | Partial | جزئي |
| `status.matrixBlocked` | Blocked | محجوب |
| `status.matrixEmpty` | No country data published yet. | لا توجد بيانات بلدان منشورة بعد. |
| `status.incidentsTitle` | Incidents | الحوادث |
| `status.incidentsNone` | No incidents in the last 30 days. | لا حوادث في آخر 30 يومًا. |
| `status.incidentsOngoing` | Ongoing | جارٍ |
| `status.incidentsResolved` | Resolved {time} | حُلّ {time} |
| `status.incidentsStarted` | Started {time} | بدأ {time} |
| `status.incidentsGlobal` | All locations | جميع المواقع |
| `status.incidentsPast` | Past incidents | الحوادث السابقة |
| `status.report` | Report a problem | الإبلاغ عن مشكلة |
