import type { Messages } from './en';

/**
 * Farsi (فارسی) — RTL. First-pass translations of the critical strings; keys not
 * present here fall back to English. FLAGGED FOR NATIVE-SPEAKER REVIEW before
 * launch (especially the reveal-once warnings and error copy).
 */
export const fa: Partial<Messages> = {
  'common.copy': 'کپی',
  'common.copied': 'در کلیپ‌بورد کپی شد',
  'common.copyFailed': 'کپی نشد — متن را انتخاب و دستی کپی کنید',
  'common.download': 'دانلود',
  'common.print': 'چاپ',
  'common.cancel': 'لغو',
  'common.close': 'بستن',
  'common.retry': 'تلاش دوباره',
  'common.loading': 'در حال بارگذاری…',
  'common.language': 'زبان',

  'nav.getAccount': 'دریافت حساب رایگان',
  'nav.signIn': 'ورود',
  'nav.account': 'حساب من',

  'captcha.initial': 'من انسان هستم',
  'captcha.verifying': 'در حال بررسی…',
  'captcha.solved': 'تأیید شد',
  'captcha.error': 'بررسی ناموفق بود — دوباره تلاش کنید',

  'reveal.title': 'شمارهٔ حساب خود را همین حالا ذخیره کنید',
  'reveal.subtitle':
    'این شمارهٔ ۳۲ رقمی تنها راه ورود دوباره است. هیچ ایمیل یا رمز عبوری برای بازیابی آن وجود ندارد. اگر آن را گم کنید، حسابتان برای همیشه از دست می‌رود.',
  'reveal.cannotRecover': 'ما نمی‌توانیم آن را برایتان بازیابی کنیم — حتی پشتیبانی هم نمی‌تواند.',
  'reveal.saveHint': 'آن را در یک مدیر رمز عبور ذخیره کنید یا در جایی امن و خصوصی یادداشت کنید.',
  'reveal.confirmCheckbox': 'شمارهٔ حسابم را در جایی امن ذخیره کرده‌ام',
  'reveal.done': 'ذخیره کردم',
  'reveal.leaveWarning':
    'شمارهٔ حساب شما هنوز روی صفحه است. اگر اکنون بدون ذخیره‌کردن خارج شوید، دیگر نمی‌توانید وارد شوید.',

  'support.label': 'شناسهٔ پشتیبانی',
  'support.hint':
    'اگر با ما تماس گرفتید این را به اشتراک بگذارید. این شمارهٔ ورود شما نیست و دسترسی‌ای نمی‌دهد.',

  'login.title': 'با شمارهٔ حساب خود وارد شوید',
  'login.subtitle':
    'شمارهٔ حساب ۳۲ رقمی‌ای را که ذخیره کرده‌اید وارد کنید. این تنها راه ورود است — ایمیل یا رمز عبوری برای بازیابی وجود ندارد.',
  'login.label': 'شمارهٔ حساب',
  'login.show': 'نمایش',
  'login.hide': 'پنهان',
  'login.submit': 'ورود',
  'login.submitting': 'در حال ورود…',
  'login.noAccount': 'هنوز شمارهٔ حساب ندارید؟',
  'login.getOne': 'دریافت حساب رایگان',
  'login.failed': 'ورود ناموفق بود',

  'account.title': 'حساب شما',
  'account.tierLabel': 'پلن شما',
  'account.statusActive': 'فعال',
  'account.statusGrace': 'به‌زودی منقضی می‌شود',
  'account.statusDisabled': 'منقضی شده',
  'account.regenerate': 'ساخت کلید جدید',
  'account.switchBackend': 'تغییر نوع سرور',
  'account.rotate': 'تغییر شمارهٔ حساب',
  'account.signOut': 'خروج',
  'account.redeemTitle': 'کد عضویت دارید؟',
  'account.redeemSubmit': 'استفاده از کد',
  'account.redeemSuccess': (p) => `استفاده شد — اکنون ${p.days} روز دیگر در ${p.tier} هستید.`,
  'account.redeemFailed': 'این کد معتبر نیست یا قبلاً استفاده شده است.',

  'renew.expiringTitle': 'عضویت شما به‌زودی منقضی می‌شود',
  'renew.expiredTitle': 'عضویت شما منقضی شده است',
  'renew.body':
    'فری‌ساکس با کمک‌های مردمی اداره می‌شود. برای تمدید عضویت، کمک مالی کنید یا برای دریافت کد عضویت با ما تماس بگیرید.',
  'renew.donate': 'کمک مالی',
  'renew.contact': 'تماس با ما',
  'renew.haveCode': 'کد عضویت دارید؟ از بالا استفاده کنید.',

  'error.offline': 'به نظر می‌رسد آفلاین هستید. اتصال خود را بررسی و دوباره تلاش کنید.',
  'error.rateLimited': 'تلاش‌های زیاد. لطفاً یک دقیقه صبر کنید و دوباره تلاش کنید.',
  'error.backendUnavailable':
    'در حال حاضر هیچ سرور پروکسی در دسترس نیست. حساب شما امن است — چند دقیقه دیگر دوباره کلید بسازید.',
  'error.generic': 'مشکلی پیش آمد. لطفاً دوباره تلاش کنید.',
  'error.captchaFailed': 'بررسی انسانی ناموفق بود. لطفاً آن را کامل کنید و دوباره تلاش کنید.',

  'setup.title': 'برنامهٔ پروکسی خود را تنظیم کنید',
  'setup.intro': 'لینک اشتراک بالا را کپی کنید، سپس آن را به یک برنامهٔ سازگار اضافه کنید:',
  'setup.android': 'اندروید',
  'setup.ios': 'آیفون / آی‌پد',
  'setup.windows': 'ویندوز',
  'setup.desktop': 'مک / لینوکس',
  'setup.step.install': 'برنامه را نصب کنید',
  'setup.step.import': 'آن را باز کنید، یک اشتراک/پروفایل اضافه کنید و لینک خود را جای‌گذاری کنید',
  'setup.step.connect': 'یک سرور انتخاب کنید و متصل شوید',
  'setup.qrHint': 'یا این کد QR را با تلفن خود اسکن کنید تا لینک منتقل شود.',

  'common.working': 'در حال انجام…',
  'common.reload': 'بارگذاری مجدد',
  'common.deviceCount': (p) => `${p.count} دستگاه`,
  'login.success': 'وارد شدید',

  'captcha.failedTitle': 'بررسی انسانی کامل نشد.',
  'captcha.failedBody':
    'این بررسی کاملاً در مرورگر شما اجرا می‌شود. اگر ناموفق بود، شاید مرورگرتان Worker مورد نیاز را مسدود کرده یا شبکه درخواست را از دست داده است.',
  'captcha.failedTip1': 'افزونه‌های مرورگر را غیرفعال کنید',
  'captcha.failedTip2': 'شبکهٔ دیگری یا یک پنجرهٔ ناشناس را امتحان کنید',
  'captcha.failedTip3': 'مطمئن شوید جاوااسکریپت و WebAssembly فعال هستند',

  'account.redeemAriaLabel': 'کد عضویت',
  'account.switchTo': (p) => `تغییر به ${p.label}`,
  'account.devicesTitle': 'دستگاه‌های متصل',
  'account.lastSeen': (p) => `آخرین اتصال ${p.date}`,
  'account.noSubTitle': 'هنوز اشتراکی ندارید',
  'account.noSubBody':
    'اولین اشتراک خود را بسازید تا لینکی دریافت کنید که در هر برنامهٔ VPN سازگار قابل استفاده است.',
  'account.createSub': 'ساخت اشتراک',
  'account.creating': 'در حال ساخت…',
  'account.rotateTitle': 'شمارهٔ حساب عوض شود؟',
  'account.rotateBody':
    'یک شمارهٔ ۳۲ رقمی جدید ساخته و فقط یک بار نمایش داده می‌شود. شمارهٔ فعلی بلافاصله از کار می‌افتد و هر کسی که آن را دارد دسترسی‌اش را از دست می‌دهد. اگر فکر می‌کنید شماره‌تان لو رفته این کار را انجام دهید.',
  'account.rotateConfirm': 'بله، عوض کن',
  'account.rotating': 'در حال تغییر…',
  'account.rotateFailedTitle': 'تغییر شمارهٔ حساب ناموفق بود',
  'account.freeTierTitle': 'شما در پلن رایگان هستید',
  'account.freeTierBody':
    'عضویت FreeSocks دستگاه‌ها و پهنای باند نامحدود را در اختیار شما می‌گذارد. کمک‌های مالی نیز حساب‌های رایگان را سرپا نگه می‌دارند.',
  'account.refreshMembership': 'قبلاً پرداخت کرده‌اید؟ به‌روزرسانی عضویت',
  'account.refreshing': 'در حال به‌روزرسانی…',
  'account.regenSuccessTitle': 'لینک اشتراک جدید ساخته شد',
  'account.regenSuccessBody':
    'آن را دوباره در همهٔ دستگاه‌هایتان وارد کنید. لینک قبلی تا ۲۴ ساعت دیگر کار می‌کند.',
  'account.regenFailedTitle': 'ساخت کلید جدید ناموفق بود',
  'account.switchSuccessTitle': (p) => `به ${p.tier} تغییر کرد`,
  'account.switchSuccessBodyGrace':
    'لینک اشتراک جدید را در همهٔ دستگاه‌ها وارد کنید. اشتراک قبلی تا ۲۴ ساعت دیگر کار می‌کند.',
  'account.switchSuccessBody': 'لینک اشتراک جدید را در همهٔ دستگاه‌ها وارد کنید.',
  'account.switchFailedTitle': 'تغییر نوع سرور ناموفق بود',
  'account.refreshWelcome': (p) => `به ${p.tier} خوش آمدید`,
  'account.refreshNoneTitle': 'هنوز عضویت فعالی یافت نشد',
  'account.refreshNoneBody': 'اگر همین حالا پرداخت کرده‌اید، کمی صبر کنید و دوباره امتحان کنید.',
  'account.refreshFailedTitle': 'به‌روزرسانی عضویت ناموفق بود',
  'account.graceTitle': 'حساب شما در مهلت ارفاقی است',
  'account.graceBody':
    'عضویت شما به پایان رسیده و این حساب به‌زودی محدود می‌شود. برای حفظ پلن خود تمدید کنید — کمک مالی کنید یا کد عضویت را در پایین وارد کنید.',
  'account.disabledTitle': 'حساب شما در حال حاضر غیرفعال است',
  'account.disabledBody':
    'ساخت کلید جدید و تغییرات در این حساب متوقف شده است. برای فعال‌سازی دوباره، کد عضویت را در پایین وارد کنید یا با پشتیبانی تماس بگیرید و شناسهٔ پشتیبانی خود را اعلام کنید.',

  'hero.titleDefault': 'اشتراک شما',
  'hero.eyebrowAccessKey': 'کلید دسترسی شما',
  'hero.urlLabelSubscription': 'لینک اشتراک',
  'hero.urlLabelAccessKey': 'کلید دسترسی',
  'hero.tierLine': (p) => `سطح ${p.tier}`,
  'hero.viaLine': (p) => `از طریق ${p.backend}`,
  'hero.copyUrl': 'کپی لینک',
  'hero.copiedShort': 'کپی شد',
  'hero.qrShow': 'QR',
  'hero.qrHide': 'پنهان',
  'hero.scanPhone': 'با تلفن خود اسکن کنید',
  'hero.scanOther': 'با دستگاه دیگری اسکن کنید',
  'hero.scanFallback': 'لینک جایگزین را با دستگاه دیگری اسکن کنید',
  'hero.fallbackLabel': 'لینک جایگزین',
  'hero.fallbackHint': 'اگر لینک اصلی مسدود شد از این استفاده کنید',
  'hero.fallbackQrAria': 'نمایش کد QR لینک جایگزین',
  'hero.downloaded': (p) => `${p.filename} دانلود شد`,
  'hero.traffic': 'ترافیک',
  'hero.unlimited': 'نامحدود',
  'hero.usedSoFar': (p) => `${p.amount} مصرف شده`,
  'hero.leftThisPeriod': (p) => `${p.amount} از این دوره باقی مانده.`,
  'hero.nearlyOut': (p) => `رو به اتمام — فقط ${p.amount} از این دوره باقی مانده.`,
  'hero.expires': 'انقضا',
  'hero.noExpiry': 'بدون انقضا',
  'hero.expiresToday': 'امروز منقضی می‌شود',
  'hero.daysRemaining': (p) => `${p.count} روز باقی مانده`,
  'hero.expiredDaysAgo': (p) => `${p.count} روز پیش منقضی شد`,

  'regen.title': 'اشتراک از نو ساخته شود؟',
  'regen.body': (p) =>
    `لینک اشتراک فعلی شما (با پایان …${p.suffix}) با لینک جدیدی جایگزین می‌شود. لینک قبلی ۲۴ ساعت فقط‌خواندنی می‌ماند و سپس حذف می‌شود.`,
  'regen.point1': 'کلید فعلی شما تا ۲۴ ساعت آینده قابل استفاده می‌ماند',
  'regen.point2': 'باید لینک جدید را در هر یک از دستگاه‌هایتان دوباره وارد کنید',
  'regen.pointDevices': (p) => `اکنون ${p.count} دستگاه متصل دارید — همگی به لینک جدید نیاز دارند`,
  'regen.confirm': 'ساخت دوباره',
  'regen.working': 'در حال ساخت…',

  'switch.title': (p) => `تغییر به ${p.to}؟`,
  'switch.body': (p) =>
    `اشتراک فعلی ${p.from} شما با اشتراک جدید ${p.to} جایگزین می‌شود. اشتراک قبلی ۲۴ ساعت قابل استفاده می‌ماند تا پیش از قطع شدن، لینک جدید را روی همهٔ دستگاه‌ها وارد کنید.`,
  'switch.point1': (p) => `یک لینک اشتراک جدید روی بک‌اند ${p.to} صادر می‌شود`,
  'switch.point2': (p) => `لینک فعلی ${p.from} تا ۲۴ ساعت کار می‌کند و سپس حذف می‌شود`,
  'switch.point3': 'باید لینک جدید را در هر برنامهٔ VPN که استفاده می‌کنید دوباره وارد کنید',
  'switch.pointDevices': (p) =>
    `اکنون ${p.count} دستگاه متصل دارید — روی همهٔ آن‌ها دوباره وارد کنید`,
  'switch.confirm': (p) => `تغییر به ${p.to}`,
  'switch.working': 'در حال تغییر…',

  'get.badge': 'حساب رایگان',
  'get.title': 'دریافت حساب فری‌ساکس',
  'get.introTwoSteps':
    'دو مرحلهٔ سریع: بررسی انسانی را انجام دهید تا حساب رایگان ساخته شود، سپس اشتراک خود را بسازید.',
  'get.step1Title': 'حساب خود را بسازید',
  'get.chooseBackend': 'یک بک‌اند انتخاب کنید',
  'get.backendAria': 'بک‌اند',
  'get.backendMultiProtocol': 'چندپروتکلی (VLESS، Trojan، Shadowsocks)',
  'get.backendShadowsocks': 'Shadowsocks از طریق Outline',
  'get.createAccount': 'ساخت حساب من',
  'get.freeAccountNote':
    'حساب‌های رایگان ۳۰ روز اعتبار دارند و به یک دستگاه محدودند. بدون ایمیل یا رمز عبور.',
  'get.accountReady': 'حساب شما آماده است.',
  'get.step2Title': 'اشتراک خود را بسازید',
  'get.step2Intro':
    'یک اشتراک پروکسی بسازید تا لینکی دریافت کنید که می‌توانید در هر برنامهٔ VPN سازگار جای‌گذاری کنید.',
  'get.manageHintPrefix': 'این اشتراک را هر زمان مدیریت کنید از',
  'get.manageLinkLabel': 'حساب شما',
  'get.subErrorSafePrefix': 'حساب شما امن است. بعداً می‌توانید اشتراک را بسازید از',
  'get.subErrorSafeSuffix': 'وقتی سروری در دسترس شد.',
  'get.createSubToastTitle': 'اشتراک ساخته شد',
  'get.createSubToastBody': 'لینک را در برنامهٔ VPN خود کپی کنید یا کد QR را اسکن کنید.',
  'get.createAccountFailedTitle': 'ساخت حساب ناموفق بود',
  'get.createSubFailedTitle': 'ساخت اشتراک ناموفق بود',
  'get.haveAccountPrefix': 'از قبل حساب دارید؟',
  'get.lostNumberHint': 'شمارهٔ حساب را پیش از ذخیره گم کردید؟ می‌توانید شمارهٔ جدیدی بگیرید —',
  'get.lostNumberLinkLabel': 'از صفحهٔ حساب خود آن را تغییر دهید',

  'tiers.title': 'سطح‌ها',
  'tiers.subtitle': 'هر سطح چه چیزهایی دارد.',
  'tiers.yourTier': 'سطح شما',
  'tiers.gbPerMonth': (p) => `${p.gb} گیگابایت / ماه`,
  'tiers.validity30': 'کلید ۳۰ روزه',
  'tiers.validityContinuous': 'پیوسته',
  'tiers.mirrors': 'لینک‌های آینه',
  'tiers.comingSoon': 'به‌زودی',
  'tiers.comingSoonTitle': 'ثبت‌نام عضویت به‌زودی فعال می‌شود',

  'impact.title': 'کمک‌های مالی از Unredacted پشتیبانی می‌کنند',
  'impact.body':
    'Unredacted یک سازمان غیرانتفاعی 501(c)(3) آمریکایی است. فری‌ساکس یکی از پروژه‌های آن است. کمک‌های مالی هزینهٔ این کار را تأمین می‌کنند. جزئیات را در سایت Unredacted ببینید.',
  'impact.membershipSoon': 'عضویت (به‌زودی)',

  'qr.ariaLabel': 'کد QR لینک اشتراک',
  'app.notFound': 'یافت نشد',
  'app.goHome': 'بازگشت به خانه',
  'footer.operatedPrefix': 'اداره‌شده توسط',
  'footer.operatedSuffix': '، یک سازمان غیرانتفاعی 501(c)(3) آمریکایی',
  'footer.apiDocs': 'مستندات API',

  'tiers.upgradeCta': 'ارتقا',

  'upgrade.title': 'به عضویت FreeSocks ارتقا دهید',
  'upgrade.extendTitle': 'عضویت خود را تمدید کنید',
  'upgrade.subtitle': 'پهنای باند و دستگاه‌های نامحدود. مدت و روش پرداخت را انتخاب کنید.',
  'upgrade.durationLabel': 'مدت عضویت',
  'upgrade.cryptoMinNote': (p) =>
    `پرداخت رمزارزی از ${p.months} ماه شروع می‌شود — مدت‌های کوتاه‌تر کمتر از حداقل شبکه هستند. برای مدت کوتاه‌تر روش دیگری انتخاب کنید.`,
  'upgrade.months': (p) => `${p.count} ماه`,
  'upgrade.perMonth': (p) => `${p.price}/ماه`,
  'upgrade.save': (p) => `${p.pct}٪ صرفه‌جویی`,
  'upgrade.methodLabel': 'روش پرداخت',
  'upgrade.payNowpayments': 'ارز دیجیتال',
  'upgrade.payNowpaymentsHint': 'مونرو، بیت‌کوین و بیشتر',
  'upgrade.payStripe': 'کارت',
  'upgrade.payStripeHint': 'کارت اعتباری یا نقدی',
  'upgrade.payPaypal': 'پی‌پال',
  'upgrade.payPaypalHint': 'موجودی پی‌پال یا کارت',
  'upgrade.total': (p) => `مجموع ${p.price}`,
  'upgrade.continue': 'ادامه به پرداخت',
  'upgrade.starting': 'در حال شروع پرداخت…',
  'upgrade.startFailed': 'شروع پرداخت ممکن نشد',
  'upgrade.noStoreNote': 'ما هرگز ایمیل یا اطلاعات پرداخت شما را ذخیره نمی‌کنیم.',
  'upgrade.confirmingTitle': 'در حال تأیید پرداخت شما…',
  'upgrade.confirmingBody':
    'تأیید ارز دیجیتال ممکن است چند دقیقه طول بکشد. می‌توانید این صفحه را ترک کنید — عضویت شما به‌طور خودکار فعال می‌شود.',
  'upgrade.paidTitle': 'عضویت فعال شد',
  'upgrade.paidBody': 'متشکریم! عضویت شما اکنون فعال است.',
  'upgrade.failedTitle': 'پرداخت کامل نشد',
  'upgrade.failedBody':
    'پرداخت شما انجام نشد یا مهلت پرداخت به پایان رسید. می‌توانید دوباره تلاش کنید.',

  'get.upsellTitle': 'نامحدود می‌خواهید؟',
  'get.upsellBody':
    'هر زمان خواستید به عضویت FreeSocks ارتقا دهید تا پهنای باند و دستگاه‌های نامحدود داشته باشید.',

  // --- آینه‌های اشتراک (گزینهٔ اختیاری «مشکل در اتصال») ---
  'mirror.disclosure': 'مشکل در اتصال دارید؟',
  'mirror.explainer':
    'اگر لینک اشتراک معمولی شما در محل شما وصل نمی‌شود، یک لینک آینه از پایین اضافه کنید. همان کلید را از میزبانی دیگر که ممکن است مسدود نباشد ارائه می‌دهد.',
  'mirror.addedLabel': 'لینک‌های آینهٔ شما',
  'mirror.addToAppHint':
    'هر کدام را به‌عنوان یک اشتراک اضافی در برنامه‌تان وارد کنید و سپس اتصال را امتحان کنید.',
  'mirror.regionLabel': 'منطقهٔ شما',
  'mirror.regionGlobal': 'جهانی (هر منطقه)',
  'mirror.regionNotStored': 'فقط برای انتخاب یک آینهٔ نزدیک استفاده می‌شود — ذخیره نمی‌شود.',
  'mirror.getButton': 'دریافت لینک آینه',
  'mirror.tryAnother': 'امتحان آینهٔ دیگر',
  'mirror.working': 'در حال انجام…',
  'mirror.capped': 'به حداکثر تعداد آینه‌ها رسیده‌اید.',
  'mirror.exhausted': 'در حال حاضر آینهٔ دیگری برای منطقهٔ شما موجود نیست.',
  'mirror.noSubscription': 'ابتدا کلید خود را بسازید، سپس می‌توانید آینه اضافه کنید.',
  'mirror.removeAll': 'حذف همهٔ آینه‌ها',
  'mirror.errorToast': 'افزودن آینه ممکن نشد',
  'mirror.removedToast': 'آینه‌ها حذف شدند',

  // --- نمایشگر پیکربندی خام (تنظیم دستی با حفظ E2EE) ---
  'rawconfig.disclosure': 'نمایش پیکربندی خام',
  'rawconfig.explainer':
    'پیکربندی کامل پروکسی شما، که از طریق یک کانال رمزگذاری‌شده دریافت می‌شود تا هرگز به‌صورت متن ساده از CDN عبور نکند. به‌جای استفاده از لینک اشتراک، آن را دستی در برنامه‌تان وارد کنید.',
  'rawconfig.addHint': 'این ورودی‌های سرور را به‌صورت دستی در برنامهٔ پروکسی خود وارد کنید.',

  // --- اولویت تحویل (حریم خصوصی در برابر دور زدن سانسور) ---
  'delivery.title': 'چه چیزی برایتان مهم‌تر است؟',
  'delivery.subtitle':
    'یک اولویت انتخاب کنید — فقط روی همین دستگاه ذخیره می‌شود و هر زمان می‌توانید تغییرش دهید.',
  'delivery.evadeTitle': 'اتصال پایدار',
  'delivery.evadeBody':
    'وقتی سایت‌ها در محل شما مسدود هستند بهترین گزینه است. لینک‌های پشتیبان که سخت‌تر مسدود می‌شوند را نشان می‌دهیم.',
  'delivery.privacyTitle': 'حداکثر حریم خصوصی',
  'delivery.privacyBody':
    'برای بالاترین محرمانگی بهترین گزینه است. روش‌هایی را ترجیح می‌دهیم که پیکربندی شما را از سرورهای شخص ثالث دور نگه دارد.',
  'delivery.recommended': 'پیشنهادی',
};
