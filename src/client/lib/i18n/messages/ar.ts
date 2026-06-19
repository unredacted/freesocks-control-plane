import type { Messages } from './en';

/**
 * Arabic (العربية) — RTL. First-pass translations of the critical strings;
 * missing keys fall back to English. FLAGGED FOR NATIVE-SPEAKER REVIEW.
 */
export const ar: Partial<Messages> = {
  'common.copy': 'نسخ',
  'common.copied': 'تم النسخ إلى الحافظة',
  'common.copyFailed': 'فشل النسخ — حدّد النص وانسخه يدويًا',
  'common.download': 'تنزيل',
  'common.print': 'طباعة',
  'common.cancel': 'إلغاء',
  'common.close': 'إغلاق',
  'common.retry': 'إعادة المحاولة',
  'common.loading': 'جارٍ التحميل…',
  'common.language': 'اللغة',

  'nav.getAccount': 'احصل على حساب مجاني',
  'nav.signIn': 'تسجيل الدخول',
  'nav.account': 'حسابي',

  'captcha.initial': 'أنا إنسان',
  'captcha.verifying': 'جارٍ التحقق…',
  'captcha.solved': 'تم التحقق',
  'captcha.error': 'فشل التحقق — أعد المحاولة',

  'reveal.title': 'احفظ رقم حسابك الآن',
  'reveal.subtitle':
    'هذا الرقم المكوّن من 32 خانة هو الطريقة الوحيدة لتسجيل الدخول مرة أخرى. لا يوجد بريد إلكتروني أو كلمة مرور لاستعادته. إذا فقدته، فسيضيع حسابك نهائيًا.',
  'reveal.cannotRecover': 'لا يمكننا استعادته لك — ولا حتى الدعم الفني.',
  'reveal.saveHint': 'احفظه في مدير كلمات المرور، أو اكتبه في مكان آمن وخاص.',
  'reveal.confirmCheckbox': 'لقد حفظت رقم حسابي في مكان آمن',
  'reveal.done': 'لقد حفظته',
  'reveal.leaveWarning':
    'رقم حسابك ما زال على الشاشة. إذا غادرت الآن دون حفظه، فلن تتمكن من تسجيل الدخول مرة أخرى.',

  'support.label': 'معرّف الدعم',
  'support.hint': 'شارك هذا إذا تواصلت معنا. إنه ليس رقم تسجيل دخولك ولا يمنح أي وصول.',

  'login.title': 'سجّل الدخول برقم حسابك',
  'login.subtitle':
    'أدخل رقم الحساب المكوّن من 32 خانة الذي حفظته. إنها الطريقة الوحيدة لتسجيل الدخول — لا يوجد بريد إلكتروني أو كلمة مرور للاستعادة.',
  'login.label': 'رقم الحساب',
  'login.show': 'إظهار',
  'login.hide': 'إخفاء',
  'login.submit': 'تسجيل الدخول',
  'login.submitting': 'جارٍ تسجيل الدخول…',
  'login.noAccount': 'ليس لديك رقم حساب بعد؟',
  'login.getOne': 'احصل على حساب مجاني',
  'login.failed': 'فشل تسجيل الدخول',

  'account.title': 'حسابك',
  'account.tierLabel': 'خطتك',
  'account.statusActive': 'نشط',
  'account.statusGrace': 'ينتهي قريبًا',
  'account.statusDisabled': 'منتهٍ',
  'account.regenerate': 'إنشاء مفتاح جديد',
  'account.switchBackend': 'تغيير نوع الخادم',
  'account.rotate': 'تغيير رقم الحساب',
  'account.signOut': 'تسجيل الخروج',
  'account.redeemTitle': 'لديك رمز عضوية؟',
  'account.redeemSubmit': 'استخدام الرمز',
  'account.redeemSuccess': (p) =>
    `تم الاستخدام — أنت الآن على ${p.tier} لمدة ${p.days} يومًا إضافيًا.`,
  'account.redeemFailed': 'هذا الرمز غير صالح أو تم استخدامه من قبل.',

  'renew.expiringTitle': 'عضويتك على وشك الانتهاء',
  'renew.expiredTitle': 'انتهت عضويتك',
  'renew.body':
    'FreeSocks مموّل من المجتمع — التبرعات تبقيه يعمل. لتجديد عضويتك، تبرّع أو تواصل معنا للحصول على رمز عضوية.',
  'renew.donate': 'تبرّع',
  'renew.contact': 'تواصل معنا',
  'renew.haveCode': 'لديك رمز عضوية؟ استخدمه بالأعلى.',

  'error.offline': 'يبدو أنك غير متصل. تحقق من اتصالك وأعد المحاولة.',
  'error.rateLimited': 'محاولات كثيرة جدًا. انتظر دقيقة وأعد المحاولة.',
  'error.backendUnavailable':
    'لا يوجد خادم وكيل متاح حاليًا. حسابك آمن — حاول إنشاء مفتاحك مرة أخرى بعد دقائق.',
  'error.generic': 'حدث خطأ ما. يرجى المحاولة مرة أخرى.',
  'error.captchaFailed': 'فشل التحقق البشري. أكمله وأعد المحاولة.',

  'setup.title': 'إعداد تطبيق الوكيل',
  'setup.intro': 'انسخ رابط الاشتراك بالأعلى، ثم أضفه إلى تطبيق متوافق:',
  'setup.android': 'أندرويد',
  'setup.ios': 'آيفون / آيباد',
  'setup.windows': 'ويندوز',
  'setup.desktop': 'ماك / لينكس',
  'setup.step.install': 'ثبّت التطبيق',
  'setup.step.import': 'افتحه، أضف اشتراكًا/ملفًا شخصيًا، والصق رابطك',
  'setup.step.connect': 'اختر خادمًا واتصل',
  'setup.qrHint': 'أو امسح رمز QR هذا بهاتفك لنقل الرابط.',

  'common.working': 'جارٍ التنفيذ…',
  'common.reload': 'إعادة التحميل',
  'common.deviceCount': (p) =>
    p.count === 1 ? 'جهاز واحد' : p.count === 2 ? 'جهازان' : `${p.count} أجهزة`,
  'login.success': 'تم تسجيل الدخول',
  'login.sessionExpired': 'يرجى تسجيل الدخول مرة أخرى — ربما انتهت جلستك.',

  'captcha.failedTitle': 'تعذّر إكمال التحقق البشري.',
  'captcha.failedBody':
    'يجري هذا التحقق على جهازك ولم يكتمل. عادةً ما تكون هذه مشكلة في الشبكة، وليست خطأً منك.',
  'captcha.failedTip1': 'انتظر لحظة ثم حاول مرة أخرى',
  'captcha.failedTip2': 'جرّب شبكة أخرى — أو استخدم VPN/بروكسي إذا كانت المواقع محجوبة في منطقتك',
  'captcha.failedTip3': 'ما زالت المشكلة قائمة؟ جرّب نافذة تصفح خاص أو عطّل إضافات المتصفح',

  'account.redeemAriaLabel': 'رمز العضوية',
  'account.switchTo': (p) => `التبديل إلى ${p.label}`,
  'account.devicesTitle': 'الأجهزة المتصلة',
  'account.lastSeen': (p) => `آخر اتصال ${p.date}`,
  'account.noSubTitle': 'لا يوجد اشتراك بعد',
  'account.noSubBody': 'أنشئ اشتراكك الأول للحصول على رابط يمكنك استخدامه في أي تطبيق VPN متوافق.',
  'account.createSub': 'إنشاء اشتراك',
  'account.creating': 'جارٍ الإنشاء…',
  'account.rotateTitle': 'تغيير رقم الحساب؟',
  'account.rotateBody':
    'سيتم إنشاء رقم جديد من 32 خانة وعرضه مرة واحدة فقط. يتوقف رقمك الحالي عن العمل فورًا، ويفقد أي شخص يملكه إمكانية الوصول. افعل هذا إذا كان رقمك قد تسرّب.',
  'account.rotateConfirm': 'نعم، غيّره',
  'account.rotating': 'جارٍ التغيير…',
  'account.rotateFailedTitle': 'تعذّر تغيير رقم الحساب',
  'account.freeTierTitle': 'أنت على الخطة المجانية',
  'account.freeTierBody':
    'تمنحك عضوية FreeSocks أجهزة وسعة استخدام غير محدودة. كما تُبقي التبرعات الحسابات المجانية تعمل.',
  'account.refreshMembership': 'دفعت بالفعل؟ تحقّق من عضويتي',
  'account.refreshing': 'جارٍ التحديث…',
  'account.regenSuccessTitle': 'تم إنشاء رابط اشتراك جديد',
  'account.regenSuccessBody':
    'أعد استيراده على كل أجهزتك. يظل الرابط القديم يعمل لمدة 24 ساعة إضافية.',
  'account.regenFailedTitle': 'تعذّر إنشاء مفتاح جديد',
  'account.switchSuccessTitle': (p) => `تم التبديل إلى ${p.tier}`,
  'account.switchSuccessBodyGrace':
    'أعد استيراد رابط الاشتراك الجديد على كل جهاز. يظل الاشتراك القديم يعمل لمدة 24 ساعة إضافية.',
  'account.switchSuccessBody': 'أعد استيراد رابط الاشتراك الجديد على كل جهاز.',
  'account.switchFailedTitle': 'تعذّر تبديل نوع الخادم',
  'account.refreshWelcome': (p) => `مرحبًا بك في ${p.tier}`,
  'account.refreshNoneTitle': 'لم يتم العثور على عضوية نشطة بعد',
  'account.refreshNoneBody': 'إذا كنت قد دفعت للتو، فانتظر لحظة وحاول مرة أخرى.',
  'account.refreshFailedTitle': 'تعذّر تحديث العضوية',
  'account.graceTitle': 'حسابك في فترة سماح',
  'account.graceBody':
    'انتهت عضويتك، وسيُقيَّد هذا الحساب قريبًا. جدّد — تبرّع أو استخدم رمز عضوية بالأسفل — للحفاظ على خطتك.',
  'account.disabledTitle': 'حسابك معطّل حاليًا',
  'account.disabledBody':
    'المفاتيح الجديدة والتغييرات متوقفة على هذا الحساب. استخدم رمز عضوية بالأسفل لإعادة تفعيله، أو تواصل مع الدعم وشارك معرّف الدعم الخاص بك.',

  'hero.titleDefault': 'اشتراكك',
  'hero.eyebrowAccessKey': 'مفتاح الوصول الخاص بك',
  'hero.urlLabelSubscription': 'رابط الاشتراك',
  'hero.urlLabelAccessKey': 'مفتاح الوصول',
  'hero.tierLine': (p) => `الفئة ${p.tier}`,
  'hero.viaLine': (p) => `عبر ${p.backend}`,
  'hero.copyUrl': 'نسخ الرابط',
  'hero.copiedShort': 'تم النسخ',
  'hero.qrShow': 'QR',
  'hero.qrHide': 'إخفاء',
  'hero.scanPhone': 'امسحه بهاتفك',
  'hero.scanOther': 'امسحه بجهاز آخر',
  'hero.scanFallback': 'امسح الرابط الاحتياطي بجهاز آخر',
  'hero.fallbackLabel': 'رابط احتياطي',
  'hero.fallbackHint': 'استخدم هذا إذا حُجب الرابط الرئيسي',
  'hero.fallbackQrAria': 'عرض رمز QR للرابط الاحتياطي',
  'hero.downloaded': (p) => `تم تنزيل ${p.filename}`,
  'hero.traffic': 'البيانات',
  'hero.unlimited': 'غير محدود',
  'hero.configBelowNote':
    'إعدادك الكامل في الأسفل — أضِف الخوادم يدويًا. حفاظًا على الخصوصية، لا يُعرض هنا رابط الاشتراك ذاتي التحديث (لأن تطبيقك سيجلبه عبر شبكة CDN).',
  'hero.usedSoFar': (p) => `${p.amount} مستخدمة حتى الآن`,
  'hero.leftThisPeriod': (p) => `${p.amount} متبقية لهذه الفترة.`,
  'hero.nearlyOut': (p) => `أوشكت على النفاد — تبقّى ${p.amount} فقط لهذه الفترة.`,
  'hero.expires': 'تاريخ الانتهاء',
  'hero.noExpiry': 'بلا انتهاء',
  'hero.expiresToday': 'ينتهي اليوم',
  'hero.daysRemaining': (p) =>
    p.count === 1 ? 'يوم واحد متبقٍ' : p.count === 2 ? 'يومان متبقيان' : `${p.count} أيام متبقية`,
  'hero.expiredDaysAgo': (p) =>
    p.count === 1
      ? 'انتهى منذ يوم واحد'
      : p.count === 2
        ? 'انتهى منذ يومين'
        : `انتهى منذ ${p.count} أيام`,

  'regen.title': 'إعادة إنشاء الاشتراك؟',
  'regen.body': (p) =>
    `سيُستبدل رابط اشتراكك الحالي (المنتهي بـ …${p.suffix}) برابط جديد. يصبح الرابط القديم للقراءة فقط لمدة 24 ساعة ثم يُحذف.`,
  'regen.point1': 'يظل مفتاحك الحالي قابلاً للاستخدام خلال الـ 24 ساعة القادمة',
  'regen.point2': 'ستحتاج إلى إعادة استيراد الرابط الجديد على كل جهاز من أجهزتك',
  'regen.pointDevices': (p) =>
    p.count === 1
      ? 'لديك حاليًا جهاز واحد متصل — سيحتاج إلى الرابط الجديد'
      : `لديك حاليًا ${p.count} أجهزة متصلة — ستحتاج كلها إلى الرابط الجديد`,
  'regen.confirm': 'إعادة الإنشاء',
  'regen.working': 'جارٍ الإنشاء…',

  'switch.title': (p) => `التبديل إلى ${p.to}؟`,
  'switch.body': (p) =>
    `سيُستبدل اشتراكك الحالي على ${p.from} باشتراك جديد على ${p.to}. يظل الاشتراك القديم يعمل لمدة 24 ساعة حتى تعيد الاستيراد على كل جهاز قبل توقفه.`,
  'switch.point1': (p) => `يُصدر رابط اشتراك جديد على خادم ${p.to}`,
  'switch.point2': (p) => `يظل رابط ${p.from} الحالي يعمل لمدة 24 ساعة ثم يُحذف`,
  'switch.point3': 'ستحتاج إلى إعادة استيراد الرابط الجديد في كل تطبيق VPN تستخدمه',
  'switch.pointDevices': (p) =>
    p.count === 1
      ? 'لديك حاليًا جهاز واحد متصل — أعد الاستيراد عليه'
      : `لديك حاليًا ${p.count} أجهزة متصلة — أعد الاستيراد عليها كلها`,
  'switch.confirm': (p) => `التبديل إلى ${p.to}`,
  'switch.working': 'جارٍ التبديل…',

  'get.badge': 'حساب مجاني',
  'get.title': 'احصل على حساب FreeSocks',
  'get.introTwoSteps': 'خطوتان سريعتان: أكمل التحقق البشري لإنشاء حساب مجاني، ثم أنشئ اشتراكك.',
  'get.step1Title': 'أنشئ حسابك',
  'get.chooseBackend': 'اختر نوع الخادم',
  'get.backendAria': 'نوع الخادم',
  'get.backendMultiProtocol': 'متعدد البروتوكولات (VLESS وTrojan وShadowsocks)',
  'get.backendShadowsocks': 'Shadowsocks عبر Outline',
  'get.createAccount': 'إنشاء حسابي',
  'get.freeAccountNote':
    'الحسابات المجانية صالحة لمدة 30 يومًا ومحدودة بجهاز واحد. بلا بريد إلكتروني أو كلمة مرور.',
  'get.accountReady': 'حسابك جاهز.',
  'get.step2Title': 'أنشئ اشتراكك',
  'get.step2Intro': 'أنشئ اشتراك وكيل للحصول على رابط يمكنك لصقه في أي تطبيق VPN متوافق.',
  'get.manageHintPrefix': 'أدر هذا الاشتراك في أي وقت من',
  'get.manageLinkLabel': 'حسابك',
  'get.subErrorSafePrefix': 'حسابك آمن. يمكنك إنشاء الاشتراك لاحقًا من',
  'get.subErrorSafeSuffix': 'عندما يتوفر خادم.',
  'get.createSubToastTitle': 'تم إنشاء الاشتراك',
  'get.createSubToastBody': 'انسخ الرابط في تطبيق VPN لديك، أو امسح رمز QR.',
  'get.createAccountFailedTitle': 'تعذّر إنشاء الحساب',
  'get.createSubFailedTitle': 'تعذّر إنشاء الاشتراك',
  'get.haveAccountPrefix': 'لديك حساب بالفعل؟',
  'get.lostNumberHint': 'فقدت رقم حسابك قبل حفظه؟ يمكنك التبديل إلى رقم جديد —',
  'get.lostNumberLinkLabel': 'غيّره من صفحة حسابك',

  'tiers.title': 'الفئات',
  'tiers.subtitle': 'ما تتضمنه كل فئة.',
  'tiers.yourTier': 'فئتك',
  'tiers.gbPerMonth': (p) => `${p.gb} غيغابايت / شهر`,
  'tiers.validity30': 'مفتاح لمدة 30 يومًا',
  'tiers.validityContinuous': 'مستمر',
  'tiers.mirrors': 'روابط بديلة',
  'tiers.comingSoon': 'قريبًا',
  'tiers.comingSoonTitle': 'التسجيل في العضوية قادم قريبًا',

  'impact.title': 'التبرعات تدعم Unredacted',
  'impact.body':
    'Unredacted منظمة أمريكية غير ربحية 501(c)(3). وFreeSocks أحد مشاريعها. التبرعات تموّل هذا العمل. اطّلع على تفاصيله في موقع Unredacted.',
  'impact.membershipSoon': 'العضوية (قريبًا)',

  'qr.ariaLabel': 'رمز QR لرابط الاشتراك',
  'app.skipToContent': 'تخطَّ إلى المحتوى',
  'app.notFound': 'غير موجود',
  'app.goHome': 'العودة إلى الرئيسية',
  'footer.operatedPrefix': 'يديره',
  'footer.operatedSuffix': '، منظمة أمريكية غير ربحية 501(c)(3)',
  'footer.apiDocs': 'وثائق API',

  'tiers.upgradeCta': 'ترقية',

  'upgrade.title': 'الترقية إلى عضوية FreeSocks',
  'upgrade.extendTitle': 'مدّد عضويتك',
  'upgrade.subtitle': 'نطاق ترددي وأجهزة غير محدودة. اختر المدة وطريقة الدفع.',
  'upgrade.durationLabel': 'مدة العضوية',
  'upgrade.cryptoMinNote': (p) =>
    `تبدأ مدفوعات العملات المشفّرة من ${p.months} أشهر — المدد الأقصر أقل من الحد الأدنى للشبكة. اختر طريقة أخرى للمدد الأقصر.`,
  'upgrade.months': (p) => `${p.count} شهر`,
  'upgrade.perMonth': (p) => `${p.price}/شهر`,
  'upgrade.save': (p) => `وفّر ${p.pct}٪`,
  'upgrade.methodLabel': 'طريقة الدفع',
  'upgrade.payNowpayments': 'العملات المشفرة',
  'upgrade.payNowpaymentsHint': 'مونيرو والبيتكوين والمزيد',
  'upgrade.payStripe': 'بطاقة',
  'upgrade.payStripeHint': 'بطاقة ائتمان أو خصم',
  'upgrade.payPaypal': 'باي بال',
  'upgrade.payPaypalHint': 'رصيد باي بال أو بطاقة',
  'upgrade.total': (p) => `الإجمالي ${p.price}`,
  'upgrade.continue': 'المتابعة إلى الدفع',
  'upgrade.starting': 'جارٍ بدء الدفع…',
  'upgrade.startFailed': 'تعذّر بدء الدفع',
  'upgrade.noStoreNote': 'لا نخزّن أبدًا بريدك الإلكتروني أو تفاصيل الدفع.',
  'upgrade.confirmingTitle': 'جارٍ تأكيد دفعتك…',
  'upgrade.confirmingBody':
    'قد يستغرق تأكيد العملات المشفرة بضع دقائق. يمكنك مغادرة هذه الصفحة — ستُفعّل عضويتك تلقائيًا.',
  'upgrade.paidTitle': 'العضوية مفعّلة',
  'upgrade.paidBody': 'شكرًا لك! عضويتك مفعّلة الآن.',
  'upgrade.failedTitle': 'لم يكتمل الدفع',
  'upgrade.failedBody': 'لم تتم عملية الدفع، أو انتهت صلاحية الجلسة. يمكنك المحاولة مرة أخرى.',

  'get.upsellTitle': 'تريد بلا حدود؟',
  'get.upsellBody':
    'يمكنك الترقية إلى عضوية FreeSocks في أي وقت للحصول على نطاق ترددي وأجهزة غير محدودة.',

  // --- مرايا الاشتراك (خيار «تواجه مشكلة في الاتصال؟») ---
  'mirror.disclosure': 'تواجه مشكلة في الاتصال؟',
  'mirror.explainer':
    'إذا كان رابط الاشتراك العادي لا يتصل في مكانك، أضِف رابط مرآة أدناه. يقدّم المفتاح نفسه من مضيف آخر قد لا يكون محجوبًا.',
  'mirror.addedLabel': 'روابط المرآة الخاصة بك',
  'mirror.addToAppHint': 'أضِف كل رابط كاشتراك إضافي في تطبيقك ثم حاول الاتصال.',
  'mirror.regionLabel': 'منطقتك',
  'mirror.regionGlobal': 'عالمي (أي منطقة)',
  'mirror.regionNotStored': 'يُستخدم فقط لاختيار مرآة قريبة — ولا يتم تخزينه.',
  'mirror.getButton': 'احصل على رابط مرآة',
  'mirror.tryAnother': 'جرّب مرآة أخرى',
  'mirror.working': 'جارٍ التنفيذ…',
  'mirror.capped': 'لقد أضفت الحد الأقصى من المرايا.',
  'mirror.exhausted': 'لا تتوفر مرايا أخرى لمنطقتك حاليًا.',
  'mirror.noSubscription': 'أنشئ مفتاحك أولًا، ثم يمكنك إضافة مرآة.',
  'mirror.removeAll': 'إزالة كل المرايا',
  'mirror.errorToast': 'تعذّر إضافة مرآة',
  'mirror.removedToast': 'تمت إزالة المرايا',

  // --- عارض الإعداد الخام (إعداد يدوي مع الحفاظ على التشفير) ---
  'rawconfig.disclosure': 'إظهار الإعداد الخام',
  'rawconfig.title': 'إعدادك',
  'rawconfig.explainer':
    'إعداد الوكيل الكامل الخاص بك، يُجلب عبر قناة مشفّرة بحيث لا يمر أبدًا عبر شبكة CDN كنص عادي. انسخه يدويًا إلى تطبيقك بدلًا من استخدام رابط الاشتراك.',
  'rawconfig.addHint': 'الصق إدخالات الخوادم هذه في تطبيق الوكيل يدويًا.',

  // --- تفضيل التسليم (الخصوصية مقابل تجاوز الحجب) ---
  'delivery.title': 'ما الأهم بالنسبة لك؟',
  'delivery.subtitle': 'اختر أولوية — تُحفظ على هذا الجهاز فقط، ويمكنك تغييرها في أي وقت.',
  'delivery.evadeTitle': 'البقاء متصلاً',
  'delivery.evadeBody':
    'الأفضل عندما تكون المواقع محجوبة في مكانك. سنعرض روابط احتياطية يصعب حجبها.',
  'delivery.privacyTitle': 'أقصى خصوصية',
  'delivery.privacyBody':
    'الأفضل لأقوى سرية. سنفضّل إعدادًا يُبقي تهيئتك بعيدًا عن خوادم الأطراف الثالثة.',
  'delivery.recommended': 'موصى به',
};
