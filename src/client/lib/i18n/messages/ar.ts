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
  'setup.qrHint': 'أو امسح رمز QR هذا بهاتفك لنقل الرابط.',
};
