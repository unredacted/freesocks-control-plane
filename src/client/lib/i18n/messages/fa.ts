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
  'setup.qrHint': 'یا این کد QR را با تلفن خود اسکن کنید تا لینک منتقل شود.',
};
