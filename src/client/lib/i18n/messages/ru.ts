import type { Messages } from './en';

/**
 * Russian (Русский). First-pass translations of the critical strings; missing
 * keys fall back to English. FLAGGED FOR NATIVE-SPEAKER REVIEW.
 */
export const ru: Partial<Messages> = {
  'common.copy': 'Копировать',
  'common.copied': 'Скопировано в буфер обмена',
  'common.copyFailed': 'Не удалось скопировать — выделите текст и скопируйте вручную',
  'common.download': 'Скачать',
  'common.print': 'Печать',
  'common.cancel': 'Отмена',
  'common.close': 'Закрыть',
  'common.retry': 'Повторить',
  'common.loading': 'Загрузка…',
  'common.language': 'Язык',

  'nav.getAccount': 'Получить бесплатный аккаунт',
  'nav.signIn': 'Войти',
  'nav.account': 'Мой аккаунт',

  'captcha.initial': 'Я человек',
  'captcha.verifying': 'Проверка…',
  'captcha.solved': 'Проверено',
  'captcha.error': 'Проверка не удалась — повторите',

  'reveal.title': 'Сохраните номер аккаунта сейчас',
  'reveal.subtitle':
    'Этот 32-значный номер — единственный способ снова войти. Нет ни почты, ни пароля для восстановления. Если вы его потеряете, аккаунт будет утрачен навсегда.',
  'reveal.cannotRecover': 'Мы не сможем его восстановить — даже поддержка не сможет.',
  'reveal.saveHint': 'Сохраните его в менеджере паролей или запишите в надёжном личном месте.',
  'reveal.confirmCheckbox': 'Я сохранил номер аккаунта в надёжном месте',
  'reveal.done': 'Я сохранил',
  'reveal.leaveWarning':
    'Номер аккаунта всё ещё на экране. Если вы уйдёте сейчас, не сохранив его, вы не сможете снова войти.',

  'support.label': 'ID для поддержки',
  'support.hint': 'Сообщите его, если обращаетесь к нам. Это не номер для входа и не даёт доступа.',

  'login.title': 'Войдите по номеру аккаунта',
  'login.subtitle':
    'Введите 32-значный номер аккаунта, который вы сохранили. Это единственный способ войти — нет почты или пароля для восстановления.',
  'login.label': 'Номер аккаунта',
  'login.show': 'Показать',
  'login.hide': 'Скрыть',
  'login.submit': 'Войти',
  'login.submitting': 'Вход…',
  'login.noAccount': 'Ещё нет номера аккаунта?',
  'login.getOne': 'Получить бесплатный аккаунт',
  'login.failed': 'Не удалось войти',

  'account.title': 'Ваш аккаунт',
  'account.tierLabel': 'Ваш план',
  'account.statusActive': 'Активен',
  'account.statusGrace': 'Скоро истекает',
  'account.statusDisabled': 'Истёк',
  'account.regenerate': 'Создать новый ключ',
  'account.switchBackend': 'Сменить тип сервера',
  'account.rotate': 'Сменить номер аккаунта',
  'account.signOut': 'Выйти',
  'account.redeemTitle': 'Есть код членства?',
  'account.redeemSubmit': 'Активировать код',
  'account.redeemSuccess': (p) => `Активировано — теперь у вас ${p.tier} ещё на ${p.days} дн.`,
  'account.redeemFailed': 'Этот код недействителен или уже использован.',

  'renew.expiringTitle': 'Ваше членство скоро истекает',
  'renew.expiredTitle': 'Ваше членство истекло',
  'renew.body':
    'FreeSocks существует на пожертвования. Чтобы продлить членство, сделайте пожертвование или свяжитесь с нами для получения кода членства.',
  'renew.donate': 'Пожертвовать',
  'renew.contact': 'Связаться с нами',
  'renew.haveCode': 'Есть код членства? Активируйте его выше.',

  'error.offline': 'Похоже, вы офлайн. Проверьте подключение и повторите попытку.',
  'error.rateLimited': 'Слишком много попыток. Подождите минуту и повторите.',
  'error.backendUnavailable':
    'Сейчас нет доступного прокси-сервера. Ваш аккаунт в безопасности — попробуйте создать ключ через несколько минут.',
  'error.generic': 'Что-то пошло не так. Повторите попытку.',
  'error.captchaFailed': 'Проверка не пройдена. Завершите её и повторите попытку.',

  'setup.title': 'Настройте прокси-приложение',
  'setup.intro': 'Скопируйте ссылку подписки выше и добавьте её в совместимое приложение:',
  'setup.qrHint': 'Или отсканируйте этот QR-код телефоном, чтобы перенести ссылку.',
};
