import type { Messages } from './en';

/**
 * Russian (Русский). First-pass translations of the critical strings; missing
 * keys fall back to English. FLAGGED FOR NATIVE-SPEAKER REVIEW.
 */

/** Russian 3-form plural: 1 день / 2 дня / 5 дней (with the 11–14 exception). */
const plural = (n: number, [one, few, many]: [string, string, string]): string => {
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
  return many;
};

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
  'setup.android': 'Android',
  'setup.ios': 'iPhone / iPad',
  'setup.windows': 'Windows',
  'setup.desktop': 'macOS / Linux',
  'setup.step.install': 'Установите приложение',
  'setup.step.import': 'Откройте его, добавьте подписку/профиль и вставьте свою ссылку',
  'setup.step.connect': 'Выберите сервер и подключитесь',
  'setup.qrHint': 'Или отсканируйте этот QR-код телефоном, чтобы перенести ссылку.',

  'common.working': 'Выполняется…',
  'common.reload': 'Перезагрузить',
  'common.deviceCount': (p) =>
    `${p.count} ${plural(Number(p.count), ['устройство', 'устройства', 'устройств'])}`,
  'login.success': 'Вы вошли',
  'login.sessionExpired': 'Пожалуйста, войдите снова — возможно, ваша сессия завершилась.',

  'captcha.failedTitle': 'Не удалось пройти проверку.',
  'captcha.failedBody':
    'Проверка выполняется на вашем устройстве и не завершилась. Обычно это проблема с сетью, а не ваша ошибка.',
  'captcha.failedTip1': 'Подождите немного и попробуйте снова',
  'captcha.failedTip2':
    'Попробуйте другую сеть — или VPN/прокси, если сайты заблокированы в вашем регионе',
  'captcha.failedTip3':
    'Всё ещё не работает? Откройте приватное окно или отключите расширения браузера',

  'account.redeemAriaLabel': 'Код членства',
  'account.switchTo': (p) => `Перейти на ${p.label}`,
  'account.devicesTitle': 'Подключённые устройства',
  'account.lastSeen': (p) => `Последняя активность ${p.date}`,
  'account.noSubTitle': 'Подписки пока нет',
  'account.noSubBody':
    'Создайте первую подписку, чтобы получить ссылку для любого совместимого VPN-клиента.',
  'account.createSub': 'Создать подписку',
  'account.creating': 'Создание…',
  'account.rotateTitle': 'Сменить номер аккаунта?',
  'account.rotateBody':
    'Будет создан новый 32-значный номер, показанный только один раз. Текущий номер сразу перестанет работать — все, у кого он есть, потеряют доступ. Делайте это, если номер мог утечь.',
  'account.rotateConfirm': 'Да, сменить',
  'account.rotating': 'Смена…',
  'account.rotateFailedTitle': 'Не удалось сменить номер аккаунта',
  'account.freeTierTitle': 'Вы на бесплатном тарифе',
  'account.freeTierBody':
    'Членство FreeSocks открывает неограниченное число устройств и трафик. Пожертвования также поддерживают бесплатные аккаунты.',
  'account.refreshMembership': 'Уже оплатили? Проверить членство',
  'account.refreshing': 'Обновление…',
  'account.regenSuccessTitle': 'Создана новая ссылка подписки',
  'account.regenSuccessBody':
    'Импортируйте её заново на каждом устройстве. Старая ссылка работает ещё 24 часа.',
  'account.regenFailedTitle': 'Не удалось создать новый ключ',
  'account.switchSuccessTitle': (p) => `Вы перешли на ${p.tier}`,
  'account.switchSuccessBodyGrace':
    'Импортируйте новую ссылку подписки на каждом устройстве. Старая подписка работает ещё 24 часа.',
  'account.switchSuccessBody': 'Импортируйте новую ссылку подписки на каждом устройстве.',
  'account.switchFailedTitle': 'Не удалось сменить тип сервера',
  'account.refreshWelcome': (p) => `Добро пожаловать в ${p.tier}`,
  'account.refreshNoneTitle': 'Активное членство пока не найдено',
  'account.refreshNoneBody': 'Если вы только что оплатили, подождите немного и повторите.',
  'account.refreshFailedTitle': 'Не удалось обновить членство',
  'account.graceTitle': 'Аккаунт в льготном периоде',
  'account.graceBody':
    'Членство закончилось, и скоро аккаунт будет ограничен. Продлите его — пожертвуйте или активируйте код членства ниже — чтобы сохранить тариф.',
  'account.disabledTitle': 'Аккаунт сейчас отключён',
  'account.disabledBody':
    'Новые ключи и изменения для этого аккаунта приостановлены. Активируйте код членства ниже, чтобы вернуть доступ, или напишите в поддержку, указав свой ID для поддержки.',

  'hero.titleDefault': 'Ваша подписка',
  'hero.eyebrowAccessKey': 'Ваш ключ доступа',
  'hero.urlLabelSubscription': 'Ссылка подписки',
  'hero.urlLabelAccessKey': 'Ключ доступа',
  'hero.tierLine': (p) => `Тариф ${p.tier}`,
  'hero.viaLine': (p) => `через ${p.backend}`,
  'hero.copyUrl': 'Копировать ссылку',
  'hero.copiedShort': 'Скопировано',
  'hero.qrShow': 'QR',
  'hero.qrHide': 'Скрыть',
  'hero.scanPhone': 'Отсканируйте телефоном',
  'hero.scanOther': 'Отсканируйте другим устройством',
  'hero.scanFallback': 'Отсканируйте резервную ссылку другим устройством',
  'hero.fallbackLabel': 'Резервная ссылка',
  'hero.fallbackHint': 'Используйте её, если основную ссылку заблокируют',
  'hero.fallbackQrAria': 'Показать QR-код резервной ссылки',
  'hero.downloaded': (p) => `Скачан файл ${p.filename}`,
  'hero.traffic': 'Трафик',
  'hero.unlimited': 'Безлимит',
  'hero.configBelowNote':
    'Ваша полная конфигурация ниже — добавьте серверы вручную. Ради приватности автообновляемая ссылка-подписка здесь не показывается (приложение загружало бы её через CDN).',
  'hero.usedSoFar': (p) => `Использовано ${p.amount}`,
  'hero.leftThisPeriod': (p) => `Осталось ${p.amount} в этом периоде.`,
  'hero.nearlyOut': (p) => `Почти исчерпано — осталось всего ${p.amount} в этом периоде.`,
  'hero.expires': 'Истекает',
  'hero.noExpiry': 'Бессрочно',
  'hero.expiresToday': 'Истекает сегодня',
  'hero.daysRemaining': (p) =>
    `Осталось ${p.count} ${plural(Number(p.count), ['день', 'дня', 'дней'])}`,
  'hero.expiredDaysAgo': (p) =>
    `Истекла ${p.count} ${plural(Number(p.count), ['день', 'дня', 'дней'])} назад`,

  'regen.title': 'Пересоздать подписку?',
  'regen.body': (p) =>
    `Текущая ссылка подписки (оканчивается на …${p.suffix}) будет заменена новой. Старая ссылка станет доступна только для чтения на 24 часа, затем будет удалена.`,
  'regen.point1': 'Текущий ключ продолжит работать ближайшие 24 часа',
  'regen.point2': 'Новую ссылку нужно будет заново импортировать на каждом устройстве',
  'regen.pointDevices': (p) =>
    `Сейчас подключено ${p.count} ${plural(Number(p.count), ['устройство', 'устройства', 'устройств'])} — всем понадобится новая ссылка`,
  'regen.confirm': 'Пересоздать',
  'regen.working': 'Пересоздание…',

  'switch.title': (p) => `Перейти на ${p.to}?`,
  'switch.body': (p) =>
    `Текущая подписка ${p.from} будет заменена новой подпиской ${p.to}. Старая подписка работает ещё 24 часа, чтобы вы успели переимпортировать ссылку на всех устройствах.`,
  'switch.point1': (p) => `Новая ссылка подписки выпускается на сервере ${p.to}`,
  'switch.point2': (p) => `Текущая ссылка ${p.from} работает ещё 24 часа, затем удаляется`,
  'switch.point3': 'Новую ссылку нужно заново импортировать в каждом VPN-клиенте',
  'switch.pointDevices': (p) =>
    `Сейчас подключено ${p.count} ${plural(Number(p.count), ['устройство', 'устройства', 'устройств'])} — переимпортируйте на всех`,
  'switch.confirm': (p) => `Перейти на ${p.to}`,
  'switch.working': 'Переход…',

  'get.badge': 'Бесплатный аккаунт',
  'get.title': 'Получите аккаунт FreeSocks',
  'get.introTwoSteps':
    'Два быстрых шага: пройдите проверку, чтобы создать бесплатный аккаунт, затем создайте подписку.',
  'get.step1Title': 'Создайте аккаунт',
  'get.chooseBackend': 'Выберите тип сервера',
  'get.backendAria': 'Тип сервера',
  'get.backendMultiProtocol': 'Мультипротокол (VLESS, Trojan, Shadowsocks)',
  'get.backendShadowsocks': 'Shadowsocks через Outline',
  'get.createAccount': 'Создать аккаунт',
  'get.freeAccountNote':
    'Бесплатные аккаунты действуют 30 дней и ограничены одним устройством. Без почты и пароля.',
  'get.accountReady': 'Ваш аккаунт готов.',
  'get.step2Title': 'Создайте подписку',
  'get.step2Intro':
    'Создайте прокси-подписку, чтобы получить ссылку для любого совместимого VPN-клиента.',
  'get.manageHintPrefix': 'Управляйте этой подпиской в любое время из',
  'get.manageLinkLabel': 'вашего аккаунта',
  'get.subErrorSafePrefix': 'Ваш аккаунт в безопасности. Подписку можно создать позже из',
  'get.subErrorSafeSuffix': 'когда сервер станет доступен.',
  'get.createSubToastTitle': 'Подписка создана',
  'get.createSubToastBody': 'Скопируйте ссылку в VPN-клиент или отсканируйте QR-код.',
  'get.createAccountFailedTitle': 'Не удалось создать аккаунт',
  'get.createSubFailedTitle': 'Не удалось создать подписку',
  'get.haveAccountPrefix': 'Уже есть аккаунт?',
  'get.lostNumberHint': 'Потеряли номер аккаунта, не успев сохранить? Можно получить новый —',
  'get.lostNumberLinkLabel': 'смените его на странице аккаунта',

  'tiers.title': 'Тарифы',
  'tiers.subtitle': 'Что входит в каждый тариф.',
  'tiers.yourTier': 'Ваш тариф',
  'tiers.gbPerMonth': (p) => `${p.gb} ГБ / месяц`,
  'tiers.validity30': 'Ключ на 30 дней',
  'tiers.validityContinuous': 'Непрерывно',
  'tiers.mirrors': 'Резервные ссылки',
  'tiers.comingSoon': 'Скоро',
  'tiers.comingSoonTitle': 'Оформление членства появится скоро',

  'impact.title': 'Пожертвования поддерживают Unredacted',
  'impact.body':
    'Unredacted — американская некоммерческая организация 501(c)(3). FreeSocks — один из её проектов. Работа финансируется пожертвованиями. Подробности — на сайте Unredacted.',
  'impact.membershipSoon': 'Членство (скоро)',

  'qr.ariaLabel': 'QR-код ссылки подписки',
  'app.skipToContent': 'Перейти к содержимому',
  'app.notFound': 'Страница не найдена',
  'app.goHome': 'На главную',
  'footer.operatedPrefix': 'Управляется',
  'footer.operatedSuffix': ' — американской некоммерческой организацией 501(c)(3)',
  'footer.apiDocs': 'Документация API',

  'tiers.upgradeCta': 'Оформить',

  'upgrade.title': 'Оформить членство FreeSocks',
  'upgrade.extendTitle': 'Продлить членство',
  'upgrade.subtitle': 'Безлимитный трафик и устройства. Выберите срок и способ оплаты.',
  'upgrade.durationLabel': 'Срок членства',
  'upgrade.cryptoMinNote': (p) =>
    `Оплата криптовалютой — от ${p.months} мес.; более короткие сроки ниже сетевого минимума. Для коротких сроков выберите другой способ.`,
  'upgrade.months': (p) => `${p.count} мес.`,
  'upgrade.perMonth': (p) => `${p.price}/мес`,
  'upgrade.save': (p) => `скидка ${p.pct}%`,
  'upgrade.methodLabel': 'Способ оплаты',
  'upgrade.payNowpayments': 'Криптовалюта',
  'upgrade.payNowpaymentsHint': 'Monero, Bitcoin и другие',
  'upgrade.payStripe': 'Карта',
  'upgrade.payStripeHint': 'Кредитная или дебетовая карта',
  'upgrade.payPaypal': 'PayPal',
  'upgrade.payPaypalHint': 'Баланс PayPal или карта',
  'upgrade.total': (p) => `Итого ${p.price}`,
  'upgrade.continue': 'Перейти к оплате',
  'upgrade.starting': 'Начинаем оплату…',
  'upgrade.startFailed': 'Не удалось начать оплату',
  'upgrade.noStoreNote': 'Мы никогда не храним вашу почту или платёжные данные.',
  'upgrade.confirmingTitle': 'Подтверждаем оплату…',
  'upgrade.confirmingBody':
    'Подтверждение криптовалюты может занять несколько минут. Можете покинуть страницу — членство активируется автоматически.',
  'upgrade.paidTitle': 'Членство активно',
  'upgrade.paidBody': 'Спасибо! Ваше членство теперь активно.',
  'upgrade.failedTitle': 'Оплата не завершена',
  'upgrade.failedBody': 'Платёж не прошёл или срок оплаты истёк. Вы можете попробовать снова.',

  'get.upsellTitle': 'Хотите без лимитов?',
  'get.upsellBody':
    'В любой момент оформите членство FreeSocks ради безлимитного трафика и устройств.',

  // --- зеркала подписки (вариант «Проблемы с подключением?») ---
  'mirror.disclosure': 'Проблемы с подключением?',
  'mirror.explainer':
    'Если обычная ссылка-подписка не подключается в вашем регионе, добавьте зеркальную ссылку ниже. Она отдаёт тот же ключ с другого хоста, который может быть не заблокирован.',
  'mirror.addedLabel': 'Ваши зеркальные ссылки',
  'mirror.addToAppHint':
    'Добавьте каждую как отдельную подписку в приложении и попробуйте подключиться.',
  'mirror.regionLabel': 'Ваш регион',
  'mirror.regionGlobal': 'Глобально (любой регион)',
  'mirror.regionNotStored': 'Используется только для выбора ближайшего зеркала — не сохраняется.',
  'mirror.getButton': 'Получить зеркальную ссылку',
  'mirror.tryAnother': 'Попробовать другое зеркало',
  'mirror.working': 'Выполняется…',
  'mirror.capped': 'Вы добавили максимальное число зеркал.',
  'mirror.exhausted': 'Сейчас для вашего региона больше нет доступных зеркал.',
  'mirror.noSubscription': 'Сначала создайте ключ, затем можно добавить зеркало.',
  'mirror.removeAll': 'Удалить все зеркала',
  'mirror.errorToast': 'Не удалось добавить зеркало',
  'mirror.removedToast': 'Зеркала удалены',

  // --- просмотр необработанной конфигурации (ручная настройка, E2EE сохраняется) ---
  'rawconfig.disclosure': 'Показать необработанную конфигурацию',
  'rawconfig.title': 'Ваша конфигурация',
  'rawconfig.explainer':
    'Полная конфигурация вашего прокси, полученная по зашифрованному каналу — она никогда не проходит через CDN в открытом виде. Вставьте её в приложение вручную вместо ссылки-подписки.',
  'rawconfig.addHint': 'Вставьте эти серверные записи в ваше прокси-приложение вручную.',

  // --- предпочтение доставки (приватность против обхода блокировок) ---
  'delivery.title': 'Что для вас важнее всего?',
  'delivery.subtitle':
    'Выберите приоритет — сохраняется только на этом устройстве, изменить можно в любой момент.',
  'delivery.evadeTitle': 'Оставаться на связи',
  'delivery.evadeBody':
    'Лучше всего, когда сайты заблокированы в вашем регионе. Мы покажем резервные ссылки, которые сложнее заблокировать.',
  'delivery.privacyTitle': 'Максимум приватности',
  'delivery.privacyBody':
    'Лучше всего для строгой конфиденциальности. Мы предпочтём настройку, при которой конфиг не попадает на сторонние серверы.',
  'delivery.recommended': 'Рекомендуется',
};
