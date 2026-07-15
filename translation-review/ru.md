# FreeSocks translation review — Russian (Русский)

Generated from `messages/en.json` (source of truth) vs `messages/ru.json`.
**184 of 646 strings are missing** (the app currently shows English for
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

- Edit the **"Russian (Русский)" column** (or add a correction below a row). Rows marked
  ⚠️ MISSING have no translation yet.


## `faq` — The landing-page FAQ (questions + answers). *(4 missing)*

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `faq.title` | Frequently asked questions | Часто задаваемые вопросы |
| `faq.subtitle` | Answers to common questions. | Основные вопросы решены. Остались вопросы? Свяжитесь со службой поддержки, указав свой идентификатор. |
| `faq.tabGeneral` | General | ⚠️ **MISSING** |
| `faq.tabThreat` | What we protect you from | ⚠️ **MISSING** |
| `faq.contactPrefix` | For anything else, email | ⚠️ **MISSING** |
| `faq.contactSuffix` | and include your Support ID. | ⚠️ **MISSING** |
| `faq.q1.question` | What is FreeSocks? | Что такое FreeSocks? |
| `faq.q1.answer` | A free proxy service that helps people in heavily-censored regions reach the open internet. It's operated by Unredacted, a US 501(c)(3) nonprofit. | Бесплатный прокси-сервис, помогающий людям в регионах с жесткой цензурой получить доступ к открытому интернету. Он управляется некоммерческой организацией Unredacted, зарегистрированной в США как 501(c)(3). |
| `faq.q2.question` | Is it really free? | Это действительно бесплатно? |
| `faq.q2.answer` | Yes. A free account gives you a working proxy. A paid FreeSocks membership lifts the limits and helps fund free access for others. | Да. Бесплатный аккаунт предоставляет вам работающий прокси. Платная подписка FreeSocks снимает ограничения и помогает финансировать бесплатный доступ для других пользователей. |
| `faq.q3.question` | Do I need to give an email or password? | Нужно ли указывать адрес электронной почты или пароль? |
| `faq.q3.answer` | No. You pass a one-time human check and we generate a 32-digit account number - that's your only credential. We never ask for an email, phone number, or name. | Нет. Вы проходите одноразовую проверку человеком, и мы генерируем 32-значный номер счета - это ваши единственные учетные данные. Мы никогда не запрашиваем адрес электронной почты, номер телефона или имя. |
| `faq.q4.question` | What if I lose my account number? | Что если я потеряю номер своего счета? |
| `faq.q4.answer` | It's the only way back into your account and we can't recover it (we store only a hashed version), so save it in a password manager when you create it. If you lose it, just create a new free account. | Это единственный способ восстановить доступ к вашей учетной записи, и мы не сможем ее восстановить (мы храним только хешированную версию), поэтому сохраните ее в менеджере паролей при создании. Если вы ее потеряете, просто создайте новую бесплатную учетную запись. |
| `faq.q5.question` | How do I connect? | Как мне подключиться? |
| `faq.q5.answer` | Create a subscription, copy its link (or scan the QR code), and add it to a compatible app. Your account page lists the recommended app for each platform (Android, iPhone, Windows, macOS / Linux). | Создайте подписку, скопируйте ссылку (или отсканируйте QR-код) и добавьте её в совместимое приложение, например, v2rayNG, Hiddify или Streisand. На странице вашей учетной записи будут перечислены рекомендуемые приложения для каждой платформы. |
| `faq.q6.question` | What do you log about me? | Что вы записываете обо мне? |
| `faq.q6.answer` | As little as possible: only a hashed version of your account number - never your email, name, or IP address - and no logs of the sites you visit or the traffic you send. | Минимум информации: только хешированная версия номера вашего счета - никогда не ваш адрес электронной почты или имя - и никаких журналов посещенных вами сайтов или трафика, который вы отправляете. |
| `faq.q7.question` | The link is blocked where I am. What can I do? | Ссылка заблокирована в моём регионе. Что я могу сделать? |
| `faq.q7.answer` | On your account page, open "Trouble connecting?" to get a mirror link served from a different host that may not be blocked. You can also set your delivery preference to favor staying connected. | На странице вашей учетной записи откройте раздел «Проблемы с подключением?», чтобы получить зеркальную ссылку с другого хоста, которая, возможно, не заблокирована. Вы также можете настроить параметры доставки таким образом, чтобы соединение оставалось стабильным. |
| `faq.q8.question` | Can I buy a membership for someone else? | Могу ли я приобрести абонемент для другого человека? |
| `faq.q8.answer` | Yes - on your account page use "Buy codes to share" to purchase membership codes you can give to friends or family. Each one works on any account and doesn't affect yours. | Да - на странице вашего аккаунта используйте кнопку «Купить коды для распространения», чтобы приобрести коды членства, которые вы можете передать друзьям или родственникам. Каждый из них работает на любом аккаунте и не влияет на ваш. |
| `faq.q9.question` | Can I pay anonymously? | Можно ли оплатить анонимно? |
| `faq.q9.answer` | Yes. You can pay with cryptocurrency - Bitcoin, or Monero and Zcash for the most privacy - with no account, email, or card. Your membership activates automatically once the payment confirms. | Да. Вы можете оплатить криптовалютой - Bitcoin, или Monero и Zcash для максимальной конфиденциальности - без учетной записи, электронной почты или карты. Ваша подписка активируется автоматически после подтверждения платежа. |

## `threat` — Miscellaneous strings. *(15 missing)*

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `threat.subtitle` | An honest look at what this service can and cannot do. Security tools that overpromise get people hurt, so here is exactly where the lines are. | ⚠️ **MISSING** |
| `threat.q1.question` | What does FreeSocks protect me from? | ⚠️ **MISSING** |
| `threat.q1.answer` | FreeSocks tunnels your traffic through an encrypted proxy, so your ISP, mobile carrier, school, or workplace network cannot see which sites you visit or block them. It is built for getting past censorship and for keeping the network you are on from watching what you do. | ⚠️ **MISSING** |
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

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `common.copy` | Copy | Копировать |
| `common.copied` | Copied to clipboard | Скопировано в буфер обмена |
| `common.copyFailed` | Copy failed - select the text and copy it manually | Не удалось скопировать - выделите текст и скопируйте вручную |
| `common.download` | Download | Скачать |
| `common.cancel` | Cancel | Отмена |
| `common.close` | Close | Закрыть |
| `common.retry` | Retry | Повторить |
| `common.loading` | Loading… | Загрузка… |
| `common.working` | Working… | Выполняется… |
| `common.reload` | Reload | Перезагрузить |
| `common.language` | Language | Язык |
| `common.deviceCount [countPlural=one]` | 1 device | 1 устройство |
| `common.deviceCount [countPlural=other]` | {count} devices | {count} устройств |

## `nav` — The site header: navigation buttons, menu, language/theme controls. *(3 missing)*

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `nav.getAccount` | Get a free account | Получить бесплатный аккаунт |
| `nav.signIn` | Sign in | Войти |
| `nav.account` | My account | Мой аккаунт |
| `nav.menu` | Menu | ⚠️ **MISSING** |
| `nav.theme` | Theme | ⚠️ **MISSING** |
| `nav.home` | FreeSocks home | ⚠️ **MISSING** |

## `captcha` — The proof-of-work human check widget states.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `captcha.initial` | I'm human | Я человек |
| `captcha.verifying` | Verifying… | Проверка… |
| `captcha.solved` | Verified | Проверено |
| `captcha.error` | Check failed - retry | Проверка не удалась - повторите |
| `captcha.failedTitle` | Couldn't complete the human check. | Не удалось пройти проверку. |
| `captcha.failedBody` | The check runs on your device and didn't finish. This is usually a network problem, not something you did wrong. | Проверка выполняется на вашем устройстве и не завершилась. Обычно это проблема с сетью, а не ваша ошибка. |
| `captcha.failedTip1` | Wait a moment, then try again | Подождите немного и попробуйте снова |
| `captcha.failedTip2` | Try a different network - or a VPN/proxy if sites are blocked where you are | Попробуйте другую сеть - или VPN/прокси, если сайты заблокированы в вашем регионе |
| `captcha.failedTip3` | Still stuck? Try a private/incognito window or turn off browser extensions | Всё ещё не работает? Откройте приватное окно или отключите расширения браузера |

## `reveal` — The save-your-account-number modal (the 32-digit sign-in number is shown ONCE; users must download it and paste it back to verify). The single most safety-critical copy in the product. *(8 missing)*

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `reveal.title` | Save your account number now | Сохраните номер аккаунта сейчас |
| `reveal.subtitle` | This 32-digit number is the ONLY way to sign in again. There is no email or password to recover it. If you lose it, your account is gone for good. | Этот 32-значный номер - единственный способ снова войти. Нет ни почты, ни пароля для восстановления. Если вы его потеряете, аккаунт будет утрачен навсегда. |
| `reveal.cannotRecover` | We cannot recover it for you - not even support can. | Мы не сможем его восстановить - даже поддержка не сможет. |
| `reveal.saveHint` | Save it in a password manager, or write it down somewhere safe and private. | Сохраните его в менеджере паролей или запишите в надёжном личном месте. |
| `reveal.downloadRequired` | Download your account number to continue. Keep the file somewhere safe. | ⚠️ **MISSING** |
| `reveal.continue` | Continue | ⚠️ **MISSING** |
| `reveal.verifyTitle` | Confirm you saved it | ⚠️ **MISSING** |
| `reveal.verifySubtitle` | Your account number is now hidden. Enter or paste it from the copy you just saved to confirm you can sign in later. | ⚠️ **MISSING** |
| `reveal.verifyPlaceholder` | Paste your 32-digit account number | ⚠️ **MISSING** |
| `reveal.verifyMismatch` | That doesn't match your account number. Check the copy you saved, or go back to see it again. | ⚠️ **MISSING** |
| `reveal.back` | Back | ⚠️ **MISSING** |
| `reveal.done` | I've saved it | Я сохранил |
| `reveal.savedConfirmed` | Account number saved and verified | ⚠️ **MISSING** |
| `reveal.downloadFilename` | freesocks-account-number.txt | freesocks-account-number.txt |
| `reveal.leaveWarning` | Your account number is still on screen. If you leave now without saving it, you will not be able to sign in again. | Номер аккаунта всё ещё на экране. Если вы уйдёте сейчас, не сохранив его, вы не сможете снова войти. |

## `support` — The support-ID line (a non-secret handle for contacting support). *(2 missing)*

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `support.label` | Support ID | ID для поддержки |
| `support.hint` | Share this if you contact us. It is NOT your sign-in number and grants no access. | Сообщите его, если обращаетесь к нам. Это не номер для входа и не даёт доступа. |
| `support.emailUs` | Email us: | ⚠️ **MISSING** |
| `support.getAccountLine` | Questions or problems? Email us at | ⚠️ **MISSING** |

## `login` — The sign-in page (account number + optional passkey). *(1 missing)*

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `login.title` | Sign in with your account number | Войдите по номеру аккаунта |
| `login.subtitle` | Enter the 32-digit account number you saved. It's the only way to sign in - there's no email or password to recover. | Введите 32-значный номер аккаунта, который вы сохранили. Это единственный способ войти - нет почты или пароля для восстановления. |
| `login.label` | Account number | Номер аккаунта |
| `login.show` | Show | Показать |
| `login.hide` | Hide | Скрыть |
| `login.submit` | Sign in | Войти |
| `login.submitting` | Signing in… | Вход… |
| `login.noAccount` | Don't have an account number yet? | Ещё нет номера аккаунта? |
| `login.getOne` | Get a free account | Получить бесплатный аккаунт |
| `login.failed` | Sign-in failed | Не удалось войти |
| `login.success` | Signed in | Вы вошли |
| `login.sessionExpired` | Please sign in again - your session may have ended. | Пожалуйста, войдите снова - возможно, ваша сессия завершилась. |
| `login.digitProgress` | {count} of {total} digits entered | {count} из {total} цифр введено |
| `login.or` | or | ⚠️ **MISSING** |

## `passkey` — Optional passkey (Face ID / fingerprint) sign-in management. *(20 missing)*

| Key | English | Russian (Русский) |
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

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `account.title` | Your account | Ваш аккаунт |
| `account.tierLabel` | Your plan | Ваш план |
| `account.statusActive` | Active | Активен |
| `account.statusGrace` | Expiring soon | Скоро истекает |
| `account.statusDisabled` | Disabled | Истёк |
| `account.regenerate` | Create a new key | Создать новый ключ |
| `account.switchBackend` | Switch server type | Сменить тип сервера |
| `account.rotate` | Change account number | Сменить номер аккаунта |
| `account.signOut` | Sign out | Выйти |
| `account.redeemTitle` | Have a membership code? | Есть код членства? |
| `account.redeemPlaceholder` | FSM-XXXX-XXXX-XXXX | ФСМ-XXXX-XXXX-XXXX |
| `account.redeemSubmit` | Redeem code | Активировать код |
| `account.redeemSuccess` | Redeemed - you're now on {tier} for {days} more days. | Активировано - теперь у вас {tier} ещё на {days} дн. |
| `account.redeemFailed` | That code is not valid, or has already been used. | Этот код недействителен или уже использован. |
| `account.redeemAriaLabel` | Membership code | Код членства |
| `account.switchTo` | Switch to {label} | Перейти на {label} |
| `account.devicesTitle` | Connected devices | Подключённые устройства |
| `account.lastSeen` | Last seen {date} | Последняя активность {date} |
| `account.noSubTitle` | No subscription yet | Подписки пока нет |
| `account.noSubBody` | Create your first subscription to get a URL you can use in any compatible VPN client. | Создайте первую подписку, чтобы получить ссылку для любого совместимого VPN-клиента. |
| `account.createSub` | Create subscription | Создать подписку |
| `account.creating` | Creating… | Создание… |
| `account.rotateTitle` | Change your account number? | Сменить номер аккаунта? |
| `account.rotateBody` | A new 32-digit number is generated and shown once. Your current number stops working immediately. Anyone who has it loses access. Do this if your number may have leaked. | Будет создан новый 32-значный номер, показанный только один раз. Текущий номер сразу перестанет работать - все, у кого он есть, потеряют доступ. Делайте это, если номер мог утечь. |
| `account.rotateConfirm` | Yes, change it | Да, сменить |
| `account.rotating` | Rotating… | Смена… |
| `account.rotateFailedTitle` | Could not change the account number | Не удалось сменить номер аккаунта |
| `account.refreshMembership` | Already paid? Check for my membership | Уже оплатили? Проверить членство |
| `account.memberActiveTitle` | Membership active | Членство активно |
| `account.memberActiveExpiry` | Active until {date} | Активно до {date} |
| `account.membershipNudge.title` | Go unlimited with a membership | Безлимит с подпиской |
| `account.membershipNudge.body` | Unlimited bandwidth and devices. | Безлимитный трафик и устройства. |
| `account.membershipNudge.bodyNoDevices` | Unlimited bandwidth. | ⚠️ **MISSING** |
| `account.membershipNudge.cta` | View membership | Открыть подписку |
| `account.tab.connection` | Connection | Подключение |
| `account.tab.membership` | Membership | Членство |
| `account.tab.codes` | Codes & gifts | Коды и подарки |
| `account.tab.security` | Security | Безопасность |
| `account.refreshing` | Refreshing… | Обновление… |
| `account.regenSuccessTitle` | New subscription URL generated | Создана новая ссылка подписки |
| `account.regenSuccessBody` | Re-import it on each of your devices. The old URL works for 24 more hours. | Импортируйте её заново на каждом устройстве. Старая ссылка работает ещё 24 часа. |
| `account.regenFailedTitle` | Could not create a new key | Не удалось создать новый ключ |
| `account.switchSuccessTitle` | Switched to {tier} | Вы перешли на {tier} |
| `account.switchSuccessBodyGrace` | Re-import the new subscription URL on each device. The old subscription works for 24 more hours. | Импортируйте новую ссылку подписки на каждом устройстве. Старая подписка работает ещё 24 часа. |
| `account.switchSuccessBody` | Re-import the new subscription URL on each device. | Импортируйте новую ссылку подписки на каждом устройстве. |
| `account.switchFailedTitle` | Could not switch server type | Не удалось сменить тип сервера |
| `account.refreshWelcome` | Welcome to {tier} | Добро пожаловать в {tier} |
| `account.refreshNoneTitle` | No active membership found yet | Активное членство пока не найдено |
| `account.refreshNoneBody` | If you just paid, give it a moment and try again. | Если вы только что оплатили, подождите немного и повторите. |
| `account.refreshFailedTitle` | Could not refresh membership | Не удалось обновить членство |
| `account.graceTitle` | Your account is in a grace period | Аккаунт в льготном периоде |
| `account.graceBody` | Your membership has lapsed, so this account will be limited soon. Renew - donate or redeem a membership code below - to keep your plan. | Членство закончилось, и скоро аккаунт будет ограничен. Продлите его - пожертвуйте или активируйте код членства ниже - чтобы сохранить тариф. |
| `account.disabledTitle` | Your account is currently disabled | Аккаунт сейчас отключён |
| `account.disabledBody` | New keys and changes are paused on this account. Redeem a membership code below to reactivate it, or contact support and share your Support ID. | Новые ключи и изменения для этого аккаунта приостановлены. Активируйте код членства ниже, чтобы вернуть доступ, или напишите в поддержку, указав свой ID для поддержки. |
| `account.rotateHint` | Replace your 32-digit account number if it may have leaked - or, if you never saved it, rotate now to get a fresh one you can save. The old one stops working immediately. | Замените свой 32-значный номер счета, если произошла утечка данных. Старый номер перестанет работать немедленно. |
| `account.keyActionsHint` | These change your proxy connection only - your 32-digit account number stays the same. | Эти изменения касаются только подключения к прокси-серверу - ваш 32-значный номер счета остается неизменным. |
| `account.section.connection.title` | Your connection | Ваше соединение |
| `account.section.connection.desc` | Your proxy key, setup help, and connected devices. | Ваш прокси-ключ, справка по настройке и подключенные устройства. |
| `account.section.membership.title` | Membership | Членство |
| `account.section.membership.desc` | Your plan, and how to upgrade or extend it. | Ваш план и способы его модернизации или расширения. |
| `account.section.codes.title` | Codes & gifts | Коды и подарки |
| `account.section.codes.desc` | Redeem a membership code, or buy codes to share with others. | Активируйте промокод или купите коды, чтобы поделиться ими с другими. |
| `account.section.security.title` | Account & security | Учетная запись и безопасность |
| `account.section.security.desc` | Your support ID and account-number controls. | Ваш идентификатор службы поддержки и номер счета находятся под контролем. |
| `account.deviceRevoke` | Revoke | Отменить |
| `account.deviceRevokedTitle` | Device revoked | Устройство аннулировано |
| `account.deviceRevokedBody` | The slot is free. That device loses access until it re-imports your subscription. | Слот бесплатный. Это устройство потеряет доступ, пока не повторно не импортирует вашу подписку. |
| `account.deviceRevokeFailedTitle` | Couldn't revoke the device | Не удалось отозвать устройство. |

## `hero` — The subscription panel: the key/URL block, traffic + expiry stats, QR, status callouts. *(8 missing)*

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `hero.titleDefault` | Your subscription | Ваша подписка |
| `hero.eyebrowAccessKey` | Your access key | Ваш ключ доступа |
| `hero.urlLabelSubscription` | Subscription URL | Ссылка подписки |
| `hero.urlLabelAccessKey` | Access key | Ключ доступа |
| `hero.tierLine` | Plan {tier} | Тариф {tier} |
| `hero.viaLine` | via {backend} | через {backend} |
| `hero.copyUrl` | Copy URL | Копировать ссылку |
| `hero.copiedShort` | Copied | Скопировано |
| `hero.qrShow` | QR | QR |
| `hero.qrHide` | Hide | Скрыть |
| `hero.scanPhone` | Scan with your phone | Отсканируйте телефоном |
| `hero.scanOther` | Scan with another device | Отсканируйте другим устройством |
| `hero.importTitle` | Add to your app | Добавить в приложение |
| `hero.importPlain` | Plain link | Обычная ссылка |
| `hero.importOpen` | Open in {app} | Открыть в {app} |
| `hero.importScan` | Scan to add to {app} | Сканируйте, чтобы добавить в {app} |
| `hero.importOpenHint` | Tap to import on this device, or scan the code from your phone. | Нажмите, чтобы импортировать на этом устройстве, или отсканируйте код телефоном. |
| `hero.scanFallback` | Scan the fallback on another device | Отсканируйте резервную ссылку другим устройством |
| `hero.fallbackLabel` | Fallback URL | Резервная ссылка |
| `hero.fallbackHint` | Use this if the main URL gets blocked | Используйте её, если основную ссылку заблокируют |
| `hero.fallbackQrAria` | Show fallback URL QR code | Показать QR-код резервной ссылки |
| `hero.downloaded` | Downloaded {filename} | Скачан файл {filename} |
| `hero.traffic` | Traffic | Трафик |
| `hero.unlimited` | Unlimited | Безлимит |
| `hero.configBelowNote` | Your full configuration is below - add the servers by hand. For privacy, the auto-updating subscription link isn't shown by default (your app would fetch it through a CDN). | ⚠️ **MISSING** |
| `hero.showUrlAnyway` | Show the subscription link anyway | ⚠️ **MISSING** |
| `hero.urlDangerBody` | This link works in any app, but the app then downloads your configuration through a third-party CDN in plain text - the CDN operator can see your server details and that you use FreeSocks. That is exactly what this focus avoids. Use it only if your app cannot import the configuration below. | ⚠️ **MISSING** |
| `hero.usedSoFar` | {amount} used so far | Использовано {amount} |
| `hero.leftThisPeriod` | {amount} left this period. | Осталось {amount} в этом периоде. |
| `hero.nearlyOut` | Nearly out, only {amount} left this period. | Почти исчерпано - осталось всего {amount} в этом периоде. |
| `hero.expires` | Expires | Истекает |
| `hero.noExpiry` | No expiry | Бессрочно |
| `hero.expiresToday` | Expires today | Истекает сегодня |
| `hero.daysRemaining [countPlural=one]` | 1 day remaining | Осталось 1 день |
| `hero.daysRemaining [countPlural=other]` | {count} days remaining | Осталось {count} дней |
| `hero.expiredDaysAgo [countPlural=one]` | Expired 1 day ago | Истекла 1 день назад |
| `hero.expiredDaysAgo [countPlural=other]` | Expired {count} days ago | Истекла {count} дней назад |
| `hero.nodeOnline` | Node online | ⚠️ **MISSING** |
| `hero.nodeOffline` | Node offline | ⚠️ **MISSING** |
| `hero.nodeUnknown` | Node status unknown | ⚠️ **MISSING** |
| `hero.nodeOnlineHint` | The server behind your config is up and responding. If you still can't connect, your network or ISP is likely filtering it - try another connection mode or location. | ⚠️ **MISSING** |
| `hero.nodeOfflineBody` | The server behind your config is currently offline. This is on our side, not your network. Try again in a few minutes, or create a new config (optionally in a different location). | ⚠️ **MISSING** |
| `hero.keyLimited` | You've used all your data for this period. It resets automatically, or you can upgrade for more. | Вы использовали весь свой трафик за этот период. Он автоматически обнуляется, или вы можете приобрести более дорогой тарифный план. |
| `hero.keyExpired` | This key has expired. Renew your membership or create a new key to reconnect. | Срок действия этого ключа истек. Продлите свою подписку или создайте новый ключ для повторного подключения. |
| `hero.keyDisabled` | This key is currently disabled. If your membership lapsed, renew it; otherwise contact support with your support ID. | Этот ключ в настоящее время отключен. Если срок действия вашей подписки истек, продлите ее; в противном случае свяжитесь со службой поддержки, указав свой идентификатор службы поддержки. |
| `hero.resetsInDays [countPlural=one]` | Resets in 1 day | Сброс через 1 день |
| `hero.resetsInDays [countPlural=other]` | Resets in {count} days | Сбросы в {count} днях |

## `location` — Miscellaneous strings. *(4 missing)*

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `location.pickerLabel` | Server location | ⚠️ **MISSING** |
| `location.auto` | Automatic (least busy) | ⚠️ **MISSING** |
| `location.offline` | offline | ⚠️ **MISSING** |
| `location.pickerHint` | Where your config's server is. Automatic picks the least busy location; pick one yourself if it works better on your network. | ⚠️ **MISSING** |

## `usage` — The 30-day usage trend under the traffic stats.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `usage.show` | Show usage trend | Показать тенденцию использования |
| `usage.title` | Usage (last 30 days) | Использование (за последние 30 дней) |
| `usage.total` | {amount} used in the last 30 days | {amount} использовано за последние 30 дней |
| `usage.unavailable` | Usage isn't available right now. | В настоящий момент эта функция недоступна. |
| `usage.none` | No usage recorded yet. | Пока не зафиксировано ни одного случая использования. |

## `regen` — The regenerate-subscription confirmation dialog.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `regen.title` | Create a new subscription URL? | Пересоздать подписку? |
| `regen.body` | Your current subscription URL (ending …{suffix}) will be replaced with a new one. The old URL becomes read-only for 24 hours, then is deleted. | Текущая ссылка подписки (оканчивается на …{suffix}) будет заменена новой. Старая ссылка станет доступна только для чтения на 24 часа, затем будет удалена. |
| `regen.point1` | Your current key remains usable for the next 24 hours | Текущий ключ продолжит работать ближайшие 24 часа |
| `regen.point2` | You'll need to re-import the new URL in each of your devices | Новую ссылку нужно будет заново импортировать на каждом устройстве |
| `regen.pointDevices [countPlural=one]` | You currently have 1 connected device - it will need the new URL | Сейчас подключено 1 устройство - всем понадобится новая ссылка |
| `regen.pointDevices [countPlural=other]` | You currently have {count} connected devices - they will all need the new URL | Сейчас подключено {count} устройств - всем понадобится новая ссылка |
| `regen.confirm` | Create new URL | Пересоздать |
| `regen.working` | Creating… | Пересоздание… |

## `switch` — The switch-backend confirmation dialog.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `switch.title` | Switch to {to}? | Перейти на {to}? |
| `switch.body` | Your current {from} subscription will be replaced with a new {to} one. The old subscription stays usable for 24 hours so you can re-import on every device before it stops working. | Текущая подписка {from} будет заменена новой подпиской {to}. Старая подписка работает ещё 24 часа, чтобы вы успели переимпортировать ссылку на всех устройствах. |
| `switch.point1` | A new subscription URL is issued on the {to} backend | Новая ссылка подписки выпускается на сервере {to} |
| `switch.point2` | The current {from} URL keeps working for 24 hours, then is deleted | Текущая ссылка {from} работает ещё 24 часа, затем удаляется |
| `switch.point3` | You'll need to re-import the new URL in each VPN client you use | Новую ссылку нужно заново импортировать в каждом VPN-клиенте |
| `switch.pointDevices [countPlural=one]` | You currently have 1 connected device - re-import on it | Сейчас подключено 1 устройство - переимпортируйте на всех |
| `switch.pointDevices [countPlural=other]` | You currently have {count} connected devices - re-import on all of them | Сейчас подключено {count} устройств - переимпортируйте на всех |
| `switch.confirm` | Switch to {to} | Перейти на {to} |
| `switch.working` | Switching… | Переход… |

## `get` — The /get-account sign-up flow: create account (step 1) and create subscription (step 2). *(4 missing)*

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `get.badge` | Free account | Бесплатный аккаунт |
| `get.title` | Get a FreeSocks account | Получите аккаунт FreeSocks |
| `get.introTwoSteps` | Two quick steps: solve the human-check to create a free account, then create your subscription. | Два быстрых шага: пройдите проверку, чтобы создать бесплатный аккаунт, затем создайте подписку. |
| `get.step1Title` | Create your account | Создайте аккаунт |
| `get.chooseBackend` | Choose a connection type | Выберите тип сервера |
| `get.backendAria` | Connection type | Тип сервера |
| `get.backendMultiProtocol` | VLESS (Xray) | VLESS (Xray) |
| `get.backendShadowsocks` | Shadowsocks via Outline | Shadowsocks через Outline |
| `get.createAccount` | Create my account | Создать аккаунт |
| `get.freeAccountNote` | Free accounts are valid for {days} days and limited to {devices}. No email or password. | Бесплатные аккаунты действуют {days} дней · {devices}. Без почты и пароля. |
| `get.freeAccountNoteNoDevices` | Free accounts are valid for {days} days. No email or password. | ⚠️ **MISSING** |
| `get.accountReady` | Your account is ready | Ваш аккаунт готов. |
| `get.nextStepHint` | One step left - your account can't connect to anything until you create your subscription. | ⚠️ **MISSING** |
| `get.nextStepCta` | Next: create your subscription | ⚠️ **MISSING** |
| `get.nextStepBadge` | Next step | ⚠️ **MISSING** |
| `get.step2Title` | Create your subscription | Создайте подписку |
| `get.step2Intro` | Create a proxy subscription to get a URL you can paste into any compatible VPN client. | Создайте прокси-подписку, чтобы получить ссылку для любого совместимого VPN-клиента. |
| `get.manageHintPrefix` | Manage this subscription anytime from | Управляйте этой подпиской в любое время из |
| `get.manageLinkLabel` | your account | вашего аккаунта |
| `get.subErrorSafePrefix` | Your account is safe. You can create the subscription later from | Ваш аккаунт в безопасности. Подписку можно создать позже из |
| `get.subErrorSafeSuffix` | once a server is available. | когда сервер станет доступен. |
| `get.createSubToastTitle` | Subscription created | Подписка создана |
| `get.createSubToastBody` | Copy the URL into your VPN client, or scan the QR code. | Скопируйте ссылку в VPN-клиент или отсканируйте QR-код. |
| `get.createAccountFailedTitle` | Could not create account | Не удалось создать аккаунт |
| `get.createSubFailedTitle` | Could not create subscription | Не удалось создать подписку |
| `get.haveAccountPrefix` | Already have an account? | Уже есть аккаунт? |
| `get.lostNumberHint` | Lost your account number before saving it? You can switch to a new one - | Потеряли номер аккаунта, не успев сохранить? Можно получить новый - |
| `get.lostNumberLinkLabel` | change it from your account page | смените его на странице аккаунта |
| `get.upsellTitle` | Want unlimited? | Хотите без лимитов? |
| `get.upsellBody` | Upgrade to a FreeSocks membership any time for unlimited bandwidth and devices. | В любой момент оформите членство FreeSocks ради безлимитного трафика и устройств. |
| `get.redeemTitle` | Got a gift code? | У вас есть подарочный код? |
| `get.redeemBody` | Redeem it now to upgrade your new account instantly. | Активируйте сейчас, чтобы мгновенно обновить свою учетную запись. |

## `tiers` — The plan-comparison cards (Free vs Membership limits).

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `tiers.title` | Tiers | Тарифы |
| `tiers.subtitle` | What each tier includes. | Что входит в каждый тариф. |
| `tiers.yourTier` | Your plan | Ваш тариф |
| `tiers.gbPerMonth` | {gb} GB / month | {gb} ГБ / месяц |
| `tiers.mirrors` | Mirror URLs | Резервные ссылки |
| `tiers.upgradeCta` | Upgrade | Оформить |

## `impact` — The donation-impact panel: bandwidth donated, free users helped, charts. *(16 missing)*

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `impact.title` | Donations support Unredacted | Пожертвования поддерживают Unredacted |
| `impact.body` | Unredacted is a US 501(c)(3) nonprofit. FreeSocks is one of the projects it runs. Donations fund the work. See what that work is on the Unredacted site. | Unredacted - американская некоммерческая организация 501(c)(3). FreeSocks - один из её проектов. Работа финансируется пожертвованиями. Подробности - на сайте Unredacted. |
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

| Key | English | Russian (Русский) |
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

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `qr.ariaLabel` | QR code for the subscription URL | QR-код ссылки подписки |
| `qr.failed` | Couldn't generate the QR code. | Не удалось сгенерировать QR-код. |

## `app` — App-level chrome (skip link, page titles).

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `app.skipToContent` | Skip to content | Перейти к содержимому |
| `app.notFound` | Not found | Страница не найдена |
| `app.goHome` | Go home | На главную |
| `app.adminLoadFailedTitle` | Couldn't load the admin console | Не удалось загрузить консоль администратора. |
| `app.adminLoadFailedBody` | The network request for this section failed. Reload to retry. | Сетевой запрос к этому разделу не удался. Перезагрузите страницу, чтобы повторить попытку. |

## `footer` — The site footer (nonprofit line, terms/privacy links). *(8 missing)*

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `footer.operatedPrefix` | Operated by | Управляется |
| `footer.operatedSuffix` | , a US 501(c)(3) nonprofit |  - американской некоммерческой организацией 501(c)(3) |
| `footer.viewSource` | View source | ⚠️ **MISSING** |
| `footer.terms` | Terms of Service | ⚠️ **MISSING** |
| `footer.privacy` | Privacy Policy | ⚠️ **MISSING** |
| `footer.transparency` | Transparency Report | ⚠️ **MISSING** |
| `footer.socialX` | FreeSocks on X | ⚠️ **MISSING** |
| `footer.socialMastodon` | FreeSocks on Mastodon | ⚠️ **MISSING** |
| `footer.socialBluesky` | FreeSocks on Bluesky | ⚠️ **MISSING** |
| `footer.support` | Support | ⚠️ **MISSING** |

## `renew` — Expiring/expired membership callouts and renewal prompts.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `renew.expiringTitle` | Your membership is expiring soon | Ваше членство скоро истекает |
| `renew.expiredTitle` | Your membership has expired | Ваше членство истекло |
| `renew.body` | FreeSocks is community-funded - donations keep it running. To renew your membership, donate or contact us for a membership code. | FreeSocks существует на пожертвования. Чтобы продлить членство, сделайте пожертвование или свяжитесь с нами для получения кода членства. |
| `renew.donate` | Donate | Пожертвовать |
| `renew.contact` | Contact us | Связаться с нами |
| `renew.lapsedBody` | You're on the free tier now. Renew below to restore your membership. | Сейчас вы на бесплатном тарифе. Продлите ниже, чтобы восстановить членство. |
| `renew.renewCta` | Renew membership | Продлить членство |

## `upgrade` — The paid-membership purchase panel (payment method, duration, totals). *(4 missing)*

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `upgrade.title` | Upgrade to a FreeSocks membership | Оформить членство FreeSocks |
| `upgrade.extendTitle` | Extend your membership | Продлить членство |
| `upgrade.subtitle` | Unlimited bandwidth and devices. Choose a length and how to pay. | Безлимитный трафик и устройства. Выберите срок и способ оплаты. |
| `upgrade.subtitleNoDevices` | Unlimited bandwidth. Choose a length and how to pay. | ⚠️ **MISSING** |
| `upgrade.durationLabel` | Membership length | Срок членства |
| `upgrade.cryptoMinNote` | Crypto payments start at {months} months - shorter terms fall below the network minimum. Pick another method for shorter terms. | Оплата криптовалютой - от {months} мес.; более короткие сроки ниже сетевого минимума. Для коротких сроков выберите другой способ. |
| `upgrade.months [countPlural=one]` | 1 month | 1 мес. |
| `upgrade.months [countPlural=other]` | {count} months | {count} мес. |
| `upgrade.perMonth` | {price}/mo | {price}/мес |
| `upgrade.fromPerMonth` | From {price}/month | ⚠️ **MISSING** |
| `upgrade.benefitsShort` | Unlimited bandwidth and devices | ⚠️ **MISSING** |
| `upgrade.benefitsShortNoDevices` | Unlimited bandwidth | ⚠️ **MISSING** |
| `upgrade.save` | save {pct}% | скидка {pct}% |
| `upgrade.methodLabel` | Payment method | Способ оплаты |
| `upgrade.payNowpayments` | Cryptocurrency | Криптовалюта |
| `upgrade.payNowpaymentsHint` | Bitcoin, Monero, Zcash & more | Bitcoin, Monero и другие |
| `upgrade.payNowpaymentsBadge` | Private | Частный |
| `upgrade.cryptoPrivacyNote` | No account, email, or card needed - pay privately. Monero and Zcash offer the most privacy. | Не требуется регистрация, электронная почта или банковская карта - оплата производится конфиденциально. Monero и Zcash обеспечивают максимальную конфиденциальность. |
| `upgrade.payBtcpay` | Bitcoin | Bitcoin |
| `upgrade.payBtcpayHint` | On-chain or Lightning | Ончейн или Lightning |
| `upgrade.payBtcpayBadge` | No intermediary | Без посредников |
| `upgrade.payStripe` | Card | Карта |
| `upgrade.payStripeHint` | Credit or debit card | Кредитная или дебетовая карта |
| `upgrade.payPaypal` | PayPal | PayPal |
| `upgrade.payPaypalHint` | PayPal balance or card | Баланс PayPal или карта |
| `upgrade.total` | Total {price} | Итого {price} |
| `upgrade.continue` | Continue to payment | Перейти к оплате |
| `upgrade.starting` | Starting checkout… | Начинаем оплату… |
| `upgrade.startFailed` | Could not start checkout | Не удалось начать оплату |
| `upgrade.noStoreNote` | We never see your card or wallet, and store no payment details. | Мы никогда не храним вашу почту или платёжные данные. |
| `upgrade.confirmingTitle` | Confirming your payment… | Подтверждаем оплату… |
| `upgrade.confirmingBody` | Crypto can take a few minutes to confirm. You can leave this page - your membership activates automatically. | Подтверждение криптовалюты может занять несколько минут. Можете покинуть страницу - членство активируется автоматически. |
| `upgrade.paidTitle` | Membership active | Членство активно |
| `upgrade.paidBody` | Thank you! Your membership is now active. | Спасибо! Ваше членство теперь активно. |
| `upgrade.failedTitle` | Payment not completed | Оплата не завершена |
| `upgrade.failedBody` | Your payment did not go through, or the checkout expired. You can try again. | Платёж не прошёл или срок оплаты истёк. Вы можете попробовать снова. |

## `gift` — Gift membership codes: buying, revealing (show-once), and redeeming.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `gift.title` | Buy codes to share | Купите коды, чтобы поделиться ими. |
| `gift.subtitle` | Purchase membership codes to give to friends or family. Each works on any account and never touches yours. | Приобретите промокоды, чтобы подарить их друзьям или родственникам. Каждый из них работает на любом аккаунте и не затрагивает ваш. |
| `gift.quantityLabel` | How many | Сколько |
| `gift.buy` | Buy codes | Купить коды |
| `gift.starting` | Starting checkout… | Начало оформления заказа… |
| `gift.startFailed` | Could not start checkout | Не удалось начать оформление заказа. |
| `gift.boughtTitle` | Codes you've bought | Приобретенные вами коды |
| `gift.boughtEmpty` | You haven't bought any codes yet. | Вы ещё не приобрели ни одного кода. |
| `gift.statusAvailable` | Available | Доступный |
| `gift.statusRedeemed` | Redeemed | Искупленный |
| `gift.statusRevoked` | Revoked | Отменено |
| `gift.redeemedOn` | Redeemed {date} | Искуплено {date} |
| `gift.copyAll` | Copy all | Скопировать все |
| `gift.reveal.title` | Save these codes now | Сохраните эти коды прямо сейчас. |
| `gift.reveal.body` | Copy and share each code. For security we show them only once - afterwards you will see only a prefix. | Скопируйте и поделитесь каждым кодом. В целях безопасности мы показываем их только один раз - после этого вы будете видеть только префикс. |
| `gift.reveal.ack` | I have saved these codes | Я сохранил эти коды. |
| `gift.reveal.saved` | I've saved them | Я их сохранил. |
| `gift.reveal.leaveWarning` | Your codes are still on screen. If you leave now without saving them, you will not be able to see them again. | Ваши коды по-прежнему отображаются на экране. Если вы сейчас уйдете, не сохранив их, вы больше не сможете их увидеть. |

## `error` — API error messages shown to members.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `error.offline` | You appear to be offline. Check your connection and try again. | Похоже, вы офлайн. Проверьте подключение и повторите попытку. |
| `error.rateLimited` | Too many attempts. Please wait a minute and try again. | Слишком много попыток. Подождите минуту и повторите. |
| `error.backendUnavailable` | No proxy server is available right now. Your account is safe - try creating your key again in a few minutes. | Сейчас нет доступного прокси-сервера. Ваш аккаунт в безопасности - попробуйте создать ключ через несколько минут. |
| `error.generic` | Something went wrong. Please try again. | Что-то пошло не так. Повторите попытку. |
| `error.captchaFailed` | The human check failed. Please complete it and try again. | Проверка не пройдена. Завершите её и повторите попытку. |
| `error.captchaUnconfigured` | The service is temporarily unavailable. Please try again in a few minutes. | Сервис временно недоступен. Пожалуйста, повторите попытку через несколько минут. |
| `error.renderTitle` | Something went wrong | Что-то пошло не так. |
| `error.renderBody` | The page failed to render. This is a bug in the app, and refreshing usually fixes it. If it keeps happening, please report it. | Страница не отобразилась. Это ошибка в приложении, и обычно её устраняют обновление страницы. Если это повторяется, пожалуйста, сообщите об этом. |
| `error.reloadPage` | Reload page | Перезагрузить страницу |
| `error.tryAgain` | Try again | Попробуйте еще раз |
| `error.sessionExpired` | Your session has ended. Please sign in again. | Ваша сессия завершилась. Пожалуйста, войдите снова. |
| `error.invalidAccountId` | That account number wasn't recognized. Check it and try again. | Номер счета не распознан. Проверьте его и попробуйте снова. |
| `error.codeInvalid` | That code can't be redeemed. Check it for typos and try again. | Этот код нельзя активировать. Проверьте его на наличие опечаток и попробуйте снова. |
| `error.changeInProgress` | Another change is already in progress - try again in a moment. | Уже идёт очередное изменение - попробуйте ещё раз через мгновение. |
| `error.backendDisabled` | That option is currently unavailable. | В настоящее время эта опция недоступна. |
| `error.noPeerTier` | Switching isn't available for your plan yet. | Смена тарифного плана пока недоступна. |
| `error.deviceNotFound` | That device is no longer on your account. | Это устройство больше не привязано к вашему аккаунту. |
| `error.deviceUnsupported` | Your current server type doesn't support removing individual devices. | Ваш текущий тип сервера не поддерживает удаление отдельных устройств. |
| `error.billing` | The payment service couldn't process this. Please try again later. | Платежная система не смогла обработать этот платеж. Пожалуйста, попробуйте позже. |
| `error.serverError` | The server had a problem handling this. Please try again in a few minutes. | Сервер столкнулся с проблемой при обработке этого запроса. Пожалуйста, попробуйте еще раз через несколько минут. |

## `setup` — The "set up your app" section: recommended VPN clients per platform, install steps. *(26 missing)*

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `setup.title` | Set up your proxy app | Настройте прокси-приложение |
| `setup.install` | Install | Установить |
| `setup.noApps` | No recommended apps for this platform yet - use any compatible client and add your subscription manually. | ⚠️ **MISSING** |
| `setup.openSource` | Open source | ⚠️ **MISSING** |
| `setup.proprietary` | Proprietary | ⚠️ **MISSING** |
| `setup.easeEasy` | Easy to use | ⚠️ **MISSING** |
| `setup.easeAdvanced` | Advanced | ⚠️ **MISSING** |
| `setup.viewSource` | Source | ⚠️ **MISSING** |
| `setup.intro` | Copy your subscription link above, then add it to a compatible app: | Скопируйте ссылку подписки выше и добавьте её в совместимое приложение: |
| `setup.android` | Android | Android |
| `setup.ios` | iPhone / iPad | iPhone / iPad |
| `setup.windows` | Windows | Windows |
| `setup.desktop` | macOS / Linux | macOS / Linux |
| `setup.step.install` | Install the app | Установите приложение |
| `setup.step.import` | Open it, add a subscription / profile, and paste your link | Откройте его, добавьте подписку/профиль и вставьте свою ссылку |
| `setup.step.importConfig` | Open it, choose to add servers manually, and enter the configuration shown below | Откройте программу, выберите добавление серверов вручную и введите приведенную ниже конфигурацию. |
| `setup.step.connect` | Select a server and connect | Выберите сервер и подключитесь |
| `setup.noDeviceLimit` | no device limit | без ограничений по устройствам |
| `setup.hwidNote` | On a device-limited plan, turn on "device identification" (HWID) in the app's settings so your device is recognized. | При использовании тарифного плана с ограниченным количеством устройств включите функцию "идентификации устройства" (HWID) в настройках приложения, чтобы ваше устройство было распознано. |
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

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `mirror.disclosure` | Trouble connecting? | Проблемы с подключением? |
| `mirror.explainer` | If your normal subscription link won't connect where you are, add a mirror link below. It serves the same key from a different host that may not be blocked. | Если обычная ссылка-подписка не подключается в вашем регионе, добавьте зеркальную ссылку ниже. Она отдаёт тот же ключ с другого хоста, который может быть не заблокирован. |
| `mirror.addedLabel` | Your mirror links | Ваши зеркальные ссылки |
| `mirror.addToAppHint` | Add each one as an extra subscription in your app, then try connecting. | Добавьте каждую как отдельную подписку в приложении и попробуйте подключиться. |
| `mirror.regionLabel` | Your region | Ваш регион |
| `mirror.regionGlobal` | Global (any region) | Глобально (любой регион) |
| `mirror.regionNotStored` | Used only to pick a nearby mirror - it isn't stored. | Используется только для выбора ближайшего зеркала - не сохраняется. |
| `mirror.getButton` | Get a mirror link | Получить зеркальную ссылку |
| `mirror.tryAnother` | Try another mirror | Попробовать другое зеркало |
| `mirror.working` | Working… | Выполняется… |
| `mirror.capped` | You've added the maximum number of mirrors. | Вы добавили максимальное число зеркал. |
| `mirror.exhausted` | No more mirrors are available for your region right now. | Сейчас для вашего региона больше нет доступных зеркал. |
| `mirror.noSubscription` | Create your key first, then you can add a mirror. | Сначала создайте ключ, затем можно добавить зеркало. |
| `mirror.removeAll` | Remove all mirrors | Удалить все зеркала |
| `mirror.errorToast` | Couldn't add a mirror | Не удалось добавить зеркало |
| `mirror.removedToast` | Mirrors removed | Зеркала удалены |

## `rawconfig` — The raw-configuration viewer (privacy mode delivers config text, not a URL).

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `rawconfig.disclosure` | Show raw configuration | Показать необработанную конфигурацию |
| `rawconfig.title` | Your configuration | Ваша конфигурация |
| `rawconfig.explainer` | Your full proxy configuration, fetched over an encrypted channel so it never crosses a CDN in plain text. Copy it into your app by hand instead of using a subscription link. | Полная конфигурация вашего прокси, полученная по зашифрованному каналу - она никогда не проходит через CDN в открытом виде. Вставьте её в приложение вручную вместо ссылки-подписки. |
| `rawconfig.addHint` | Paste these server entries into your proxy app manually. | Вставьте эти серверные записи в ваше прокси-приложение вручную. |

## `delivery` — The connection-mode picker: "Beat censorship" (for censored countries) vs "Maximum privacy" (for open internet), plus the switch-confirmation dialog. *(6 missing)*

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `delivery.title` | What matters most to you? | Что для вас важнее всего? |
| `delivery.subtitle` | Pick a focus. It's saved on this device only, and you can change it anytime. | Выберите приоритет - сохраняется только на этом устройстве, изменить можно в любой момент. |
| `delivery.subtitleServer` | Pick a focus. Changing it moves your existing key to the matching servers - your subscription URL stays the same. | Выберите приоритет. Изменение приоритета приведет к повторной выдаче ключа для соответствующих серверов; ваш текущий ключ будет продолжать работать в течение 24 часов. |
| `delivery.subtitleSignup` | Pick a focus. It's saved to your account, and your first key uses it - you can change it anytime. | Выберите приоритет. Он сохраняется в вашем аккаунте, и ваш первый ключ будет его использовать - изменить можно в любой момент. |
| `delivery.evadeTitle` | Internet Freedom Mode | ⚠️ **MISSING** |
| `delivery.evadeAudience` | For censored countries | ⚠️ **MISSING** |
| `delivery.evadeBody` | Pick this if websites, apps, or VPNs are blocked where you are. Built to keep working under censorship, with backup links that are harder to block. | ⚠️ **MISSING** |
| `delivery.privacyTitle` | Privacy Mode | ⚠️ **MISSING** |
| `delivery.privacyAudience` | For open internet | ⚠️ **MISSING** |
| `delivery.privacyBody` | Pick this if the internet is mostly open where you are. The strongest confidentiality - your configuration stays off third-party servers - but it is easier for censors to block. | ⚠️ **MISSING** |
| `delivery.recommended` | Recommended | Рекомендуется |
| `delivery.unavailable` | Not available yet | Пока недоступно |
| `delivery.confirmTitle` | Switch to "{label}"? | Переключиться на " {label} "? |
| `delivery.confirmBody` | This moves your existing key to the {label} servers, keeping the same subscription URL. Your apps keep working and pick up the new servers on their next refresh. | Это повторно выпустит ваш прокси-ключ для серверов {label} . Ваш текущий ключ будет работать в течение 24 часов, поэтому вы можете сначала повторно импортировать данные на каждом устройстве. |
| `delivery.confirmPoint1` | Your key moves to the {label} servers - same subscription URL, nothing to re-import | Для серверов {label} выдан новый URL-адрес подписки. |
| `delivery.confirmPoint2` | Takes effect within a minute - reconnect in your app if it doesn't refresh on its own | Ваш текущий ключ продолжает работать в течение 24 часов, а затем удаляется. |
| `delivery.confirmPoint3` | Using the raw config? Copy the new one after switching | Вам потребуется повторно импортировать новый URL-адрес в каждый используемый вами VPN-клиент. |
| `delivery.confirmPointDevices [countPlural=one]` | Your 1 connected device will reconnect to the new servers | В данный момент у вас подключено 1 устройство; повторно импортируйте данные на него. |
| `delivery.confirmPointDevices [countPlural=other]` | Your {count} connected devices will reconnect to the new servers | В данный момент к вам подключено {count} устройств; повторно импортируйте данные на всех из них. |
| `delivery.confirm` | Switch focus | Переключить фокус |
| `delivery.working` | Switching… | Переключение… |
| `delivery.switchSuccessTitle` | Switched to "{label}" | Переключено на " {label} " |
| `delivery.switchSuccessBodyGrace` | Re-import the new subscription URL on each device. Your old key works for 24 more hours. | Повторно импортируйте новый URL-адрес подписки на каждое устройство. Ваш старый ключ будет действовать еще 24 часа. |
| `delivery.switchSuccessBody` | Same subscription URL - your apps will pick up the new servers on their next refresh. | Повторно импортируйте новый URL-адрес подписки на каждом устройстве. |
| `delivery.switchFailedTitle` | Could not switch focus | Не удалось переключить фокус. |

## `home` — The public landing page: hero, feature sections, impact section, FAQ intros. *(36 missing)*

| Key | English | Russian (Русский) |
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
| `home.hero.subtitle` | FreeSocks exists to get people online where the internet is censored, and works as a privacy-friendly VPN anywhere. One human-check creates your account: no email, no password, nothing that identifies you. Paste your subscription URL into any modern VPN client. A FreeSocks membership unlocks {limits}. | ⚠️ **MISSING** |
| `home.hero.impactNote` | Donations made through FreeSocks directly power free users: every donation buys real bandwidth for people in censored countries, that same month. | ⚠️ **MISSING** |
| `home.hero.impactLink` | See the impact | ⚠️ **MISSING** |
| `home.cta.getMembership` | Get a membership | Оформите членство |
| `home.freeCard.title` | Free tier | Бесплатный уровень |
| `home.freeCard.badge` | What you get | Что вы получите |
| `home.freeCard.urlTitle` | Xray subscription URL | URL-адрес подписки на рентгеновский снимок |
| `home.freeCard.urlBody` | Xray-powered VLESS. Paste into any compatible client. | Xray-powered VLESS. Paste into any compatible client. |
| `home.freeCard.membershipLine` | A FreeSocks membership gives you {limits}. | Подписка на FreeSocks предоставляет вам {limits} . |
| `home.freeCard.noAuthTitle` | No email or password | Электронная почта и пароль не требуются. |
| `home.freeCard.noAuthBody` | One human-check. Save your account number to sign in. No email collected. | Одна проверка человеком. Сохраните номер своего счета для входа. Адрес электронной почты не собирается. |
| `home.freeCard.footnote` | Numbers reflect the current free-tier configuration. Solve the check to get yours. | Цифры отражают текущую конфигурацию бесплатного тарифа. Пройдите проверку, чтобы получить свой. |
| `home.freeCard.upsellTitle` | Want unlimited? | Хотите безлимитный доступ? |
| `home.freeCard.upsellBody` | Get {limits} - and help keep FreeSocks free for others. | Получите {limits} - и помогите сохранить FreeSocks бесплатным для других. |
| `home.freeCard.fromPerMonth` | from {price}/mo | из {price} /mo |
| `home.freeCard.cryptoNote` | Crypto accepted - Bitcoin, Monero, Zcash and more | ⚠️ **MISSING** |
| `home.features.title` | What FreeSocks is | Что такое FreeSocks? |
| `home.features.noAuth.title` | No email or password | Электронная почта и пароль не требуются. |
| `home.features.noAuth.body` | One human-check and you are in. We mint a 32-digit account number you save to sign back in. No email collected. | Одна проверка человеком - и вы авторизованы. Мы создаём 32-значный номер аккаунта, который вы сохраняете для повторного входа. Адрес электронной почты не собирается. |
| `home.features.mirrors.title` | Mirror URLs | Зеркальные URL-адреса |
| `home.features.mirrors.body` | Subscriptions are mirrored across multiple providers so a single block does not cut you off. | Подписки дублируются у нескольких провайдеров, поэтому блокировка одного пакета услуг не приведет к отключению. |
| `home.features.protocols.title` | Standard protocols | Стандартные протоколы |
| `home.features.protocols.body` | Xray-powered VLESS. Works in most VPN clients. | Xray-powered VLESS. Works in most VPN clients. |
| `home.privacy.title` | What we store | Что мы храним |
| `home.privacy.subtitle` | FreeSocks is built to know as little about you as possible. | FreeSocks создан для того, чтобы знать о вас как можно меньше. |
| `home.privacy.point1` | We store only a hashed version of your account number - never the number itself. | Мы храним только хешированную версию номера вашего счета - сам номер никогда не сохраняется. |
| `home.privacy.point2` | No email, phone number, or name. We never ask for them. | Никакого адреса электронной почты, номера телефона или имени. Мы никогда их не запрашиваем. |
| `home.privacy.point3` | No logs of the sites you visit or the traffic you send - and we don't store your IP address, on our servers or the proxy nodes. | Никакой информации о посещаемых вами сайтах или об объеме трафика, который вы на них отправляете. |
| `home.privacy.point4` | We store no payment details - you pay on the provider's own page, and the provider never sees your account or proxy subscription. | Мы не храним никакие платежные данные - вы оплачиваете на странице самого провайдера, и провайдер никогда не видит вашу учетную запись или подписку на прокси. |
| `home.how.title` | How it works | Как это работает |
| `home.how.cta` | Try it now | Попробуйте прямо сейчас! |
| `home.how.s1.title` | Create a free account | Создайте бесплатный аккаунт |
| `home.how.s1.body` | Solve a quick human-check. You get a 32-digit account number to save: it is how you sign back in. | Пройдите быструю проверку на человека. Вам будет присвоен 32-значный номер счета для сохранения: именно по нему вы будете входить в систему. |
| `home.how.s2.title` | Create your subscription | Оформите подписку |
| `home.how.s2.body` | Once you are signed in, create a subscription URL, with a QR code for handoff to a phone. | После входа в систему создайте URL-адрес подписки с QR-кодом для передачи на телефон. |
| `home.how.s3.title` | Paste it into a VPN client | Вставьте это в VPN-клиент. |
| `home.how.s3.body` | Add the URL as a subscription in any compatible client. | Добавьте URL-адрес в качестве подписки в любом совместимом клиенте. |
| `home.membership.title` | Membership | Членство |
| `home.membership.lead` | Free covers the basics. | Бесплатная версия охватывает основные моменты. |
| `home.membership.descriptionFallback` | A FreeSocks membership lifts every limit. | Членство в FreeSocks снимает все ограничения. |
| `home.membership.payNote` | Pay privately with Bitcoin, Monero, or Zcash - or use a card or PayPal. | Оплачивайте криптовалютой (Bitcoin, Monero и другие), картой или PayPal. |
| `home.about.title` | About FreeSocks | ⚠️ **MISSING** |
| `home.about.bodyPrefix` | FreeSocks is operated by | FreeSocks управляется компанией |
| `home.about.bodySuffix` | , a US 501(c)(3) nonprofit. | ⚠️ **MISSING** |
| `home.about.siteLink` | unredacted.org | unredacted.org |
| `home.about.openSource` | The code that runs this service is published for anyone to inspect, audit, or run themselves. | ⚠️ **MISSING** |
| `home.about.viewSourceCta` | View the source | ⚠️ **MISSING** |
| `home.about.fact2Title` | Open source | ⚠️ **MISSING** |
| `home.about.fact3Title` | Donation funded | ⚠️ **MISSING** |
| `home.about.fact3Body` | Free accounts are paid for by donations and memberships. There are no ads and nothing is sold. | ⚠️ **MISSING** |
| `home.limits.unlimitedBoth` | unlimited bandwidth and devices | неограниченная пропускная способность и устройства |
| `home.limits.unlimitedBandwidth` | unlimited bandwidth | неограниченная пропускная способность |
| `home.limits.unlimitedDevices` | unlimited devices | неограниченное количество устройств |
| `home.limits.bandwidthAndDevices` | {bandwidth} and {devices} | {bandwidth} и {devices} |
| `home.limits.upToDevices [countPlural=one]` | up to 1 device | до 1 устройства |
| `home.limits.upToDevices [countPlural=other]` | up to {count} devices | до {count} устройств |

## `e2ee` — The HPKE/E2EE "encrypted to this server" badge + verification panel.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `e2ee.badgeActiveTitle` | Encrypted to this server with HPKE. Click to verify. | Зашифровано на этом сервере с помощью HPKE. Нажмите для проверки. |
| `e2ee.badgeWarnTitle` | Couldn't verify the encryption key. Click to verify out-of-band before entering your account number. | Не удалось проверить ключ шифрования. Нажмите, чтобы подтвердить его внеполосным способом, прежде чем вводить номер счета. |
| `e2ee.badgeActiveTitleAdmin` | Sensitive member and admin actions are HPKE-encrypted on this deployment. Click for details. | В этой версии системы конфиденциальные действия пользователей и администраторов шифруются с помощью HPKE. Нажмите для получения подробной информации. |
| `e2ee.badgeWarnTitleAdmin` | Couldn't verify this deployment's encryption key. Click for details and out-of-band verification. | Не удалось проверить ключ шифрования этого развертывания. Нажмите для получения подробной информации и внеполосной проверки. |
| `e2ee.badgeOff` | TLS | ТЛС |
| `e2ee.badgeOffTitle` | Standard TLS only. Extra HPKE body encryption isn't enabled on this deployment. | Используется только стандартный TLS. Дополнительное шифрование тела запроса HPKE в данной конфигурации не включено. |
| `e2ee.bannerWarn` | Couldn't verify the encryption key | Не удалось проверить ключ шифрования. |
| `e2ee.bannerWarnDetail` | Don't enter your account number yet - verify this connection out-of-band first. | Пока не вводите номер своего счета - сначала проверьте это соединение внеполосным способом. |
| `e2ee.verify` | Verify | Проверять |
| `e2ee.verifyTitle` | Verify this connection | Проверьте это соединение. |
| `e2ee.verifyIntro` | FreeSocks seals your account number and proxy key to this server with HPKE, so a compromised CDN can't read them. These fingerprints identify the keys your browser is using - compare them against the values published out-of-band to be sure they haven't been swapped. | FreeSocks защищает номер вашей учетной записи и ключ прокси-сервера с помощью HPKE, поэтому скомпрометированная CDN не сможет их прочитать. Эти «отпечатки» идентифицируют ключи, используемые вашим браузером - сравните их со значениями, опубликованными вне сети, чтобы убедиться, что они не были подменены. |
| `e2ee.protectHeading` | What this protects | Что это защищает |
| `e2ee.protectScope` | Your account number and key are encrypted to this server with HPKE, so the network and any CDN in front of it can't read them. | Номер вашего счета и ключ зашифрованы на этом сервере с помощью HPKE, поэтому сеть и любая CDN-сеть перед ним не смогут их прочитать. |
| `e2ee.protectServerReads` | FreeSocks itself can read them to set up your account, so this protects you from the network in between, not from the server. | FreeSocks сам может считывать их для настройки вашей учетной записи, поэтому это защищает вас от сетевой защиты, а не от защиты сервера. |
| `e2ee.protectTunnel` | It's separate from your VPN connection, which is encrypted on its own. | Это отдельная функция, не связанная с вашим VPN-соединением, которое шифруется самостоятельно. |
| `e2ee.protectAdmin` | On the admin dashboard, sensitive actions - creating API tokens, invites, and membership codes, and uploading backend, billing, or storage credentials - are HPKE-encrypted to this server too. Routine reads and settings use TLS, your passkey, and proof-of-possession. | На панели администратора конфиденциальные действия - создание токенов API, приглашений и кодов членства, а также загрузка учетных данных для бэкэнда, выставления счетов или хранения данных - также шифруются HPKE на этом сервере. Для обычных операций чтения и настройки используется TLS, ваш пароль и подтверждение владения. |
| `e2ee.fingerprintsHeading` | Key fingerprints | Ключевые отпечатки пальцев |
| `e2ee.fpHpke` | Server key (HPKE / X-Wing) | Ключ сервера (HPKE / X-Wing) |
| `e2ee.fpKid` | Key id | Идентификатор ключа |
| `e2ee.fpManifest` | Manifest key (Ed25519) | Ключ манифеста (Ed25519) |
| `e2ee.fpManifestPq` | Manifest key (ML-DSA-65, post-quantum) | Ключ манифеста (ML-DSA-65, постквантовый) |
| `e2ee.fpSuite` | Cipher suite | Набор шифров |
| `e2ee.copy` | Copy | Копия |
| `e2ee.copied` | Copied | Скопировано |
| `e2ee.attestationHeading` | Live server attestation | Аттестация работающего сервера |
| `e2ee.attestationOk` | Verified - the server is attesting a valid key signed by the manifest key your app trusts. | Подтверждено - сервер подтверждает действительность ключа, подписанного ключом манифеста, которому доверяет ваше приложение. |
| `e2ee.attestationEpoch` | Current key {kid}, expires {expiry}. | Текущий ключ {kid} , истекает {expiry} . |
| `e2ee.attestationFail` | Could not verify the server's current key - a network problem, or a CDN tampering with the key endpoint. Verify out-of-band before continuing. | Не удалось проверить текущий ключ сервера - проблема в сети или CDN вмешивается в работу конечной точки ключа. Перед продолжением проверьте внеполосное соединение. |
| `e2ee.attestationUnreachable` | The live key check is temporarily unavailable. Your connection still uses the verified key built into the app. | Функция проверки ключа в реальном времени временно недоступна. Ваше соединение по-прежнему использует проверенный ключ, встроенный в приложение. |
| `e2ee.attestationUnconfigured` | Live key checking isn't set up on this build. | В этой сборке проверка работоспособности клавиатуры в реальном времени не настроена. |
| `e2ee.compareHeading` | How to verify | Как проверить |
| `e2ee.compareBody` | Compare the fingerprints above against the values published through a channel this server doesn't control. They must match. | Сравните приведенные выше отпечатки пальцев со значениями, опубликованными по каналу, который не контролируется этим сервером. Они должны совпадать. |
| `e2ee.channelRelease` | Signed release notes | Подписанные примечания к выпуску |
| `e2ee.channelSource` | Source code (rebuild to compare) | Исходный код (для сравнения пересоберите) |
| `e2ee.channelOnion` | Tor mirror | Зеркало Тора |
| `e2ee.dnsHeading` | Verify via DNS | Проверка через DNS |
| `e2ee.dnsBody` | Look the pin up yourself in a terminal, through your own DNS resolver - a path that doesn't run through this site or its CDN. The answer should contain the same fingerprints shown above. (If it returns nothing, the operator may not have published the record yet; use the signed release instead.) | Найдите PIN-код самостоятельно в терминале, используя свой собственный DNS-сервер - путь, который не проходит через этот сайт или его CDN. Ответ должен содержать те же отпечатки, что и выше. (Если он ничего не возвращает, возможно, оператор еще не опубликовал запись; используйте вместо этого подписанный релиз.) |
| `e2ee.dnsCommand` | Run this in a terminal | Выполните это в терминале. |
| `e2ee.dnsExpected` | It should return | Оно должно вернуться |
| `e2ee.dnsCaveat` | Independent only if your DNS isn't run by the same company as the CDN; a DNSSEC-validating resolver is best. For full assurance, confirm the same values in the signed release too. | Независимый сервер необходим только в том случае, если ваш DNS-сервер управляется не той же компанией, что и CDN; лучше всего использовать DNSSEC-проверяющий резолвер. Для полной уверенности подтвердите одинаковые значения и в подписанном релизе. |
| `e2ee.verifierExtension` | A verifier browser extension that re-checks this build on every visit is planned, but not available yet. | Планируется выпуск расширения для браузера, которое будет повторно проверять эту сборку при каждом посещении, но пока оно недоступно. |
| `e2ee.verifierExtensionInstall` | Install the verifier extension - it re-checks this build against the published one on every visit (the strongest protection against a tampered page). | Установите расширение для проверки - оно будет перепроверять эту сборку на соответствие опубликованной при каждом посещении (самая надежная защита от подделки страницы). |
| `e2ee.caveat` | This in-page check is a convenience. A tampered page could lie about its own status, so the real proof comes from comparing these values somewhere outside this server, such as the DNS lookup above or a published release. | Эта проверка на странице - удобство. Подделанная страница может искажать свой собственный статус, поэтому реальное доказательство можно получить, сравнив эти значения с данными за пределами этого сервера, например, с результатами DNS-запроса, приведенного выше, или с опубликованным релизом. |
| `e2ee.close` | Close | Закрывать |

## `deviceRevoke` — The disconnect-a-device confirmation dialog.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `deviceRevoke.title` | Revoke this device? | Отозвать это устройство? |
| `deviceRevoke.body` | The device ending …{suffix} will be disconnected and its slot freed. It can reconnect later by re-importing your subscription URL. | Устройство, оканчивающееся на … {suffix} будет отключено, и его слот освободится. Позже его можно будет повторно подключить, повторно импортировав URL-адрес вашей подписки. |
| `deviceRevoke.confirm` | Revoke device | Отменить устройство |
| `deviceRevoke.working` | Revoking… | Отмена… |
