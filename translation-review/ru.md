# FreeSocks translation review — Russian (Русский)

Generated from `messages/en.json` (source of truth) vs `messages/ru.json`.
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

- Edit the **"Russian (Русский)" column** (or add a correction below a row). Rows marked
  ⚠️ MISSING have no translation yet.


## `faq` — The landing-page FAQ (questions + answers).

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `faq.title` | Frequently asked questions | Часто задаваемые вопросы |
| `faq.subtitle` | Answers to common questions. | Основные вопросы решены. Остались вопросы? Свяжитесь со службой поддержки, указав свой идентификатор. |
| `faq.tabGeneral` | General | Общие |
| `faq.tabThreat` | What we protect you from | От чего мы вас защищаем |
| `faq.contactPrefix` | For anything else, email | По всем остальным вопросам пишите на |
| `faq.contactSuffix` | and include your Support ID. | и укажите свой ID для поддержки. |
| `faq.q1.question` | What is FreeSocks? | Что такое FreeSocks? |
| `faq.q1.answer` | A free VPN service that helps people in heavily-censored regions reach the open internet. It's operated by Unredacted, a US 501(c)(3) nonprofit. | Бесплатный прокси-сервис, помогающий людям в регионах с жесткой цензурой получить доступ к открытому интернету. Он управляется некоммерческой организацией Unredacted, зарегистрированной в США как 501(c)(3). |
| `faq.q2.question` | Is it really free? | Это действительно бесплатно? |
| `faq.q2.answer` | Yes. A free account gives you a working VPN. A paid FreeSocks membership lifts the limits and helps fund free access for others. | Да. Бесплатный аккаунт предоставляет вам работающий прокси. Платная подписка FreeSocks снимает ограничения и помогает финансировать бесплатный доступ для других пользователей. |
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
| `faq.q10.question` | Do you own your servers, or rent them? | У вас собственные серверы или арендованные? |
| `faq.q10.answer` | We own our hardware and run it ourselves. Plenty of VPN companies rent theirs from datacenters or cloud hosts, which puts the machine your traffic passes through in someone else's hands - they can be pressured to hand it over, or just quietly copy what is on it. That is a line we are not willing to cross, so we buy and run our own equipment instead. It costs more and we grow slower because of it, but it is the only way the privacy promises on this page actually mean anything. | Мы владеем своим оборудованием и обслуживаем его сами. Многие VPN-компании арендуют серверы в дата-центрах или у облачных провайдеров, и тогда машина, через которую проходит ваш трафик, оказывается в чужих руках - её могут заставить передать или просто незаметно скопировать всё, что на ней есть. Мы не готовы переступить эту черту, поэтому покупаем и обслуживаем собственное оборудование. Это дороже, и из-за этого мы растём медленнее, но только так обещания приватности на этой странице действительно что-то значат. |

## `threat` — Miscellaneous strings.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `threat.subtitle` | An honest look at what this service can and cannot do. Security tools that overpromise get people hurt, so here is exactly where the lines are. | Честный взгляд на то, что этот сервис может и чего не может. Инструменты безопасности, которые обещают слишком много, могут навредить людям, поэтому здесь точно указано, где проходят границы. |
| `threat.q1.question` | What does FreeSocks protect me from? | От чего FreeSocks меня защищает? |
| `threat.q1.answer` | FreeSocks tunnels your traffic through an encrypted VPN connection, so your ISP, mobile carrier, school, or workplace network cannot see which sites you visit or block them. It is built for getting past censorship and for keeping the network you are on from watching what you do. | FreeSocks направляет ваш трафик через зашифрованное VPN-соединение, поэтому ваш провайдер, мобильный оператор, школа или рабочая сеть не видят, какие сайты вы посещаете, и не могут их заблокировать. Сервис создан для обхода цензуры и для того, чтобы сеть, в которой вы находитесь, не следила за тем, что вы делаете. |
| `threat.q2.question` | What does FreeSocks NOT protect me from? | От чего FreeSocks НЕ защищает? |
| `threat.q2.answer` | It does not make you anonymous to sites you sign in to: if you log in to an account, that site knows who you are. It cannot protect a device that is already compromised (spyware, a managed work profile, someone with physical access). And a powerful adversary that can watch traffic at many points on the internet may still correlate patterns. If your safety depends on strong anonymity, use Tor and follow specialist guidance for your situation. | Он не делает вас анонимным для сайтов, на которых вы входите в аккаунт: если вы вошли, сайт знает, кто вы. Он не может защитить уже скомпрометированное устройство (шпионское ПО, управляемый рабочий профиль, кто-то с физическим доступом). А сильный противник, способный наблюдать трафик во многих точках интернета, всё ещё может сопоставить закономерности. Если ваша безопасность зависит от надёжной анонимности, используйте Tor и следуйте рекомендациям специалистов для вашей ситуации. |
| `threat.q3.question` | Can FreeSocks see my traffic? | Видит ли FreeSocks мой трафик? |
| `threat.q3.answer` | Your traffic exits through our servers, so treat us like any exit: sites you use over HTTPS (almost all of the modern web) stay encrypted end to end and we cannot read their contents. We configure our servers to keep no connection logs, no visited-site logs, and no source IPs, and the control plane never stores your IP address at all. | Ваш трафик выходит через наши серверы, поэтому относитесь к нам как к любой точке выхода: сайты, которые вы используете по HTTPS (почти весь современный интернет), остаются зашифрованными от начала до конца, и мы не можем прочитать их содержимое. Мы настраиваем серверы так, чтобы не вести журналы подключений, журналы посещённых сайтов и не хранить исходные IP-адреса, а панель управления вообще никогда не хранит ваш IP-адрес. |
| `threat.q4.question` | What happens if a FreeSocks server is seized or compromised? | Что будет, если сервер FreeSocks изымут или взломают? |
| `threat.q4.answer` | There is nothing identifying on it. Servers hold no names, emails, IPs, or traffic history, because we never collect those in the first place. Access keys can be revoked and reissued quickly, and we can rotate infrastructure without losing accounts. | На нём нет ничего, что могло бы вас идентифицировать. На серверах нет имён, адресов почты, IP-адресов и истории трафика, потому что мы их вообще не собираем. Ключи доступа можно быстро отозвать и перевыпустить, а инфраструктуру заменить без потери аккаунтов. |
| `threat.q5.question` | Can my government or ISP tell that I am using FreeSocks? | Могут ли власти или провайдер понять, что я пользуюсь FreeSocks? |
| `threat.q5.answer` | Sometimes censors can detect that circumvention traffic is in use even when they cannot read it. Our transports are designed to look like ordinary encrypted web traffic, and Internet Freedom Mode routes through infrastructure that is expensive to block. Still, whether use is detectable, and what the consequences are, varies by country. Weigh your local risk. | Иногда цензоры могут обнаружить сам факт использования трафика обхода блокировок, даже когда не могут его прочитать. Наши транспорты маскируются под обычный зашифрованный веб-трафик, а режим свободного интернета работает через инфраструктуру, которую дорого блокировать. Всё же то, заметно ли использование и каковы последствия, зависит от страны. Оцените свой местный риск. |
| `threat.q6.question` | Why should I believe any of this? | Почему мне стоит этому верить? |
| `threat.q6.answer` | The control plane is open source, so anyone can read exactly what it stores and check that there is no place a name, email, or IP address could even go. Claims that depend on server configuration (like disabled logging) are documented and enforced by the same code. You still have to trust the operator for the parts you cannot see, as with every VPN; our approach is to minimize what there is to trust. | Панель управления - открытый код, поэтому любой может прочитать, что именно она хранит, и убедиться, что в ней просто некуда записать имя, почту или IP-адрес. Утверждения, зависящие от настройки серверов (например, отключённые журналы), задокументированы и обеспечиваются тем же кодом. За то, чего вы не видите, вам всё равно придётся доверять оператору, как с любым VPN; наш подход - свести к минимуму то, чему нужно доверять. |
| `threat.q7.question` | Do payments link my identity to my browsing? | Связывают ли платежи мою личность с моими действиями в сети? |
| `threat.q7.answer` | Membership is optional, and payment is handled by outside processors: we never store the payer's name, email, or address, and an order is tied to your account only through an opaque reference. Cryptocurrency options (including Monero) exist for people who do not want a card trail at all. | Членство необязательно, а оплату обрабатывают внешние платёжные системы: мы никогда не храним имя, почту или адрес плательщика, и заказ связан с вашим аккаунтом только через непрозрачный идентификатор. Для тех, кто вообще не хочет оставлять карточный след, есть оплата криптовалютой (включая Monero). |

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

## `nav` — The site header: navigation buttons, menu, language/theme controls.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `nav.getAccount` | Get a free account | Получить бесплатный аккаунт |
| `nav.signIn` | Sign in | Войти |
| `nav.account` | My account | Мой аккаунт |
| `nav.menu` | Menu | Меню |
| `nav.theme` | Theme | Тема |
| `nav.home` | FreeSocks home | Главная FreeSocks |

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
| `captcha.failedTip2` | Try a different network - or a VPN if sites are blocked where you are | Попробуйте другую сеть - или VPN/прокси, если сайты заблокированы в вашем регионе |
| `captcha.failedTip3` | Still stuck? Try a private/incognito window or turn off browser extensions | Всё ещё не работает? Откройте приватное окно или отключите расширения браузера |

## `reveal` — The save-your-account-number modal (the 32-digit sign-in number is shown ONCE; users must download it and paste it back to verify). The single most safety-critical copy in the product.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `reveal.title` | Save your account number now | Сохраните номер аккаунта сейчас |
| `reveal.subtitle` | This 32-digit number is the ONLY way to sign in again. There is no email or password to recover it. If you lose it, your account is gone for good. | Этот 32-значный номер - единственный способ снова войти. Нет ни почты, ни пароля для восстановления. Если вы его потеряете, аккаунт будет утрачен навсегда. |
| `reveal.cannotRecover` | We cannot recover it for you - not even support can. | Мы не сможем его восстановить - даже поддержка не сможет. |
| `reveal.saveHint` | Save it in a password manager, or write it down somewhere safe and private. | Сохраните его в менеджере паролей или запишите в надёжном личном месте. |
| `reveal.downloadRequired` | Download your account number to continue. Keep the file somewhere safe. | Скачайте номер аккаунта, чтобы продолжить. Храните файл в надёжном месте. |
| `reveal.continue` | Continue | Продолжить |
| `reveal.verifyTitle` | Confirm you saved it | Подтвердите, что вы его сохранили |
| `reveal.verifySubtitle` | Your account number is now hidden. Enter or paste it from the copy you just saved to confirm you can sign in later. | Номер аккаунта теперь скрыт. Введите или вставьте его из только что сохранённой копии, чтобы подтвердить, что вы сможете войти позже. |
| `reveal.verifyPlaceholder` | Paste your 32-digit account number | Вставьте свой 32-значный номер аккаунта |
| `reveal.verifyMismatch` | That doesn't match your account number. Check the copy you saved, or go back to see it again. | Это не совпадает с вашим номером аккаунта. Проверьте сохранённую копию или вернитесь назад, чтобы посмотреть его снова. |
| `reveal.back` | Back | Назад |
| `reveal.done` | I've saved it | Я сохранил |
| `reveal.savedConfirmed` | Account number saved and verified | Номер аккаунта сохранён и подтверждён |
| `reveal.downloadFilename` | freesocks-account-number.txt | freesocks-account-number.txt |
| `reveal.leaveWarning` | Your account number is still on screen. If you leave now without saving it, you will not be able to sign in again. | Номер аккаунта всё ещё на экране. Если вы уйдёте сейчас, не сохранив его, вы не сможете снова войти. |

## `support` — The support-ID line (a non-secret handle for contacting support).

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `support.label` | Support ID | ID для поддержки |
| `support.hint` | Share this if you contact us. It is NOT your sign-in number and grants no access. | Сообщите его, если обращаетесь к нам. Это не номер для входа и не даёт доступа. |
| `support.copyAria` | Copy your support ID | Скопировать ID для поддержки |
| `support.emailUs` | Email us: | Напишите нам: |
| `support.getAccountLine` | Questions or problems? Email us at | Вопросы или проблемы? Напишите нам на |

## `login` — The sign-in page (account number + optional passkey).

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
| `login.or` | or | или |

## `passkey` — Optional passkey (Face ID / fingerprint) sign-in management.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `passkey.title` | Passkeys | Пасс-ключи |
| `passkey.desc` | Sign in with Face ID, Touch ID, a security key, or your password manager - no account number to type. | Входите через Face ID, Touch ID, аппаратный ключ безопасности или менеджер паролей - без ввода номера аккаунта. |
| `passkey.warning` | Heads-up: a passkey saved on your phone or in your browser may sync to your Apple or Google account, which can link this anonymous account to that identity. Use a hardware security key, or skip passkeys, if that matters to you. | Важно: пасс-ключ, сохранённый на телефоне или в браузере, может синхронизироваться с вашим аккаунтом Apple или Google, и это может связать этот анонимный аккаунт с вашей личностью. Если для вас это важно, используйте аппаратный ключ безопасности или не используйте пасс-ключи. |
| `passkey.unsupported` | This device or browser doesn't support passkeys. | Это устройство или браузер не поддерживает пасс-ключи. |
| `passkey.none` | No passkeys yet. Your account number still signs you in. | Пасс-ключей пока нет. Номер аккаунта по-прежнему позволяет войти. |
| `passkey.add` | Add a passkey | Добавить пасс-ключ |
| `passkey.adding` | Adding… | Добавление… |
| `passkey.added` | Passkey added | Пасс-ключ добавлен |
| `passkey.addFailed` | Couldn't add the passkey | Не удалось добавить пасс-ключ |
| `passkey.remove` | Remove | Удалить |
| `passkey.removed` | Passkey removed | Пасс-ключ удалён |
| `passkey.removeFailed` | Couldn't remove the passkey | Не удалось удалить пасс-ключ |
| `passkey.deviceLabelLabel` | Device name (optional) | Название устройства (необязательно) |
| `passkey.deviceLabelPlaceholder` | e.g. My phone | например, Мой телефон |
| `passkey.addedOn` | Added {date} | Добавлен {date} |
| `passkey.lastUsed` | last used {date} | последний вход {date} |
| `passkey.signIn` | Sign in with a passkey | Войти с пасс-ключом |
| `passkey.signingIn` | Authenticating… | Проверка… |
| `passkey.signInFailed` | Passkey sign-in failed | Не удалось войти с пасс-ключом |
| `passkey.notNow` | Not now | Не сейчас |

## `account` — The signed-in /account dashboard: connection, membership, codes, security tabs.

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
| `account.noSubTitle` | No key yet | Подписки пока нет |
| `account.noSubBody` | Create your key to get a link you can use in any compatible VPN app. | Создайте первую подписку, чтобы получить ссылку для любого совместимого VPN-клиента. |
| `account.createSub` | Get my key | Создать подписку |
| `account.creating` | Creating your key… | Создание… |
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
| `account.membershipNudge.bodyNoDevices` | Unlimited bandwidth. | Безлимитный трафик. |
| `account.membershipNudge.cta` | View membership | Открыть подписку |
| `account.tab.connection` | Connection | Подключение |
| `account.tab.membership` | Membership | Членство |
| `account.tab.gifts` | Gifts & referrals | Подарки и приглашения |
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
| `account.keyActionsHint` | These change your VPN connection only - your 32-digit account number stays the same. | Эти изменения касаются только подключения к прокси-серверу - ваш 32-значный номер счета остается неизменным. |
| `account.section.connection.title` | Your connection | Ваше соединение |
| `account.section.connection.desc` | Your VPN key, setup help, and connected devices. | Ваш прокси-ключ, справка по настройке и подключенные устройства. |
| `account.section.membership.title` | Membership | Членство |
| `account.section.membership.desc` | Your plan, and how to upgrade or extend it. | Ваш план и способы его модернизации или расширения. |
| `account.section.gifts.title` | Gifts & referrals | Подарки и приглашения |
| `account.section.gifts.desc` | Redeem a code, buy codes to share, and invite people you trust. | Погасите код, купите коды в подарок и пригласите тех, кому доверяете. |
| `account.section.codes.title` | Codes & gifts | Коды и подарки |
| `account.section.codes.desc` | Redeem a membership code, or buy codes to share with others. | Активируйте промокод или купите коды, чтобы поделиться ими с другими. |
| `account.section.security.title` | Account & security | Учетная запись и безопасность |
| `account.section.security.desc` | Your support ID and account-number controls. | Ваш идентификатор службы поддержки и номер счета находятся под контролем. |
| `account.deviceRevoke` | Revoke | Отменить |
| `account.deviceRevokedTitle` | Device revoked | Устройство аннулировано |
| `account.deviceRevokedBody` | The slot is free. That device loses access until it re-imports your subscription. | Слот бесплатный. Это устройство потеряет доступ, пока не повторно не импортирует вашу подписку. |
| `account.deviceRevokeFailedTitle` | Couldn't revoke the device | Не удалось отозвать устройство. |

## `hero` — The subscription panel: the key/URL block, traffic + expiry stats, QR, status callouts.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `hero.titleDefault` | Your key | Ваша подписка |
| `hero.eyebrowAccessKey` | FreeSocks Access Pass | Ваш ключ доступа |
| `hero.urlLabelSubscription` | Your link | Ссылка подписки |
| `hero.urlLabelAccessKey` | Access key | Ключ доступа |
| `hero.tierLine` | Plan {tier} | Тариф {tier} |
| `hero.viaLine` | via {backend} | через {backend} |
| `hero.copyUrl` | Copy link | Копировать ссылку |
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
| `hero.fallbackLabel` | Fallback link | Резервная ссылка |
| `hero.fallbackHint` | Use this if the main link gets blocked | Используйте её, если основную ссылку заблокируют |
| `hero.fallbackQrAria` | Show fallback link QR code | Показать QR-код резервной ссылки |
| `hero.downloaded` | Downloaded {filename} | Скачан файл {filename} |
| `hero.traffic` | Traffic | Трафик |
| `hero.unlimited` | Unlimited | Безлимит |
| `hero.configBelowNote` | Your full configuration is below - add the servers by hand. For privacy, the auto-updating subscription link isn't shown by default (your app would fetch it through a CDN). | Ваша полная конфигурация ниже - добавьте серверы вручную. Для приватности автообновляемая ссылка подписки по умолчанию не показывается (приложение получало бы её через CDN). |
| `hero.showUrlAnyway` | Show the subscription link anyway | Всё равно показать ссылку подписки |
| `hero.urlDangerBody` | This link works in any app, but the app then downloads your configuration through a third-party CDN in plain text - the CDN operator can see your server details and that you use FreeSocks. That is exactly what this focus avoids. Use it only if your app cannot import the configuration below. | Эта ссылка работает в любом приложении, но тогда приложение скачивает вашу конфигурацию через стороннюю CDN в открытом виде - оператор CDN может видеть данные вашего сервера и то, что вы пользуетесь FreeSocks. Именно этого избегает этот приоритет. Используйте её, только если ваше приложение не может импортировать конфигурацию ниже. |
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
| `hero.nodeOnline` | Node online | Узел в сети |
| `hero.nodeOffline` | Node offline | Узел не в сети |
| `hero.nodeUnknown` | Node status unknown | Статус узла неизвестен |
| `hero.nodeStatusLink` | Network status | Состояние сети |
| `hero.nodeOnlineHint` | The server behind your config is up and responding. If you still can't connect, your network or ISP is likely filtering it - try another connection mode or location. | Сервер вашей конфигурации работает и отвечает. Если подключиться всё равно не удаётся, скорее всего, ваша сеть или провайдер его фильтрует - попробуйте другой режим подключения или другую локацию. |
| `hero.nodeOfflineBody` | The server behind your config is currently offline. This is on our side, not your network. Try again in a few minutes, or create a new config (optionally in a different location). | Сервер вашей конфигурации сейчас не в сети. Проблема на нашей стороне, а не в вашей сети. Попробуйте снова через несколько минут или создайте новую конфигурацию (можно в другой локации). |
| `hero.keyLimited` | You've used all your data for this period. It resets automatically, or you can upgrade for more. | Вы использовали весь свой трафик за этот период. Он автоматически обнуляется, или вы можете приобрести более дорогой тарифный план. |
| `hero.keyExpired` | This key has expired. Renew your membership or create a new key to reconnect. | Срок действия этого ключа истек. Продлите свою подписку или создайте новый ключ для повторного подключения. |
| `hero.keyDisabled` | This key is currently disabled. If your membership lapsed, renew it; otherwise contact support with your support ID. | Этот ключ в настоящее время отключен. Если срок действия вашей подписки истек, продлите ее; в противном случае свяжитесь со службой поддержки, указав свой идентификатор службы поддержки. |
| `hero.resetsInDays [countPlural=one]` | Resets in 1 day | Сброс через 1 день |
| `hero.resetsInDays [countPlural=other]` | Resets in {count} days | Сбросы в {count} днях |

## `location` — Miscellaneous strings.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `location.pickerLabel` | Server location | Локация сервера |
| `location.auto` | Automatic (least busy) | Автоматически (наименее загруженная) |
| `location.offline` | offline | не в сети |
| `location.pickerHint` | Where your config's server is. Automatic picks the least busy location; pick one yourself if it works better on your network. | Где находится сервер вашей конфигурации. Автоматический выбор берёт наименее загруженную локацию; выберите сами, если в вашей сети так работает лучше. |

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

## `get` — The /get-account sign-up flow: create account (step 1) and create subscription (step 2).

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `get.badge` | Free account | Бесплатный аккаунт |
| `get.title` | Get a FreeSocks account | Получите аккаунт FreeSocks |
| `get.progressAria` | Sign-up progress | Прогресс регистрации |
| `get.progress.step1` | Create account | Создание аккаунта |
| `get.progress.step2` | Save your number | Сохраните номер |
| `get.progress.step3` | Get connected | Подключитесь |
| `get.step1Title` | Create your account | Создайте аккаунт |
| `get.chooseBackend` | Choose a connection type | Выберите тип сервера |
| `get.backendAria` | Connection type | Тип сервера |
| `get.backendMultiProtocol` | VLESS (Xray) | VLESS (Xray) |
| `get.backendShadowsocks` | Shadowsocks via Outline | Shadowsocks через Outline |
| `get.createAccount` | Create my account | Создать аккаунт |
| `get.freeAccountNote` | Free accounts are valid for {days} days and limited to {devices}. No email or password. | Бесплатные аккаунты действуют {days} дней · {devices}. Без почты и пароля. |
| `get.freeAccountNoteNoDevices` | Free accounts are valid for {days} days. No email or password. | Бесплатные аккаунты действуют {days} дней. Без почты и пароля. |
| `get.step3Title` | Get your key | Получите свой ключ |
| `get.step3Intro` | Your key is what connects your app to the VPN. Create it, then add it to your app. | Ключ - это то, что связывает ваше приложение с VPN. Создайте его и добавьте в приложение. |
| `get.manageHintPrefix` | Manage your key anytime from | Управляйте этой подпиской в любое время из |
| `get.manageLinkLabel` | your account | вашего аккаунта |
| `get.subErrorSafePrefix` | Your account is safe. You can create your key later from | Ваш аккаунт в безопасности. Подписку можно создать позже из |
| `get.subErrorSafeSuffix` | once a server is available. | когда сервер станет доступен. |
| `get.createSubToastTitle` | Your key is ready | Подписка создана |
| `get.createSubToastBody` | Copy the link into your VPN app, or scan the QR code. | Скопируйте ссылку в VPN-клиент или отсканируйте QR-код. |
| `get.createAccountFailedTitle` | Could not create account | Не удалось создать аккаунт |
| `get.createSubFailedTitle` | Could not create your key | Не удалось создать подписку |
| `get.haveAccountPrefix` | Already have an account? | Уже есть аккаунт? |
| `get.lostNumberHint` | Lost your account number before saving it? You can switch to a new one - | Потеряли номер аккаунта, не успев сохранить? Можно получить новый - |
| `get.lostNumberLinkLabel` | change it from your account page | смените его на странице аккаунта |
| `get.redeemPrompt` | Have a gift code? Redeem it before creating your key. | Есть подарочный код? Активируйте его перед созданием ключа. |
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

## `impact` — The donation-impact panel: bandwidth donated, free users helped, charts.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `impact.title` | Donations support Unredacted | Пожертвования поддерживают Unredacted |
| `impact.body` | Unredacted is a US 501(c)(3) nonprofit. FreeSocks is one of the projects it runs. Donations fund the work. See what that work is on the Unredacted site. | Unredacted - американская некоммерческая организация 501(c)(3). FreeSocks - один из её проектов. Работа финансируется пожертвованиями. Подробности - на сайте Unredacted. |
| `impact.collectiveTitle` | Donation impact | Вклад пожертвований |
| `impact.collectiveBody` | Donations made through FreeSocks raise every free user's monthly bandwidth for the month they're given. This is what the community's donations are doing right now. | Пожертвования, сделанные через FreeSocks, увеличивают месячный трафик каждого бесплатного пользователя в том месяце, в котором они сделаны. Вот что дают пожертвования сообщества прямо сейчас. |
| `impact.bonusThisMonth` | GB added this month | ГБ добавлено в этом месяце |
| `impact.bonusThisMonthDetail` | on top of every free account's monthly allowance | сверх месячной нормы каждого бесплатного аккаунта |
| `impact.usersHelped` | free accounts reached | охвачено бесплатных аккаунтов |
| `impact.usersHelpedDetail` | active free users whose allowance the bonus raises | активные бесплатные пользователи, чью норму увеличивает бонус |
| `impact.historyTitle` | Bandwidth added per month | Добавленный трафик по месяцам |
| `impact.chartAria` | Bandwidth added to every free user by donations, month by month over the last {n} months | Трафик, добавленный каждому бесплатному пользователю за счёт пожертвований, по месяцам за последние {n} месяцев |
| `impact.yourContribution` | Your contribution | Ваш вклад |
| `impact.yourGiven` | You've given {amount} | Вы пожертвовали {amount} |
| `impact.yourGb` | That's about {gb} GB of extra bandwidth for free users | Это примерно {gb} ГБ дополнительного трафика для бесплатных пользователей |
| `impact.yourCount [countPlural=one]` | across 1 donation | за 1 пожертвование |
| `impact.yourCount [countPlural=other]` | across {count} donations | за {count} пожертвований |
| `impact.empty` | No donations yet this month - the first one starts the counter. | В этом месяце пожертвований пока нет - первое запустит счётчик. |
| `impact.externalNote` | This counter tracks donations made through FreeSocks only. Gifts made directly at unredacted.org/donate support Unredacted's wider work, but don't add bandwidth here. | Этот счётчик учитывает только пожертвования, сделанные через FreeSocks. Пожертвования напрямую на unredacted.org/donate поддерживают более широкую работу Unredacted, но не добавляют трафик здесь. |
| `impact.aboutUnredacted` | About Unredacted | Об Unredacted |

## `donate` — The donation card + amount picker (donations add bandwidth for all free users).

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `donate.addTitle` | Add a donation | Добавить пожертвование |
| `donate.addSubtitle` | Chip in to help keep FreeSocks free for everyone. | Внесите вклад, чтобы FreeSocks оставался бесплатным для всех. |
| `donate.standaloneTitle` | Donate to FreeSocks | Поддержать FreeSocks |
| `donate.standaloneSubtitle` | FreeSocks is free for everyone, funded by donations. Give any amount to help keep it running - a donation also raises this month's bandwidth for every free user. | FreeSocks бесплатен для всех и существует на пожертвования. Поддержите любой суммой, чтобы он продолжал работать, - пожертвование также увеличивает трафик каждого бесплатного пользователя в этом месяце. |
| `donate.amountLabel` | Amount | Сумма |
| `donate.none` | No thanks | Нет, спасибо |
| `donate.custom` | Custom | Своя сумма |
| `donate.customPlaceholder` | Other amount | Другая сумма |
| `donate.impact` | Adds about {gb} GB to every free user this month | Добавит примерно {gb} ГБ каждому бесплатному пользователю в этом месяце |
| `donate.bonusActive` | Donations this month have added {gb} GB to every free user's monthly allowance. | Пожертвования этого месяца добавили {gb} ГБ к месячной норме каждого бесплатного пользователя. |
| `donate.minNote` | Minimum {amount} | Минимум {amount} |
| `donate.give` | Donate {amount} | Пожертвовать {amount} |
| `donate.giving` | Starting… | Начинаем… |
| `donate.startFailed` | Couldn't start the donation | Не удалось начать пожертвование |
| `donate.badge` | Donor | Донор |
| `donate.badgeTooltip` | Thank you for supporting FreeSocks | Спасибо за поддержку FreeSocks |
| `donate.thanksTitle` | You're a FreeSocks donor | Вы - донор FreeSocks |
| `donate.thanksBody` | Thank you - your support helps keep FreeSocks free for everyone. | Спасибо - ваша поддержка помогает FreeSocks оставаться бесплатным для всех. |

## `referral` — Miscellaneous strings.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `referral.fieldLabel` | Referral code (optional) | Реферальный код (необязательно) |
| `referral.fieldHint` | Have a code from a friend? You each get bonus membership days when you upgrade. | Есть код от друга? Каждый из вас получит бонусные дни членства, когда вы оформите его. |
| `referral.fieldPlaceholder` | FSR-XXXX-XXXX | FSR-XXXX-XXXX |
| `referral.applied` | Referral applied — bonus days are yours when you upgrade. | Реферальный код применён - бонусные дни будут вашими при оформлении членства. |
| `referral.cardTitle` | Referrals | Приглашения |
| `referral.cardBody` | Share your link. When someone signs up with it and becomes a member, you each get bonus days — theirs right away, yours after {vestingDays} days. | Поделитесь своей ссылкой. Когда кто-то зарегистрируется по ней и станет членом, вы оба получите бонусные дни - он сразу, а вы через {vestingDays} дней. |
| `referral.copyLink` | Copy invite link | Копировать ссылку-приглашение |
| `referral.codeLabel` | Your code | Ваш код |
| `referral.statsInvited` | Signed up | Зарегистрировались |
| `referral.statsConverted` | Became members | Стали членами |
| `referral.statsPending` | Not yet members | Пока не члены |
| `referral.statsDays` | Bonus days earned | Заработано бонусных дней |

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

## `footer` — The site footer (nonprofit line, terms/privacy links).

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `footer.operatedPrefix` | Operated by | Управляется |
| `footer.operatedSuffix` | , a US 501(c)(3) nonprofit |  - американской некоммерческой организацией 501(c)(3) |
| `footer.viewSource` | View source | Исходный код |
| `footer.terms` | Terms of Service | Условия использования |
| `footer.privacy` | Privacy Policy | Политика конфиденциальности |
| `footer.transparency` | Transparency Report | Отчёт о прозрачности |
| `footer.socialX` | FreeSocks on X | FreeSocks в X |
| `footer.socialMastodon` | FreeSocks on Mastodon | FreeSocks в Mastodon |
| `footer.socialBluesky` | FreeSocks on Bluesky | FreeSocks в Bluesky |
| `footer.support` | Support | Поддержка |

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

## `upgrade` — The paid-membership purchase panel (payment method, duration, totals).

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `upgrade.title` | Upgrade to a FreeSocks membership | Оформить членство FreeSocks |
| `upgrade.extendTitle` | Extend your membership | Продлить членство |
| `upgrade.subtitle` | Unlimited bandwidth and devices. Choose a length and how to pay. | Безлимитный трафик и устройства. Выберите срок и способ оплаты. |
| `upgrade.subtitleNoDevices` | Unlimited bandwidth. Choose a length and how to pay. | Безлимитный трафик. Выберите срок и способ оплаты. |
| `upgrade.compareBandwidth` | Bandwidth per month | Трафик в месяц |
| `upgrade.compareDevices` | Devices | Устройства |
| `upgrade.durationLabel` | Membership length | Срок членства |
| `upgrade.cryptoMinNote` | Crypto payments start at {months} months - shorter terms fall below the network minimum. Pick another method for shorter terms. | Оплата криптовалютой - от {months} мес.; более короткие сроки ниже сетевого минимума. Для коротких сроков выберите другой способ. |
| `upgrade.months [countPlural=one]` | 1 month | 1 мес. |
| `upgrade.months [countPlural=other]` | {count} months | {count} мес. |
| `upgrade.perMonth` | {price}/mo | {price}/мес |
| `upgrade.fromPerMonth` | From {price}/month | От {price}/мес |
| `upgrade.benefitsShort` | Unlimited bandwidth and devices | Безлимитный трафик и устройства |
| `upgrade.benefitsShortNoDevices` | Unlimited bandwidth | Безлимитный трафик |
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
| `error.backendUnavailable` | No VPN server is available right now. Your account is safe - try creating your key again in a few minutes. | Сейчас нет доступного прокси-сервера. Ваш аккаунт в безопасности - попробуйте создать ключ через несколько минут. |
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
| `error.modeUnavailable` | Your current connection mode is no longer available. Switch to another mode first, then try again. | Ваш текущий режим подключения больше недоступен. Сначала переключитесь на другой режим, затем повторите. |

## `setup` — The "set up your app" section: recommended VPN clients per platform, install steps.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `setup.title` | Set up your VPN app | Настройте прокси-приложение |
| `setup.install` | Install | Установить |
| `setup.noApps` | No recommended apps for this platform yet - use any compatible client and add your subscription manually. | Для этой платформы пока нет рекомендуемых приложений - используйте любой совместимый клиент и добавьте подписку вручную. |
| `setup.openSource` | Open source | Открытый код |
| `setup.recommended` | Recommended | Рекомендуется |
| `setup.proprietary` | Proprietary | Проприетарное |
| `setup.easeEasy` | Easy to use | Простое в использовании |
| `setup.easeAdvanced` | Advanced | Для продвинутых |
| `setup.viewSource` | Source | Исходный код |
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
| `setup.deviceCompatibleTitle` | Works with your device limit | Подходит для вашего лимита устройств |
| `setup.deviceIncompatibleTitle` | Not recommended for your plan | Не рекомендуется для вашего плана |
| `setup.deviceIncompatibleNote` | These apps don't identify your device, so each launch can use up a device slot - or fail to connect on a device-limited plan. Prefer an app above. | Эти приложения не идентифицируют ваше устройство, поэтому каждый запуск может занять слот устройства - или не подключиться на плане с лимитом устройств. Лучше выберите приложение выше. |
| `setup.linkKind.play` | Google Play | Google Play |
| `setup.linkKind.appStore` | App Store | App Store |
| `setup.linkKind.github` | GitHub | GitHub |
| `setup.linkKind.apk` | APK | APK |
| `setup.linkKind.website` | Website | Сайт |
| `setup.clientDesc.hiddify` | The easiest all-round choice: one-tap import, a clean interface, and builds for every platform. | Самый простой универсальный выбор: импорт в одно нажатие, чистый интерфейс и сборки для всех платформ. |
| `setup.clientDesc.karing` | Feature-rich and honors your plan's device limit. Slightly busier than Hiddify, but works well everywhere. | Богат функциями и соблюдает лимит устройств вашего плана. Чуть перегружен по сравнению с Hiddify, но хорошо работает везде. |
| `setup.clientDesc.anywhere` | A polished, easy client for Apple devices only: iPhone, iPad, Apple TV, and Mac. No Android, Windows, or Linux version. | Отточенный и простой клиент только для устройств Apple: iPhone, iPad, Apple TV и Mac. Версий для Android, Windows и Linux нет. |
| `setup.clientDesc.singBox` | The reference app for the sing-box core. Powerful but minimal, so it's best if you are comfortable with technical settings. | Эталонное приложение на ядре sing-box. Мощное, но минималистичное - лучше подойдёт, если вы уверенно разбираетесь в технических настройках. |
| `setup.clientDesc.v2rayng` | A long-standing, lightweight Android client with one-tap import. More utilitarian than Hiddify, but dependable. | Давно существующий лёгкий клиент для Android с импортом в одно нажатие. Более утилитарный, чем Hiddify, но надёжный. |
| `setup.clientDesc.v2rayn` | A powerful desktop app for advanced users. Import is manual, and links using encryption "none" can need a manual tweak. Prefer Hiddify if that sounds fiddly. | Мощное настольное приложение для продвинутых пользователей. Импорт ручной, а ссылки с шифрованием "none" могут потребовать ручной правки. Если это звучит сложно, выберите Hiddify. |
| `setup.clientDesc.clash` | Clash Verge, a popular desktop app with strong routing rules. Some versions reject VLESS subscription links; if yours won't import, use Hiddify or v2rayN instead. | Clash Verge - популярное настольное приложение с мощными правилами маршрутизации. Некоторые версии не принимают ссылки подписки VLESS; если импорт не срабатывает, используйте Hiddify или v2rayN. |
| `setup.clientDesc.flclash` | A clean, cross-platform Clash-family app. Import by pasting your subscription link (no one-tap import). | Аккуратное кроссплатформенное приложение семейства Clash. Импорт вставкой ссылки подписки (импорта в одно нажатие нет). |
| `setup.clientDesc.mihomoParty` | A friendly desktop app for the Clash (mihomo) core. Paste your subscription link to import. | Дружелюбное настольное приложение на ядре Clash (mihomo). Вставьте ссылку подписки для импорта. |
| `setup.clientDesc.throne` | An advanced desktop client that honors your plan's device limit, with solid Linux support. Expect manual setup. | Продвинутый настольный клиент, соблюдающий лимит устройств вашего плана, с хорошей поддержкой Linux. Настройка ручная. |
| `setup.clientDesc.shadowrocket` | A paid, closed-source iOS app that is popular and reliable. Worth using if you already own it; the open-source apps above do the same job for free. | Платное приложение для iOS с закрытым кодом, популярное и надёжное. Имеет смысл, если оно у вас уже есть; приложения с открытым кодом выше делают то же самое бесплатно. |
| `setup.clientDesc.outline` | The simplest experience there is: paste your access key and connect. Only works with Outline (Shadowsocks) access keys. | Максимально простой вариант: вставьте ключ доступа и подключитесь. Работает только с ключами доступа Outline (Shadowsocks). |

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
| `rawconfig.explainer` | Your full VPN configuration, fetched over an encrypted channel so it never crosses a CDN in plain text. Copy it into your app by hand instead of using a subscription link. | Полная конфигурация вашего прокси, полученная по зашифрованному каналу - она никогда не проходит через CDN в открытом виде. Вставьте её в приложение вручную вместо ссылки-подписки. |
| `rawconfig.addHint` | Paste these server entries into your VPN app manually. | Вставьте эти серверные записи в ваше прокси-приложение вручную. |

## `delivery` — The connection-mode picker: "Beat censorship" (for censored countries) vs "Maximum privacy" (for open internet), plus the switch-confirmation dialog.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `delivery.title` | What matters most to you? | Что для вас важнее всего? |
| `delivery.subtitle` | Pick a focus. It's saved on this device only, and you can change it anytime. | Выберите приоритет - сохраняется только на этом устройстве, изменить можно в любой момент. |
| `delivery.subtitleServer` | Pick a focus. Changing it moves your existing key to the matching servers - your subscription URL stays the same. | Выберите приоритет. Изменение приоритета приведет к повторной выдаче ключа для соответствующих серверов; ваш текущий ключ будет продолжать работать в течение 24 часов. |
| `delivery.subtitleSignup` | Pick a focus. It's saved to your account, and your first key uses it - you can change it anytime. | Выберите приоритет. Он сохраняется в вашем аккаунте, и ваш первый ключ будет его использовать - изменить можно в любой момент. |
| `delivery.evadeTitle` | Internet Freedom Mode | Режим свободного интернета |
| `delivery.evadeAudience` | For censored countries | Для стран с цензурой |
| `delivery.evadeBody` | Pick this if websites, apps, or VPNs are blocked where you are. Built to keep working under censorship, with backup links that are harder to block. | Выберите это, если сайты, приложения или VPN заблокированы там, где вы находитесь. Создан, чтобы продолжать работать под цензурой, с резервными ссылками, которые сложнее заблокировать. |
| `delivery.privacyTitle` | Privacy Mode | Режим приватности |
| `delivery.privacyAudience` | For open internet | Для открытого интернета |
| `delivery.privacyBody` | Pick this if the internet is mostly open where you are. The strongest confidentiality - your configuration stays off third-party servers - but it is easier for censors to block. | Выберите это, если интернет там, где вы находитесь, в основном открыт. Самая сильная конфиденциальность - ваша конфигурация не попадает на сторонние серверы, - но цензорам его проще заблокировать. |
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

## `home` — The public landing page: hero, feature sections, impact section, FAQ intros.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `home.trust.nonprofit` | Run by a US 501(c)(3) nonprofit | Управляется некоммерческой организацией США 501(c)(3) |
| `home.trust.openSource` | Open source | Открытый код |
| `home.trust.noLogs` | No traffic logs | Без журналов трафика |
| `home.network.title` | Network status | Состояние сети |
| `home.network.offline` | offline | не в сети |
| `home.network.srOnline` | online | в сети |
| `home.network.srOffline` | offline | не в сети |
| `home.network.note` | Checked every 10 minutes | Проверяется каждые 10 минут |
| `home.network.link` | Live status | Статус в реальном времени |
| `home.quicknav.label` | Jump to a section | Перейти к разделу |
| `home.quicknav.privacy` | What we store | Что мы храним |
| `home.quicknav.threat` | Threat model | Модель угроз |
| `home.quicknav.faq` | FAQ | ЧаВо |
| `home.quicknav.impact` | Donation impact | Вклад пожертвований |
| `home.sections.features` | Features | Возможности |
| `home.sections.privacy` | Privacy | Приватность |
| `home.sections.how` | Getting started | С чего начать |
| `home.sections.membership` | Membership | Членство |
| `home.sections.impact` | Impact | Вклад |
| `home.sections.faq` | FAQ | ЧаВо |
| `home.sections.about` | About | О нас |
| `home.sections.globe` | The map | Карта |
| `home.globe.title` | Voices from behind the firewall | Голоса из-за файрвола |
| `home.globe.body` | Every day, people behind national firewalls use FreeSocks to read, share, and publish - and to be heard. | Каждый день люди за государственными файрволами читают, делятся и публикуют через FreeSocks — и их слышат. |
| `home.globe.aria` | A rotating globe: labels with voices from censored countries | Вращающийся глобус: подписи с голосами из стран с цензурой |
| `home.globe.voices.ir.place` | Tehran, Iran | Тегеран, Иран |
| `home.globe.voices.ir.l1` | They filter the internet; they can't filter the truth. | Они фильтруют интернет, но правду не отфильтруешь. |
| `home.globe.voices.ir.l2` | My report on the protests reached the world. | Мой репортаж о протестах увидел весь мир. |
| `home.globe.voices.ir.l3` | My students read what the state calls lies. | Мои студенты читают то, что государство называет ложью. |
| `home.globe.voices.cn.place` | Beijing, China | Пекин, Китай |
| `home.globe.voices.cn.l1` | History should not be a banned word. | История не должна быть запрещённым словом. |
| `home.globe.voices.cn.l2` | I shared what happened in my city - and it stayed up. | Я рассказал, что случилось в моём городе, — и это осталось в сети. |
| `home.globe.voices.cn.l3` | I archived the deleted posts before they vanished. | Я заархивировал удалённые посты до того, как они исчезли. |
| `home.globe.voices.ru.place` | Moscow, Russia | Москва, Россия |
| `home.globe.voices.ru.l1` | The truth should not need a permit. | Правда не должна требовать разрешения. |
| `home.globe.voices.ru.l2` | Independent journalism is not a crime. | Независимая журналистика — не преступление. |
| `home.globe.voices.ru.l3` | A blocked newspaper still gets read. | Заблокированную газету всё равно читают. |
| `home.globe.voices.tm.place` | Ashgabat, Turkmenistan | Ашхабад, Туркменистан |
| `home.globe.voices.tm.l1` | A whole country, almost offline - and still heard. | Целая страна почти офлайн — и всё равно услышанная. |
| `home.globe.voices.tm.l2` | They control the media, not my voice. | Они контролируют СМИ, но не мой голос. |
| `home.globe.voices.tm.l3` | Silence is the law here; we whisper anyway. | Молчание здесь — закон; но мы всё равно шепчемся. |
| `home.globe.voices.cu.place` | Havana, Cuba | Гавана, Куба |
| `home.globe.voices.cu.l1` | My voice travels farther than I ever will. | Мой голос улетает дальше, чем я когда-либо смогу. |
| `home.globe.voices.cu.l2` | We document what the state denies. | Мы документируем то, что государство отрицает. |
| `home.globe.voices.cu.l3` | Independent voices, hand to hand, screen to screen. | Независимые голоса — из рук в руки, с экрана на экран. |
| `home.globe.voices.by.place` | Minsk, Belarus | Минск, Беларусь |
| `home.globe.voices.by.l1` | When they shut us down, we still spoke. | Когда нас отключали, мы всё равно говорили. |
| `home.globe.voices.by.l2` | Free elections are not extremism. | Свободные выборы — это не экстремизм. |
| `home.globe.voices.by.l3` | They banned our flag; not our voice. | Они запретили наш флаг, но не наш голос. |
| `home.globe.voices.mm.place` | Yangon, Myanmar | Янгон, Мьянма |
| `home.globe.voices.mm.l1` | The blackout did not silence us. | Блэкаут не заставил нас замолчать. |
| `home.globe.voices.mm.l2` | Evidence of the crackdown got out. | Доказательства репрессий вышли наружу. |
| `home.globe.voices.mm.l3` | When the towers fell silent, the story did not. | Когда вышки замолчали, история не замолчала. |
| `home.globe.voices.ve.place` | Caracas, Venezuela | Каракас, Венесуэла |
| `home.globe.voices.ve.l1` | We count the votes they won't. | Мы считаем голоса, которые они не считают. |
| `home.globe.voices.ve.l2` | Hunger is not a state secret. | Голод — не государственная тайна. |
| `home.globe.voices.ve.l3` | The queue for food is long; the truth is longer. | Очередь за хлебом длинная; правда длиннее. |
| `home.globe.voices.vn.place` | Hanoi, Vietnam | Ханой, Вьетнам |
| `home.globe.voices.vn.l1` | Writing about corruption is not a crime. | Писать о коррупции — не преступление. |
| `home.globe.voices.vn.l2` | My blog outlived the block. | Мой блог пережил блокировку. |
| `home.globe.voices.vn.l3` | One article they deleted reached thousands. | Одна удалённая статья дошла до тысяч. |
| `home.globe.voices.pk.place` | Karachi, Pakistan | Карачи, Пакистан |
| `home.globe.voices.pk.l1` | During the shutdown, witnesses still spoke. | Во время отключения свидетели продолжали говорить. |
| `home.globe.voices.pk.l2` | Silencing journalists won't hide the story. | Заткнув журналистов, историю не скроешь. |
| `home.globe.voices.pk.l3` | The channel went dark; the reporting did not. | Канал погас; журналистика — нет. |
| `home.globe.voices.eg.place` | Cairo, Egypt | Каир, Египет |
| `home.globe.voices.eg.l1` | They jailed the bloggers, not the words. | Блогеров посадили, но не слова. |
| `home.globe.voices.eg.l2` | The protest was documented anyway. | Протесты всё равно задокументировали. |
| `home.globe.voices.eg.l3` | From a small screen, a big story. | С маленького экрана — большая история. |
| `home.globe.voices.sa.place` | Riyadh, Saudi Arabia | Эр-Рияд, Саудовская Аравия |
| `home.globe.voices.sa.l1` | Speaking is not a crime. | Говорить — не преступление. |
| `home.globe.voices.sa.l2` | Her voice reached beyond the wall. | Её голос прорвался за стену. |
| `home.globe.voices.sa.l3` | She asked a question the kingdom bans. | Она задала вопрос, запрещённый в королевстве. |
| `home.globe.voices.et.place` | Addis Ababa, Ethiopia | Аддис-Абеба, Эфиопия |
| `home.globe.voices.et.l1` | The shutdown hid nothing. | Отключение ничего не скрыло. |
| `home.globe.voices.et.l2` | Witnesses still found a way out. | Свидетели всё равно нашли выход. |
| `home.globe.voices.et.l3` | The dead were counted, despite the blackout. | Погибших посчитали, несмотря на блэкаут. |
| `home.globe.voices.tr.place` | Istanbul, Turkey | Стамбул, Турция |
| `home.globe.voices.tr.l1` | Blocking the site won't block the story. | Заблокировать сайт — не заблокировать историю. |
| `home.globe.voices.tr.l2` | Journalism continues, court order or not. | Журналистика продолжается, с решением суда или без. |
| `home.globe.voices.tr.l3` | An arrested anchor cannot sign off the news. | Арестованный ведущий не может закончить выпуск. |
| `home.globe.voices.az.place` | Baku, Azerbaijan | Баку, Азербайджан |
| `home.globe.voices.az.l1` | They call reporting extremism. | Они называют репортажи экстремизмом. |
| `home.globe.voices.az.l2` | The investigation was published anyway. | Расследование всё равно вышло. |
| `home.globe.voices.az.l3` | They froze our accounts, not our work. | Они заморозили наши счета, но не нашу работу. |
| `home.globe.voices.uz.place` | Tashkent, Uzbekistan | Ташкент, Узбекистан |
| `home.globe.voices.uz.l1` | A closed internet is not a quiet one. | Закрытый интернет — не тихий интернет. |
| `home.globe.voices.uz.l2` | The world still heard what happened here. | Мир всё равно услышал, что здесь произошло. |
| `home.globe.voices.uz.l3` | The squares are watched; the words still move. | Площади под наблюдением; слова всё равно движутся. |
| `home.impact.title` | Donations at work | Пожертвования в деле |
| `home.impact.body` | Every donation made through FreeSocks raises the monthly bandwidth of every free account for that month. This is what donors have added so far - you could add to it too. | Каждое пожертвование через FreeSocks увеличивает месячный трафик каждого бесплатного аккаунта в том месяце. Вот что уже добавили доноры - и вы тоже можете внести вклад. |
| `home.impact.cta` | Make a donation | Сделать пожертвование |
| `home.impact.chartAria` | Bandwidth added to every free user by donations, month by month | Трафик, добавленный каждому бесплатному пользователю за счёт пожертвований, по месяцам |
| `home.hero.variants.freedom` | A VPN for Internet Freedom | VPN для свободного интернета |
| `home.hero.variants.dissidents` | A VPN for dissidents | VPN для инакомыслящих |
| `home.hero.variants.privacy` | A VPN for privacy | VPN для приватности |
| `home.hero.variants.world` | A VPN for the world | VPN для всего мира |
| `home.hero.subtitle` | FreeSocks is made for people whose internet is censored, and works as a privacy-respecting VPN anywhere else. Signing up takes one quick human check. We never ask for an email or a password. Your subscription URL works in most modern VPN apps, and a membership gets you {limits}. | FreeSocks создан для людей, чей интернет подвергается цензуре, а в остальных местах работает как VPN, уважающий приватность. Регистрация - одна быстрая проверка на человека. Мы никогда не просим почту или пароль. Ваша ссылка подписки работает в большинстве современных VPN-приложений, а членство даёт вам {limits}. |
| `home.hero.impactNote` | Donations made through FreeSocks directly power free users: every donation buys real bandwidth for people in censored countries, that same month. | Пожертвования через FreeSocks напрямую поддерживают бесплатных пользователей: каждое пожертвование покупает реальный трафик для людей в странах с цензурой уже в том же месяце. |
| `home.hero.impactLink` | See the impact | Посмотреть вклад |
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
| `home.freeCard.cryptoNote` | Crypto accepted - Bitcoin, Monero, Zcash and more | Принимаем криптовалюту - Bitcoin, Monero, Zcash и другие |
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
| `home.privacy.point3` | No logs of the sites you visit or the traffic you send - and we don't store your IP address, on our servers or the VPN nodes. | Никакой информации о посещаемых вами сайтах или об объеме трафика, который вы на них отправляете. |
| `home.privacy.point4` | We store no payment details - you pay on the provider's own page, and the provider never sees your account or VPN subscription. | Мы не храним никакие платежные данные - вы оплачиваете на странице самого провайдера, и провайдер никогда не видит вашу учетную запись или подписку на прокси. |
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
| `home.about.title` | About FreeSocks | О FreeSocks |
| `home.about.bodyPrefix` | FreeSocks is operated by | FreeSocks управляется компанией |
| `home.about.bodySuffix` | , a US 501(c)(3) nonprofit. | , американской некоммерческой организацией 501(c)(3). |
| `home.about.body2` | Most VPNs assume you can pay for a subscription and safely hand over an email address. In much of the world neither is true, so FreeSocks asks for neither. Anyone can get a working key in about a minute and keep it for as long as they use it. | Большинство VPN исходят из того, что вы можете оплатить подписку и безопасно сообщить адрес почты. Во многих странах ни то, ни другое невозможно, поэтому FreeSocks не просит ни того, ни другого. Любой может получить рабочий ключ примерно за минуту и пользоваться им, пока он нужен. |
| `home.about.siteLink` | unredacted.org | unredacted.org |
| `home.about.openSource` | The code that runs this service is published for anyone to inspect, audit, or run themselves. | Код, на котором работает этот сервис, опубликован - любой может изучить его, проверить или запустить самостоятельно. |
| `home.about.viewSourceCta` | View the source | Посмотреть исходный код |
| `home.about.fact2Title` | Open source | Открытый код |
| `home.about.fact3Title` | Donation funded | Финансируется пожертвованиями |
| `home.about.fact3Body` | Free accounts are paid for by donations and memberships. There are no ads and nothing is sold. | Бесплатные аккаунты оплачиваются пожертвованиями и членствами. Здесь нет рекламы, и ничего не продаётся. |
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
| `e2ee.verifyIntro` | FreeSocks seals your account number and VPN key to this server with HPKE, so a compromised CDN can't read them. These fingerprints identify the keys your browser is using - compare them against the values published out-of-band to be sure they haven't been swapped. | FreeSocks защищает номер вашей учетной записи и ключ прокси-сервера с помощью HPKE, поэтому скомпрометированная CDN не сможет их прочитать. Эти «отпечатки» идентифицируют ключи, используемые вашим браузером - сравните их со значениями, опубликованными вне сети, чтобы убедиться, что они не были подменены. |
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

## `status` — Miscellaneous strings.

| Key | English | Russian (Русский) |
| --- | --- | --- |
| `status.title` | Network status | Состояние сети |
| `status.updated` | Updated {time} | Обновлено {time} |
| `status.overallOk` | All locations are operating normally | Все локации работают нормально |
| `status.overallPartial` | Some locations are having issues | В некоторых локациях есть проблемы |
| `status.overallMajor` | A major outage is in progress | Идёт крупный сбой |
| `status.locationsTitle` | Locations | Локации |
| `status.nodesUp` | {online} of {total} nodes up | {online} из {total} узлов в сети |
| `status.online` | Online | В сети |
| `status.offline` | Offline | Не в сети |
| `status.srOnline` | online | в сети |
| `status.srOffline` | offline | не в сети |
| `status.loadQuiet` | Quiet | Свободно |
| `status.loadBusy` | Busy | Загружено |
| `status.loadCrowded` | Crowded | Переполнено |
| `status.loadUnknown` | Load unknown | Загрузка неизвестна |
| `status.matrixTitle` | Availability in censored regions | Доступность в регионах с цензурой |
| `status.matrixBody` | How well each connection mode works from specific countries, based on reports we receive. "Partial" means some networks or times of day block it. | Насколько хорошо каждый режим подключения работает из конкретных стран, по полученным нами сообщениям. "Частично" означает, что некоторые сети или время суток его блокируют. |
| `status.matrixAvailable` | Available | Доступен |
| `status.matrixPartial` | Partial | Частично |
| `status.matrixBlocked` | Blocked | Заблокирован |
| `status.matrixEmpty` | No country data published yet. | Данные по странам пока не опубликованы. |
| `status.incidentsTitle` | Incidents | Инциденты |
| `status.incidentsNone` | No incidents in the last 30 days. | За последние 30 дней инцидентов не было. |
| `status.incidentsOngoing` | Ongoing | Продолжается |
| `status.incidentsResolved` | Resolved {time} | Решён {time} |
| `status.incidentsStarted` | Started {time} | Начался {time} |
| `status.incidentsGlobal` | All locations | Все локации |
| `status.incidentsPast` | Past incidents | Прошлые инциденты |
| `status.report` | Report a problem | Сообщить о проблеме |
