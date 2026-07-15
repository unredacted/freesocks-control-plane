# FreeSocks translation review — Chinese (中文)

Generated from `messages/en.json` (source of truth) vs `messages/zh.json`.
**185 of 647 strings are missing** (the app currently shows English for
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

- Edit the **"Chinese (中文)" column** (or add a correction below a row). Rows marked
  ⚠️ MISSING have no translation yet.


## `faq` — The landing-page FAQ (questions + answers). *(4 missing)*

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `faq.title` | Frequently asked questions | 常见问题解答 |
| `faq.subtitle` | Answers to common questions. | 基本问题已解答。还有疑问？请使用您的支持 ID 联系我们。 |
| `faq.tabGeneral` | General | ⚠️ **MISSING** |
| `faq.tabThreat` | What we protect you from | ⚠️ **MISSING** |
| `faq.contactPrefix` | For anything else, email | ⚠️ **MISSING** |
| `faq.contactSuffix` | and include your Support ID. | ⚠️ **MISSING** |
| `faq.q1.question` | What is FreeSocks? | FreeSocks是什么？ |
| `faq.q1.answer` | A free proxy service that helps people in heavily-censored regions reach the open internet. It's operated by Unredacted, a US 501(c)(3) nonprofit. | 这是一个免费代理服务，帮助身处网络审查严格地区的人们访问开放的互联网。它由美国非营利组织 Unredacted（501(c)(3)）运营。 |
| `faq.q2.question` | Is it really free? | 真的免费吗？ |
| `faq.q2.answer` | Yes. A free account gives you a working proxy. A paid FreeSocks membership lifts the limits and helps fund free access for others. | 是的。免费账户可以让你使用代理服务器。付费的 FreeSocks 会员服务可以解除限制，并帮助资助其他人免费使用。 |
| `faq.q3.question` | Do I need to give an email or password? | 我需要提供邮箱地址或密码吗？ |
| `faq.q3.answer` | No. You pass a one-time human check and we generate a 32-digit account number - that's your only credential. We never ask for an email, phone number, or name. | 不。您只需通过一次性人工审核，我们就会生成一个32位数的账号--这就是您唯一的凭证。我们绝不会索要您的邮箱地址、电话号码或姓名。 |
| `faq.q4.question` | What if I lose my account number? | 如果我的账号丢失了怎么办？ |
| `faq.q4.answer` | It's the only way back into your account and we can't recover it (we store only a hashed version), so save it in a password manager when you create it. If you lose it, just create a new free account. | 这是您恢复账户的唯一方法，而且我们无法恢复您的原始密码（我们只存储哈希版本），因此请在创建密码时将其保存到密码管理器中。如果您丢失了密码，只需创建一个新的免费账户即可。 |
| `faq.q5.question` | How do I connect? | 我该如何连接？ |
| `faq.q5.answer` | Create a subscription, copy its link (or scan the QR code), and add it to a compatible app. Your account page lists the recommended app for each platform (Android, iPhone, Windows, macOS / Linux). | 创建订阅后，复制其链接（或扫描二维码），并将其添加到兼容的应用程序，例如 v2rayNG、Hiddify 或 Streisand。您的帐户页面会列出每个平台的推荐应用程序。 |
| `faq.q6.question` | What do you log about me? | 你记录了我的哪些信息？ |
| `faq.q6.answer` | As little as possible: only a hashed version of your account number - never your email, name, or IP address - and no logs of the sites you visit or the traffic you send. | 尽可能少地收集信息：只收集您账号的哈希版本--绝不会收集您的电子邮件或姓名--也不会记录您访问的网站或您发送的流量。 |
| `faq.q7.question` | The link is blocked where I am. What can I do? | 我这里无法访问该链接，该怎么办？ |
| `faq.q7.answer` | On your account page, open "Trouble connecting?" to get a mirror link served from a different host that may not be blocked. You can also set your delivery preference to favor staying connected. | 在您的账户页面，打开“连接有问题？”以获取来自其他可能未被屏蔽的主机的镜像链接。您还可以设置您的接收偏好，优先保持连接。 |
| `faq.q8.question` | Can I buy a membership for someone else? | 我可以为别人购买会员资格吗？ |
| `faq.q8.answer` | Yes - on your account page use "Buy codes to share" to purchase membership codes you can give to friends or family. Each one works on any account and doesn't affect yours. | 是的--在您的账户页面，使用“购买分享码”功能购买会员码，您可以将这些会员码赠送给朋友或家人。每个会员码都适用于任何账户，不会影响您的账户。 |
| `faq.q9.question` | Can I pay anonymously? | 我可以匿名支付吗？ |
| `faq.q9.answer` | Yes. You can pay with cryptocurrency - Bitcoin, or Monero and Zcash for the most privacy - with no account, email, or card. Your membership activates automatically once the payment confirms. | 是的。您可以使用加密货币支付--比特币，或使用门罗币 (Monero) 或 Zcash 以最大程度保护您的隐私--无需注册账户、邮箱或银行卡。付款确认后，您的会员资格将自动激活。 |

## `threat` — Miscellaneous strings. *(15 missing)*

| Key | English | Chinese (中文) |
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

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `common.copy` | Copy | 复制 |
| `common.copied` | Copied to clipboard | 已复制到剪贴板 |
| `common.copyFailed` | Copy failed - select the text and copy it manually | 复制失败--请选中文本手动复制 |
| `common.download` | Download | 下载 |
| `common.cancel` | Cancel | 取消 |
| `common.close` | Close | 关闭 |
| `common.retry` | Retry | 重试 |
| `common.loading` | Loading… | 加载中… |
| `common.working` | Working… | 处理中… |
| `common.reload` | Reload | 重新加载 |
| `common.language` | Language | 语言 |
| `common.deviceCount [countPlural=one]` | 1 device | 1 台设备 |
| `common.deviceCount [countPlural=other]` | {count} devices | {count} 台设备 |

## `nav` — The site header: navigation buttons, menu, language/theme controls. *(3 missing)*

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `nav.getAccount` | Get a free account | 获取免费账户 |
| `nav.signIn` | Sign in | 登录 |
| `nav.account` | My account | 我的账户 |
| `nav.menu` | Menu | ⚠️ **MISSING** |
| `nav.theme` | Theme | ⚠️ **MISSING** |
| `nav.home` | FreeSocks home | ⚠️ **MISSING** |

## `captcha` — The proof-of-work human check widget states.

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `captcha.initial` | I'm human | 我是真人 |
| `captcha.verifying` | Verifying… | 验证中… |
| `captcha.solved` | Verified | 已验证 |
| `captcha.error` | Check failed - retry | 验证失败--请重试 |
| `captcha.failedTitle` | Couldn't complete the human check. | 无法完成真人验证。 |
| `captcha.failedBody` | The check runs on your device and didn't finish. This is usually a network problem, not something you did wrong. | 该验证在你的设备上运行，但未能完成。这通常是网络问题，而不是你的错。 |
| `captcha.failedTip1` | Wait a moment, then try again | 稍等片刻，然后重试 |
| `captcha.failedTip2` | Try a different network - or a VPN/proxy if sites are blocked where you are | 换一个网络试试 - 如果你所在地区的网站被屏蔽，可使用 VPN/代理 |
| `captcha.failedTip3` | Still stuck? Try a private/incognito window or turn off browser extensions | 仍然无法通过？试试隐私/无痕窗口，或关闭浏览器扩展 |

## `reveal` — The save-your-account-number modal (the 32-digit sign-in number is shown ONCE; users must download it and paste it back to verify). The single most safety-critical copy in the product. *(8 missing)*

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `reveal.title` | Save your account number now | 立即保存你的账户号码 |
| `reveal.subtitle` | This 32-digit number is the ONLY way to sign in again. There is no email or password to recover it. If you lose it, your account is gone for good. | 这个 32 位数字是再次登录的唯一方式。没有电子邮件或密码可用于找回。一旦丢失，你的账户将永久无法恢复。 |
| `reveal.cannotRecover` | We cannot recover it for you - not even support can. | 我们无法为你找回--客服也不行。 |
| `reveal.saveHint` | Save it in a password manager, or write it down somewhere safe and private. | 把它保存到密码管理器，或写在安全私密的地方。 |
| `reveal.downloadRequired` | Download your account number to continue. Keep the file somewhere safe. | ⚠️ **MISSING** |
| `reveal.continue` | Continue | ⚠️ **MISSING** |
| `reveal.verifyTitle` | Confirm you saved it | ⚠️ **MISSING** |
| `reveal.verifySubtitle` | Your account number is now hidden. Enter or paste it from the copy you just saved to confirm you can sign in later. | ⚠️ **MISSING** |
| `reveal.verifyPlaceholder` | Paste your 32-digit account number | ⚠️ **MISSING** |
| `reveal.verifyMismatch` | That doesn't match your account number. Check the copy you saved, or go back to see it again. | ⚠️ **MISSING** |
| `reveal.back` | Back | ⚠️ **MISSING** |
| `reveal.done` | I've saved it | 我已保存 |
| `reveal.savedConfirmed` | Account number saved and verified | ⚠️ **MISSING** |
| `reveal.downloadFilename` | freesocks-account-number.txt | freesocks-account-number.txt |
| `reveal.leaveWarning` | Your account number is still on screen. If you leave now without saving it, you will not be able to sign in again. | 你的账户号码仍显示在屏幕上。如果现在未保存就离开，你将无法再次登录。 |

## `support` — The support-ID line (a non-secret handle for contacting support). *(2 missing)*

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `support.label` | Support ID | 支持 ID |
| `support.hint` | Share this if you contact us. It is NOT your sign-in number and grants no access. | 联系我们时请提供它。它不是你的登录号码，也不授予任何访问权限。 |
| `support.emailUs` | Email us: | ⚠️ **MISSING** |
| `support.getAccountLine` | Questions or problems? Email us at | ⚠️ **MISSING** |

## `login` — The sign-in page (account number + optional passkey). *(1 missing)*

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `login.title` | Sign in with your account number | 使用账户号码登录 |
| `login.subtitle` | Enter the 32-digit account number you saved. It's the only way to sign in - there's no email or password to recover. | 输入你保存的 32 位账户号码。这是唯一的登录方式--没有可找回的电子邮件或密码。 |
| `login.label` | Account number | 账户号码 |
| `login.show` | Show | 显示 |
| `login.hide` | Hide | 隐藏 |
| `login.submit` | Sign in | 登录 |
| `login.submitting` | Signing in… | 登录中… |
| `login.noAccount` | Don't have an account number yet? | 还没有账户号码？ |
| `login.getOne` | Get a free account | 获取免费账户 |
| `login.failed` | Sign-in failed | 登录失败 |
| `login.success` | Signed in | 已登录 |
| `login.sessionExpired` | Please sign in again - your session may have ended. | 请重新登录 - 你的会话可能已结束。 |
| `login.digitProgress` | {count} of {total} digits entered | {count}位数，共{total}位数字 |
| `login.or` | or | ⚠️ **MISSING** |

## `passkey` — Optional passkey (Face ID / fingerprint) sign-in management. *(20 missing)*

| Key | English | Chinese (中文) |
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

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `account.title` | Your account | 你的账户 |
| `account.tierLabel` | Your plan | 你的套餐 |
| `account.statusActive` | Active | 有效 |
| `account.statusGrace` | Expiring soon | 即将到期 |
| `account.statusDisabled` | Disabled | 已过期 |
| `account.regenerate` | Create a new key | 创建新密钥 |
| `account.switchBackend` | Switch server type | 切换服务器类型 |
| `account.rotate` | Change account number | 更改账户号码 |
| `account.signOut` | Sign out | 退出登录 |
| `account.redeemTitle` | Have a membership code? | 有会员码？ |
| `account.redeemPlaceholder` | FSM-XXXX-XXXX-XXXX | FSM-XXXX-XXXX-XXXX |
| `account.redeemSubmit` | Redeem code | 兑换码 |
| `account.redeemSuccess` | Redeemed - you're now on {tier} for {days} more days. | 已兑换--你现在是 {tier}，还有 {days} 天。 |
| `account.redeemFailed` | That code is not valid, or has already been used. | 该码无效或已被使用。 |
| `account.redeemAriaLabel` | Membership code | 会员码 |
| `account.switchTo` | Switch to {label} | 切换到 {label} |
| `account.devicesTitle` | Connected devices | 已连接设备 |
| `account.lastSeen` | Last seen {date} | 最近活跃 {date} |
| `account.noSubTitle` | No subscription yet | 还没有订阅 |
| `account.noSubBody` | Create your first subscription to get a URL you can use in any compatible VPN client. | 创建你的第一个订阅，获得可在任何兼容 VPN 客户端中使用的链接。 |
| `account.createSub` | Create subscription | 创建订阅 |
| `account.creating` | Creating… | 创建中… |
| `account.rotateTitle` | Change your account number? | 更换账户号码？ |
| `account.rotateBody` | A new 32-digit number is generated and shown once. Your current number stops working immediately. Anyone who has it loses access. Do this if your number may have leaked. | 将生成一个新的 32 位号码，并且只显示一次。当前号码立即失效，持有它的任何人都会失去访问权限。如果你的号码可能已泄露，请执行此操作。 |
| `account.rotateConfirm` | Yes, change it | 是，更换 |
| `account.rotating` | Rotating… | 更换中… |
| `account.rotateFailedTitle` | Could not change the account number | 无法更换账户号码 |
| `account.refreshMembership` | Already paid? Check for my membership | 已付款？查询我的会员状态 |
| `account.memberActiveTitle` | Membership active | 会员有效 |
| `account.memberActiveExpiry` | Active until {date} | 有效期至 {date} |
| `account.membershipNudge.title` | Go unlimited with a membership | 升级会员，畅享无限 |
| `account.membershipNudge.body` | Unlimited bandwidth and devices. | 无限流量与设备。 |
| `account.membershipNudge.bodyNoDevices` | Unlimited bandwidth. | ⚠️ **MISSING** |
| `account.membershipNudge.cta` | View membership | 查看会员 |
| `account.tab.connection` | Connection | 连接 |
| `account.tab.membership` | Membership | 会员 |
| `account.tab.codes` | Codes & gifts | 兑换码与礼物 |
| `account.tab.security` | Security | 安全 |
| `account.refreshing` | Refreshing… | 刷新中… |
| `account.regenSuccessTitle` | New subscription URL generated | 已生成新的订阅链接 |
| `account.regenSuccessBody` | Re-import it on each of your devices. The old URL works for 24 more hours. | 请在每台设备上重新导入。旧链接还能用 24 小时。 |
| `account.regenFailedTitle` | Could not create a new key | 无法创建新密钥 |
| `account.switchSuccessTitle` | Switched to {tier} | 已切换到 {tier} |
| `account.switchSuccessBodyGrace` | Re-import the new subscription URL on each device. The old subscription works for 24 more hours. | 请在每台设备上导入新订阅链接。旧订阅还能用 24 小时。 |
| `account.switchSuccessBody` | Re-import the new subscription URL on each device. | 请在每台设备上导入新订阅链接。 |
| `account.switchFailedTitle` | Could not switch server type | 无法切换服务器类型 |
| `account.refreshWelcome` | Welcome to {tier} | 欢迎加入 {tier} |
| `account.refreshNoneTitle` | No active membership found yet | 尚未找到有效会员 |
| `account.refreshNoneBody` | If you just paid, give it a moment and try again. | 如果你刚刚付款，请稍等片刻再试。 |
| `account.refreshFailedTitle` | Could not refresh membership | 无法刷新会员状态 |
| `account.graceTitle` | Your account is in a grace period | 你的账户处于宽限期 |
| `account.graceBody` | Your membership has lapsed, so this account will be limited soon. Renew - donate or redeem a membership code below - to keep your plan. | 你的会员已到期，此账户即将受限。请续订--捐款或在下方兑换会员码--以保留你的套餐。 |
| `account.disabledTitle` | Your account is currently disabled | 你的账户当前已停用 |
| `account.disabledBody` | New keys and changes are paused on this account. Redeem a membership code below to reactivate it, or contact support and share your Support ID. | 此账户的新密钥与更改已暂停。请在下方兑换会员码以重新激活，或联系支持并提供你的支持 ID。 |
| `account.rotateHint` | Replace your 32-digit account number if it may have leaked - or, if you never saved it, rotate now to get a fresh one you can save. The old one stops working immediately. | 如果您的32位账号可能已泄露，请立即更换。旧账号将立即失效。 |
| `account.keyActionsHint` | These change your proxy connection only - your 32-digit account number stays the same. | 这些更改只会改变您的代理连接--您的 32 位账号保持不变。 |
| `account.section.connection.title` | Your connection | 您的连接 |
| `account.section.connection.desc` | Your proxy key, setup help, and connected devices. | 您的代理密钥、设置帮助和已连接的设备。 |
| `account.section.membership.title` | Membership | 会员资格 |
| `account.section.membership.desc` | Your plan, and how to upgrade or extend it. | 您的计划，以及如何升级或扩展它。 |
| `account.section.codes.title` | Codes & gifts | 代码和礼物 |
| `account.section.codes.desc` | Redeem a membership code, or buy codes to share with others. | 兑换会员码，或购买会员码与他人分享。 |
| `account.section.security.title` | Account & security | 账户与安全 |
| `account.section.security.desc` | Your support ID and account-number controls. | 您的支持 ID 和账号控制。 |
| `account.deviceRevoke` | Revoke | 撤销 |
| `account.deviceRevokedTitle` | Device revoked | 设备被撤销 |
| `account.deviceRevokedBody` | The slot is free. That device loses access until it re-imports your subscription. | 该插槽空闲。该设备将失去访问权限，直到重新导入您的订阅。 |
| `account.deviceRevokeFailedTitle` | Couldn't revoke the device | 无法撤销该设备 |

## `hero` — The subscription panel: the key/URL block, traffic + expiry stats, QR, status callouts. *(8 missing)*

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `hero.titleDefault` | Your subscription | 你的订阅 |
| `hero.eyebrowAccessKey` | Your access key | 你的访问密钥 |
| `hero.urlLabelSubscription` | Subscription URL | 订阅链接 |
| `hero.urlLabelAccessKey` | Access key | 访问密钥 |
| `hero.tierLine` | Plan {tier} | 套餐 {tier} |
| `hero.viaLine` | via {backend} | 通过 {backend} |
| `hero.copyUrl` | Copy URL | 复制链接 |
| `hero.copiedShort` | Copied | 已复制 |
| `hero.qrShow` | QR | 二维码 |
| `hero.qrHide` | Hide | 隐藏 |
| `hero.scanPhone` | Scan with your phone | 用手机扫描 |
| `hero.scanOther` | Scan with another device | 用另一台设备扫描 |
| `hero.importTitle` | Add to your app | 添加到你的应用 |
| `hero.importPlain` | Plain link | 纯链接 |
| `hero.importOpen` | Open in {app} | 在 {app} 中打开 |
| `hero.importScan` | Scan to add to {app} | 扫描以添加到 {app} |
| `hero.importOpenHint` | Tap to import on this device, or scan the code from your phone. | 点按可在本设备导入，或用手机扫描二维码。 |
| `hero.scanFallback` | Scan the fallback on another device | 用另一台设备扫描备用链接 |
| `hero.fallbackLabel` | Fallback URL | 备用链接 |
| `hero.fallbackHint` | Use this if the main URL gets blocked | 主链接被封锁时使用 |
| `hero.fallbackQrAria` | Show fallback URL QR code | 显示备用链接二维码 |
| `hero.downloaded` | Downloaded {filename} | 已下载 {filename} |
| `hero.traffic` | Traffic | 流量 |
| `hero.unlimited` | Unlimited | 不限量 |
| `hero.configBelowNote` | Your full configuration is below - add the servers by hand. For privacy, the auto-updating subscription link isn't shown by default (your app would fetch it through a CDN). | ⚠️ **MISSING** |
| `hero.showUrlAnyway` | Show the subscription link anyway | ⚠️ **MISSING** |
| `hero.urlDangerBody` | This link works in any app, but the app then downloads your configuration through a third-party CDN in plain text - the CDN operator can see your server details and that you use FreeSocks. That is exactly what this focus avoids. Use it only if your app cannot import the configuration below. | ⚠️ **MISSING** |
| `hero.usedSoFar` | {amount} used so far | 已使用 {amount} |
| `hero.leftThisPeriod` | {amount} left this period. | 本周期剩余 {amount}。 |
| `hero.nearlyOut` | Nearly out, only {amount} left this period. | 即将用尽--本周期仅剩 {amount}。 |
| `hero.expires` | Expires | 到期 |
| `hero.noExpiry` | No expiry | 永不过期 |
| `hero.expiresToday` | Expires today | 今天到期 |
| `hero.daysRemaining [countPlural=one]` | 1 day remaining | 剩余 1 天 |
| `hero.daysRemaining [countPlural=other]` | {count} days remaining | 剩余 {count} 天 |
| `hero.expiredDaysAgo [countPlural=one]` | Expired 1 day ago | 已过期 1 天 |
| `hero.expiredDaysAgo [countPlural=other]` | Expired {count} days ago | 已过期 {count} 天 |
| `hero.nodeOnline` | Node online | ⚠️ **MISSING** |
| `hero.nodeOffline` | Node offline | ⚠️ **MISSING** |
| `hero.nodeUnknown` | Node status unknown | ⚠️ **MISSING** |
| `hero.nodeOnlineHint` | The server behind your config is up and responding. If you still can't connect, your network or ISP is likely filtering it - try another connection mode or location. | ⚠️ **MISSING** |
| `hero.nodeOfflineBody` | The server behind your config is currently offline. This is on our side, not your network. Try again in a few minutes, or create a new config (optionally in a different location). | ⚠️ **MISSING** |
| `hero.keyLimited` | You've used all your data for this period. It resets automatically, or you can upgrade for more. | 您本周期的数据流量已用完。流量将自动重置，或者您可以升级以获得更多流量。 |
| `hero.keyExpired` | This key has expired. Renew your membership or create a new key to reconnect. | 此密钥已过期。请续订会员资格或创建新密钥以重新连接。 |
| `hero.keyDisabled` | This key is currently disabled. If your membership lapsed, renew it; otherwise contact support with your support ID. | 此密钥目前已禁用。如果您的会员资格已过期，请续订；否则，请使用您的支持 ID 联系支持团队。 |
| `hero.resetsInDays [countPlural=one]` | Resets in 1 day | 1天内重置 |
| `hero.resetsInDays [countPlural=other]` | Resets in {count} days | 重置时间为{count}天 |

## `location` — Miscellaneous strings. *(4 missing)*

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `location.pickerLabel` | Server location | ⚠️ **MISSING** |
| `location.auto` | Automatic (least busy) | ⚠️ **MISSING** |
| `location.offline` | offline | ⚠️ **MISSING** |
| `location.pickerHint` | Where your config's server is. Automatic picks the least busy location; pick one yourself if it works better on your network. | ⚠️ **MISSING** |

## `usage` — The 30-day usage trend under the traffic stats.

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `usage.show` | Show usage trend | 显示使用趋势 |
| `usage.title` | Usage (last 30 days) | 使用情况（过去 30 天） |
| `usage.total` | {amount} used in the last 30 days | 过去 30 天内使用的{amount} |
| `usage.unavailable` | Usage isn't available right now. | 目前暂不支持使用。 |
| `usage.none` | No usage recorded yet. | 尚未记录使用情况。 |

## `regen` — The regenerate-subscription confirmation dialog.

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `regen.title` | Create a new subscription URL? | 重新生成订阅？ |
| `regen.body` | Your current subscription URL (ending …{suffix}) will be replaced with a new one. The old URL becomes read-only for 24 hours, then is deleted. | 你当前的订阅链接（结尾为 …{suffix}）将被新链接替换。旧链接将变为只读并保留 24 小时，之后删除。 |
| `regen.point1` | Your current key remains usable for the next 24 hours | 当前密钥在接下来的 24 小时内仍可使用 |
| `regen.point2` | You'll need to re-import the new URL in each of your devices | 你需要在每台设备上重新导入新链接 |
| `regen.pointDevices [countPlural=one]` | You currently have 1 connected device - it will need the new URL | 你当前有 1 台已连接设备--都需要导入新链接 |
| `regen.pointDevices [countPlural=other]` | You currently have {count} connected devices - they will all need the new URL | 你当前有 {count} 台已连接设备--都需要导入新链接 |
| `regen.confirm` | Create new URL | 重新生成 |
| `regen.working` | Creating… | 生成中… |

## `switch` — The switch-backend confirmation dialog.

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `switch.title` | Switch to {to}? | 切换到 {to}？ |
| `switch.body` | Your current {from} subscription will be replaced with a new {to} one. The old subscription stays usable for 24 hours so you can re-import on every device before it stops working. | 你当前的 {from} 订阅将被新的 {to} 订阅替换。旧订阅在 24 小时内仍可使用，方便你在所有设备上完成重新导入。 |
| `switch.point1` | A new subscription URL is issued on the {to} backend | 将在 {to} 服务器上签发新的订阅链接 |
| `switch.point2` | The current {from} URL keeps working for 24 hours, then is deleted | 当前 {from} 链接还能用 24 小时，之后删除 |
| `switch.point3` | You'll need to re-import the new URL in each VPN client you use | 你需要在使用的每个 VPN 客户端中重新导入新链接 |
| `switch.pointDevices [countPlural=one]` | You currently have 1 connected device - re-import on it | 你当前有 1 台已连接设备--请全部重新导入 |
| `switch.pointDevices [countPlural=other]` | You currently have {count} connected devices - re-import on all of them | 你当前有 {count} 台已连接设备--请全部重新导入 |
| `switch.confirm` | Switch to {to} | 切换到 {to} |
| `switch.working` | Switching… | 切换中… |

## `get` — The /get-account sign-up flow: create account (step 1) and create subscription (step 2). *(4 missing)*

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `get.badge` | Free account | 免费账户 |
| `get.title` | Get a FreeSocks account | 获取 FreeSocks 账户 |
| `get.introTwoSteps` | Two quick steps: solve the human-check to create a free account, then create your subscription. | 两个快速步骤：完成真人验证以创建免费账户，然后创建订阅。 |
| `get.step1Title` | Create your account | 创建你的账户 |
| `get.chooseBackend` | Choose a connection type | 选择服务器类型 |
| `get.backendAria` | Connection type | 服务器类型 |
| `get.backendMultiProtocol` | VLESS (Xray) | VLESS (Xray) |
| `get.backendShadowsocks` | Shadowsocks via Outline | 通过 Outline 的 Shadowsocks |
| `get.createAccount` | Create my account | 创建我的账户 |
| `get.freeAccountNote` | Free accounts are valid for {days} days and limited to {devices}. No email or password. | 免费账户有效期 {days} 天，限 {devices}。无需电子邮件或密码。 |
| `get.freeAccountNoteNoDevices` | Free accounts are valid for {days} days. No email or password. | ⚠️ **MISSING** |
| `get.accountReady` | Your account is ready | 你的账户已就绪。 |
| `get.nextStepHint` | One step left - your account can't connect to anything until you create your subscription. | ⚠️ **MISSING** |
| `get.nextStepCta` | Next: create your subscription | ⚠️ **MISSING** |
| `get.nextStepBadge` | Next step | ⚠️ **MISSING** |
| `get.step2Title` | Create your subscription | 创建你的订阅 |
| `get.step2Intro` | Create a proxy subscription to get a URL you can paste into any compatible VPN client. | 创建代理订阅，获得可粘贴到任何兼容 VPN 客户端的链接。 |
| `get.manageHintPrefix` | Manage this subscription anytime from | 随时管理此订阅，前往 |
| `get.manageLinkLabel` | your account | 你的账户 |
| `get.subErrorSafePrefix` | Your account is safe. You can create the subscription later from | 你的账户是安全的。稍后可以创建订阅，前往 |
| `get.subErrorSafeSuffix` | once a server is available. | 等服务器可用时。 |
| `get.createSubToastTitle` | Subscription created | 订阅已创建 |
| `get.createSubToastBody` | Copy the URL into your VPN client, or scan the QR code. | 将链接复制到你的 VPN 客户端，或扫描二维码。 |
| `get.createAccountFailedTitle` | Could not create account | 无法创建账户 |
| `get.createSubFailedTitle` | Could not create subscription | 无法创建订阅 |
| `get.haveAccountPrefix` | Already have an account? | 已有账户？ |
| `get.lostNumberHint` | Lost your account number before saving it? You can switch to a new one - | 保存前丢失了账户号码？可以换一个新号码-- |
| `get.lostNumberLinkLabel` | change it from your account page | 在账户页面更换 |
| `get.upsellTitle` | Want unlimited? | 想要无限制？ |
| `get.upsellBody` | Upgrade to a FreeSocks membership any time for unlimited bandwidth and devices. | 随时可升级到 FreeSocks 会员，享受无限流量与设备。 |
| `get.redeemTitle` | Got a gift code? | 你有礼品码吗？ |
| `get.redeemBody` | Redeem it now to upgrade your new account instantly. | 立即兑换，即可立即升级您的新账户。 |

## `tiers` — The plan-comparison cards (Free vs Membership limits).

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `tiers.title` | Tiers | 套餐 |
| `tiers.subtitle` | What each tier includes. | 各套餐包含的内容。 |
| `tiers.yourTier` | Your plan | 你的套餐 |
| `tiers.gbPerMonth` | {gb} GB / month | 每月 {gb} GB |
| `tiers.mirrors` | Mirror URLs | 镜像链接 |
| `tiers.upgradeCta` | Upgrade | 升级 |

## `impact` — The donation-impact panel: bandwidth donated, free users helped, charts. *(16 missing)*

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `impact.title` | Donations support Unredacted | 捐款支持 Unredacted |
| `impact.body` | Unredacted is a US 501(c)(3) nonprofit. FreeSocks is one of the projects it runs. Donations fund the work. See what that work is on the Unredacted site. | Unredacted 是美国 501(c)(3) 非营利组织，FreeSocks 是其运营的项目之一。捐款支持这项工作。详情请见 Unredacted 网站。 |
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

| Key | English | Chinese (中文) |
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

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `qr.ariaLabel` | QR code for the subscription URL | 订阅链接二维码 |
| `qr.failed` | Couldn't generate the QR code. | 无法生成二维码。 |

## `app` — App-level chrome (skip link, page titles).

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `app.skipToContent` | Skip to content | 跳到主要内容 |
| `app.notFound` | Not found | 页面不存在 |
| `app.goHome` | Go home | 返回首页 |
| `app.adminLoadFailedTitle` | Couldn't load the admin console | 无法加载管理控制台 |
| `app.adminLoadFailedBody` | The network request for this section failed. Reload to retry. | 此部分的联网请求失败。请重新加载以重试。 |

## `footer` — The site footer (nonprofit line, terms/privacy links). *(8 missing)*

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `footer.operatedPrefix` | Operated by | 运营方： |
| `footer.operatedSuffix` | , a US 501(c)(3) nonprofit | （美国 501(c)(3) 非营利组织） |
| `footer.viewSource` | View source | ⚠️ **MISSING** |
| `footer.terms` | Terms of Service | ⚠️ **MISSING** |
| `footer.privacy` | Privacy Policy | ⚠️ **MISSING** |
| `footer.transparency` | Transparency Report | ⚠️ **MISSING** |
| `footer.socialX` | FreeSocks on X | ⚠️ **MISSING** |
| `footer.socialMastodon` | FreeSocks on Mastodon | ⚠️ **MISSING** |
| `footer.socialBluesky` | FreeSocks on Bluesky | ⚠️ **MISSING** |
| `footer.support` | Support | ⚠️ **MISSING** |

## `renew` — Expiring/expired membership callouts and renewal prompts.

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `renew.expiringTitle` | Your membership is expiring soon | 你的会员即将到期 |
| `renew.expiredTitle` | Your membership has expired | 你的会员已过期 |
| `renew.body` | FreeSocks is community-funded - donations keep it running. To renew your membership, donate or contact us for a membership code. | FreeSocks 由社区捐助运营。要续订会员，请捐款或联系我们获取会员码。 |
| `renew.donate` | Donate | 捐款 |
| `renew.contact` | Contact us | 联系我们 |
| `renew.lapsedBody` | You're on the free tier now. Renew below to restore your membership. | 您当前使用的是免费套餐。在下方续订以恢复您的会员资格。 |
| `renew.renewCta` | Renew membership | 续订会员 |

## `upgrade` — The paid-membership purchase panel (payment method, duration, totals). *(4 missing)*

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `upgrade.title` | Upgrade to a FreeSocks membership | 升级到 FreeSocks 会员 |
| `upgrade.extendTitle` | Extend your membership | 续订你的会员 |
| `upgrade.subtitle` | Unlimited bandwidth and devices. Choose a length and how to pay. | 无限流量与设备。选择时长和支付方式。 |
| `upgrade.subtitleNoDevices` | Unlimited bandwidth. Choose a length and how to pay. | ⚠️ **MISSING** |
| `upgrade.durationLabel` | Membership length | 会员时长 |
| `upgrade.cryptoMinNote` | Crypto payments start at {months} months - shorter terms fall below the network minimum. Pick another method for shorter terms. | 加密支付最少 {months} 个月，更短周期低于网络最低限额。如需更短周期请改用其他方式。 |
| `upgrade.months [countPlural=one]` | 1 month | 1 个月 |
| `upgrade.months [countPlural=other]` | {count} months | {count} 个月 |
| `upgrade.perMonth` | {price}/mo | {price}/月 |
| `upgrade.fromPerMonth` | From {price}/month | ⚠️ **MISSING** |
| `upgrade.benefitsShort` | Unlimited bandwidth and devices | ⚠️ **MISSING** |
| `upgrade.benefitsShortNoDevices` | Unlimited bandwidth | ⚠️ **MISSING** |
| `upgrade.save` | save {pct}% | 省 {pct}% |
| `upgrade.methodLabel` | Payment method | 支付方式 |
| `upgrade.payNowpayments` | Cryptocurrency | 加密货币 |
| `upgrade.payNowpaymentsHint` | Bitcoin, Monero, Zcash & more | 比特币、门罗币等 |
| `upgrade.payNowpaymentsBadge` | Private | 私人的 |
| `upgrade.cryptoPrivacyNote` | No account, email, or card needed - pay privately. Monero and Zcash offer the most privacy. | 无需账户、邮箱或银行卡--私密支付。门罗币和Zcash提供最高的隐私保护。 |
| `upgrade.payBtcpay` | Bitcoin | 比特币 |
| `upgrade.payBtcpayHint` | On-chain or Lightning | 链上或闪电网络 |
| `upgrade.payBtcpayBadge` | No intermediary | 无中介 |
| `upgrade.payStripe` | Card | 银行卡 |
| `upgrade.payStripeHint` | Credit or debit card | 信用卡或借记卡 |
| `upgrade.payPaypal` | PayPal | PayPal |
| `upgrade.payPaypalHint` | PayPal balance or card | PayPal 余额或银行卡 |
| `upgrade.total` | Total {price} | 合计 {price} |
| `upgrade.continue` | Continue to payment | 继续付款 |
| `upgrade.starting` | Starting checkout… | 正在开始付款… |
| `upgrade.startFailed` | Could not start checkout | 无法开始付款 |
| `upgrade.noStoreNote` | We never see your card or wallet, and store no payment details. | 我们绝不存储你的邮箱或支付信息。 |
| `upgrade.confirmingTitle` | Confirming your payment… | 正在确认你的付款… |
| `upgrade.confirmingBody` | Crypto can take a few minutes to confirm. You can leave this page - your membership activates automatically. | 加密货币确认可能需要几分钟。你可以离开此页面--会员将自动激活。 |
| `upgrade.paidTitle` | Membership active | 会员已激活 |
| `upgrade.paidBody` | Thank you! Your membership is now active. | 谢谢！你的会员现已激活。 |
| `upgrade.failedTitle` | Payment not completed | 付款未完成 |
| `upgrade.failedBody` | Your payment did not go through, or the checkout expired. You can try again. | 你的付款未成功，或结账已过期。你可以重试。 |

## `gift` — Gift membership codes: buying, revealing (show-once), and redeeming.

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `gift.title` | Buy codes to share | 购买分享码 |
| `gift.subtitle` | Purchase membership codes to give to friends or family. Each works on any account and never touches yours. | 购买会员码赠送给亲朋好友。每个会员码都适用于任何账户，绝不会影响您的账户。 |
| `gift.quantityLabel` | How many | 多少 |
| `gift.buy` | Buy codes | 购买代码 |
| `gift.starting` | Starting checkout… | 开始结账…… |
| `gift.startFailed` | Could not start checkout | 无法开始结账 |
| `gift.boughtTitle` | Codes you've bought | 你购买的兑换码 |
| `gift.boughtEmpty` | You haven't bought any codes yet. | 您尚未购买任何兑换码。 |
| `gift.statusAvailable` | Available | 可用的 |
| `gift.statusRedeemed` | Redeemed | 已赎回 |
| `gift.statusRevoked` | Revoked | 撤销 |
| `gift.redeemedOn` | Redeemed {date} | 已兑换{date} |
| `gift.copyAll` | Copy all | 全部复制 |
| `gift.reveal.title` | Save these codes now | 立即保存这些代码 |
| `gift.reveal.body` | Copy and share each code. For security we show them only once - afterwards you will see only a prefix. | 复制并分享每个代码。出于安全考虑，我们只会显示一次完整代码--之后您将只会看到前缀。 |
| `gift.reveal.ack` | I have saved these codes | 我已经保存了这些代码。 |
| `gift.reveal.saved` | I've saved them | 我把它们保存下来了。 |
| `gift.reveal.leaveWarning` | Your codes are still on screen. If you leave now without saving them, you will not be able to see them again. | 您的代码仍然显示在屏幕上。如果您现在不保存就离开，您将无法再次看到它们。 |

## `error` — API error messages shown to members.

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `error.offline` | You appear to be offline. Check your connection and try again. | 你似乎已离线。请检查网络连接后重试。 |
| `error.rateLimited` | Too many attempts. Please wait a minute and try again. | 尝试次数过多。请等待一分钟后重试。 |
| `error.backendUnavailable` | No proxy server is available right now. Your account is safe - try creating your key again in a few minutes. | 当前没有可用的代理服务器。你的账户是安全的--请几分钟后再创建密钥。 |
| `error.generic` | Something went wrong. Please try again. | 出错了，请重试。 |
| `error.captchaFailed` | The human check failed. Please complete it and try again. | 真人验证失败。请完成验证后重试。 |
| `error.captchaUnconfigured` | The service is temporarily unavailable. Please try again in a few minutes. | 服务暂时不可用，请几分钟后重试。 |
| `error.renderTitle` | Something went wrong | 出问题了 |
| `error.renderBody` | The page failed to render. This is a bug in the app, and refreshing usually fixes it. If it keeps happening, please report it. | 页面渲染失败。这是应用的一个bug，通常刷新页面即可解决。如果问题持续出现，请提交报告。 |
| `error.reloadPage` | Reload page | 重新加载页面 |
| `error.tryAgain` | Try again | 再试一次 |
| `error.sessionExpired` | Your session has ended. Please sign in again. | 您的会话已结束。请重新登录。 |
| `error.invalidAccountId` | That account number wasn't recognized. Check it and try again. | 系统无法识别该账号。请检查并重试。 |
| `error.codeInvalid` | That code can't be redeemed. Check it for typos and try again. | 该代码无法兑换。请检查是否有拼写错误，然后重试。 |
| `error.changeInProgress` | Another change is already in progress - try again in a moment. | 另一项更改已在进行中--请稍后再试。 |
| `error.backendDisabled` | That option is currently unavailable. | 目前无法选择此选项。 |
| `error.noPeerTier` | Switching isn't available for your plan yet. | 您的套餐目前尚不支持切换。 |
| `error.deviceNotFound` | That device is no longer on your account. | 该设备已不在您的帐户中。 |
| `error.deviceUnsupported` | Your current server type doesn't support removing individual devices. | 您当前的服务器类型不支持移除单个设备。 |
| `error.billing` | The payment service couldn't process this. Please try again later. | 支付服务无法处理此笔交易。请稍后再试。 |
| `error.serverError` | The server had a problem handling this. Please try again in a few minutes. | 服务器处理此请求时出现问题，请稍后再试。 |

## `setup` — The "set up your app" section: recommended VPN clients per platform, install steps. *(26 missing)*

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `setup.title` | Set up your proxy app | 设置你的代理应用 |
| `setup.install` | Install | 安装 |
| `setup.noApps` | No recommended apps for this platform yet - use any compatible client and add your subscription manually. | ⚠️ **MISSING** |
| `setup.openSource` | Open source | ⚠️ **MISSING** |
| `setup.proprietary` | Proprietary | ⚠️ **MISSING** |
| `setup.easeEasy` | Easy to use | ⚠️ **MISSING** |
| `setup.easeAdvanced` | Advanced | ⚠️ **MISSING** |
| `setup.viewSource` | Source | ⚠️ **MISSING** |
| `setup.intro` | Copy your subscription link above, then add it to a compatible app: | 复制上方的订阅链接，然后添加到兼容的应用中： |
| `setup.android` | Android | 安卓 |
| `setup.ios` | iPhone / iPad | iPhone / iPad |
| `setup.windows` | Windows | Windows |
| `setup.desktop` | macOS / Linux | macOS / Linux |
| `setup.step.install` | Install the app | 安装应用 |
| `setup.step.import` | Open it, add a subscription / profile, and paste your link | 打开它，添加订阅/配置文件，并粘贴你的链接 |
| `setup.step.importConfig` | Open it, choose to add servers manually, and enter the configuration shown below | 打开它，选择手动添加服务器，然后输入如下所示的配置。 |
| `setup.step.connect` | Select a server and connect | 选择一个服务器并连接 |
| `setup.noDeviceLimit` | no device limit | 无设备限制 |
| `setup.hwidNote` | On a device-limited plan, turn on "device identification" (HWID) in the app's settings so your device is recognized. | 如果套餐包含有限数量的设备，请在应用程序的设置中启用“设备识别”（HWID），以便识别您的设备。 |
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

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `mirror.disclosure` | Trouble connecting? | 连接有问题？ |
| `mirror.explainer` | If your normal subscription link won't connect where you are, add a mirror link below. It serves the same key from a different host that may not be blocked. | 如果你所在位置无法用普通订阅链接连接，可在下方添加镜像链接。它会从另一个可能未被封锁的主机提供相同的密钥。 |
| `mirror.addedLabel` | Your mirror links | 你的镜像链接 |
| `mirror.addToAppHint` | Add each one as an extra subscription in your app, then try connecting. | 将每个链接作为额外的订阅添加到你的应用中，然后尝试连接。 |
| `mirror.regionLabel` | Your region | 你所在的地区 |
| `mirror.regionGlobal` | Global (any region) | 全球（任意地区） |
| `mirror.regionNotStored` | Used only to pick a nearby mirror - it isn't stored. | 仅用于选择就近的镜像 - 不会被存储。 |
| `mirror.getButton` | Get a mirror link | 获取镜像链接 |
| `mirror.tryAnother` | Try another mirror | 尝试其他镜像 |
| `mirror.working` | Working… | 处理中… |
| `mirror.capped` | You've added the maximum number of mirrors. | 你添加的镜像数量已达上限。 |
| `mirror.exhausted` | No more mirrors are available for your region right now. | 当前没有更多适用于你所在地区的镜像。 |
| `mirror.noSubscription` | Create your key first, then you can add a mirror. | 请先创建你的密钥，然后才能添加镜像。 |
| `mirror.removeAll` | Remove all mirrors | 移除所有镜像 |
| `mirror.errorToast` | Couldn't add a mirror | 无法添加镜像 |
| `mirror.removedToast` | Mirrors removed | 镜像已移除 |

## `rawconfig` — The raw-configuration viewer (privacy mode delivers config text, not a URL).

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `rawconfig.disclosure` | Show raw configuration | 显示原始配置 |
| `rawconfig.title` | Your configuration | 你的配置 |
| `rawconfig.explainer` | Your full proxy configuration, fetched over an encrypted channel so it never crosses a CDN in plain text. Copy it into your app by hand instead of using a subscription link. | 你的完整代理配置，通过加密通道获取，因此不会以明文经过 CDN。可手动复制到你的应用中，而无需使用订阅链接。 |
| `rawconfig.addHint` | Paste these server entries into your proxy app manually. | 将这些服务器条目手动粘贴到你的代理应用中。 |

## `delivery` — The connection-mode picker: "Beat censorship" (for censored countries) vs "Maximum privacy" (for open internet), plus the switch-confirmation dialog. *(6 missing)*

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `delivery.title` | What matters most to you? | 你最看重什么？ |
| `delivery.subtitle` | Pick a focus. It's saved on this device only, and you can change it anytime. | 选择一个侧重点 - 仅保存在本设备，可随时更改。 |
| `delivery.subtitleServer` | Pick a focus. Changing it moves your existing key to the matching servers - your subscription URL stays the same. | 选择一个焦点。更改焦点后，系统会重新颁发匹配服务器的密钥；您当前的密钥将继续有效 24 小时。 |
| `delivery.subtitleSignup` | Pick a focus. It's saved to your account, and your first key uses it - you can change it anytime. | 选择一个焦点。它会保存到你的账户，你的第一个密钥将使用它--可随时更改。 |
| `delivery.evadeTitle` | Internet Freedom Mode | ⚠️ **MISSING** |
| `delivery.evadeAudience` | For censored countries | ⚠️ **MISSING** |
| `delivery.evadeBody` | Pick this if websites, apps, or VPNs are blocked where you are. Built to keep working under censorship, with backup links that are harder to block. | ⚠️ **MISSING** |
| `delivery.privacyTitle` | Privacy Mode | ⚠️ **MISSING** |
| `delivery.privacyAudience` | For open internet | ⚠️ **MISSING** |
| `delivery.privacyBody` | Pick this if the internet is mostly open where you are. The strongest confidentiality - your configuration stays off third-party servers - but it is easier for censors to block. | ⚠️ **MISSING** |
| `delivery.recommended` | Recommended | 推荐 |
| `delivery.unavailable` | Not available yet | 暂无 |
| `delivery.confirmTitle` | Switch to "{label}"? | 切换到“ {label} "？ |
| `delivery.confirmBody` | This moves your existing key to the {label} servers, keeping the same subscription URL. Your apps keep working and pick up the new servers on their next refresh. | 这将重新颁发您用于{label}服务器的代理密钥。您当前的密钥将继续有效 24 小时，因此您可以先在所有设备上重新导入。 |
| `delivery.confirmPoint1` | Your key moves to the {label} servers - same subscription URL, nothing to re-import | 为{label}服务器颁发新的订阅 URL |
| `delivery.confirmPoint2` | Takes effect within a minute - reconnect in your app if it doesn't refresh on its own | 您当前的密钥将继续有效 24 小时，然后将被删除。 |
| `delivery.confirmPoint3` | Using the raw config? Copy the new one after switching | 您需要在您使用的每个 VPN 客户端中重新导入新的 URL。 |
| `delivery.confirmPointDevices [countPlural=one]` | Your 1 connected device will reconnect to the new servers | 您当前已连接 1 台设备；请重新导入到该设备。 |
| `delivery.confirmPointDevices [countPlural=other]` | Your {count} connected devices will reconnect to the new servers | 您当前已连接{count}个设备；请重新导入所有设备。 |
| `delivery.confirm` | Switch focus | 切换焦点 |
| `delivery.working` | Switching… | 交换… |
| `delivery.switchSuccessTitle` | Switched to "{label}" | 切换到“ {label} |
| `delivery.switchSuccessBodyGrace` | Re-import the new subscription URL on each device. Your old key works for 24 more hours. | 在每台设备上重新导入新的订阅网址。您的旧密钥还能再用24小时。 |
| `delivery.switchSuccessBody` | Same subscription URL - your apps will pick up the new servers on their next refresh. | 在每台设备上重新导入新的订阅网址。 |
| `delivery.switchFailedTitle` | Could not switch focus | 无法切换焦点 |

## `home` — The public landing page: hero, feature sections, impact section, FAQ intros. *(37 missing)*

| Key | English | Chinese (中文) |
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
| `home.hero.subtitle` | FreeSocks is made for people whose internet is censored, and works as a privacy-respecting VPN anywhere else. Signing up takes one quick human check. We never ask for an email or a password. Your subscription URL works in most modern VPN apps, and a membership gets you {limits}. | ⚠️ **MISSING** |
| `home.hero.impactNote` | Donations made through FreeSocks directly power free users: every donation buys real bandwidth for people in censored countries, that same month. | ⚠️ **MISSING** |
| `home.hero.impactLink` | See the impact | ⚠️ **MISSING** |
| `home.cta.getMembership` | Get a membership | 加入会员 |
| `home.freeCard.title` | Free tier | 免费套餐 |
| `home.freeCard.badge` | What you get | 你将获得什么 |
| `home.freeCard.urlTitle` | Xray subscription URL | X射线订阅网址 |
| `home.freeCard.urlBody` | Xray-powered VLESS. Paste into any compatible client. | Xray-powered VLESS. Paste into any compatible client. |
| `home.freeCard.membershipLine` | A FreeSocks membership gives you {limits}. | FreeSocks 会员资格为您提供{limits} 。 |
| `home.freeCard.noAuthTitle` | No email or password | 无需电子邮件或密码 |
| `home.freeCard.noAuthBody` | One human-check. Save your account number to sign in. No email collected. | 一次人工验证。保存您的账号即可登录。不收集邮箱地址。 |
| `home.freeCard.footnote` | Numbers reflect the current free-tier configuration. Solve the check to get yours. | 此处显示的数字反映的是当前免费套餐的配置。完成验证即可获取您的套餐配置。 |
| `home.freeCard.upsellTitle` | Want unlimited? | 想要无限量供应？ |
| `home.freeCard.upsellBody` | Get {limits} - and help keep FreeSocks free for others. | 获取{limits} - 并帮助 FreeSocks 继续免费供他人使用。 |
| `home.freeCard.fromPerMonth` | from {price}/mo | 来自{price} /月 |
| `home.freeCard.cryptoNote` | Crypto accepted - Bitcoin, Monero, Zcash and more | ⚠️ **MISSING** |
| `home.features.title` | What FreeSocks is | FreeSocks是什么 |
| `home.features.noAuth.title` | No email or password | 无需电子邮件或密码 |
| `home.features.noAuth.body` | One human-check and you are in. We mint a 32-digit account number you save to sign back in. No email collected. | 只需一次人工验证即可登录。我们会生成一个32位数的账号，您可以保存该账号以便下次登录。我们不会收集您的邮箱地址。 |
| `home.features.mirrors.title` | Mirror URLs | 镜像网址 |
| `home.features.mirrors.body` | Subscriptions are mirrored across multiple providers so a single block does not cut you off. | 订阅服务在多个提供商之间是同步的，因此单个服务中断不会导致您的服务中断。 |
| `home.features.protocols.title` | Standard protocols | 标准协议 |
| `home.features.protocols.body` | Xray-powered VLESS. Works in most VPN clients. | Xray-powered VLESS. Works in most VPN clients. |
| `home.privacy.title` | What we store | 我们储存 |
| `home.privacy.subtitle` | FreeSocks is built to know as little about you as possible. | FreeSocks 的设计理念是尽可能少地了解你的信息。 |
| `home.privacy.point1` | We store only a hashed version of your account number - never the number itself. | 我们只存储您账号的哈希版本，绝不会存储账号本身。 |
| `home.privacy.point2` | No email, phone number, or name. We never ask for them. | 无需提供电子邮件地址、电话号码或姓名。我们从不索取这些信息。 |
| `home.privacy.point3` | No logs of the sites you visit or the traffic you send - and we don't store your IP address, on our servers or the proxy nodes. | 不会记录您访问的网站或您发送的流量。 |
| `home.privacy.point4` | We store no payment details - you pay on the provider's own page, and the provider never sees your account or proxy subscription. | 我们不会存储任何付款详情--您在服务提供商的页面上付款，服务提供商永远不会看到您的帐户或代理订阅信息。 |
| `home.how.title` | How it works | 工作原理 |
| `home.how.cta` | Try it now | 立即尝试 |
| `home.how.s1.title` | Create a free account | 创建免费帐户 |
| `home.how.s1.body` | Solve a quick human-check. You get a 32-digit account number to save: it is how you sign back in. | 完成一个简单的验证。您将获得一个32位数的账号，请保存：这是您下次登录的凭证。 |
| `home.how.s2.title` | Create your subscription | 创建您的订阅 |
| `home.how.s2.body` | Once you are signed in, create a subscription URL, with a QR code for handoff to a phone. | 登录后，创建一个订阅网址，并生成一个二维码，以便将其传输到手机上。 |
| `home.how.s3.title` | Paste it into a VPN client | 将其粘贴到 VPN 客户端中 |
| `home.how.s3.body` | Add the URL as a subscription in any compatible client. | 在任何兼容的客户端中将该URL添加为订阅。 |
| `home.membership.title` | Membership | 会员资格 |
| `home.membership.lead` | Free covers the basics. | 免费版涵盖基本内容。 |
| `home.membership.descriptionFallback` | A FreeSocks membership lifts every limit. | FreeSocks 会员资格可解除所有限制。 |
| `home.membership.payNote` | Pay privately with Bitcoin, Monero, or Zcash - or use a card or PayPal. | 可使用加密货币（比特币、门罗币等）、银行卡或PayPal支付。 |
| `home.about.title` | About FreeSocks | ⚠️ **MISSING** |
| `home.about.bodyPrefix` | FreeSocks is operated by | FreeSocks 由 |
| `home.about.bodySuffix` | , a US 501(c)(3) nonprofit. | ⚠️ **MISSING** |
| `home.about.body2` | Most VPNs assume you can pay for a subscription and safely hand over an email address. In much of the world neither is true, so FreeSocks asks for neither. Anyone can get a working key in about a minute and keep it for as long as they use it. | ⚠️ **MISSING** |
| `home.about.siteLink` | unredacted.org | 未编辑的.org |
| `home.about.openSource` | The code that runs this service is published for anyone to inspect, audit, or run themselves. | ⚠️ **MISSING** |
| `home.about.viewSourceCta` | View the source | ⚠️ **MISSING** |
| `home.about.fact2Title` | Open source | ⚠️ **MISSING** |
| `home.about.fact3Title` | Donation funded | ⚠️ **MISSING** |
| `home.about.fact3Body` | Free accounts are paid for by donations and memberships. There are no ads and nothing is sold. | ⚠️ **MISSING** |
| `home.limits.unlimitedBoth` | unlimited bandwidth and devices | 无限带宽和设备 |
| `home.limits.unlimitedBandwidth` | unlimited bandwidth | 无限带宽 |
| `home.limits.unlimitedDevices` | unlimited devices | 无限设备 |
| `home.limits.bandwidthAndDevices` | {bandwidth} and {devices} | {bandwidth}和{devices} |
| `home.limits.upToDevices [countPlural=one]` | up to 1 device | 最多 1 台设备 |
| `home.limits.upToDevices [countPlural=other]` | up to {count} devices | 最多{count}设备 |

## `e2ee` — The HPKE/E2EE "encrypted to this server" badge + verification panel.

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `e2ee.badgeActiveTitle` | Encrypted to this server with HPKE. Click to verify. | 已使用HPKE加密传输到此服务器。点击验证。 |
| `e2ee.badgeWarnTitle` | Couldn't verify the encryption key. Click to verify out-of-band before entering your account number. | 无法验证加密密钥。请点击进行带外验证，然后再输入您的账号。 |
| `e2ee.badgeActiveTitleAdmin` | Sensitive member and admin actions are HPKE-encrypted on this deployment. Click for details. | 在此部署中，敏感的成员和管理员操作均采用 HPKE 加密。点击查看详情。 |
| `e2ee.badgeWarnTitleAdmin` | Couldn't verify this deployment's encryption key. Click for details and out-of-band verification. | 无法验证此部署的加密密钥。点击此处查看详情并进行带外验证。 |
| `e2ee.badgeOff` | TLS | TLS |
| `e2ee.badgeOffTitle` | Standard TLS only. Extra HPKE body encryption isn't enabled on this deployment. | 仅支持标准 TLS。此部署未启用额外的 HPKE 正文加密。 |
| `e2ee.bannerWarn` | Couldn't verify the encryption key | 无法验证加密密钥 |
| `e2ee.bannerWarnDetail` | Don't enter your account number yet - verify this connection out-of-band first. | 暂时不要输入您的账号 - 请先通过带外方式验证此连接。 |
| `e2ee.verify` | Verify | 核实 |
| `e2ee.verifyTitle` | Verify this connection | 验证此连接 |
| `e2ee.verifyIntro` | FreeSocks seals your account number and proxy key to this server with HPKE, so a compromised CDN can't read them. These fingerprints identify the keys your browser is using - compare them against the values published out-of-band to be sure they haven't been swapped. | FreeSocks 使用 HPKE 将您的账号和代理密钥与此服务器进行加密，因此即使 CDN 遭到入侵也无法读取它们。这些指纹可以识别您的浏览器正在使用的密钥--请将它们与带外发布的密钥值进行比较，以确保密钥未被替换。 |
| `e2ee.protectHeading` | What this protects | 它保护的是什么 |
| `e2ee.protectScope` | Your account number and key are encrypted to this server with HPKE, so the network and any CDN in front of it can't read them. | 您的账号和密钥已使用 HPKE 加密到此服务器，因此网络及其前面的任何 CDN 都无法读取它们。 |
| `e2ee.protectServerReads` | FreeSocks itself can read them to set up your account, so this protects you from the network in between, not from the server. | FreeSocks 本身可以读取这些信息来设置您的帐户，因此这保护您免受中间网络的侵害，而不是免受服务器的侵害。 |
| `e2ee.protectTunnel` | It's separate from your VPN connection, which is encrypted on its own. | 它与您的 VPN 连接是分开的，VPN 连接本身是加密的。 |
| `e2ee.protectAdmin` | On the admin dashboard, sensitive actions - creating API tokens, invites, and membership codes, and uploading backend, billing, or storage credentials - are HPKE-encrypted to this server too. Routine reads and settings use TLS, your passkey, and proof-of-possession. | 在管理后台，创建 API 令牌、邀请码和会员代码，以及上传后端、计费或存储凭证等敏感操作也会使用 HPKE 加密传输到此服务器。常规读取和设置操作则使用 TLS、您的密码和所有权证明。 |
| `e2ee.fingerprintsHeading` | Key fingerprints | 关键指纹 |
| `e2ee.fpHpke` | Server key (HPKE / X-Wing) | 服务器密钥（HPKE / X-Wing） |
| `e2ee.fpKid` | Key id | 密钥 ID |
| `e2ee.fpManifest` | Manifest key (Ed25519) | 清单密钥（Ed25519） |
| `e2ee.fpManifestPq` | Manifest key (ML-DSA-65, post-quantum) | 清单密钥（ML-DSA-65，后量子时代） |
| `e2ee.fpSuite` | Cipher suite | 密码套件 |
| `e2ee.copy` | Copy | 复制 |
| `e2ee.copied` | Copied | 已复制 |
| `e2ee.attestationHeading` | Live server attestation | 在线服务器证明 |
| `e2ee.attestationOk` | Verified - the server is attesting a valid key signed by the manifest key your app trusts. | 已验证 - 服务器正在验证由您的应用信任的清单密钥签名的有效密钥。 |
| `e2ee.attestationEpoch` | Current key {kid}, expires {expiry}. | 当前键{kid} ，过期{expiry} 。 |
| `e2ee.attestationFail` | Could not verify the server's current key - a network problem, or a CDN tampering with the key endpoint. Verify out-of-band before continuing. | 无法验证服务器的当前密钥--可能是网络问题，或者 CDN 篡改了密钥端点。请在继续操作前进行带外验证。 |
| `e2ee.attestationUnreachable` | The live key check is temporarily unavailable. Your connection still uses the verified key built into the app. | 实时密钥验证功能暂时不可用。您的连接仍使用应用内置的已验证密钥。 |
| `e2ee.attestationUnconfigured` | Live key checking isn't set up on this build. | 此版本未启用实时密钥检查。 |
| `e2ee.compareHeading` | How to verify | 如何验证 |
| `e2ee.compareBody` | Compare the fingerprints above against the values published through a channel this server doesn't control. They must match. | 将上述指纹与通过此服务器无法控制的渠道发布的值进行比较。它们必须匹配。 |
| `e2ee.channelRelease` | Signed release notes | 已签署的发布说明 |
| `e2ee.channelSource` | Source code (rebuild to compare) | 源代码（重新构建以进行比较） |
| `e2ee.channelOnion` | Tor mirror | Tor镜像 |
| `e2ee.dnsHeading` | Verify via DNS | 通过 DNS 验证 |
| `e2ee.dnsBody` | Look the pin up yourself in a terminal, through your own DNS resolver - a path that doesn't run through this site or its CDN. The answer should contain the same fingerprints shown above. (If it returns nothing, the operator may not have published the record yet; use the signed release instead.) | 请在终端中使用您自己的 DNS 解析器查找该 PIN 码--该解析器使用的路径不应经过此站点或其 CDN。查询结果应包含与上面显示的相同的指纹。（如果没有任何返回结果，则可能是运营商尚未发布该记录；请改用已签名的发布版本。） |
| `e2ee.dnsCommand` | Run this in a terminal | 在终端中运行此命令。 |
| `e2ee.dnsExpected` | It should return | 它应该返回 |
| `e2ee.dnsCaveat` | Independent only if your DNS isn't run by the same company as the CDN; a DNSSEC-validating resolver is best. For full assurance, confirm the same values in the signed release too. | 仅当您的 DNS 服务器与 CDN 服务器并非由同一家公司运营时，才应使用独立 DNS 服务器；最好使用支持 DNSSEC 验证的解析器。为确保万无一失，请同时确认已签署的发布文件中的相同值。 |
| `e2ee.verifierExtension` | A verifier browser extension that re-checks this build on every visit is planned, but not available yet. | 我们计划推出一款浏览器扩展程序，每次访问时都会重新检查此版本，但目前尚未推出。 |
| `e2ee.verifierExtensionInstall` | Install the verifier extension - it re-checks this build against the published one on every visit (the strongest protection against a tampered page). | 安装验证器扩展程序 - 每次访问时，它都会将此版本与已发布的版本进行重新检查（这是防止页面被篡改的最强保护措施）。 |
| `e2ee.caveat` | This in-page check is a convenience. A tampered page could lie about its own status, so the real proof comes from comparing these values somewhere outside this server, such as the DNS lookup above or a published release. | 页面内检查只是为了方便。被篡改的页面可能会谎报自身状态，因此真正的验证方法是将这些数据与服务器外部的值进行比较，例如上述 DNS 查询或已发布的版本。 |
| `e2ee.close` | Close | 关闭 |

## `deviceRevoke` — The disconnect-a-device confirmation dialog.

| Key | English | Chinese (中文) |
| --- | --- | --- |
| `deviceRevoke.title` | Revoke this device? | 撤销此设备？ |
| `deviceRevoke.body` | The device ending …{suffix} will be disconnected and its slot freed. It can reconnect later by re-importing your subscription URL. | 设备名称以… {suffix}结尾，该设备将被断开连接并释放其插槽。稍后可通过重新导入订阅 URL 来重新连接。 |
| `deviceRevoke.confirm` | Revoke device | 撤销装置 |
| `deviceRevoke.working` | Revoking… | 撤销…… |
