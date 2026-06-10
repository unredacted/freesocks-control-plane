import type { Messages } from './en';

/**
 * Simplified Chinese (简体中文). First-pass translations of the critical strings;
 * missing keys fall back to English. FLAGGED FOR NATIVE-SPEAKER REVIEW. (zh uses
 * the system font stack — we don't bundle CJK fonts.)
 */
export const zh: Partial<Messages> = {
  'common.copy': '复制',
  'common.copied': '已复制到剪贴板',
  'common.copyFailed': '复制失败——请选中文本手动复制',
  'common.download': '下载',
  'common.print': '打印',
  'common.cancel': '取消',
  'common.close': '关闭',
  'common.retry': '重试',
  'common.loading': '加载中…',
  'common.language': '语言',

  'nav.getAccount': '获取免费账户',
  'nav.signIn': '登录',
  'nav.account': '我的账户',

  'captcha.initial': '我是真人',
  'captcha.verifying': '验证中…',
  'captcha.solved': '已验证',
  'captcha.error': '验证失败——请重试',

  'reveal.title': '立即保存你的账户号码',
  'reveal.subtitle':
    '这个 32 位数字是再次登录的唯一方式。没有电子邮件或密码可用于找回。一旦丢失，你的账户将永久无法恢复。',
  'reveal.cannotRecover': '我们无法为你找回——客服也不行。',
  'reveal.saveHint': '把它保存到密码管理器，或写在安全私密的地方。',
  'reveal.confirmCheckbox': '我已把账户号码保存在安全的地方',
  'reveal.done': '我已保存',
  'reveal.leaveWarning': '你的账户号码仍显示在屏幕上。如果现在未保存就离开，你将无法再次登录。',

  'support.label': '支持 ID',
  'support.hint': '联系我们时请提供它。它不是你的登录号码，也不授予任何访问权限。',

  'login.title': '使用账户号码登录',
  'login.subtitle': '输入你保存的 32 位账户号码。这是唯一的登录方式——没有可找回的电子邮件或密码。',
  'login.label': '账户号码',
  'login.show': '显示',
  'login.hide': '隐藏',
  'login.submit': '登录',
  'login.submitting': '登录中…',
  'login.noAccount': '还没有账户号码？',
  'login.getOne': '获取免费账户',
  'login.failed': '登录失败',

  'account.title': '你的账户',
  'account.tierLabel': '你的套餐',
  'account.statusActive': '有效',
  'account.statusGrace': '即将到期',
  'account.statusDisabled': '已过期',
  'account.regenerate': '创建新密钥',
  'account.switchBackend': '切换服务器类型',
  'account.rotate': '更改账户号码',
  'account.signOut': '退出登录',
  'account.redeemTitle': '有会员码？',
  'account.redeemSubmit': '兑换码',
  'account.redeemSuccess': (p) => `已兑换——你现在是 ${p.tier}，还有 ${p.days} 天。`,
  'account.redeemFailed': '该码无效或已被使用。',

  'renew.expiringTitle': '你的会员即将到期',
  'renew.expiredTitle': '你的会员已过期',
  'renew.body': 'FreeSocks 由社区捐助运营。要续订会员，请捐款或联系我们获取会员码。',
  'renew.donate': '捐款',
  'renew.contact': '联系我们',
  'renew.haveCode': '有会员码？在上方兑换。',

  'error.offline': '你似乎已离线。请检查网络连接后重试。',
  'error.rateLimited': '尝试次数过多。请等待一分钟后重试。',
  'error.backendUnavailable': '当前没有可用的代理服务器。你的账户是安全的——请几分钟后再创建密钥。',
  'error.generic': '出错了，请重试。',
  'error.captchaFailed': '真人验证失败。请完成验证后重试。',

  'setup.title': '设置你的代理应用',
  'setup.intro': '复制上方的订阅链接，然后添加到兼容的应用中：',
  'setup.qrHint': '或用手机扫描此二维码来传输链接。',
};
