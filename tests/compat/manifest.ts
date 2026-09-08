/** Versioned test inputs, not a claim that a GUI sharing an engine was tested. */
export const artifacts = {
  singbox: {
    repo: 'SagerNet/sing-box',
    version: '1.14.0',
    asset: 'sing-box-1.14.0-linux-amd64.tar.gz',
    sha256: '2375de6999f4f56ab46b4fc5ddf26a6aba1d3e61a0f4e7ddec2f4690457d5f63',
  },
  mihomo: {
    repo: 'MetaCubeX/mihomo',
    version: '1.19.30',
    asset: 'mihomo-linux-amd64-v1.19.30.gz',
    sha256: 'cf06ce2c7d1421bdbda14ee4a5b6046672dc35ebf8eecd8e77504ec3c0ed9a84',
  },
  sfl: {
    repo: 'SagerNet/sing-box',
    version: '1.14.0',
    asset: 'SFL-1.14.0-amd64.deb',
    sha256: '8502e0c7aafbc7af03d8ddfbeb5b8de7f4c0b9cbe6ee3c19038a57b4c12e1a0e',
  },
} as const;

export type Format = 'singbox' | 'mihomo' | 'links' | 'outline';
export interface CompatibilityClient {
  name: string;
  format: Format;
  /** Regression/contract inputs; only SFL is captured from a pinned package. */
  userAgents: string[];
  application: 'automated-sfl' | 'manual';
  limitation: string;
}
export const clients: CompatibilityClient[] = [
  {
    name: 'sing-box',
    format: 'singbox',
    userAgents: [
      'SFL (sing-box 1.14.0; language en_US)',
      'SFL (sing-box 1.14.0; language zh_CN)',
      'SFW (sing-box 1.14.0; language en_US)',
      'SFL/1.14.0',
      'SFA/1.14.0',
      'SFI/1.14.0',
      'SFM/1.14.0',
    ],
    application: 'automated-sfl',
    limitation:
      'SFL package import/refresh automated on Linux; other shells require device verification.',
  },
  {
    name: 'Hiddify',
    format: 'links',
    userAgents: ['Hiddify/2.0'],
    application: 'manual',
    limitation:
      'Subscription contract only; bundled parser, engine and GUI need device verification.',
  },
  {
    name: 'Karing',
    format: 'singbox',
    userAgents: ['Karing/1.0'],
    application: 'manual',
    limitation:
      'Contract plus reference sing-box engine; bundled engine, HWID and GUI require device verification.',
  },
  {
    name: 'Anywhere',
    format: 'links',
    userAgents: ['Anywhere/1.0'],
    application: 'manual',
    limitation: 'Apple hardware and installed App Store build required.',
  },
  {
    name: 'v2rayNG',
    format: 'links',
    userAgents: ['v2rayNG/1.8.29'],
    application: 'manual',
    limitation: 'Android application and bundled Xray engine require device verification.',
  },
  {
    name: 'v2rayN',
    format: 'links',
    userAgents: ['v2rayN/7.0'],
    application: 'manual',
    limitation: 'Application and bundled Xray engine require device verification.',
  },
  {
    name: 'Clash',
    format: 'mihomo',
    userAgents: ['Clash-Verge/v2.0'],
    application: 'manual',
    limitation:
      'Contract plus reference Mihomo engine; packaged application requires device verification.',
  },
  {
    name: 'FlClash',
    format: 'mihomo',
    userAgents: ['FlClash/0.8'],
    application: 'manual',
    limitation:
      'Contract plus reference Mihomo engine; packaged application requires device verification.',
  },
  {
    name: 'Mihomo Party',
    format: 'mihomo',
    userAgents: ['mihomo/1.19.30'],
    application: 'manual',
    limitation:
      'Contract plus reference Mihomo engine; packaged application requires device verification.',
  },
  {
    name: 'Throne',
    format: 'links',
    userAgents: ['Throne/1.0'],
    application: 'manual',
    limitation:
      'Subscription contract only; packaged application and HWID require device verification.',
  },
  {
    name: 'Shadowrocket',
    format: 'links',
    userAgents: ['Shadowrocket/2.2'],
    application: 'manual',
    limitation: 'Licensed iOS application on Apple hardware required.',
  },
  {
    name: 'Outline',
    format: 'outline',
    userAgents: [],
    application: 'manual',
    limitation:
      'Static ss:// key contract only; Outline application and Shadowsocks transport require device verification.',
  },
];

export const applicationTargets = [
  { id: 'debian-13-xfce', runner: 'fcp-debian-13-xfce', package: 'sfl' },
  { id: 'mx-25.2-xfce', runner: 'fcp-mx-25-2-xfce', package: 'sfl' },
] as const;
