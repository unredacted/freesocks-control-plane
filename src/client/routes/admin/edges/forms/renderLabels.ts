/** Display names for render client families and body formats (pure). */
import type { EdgeRenderPreviewResponse, RenderClientFamily } from '@shared/contracts/edges';

export const FAMILY_LABELS: Record<RenderClientFamily, string> = {
  singbox: 'sing-box',
  mihomo: 'Mihomo / Clash',
  'xray-links': 'Xray links',
  happ: 'Happ',
  hiddify: 'Hiddify',
  streisand: 'Streisand',
  v2rayng: 'v2rayNG',
  other: 'Other clients',
};

export const FORMAT_LABELS: Record<EdgeRenderPreviewResponse['format'], string> = {
  links: 'share links',
  'singbox-json': 'sing-box JSON',
  'clash-yaml': 'Clash YAML',
};
