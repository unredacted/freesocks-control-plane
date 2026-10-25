/**
 * The REALITY client verdict (src/shared/contracts/realityClients.ts) in words:
 * which clients a transport refuses, why, and the one change that lets them
 * in. Shared by the protect sheet, the test card and the adopt dialog, so the
 * fix is named the same way everywhere.
 *
 * Exports:
 *   REALITY_FAMILY_WORDS          a refused family, with the apps built on it
 *   realityRefusalWords(r)        { title, why, fix } for one transport's verdict
 *   REALITY_TEST_ADVICE           the test card's line under every REALITY link
 */
import {
  ADMITTING_MIN_CLIENT_VER,
  REALITY_CLIENT_VERSIONS,
  XRAY_DEFAULT_MIN_CLIENT_VER,
  XRAY_DEFAULT_MIN_LAST,
  XRAY_DEFAULT_MIN_SINCE,
  type RealityClientFamily,
  type RealityClientRefusal,
} from '../../shared/contracts/realityClients';

export const REALITY_FAMILY_WORDS: Record<RealityClientFamily, string> = {
  singbox: 'sing-box (Hiddify, Karing)',
  mihomo: 'Mihomo (Clash Verge, FlClash)',
};

const FAMILY_NAMES: Record<RealityClientFamily, string> = { singbox: 'sing-box', mihomo: 'Mihomo' };

function list(items: string[]): string {
  return items.length <= 1
    ? (items[0] ?? '')
    : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

/** What the refused families send, in words ("sing-box sends 1.8.1"). */
function sends(r: RealityClientRefusal): string {
  return list(r.refuses.map((f) => `${FAMILY_NAMES[f]} sends ${REALITY_CLIENT_VERSIONS[f]}`));
}

/** One transport's verdict in words; no em-dashes, the setting named as it is written. */
export function realityRefusalWords(r: RealityClientRefusal): {
  title: string;
  why: string;
  fix: string;
} {
  const families = list(r.refuses.map((f) => REALITY_FAMILY_WORDS[f]));
  const addMin = `Add "minClientVer": "${ADMITTING_MIN_CLIENT_VER}" to the transport's realitySettings in the backend (FCP's own template sets it).`;
  switch (r.cause) {
    case 'core_default':
      return {
        title: `Refuses ${families} clients`,
        why: `It sets no minClientVer, and Xray ${r.xrayVersion ?? ''} then lets in only Xray clients from ${XRAY_DEFAULT_MIN_CLIENT_VER} on. A test with an Xray client passes while members on these clients cannot connect.`,
        fix: addMin,
      };
    case 'core_unknown':
      return {
        title: `May refuse ${families} clients`,
        why: `It sets no minClientVer, and FCP could not read the node's Xray version. From Xray ${XRAY_DEFAULT_MIN_SINCE} to ${XRAY_DEFAULT_MIN_LAST}, such a transport lets in only Xray clients from ${XRAY_DEFAULT_MIN_CLIENT_VER} on.`,
        fix: addMin,
      };
    case 'min_above':
      return {
        title: `Refuses ${families} clients`,
        why: `Its minClientVer is ${r.minClientVer ?? ''}, above what they send (${sends(r)}).`,
        fix: `Set "minClientVer" to "${ADMITTING_MIN_CLIENT_VER}" in the transport's realitySettings in the backend.`,
      };
    case 'max_below':
      return {
        title: `Refuses ${families} clients`,
        why: `Its maxClientVer is ${r.maxClientVer ?? ''}, below what they send (${sends(r)}).`,
        fix: `Remove "maxClientVer" from the transport's realitySettings in the backend, or raise it to ${REALITY_CLIENT_VERSIONS.mihomo} or above.`,
      };
  }
}

/** Under every REALITY test link: an Xray client can connect where the others cannot. */
export const REALITY_TEST_ADVICE =
  'Try it with a sing-box or Mihomo client too (Hiddify, Karing, Clash Verge): a REALITY transport can let in Xray clients only.';
