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
  XRAY_KEY_SHARE_SINCE,
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

/** "what sing-box sends (1.8.1)", "what sing-box and Mihomo send (1.8.1 and 1.8.2)". */
function whatTheySend(families: readonly RealityClientFamily[]): string {
  const names = list(families.map((f) => FAMILY_NAMES[f]));
  const versions = list(families.map((f) => REALITY_CLIENT_VERSIONS[f]));
  return `what ${names} ${families.length === 1 ? 'sends' : 'send'} (${versions})`;
}

const ADD_MIN = `Add "minClientVer": "${ADMITTING_MIN_CLIENT_VER}" to the transport's realitySettings in the backend (FCP's own template sets it).`;

/** One reason in words: why, and the change that lifts it. */
function reasonWords(
  reason: RealityClientRefusal['reasons'][number],
  r: RealityClientRefusal,
): { why: string; fix: string } {
  switch (reason.cause) {
    case 'min_above':
      return {
        why: `Its minClientVer is ${r.minClientVer ?? ''}, above ${whatTheySend(reason.families)}.`,
        fix: `Set "minClientVer" to "${ADMITTING_MIN_CLIENT_VER}" in the transport's realitySettings in the backend.`,
      };
    case 'core_default':
      return {
        why: `It sets no minClientVer, and Xray ${r.xrayVersion ?? ''} then lets in only Xray clients from ${XRAY_DEFAULT_MIN_CLIENT_VER} on.`,
        fix: ADD_MIN,
      };
    case 'max_below':
      return {
        why: `Its maxClientVer is ${r.maxClientVer ?? ''}, below ${whatTheySend(reason.families)}.`,
        fix: `Remove "maxClientVer" from the transport's realitySettings in the backend, or raise it to ${REALITY_CLIENT_VERSIONS.mihomo} or above.`,
      };
    case 'core_key_share':
      return {
        why: `From Xray ${XRAY_KEY_SHARE_SINCE} on (this node runs ${r.xrayVersion ?? ''}), a REALITY server refuses a Client Hello without an X25519MLKEM768 key share, and sing-box sends none, whatever the transport sets.`,
        fix: `No setting of the transport lets sing-box in on this Xray: run the node on Xray ${XRAY_DEFAULT_MIN_LAST} or earlier with "minClientVer": "${ADMITTING_MIN_CLIENT_VER}", or give sing-box members another node.`,
      };
    case 'core_unknown':
      return r.minClientVer === null
        ? {
            why: `It sets no minClientVer, and FCP could not read the node's Xray version: Xray ${XRAY_DEFAULT_MIN_SINCE} to ${XRAY_DEFAULT_MIN_LAST} then let in only Xray clients from ${XRAY_DEFAULT_MIN_CLIENT_VER} on, and from ${XRAY_KEY_SHARE_SINCE} on no setting lets sing-box in.`,
            fix: `${ADD_MIN} Then check the node's Xray version: sing-box cannot connect to ${XRAY_KEY_SHARE_SINCE} or later.`,
          }
        : {
            why: `FCP could not read the node's Xray version: from Xray ${XRAY_KEY_SHARE_SINCE} on, no setting of the transport lets sing-box in.`,
            fix: `Check the node's Xray version in the backend: sing-box cannot connect to ${XRAY_KEY_SHARE_SINCE} or later.`,
          };
  }
}

/**
 * One transport's verdict in words, no em-dashes, each setting named as it is
 * written: the families (from every reason), why each reason holds, and the
 * fixes once each. "May refuse" only when FCP is sure of no reason (the
 * node's version is unknown).
 */
export function realityRefusalWords(r: RealityClientRefusal): {
  title: string;
  why: string;
  fix: string;
} {
  const families = list(r.refuses.map((f) => REALITY_FAMILY_WORDS[f]));
  const sure = r.reasons.some((x) => x.cause !== 'core_unknown');
  const parts = r.reasons.map((x) => reasonWords(x, r));
  return {
    title: `${sure ? 'Refuses' : 'May refuse'} ${families} clients`,
    why: `${parts.map((p) => p.why).join(' ')} A test with an Xray client passes while members on these clients cannot connect.`,
    fix: [...new Set(parts.map((p) => p.fix))].join(' '),
  };
}

/** Under every REALITY test link: an Xray client can connect where the others cannot. */
export const REALITY_TEST_ADVICE =
  'Try it with a sing-box or Mihomo client too (Hiddify, Karing, Clash Verge): a REALITY transport can let in Xray clients only.';
