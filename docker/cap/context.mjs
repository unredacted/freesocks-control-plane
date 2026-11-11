// Installed as src/events/context.js in the pinned image. The public proxy's
// socket address remains the shared rate-limit bucket; forwarding and geo
// headers are never consulted, even if a dashboard setting changes.
import { socketIp } from '#platform';
import { unmapIpv4 } from '../policy/address.js';

export function getClientIp(request, server) {
  const peer = socketIp(request, server);
  return peer ? unmapIpv4(peer) : null;
}

// Kept for the event store's import interface. recordEvent is disabled.
export const setVisitorSalt = () => {};
export const maskIp = () => '';

export async function requestContext(request, server) {
  return {
    ip: getClientIp(request, server) || '',
    // UA and headers are used only in memory by protection rules and signed
    // agent verification. Do not derive visitor fingerprints from them.
    ua: request.headers.get('user-agent') || '',
    headers: request.headers,
    fp: '',
    country: '',
    asn: 0,
    asn_org: '',
    origin: '',
    lang: '',
    platform: '',
    os: '',
    browser: '',
  };
}
