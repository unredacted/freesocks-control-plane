/**
 * OVHcloud API request signing (the `$1$` scheme):
 *   X-Ovh-Signature = "$1$" + SHA1_HEX(AS + "+" + CK + "+" + METHOD + "+" + URL + "+" + BODY + "+" + TIMESTAMP)
 * with the timestamp corrected by the server clock (`GET /auth/time`). Pure and
 * WebCrypto-only, so it runs in the Node action runtime and in tests.
 */

export const OVH_ENDPOINTS = {
  'ovh-eu': 'https://eu.api.ovh.com/1.0',
  'ovh-ca': 'https://ca.api.ovh.com/1.0',
  'ovh-us': 'https://api.us.ovhcloud.com/1.0',
} as const;
export type OvhEndpoint = keyof typeof OVH_ENDPOINTS;

function hex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function sha1Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(input));
  return hex(digest);
}

export interface OvhSignInput {
  applicationSecret: string;
  consumerKey: string;
  method: string;
  /** The FULL request URL (scheme + host + path + query). */
  url: string;
  /** The exact body string sent ('' for GET/DELETE). */
  body: string;
  /** Unix seconds, already skew-corrected. */
  timestamp: number;
}

export async function ovhSignature(a: OvhSignInput): Promise<string> {
  const toSign = [
    a.applicationSecret,
    a.consumerKey,
    a.method.toUpperCase(),
    a.url,
    a.body,
    String(a.timestamp),
  ].join('+');
  return `$1$${await sha1Hex(toSign)}`;
}

export interface OvhSignedHeadersInput extends Omit<OvhSignInput, 'timestamp'> {
  applicationKey: string;
  /** Server-time delta in seconds (server - local). */
  skewSeconds: number;
  nowMs?: number;
}

export async function ovhSignedHeaders(a: OvhSignedHeadersInput): Promise<Record<string, string>> {
  const timestamp = Math.floor((a.nowMs ?? Date.now()) / 1000) + Math.round(a.skewSeconds);
  return {
    'x-ovh-application': a.applicationKey,
    'x-ovh-consumer': a.consumerKey,
    'x-ovh-timestamp': String(timestamp),
    'x-ovh-signature': await ovhSignature({
      applicationSecret: a.applicationSecret,
      consumerKey: a.consumerKey,
      method: a.method,
      url: a.url,
      body: a.body,
      timestamp,
    }),
  };
}
