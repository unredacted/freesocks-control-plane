/**
 * The client network's resolver in the edge connection test: every name under
 * the fake L7 provider's zone (`EC_DNS_ZONE`) resolves to the fake front
 * (`EC_DNS_ANSWER`), as a CDN's DNS answers for every hostname it serves.
 * FCP mints an L7 edge's hostname from the edge's provider-side name, so it is
 * not known before provisioning and a static host entry cannot carry it.
 *
 * Anything else is NXDOMAIN: the client network resolves nothing but the
 * fronts, so a client that tried an origin name would fail visibly.
 */
import { createSocket } from 'node:dgram';

const zone = (process.env.EC_DNS_ZONE ?? '').toLowerCase().replace(/\.$/, '');
const answer = (process.env.EC_DNS_ANSWER ?? '').split('.').map(Number);
if (!zone || answer.length !== 4 || answer.some((o) => !Number.isInteger(o) || o < 0 || o > 255))
  throw new Error('EC_DNS_ZONE and EC_DNS_ANSWER are required');

/** The question's name and the offset just past QTYPE/QCLASS, or null for anything unusual. */
function question(q: Buffer): { name: string; type: number; end: number } | null {
  if (q.length < 17 || q.readUInt16BE(4) !== 1) return null;
  const labels: string[] = [];
  let i = 12;
  while (i < q.length) {
    const len = q[i]!;
    if (len === 0) break;
    if (len > 63 || i + 1 + len > q.length) return null;
    labels.push(q.subarray(i + 1, i + 1 + len).toString('ascii'));
    i += 1 + len;
  }
  if (i + 5 > q.length) return null;
  return { name: labels.join('.').toLowerCase(), type: q.readUInt16BE(i + 1), end: i + 5 };
}

const socket = createSocket('udp4');
socket.on('message', (query, peer) => {
  const q = question(query);
  if (!q) return;
  const head = Buffer.from(query.subarray(0, q.end));
  const inZone = q.name === zone || q.name.endsWith(`.${zone}`);
  // Response, recursion available, the client's RD bit kept; NXDOMAIN outside the zone.
  head.writeUInt16BE(0x8180 | (query.readUInt16BE(2) & 0x0100) | (inZone ? 0 : 3), 2);
  head.writeUInt16BE(0, 8); // NSCOUNT
  head.writeUInt16BE(0, 10); // ARCOUNT (any EDNS record of the query is dropped)
  if (inZone && q.type === 1) {
    head.writeUInt16BE(1, 6);
    // Name pointer to the question, A, IN, TTL 30, 4 bytes of address.
    const rr = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, ...answer]);
    socket.send(Buffer.concat([head, rr]), peer.port, peer.address);
    return;
  }
  // AAAA (and every other type) in the zone: NOERROR with no answer.
  head.writeUInt16BE(0, 6);
  socket.send(head, peer.port, peer.address);
});
socket.bind(53, '0.0.0.0');
