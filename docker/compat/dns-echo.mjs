// The Hysteria engines test (convex/lib/hysteriaEngines.integration.test.ts):
// a UDP DNS echo behind the servers only, the far end of the datagram round
// trip scripts/compat/probe.py sends through each engine. It answers a valid
// single-question query with an A record 192.0.2.42, as docker/compat/origin.mjs
// does for the subscription suite.
import { createSocket } from 'node:dgram';
const dns = createSocket('udp4');
dns.on('message', (query, peer) => {
  if (query.length < 17 || query.readUInt16BE(4) !== 1) return;
  const answer = Buffer.concat([query, Buffer.from('c00c000100010000003c0004c000022a', 'hex')]);
  answer.writeUInt16BE(0x8180, 2);
  answer.writeUInt16BE(1, 6);
  dns.send(answer, peer.port, peer.address);
});
dns.bind(5353, '0.0.0.0');
