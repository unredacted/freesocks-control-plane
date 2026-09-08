// A test-owned HTTPS and DNS endpoint, reachable only from the proxy container.
import { createServer } from 'node:https';
import { readFileSync } from 'node:fs';
import { createSocket } from 'node:dgram';
const tls = { key: readFileSync('/work/key.pem'), cert: readFileSync('/work/cert.pem') };
createServer(tls, (req, res) => {
  res.setHeader('content-type', 'application/json');
  res.end(
    JSON.stringify({
      nonce: req.url.slice(1),
      peer: req.socket.remoteAddress,
      via: 'isolated-origin',
    }),
  );
}).listen(8443, '0.0.0.0');
const dns = createSocket('udp4');
dns.on('message', (query, peer) => {
  // Echo a valid single-question DNS query with an A answer 192.0.2.42.
  if (query.length < 17 || query.readUInt16BE(4) !== 1) return;
  const answer = Buffer.concat([query, Buffer.from('c00c000100010000003c0004c000022a', 'hex')]);
  answer.writeUInt16BE(0x8180, 2);
  answer.writeUInt16BE(1, 6);
  dns.send(answer, peer.port, peer.address);
});
dns.bind(5353, '0.0.0.0');
