// The egress target of the front-qualification integration test: a 204 and
// nothing else, reachable only from the Xray container on the compat network.
// The real check fetches a neutral /generate_204; this stands in for it so CI
// proves the tunnel end to end without depending on the public internet.
import { createServer } from 'node:http';

createServer((req, res) => {
  if (req.url === '/generate_204') {
    res.writeHead(204).end();
    return;
  }
  res.writeHead(200, { 'content-type': 'text/plain' }).end('frontcheck-origin\n');
}).listen(8080, '0.0.0.0');
