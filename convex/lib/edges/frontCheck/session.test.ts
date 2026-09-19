// @vitest-environment node
/**
 * The whole front-qualification session against local servers.
 *
 * Each server plays one role the real chain can play: a node that proxies
 * properly, a node that refuses the credential, a target that answers something
 * other than 204, and a front that answers for itself. The assertions are on the
 * failure CODE, because that code is what an operator acts on: it has to say
 * whether the front, the credential or the egress is at fault.
 *
 * These servers are written to the specifications, not to our decoder: the
 * WebSocket side computes its own accept key and frames its own replies
 * unmasked. A pinned Xray-core then proves the same session against the real
 * software in frontCheck.integration.test.ts.
 */
import { afterEach, describe, expect, test } from 'vitest';
import { createServer as createTlsServer, type TLSSocket } from 'node:tls';
import {
  createSecureServer,
  type Http2Server,
  type IncomingHttpHeaders,
  type ServerHttp2Stream,
} from 'node:http2';
import { createHash } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:net';
import { qualifyFront, type FrontCheckResult } from './index';
import type { ListenerProto } from '../protocols';
import { createWsDecoder, WS_GUID, WS_OPCODE } from './ws';
import { createGrpcDecoder, decodeHunk, encodeHunkFrame } from './grpc';

const UUID = '01234567-89ab-cdef-0123-456789abcdef';
/** The VLESS listener behind the front, per HTTP stream transport. */
const VLESS = (stream: 'ws' | 'httpupgrade' | 'grpc' | 'xhttp'): ListenerProto => ({
  protocol: 'vless',
  streamTransport: stream,
  security: 'tls',
});
const OTHER_UUID = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
const HOSTNAME = 'front.test';
const SERVICE = 'relay-svc';

/**
 * A throwaway self-signed certificate for 127.0.0.1 loopback servers, valid for
 * `front.test` only. It is not a secret and never leaves this file: the tests
 * pass it as an explicit trust anchor through `deps.dial.ca`, exactly where
 * production passes nothing and uses the system CA store.
 */
const KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDFuTO2IDolkL8r
ZZ+OWkfj/rWRwDc0ehpdWAdr2JPlxLtlGNk2cyTm6etGuauyXzgtBW/1ebYYQPgF
5L/ifZfcyYcdyRc94JCqvd2xC9I19YI/gEOb6VrgCwDU+6EKrt6ZkNDAo5CZVreC
rAR5wpZHWFV9LXgdoAoDbQLoP61X2lIlDa3jWKo3LUoz8iBoEDcDp31IG7sS1S48
BuPO3lR19rlLkU1BK78Ra1WQ+hPTwNh7gX3sf+WUhcAYUaEnA9FlXQL5Z58IwPSg
mffIhbTtLhJpum/A1CjIEQ6C2dNxAw4au5Rrbpwin0uun4CO5X3v0Cbgf4Kn+1fJ
6Hpd8UutAgMBAAECggEAAWcThcCmRkhygWYOkvWzKgakoUSmD5uoeWOLupk2JAyN
0MUzm0YyAOewE9fILvMrz0Pz2/UG/0E3Zov4IYJHFBmjjqjzyYGrkmPXlq8xCKbL
IP9cW2w1HmmYPKqOpVMBa2uifiSwPKo9Ed1TCHhtKlM8g1oRzqdT6DDQiGG/7Xjb
kX47/JLB7gGDBMOnPh50bnCy9rh8aRCaUt/JV1ac4u995hzJqUK1fdNBcnmtolze
M0rk6nRGI+Uw6l04VtoCHsjB3hgdA1T6O+zOqYN6bgCTMq68YqK5k88HSVGFJq16
OsDPsHyKtDKxpgmwofInlCD0F2chacodsfY09DAUEQKBgQDu/QnyVOwcx4rdJCOp
Elnb3/B4iXx32j9QuU6M6+2Z6jwWFEGekCJKkogIvhxOTkWNw7tTS6d9JzHM60pl
pzhNHYkRvNnyCZTvZZvlECujExD0mHqXQet/LYExOLY7uZpvH5hZbc6PzJAjPSXK
gzA+DcAZye6gWyLNFG/SEi0//QKBgQDTzDZ+fursAB3wSEosBeYkUTVOBgDKa47Q
chgrUUbHjQj3Cfbs10kwqCQry8bQX7dGxmfY2btPU2c8DxTi5ijdddPb1+9mi6Kl
bXHXoBeoUvnPtvJxpLRTmB4bC5CW61O/eq3iftn9VkDMufkW7cUFXA6NpijqPJYD
2hjBaG1RcQKBgBBCoSmew43VucoACnkXaYu/OdJJsHFLJSGt6f1GlBzzxfDOogRS
1DJ0s9K8dJqTUsIpfhZVwGiQgR/rJl2yOe9tQgU17zI7mqmLJUc5iW6H/pBVy4l9
D7PQecjKjgOURkCnSqtTAEniZjAvmeGkeWTPdLGMfrLkYILJkC4f1HpVAoGBAMbb
nWrFhZMSRQnfBe0xmLUOnmrkjgeAV3X1OiYpyLgB/qHcdEBJnomVxWhtiv0IcY99
J/Hd9NV1LJ+iVWz4xvOv9rwakceJYavLB7F5udysE6toTVhQWZOHZvTjtd1NlLNa
3zqi+c+4FV1jW7Ggi3UNywhKM25CdmOlecrWXpWxAoGBAMjgWosyQ6RdIIVkderj
HygSVOmxjP3VifJEmysfNKQH7MD0ntk+cq/mfS5BRm5L0+fHQw91MDySKItZlD/j
S9f9f1EWuJ0QtvXZkmln/4FxN57ldXKvB2/1zhfFaHsNRepQzdkhBcKIX4hn3d0J
7nn46PmPMx000pbBXLDc/VWG
-----END PRIVATE KEY-----
`;
const CERT = `-----BEGIN CERTIFICATE-----
MIIDIjCCAgqgAwIBAgIUWDclUFmmQduKJWq/P/GBAF5OXVgwDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKZnJvbnQudGVzdDAeFw0yNjA5MTYyMjU0NTFaFw00NjA5
MTEyMjU0NTFaMBUxEzARBgNVBAMMCmZyb250LnRlc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDFuTO2IDolkL8rZZ+OWkfj/rWRwDc0ehpdWAdr2JPl
xLtlGNk2cyTm6etGuauyXzgtBW/1ebYYQPgF5L/ifZfcyYcdyRc94JCqvd2xC9I1
9YI/gEOb6VrgCwDU+6EKrt6ZkNDAo5CZVreCrAR5wpZHWFV9LXgdoAoDbQLoP61X
2lIlDa3jWKo3LUoz8iBoEDcDp31IG7sS1S48BuPO3lR19rlLkU1BK78Ra1WQ+hPT
wNh7gX3sf+WUhcAYUaEnA9FlXQL5Z58IwPSgmffIhbTtLhJpum/A1CjIEQ6C2dNx
Aw4au5Rrbpwin0uun4CO5X3v0Cbgf4Kn+1fJ6Hpd8UutAgMBAAGjajBoMB0GA1Ud
DgQWBBRZMLgL1MlSxCxSsTfHLSlLjoENlDAfBgNVHSMEGDAWgBRZMLgL1MlSxCxS
sTfHLSlLjoENlDAPBgNVHRMBAf8EBTADAQH/MBUGA1UdEQQOMAyCCmZyb250LnRl
c3QwDQYJKoZIhvcNAQELBQADggEBAGxS/jq6ns78UqrPqTPoF4qCTF7dmJDLHcdz
lpvUnSBqqRD68wmC71saNw3TAYeOYvyun+mhijXpljISPzTEklzfb+PiOmSHdtDX
tzg7QniMHgyNJzFxv/UZsInJgos74gVCJrQQfxp1B58csTsXQK4WTfz1lFhh3b2A
Xon7DCMH18ioQ+T9N5m16IKSUmOSN9V59EW/Daxz+QYnlHdR94RswaxjzCkOiNiW
QSwbnsfDrrZHC+m/5wByPTmVaLD8UEp1rXza68iiFihMJ1mB6mwJbiHRdVLvDEh0
moSW2vRmP6rSvhjezfEq8IIibRG6fT6j+2IqaHPqQgW6s1Wl3Zk=
-----END CERTIFICATE-----
`;

// --- the fake node ---------------------------------------------------------

/** What the inbound at the far end of the tunnel does with our VLESS request. */
type NodeRole = 'proxy204' | 'proxy200' | 'reject' | 'silent' | 'garbage';

interface NodeAction {
  reply?: Uint8Array;
  close?: boolean;
}

const enc = (s: string) => new TextEncoder().encode(s);

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function handleVless(role: NodeRole, request: Uint8Array): NodeAction {
  // version(1) uuid(16) addonsLen(1) cmd(1) port(2) atyp(1) len(1) domain...
  if (request.length < 23) return {};
  if (request[0] !== 0x00) return { close: true };
  const uuid = Buffer.from(request.subarray(1, 17)).toString('hex');
  if (uuid !== UUID.replace(/-/g, '')) return { close: true };
  if (role === 'reject') return { close: true };
  if (role === 'silent') return {};
  if (role === 'garbage') return { reply: enc('<html>denied</html>') };
  const status = role === 'proxy200' ? 'HTTP/1.1 200 OK' : 'HTTP/1.1 204 No Content';
  return {
    reply: concat([new Uint8Array([0x00, 0x00]), enc(`${status}\r\nConnection: close\r\n\r\n`)]),
  };
}

// --- raw (ws / httpupgrade) servers ----------------------------------------

type HandshakeRole = 'ok' | 'bad-accept' | 'forbidden' | 'hang' | 'wrong-token';

interface RawServerOpts {
  transport: 'ws' | 'httpupgrade';
  node: NodeRole;
  handshake?: HandshakeRole;
  token?: string;
}

/** Unmasked server frame (RFC 6455 §5.1: the server must not mask). */
function serverFrame(opcode: number, payload: Uint8Array): Uint8Array {
  const len = payload.length;
  const extra = len < 126 ? 0 : 2;
  const out = new Uint8Array(2 + extra + len);
  out[0] = 0x80 | opcode;
  if (extra === 0) out[1] = len;
  else {
    out[1] = 126;
    out[2] = (len >> 8) & 0xff;
    out[3] = len & 0xff;
  }
  out.set(payload, 2 + extra);
  return out;
}

function parseRequestHead(text: string): { line: string; headers: Record<string, string> } {
  const [line, ...rest] = text.split('\r\n');
  const headers: Record<string, string> = {};
  for (const h of rest) {
    const i = h.indexOf(':');
    if (i > 0) headers[h.slice(0, i).trim().toLowerCase()] = h.slice(i + 1).trim();
  }
  return { line, headers };
}

interface Running {
  port: number;
  close: () => Promise<void>;
}

async function listen(server: Server | Http2Server): Promise<Running> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    port,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}

function startRawServer(opts: RawServerOpts): Promise<Running> {
  const handshake = opts.handshake ?? 'ok';
  const token = opts.token ?? 'websocket';
  const server = createTlsServer({ key: KEY, cert: CERT }, (socket: TLSSocket) => {
    let head = Buffer.alloc(0);
    let upgraded = false;
    let tunnel: Uint8Array = new Uint8Array(0);
    const decoder = createWsDecoder();

    const answerNode = (bytes: Uint8Array, wrap: (b: Uint8Array) => Uint8Array) => {
      tunnel = concat([tunnel, bytes]);
      const action = handleVless(opts.node, tunnel);
      if (action.close) {
        socket.destroy();
        return;
      }
      if (action.reply) {
        tunnel = new Uint8Array(0);
        socket.write(Buffer.from(wrap(action.reply)));
      }
    };

    const onTunnelBytes = (chunk: Uint8Array) => {
      if (opts.transport === 'httpupgrade') {
        answerNode(chunk, (b) => b);
        return;
      }
      for (const ev of decoder.push(chunk)) {
        if (ev.type === 'message') answerNode(ev.data, (b) => serverFrame(WS_OPCODE.binary, b));
        else if (ev.type === 'close') {
          socket.write(Buffer.from(serverFrame(WS_OPCODE.close, new Uint8Array([0x03, 0xe8]))));
          socket.end();
        }
      }
    };

    socket.on('error', () => {});
    socket.on('data', (d: Buffer) => {
      if (upgraded) {
        onTunnelBytes(new Uint8Array(d));
        return;
      }
      head = Buffer.concat([head, d]);
      const end = head.indexOf('\r\n\r\n');
      if (end < 0) return;
      const req = parseRequestHead(head.subarray(0, end).toString('latin1'));
      const rest = new Uint8Array(head.subarray(end + 4));
      head = Buffer.alloc(0);

      if (handshake === 'hang') return;
      if (handshake === 'forbidden') {
        socket.write(
          'HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\ncf-ray: 000\r\nContent-Length: 0\r\n\r\n',
        );
        return;
      }
      if (opts.transport === 'ws') {
        const key = req.headers['sec-websocket-key'] ?? '';
        const accept =
          handshake === 'bad-accept'
            ? 'AAAAAAAAAAAAAAAAAAAAAAAAAAA='
            : createHash('sha1').update(`${key}${WS_GUID}`).digest('base64');
        socket.write(
          'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
            `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
        );
      } else {
        const echoed = handshake === 'wrong-token' ? 'something-else' : token;
        socket.write(
          `HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: ${echoed}\r\n\r\n`,
        );
      }
      upgraded = true;
      if (rest.length > 0) onTunnelBytes(rest);
    });
  });
  server.on('error', () => {});
  return listen(server);
}

// --- gRPC server -----------------------------------------------------------

type GrpcRole = 'ok' | 'unimplemented' | 'forbidden' | 'not-grpc';

function startGrpcServer(opts: { grpc: GrpcRole; node: NodeRole }): Promise<Running> {
  const server = createSecureServer({ key: KEY, cert: CERT, ALPNProtocols: ['h2'] });
  server.on('error', () => {});
  server.on('stream', (stream: ServerHttp2Stream, headers: IncomingHttpHeaders) => {
    stream.on('error', () => {});
    if (opts.grpc === 'forbidden') {
      stream.respond({ ':status': 403, server: 'cloudflare' }, { endStream: true });
      return;
    }
    if (opts.grpc === 'unimplemented') {
      // Trailers-only: what a front that does not carry gRPC returns.
      stream.respond(
        { ':status': 200, 'content-type': 'application/grpc', 'grpc-status': '12' },
        { endStream: true },
      );
      return;
    }
    if (opts.grpc === 'not-grpc') {
      stream.respond({ ':status': 200, 'content-type': 'text/html' });
      stream.end('<html>error</html>');
      return;
    }
    if (headers[':path'] !== `/${SERVICE}/Tun`) {
      stream.respond({ ':status': 404 }, { endStream: true });
      return;
    }
    stream.respond({ ':status': 200, 'content-type': 'application/grpc' });
    const decoder = createGrpcDecoder();
    let tunnel: Uint8Array = new Uint8Array(0);
    stream.on('data', (d: Buffer) => {
      for (const message of decoder.push(new Uint8Array(d))) {
        tunnel = concat([tunnel, decodeHunk(message)]);
        const action = handleVless(opts.node, tunnel);
        if (action.close) {
          stream.close();
          return;
        }
        if (action.reply) {
          tunnel = new Uint8Array(0);
          stream.write(Buffer.from(encodeHunkFrame(action.reply)));
        }
      }
    });
    stream.on('end', () => stream.end());
  });
  return listen(server);
}

// --- XHTTP (packet-up) server -----------------------------------------------

type XhttpRole = 'ok' | 'forbidden' | 'html';

/**
 * Xray's packet-up server in miniature: `GET /relay/<session>` is the
 * downstream, `POST /relay/<session>/<seq>` the uploads. Like the real server
 * it refuses a request whose `Referer` carries no `x_padding` of 100 to 1000
 * bytes, which is the rule the checker was first caught breaking.
 */
function startXhttpServer(opts: { xhttp: XhttpRole; node: NodeRole }): Promise<Running> {
  const server = createSecureServer({ key: KEY, cert: CERT, ALPNProtocols: ['h2'] });
  server.on('error', () => {});
  const downs = new Map<string, ServerHttp2Stream>();
  server.on('stream', (stream: ServerHttp2Stream, headers: IncomingHttpHeaders) => {
    stream.on('error', () => {});
    if (opts.xhttp === 'forbidden') {
      stream.respond({ ':status': 403, server: 'cloudflare' }, { endStream: true });
      return;
    }
    const padding = new URL(String(headers.referer ?? 'https://x/')).searchParams.get('x_padding');
    if (!padding || padding.length < 100 || padding.length > 1000) {
      stream.respond({ ':status': 400 }, { endStream: true });
      return;
    }
    const parts = String(headers[':path']).split('/').filter(Boolean);
    if (parts[0] !== 'relay' || !parts[1]) {
      stream.respond({ ':status': 404 }, { endStream: true });
      return;
    }
    const session = parts[1];
    if (headers[':method'] === 'GET') {
      if (opts.xhttp === 'html') {
        stream.respond({ ':status': 200, 'content-type': 'text/html' });
        stream.end('<html>front</html>');
        return;
      }
      stream.respond({ ':status': 200, 'content-type': 'text/event-stream' });
      downs.set(session, stream);
      return;
    }
    const chunks: Buffer[] = [];
    stream.on('data', (d: Buffer) => chunks.push(d));
    stream.on('end', () => {
      stream.respond({ ':status': 200 }, { endStream: true });
      const down = downs.get(session);
      if (!down) return;
      const action = handleVless(opts.node, new Uint8Array(Buffer.concat(chunks)));
      if (action.close) down.close();
      else if (action.reply) down.write(Buffer.from(action.reply));
    });
  });
  return listen(server);
}

// --- the checks ------------------------------------------------------------

const running: Running[] = [];
afterEach(async () => {
  while (running.length > 0) await running.pop()!.close();
});

async function track(p: Promise<Running>): Promise<Running> {
  const r = await p;
  running.push(r);
  return r;
}

function run(
  port: number,
  stream: 'ws' | 'httpupgrade' | 'grpc' | 'xhttp',
  overrides: { uuid?: string; trust?: boolean; stepTimeoutMs?: number; mode?: string } = {},
): Promise<FrontCheckResult> {
  return qualifyFront(
    {
      hostname: HOSTNAME,
      proto: VLESS(stream),
      params: {
        path: '/relay',
        serviceName: SERVICE,
        upgradeToken: 'websocket',
        ...(overrides.mode ? { mode: overrides.mode } : {}),
      },
      uuid: overrides.uuid ?? UUID,
      stepTimeoutMs: overrides.stepTimeoutMs ?? 2_000,
    },
    {
      dial: {
        host: '127.0.0.1',
        port,
        ...(overrides.trust === false ? {} : { ca: CERT }),
      },
    },
  );
}

/** No result may name the front, the credential or anything the peer returned. */
function expectNoSecrets(result: FrontCheckResult): void {
  const blob = JSON.stringify(result);
  expect(blob).not.toContain(HOSTNAME);
  expect(blob).not.toContain(UUID);
  expect(blob).not.toContain('html');
  expect(blob).not.toContain(SERVICE);
}

describe('a working chain', () => {
  test('websocket: transport, authentication and a 204 out of the tunnel', async () => {
    const s = await track(startRawServer({ transport: 'ws', node: 'proxy204' }));
    const result = await run(s.port, 'ws');
    expect(result.ok).toBe(true);
    expect(result.code).toBeUndefined();
    expect(result.steps.map((x) => x.step)).toEqual(['tls', 'transport', 'vless', 'close']);
    expect(result.steps.every((x) => x.ok)).toBe(true);
    expectNoSecrets(result);
  });

  test('httpupgrade: same session over a bare Upgrade', async () => {
    const s = await track(startRawServer({ transport: 'httpupgrade', node: 'proxy204' }));
    const result = await run(s.port, 'httpupgrade');
    expect(result.ok).toBe(true);
    expect(result.steps).toHaveLength(4);
  });

  test('grpc: same session over HTTP/2 Hunk messages', async () => {
    const s = await track(startGrpcServer({ grpc: 'ok', node: 'proxy204' }));
    const result = await run(s.port, 'grpc');
    expect(result).toMatchObject({ ok: true });
    expectNoSecrets(result);
  });
});

describe('xhttp (packet-up)', () => {
  test('the same session over a GET stream and a sequenced POST', async () => {
    const s = await track(startXhttpServer({ xhttp: 'ok', node: 'proxy204' }));
    const result = await run(s.port, 'xhttp');
    expect(result.code).toBeUndefined();
    expect(result.ok).toBe(true);
    expect(result.steps.map((x) => x.step)).toEqual(['tls', 'transport', 'vless', 'close']);
    expectNoSecrets(result);
  });

  test('a front that answers the requests itself is front_error with its status', async () => {
    const s = await track(startXhttpServer({ xhttp: 'forbidden', node: 'proxy204' }));
    expect(await run(s.port, 'xhttp')).toMatchObject({
      ok: false,
      code: 'front_error',
      detail: '403',
    });
  });

  test('a 200 that is a web page is the front answering for itself', async () => {
    const s = await track(startXhttpServer({ xhttp: 'html', node: 'proxy204' }));
    expect(await run(s.port, 'xhttp')).toMatchObject({
      ok: false,
      code: 'front_error',
      detail: '200',
    });
  });

  test('a rejected credential closes the downstream: auth_failed', async () => {
    const s = await track(startXhttpServer({ xhttp: 'ok', node: 'reject' }));
    expect(await run(s.port, 'xhttp')).toMatchObject({ ok: false, code: 'auth_failed' });
  });

  test('a stream-only inbound is refused before any request is made', async () => {
    const s = await track(startXhttpServer({ xhttp: 'ok', node: 'proxy204' }));
    expect(await run(s.port, 'xhttp', { mode: 'stream-one' })).toMatchObject({
      ok: false,
      code: 'transport_failed',
      detail: 'mode',
    });
  });
});

describe('the front answers instead of the node', () => {
  test('403 with the front own headers is front_error with the status', async () => {
    const s = await track(
      startRawServer({ transport: 'ws', node: 'proxy204', handshake: 'forbidden' }),
    );
    const result = await run(s.port, 'ws');
    expect(result).toMatchObject({ ok: false, code: 'front_error', detail: '403' });
    expectNoSecrets(result);
  });

  test('gRPC trailers without a tunnel carry the status into the code', async () => {
    const s = await track(startGrpcServer({ grpc: 'unimplemented', node: 'proxy204' }));
    const result = await run(s.port, 'grpc');
    expect(result).toMatchObject({ ok: false, code: 'grpc_12' });
  });

  test('a non-gRPC 200 is the front answering for itself', async () => {
    const s = await track(startGrpcServer({ grpc: 'not-grpc', node: 'proxy204' }));
    const result = await run(s.port, 'grpc');
    expect(result).toMatchObject({ ok: false, code: 'front_error', detail: '200' });
    expectNoSecrets(result);
  });

  test('an HTTP/2 403 is reported with its status', async () => {
    const s = await track(startGrpcServer({ grpc: 'forbidden', node: 'proxy204' }));
    const result = await run(s.port, 'grpc');
    expect(result).toMatchObject({ ok: false, code: 'front_error', detail: '403' });
  });
});

describe('the transport is broken even though the status says 101', () => {
  test('a wrong Sec-WebSocket-Accept fails the transport, not the front', async () => {
    const s = await track(
      startRawServer({ transport: 'ws', node: 'proxy204', handshake: 'bad-accept' }),
    );
    const result = await run(s.port, 'ws');
    expect(result).toMatchObject({ ok: false, code: 'transport_failed', detail: 'accept' });
  });

  test('httpupgrade must echo the configured token', async () => {
    const s = await track(
      startRawServer({ transport: 'httpupgrade', node: 'proxy204', handshake: 'wrong-token' }),
    );
    const result = await run(s.port, 'httpupgrade');
    expect(result).toMatchObject({ ok: false, code: 'transport_failed', detail: 'upgrade' });
  });

  test('gRPC without a service name never opens a stream', async () => {
    const s = await track(startGrpcServer({ grpc: 'ok', node: 'proxy204' }));
    const result = await qualifyFront(
      {
        hostname: HOSTNAME,
        proto: VLESS('grpc'),
        params: {},
        uuid: UUID,
        stepTimeoutMs: 2_000,
      },
      { dial: { host: '127.0.0.1', port: s.port, ca: CERT } },
    );
    expect(result).toMatchObject({
      ok: false,
      code: 'transport_failed',
      detail: 'no_service_name',
    });
  });
});

describe('the node refuses or the egress fails', () => {
  test('a rejected credential closes before the response header: auth_failed', async () => {
    const s = await track(startRawServer({ transport: 'ws', node: 'proxy204' }));
    const result = await run(s.port, 'ws', { uuid: OTHER_UUID });
    expect(result).toMatchObject({ ok: false, code: 'auth_failed' });
    expectNoSecrets(result);
  });

  test('a body that is not a VLESS response is auth_failed, not a parse crash', async () => {
    const s = await track(startRawServer({ transport: 'ws', node: 'garbage' }));
    const result = await run(s.port, 'ws');
    expect(result).toMatchObject({ ok: false, code: 'auth_failed', detail: 'header' });
    expectNoSecrets(result);
  });

  test('a tunnel that answers something other than 204 is egress_failed', async () => {
    const s = await track(startRawServer({ transport: 'ws', node: 'proxy200' }));
    const result = await run(s.port, 'ws');
    expect(result).toMatchObject({ ok: false, code: 'egress_failed', detail: '200' });
  });

  test('a node that never answers times out on the vless step', async () => {
    const s = await track(startRawServer({ transport: 'ws', node: 'silent' }));
    const result = await run(s.port, 'ws', { stepTimeoutMs: 1_000 });
    expect(result).toMatchObject({ ok: false, code: 'timeout_vless' });
    expect(result.steps.find((x) => x.step === 'vless')?.ok).toBe(false);
  });
});

describe('the connection itself', () => {
  test('a front that accepts but never answers times out on the transport step', async () => {
    const s = await track(startRawServer({ transport: 'ws', node: 'proxy204', handshake: 'hang' }));
    const result = await run(s.port, 'ws', { stepTimeoutMs: 1_000 });
    expect(result).toMatchObject({ ok: false, code: 'timeout_transport' });
  });

  test('an untrusted chain for the hostname is tls_failed', async () => {
    const s = await track(startRawServer({ transport: 'ws', node: 'proxy204' }));
    const result = await run(s.port, 'ws', { trust: false });
    expect(result).toMatchObject({ ok: false, code: 'tls_failed', detail: 'chain' });
    expect(result.steps).toEqual([expect.objectContaining({ step: 'tls', ok: false })]);
    expectNoSecrets(result);
  });

  test('a listener without an authenticated proof is refused before any socket is opened', async () => {
    // Raw TCP (REALITY) is not HTTP-carried; trojan over ws has no VLESS proof;
    // a plaintext ws listener terminates no TLS the front could carry.
    const refused: ListenerProto[] = [
      { protocol: 'vless', streamTransport: 'raw', security: 'reality' },
      { protocol: 'trojan', streamTransport: 'ws', security: 'tls' },
      { protocol: 'shadowsocks', streamTransport: 'raw', security: 'none' },
      { protocol: 'hysteria2', streamTransport: 'udp', security: 'tls' },
    ];
    for (const proto of refused) {
      const result = await qualifyFront({
        hostname: HOSTNAME,
        proto,
        params: {},
        uuid: UUID,
        stepTimeoutMs: 1_000,
      });
      expect(result).toMatchObject({ ok: false, code: 'unsupported_protocol' });
      expect(result.steps).toEqual([]);
    }
  });
});
