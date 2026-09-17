/**
 * Front qualification: a short, authenticated, end-to-end test session through
 * a deployed L7 (CDN) edge.
 *
 * Why a session and not a handshake: a front answers TLS for its own
 * certificate, answers 200 for its own error pages, and will happily complete a
 * WebSocket handshake with a rule that never reaches the origin. None of that
 * proves a member can connect. So the check opens the transport exactly as the
 * slot describes, authenticates with the relay's qualification VLESS UUID, asks
 * the node to proxy `www.gstatic.com:80` and requires the 204 to come back out
 * of the tunnel. Only that sequence proves the whole chain.
 *
 * Everything observable is reported as a step with a duration, and every
 * failure gets a specific code so the admin sees WHERE the chain broke. Detail
 * strings carry status numbers and short reason tokens only: never a hostname,
 * a UUID or any body the front or the node returned.
 *
 * Runs inside a `"use node"` action (convex/frontQualifyOps.ts). Node APIs are
 * used directly; the only injected dependency is the TLS connect, so the tests
 * can run the same code against local servers.
 */
import type { TLSSocket } from 'node:tls';
import { connect as http2Connect, constants as h2, type ClientHttp2Stream } from 'node:http2';
import { randomBytes as nodeRandomBytes } from 'node:crypto';
import { protocolIsHttpTransport, type SlotProtocol } from '../protocols';
import type { TransportParams } from './binding';
import { parseHttpHead, tunnelProbeRequest, type HttpHead } from './http1';
import {
  buildWsHandshake,
  checkWsHandshake,
  createWsDecoder,
  encodeWsClose,
  encodeWsFrame,
  newWsKey,
  splitHandshake,
  WS_OPCODE,
} from './ws';
import { buildUpgradeRequest, checkUpgradeResponse, DEFAULT_UPGRADE_TOKEN } from './httpupgrade';
import { createGrpcDecoder, decodeHunk, encodeHunkFrame, grpcPath } from './grpc';
import { buildVlessRequest, parseVlessResponse } from './vless';
import { tlsConnect, type ConnectFn } from './tls';

/** The neutral, unauthenticated target the tunnel is asked to fetch. */
export const PROBE_TARGET = { host: 'www.gstatic.com', port: 80, path: '/generate_204' } as const;

/** How long we wait for the peer's orderly close before giving up on it. */
const CLOSE_GRACE_MS = 2_000;

export interface FrontCheckStep {
  step: 'tls' | 'transport' | 'vless' | 'close';
  ok: boolean;
  ms: number;
}

export interface FrontCheckResult {
  ok: boolean;
  code?: string;
  /** Status numbers and short reason tokens only. Never a body, name or secret. */
  detail?: string;
  steps: FrontCheckStep[];
  checkedAt: number;
}

export interface QualifyFrontArgs {
  /** The fronted hostname: the dial name, the SNI and the HTTP Host. */
  hostname: string;
  port?: number;
  protocol: SlotProtocol;
  params: TransportParams;
  /** The qualification account's VLESS UUID. */
  uuid: string;
  stepTimeoutMs: number;
  /** Ceiling for the whole session (default: three steps' worth). */
  totalTimeoutMs?: number;
  target?: { host: string; port: number; path: string };
}

export interface FrontCheckDeps {
  connect?: ConnectFn;
  /** Override where the TLS connection is dialled and what it trusts (tests). */
  dial?: {
    host?: string;
    port?: number;
    ca?: string | Uint8Array | Array<string | Uint8Array>;
    rejectUnauthorized?: boolean;
  };
  now?: () => number;
  randomBytes?: (n: number) => Uint8Array;
}

class StepError extends Error {
  constructor(
    readonly code: string,
    readonly detail?: string,
  ) {
    super(code);
  }
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** Rejects with `timeout_<step>` rather than letting a hung peer hold the action. */
function withTimeout<T>(p: Promise<T>, ms: number, step: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new StepError(`timeout_${step}`)), ms);
    p.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

interface CloseInfo {
  /** Present when the peer closed with gRPC trailers. */
  grpcStatus?: number;
}

interface TunnelHandlers {
  data: (chunk: Uint8Array) => void;
  close: (info: CloseInfo) => void;
  error: (err: Error) => void;
}

/**
 * A byte pipe through the transport. Events that arrive before a listener is
 * installed are buffered, and a close stays sticky so the close step can
 * observe a peer that hung up while we were still reading the response.
 */
abstract class Tunnel {
  private queue: Uint8Array[] = [];
  private closed: CloseInfo | null = null;
  private failed: Error | null = null;
  private handlers: TunnelHandlers | null = null;

  protected emitData(chunk: Uint8Array): void {
    if (this.handlers) this.handlers.data(chunk);
    else this.queue.push(chunk);
  }
  protected emitClose(info: CloseInfo = {}): void {
    if (this.closed) this.closed = { ...this.closed, ...info };
    else this.closed = info;
    if (this.handlers) this.handlers.close(this.closed);
  }
  protected emitError(err: Error): void {
    this.failed ??= err;
    if (this.handlers) this.handlers.error(err);
  }

  listen(handlers: TunnelHandlers): void {
    this.handlers = handlers;
    const pending = this.queue;
    this.queue = [];
    for (const chunk of pending) handlers.data(chunk);
    if (this.failed) handlers.error(this.failed);
    else if (this.closed) handlers.close(this.closed);
  }

  abstract send(data: Uint8Array): void;
  abstract closeOrderly(): void;
  abstract destroy(): void;
}

/**
 * One permanent socket listener, dispatched to whichever phase owns it.
 *
 * Attaching a `data` listener puts the socket in flowing mode, so between two
 * phases there must never be a moment with no owner: bytes that arrive while
 * the handshake reader has finished and the tunnel has not been built yet are
 * buffered here and replayed to the next owner, in order.
 */
class SocketPump {
  private pending: Uint8Array[] = [];
  private ended = false;
  private failure: Error | null = null;
  private onData: ((chunk: Uint8Array) => void) | null = null;
  private onEnd: (() => void) | null = null;
  private onError: ((err: Error) => void) | null = null;
  constructor(socket: TLSSocket) {
    socket.on('data', (d: Buffer) => {
      const chunk = new Uint8Array(d);
      if (this.onData) this.onData(chunk);
      else this.pending.push(chunk);
    });
    const end = () => {
      this.ended = true;
      this.onEnd?.();
    };
    socket.on('end', end);
    socket.on('close', end);
    socket.on('error', (e: Error) => {
      this.failure ??= e;
      this.onError?.(e);
    });
  }
  route(
    data: (chunk: Uint8Array) => void,
    end: () => void,
    error: (err: Error) => void = () => {},
  ): void {
    this.onData = data;
    this.onEnd = end;
    this.onError = error;
    const queued = this.pending;
    this.pending = [];
    for (const chunk of queued) data(chunk);
    if (this.failure) error(this.failure);
    else if (this.ended) end();
  }
  /** Back to buffering: the current owner is done but the next one is not built yet. */
  unroute(): void {
    this.onData = null;
    this.onEnd = null;
    this.onError = null;
  }
}

class RawTunnel extends Tunnel {
  constructor(
    private readonly socket: TLSSocket,
    pump: SocketPump,
    rest: Uint8Array,
  ) {
    super();
    // The bytes that shared the handshake's segment come first, then the pump's.
    if (rest.length > 0) this.emitData(rest);
    pump.route(
      (chunk) => this.emitData(chunk),
      () => this.emitClose(),
      (err) => this.emitError(err),
    );
  }
  send(data: Uint8Array): void {
    this.socket.write(data);
  }
  closeOrderly(): void {
    this.socket.end();
  }
  destroy(): void {
    this.socket.destroy();
  }
}

class WsTunnel extends Tunnel {
  private readonly decoder = createWsDecoder();
  constructor(
    private readonly socket: TLSSocket,
    pump: SocketPump,
    rest: Uint8Array,
    private readonly randomBytes: (n: number) => Uint8Array,
  ) {
    super();
    // Frames that shared the handshake's segment come first, then the pump's.
    if (rest.length > 0) this.feed(rest);
    pump.route(
      (chunk) => this.feed(chunk),
      () => this.emitClose(),
      (err) => this.emitError(err),
    );
  }
  private feed(chunk: Uint8Array): void {
    let events;
    try {
      events = this.decoder.push(chunk);
    } catch (err) {
      this.emitError(err as Error);
      return;
    }
    for (const ev of events) {
      if (ev.type === 'message') this.emitData(ev.data);
      else if (ev.type === 'close') this.emitClose();
      else if (ev.type === 'ping')
        this.socket.write(encodeWsFrame(WS_OPCODE.pong, ev.data, this.randomBytes(4)));
    }
  }
  send(data: Uint8Array): void {
    this.socket.write(encodeWsFrame(WS_OPCODE.binary, data, this.randomBytes(4)));
  }
  closeOrderly(): void {
    this.socket.write(encodeWsClose(1000, this.randomBytes(4)));
  }
  destroy(): void {
    this.socket.destroy();
  }
}

/**
 * The gRPC stream as a byte pipe.
 *
 * The response HEADERS are NOT awaited before the tunnel is handed over: a gRPC
 * server (Xray's included) may withhold them until it has seen the first client
 * message, so waiting for them before sending the VLESS request deadlocks. The
 * headers are validated here instead, and a bad one is raised as the specific
 * failure it is, on whichever step is running when it arrives.
 */
class GrpcTunnel extends Tunnel {
  private readonly decoder = createGrpcDecoder();
  constructor(
    private readonly stream: ClientHttp2Stream,
    private readonly closeSession: () => void,
  ) {
    super();
    stream.on('response', (headers: Record<string, unknown>) => this.onResponse(headers));
    stream.on('data', (d: Buffer) => this.feed(new Uint8Array(d)));
    stream.on('trailers', (headers: Record<string, unknown>) => {
      const raw = headers['grpc-status'];
      const status = raw === undefined ? undefined : Number(raw);
      this.emitClose(status === undefined || Number.isNaN(status) ? {} : { grpcStatus: status });
    });
    stream.on('end', () => this.emitClose());
    stream.on('close', () => this.emitClose());
    stream.on('error', () => this.emitError(new StepError('front_error', 'h2')));
  }
  /** Raise a failure the caller already classified (an HTTP/2 session error). */
  fail(err: Error): void {
    this.emitError(err);
  }
  private onResponse(headers: Record<string, unknown>): void {
    const status = Number(headers[h2.HTTP2_HEADER_STATUS]);
    if (status !== 200) {
      this.emitError(new StepError('front_error', String(status)));
      return;
    }
    const grpcStatus = headers['grpc-status'];
    if (grpcStatus !== undefined) {
      // Trailers-only: the peer refused the RPC without ever opening a tunnel.
      this.emitError(new StepError(`grpc_${Number(grpcStatus)}`));
      return;
    }
    const contentType = String(headers['content-type'] ?? '');
    // A 200 that is not gRPC is the front answering for itself.
    if (!contentType.startsWith('application/grpc'))
      this.emitError(new StepError('front_error', '200'));
  }
  private feed(chunk: Uint8Array): void {
    let messages;
    try {
      messages = this.decoder.push(chunk);
    } catch (err) {
      this.emitError(err as Error);
      return;
    }
    for (const msg of messages) {
      const data = decodeHunk(msg);
      if (data.length > 0) this.emitData(data);
    }
  }
  send(data: Uint8Array): void {
    this.stream.write(Buffer.from(encodeHunkFrame(data)));
  }
  closeOrderly(): void {
    this.stream.end();
  }
  destroy(): void {
    this.stream.destroy();
    this.closeSession();
  }
}

/** Read one HTTP/1.1 response head off the socket, keeping any trailing bytes. */
function readResponseHead(pump: SocketPump): Promise<{ head: HttpHead; rest: Uint8Array }> {
  return new Promise((resolve, reject) => {
    let buf: Uint8Array = new Uint8Array(0);
    let done = false;
    const settle = (fn: () => void) => {
      if (done) return;
      done = true;
      // Hand the socket back to the pump's buffer until the tunnel owns it.
      pump.unroute();
      fn();
    };
    pump.route(
      (chunk) => {
        buf = concat(buf, chunk);
        let split;
        try {
          split = splitHandshake(buf);
        } catch {
          settle(() => reject(new StepError('front_error', 'malformed')));
          return;
        }
        if (split) settle(() => resolve(split));
      },
      () => settle(() => reject(new StepError('front_error', 'closed'))),
      () => settle(() => reject(new StepError('front_error', 'io'))),
    );
  });
}

async function openWsTunnel(
  socket: TLSSocket,
  pump: SocketPump,
  args: QualifyFrontArgs,
  randomBytes: (n: number) => Uint8Array,
  timeoutMs: number,
): Promise<Tunnel> {
  const key = newWsKey(randomBytes);
  const path = args.params.path || '/';
  socket.write(buildWsHandshake({ path, host: args.hostname, key }));
  const { head, rest } = await withTimeout(readResponseHead(pump), timeoutMs, 'transport');
  const verdict = checkWsHandshake(head, key);
  if (!verdict.ok) {
    if (verdict.reason === 'status') throw new StepError('front_error', String(head.status));
    throw new StepError('transport_failed', verdict.reason);
  }
  return new WsTunnel(socket, pump, rest, randomBytes);
}

async function openUpgradeTunnel(
  socket: TLSSocket,
  pump: SocketPump,
  args: QualifyFrontArgs,
  timeoutMs: number,
): Promise<Tunnel> {
  const path = args.params.path || '/';
  const token = args.params.upgradeToken || DEFAULT_UPGRADE_TOKEN;
  socket.write(buildUpgradeRequest({ path, host: args.hostname, token }));
  const { head, rest } = await withTimeout(readResponseHead(pump), timeoutMs, 'transport');
  const verdict = checkUpgradeResponse(head, token);
  if (!verdict.ok) {
    if (verdict.reason === 'status') throw new StepError('front_error', String(head.status));
    throw new StepError('transport_failed', verdict.reason);
  }
  return new RawTunnel(socket, pump, rest);
}

function openGrpcTunnel(socket: TLSSocket, args: QualifyFrontArgs): Promise<Tunnel> {
  const serviceName = args.params.serviceName || '';
  if (!serviceName) return Promise.reject(new StepError('transport_failed', 'no_service_name'));
  const session = http2Connect(`https://${args.hostname}`, { createConnection: () => socket });
  const stream = session.request({
    [h2.HTTP2_HEADER_METHOD]: 'POST',
    [h2.HTTP2_HEADER_PATH]: grpcPath(serviceName),
    [h2.HTTP2_HEADER_AUTHORITY]: args.hostname,
    'content-type': 'application/grpc',
    te: 'trailers',
  });
  const tunnel = new GrpcTunnel(stream, () => session.close());
  session.on('error', () => tunnel.fail(new StepError('front_error', 'h2')));
  return Promise.resolve(tunnel);
}

/**
 * The authenticated leg: one write carrying the VLESS request header plus the
 * HTTP request, then the VLESS response header and the target's status line.
 */
function runSession(tunnel: Tunnel, args: QualifyFrontArgs, timeoutMs: number): Promise<void> {
  const target = args.target ?? PROBE_TARGET;
  const request = buildVlessRequest({
    uuid: args.uuid,
    host: target.host,
    port: target.port,
    payload: tunnelProbeRequest(target.host, target.path),
  });
  const session = new Promise<void>((resolve, reject) => {
    let buf: Uint8Array = new Uint8Array(0);
    let stage: 'vless' | 'http' = 'vless';
    let done = false;
    const settle = (fn: () => void) => {
      if (done) return;
      done = true;
      fn();
    };
    tunnel.listen({
      data(chunk) {
        buf = concat(buf, chunk);
        if (stage === 'vless') {
          let parsed;
          try {
            parsed = parseVlessResponse(buf);
          } catch {
            settle(() => reject(new StepError('auth_failed', 'header')));
            return;
          }
          if (!parsed) return;
          buf = buf.slice(parsed.headerLength);
          stage = 'http';
        }
        let head;
        try {
          head = parseHttpHead(buf);
        } catch {
          settle(() => reject(new StepError('egress_failed', 'malformed')));
          return;
        }
        if (!head) return;
        if (head.status === 204) settle(resolve);
        else settle(() => reject(new StepError('egress_failed', String(head.status))));
      },
      close(info) {
        if (info.grpcStatus !== undefined && info.grpcStatus !== 0) {
          settle(() => reject(new StepError(`grpc_${info.grpcStatus}`)));
          return;
        }
        settle(() =>
          reject(new StepError(stage === 'vless' ? 'auth_failed' : 'egress_failed', 'closed')),
        );
      },
      error(err) {
        // A transport that already classified the failure (an HTTP/2 status,
        // gRPC trailers) keeps its own code; anything else is an I/O break at
        // whichever stage we had reached.
        settle(() =>
          reject(
            err instanceof StepError
              ? err
              : new StepError(stage === 'vless' ? 'auth_failed' : 'egress_failed', 'io'),
          ),
        );
      },
    });
    tunnel.send(request);
  });
  return withTimeout(session, timeoutMs, 'vless');
}

/** Orderly close. A peer that never answers is logged as a slow close, not a failure. */
function closeTunnel(tunnel: Tunnel): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    let done = false;
    const settle = (ok: boolean) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(ok);
    };
    const timer = setTimeout(() => settle(false), CLOSE_GRACE_MS);
    tunnel.listen({
      data: () => {},
      close: () => settle(true),
      error: () => settle(true),
    });
    try {
      tunnel.closeOrderly();
    } catch {
      settle(false);
    }
  });
}

export async function qualifyFront(
  args: QualifyFrontArgs,
  deps: FrontCheckDeps = {},
): Promise<FrontCheckResult> {
  const now = deps.now ?? (() => Date.now());
  const connect = deps.connect ?? tlsConnect;
  const randomBytes = deps.randomBytes ?? ((n: number) => new Uint8Array(nodeRandomBytes(n)));
  const checkedAt = now();
  const steps: FrontCheckStep[] = [];
  const stepTimeout = Math.max(1_000, args.stepTimeoutMs);
  const deadline = checkedAt + (args.totalTimeoutMs ?? stepTimeout * 3);
  const budget = () => Math.max(1, Math.min(stepTimeout, deadline - now()));

  const record = <T>(step: FrontCheckStep['step'], fn: () => Promise<T>): Promise<T> => {
    const startedAt = now();
    return fn().then(
      (value) => {
        steps.push({ step, ok: true, ms: now() - startedAt });
        return value;
      },
      (err) => {
        steps.push({ step, ok: false, ms: now() - startedAt });
        throw err;
      },
    );
  };

  if (!protocolIsHttpTransport(args.protocol))
    return { ok: false, code: 'unsupported_protocol', steps, checkedAt };

  let socket: TLSSocket | null = null;
  let tunnel: Tunnel | null = null;
  try {
    socket = await record('tls', () =>
      withTimeout(
        connect({
          host: deps.dial?.host ?? args.hostname,
          port: deps.dial?.port ?? args.port ?? 443,
          servername: args.hostname,
          alpn: args.protocol === 'grpc' ? ['h2'] : ['http/1.1'],
          timeoutMs: budget(),
          ca: deps.dial?.ca,
          rejectUnauthorized: deps.dial?.rejectUnauthorized,
        }),
        budget(),
        'tls',
      ).catch((err) => {
        if (err instanceof StepError) throw err;
        throw new StepError('tls_failed', 'chain');
      }),
    );
    const pump = args.protocol === 'grpc' ? null : new SocketPump(socket);
    tunnel = await record('transport', () => {
      if (args.protocol === 'ws') return openWsTunnel(socket!, pump!, args, randomBytes, budget());
      if (args.protocol === 'httpupgrade') return openUpgradeTunnel(socket!, pump!, args, budget());
      return openGrpcTunnel(socket!, args);
    });
    await record('vless', () => runSession(tunnel!, args, budget()));
    // A slow close is evidence about the peer, never a reason to refuse an edge:
    // the step is recorded as not ok and the overall result stays a pass.
    const closeStartedAt = now();
    const closed = await closeTunnel(tunnel);
    steps.push({ step: 'close', ok: closed, ms: now() - closeStartedAt });
    return { ok: true, steps, checkedAt };
  } catch (err) {
    const e = err instanceof StepError ? err : new StepError('front_error', 'io');
    return { ok: false, code: e.code, detail: e.detail, steps, checkedAt };
  } finally {
    try {
      tunnel?.destroy();
    } catch {
      /* the session is over; a failing teardown adds nothing */
    }
    try {
      socket?.destroy();
    } catch {
      /* same */
    }
  }
}
