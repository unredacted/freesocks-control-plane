/**
 * The one impure edge of the front check: opening the TLS connection to the
 * fronted hostname.
 *
 * It is a separate, injectable dependency so the node-environment tests can run
 * the whole session against local servers on 127.0.0.1 with a self-signed
 * certificate they trust explicitly, while production keeps
 * `rejectUnauthorized: true` against the system CA store. Nothing else in the
 * checker knows how the socket was made.
 */
import { connect, type TLSSocket } from 'node:tls';

export interface TlsConnectOptions {
  /** Where to dial. Tests point this at 127.0.0.1; production dials the hostname. */
  host: string;
  port: number;
  /** SNI and the name the certificate must cover. Always the fronted hostname. */
  servername: string;
  /** ALPN offer: ['h2'] for the gRPC transport, ['http/1.1'] otherwise. */
  alpn: string[];
  timeoutMs: number;
  /** Extra trust anchor (tests only); absent = the system CA store. */
  ca?: string | Uint8Array | Array<string | Uint8Array>;
  rejectUnauthorized?: boolean;
}

export type ConnectFn = (opts: TlsConnectOptions) => Promise<TLSSocket>;

export const tlsConnect: ConnectFn = (opts) =>
  new Promise<TLSSocket>((resolve, reject) => {
    const socket = connect({
      host: opts.host,
      port: opts.port,
      servername: opts.servername,
      ALPNProtocols: opts.alpn,
      // Default true: an unverifiable chain for the fronted hostname is exactly
      // the failure this step exists to catch.
      rejectUnauthorized: opts.rejectUnauthorized ?? true,
      ca: opts.ca as never,
    });
    const fail = (err: Error) => {
      socket.destroy();
      reject(err);
    };
    socket.setTimeout(opts.timeoutMs, () => fail(new Error('tls timeout')));
    socket.once('error', fail);
    socket.once('secureConnect', () => {
      socket.setTimeout(0);
      socket.removeListener('error', fail);
      resolve(socket);
    });
  });
