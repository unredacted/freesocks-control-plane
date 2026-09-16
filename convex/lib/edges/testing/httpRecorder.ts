/**
 * Test helper: an in-process HTTP server that RECORDS every request and answers
 * from a routing function. Not a test file itself.
 *
 * Why a real socket rather than a `fetch` stub: the Fastly SDK talks through
 * superagent (node `http`), so a global `fetch` stub never sees its requests.
 * Pointing the SDK's base path at this recorder is the only way to observe what
 * the SDK actually puts on the wire (paths, query serialization, form vs JSON
 * bodies, headers) instead of what a hand-written mock agrees to pretend.
 *
 * `Reply.abort` destroys the connection without answering: that is how a lost
 * response / transport failure is simulated for an SDK with no retry, so a test
 * can prove exactly ONE request was made.
 *
 * Requires the node environment (`// @vitest-environment node`).
 */
import { createServer, type Server } from 'node:http';

export interface RecordedCall {
  method: string;
  path: string;
  /** Parsed query string; repeated keys keep the last value. */
  query: Record<string, string>;
  headers: Record<string, string | undefined>;
  /** JSON object, form fields as an object, or the raw string. */
  body: unknown;
  rawBody: string;
}

export interface RecorderReply {
  status: number;
  body?: unknown;
  contentType?: string;
  /** Destroy the socket instead of answering (a transport failure). */
  abort?: boolean;
}

export type RecorderRoute = (call: RecordedCall, index: number) => RecorderReply;

export interface HttpRecorder {
  calls: RecordedCall[];
  /** `http://127.0.0.1:<port>`: the base path an SDK is pointed at. */
  base: string;
  /** Swap the routing function (e.g. for a second phase of one test). */
  route: (next: RecorderRoute) => void;
  close: () => Promise<void>;
}

function parseBody(raw: string, contentType: string): unknown {
  if (raw.length === 0) return undefined;
  if (contentType.includes('json')) {
    try {
      return JSON.parse(raw);
    } catch {
      return raw;
    }
  }
  if (contentType.includes('x-www-form-urlencoded'))
    return Object.fromEntries(new URLSearchParams(raw).entries());
  return raw;
}

/** Start the recorder on an ephemeral port. Always `close()` it in an afterEach. */
export async function startHttpRecorder(initial: RecorderRoute): Promise<HttpRecorder> {
  const calls: RecordedCall[] = [];
  let current = initial;
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      // The host is irrelevant: only the path and the query are recorded.
      const url = new URL(req.url ?? '/', 'http://recorder.invalid');
      const query: Record<string, string> = {};
      url.searchParams.forEach((v, k) => (query[k] = v));
      const call: RecordedCall = {
        method: req.method ?? 'GET',
        path: url.pathname,
        query,
        headers: req.headers as Record<string, string | undefined>,
        body: parseBody(raw, String(req.headers['content-type'] ?? '')),
        rawBody: raw,
      };
      calls.push(call);
      const reply = current(call, calls.length - 1);
      if (reply.abort) {
        res.destroy();
        return;
      }
      const payload = reply.body === undefined ? '' : JSON.stringify(reply.body);
      res.writeHead(reply.status, {
        'content-type': reply.contentType ?? 'application/json',
        'content-length': Buffer.byteLength(payload),
      });
      res.end(payload);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return {
    calls,
    base: `http://127.0.0.1:${port}`,
    route: (next) => {
      current = next;
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
