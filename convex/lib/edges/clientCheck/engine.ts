/**
 * How the client-check service runs an engine (docs/edges.md § "FCP's own client
 * check"): the whole configuration around the one outbound it was given, the
 * command lines, and what the engine's own output says when a session fails.
 *
 * The configuration has a loopback HTTP proxy inbound and the outbound as its
 * ONLY outbound: there is no direct outbound and no DNS server, so nothing the
 * fetch does can leave any other way, and the egress page's name is resolved at
 * the node (the proxy hands the name through CONNECT). Mihomo's equivalent: a
 * loopback mixed port, the one proxy, one rule sending everything to it, DNS
 * off and no geodata (a `MATCH` rule never needs any, so none is downloaded).
 */
import type {
  ClientCheckEngine,
  ClientCheckSessionCode,
} from '../../../../src/shared/contracts/edgeCodes';

export const CHECK_OUTBOUND_TAG = 'check';

export function engineConfig(
  engine: ClientCheckEngine,
  outbound: Record<string, unknown>,
  listenPort: number,
): Record<string, unknown> {
  if (engine === 'mihomo') {
    return {
      'mixed-port': listenPort,
      'bind-address': '127.0.0.1',
      'allow-lan': false,
      mode: 'rule',
      'log-level': 'warning',
      ipv6: true,
      dns: { enable: false },
      'geo-auto-update': false,
      profile: { 'store-selected': false, 'store-fake-ip': false },
      proxies: [{ ...outbound, name: CHECK_OUTBOUND_TAG }],
      rules: [`MATCH,${CHECK_OUTBOUND_TAG}`],
    };
  }
  if (engine === 'sing-box') {
    return {
      log: { level: 'warn', timestamp: false },
      inbounds: [{ type: 'mixed', tag: 'in', listen: '127.0.0.1', listen_port: listenPort }],
      outbounds: [{ ...outbound, tag: CHECK_OUTBOUND_TAG }],
      route: { final: CHECK_OUTBOUND_TAG },
    };
  }
  return {
    log: { loglevel: 'warning', access: 'none' },
    inbounds: [
      { tag: 'in', listen: '127.0.0.1', port: listenPort, protocol: 'http', settings: {} },
    ],
    // The first outbound is Xray's default route; it is the only one.
    outbounds: [{ ...outbound, tag: CHECK_OUTBOUND_TAG }],
  };
}

/**
 * The command line that runs one session. sing-box and Xray take the same;
 * Mihomo reads a JSON configuration as YAML and keeps its state in `homeDir`
 * (the session's own temporary directory).
 */
export function engineRunArgs(
  engine: ClientCheckEngine,
  configPath: string,
  homeDir: string,
): string[] {
  return engine === 'mihomo' ? ['-f', configPath, '-d', homeDir] : ['run', '-c', configPath];
}

/** The command line that prints the engine's version. */
export function engineVersionArgs(engine: ClientCheckEngine): string[] {
  return engine === 'mihomo' ? ['-v'] : ['version'];
}

/**
 * Mihomo opens its port before its tunnel takes connections (a connection in
 * between is closed after the proxy handshake), so a session waits this long
 * after the port answers. The others take connections once they listen.
 */
export const ENGINE_SETTLE_MS: Record<ClientCheckEngine, number> = {
  'sing-box': 0,
  xray: 0,
  mihomo: 500,
};

/** `sing-box version` / `xray version` / `mihomo -v` output -> the version, or null. */
export function parseEngineVersion(engine: ClientCheckEngine, text: string): string | null {
  const m =
    engine === 'sing-box'
      ? /sing-box version (\S+)/.exec(text)
      : engine === 'mihomo'
        ? /Mihomo(?: Meta)? v?(\d[^\s]*)/.exec(text)
        : /^Xray (\d[^\s]*)/m.exec(text.trim());
  return m?.[1] ?? null;
}

/**
 * Why a session failed, from what the engine logged and what the fetch threw
 * (both read in memory and dropped; they carry addresses). A REALITY server that
 * refuses a client hands it to the target, whose real certificate the client
 * then rejects: through a public target that reads `reality verification
 * failed` (sing-box) or `received real certificate` (Xray), through a test
 * target an unknown-authority error. Either way, for a REALITY outbound, it is
 * a refusal of this client.
 */
export function sessionCodeOf(
  output: string,
  opts: { reality: boolean; started: boolean },
): ClientCheckSessionCode {
  const t = output.toLowerCase();
  if (!opts.started)
    return /decode config|unknown field|failed to load|parse|invalid|unmarshal|json/.test(t)
      ? 'config_refused'
      : 'session_failed';
  if (
    /reality verification failed|reality authentication failed|received real certificate|processed invalid connection/.test(
      t,
    )
  )
    return 'reality_refused';
  const tls = /x509|tls: |handshake failure|bad certificate|certificate/.test(t);
  if (tls && opts.reality) return 'reality_refused';
  if (tls) return 'tls_failed';
  if (/i\/o timeout|deadline exceeded|timed out|timeout/.test(t)) return 'timeout';
  if (/connection refused/.test(t)) return 'refused';
  if (/no route to host|network is unreachable|host is unreachable/.test(t)) return 'unreachable';
  if (/connection reset|broken pipe|\beof\b|closed/.test(t)) return 'reset';
  return 'session_failed';
}
