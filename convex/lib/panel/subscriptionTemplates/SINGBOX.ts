/** The sing-box subscription template (JSON, compared structurally). */
export const SINGBOX_JSON = {
  dns: {
    servers: [
      { type: 'tls', tag: 'cf-dns', server: '1.1.1.1' },
      { type: 'tcp', tag: 'local', server: '1.1.1.1' },
      { type: 'fakeip', tag: 'remote', inet4_range: '198.18.0.0/15', inet6_range: 'fc00::/18' },
    ],
    rules: [{ query_type: ['A', 'AAAA'], server: 'remote' }],
    independent_cache: true,
  },
  log: { level: 'debug', disabled: true, timestamp: true },
  route: {
    rules: [
      { action: 'sniff' },
      {
        mode: 'or',
        type: 'logical',
        rules: [{ protocol: 'dns' }, { port: 53 }],
        action: 'hijack-dns',
      },
      { outbound: 'direct', ip_is_private: true },
    ],
    auto_detect_interface: true,
    default_domain_resolver: { server: 'local', strategy: 'prefer_ipv4' },
  },
  inbounds: [
    {
      mtu: 9000,
      tag: 'tun-in',
      type: 'tun',
      stack: 'mixed',
      platform: { http_proxy: { server: '127.0.0.1', enabled: true, server_port: 2412 } },
      auto_route: true,
      strict_route: true,
      interface_name: 'tun125',
      endpoint_independent_nat: true,
      address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
    },
    {
      tag: 'mixed-in',
      type: 'mixed',
      users: [],
      listen: '127.0.0.1',
      listen_port: 2412,
      set_system_proxy: false,
    },
  ],
  outbounds: [
    {
      tag: '→ Remnawave',
      type: 'selector',
      outbounds: null,
      interrupt_exist_connections: true,
    },
    { tag: 'direct', type: 'direct' },
  ],
  experimental: {
    clash_api: {
      external_ui: 'yacd',
      default_mode: 'rule',
      external_controller: '127.0.0.1:9090',
      external_ui_download_url: 'https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip',
      external_ui_download_detour: 'direct',
    },
    cache_file: {
      path: 'remnawave.db',
      enabled: true,
      cache_id: 'remnawave',
      store_fakeip: true,
    },
  },
};
