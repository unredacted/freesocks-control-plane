/** Three Hosts of one node: pinning must retain every endpoint, in every format. */
export const COMPAT_NODE = 'compat-node';
export const COMPAT_ENDPOINTS = [
  { server: 'compat-proxy', port: 443, serverName: 'compat-origin' },
  { server: 'compat-proxy', port: 444, serverName: 'compat-alternate' },
  { server: 'compat-proxy', port: 445, serverName: 'compat-backup' },
] as const;
