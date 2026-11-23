/**
 * Member-facing names for NOWPayments network codes (`/v1/full-currencies`
 * `network`), used when the direct-checkout coin list comes from the account
 * (Admin -> Billing: coin source "account"). The network is what a payer must
 * get right or lose the money, so the label is OUR text for codes we know, and
 * the bare upper-cased code for anything else: never a guess, never the
 * processor's free-text coin name.
 */

interface NetworkInfo {
  /** Chain name shown to members. */
  name: string;
  /** Token standard appended for tokens on the chain, e.g. `TRC-20`. */
  std?: string;
  /** The chain's own coin (no standard appended for it), e.g. `TRX`. */
  native?: string;
  /** Ticker suffixes NOWPayments uses for tokens on this network (stripped for the unit). */
  suffixes?: string[];
}

const NETWORKS: Record<string, NetworkInfo> = {
  btc: { name: 'Bitcoin', native: 'BTC' },
  eth: { name: 'Ethereum', std: 'ERC-20', native: 'ETH', suffixes: ['erc20', 'eth'] },
  trx: { name: 'Tron', std: 'TRC-20', native: 'TRX', suffixes: ['trc20', 'trx'] },
  bsc: {
    name: 'BNB Smart Chain',
    std: 'BEP-20',
    native: 'BNB',
    suffixes: ['bsc', 'bep20', 'mainnet'],
  },
  sol: { name: 'Solana', native: 'SOL', suffixes: ['sol'] },
  ton: { name: 'TON', native: 'TON', suffixes: ['ton'] },
  matic: { name: 'Polygon', native: 'POL', suffixes: ['matic', 'polygon', 'mainnet'] },
  polygon: { name: 'Polygon', native: 'POL', suffixes: ['matic', 'polygon'] },
  arbitrum: { name: 'Arbitrum One', native: 'ETH', suffixes: ['arb', 'arbitrum'] },
  arb: { name: 'Arbitrum One', native: 'ETH', suffixes: ['arb', 'arbitrum'] },
  op: { name: 'Optimism', native: 'ETH', suffixes: ['op'] },
  base: { name: 'Base', native: 'ETH', suffixes: ['base'] },
  avaxc: { name: 'Avalanche C-Chain', native: 'AVAX', suffixes: ['avaxc', 'avax'] },
  ltc: { name: 'Litecoin', native: 'LTC' },
  xmr: { name: 'Monero', native: 'XMR' },
  zec: { name: 'Zcash', native: 'ZEC' },
  doge: { name: 'Dogecoin', native: 'DOGE' },
  bch: { name: 'Bitcoin Cash', native: 'BCH' },
  dash: { name: 'Dash', native: 'DASH' },
  xrp: { name: 'XRP Ledger', native: 'XRP' },
  xlm: { name: 'Stellar', native: 'XLM' },
  ada: { name: 'Cardano', native: 'ADA' },
  algo: { name: 'Algorand', native: 'ALGO', suffixes: ['algo'] },
  dot: { name: 'Polkadot', native: 'DOT' },
  atom: { name: 'Cosmos Hub', native: 'ATOM' },
  xtz: { name: 'Tezos', native: 'XTZ' },
  near: { name: 'NEAR', native: 'NEAR', suffixes: ['near'] },
  etc: { name: 'Ethereum Classic', native: 'ETC' },
  celo: { name: 'Celo', native: 'CELO', suffixes: ['celo'] },
  kava: { name: 'Kava', native: 'KAVA', suffixes: ['kava'] },
};

/** The unit shown next to the amount: the ticker minus its network suffix, upper-cased. */
export function coinUnit(ticker: string, network: string): string {
  const t = ticker.toLowerCase();
  for (const suffix of NETWORKS[network.toLowerCase()]?.suffixes ?? []) {
    if (t.endsWith(suffix) && t.length - suffix.length >= 2) {
      return t.slice(0, -suffix.length).toUpperCase();
    }
  }
  return t.toUpperCase();
}

/** The network label shown everywhere the coin appears. */
export function networkLabel(network: string, unit: string): string {
  const n = NETWORKS[network.toLowerCase()];
  if (!n) return network.toUpperCase();
  return n.std && unit !== n.native ? `${n.name} (${n.std})` : n.name;
}

/** The bare chain name for a known code (e.g. `Tron`), else the upper-cased code. */
export function networkName(network: string): string {
  return NETWORKS[network.toLowerCase()]?.name ?? network.toUpperCase();
}

/** Whether the code is one this table names (the admin flags the rest). */
export function knownNetwork(network: string): boolean {
  return network.toLowerCase() in NETWORKS;
}
