/**
 * The remark of an address (a backend Host) FCP writes for a direct node (pure;
 * unit-tested).
 *
 * The backend caps a remark at 40 characters (`HOST_REMARK_MAX`, the same bar
 * `checkHostFields` holds every write to). A direct node has one address per
 * server name its transport lists, so the remark names the node and the server
 * name: `<node> | <server name>`. A node name runs to 30 characters and a
 * server name to 253, so that only fits sometimes. When it does not, the server
 * name is replaced by a short tag derived from it (`<node> | <tag>`, at most
 * 30 + 3 + 7 = 40): deterministic, so every run computes the same remark for the
 * same name and finds its own address again. The address itself carries the
 * server name in its `sni` field; the remark only has to be unique per node.
 *
 * The separator is a character neither a node name (`[A-Za-z0-9 ._-]`) nor a
 * host name can carry, so the node a remark names is never in doubt: `node-a`
 * must not read `node-a-west | x.example` as its own (and delete it as extra).
 */
export const HOST_REMARK_MAX = 40;
export const ADDRESS_SEP = ' | ';
const TAG_LENGTH = 7;

/** A short, stable tag for a server name: FNV-1a 64 in base 36. Never contains a dot. */
export function remarkTag(name: string): string {
  let h = 0xcbf29ce484222325n;
  for (const ch of new TextEncoder().encode(name.toLowerCase())) {
    h ^= BigInt(ch);
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return h.toString(36).padStart(TAG_LENGTH, '0').slice(-TAG_LENGTH);
}

export function addressRemark(nodeName: string, sni: string): string {
  const full = `${nodeName}${ADDRESS_SEP}${sni}`;
  return full.length <= HOST_REMARK_MAX ? full : `${nodeName}${ADDRESS_SEP}${remarkTag(sni)}`;
}

/** Whether a remark FCP wrote names this node. */
export const ownsAddress = (nodeName: string, remark: string): boolean =>
  remark.startsWith(`${nodeName}${ADDRESS_SEP}`);
