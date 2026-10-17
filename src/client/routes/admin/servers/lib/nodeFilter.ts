/**
 * The Nodes list filter (pure): a node matches when its node name or its
 * machine name (the host name the node role reported) contains the query,
 * ignoring case. An empty query matches every node.
 */
export function nodeMatches(query: string, name: string, machineName: string | null): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return name.toLowerCase().includes(q) || (machineName ?? '').toLowerCase().includes(q);
}
