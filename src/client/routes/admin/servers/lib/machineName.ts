/**
 * The machine name (the host name the node role reported) worth showing
 * beside a node's name (pure): only when it says something the node name
 * does not. Operators name nodes after their machines, so a machine name
 * equal to the node name (ignoring case and surrounding spaces) is left out
 * rather than printed twice. Adopted nodes have no machine name.
 */
export function machineNameShown(
  name: string,
  machineName: string | null | undefined,
): string | null {
  if (!machineName?.trim()) return null;
  return machineName.trim().toLowerCase() === name.trim().toLowerCase() ? null : machineName;
}
