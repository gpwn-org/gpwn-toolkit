import type { CaptureEvent, CaptureNode, MobileUeSession } from "./model";

const macPattern = /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i;

export function isMacClient(node: CaptureNode) {
  return macPattern.test(node.mac);
}

export function clientGraphNodes(nodes: CaptureNode[], includeIpOnly: boolean) {
  if (includeIpOnly) return nodes;
  const macNodes = nodes.filter(isMacClient);
  return macNodes.length ? macNodes : nodes;
}

export function visibleGraphNodes(nodes: CaptureNode[], currentTime: number) {
  return nodes.filter((node) => node.first_seen <= currentTime);
}

export type TrafficNodeSize = { width: number; height: number; scale: number };

/**
 * Scale both dimensions by log(bytes), clipped at the 95th percentile so one
 * enormous client cannot make every other client indistinguishably small.
 */
export function trafficNodeSize(node: CaptureNode, population: CaptureNode[]): TrafficNodeSize {
  const logs = population
    .map((candidate) => Math.log1p(Math.max(0, Number.isFinite(candidate.byte_count) ? candidate.byte_count : 0)))
    .sort((a, b) => a - b);
  const value = Math.log1p(Math.max(0, Number.isFinite(node.byte_count) ? node.byte_count : 0));
  const floor = logs[0] ?? 0;
  const ceiling = logs[Math.ceil(Math.max(0, logs.length - 1) * 0.95)] ?? floor;
  const scale = ceiling > floor ? Math.max(0, Math.min(1, (value - floor) / (ceiling - floor))) : 0.35;
  const diameter = Math.round(28 + scale * 34);
  return {
    width: diameter,
    height: diameter,
    scale,
  };
}

function observedIds(client: CaptureNode) {
  return new Set([client.mac, ...client.ips.map((ip) => `ip:${ip}`)]);
}

export function clientEvents(events: CaptureEvent[], client: CaptureNode | string) {
  const ids = typeof client === "string" ? new Set([client]) : observedIds(client);
  return events.filter((event) => ids.has(event.node) || (event.peer ? ids.has(event.peer) : false));
}

export function isCellSite(node: CaptureNode, currentTime = Number.POSITIVE_INFINITY) {
  return node.gtp_receiver === true && (node.gtp_first_seen ?? node.first_seen) <= currentTime;
}

export function mobileUeSessions(node: CaptureNode, currentTime = Number.POSITIVE_INFINITY): MobileUeSession[] {
  return Object.values(node.mobile_ues ?? {})
    .filter((session) => session.first_seen <= currentTime)
    .sort((a, b) => b.byte_count - a.byte_count || a.ip.localeCompare(b.ip));
}

/** Keep playback annotations on screen for roughly two real seconds at any speed. */
export function playbackCallouts(
  events: CaptureEvent[],
  currentTime: number,
  speed: number,
  limit = 10,
  clients: CaptureNode[] = [],
) {
  const earliest = Math.max(0, currentTime - Math.max(2.5, speed * 2.2));
  const clientByObservedId = new Map<string, string>();
  for (const client of clients) {
    for (const id of observedIds(client)) clientByObservedId.set(id, client.mac);
  }
  const callouts = new Map<string, CaptureEvent>();
  for (let index = events.length - 1; index >= 0 && callouts.size < limit; index -= 1) {
    const event = events[index];
    if (event.time > currentTime || event.time < earliest) continue;
    const clientId = clientByObservedId.get(event.node)
      ?? (event.peer ? clientByObservedId.get(event.peer) : undefined)
      ?? event.node;
    if (callouts.has(clientId)) continue;
    callouts.set(clientId, event);
  }
  return callouts;
}
