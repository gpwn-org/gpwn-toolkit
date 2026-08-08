import { describe, expect, test } from "bun:test";
import { clientEvents, clientGraphNodes, isCellSite, isMacClient, mobileUeSessions, playbackCallouts, trafficNodeSize, visibleGraphNodes } from "../app/network";
import type { CaptureEvent, CaptureNode } from "../app/model";

function node(mac: string, first_seen = 0, ips: string[] = []): CaptureNode {
  return { mac, manufacturers: [], ips, hostnames: [], protocols: [], first_seen, last_seen: first_seen + 1, packet_count: 1, byte_count: 64, event_count: 0 };
}

describe("GPON client graph", () => {
  test("shows every MAC client by default without a display cap", () => {
    const macs = Array.from({ length: 120 }, (_, index) => node(`02:00:00:00:${Math.floor(index / 256).toString(16).padStart(2, "0")}:${(index % 256).toString(16).padStart(2, "0")}`));
    const input = [...macs, node("ip:100.64.0.1")];
    expect(clientGraphNodes(input, false)).toHaveLength(120);
    expect(clientGraphNodes(input, true)).toHaveLength(121);
    expect(isMacClient(macs[0])).toBe(true);
  });

  test("playback reveals clients by first-seen time", () => {
    expect(visibleGraphNodes([node("00:11:22:33:44:55", 2), node("00:11:22:33:44:66", 9)], 5)).toHaveLength(1);
  });

  test("sizes nodes by observed bytes with bounded outlier handling", () => {
    const clients = [node("00:11:22:33:44:01"), node("00:11:22:33:44:02"), node("00:11:22:33:44:03")];
    clients[0].byte_count = 64;
    clients[1].byte_count = 64_000;
    clients[2].byte_count = 64_000_000;
    const small = trafficNodeSize(clients[0], clients);
    const medium = trafficNodeSize(clients[1], clients);
    const large = trafficNodeSize(clients[2], clients);
    expect(small.width).toBeGreaterThanOrEqual(28);
    expect(medium.width).toBeGreaterThan(small.width);
    expect(large.width).toBeGreaterThan(medium.width);
    expect(large.width).toBeLessThanOrEqual(62);
    expect(large.height).toBe(large.width);
  });

  test("identifies GTP receivers and orders their visible mobile UE sessions", () => {
    const receiver = node("00:11:22:33:44:55");
    receiver.gtp_receiver = true;
    receiver.gtp_first_seen = 3;
    receiver.mobile_ues = {
      "10.0.0.5": { ip: "10.0.0.5", teids: ["0x1"], first_seen: 2, last_seen: 9, packet_count: 2, byte_count: 200 },
      "10.0.0.6": { ip: "10.0.0.6", teids: ["0x2"], first_seen: 7, last_seen: 8, packet_count: 5, byte_count: 500 },
    };
    expect(isCellSite(receiver)).toBe(true);
    expect(isCellSite(receiver, 2)).toBe(false);
    expect(isCellSite(receiver, 3)).toBe(true);
    expect(isCellSite(node("00:11:22:33:44:66"))).toBe(false);
    expect(mobileUeSessions(receiver, 6).map(({ ip }) => ip)).toEqual(["10.0.0.5"]);
    expect(mobileUeSessions(receiver).map(({ ip }) => ip)).toEqual(["10.0.0.6", "10.0.0.5"]);
  });

  test("profiles include both sides of attributed events", () => {
    const events = [
      { id: 1, time: 0, frame: 1, node: "a", peer: "b", kind: "dns_response", protocol: "DNS", severity: "info", title: "DNS", summary: "DNS", details: {} },
      { id: 2, time: 1, frame: 2, node: "c", peer: "a", kind: "tls_sni", protocol: "TLS", severity: "info", title: "TLS", summary: "TLS", details: {} },
    ] satisfies CaptureEvent[];
    expect(clientEvents(events, "a")).toHaveLength(2);
    expect(clientEvents(events, "b")).toHaveLength(1);
  });

  test("profiles include IP-layer evidence attributed to the client MAC", () => {
    const client = node("00:11:22:33:44:55", 0, ["100.64.1.7", "2001:db8::7"]);
    const events = [
      { id: 1, time: 0, frame: 1, node: "ip:100.64.1.7", peer: "ip:1.1.1.1", kind: "dns_response", protocol: "DNS", severity: "info", title: "DNS", summary: "DNS", details: {} },
      { id: 2, time: 1, frame: 2, node: "ip:2.2.2.2", peer: "ip:2001:db8::7", kind: "tls_sni", protocol: "TLS", severity: "info", title: "TLS", summary: "TLS", details: {} },
      { id: 3, time: 2, frame: 3, node: "ip:100.64.1.8", peer: "ip:3.3.3.3", kind: "tls_sni", protocol: "TLS", severity: "info", title: "Other", summary: "Other", details: {} },
    ] satisfies CaptureEvent[];
    expect(clientEvents(events, client).map(({ id }) => id)).toEqual([1, 2]);
  });

  test("playback callouts stay readable at speed and remain bounded", () => {
    const events = Array.from({ length: 14 }, (_, index) => ({
      id: index,
      time: 100 + index,
      frame: index,
      node: `00:11:22:33:44:${String(index).padStart(2, "0")}`,
      kind: "dns_response",
      severity: "info" as const,
      protocol: "DNS",
      title: `Event ${index}`,
      summary: "Observed",
      details: {},
    }));
    const callouts = playbackCallouts(events, 113, 4, 6);
    expect(callouts.size).toBe(6);
    expect([...callouts.values()].map((event) => event.id)).toEqual([13, 12, 11, 10, 9, 8]);
    expect(playbackCallouts(events, 113, 64).size).toBe(10);
  });

  test("maps IP-layer playback callouts onto the client MAC node", () => {
    const client = node("00:11:22:33:44:55", 0, ["100.64.1.7"]);
    const events = [{
      id: 1,
      time: 12,
      frame: 1,
      node: "ip:100.64.1.7",
      peer: "ip:1.1.1.1",
      kind: "dns_response",
      severity: "info" as const,
      protocol: "DNS",
      title: "DNS",
      summary: "Observed",
      details: {},
    }];
    const callouts = playbackCallouts(events, 13, 4, 10, [client]);
    expect(callouts.get(client.mac)?.id).toBe(1);
  });
});
