export type Severity = "info" | "notable" | "important";

export type MobileUeSession = {
  ip: string;
  teids: string[];
  first_seen: number;
  last_seen: number;
  packet_count: number;
  byte_count: number;
};

export type CaptureNode = {
  mac: string;
  manufacturers: string[];
  ips: string[];
  hostnames: string[];
  protocols: string[];
  first_seen: number;
  last_seen: number;
  packet_count: number;
  byte_count: number;
  event_count: number;
  gtp_receiver?: boolean;
  gtp_first_seen?: number;
  mobile_ues?: Record<string, MobileUeSession>;
};

export type CaptureEdge = {
  source: string;
  target: string;
  protocols: string[];
  first_seen: number;
  last_seen: number;
  packet_count: number;
  byte_count: number;
};

export type CaptureEvent = {
  id: number | string;
  time: number;
  frame: number;
  node: string;
  peer?: string;
  kind: string;
  severity: Severity;
  protocol: string;
  title: string;
  summary: string;
  details: Record<string, unknown>;
  category?: string;
  sensitive?: boolean;
  confidence?: number | string;
  source_file?: string;
};

export type CaptureArtifact = {
  id: number | string;
  name: string;
  size: number;
  media_type: string;
  url: string;
  frame?: number;
  time?: number;
  complete?: boolean;
  sha256?: string;
  source_file?: string;
};

export type CaptureModel = {
  source: string;
  mode: "live" | "completed";
  status: "loading" | "following" | "ready" | "error";
  packet_count: number;
  duration: number;
  first_timestamp?: number;
  last_timestamp?: number;
  nodes: CaptureNode[];
  edges: CaptureEdge[];
  events: CaptureEvent[];
  artifacts?: CaptureArtifact[];
};

export type EventPage = {
  items: CaptureEvent[];
  total: number;
  offset: number;
  limit: number;
};

export type ArtifactPage = {
  items: CaptureArtifact[];
  total: number;
  offset?: number;
  limit?: number;
  complete?: boolean;
  counts: Record<string, number>;
};

export type WorkspaceId =
  | "subscribers"
  | "leaks"
  | "media"
  | "topology";

export function mergeById<T extends { id: string | number }>(
  base: T[],
  additions: T[],
) {
  const merged = new Map(base.map((item) => [String(item.id), item]));
  for (const item of additions) merged.set(String(item.id), item);
  return [...merged.values()];
}
