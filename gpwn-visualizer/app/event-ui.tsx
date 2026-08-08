import { createElement } from "react";
import {
  Activity,
  Antenna,
  Archive,
  Box,
  Cable,
  Clock3,
  CloudCog,
  File,
  FileJson,
  Globe2,
  HardDriveDownload,
  Image as ImageIcon,
  LockKeyhole,
  MessageSquareText,
  Music,
  PhoneCall,
  Radio,
  Route,
  ServerCog,
  ShieldCheck,
  Video,
  Wifi,
  type LucideIcon,
} from "lucide-react";
import type { CaptureArtifact, CaptureEvent, WorkspaceId } from "./model";

export type EventFamily =
  | "dns"
  | "tls"
  | "http"
  | "mqtt"
  | "sip"
  | "cellular"
  | "rtp"
  | "snmp"
  | "stun"
  | "ntp"
  | "ftps"
  | "discovery"
  | "tunnel"
  | "encrypted"
  | "artifact"
  | "generic";

export const DEFAULT_REVEAL_SENSITIVE = true;

export const familyLabels: Record<EventFamily, string> = {
  dns: "DNS",
  tls: "TLS",
  http: "HTTP",
  mqtt: "MQTT",
  sip: "SIP / IMS",
  cellular: "Cellular",
  rtp: "RTP / RTCP",
  snmp: "SNMP",
  stun: "STUN / TURN",
  ntp: "NTP",
  ftps: "FTP / FTPS",
  discovery: "Discovery",
  tunnel: "Tunnel",
  encrypted: "Encrypted",
  artifact: "Artifact",
  generic: "Other",
};

const familyIcons: Record<EventFamily, LucideIcon> = {
  dns: Globe2,
  tls: LockKeyhole,
  http: HardDriveDownload,
  mqtt: MessageSquareText,
  sip: PhoneCall,
  cellular: Antenna,
  rtp: Radio,
  snmp: ServerCog,
  stun: Route,
  ntp: Clock3,
  ftps: CloudCog,
  discovery: Wifi,
  tunnel: Cable,
  encrypted: ShieldCheck,
  artifact: File,
  generic: Activity,
};

const patterns: Array<[EventFamily, RegExp]> = [
  ["artifact", /artifact|object|carved|media_file/i],
  ["dns", /(^|_)(dns|domain)(_|$)|\bdns\b/i],
  ["ftps", /ftp|ftps|auth_tls|file_transfer/i],
  ["tls", /tls|ssl|certificate|client_hello|server_hello|sni/i],
  ["http", /http|web_response|web_request/i],
  ["mqtt", /mqtt|telemetry|order_status|battery|routematic|connected_car/i],
  ["sip", /sip|ims|invite|register|call_id/i],
  ["cellular", /s1ap|x2ap|ngap|xnap|nas|paging|tmsi|mme|amf|ran_ue|cellular|lte|5g/i],
  ["rtp", /rtp|rtcp|ssrc|media_stream/i],
  ["snmp", /snmp|community|oid/i],
  ["stun", /stun|turn|xor_mapped|relayed_address/i],
  ["ntp", /ntp|stratum|refid/i],
  ["discovery", /dhcp|mdns|llmnr|ssdp|user_agent|device_discovered|address_claimed/i],
  ["tunnel", /gtp|gre|pppoe|vlan|teid|encapsulation|tunnel/i],
  ["encrypted", /quic|dtls|esp|ipsec|wireguard|openvpn|ike|srtp|btdht|encrypted/i],
];

export function classifyEvent(event: CaptureEvent): EventFamily {
  if (/^(device_discovered|address_claimed|dhcp_identity|dhcpv6_activity|mdns_activity|llmnr_activity|ssdp_activity)$/.test(event.kind)) {
    return "discovery";
  }
  if (/^(vlan_seen|tunnel_observed)$/.test(event.kind)) return "tunnel";
  const evidence = [
    event.category,
    event.kind,
    event.protocol,
    event.title,
    ...Object.keys(event.details ?? {}),
  ].join(" ");
  return patterns.find(([, pattern]) => pattern.test(evidence))?.[0] ?? "generic";
}

export function eventWorkspace(event: CaptureEvent): WorkspaceId[] {
  const family = classifyEvent(event);
  const spaces: WorkspaceId[] = [];
  if (["dns", "tls", "http", "discovery"].includes(family)) spaces.push("subscribers");
  if (["mqtt", "snmp"].includes(family)) spaces.push("leaks");
  if (["rtp", "artifact"].includes(family)) spaces.push("media");
  if (family === "tunnel") spaces.push("topology");
  return spaces;
}

const sensitivePattern = /(^|_)(macs?|ips?|hostnames?|imsi|imei|meid|msisdn|phone|telephone|sip_uri|call_id|caller|callee|from|to|identity|contact|fcm|token|pn_prid|customer|employee|driver|subscriber|order|job|teids?|tmsi|ue_id|address|email|user|username|source_user|destination_user|password|community|precise_location|latitude|longitude|coordinates?)($|_)/i;
const networkIdentifierPattern = /(^|_)(macs?|ips?|hostnames?)($|_)/i;

export function isSensitiveKey(key: string) {
  return sensitivePattern.test(key.replace(/[ .-]+/g, "_"));
}

export function eventContainsSensitiveData(event: CaptureEvent) {
  if (event.sensitive || ["mqtt", "sip", "cellular", "snmp"].includes(classifyEvent(event))) {
    return true;
  }
  return Object.keys(event.details ?? {}).some((key) => {
    const normalized = key.replace(/[ .-]+/g, "_");
    return isSensitiveKey(normalized) && !networkIdentifierPattern.test(normalized);
  });
}

export function maskValue(value: unknown) {
  const text = displayValue(value);
  if (text.length <= 4) return "••••";
  return `${text.slice(0, 2)}${"•".repeat(Math.min(12, text.length - 4))}${text.slice(-2)}`;
}

export function displayValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "Not observed";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

export function domainFromEvent(event: CaptureEvent) {
  const keys = ["domain", "query", "qry_name", "sni", "server_name", "host", "hostname"];
  for (const key of keys) {
    const value = event.details?.[key];
    if (typeof value === "string" && /[a-z0-9-]+\.[a-z]{2,}/i.test(value)) {
      return value.replace(/^https?:\/\//, "").split(/[/:]/)[0].replace(/\.$/, "");
    }
  }
  const match = `${event.title} ${event.summary}`.match(/(?:[a-z0-9-]+\.)+[a-z]{2,}/i);
  return match?.[0];
}

export function faviconUrl(api: string, domain: string) {
  return `${api.replace(/\/$/, "")}/api/favicon/${encodeURIComponent(domain)}`;
}

export function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB"];
  const exponent = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  return `${(value / 1024 ** exponent).toFixed(exponent ? 1 : 0)} ${units[exponent]}`;
}

export type ArtifactPresentation = "image" | "video" | "audio" | "text" | "archive" | "download";
export type ArtifactFilter = "all" | ArtifactPresentation;

export function artifactPresentation(artifact: CaptureArtifact): ArtifactPresentation {
  const media = artifact.media_type.toLowerCase();
  if (media.startsWith("image/") && !media.includes("svg")) return "image";
  if (media.startsWith("video/")) return "video";
  if (media.startsWith("audio/")) return "audio";
  if (/^(text\/|application\/(json|xml|x-pem-file|pkix-cert))/.test(media)) return "text";
  if (/zip|gzip|xz|cab|tar|rar|7z/.test(media)) return "archive";
  return "download";
}

export function artifactMatchesFilter(artifact: CaptureArtifact, filter: ArtifactFilter) {
  const mediaType = artifact.media_type.trim().toLowerCase();
  if (filter === "all") return mediaType !== "application/octet-stream";
  return artifactPresentation(artifact) === filter;
}

export function artifactIcon(kind: ArtifactPresentation): LucideIcon {
  return { image: ImageIcon, video: Video, audio: Music, text: FileJson, archive: Archive, download: Box }[kind];
}

export function eventIcon(family: EventFamily) {
  return familyIcons[family];
}

export function familyAccent(family: EventFamily) {
  if (["mqtt", "snmp", "cellular"].includes(family)) return "important";
  if (["sip", "rtp", "http", "tls"].includes(family)) return "notable";
  return "info";
}

export const kindLabel = (kind: string) =>
  kind.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());

export function DomainMark({ api, domain }: { api: string; domain: string }) {
  return (
    <span className="domain-mark" aria-hidden="true">
      <span>{domain.charAt(0).toUpperCase()}</span>
      {/* The analyzer always returns an image fallback, so a broken remote URL never reaches the browser. */}
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src={faviconUrl(api, domain)} alt="" loading="lazy" onError={(event) => { event.currentTarget.hidden = true; }} />
    </span>
  );
}

export function FamilyIcon({ family }: { family: EventFamily }) {
  return createElement(eventIcon(family), { size: 18, strokeWidth: 1.7 });
}
