import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { EARLY_BROWSER_ERROR_GUARD, isBenignResizeObserverError } from "../app/browser-errors";
import {
  artifactPresentation,
  artifactMatchesFilter,
  classifyEvent,
  DEFAULT_REVEAL_SENSITIVE,
  domainFromEvent,
  eventContainsSensitiveData,
  eventWorkspace,
  faviconUrl,
  isSensitiveKey,
  maskValue,
  type EventFamily,
} from "../app/event-ui";
import { AnalyzerUnavailable, ArtifactCard, EventCard } from "../app/signal-map";
import { ClientProfile } from "../app/components/topology-view";
import { ANALYZER_RETRY_INTERVAL_MS, ARTIFACT_POLL_INTERVAL_MS, shouldPollArtifacts } from "../app/use-capture";
import type { CaptureArtifact, CaptureEvent, WorkspaceId } from "../app/model";

function fixture(kind: string, protocol: string, details: Record<string, unknown> = {}): CaptureEvent {
  return {
    id: kind,
    time: 12.5,
    frame: 42,
    node: "00:11:22:33:44:55",
    kind,
    protocol,
    severity: "notable",
    title: `${protocol} observation`,
    summary: "Decoded from packet evidence",
    details,
  };
}

describe("typed event renderers", () => {
  test("shows sensitive values by default", () => {
    expect(DEFAULT_REVEAL_SENSITIVE).toBe(true);
  });
  const families: Array<[EventFamily, CaptureEvent, WorkspaceId | null]> = [
    ["dns", fixture("dns_response", "DNS", { domain: "www.example.com", answer: "192.0.2.1" }), "subscribers"],
    ["tls", fixture("certificate_observed", "TLS", { san: "example.com" }), "subscribers"],
    ["http", fixture("http_response", "HTTP", { content_type: "application/json", status: 200 }), "subscribers"],
    ["mqtt", fixture("mqtt_message", "MQTT", { topic: "driver/status", payload: { state: "arrived" } }), "leaks"],
    ["sip", fixture("sip_registration", "SIP", { sip_uri: "sip:15551212@example.net" }), null],
    ["cellular", fixture("ngap_paging", "NGAP", { tmsi: "0x10203040", tac: 123 }), null],
    ["rtp", fixture("rtcp_report", "RTCP", { ssrc: "102938", jitter: 2.1 }), "media"],
    ["snmp", fixture("snmp_get", "SNMP", { community: "public", oid: "1.3.6.1" }), "leaks"],
    ["stun", fixture("stun_binding", "STUN", { software: "Tuya" }), null],
    ["ntp", fixture("ntp_response", "NTP", { refid: "GOOG", stratum: 1 }), null],
    ["ftps", fixture("ftp_auth_tls", "FTP", { response: 234 }), null],
    ["discovery", fixture("mdns_service", "MDNS", { service: "_airplay._tcp" }), "subscribers"],
    ["tunnel", fixture("gtp_tunnel", "GTP", { teid: "0x1234", vlan: 40 }), "topology"],
    ["encrypted", fixture("wireguard_transport", "WireGuard", { receiver_index: 9 }), null],
    ["artifact", fixture("carved_object", "HTTP", { media_type: "image/jpeg" }), "media"],
    ["generic", fixture("validated_protocol", "H225", { field: "value" }), null],
  ];

  test.each(families)("classifies and renders %s observations", (family, event, expectedWorkspace) => {
    expect(classifyEvent(event)).toBe(family);
    const html = renderToStaticMarkup(<EventCard event={event} reveal={true} />);
    expect(html).toContain(`data-family="${family}"`);
    expect(html).toContain("observation");
    if (expectedWorkspace) expect(eventWorkspace(event)).toContain(expectedWorkspace);
  });

  test("uses analyzer-cached favicon URL and a local letter fallback", () => {
    const event = fixture("dns_response", "DNS", { domain: "cdn.images.example.com" });
    expect(domainFromEvent(event)).toBe("cdn.images.example.com");
    expect(faviconUrl("http://127.0.0.1:8799/", "cdn.images.example.com"))
      .toBe("http://127.0.0.1:8799/api/favicon/cdn.images.example.com");
    const html = renderToStaticMarkup(<EventCard event={event} reveal={true} />);
    expect(html).toContain("/api/favicon/cdn.images.example.com");
  });

  test("keeps explicit discovery and tunnel kinds out of payload protocol workspaces", () => {
    expect(classifyEvent(fixture("device_discovered", "SIP"))).toBe("discovery");
    expect(classifyEvent(fixture("address_claimed", "S1AP"))).toBe("discovery");
    expect(classifyEvent(fixture("vlan_seen", "HTTP"))).toBe("tunnel");
  });

  test("masks sensitive identities and management values until reveal", () => {
    expect(isSensitiveKey("imsi")).toBe(true);
    expect(isSensitiveKey("pn-prid")).toBe(true);
    expect(isSensitiveKey("community")).toBe(true);
    expect(isSensitiveKey("source_ip")).toBe(true);
    expect(isSensitiveKey("mac")).toBe(true);
    expect(isSensitiveKey("status_code")).toBe(false);
    expect(maskValue("001010000000001")).not.toContain("000000001");
    const event = fixture("sip_registration", "SIP", { imsi: "001010000000001" });
    event.title = "Registration for 001010000000001";
    event.summary = "Phone +15550101001 registered";
    expect(eventContainsSensitiveData(event)).toBe(true);
    const masked = renderToStaticMarkup(<EventCard event={event} reveal={false} />);
    const revealed = renderToStaticMarkup(<EventCard event={event} reveal={true} />);
    expect(masked).not.toContain("001010000000001");
    expect(masked).not.toContain("+15550101001");
    expect(revealed).toContain("001010000000001");
  });

  test("masks complete synthetic SIP, MQTT, cellular, and SNMP records", () => {
    const sip = fixture("sip_activity", "SIP", {
      asserted_identity: "<sip:+15550101001@ims.example.net>",
      contact: "<sip:+15550101001@192.0.2.4:5060>",
      destination_ips: "198.51.100.171",
    });
    const mqtt = fixture("mqtt_message", "MQTT", {
      topic: "driver/test-user/jobs/123",
      messages: '{"customer":"Private Person"}',
    });
    for (const event of [
      sip,
      mqtt,
      fixture("s1ap_procedure", "S1AP", { s1ap_m_tmsi: "0x12345678" }),
      fixture("snmp_activity", "SNMP", { community: "public", ip_values: "192.0.2.1" }),
    ]) {
      expect(eventContainsSensitiveData(event)).toBe(true);
      const html = renderToStaticMarkup(<EventCard event={event} reveal={false} />);
      for (const value of Object.values(event.details)) expect(html).not.toContain(String(value));
    }
  });
});

describe("analyzer availability", () => {
  test("retries an unavailable analyzer on a short fixed interval", () => {
    expect(ANALYZER_RETRY_INTERVAL_MS).toBe(3000);
  });

  test("renders an explicit error without substitute capture data", () => {
    const html = renderToStaticMarkup(<AnalyzerUnavailable />);
    expect(html).toContain("Analyzer unavailable");
    expect(html).toContain("reconnect automatically");
    expect(html).toContain("/analyzer-api");
  });
});

describe("client profile masking", () => {
  test("applies the global mask to topology profile identifiers and recent evidence", () => {
    const client = {
      mac: "00:11:22:33:44:55",
      manufacturers: ["Example Networks"],
      ips: ["192.0.2.44"],
      hostnames: ["private-device.example"],
      protocols: ["DNS"],
      first_seen: 0,
      last_seen: 10,
      packet_count: 5,
      byte_count: 500,
      event_count: 1,
    };
    const event = fixture("dns_response", "DNS", { domain: "private.example" });
    event.node = client.mac;
    event.title = "private.example lookup";
    const model = { source: "capture.pcap", mode: "completed" as const, status: "ready" as const, packet_count: 5, duration: 10, nodes: [client], edges: [], events: [event] };
    const html = renderToStaticMarkup(<ClientProfile client={client} model={model} events={[event]} reveal={false} currentTime={10} uesExpanded={false} onToggleUes={() => {}} onClose={() => {}} onInspect={() => {}} />);
    expect(html).not.toContain(client.mac.toUpperCase());
    expect(html).not.toContain("192.0.2.44");
    expect(html).not.toContain("private.example");
  });
});

describe("safe recovered-object presentation", () => {
  const artifact = (media_type: string): CaptureArtifact => ({
    id: media_type,
    name: "capture-object.bin",
    size: 1024,
    media_type,
    url: "/api/artifacts/object",
  });

  test.each([
    ["image/jpeg", "image"],
    ["video/mp4", "video"],
    ["audio/aac", "audio"],
    ["application/json", "text"],
    ["text/html", "text"],
    ["application/zip", "archive"],
    ["application/x-msdownload", "download"],
    ["image/svg+xml", "download"],
  ] as const)("maps %s to %s", (mediaType, presentation) => {
    expect(artifactPresentation(artifact(mediaType))).toBe(presentation);
  });

  test("embeds only safe native media and never embeds captured HTML", () => {
    const htmlCard = renderToStaticMarkup(<ArtifactCard artifact={{ ...artifact("text/html"), name: "captured.html" }} />);
    const imageCard = renderToStaticMarkup(<ArtifactCard artifact={{ ...artifact("image/png"), name: "photo.png" }} />);
    const videoCard = renderToStaticMarkup(<ArtifactCard artifact={{ ...artifact("video/mp4"), name: "clip.mp4" }} />);
    const audioCard = renderToStaticMarkup(<ArtifactCard artifact={{ ...artifact("audio/aac"), name: "sound.aac" }} />);
    expect(htmlCard).not.toContain("<iframe");
    expect(htmlCard).not.toContain("<object");
    expect(htmlCard).toContain("Safe preview disabled");
    expect(imageCard).toContain("<img");
    expect(videoCard).toContain("<video");
    expect(audioCard).toContain("<audio");
    expect(imageCard).toContain("/analyzer-api/api/artifacts/object");
  });

  test("hides generic binary files from the default filter and exposes them under Other", () => {
    const binary = artifact("application/octet-stream");
    expect(artifactMatchesFilter(binary, "all")).toBe(false);
    expect(artifactMatchesFilter(binary, "download")).toBe(true);
    expect(artifactMatchesFilter(artifact("image/png"), "all")).toBe(true);
    expect(artifactMatchesFilter(artifact("image/png"), "image")).toBe(true);
  });
});

describe("artifact refresh scheduling", () => {
  test("polls while recovery is incomplete and stops after completion", () => {
    expect(shouldPollArtifacts(false, 0, 100)).toBe(true);
    expect(shouldPollArtifacts(false, 100, 100 + ARTIFACT_POLL_INTERVAL_MS - 1)).toBe(false);
    expect(shouldPollArtifacts(false, 100, 100 + ARTIFACT_POLL_INTERVAL_MS)).toBe(true);
    expect(shouldPollArtifacts(true, 0, 100)).toBe(false);
  });
});

describe("browser error filtering", () => {
  test("ignores only the known ResizeObserver warning without assuming message exists", () => {
    expect(isBenignResizeObserverError({ message: "ResizeObserver loop completed with undelivered notifications." })).toBe(true);
    expect(isBenignResizeObserverError({ error: { message: "ResizeObserver loop completed with undelivered notifications." } })).toBe(true);
    expect(isBenignResizeObserverError({ message: undefined })).toBe(false);
    expect(isBenignResizeObserverError({})).toBe(false);
    expect(isBenignResizeObserverError(null)).toBe(false);
    expect(EARLY_BROWSER_ERROR_GUARD).toContain("stopImmediatePropagation");
  });
});
