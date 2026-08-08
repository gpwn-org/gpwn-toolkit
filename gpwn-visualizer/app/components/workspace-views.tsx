"use client";

import { useState } from "react";
import { Network } from "lucide-react";
import { FamilyIcon, classifyEvent, eventWorkspace, familyLabels, type EventFamily } from "../event-ui";
import type { CaptureEvent, CaptureNode } from "../model";
import { clientEvents } from "../network";
import { EmptyState, EventList, SectionHead, SensitiveValue, formatCount } from "./ui";

export function SubscribersView({ nodes, events, reveal, onInspect }: { nodes: CaptureNode[]; events: CaptureEvent[]; reveal: boolean; onInspect: (event: CaptureEvent) => void }) {
  const [selected, setSelected] = useState(nodes[0]?.mac ?? "");
  const selectedNode = nodes.find((node) => node.mac === selected) ?? nodes[0];
  const selectedEvents = selectedNode ? clientEvents(events, selectedNode) : [];
  return <div className="workspace-view">
    <SectionHead eyebrow="Observed endpoints" title="Subscriber activity" copy="Browse the devices found in the capture and open a profile to explore addresses, traffic, services, and recent connections." />
    <div className="subscriber-layout"><div className="subscriber-list">{[...nodes].sort((a, b) => b.event_count - a.event_count || b.packet_count - a.packet_count).map((node) => <button key={node.mac} className={selectedNode?.mac === node.mac ? "active" : ""} onClick={() => setSelected(node.mac)}><span className="endpoint-orb"><Network size={17} /></span><span><b><SensitiveValue name="mac" value={node.mac.toUpperCase()} reveal={reveal} /></b><small>{node.manufacturers?.[0] || "Unknown manufacturer"}</small></span><strong>{formatCount(node.packet_count)}</strong></button>)}</div>
      <section className="surface subscriber-profile">{selectedNode ? <><div className="profile-head"><span className="endpoint-orb large"><Network size={23} /></span><div><span className="eyebrow">Observed endpoint</span><h2><SensitiveValue name="mac" value={selectedNode.mac.toUpperCase()} reveal={reveal} /></h2><p>{selectedNode.manufacturers?.[0] || "Unknown manufacturer"}</p></div></div><div className="profile-facts"><div><span>IP addresses</span><b><SensitiveValue name="ip" value={selectedNode.ips.join(", ") || "Not observed"} reveal={reveal} /></b></div><div><span>Hostnames</span><b><SensitiveValue name="hostname" value={selectedNode.hostnames.join(", ") || "Not observed"} reveal={reveal} /></b></div><div><span>Protocols</span><b>{selectedNode.protocols.join(" · ") || "Ethernet"}</b></div></div><h3 className="subheading">Domain, web and discovery activity</h3><EventList events={selectedEvents.filter((event) => ["dns", "tls", "http", "discovery"].includes(classifyEvent(event)))} reveal={reveal} onInspect={onInspect} empty="No subscriber activity was attributed here" /></> : <EmptyState title="No endpoints indexed" />}</section>
    </div>
  </div>;
}

export function LeaksView({ events, reveal, onInspect }: { events: CaptureEvent[]; reveal: boolean; onInspect: (event: CaptureEvent) => void }) {
  const shown = events.filter((event) => eventWorkspace(event).includes("leaks"));
  const groups = Object.entries(shown.reduce<Partial<Record<EventFamily, number>>>((result, event) => {
    const family = classifyEvent(event);
    result[family] = (result[family] ?? 0) + 1;
    return result;
  }, {})).sort((a, b) => b[1] - a[1]) as [EventFamily, number][];
  return <div className="workspace-view"><SectionHead eyebrow="Plaintext exposure" title="Data leaks" copy="Review MQTT messages and SNMP management data that reveal application details, device state, and operational information." /><div className="family-summary">{groups.map(([family, count]) => <div key={family}><span className={`family-icon family-${family}`}><FamilyIcon family={family} /></span><span><b>{familyLabels[family]}</b><small>{formatCount(count)} observations</small></span></div>)}</div><EventList events={shown} reveal={reveal} onInspect={onInspect} empty="No data leaks found" /></div>;
}
