"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Background, Controls, Handle, MarkerType, MiniMap, NodeToolbar, Position,
  ReactFlow, ReactFlowProvider, useEdgesState, useNodesState,
  type Edge as FlowEdge, type Node as FlowNode, type NodeProps,
} from "@xyflow/react";
import { Network, RadioTower, Smartphone, X } from "lucide-react";
import "@xyflow/react/dist/style.css";
import { DomainMark, classifyEvent, domainFromEvent, eventContainsSensitiveData, familyLabels, formatBytes, kindLabel, maskValue } from "../event-ui";
import type { CaptureEvent, CaptureModel, CaptureNode, MobileUeSession } from "../model";
import { clientEvents, clientGraphNodes, isCellSite, mobileUeSessions, playbackCallouts, trafficNodeSize, visibleGraphNodes, type TrafficNodeSize } from "../network";
import { ANALYZER_API } from "../use-capture";
import { EventList, SensitiveValue, formatCount, formatTime } from "./ui";

type TopologyNodeData = { endpoint: CaptureNode; reveal: boolean; onSelect: (mac: string) => void; size: TrafficNodeSize; isCellSite: boolean; mobileUeCount: number; callout?: CaptureEvent } & Record<string, unknown>;
type TopologyFlowNode = FlowNode<TopologyNodeData, "endpoint">;
type MobileUeNodeData = { session: MobileUeSession; reveal: boolean } & Record<string, unknown>;
type MobileUeFlowNode = FlowNode<MobileUeNodeData, "mobileUe">;
type NetworkFlowNode = TopologyFlowNode | MobileUeFlowNode;

const privateText = (value: string, reveal: boolean) => reveal ? value : maskValue(value);

function TopologyNode({ data, selected }: NodeProps<TopologyFlowNode>) {
  const calloutFamily = data.callout ? classifyEvent(data.callout) : undefined;
  const traffic = formatBytes(data.endpoint.byte_count);
  const EndpointIcon = data.isCellSite ? RadioTower : Network;
  const identity = data.endpoint.ips[0] || data.endpoint.manufacturers?.[0] || "Observed endpoint";
  const ueCount = data.mobileUeCount;
  return <div className="topology-node-shell">{data.callout && calloutFamily && <NodeToolbar isVisible position={Position.Top} offset={9}><div className={`node-event-callout severity-${data.callout.severity || "info"}`}><span>[{familyLabels[calloutFamily]}]</span><b><SensitiveValue name="title" value={data.callout.title || kindLabel(data.callout.kind)} reveal={data.reveal} force={eventContainsSensitiveData(data.callout)} /></b><small>{formatTime(data.callout.time)}</small></div></NodeToolbar>}<Handle type="target" position={Position.Top} className="flow-handle" /><button className={`topology-node ${data.isCellSite ? "gtp" : "regular"} ${selected ? "selected" : ""}`} style={{ width: data.size.width, height: data.size.height }} data-byte-count={data.endpoint.byte_count} title={data.isCellSite ? "Probable cell site" : "GPON client"} onClick={(event) => { event.stopPropagation(); data.onSelect(data.endpoint.mac); }} aria-label={`Open ${data.isCellSite ? "probable cell site" : "GPON client"} ${privateText(data.endpoint.mac.toUpperCase(), data.reveal)}, ${traffic} observed`}><span className="topology-node-core"><EndpointIcon size={Math.round(14 + data.size.scale * 8)} /></span><span className="topology-node-hover"><span><b>{data.isCellSite ? "PROBABLE CELL SITE" : "GPON CLIENT"}</b><em>{traffic}</em></span><strong><SensitiveValue name="mac" value={data.endpoint.mac.toUpperCase()} reveal={data.reveal} /></strong><small>{data.isCellSite ? `${ueCount} mobile UE${ueCount === 1 ? "" : "s"}` : data.endpoint.ips[0] ? <SensitiveValue name="ip" value={identity} reveal={data.reveal} /> : identity}</small><i>Click to open profile</i></span></button><Handle type="source" position={Position.Bottom} className="flow-handle" /></div>;
}

function MobileUeNode({ data }: NodeProps<MobileUeFlowNode>) {
  return <div className="mobile-ue-node"><Handle type="target" position={Position.Top} className="flow-handle" /><Smartphone size={13} /><span><b><SensitiveValue name="ip" value={data.session.ip} reveal={data.reveal} /></b><small>{data.session.teids.length} TEID{data.session.teids.length === 1 ? "" : "s"} · {formatBytes(data.session.byte_count)}</small></span></div>;
}

const nodeTypes = { endpoint: TopologyNode, mobileUe: MobileUeNode };

function graphPosition(index: number, total: number) {
  if (!index) return { x: 0, y: 0 };
  const perRing = Math.max(12, Math.min(24, Math.ceil(Math.sqrt(total) * 2)));
  const ringIndex = Math.floor((index - 1) / perRing);
  const positionInRing = (index - 1) % perRing;
  const membersInRing = Math.min(perRing, total - 1 - ringIndex * perRing);
  const angle = (positionInRing / Math.max(membersInRing, 1)) * Math.PI * 2;
  const ring = 330 + ringIndex * 270;
  return { x: Math.cos(angle) * ring, y: Math.sin(angle) * ring * 0.68 };
}

function TopologyCanvas({ model, endpoints, reveal, currentTime, events, playbackActive, playbackSpeed, expandedCellSite, onSelect }: { model: CaptureModel; endpoints: CaptureNode[]; reveal: boolean; currentTime: number; events: CaptureEvent[]; playbackActive: boolean; playbackSpeed: number; expandedCellSite: string | null; onSelect: (mac: string) => void }) {
  const nextVisibleEndpoints = useMemo(() => visibleGraphNodes(endpoints, currentTime).sort((a, b) => b.byte_count - a.byte_count), [endpoints, currentTime]);
  const visibleEndpointKey = JSON.stringify(nextVisibleEndpoints.map((endpoint) => [endpoint.mac, endpoint.byte_count, endpoint.packet_count, endpoint.event_count, endpoint.ips[0] ?? ""]));
  const visibleEndpoints = useMemo(() => { const visibleIds = new Set((JSON.parse(visibleEndpointKey) as Array<[string]>).map(([mac]) => mac)); return endpoints.filter((endpoint) => visibleIds.has(endpoint.mac)).sort((a, b) => b.byte_count - a.byte_count); }, [endpoints, visibleEndpointKey]);
  const ids = useMemo(() => new Set(visibleEndpoints.map((node) => node.mac)), [visibleEndpoints]);
  const nextCallouts = useMemo(() => playbackActive ? playbackCallouts(events, currentTime, playbackSpeed, 10, visibleEndpoints) : new Map<string, CaptureEvent>(), [events, currentTime, playbackActive, playbackSpeed, visibleEndpoints]);
  const calloutPayload = JSON.stringify([...nextCallouts]);
  const callouts = useMemo(() => new Map<string, CaptureEvent>(JSON.parse(calloutPayload)), [calloutPayload]);
  const desiredNodes = useMemo<NetworkFlowNode[]>(() => {
    const endpointNodes: NetworkFlowNode[] = visibleEndpoints.map((endpoint, index) => {
      const size = trafficNodeSize(endpoint, endpoints);
      return { id: endpoint.mac, type: "endpoint", position: graphPosition(index, visibleEndpoints.length), initialWidth: size.width, initialHeight: size.height, ariaLabel: `Open client ${privateText(endpoint.mac.toUpperCase(), reveal)}`, data: { endpoint, reveal, onSelect, size, isCellSite: isCellSite(endpoint, currentTime), mobileUeCount: mobileUeSessions(endpoint, currentTime).length, callout: callouts.get(endpoint.mac) } };
    });
    const cellIndex = expandedCellSite ? visibleEndpoints.findIndex((endpoint) => endpoint.mac === expandedCellSite) : -1;
    if (cellIndex < 0) return endpointNodes;
    const cellPosition = graphPosition(cellIndex, visibleEndpoints.length);
    const sessions = mobileUeSessions(visibleEndpoints[cellIndex], currentTime).slice(0, 80);
    const satellites: MobileUeFlowNode[] = sessions.map((session, index) => {
      const perRing = 12; const ring = Math.floor(index / perRing); const position = index % perRing; const members = Math.min(perRing, sessions.length - ring * perRing); const angle = (position / Math.max(1, members)) * Math.PI * 2; const radius = 105 + ring * 72;
      return { id: `ue:${expandedCellSite}:${session.ip}`, type: "mobileUe", position: { x: cellPosition.x + Math.cos(angle) * radius, y: cellPosition.y + Math.sin(angle) * radius }, draggable: false, selectable: false, data: { session, reveal } };
    });
    return [...endpointNodes, ...satellites];
  }, [visibleEndpoints, endpoints, reveal, onSelect, callouts, expandedCellSite, currentTime]);
  const nextDesiredEdges = useMemo<FlowEdge[]>(() => model.edges.filter((edge) => edge.first_seen <= currentTime && ids.has(edge.source) && ids.has(edge.target)).map((edge) => ({ id: `${edge.source}-${edge.target}`, source: edge.source, target: edge.target, markerEnd: { type: MarkerType.ArrowClosed, width: 9, height: 9 }, style: { strokeWidth: Math.min(4, 0.7 + Math.log10(edge.packet_count + 1)) } })), [model.edges, ids, currentTime]);
  const satelliteEdges = useMemo<FlowEdge[]>(() => { if (!expandedCellSite) return []; const site = visibleEndpoints.find((endpoint) => endpoint.mac === expandedCellSite); if (!site) return []; return mobileUeSessions(site, currentTime).slice(0, 80).map((session) => ({ id: `${expandedCellSite}-ue-${session.ip}`, source: expandedCellSite, target: `ue:${expandedCellSite}:${session.ip}`, className: "mobile-ue-edge", style: { strokeWidth: 1.2, strokeDasharray: "3 4" } })); }, [expandedCellSite, visibleEndpoints, currentTime]);
  const edgePayload = JSON.stringify([...nextDesiredEdges, ...satelliteEdges]);
  const desiredEdges = useMemo<FlowEdge[]>(() => JSON.parse(edgePayload), [edgePayload]);
  const [nodes, setNodes, onNodesChange] = useNodesState<NetworkFlowNode>(desiredNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState<FlowEdge>(desiredEdges);
  useEffect(() => setNodes(desiredNodes), [desiredNodes, setNodes]);
  useEffect(() => setEdges(desiredEdges), [desiredEdges, setEdges]);
  return <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onNodeClick={(_, node) => { if (node.type === "endpoint") onSelect(node.id); }} fitView fitViewOptions={{ padding: .13, maxZoom: 1 }} minZoom={.08} maxZoom={2.2} nodesConnectable={false} nodesDraggable={false} deleteKeyCode={null} aria-label="GPON client network"><Background gap={30} size={1} color="rgba(20,20,20,.1)" /><Controls showInteractive={false} /><MiniMap pannable zoomable nodeColor={(node) => node.type === "mobileUe" ? "#ff806b" : "#171717"} maskColor="rgba(245,244,238,.72)" /></ReactFlow>;
}

export function ClientProfile({ client, model, events, reveal, currentTime, uesExpanded, onToggleUes, onClose, onInspect }: { client: CaptureNode; model: CaptureModel; events: CaptureEvent[]; reveal: boolean; currentTime: number; uesExpanded: boolean; onToggleUes: () => void; onClose: () => void; onInspect: (event: CaptureEvent) => void }) {
  const relatedEvents = clientEvents(events, client);
  const domains = [...new Set(relatedEvents.map(domainFromEvent).filter((domain): domain is string => Boolean(domain)))].slice(0, 18);
  const peerIds = new Set(model.edges.flatMap((edge) => edge.source === client.mac ? [edge.target] : edge.target === client.mac ? [edge.source] : []));
  const peers = model.nodes.filter((node) => peerIds.has(node.mac)).sort((a, b) => b.packet_count - a.packet_count);
  const cellSite = isCellSite(client, currentTime);
  const ueSessions = mobileUeSessions(client, currentTime);
  const ProfileIcon = cellSite ? RadioTower : Network;
  return <aside className={`client-profile ${cellSite ? "gtp-client-profile" : ""}`} aria-label="Client profile"><div className="client-profile-head"><span className="endpoint-orb large"><ProfileIcon size={23} /></span><div><span>{cellSite ? "Probable cell site · GTP receiver" : "GPON client"}</span><h2><SensitiveValue name="mac" value={client.mac.toUpperCase()} reveal={reveal} /></h2><p>{client.manufacturers?.[0] || "Unknown manufacturer"}</p></div><button className="icon-button" onClick={onClose} aria-label="Close client profile"><X size={16} /></button></div>
    <div className="client-metrics"><div><span>Packets</span><b>{formatCount(client.packet_count)}</b></div><div><span>Traffic</span><b>{formatBytes(client.byte_count)}</b></div><div><span>Events</span><b>{formatCount(relatedEvents.length)}</b></div><div><span>{cellSite ? "Mobile UEs" : "Peers"}</span><b>{cellSite ? ueSessions.length : peers.length}</b></div></div>
    <dl className="client-facts"><div><dt>IP addresses</dt><dd><SensitiveValue name="ip" value={client.ips.join(", ") || "Not observed"} reveal={reveal} /></dd></div><div><dt>Hostnames</dt><dd><SensitiveValue name="hostname" value={client.hostnames.join(", ") || "Not observed"} reveal={reveal} /></dd></div><div><dt>Protocols</dt><dd>{client.protocols.join(" · ") || "Ethernet"}</dd></div></dl>
    <section><h3>Observed domains <span>{domains.length}</span></h3>{domains.length ? <div className="client-domains">{domains.map((domain) => <span key={domain}>{reveal && <DomainMark api={ANALYZER_API} domain={domain} />}<SensitiveValue name="domain" value={domain} reveal={reveal} force /></span>)}</div> : <p className="client-empty">No domain evidence attributed to this MAC.</p>}</section>
    {cellSite && <section className="mobile-ue-section"><h3>Mobile UE sessions <span>{ueSessions.length}</span></h3><button className={`ue-expand-toggle ${uesExpanded ? "active" : ""}`} onClick={onToggleUes}><Smartphone size={14} />{uesExpanded ? "Hide UEs on graph" : ueSessions.length > 80 ? "Show first 80 UEs on graph" : "Show UEs on graph"}</button>{ueSessions.length ? <div className="mobile-ue-list">{ueSessions.map((session) => <div key={session.ip}><span className="mobile-ue-icon"><Smartphone size={13} /></span><span><b><SensitiveValue name="ip" value={session.ip} reveal={reveal} /></b><small><SensitiveValue name="teid" value={session.teids.length ? session.teids.join(" · ") : "TEID unavailable"} reveal={reveal} /></small></span><span><b>{formatBytes(session.byte_count)}</b><small>{formatCount(session.packet_count)} packets</small></span></div>)}</div> : <p className="client-empty">No inner UE address was decoded from the visible GTP traffic.</p>}</section>}
    <section><h3>Connected nodes <span>{peers.length}</span></h3><div className="client-peers">{peers.slice(0, 12).map((peer) => <div key={peer.mac}><b><SensitiveValue name="mac" value={peer.mac.toUpperCase()} reveal={reveal} /></b><span><SensitiveValue name="ip" value={peer.ips[0] || peer.manufacturers?.[0] || "Observed peer"} reveal={reveal} /></span></div>)}</div></section>
    <section><h3>Recent evidence <span>{relatedEvents.length}</span></h3><EventList events={[...relatedEvents].sort((a, b) => b.time - a.time).slice(0, 12)} reveal={reveal} onInspect={onInspect} empty="No events attributed to this client" forceSensitive /></section>
  </aside>;
}

export function TopologyView({ model, nodes, events, reveal, currentTime, playbackActive, playbackSpeed, onInspect }: { model: CaptureModel; nodes: CaptureNode[]; events: CaptureEvent[]; reveal: boolean; currentTime: number; playbackActive: boolean; playbackSpeed: number; onInspect: (event: CaptureEvent) => void }) {
  const [includeIpOnly, setIncludeIpOnly] = useState(false);
  const [selectedMac, setSelectedMac] = useState<string | null>(null);
  const [expandedCellSite, setExpandedCellSite] = useState<string | null>(null);
  const graphNodes = useMemo(() => clientGraphNodes(nodes, includeIpOnly), [nodes, includeIpOnly]);
  const selectedClient = selectedMac ? model.nodes.find((node) => node.mac === selectedMac) : undefined;
  const visibleCount = graphNodes.filter((node) => node.first_seen <= currentTime).length;
  return <div className="network-workspace"><div className="network-toolbar"><div><b>GPON client network</b><span>{visibleCount} of {graphNodes.length} nodes at {formatTime(currentTime)}</span></div><select aria-label="Select client profile" value={selectedMac ?? ""} onChange={(event) => setSelectedMac(event.target.value || null)}><option value="">Select client profile…</option>{graphNodes.map((node) => <option key={node.mac} value={node.mac}>{privateText(node.mac.toUpperCase(), reveal)} · {node.ips[0] ? privateText(node.ips[0], reveal) : node.manufacturers?.[0] || "Observed endpoint"}</option>)}</select><label><input type="checkbox" checked={includeIpOnly} onChange={(event) => setIncludeIpOnly(event.target.checked)} /> Include IP-only endpoints</label><span>Click a node to open its profile</span></div><div className={`topology-wrap ${selectedClient ? "with-client-profile" : ""}`}><ReactFlowProvider><TopologyCanvas model={model} endpoints={graphNodes} reveal={reveal} currentTime={currentTime} events={events} playbackActive={playbackActive} playbackSpeed={playbackSpeed} expandedCellSite={expandedCellSite} onSelect={setSelectedMac} /></ReactFlowProvider><div className="graph-caption"><span className="regular-key" /> GPON <span className="gtp-key" /> probable cell site · size = traffic · hover for identity</div>{selectedClient && <ClientProfile client={selectedClient} model={model} events={events} reveal={reveal} currentTime={currentTime} uesExpanded={expandedCellSite === selectedClient.mac} onToggleUes={() => setExpandedCellSite((value) => value === selectedClient.mac ? null : selectedClient.mac)} onClose={() => { setSelectedMac(null); setExpandedCellSite(null); }} onInspect={onInspect} />}</div></div>;
}
