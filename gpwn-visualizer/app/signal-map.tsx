"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Eye, EyeOff, Files, Network, Pause, Play, RotateCcw, Search, ShieldAlert, Users, X } from "lucide-react";
import { MediaView } from "./components/media-view";
import { TopologyView } from "./components/topology-view";
import { AlertStack, AnalyzerUnavailable, EvidencePanel, formatCount, formatTime } from "./components/ui";
import { LeaksView, SubscribersView } from "./components/workspace-views";
import { DEFAULT_REVEAL_SENSITIVE, displayValue } from "./event-ui";
import type { CaptureEvent, WorkspaceId } from "./model";
import { playbackStart, playbackTime, timelinePercent } from "./timeline";
import { useCapture } from "./use-capture";

export { ArtifactCard } from "./components/media-view";
export { AnalyzerUnavailable, EventCard } from "./components/ui";
export { formatTime } from "./components/ui";

const workspaceMeta: Array<{ id: WorkspaceId; label: string; short: string; icon: typeof Network }> = [
  { id: "topology", label: "GPON network", short: "Network", icon: Network },
  { id: "subscribers", label: "Client profiles", short: "Profiles", icon: Users },
  { id: "leaks", label: "Data leaks", short: "Leaks", icon: ShieldAlert },
  { id: "media", label: "Media & files", short: "Media", icon: Files },
];

function eventSearchText(event: CaptureEvent) {
  return [event.kind, event.protocol, event.title, event.summary, event.node, event.peer, event.source_file, ...Object.values(event.details ?? {}).map(displayValue)].join(" ").toLowerCase();
}

export default function Home() {
  const capture = useCapture();
  const { model, artifacts, connection, loadMoreArtifacts, loadEventWindow, loadingMore } = capture;
  const [workspace, setWorkspace] = useState<WorkspaceId>("topology");
  const [selectedEvent, setSelectedEvent] = useState<CaptureEvent | null>(null);
  const [search, setSearch] = useState("");
  const [reveal, setReveal] = useState(DEFAULT_REVEAL_SENSITIVE);
  const [cursor, setCursor] = useState<number | null>(null);
  const [playing, setPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(4);
  const cursorRef = useRef<number | null>(null);
  const captureDuration = model?.duration ?? 0;
  const captureMode = model?.mode;

  useEffect(() => { cursorRef.current = cursor; }, [cursor]);
  useEffect(() => {
    if (!playing || captureMode === "live" || captureDuration <= 0) return;
    const start = playbackStart(cursorRef.current, captureDuration);
    if (cursorRef.current !== start) { cursorRef.current = 0; setCursor(0); }
    const startedAt = Date.now();
    const tick = () => {
      const next = playbackTime(start, Date.now() - startedAt, playbackSpeed, captureDuration);
      cursorRef.current = next;
      setCursor(next);
      if (next >= captureDuration) setPlaying(false);
    };
    const timer = window.setInterval(tick, 100);
    tick();
    return () => window.clearInterval(timer);
  }, [playing, playbackSpeed, captureDuration, captureMode]);

  const playbackBucket = cursor === null ? null : Math.floor(cursor / 10);
  useEffect(() => {
    if (connection !== "local" || playbackBucket === null) return;
    const start = playbackBucket * 10;
    void loadEventWindow(start, Math.min(captureDuration, start + 20));
  }, [connection, playbackBucket, captureDuration, loadEventWindow]);

  const visibleEvents = useMemo(() => {
    const time = cursor ?? model?.duration ?? 0;
    const query = search.trim().toLowerCase();
    return capture.events.filter((event) => event.time <= time && (!query || eventSearchText(event).includes(query)));
  }, [capture.events, cursor, model?.duration, search]);

  const matchingNodes = useMemo(() => {
    if (!model) return [];
    const query = search.trim().toLowerCase();
    if (!query) return model.nodes;
    return model.nodes.filter((node) => [node.mac, ...node.ips, ...node.hostnames, ...node.manufacturers].join(" ").toLowerCase().includes(query));
  }, [model, search]);

  const matchingArtifacts = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return artifacts;
    return artifacts.filter((artifact) => [artifact.name, artifact.media_type, artifact.sha256, artifact.source_file, artifact.frame].map(displayValue).join(" ").toLowerCase().includes(query));
  }, [artifacts, search]);

  const timelineEvents = useMemo(() => {
    const query = search.trim().toLowerCase();
    return capture.events.filter((event) => !query || eventSearchText(event).includes(query));
  }, [capture.events, search]);

  if (connection === "error") return <AnalyzerUnavailable />;
  if (!model) return <main className="loading-screen"><div className="radar-loader"><i /></div><p>Connecting to the analyzer…</p><span>Reading packet capture data from the local analyzer</span></main>;

  const activeEvents = visibleEvents;
  const protocolCount = new Set(activeEvents.map((event) => event.protocol).filter(Boolean)).size;
  const currentTime = cursor ?? model.duration;

  return <main className="app-shell">
    <header className="controlbar"><button className="brand compact" onClick={() => setWorkspace("topology")} aria-label="Open GPON network"><span className="brand-mark"><i /></span><strong>GPWN</strong></button><nav className="workspace-nav" aria-label="Capture workspaces">{workspaceMeta.map((item) => { const Icon = item.icon; return <button key={item.id} className={workspace === item.id ? "active" : ""} onClick={() => setWorkspace(item.id)} title={item.label} aria-label={item.label}><Icon size={15} /><span>{item.short}</span></button>; })}</nav><label className="global-search"><Search size={15} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search MAC, IP, hostname, domain or identity…" />{search && <button onClick={() => setSearch("")} aria-label="Clear search"><X size={14} /></button>}</label><div className="toolbar-stats" title={`${model.packet_count.toLocaleString()} packets · ${activeEvents.length.toLocaleString()} visible events · ${protocolCount} protocols`}><b>{formatCount(model.nodes.length)}</b><span>nodes</span><b>{formatCount(activeEvents.length)}</b><span>events</span></div><button className={`sensitive-toggle ${reveal ? "revealed" : ""}`} onClick={() => setReveal((value) => !value)} title={reveal ? "Hide sensitive values" : "Show sensitive values"}>{reveal ? <Eye size={15} /> : <EyeOff size={15} />}<span>{reveal ? "Shown" : "Masked"}</span></button><div className="source-state" title={model.source}><span className={`status-light ${model.mode}`} /><div><strong>{model.source}</strong><span>{model.mode === "live" ? "Following full file" : `${model.status} · full file`}</span></div></div></header>
    <AlertStack alerts={capture.alerts} onDismiss={capture.dismissAlert} />
    <div className={`content-shell ${selectedEvent ? "with-evidence" : ""}`}><section className="content-main">{search && <div className="search-context"><Search size={14} /><span>Showing capture evidence matching <b>“{search}”</b></span><strong>{activeEvents.length} events · {matchingNodes.length} endpoints</strong></div>}{workspace === "subscribers" && <SubscribersView nodes={matchingNodes} events={activeEvents} reveal={reveal} onInspect={setSelectedEvent} />}{workspace === "leaks" && <LeaksView events={activeEvents} reveal={reveal} onInspect={setSelectedEvent} />}{workspace === "media" && <MediaView artifacts={matchingArtifacts} events={activeEvents} reveal={reveal} onInspect={setSelectedEvent} total={search ? matchingArtifacts.length : capture.artifactTotal} counts={capture.artifactCounts} filter={capture.artifactFilter} onFilterChange={(filter) => void capture.setArtifactFilter(filter)} loadMore={() => void loadMoreArtifacts()} loading={loadingMore} complete={capture.artifactsComplete} />}{workspace === "topology" && <TopologyView model={model} nodes={matchingNodes} events={activeEvents} reveal={reveal} currentTime={currentTime} playbackActive={cursor !== null} playbackSpeed={playbackSpeed} onInspect={setSelectedEvent} />}</section>{selectedEvent && <EvidencePanel event={selectedEvent} reveal={reveal} onClose={() => setSelectedEvent(null)} />}</div>
    <footer className="timebar"><button className="play-button" disabled={model.mode === "live"} onClick={() => setPlaying((value) => !value)} aria-label={playing ? "Pause timeline" : "Play timeline"}>{playing ? <Pause size={16} /> : <Play size={16} />}</button><button className="restart-button" disabled={model.mode === "live"} onClick={() => { setPlaying(false); setCursor(0); }} aria-label="Restart timeline"><RotateCcw size={14} /></button><select value={playbackSpeed} onChange={(event) => setPlaybackSpeed(Number(event.target.value))} aria-label="Playback speed"><option value="1">1×</option><option value="4">4×</option><option value="16">16×</option><option value="64">64×</option></select><b>{formatTime(currentTime)}</b><div className="timebar-track"><div className="timeline-progress" style={{ width: timelinePercent(currentTime, model.duration) }} />{timelineEvents.slice(-1000).map((event) => <i key={event.id} className={`severity-${event.severity}`} style={{ left: timelinePercent(event.time, model.duration) }} />)}<input aria-label="Capture playhead" type="range" min="0" max={Math.max(model.duration, .001)} step=".01" value={currentTime} onChange={(event) => { setPlaying(false); setCursor(Number(event.target.value)); }} /></div><b>{formatTime(model.duration)}</b><button className="jump-button" onClick={() => { setPlaying(false); setCursor(null); }} aria-label="Jump to live edge">End</button></footer>
  </main>;
}
