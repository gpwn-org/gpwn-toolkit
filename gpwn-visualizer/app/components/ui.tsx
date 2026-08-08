"use client";

import { useState } from "react";
import { AlertTriangle, ChevronRight, RadioTower, X } from "lucide-react";
import {
  DomainMark,
  FamilyIcon,
  classifyEvent,
  displayValue,
  domainFromEvent,
  eventContainsSensitiveData,
  familyLabels,
  isSensitiveKey,
  kindLabel,
  maskValue,
} from "../event-ui";
import type { CaptureEvent } from "../model";
import { ANALYZER_API, type UiAlert } from "../use-capture";

export function formatTime(seconds: number) {
  const safe = Math.max(0, Number.isFinite(seconds) ? seconds : 0);
  const hours = Math.floor(safe / 3600);
  const minutes = Math.floor((safe % 3600) / 60);
  const secs = Math.floor(safe % 60);
  return `${hours ? `${hours}:` : ""}${String(minutes).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
}

export const formatCount = (count: number) =>
  new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(count);

export function SensitiveValue({ name, value, reveal, force = false }: {
  name: string;
  value: unknown;
  reveal: boolean;
  force?: boolean;
}) {
  const sensitive = force || isSensitiveKey(name);
  const shown = sensitive && !reveal ? maskValue(value) : displayValue(value);
  return <span className={sensitive && !reveal ? "masked" : ""}>{shown}</span>;
}

export function EmptyState({ title, detail = "No matching packet evidence has been indexed." }: { title: string; detail?: string }) {
  return <div className="empty-state"><RadioTower size={28} /><strong>{title}</strong><span>{detail}</span></div>;
}

export function SectionHead({ eyebrow, title, copy }: { eyebrow: string; title: string; copy: string }) {
  return <div className="section-head"><div><span className="eyebrow">{eyebrow}</span><h1>{title}</h1><p>{copy}</p></div></div>;
}

export function AnalyzerUnavailable() {
  return <main className="loading-screen error-screen"><div className="analyzer-error-mark">!</div><p>Analyzer unavailable</p><span>Start the local GPWN analyzer. Signal Map will reconnect automatically.</span><code>{ANALYZER_API}</code></main>;
}

export function AlertStack({ alerts, onDismiss }: { alerts: UiAlert[]; onDismiss: (id: number) => void }) {
  if (!alerts.length) return null;
  return <div className="alert-stack" role="region" aria-label="Analyzer alerts">{alerts.map((alert) => <div className="error-alert" role="alert" key={alert.id}><AlertTriangle size={18} /><span>{alert.message}</span><button onClick={() => onDismiss(alert.id)} aria-label="Dismiss alert"><X size={15} /></button></div>)}</div>;
}

export function EvidencePanel({ event, reveal, onClose }: { event: CaptureEvent; reveal: boolean; onClose: () => void }) {
  const family = classifyEvent(event);
  const sensitive = eventContainsSensitiveData(event);
  return <aside className="evidence-panel" aria-label="Packet evidence">
    <div className="evidence-head"><div className={`family-icon family-${family}`}><FamilyIcon family={family} /></div><div><span className="eyebrow">Packet evidence</span><h2><SensitiveValue name="title" value={event.title} reveal={reveal} force={sensitive} /></h2></div><button className="icon-button" onClick={onClose} aria-label="Close evidence"><X size={17} /></button></div>
    <p className="evidence-summary"><SensitiveValue name="summary" value={event.summary} reveal={reveal} force={sensitive} /></p>
    <dl className="evidence-provenance"><div><dt>Source</dt><dd><SensitiveValue name="source_file" value={event.source_file || "Current capture"} reveal={reveal} /></dd></div><div><dt>Frame</dt><dd>#{event.frame || "—"}</dd></div><div><dt>Capture time</dt><dd>{formatTime(event.time)}</dd></div><div><dt>Parser</dt><dd>{event.protocol || familyLabels[family]}</dd></div>{event.confidence !== undefined && <div><dt>Confidence</dt><dd>{displayValue(event.confidence)}</dd></div>}</dl>
    <div className="evidence-fields"><h3>Decoded fields</h3>{Object.entries(event.details ?? {}).map(([key, value]) => <div key={key}><span>{kindLabel(key)}</span><code><SensitiveValue name={key} value={value} reveal={reveal} force={eventContainsSensitiveData(event)} /></code></div>)}{!Object.keys(event.details ?? {}).length && <p>No additional decoded fields.</p>}</div>
  </aside>;
}

export function EventCard({ event, reveal, onInspect, forceSensitive = false }: { event: CaptureEvent; reveal: boolean; onInspect?: (event: CaptureEvent) => void; forceSensitive?: boolean }) {
  const family = classifyEvent(event);
  const sensitive = forceSensitive || eventContainsSensitiveData(event);
  const domain = ["dns", "tls", "http"].includes(family) ? domainFromEvent(event) : undefined;
  return <article className={`event-card severity-${event.severity || "info"}`} data-family={family}>
    <div className={`family-icon family-${family}`}>{domain && reveal ? <DomainMark api={ANALYZER_API} domain={domain} /> : <FamilyIcon family={family} />}</div>
    <div className="event-copy"><div className="event-meta"><b>{familyLabels[family]}</b><span>{formatTime(event.time)}</span><span>frame {event.frame || "—"}</span>{event.confidence !== undefined && <span>{displayValue(event.confidence)} confidence</span>}</div><h3><SensitiveValue name="title" value={event.title || kindLabel(event.kind)} reveal={reveal} force={sensitive} /></h3><p><SensitiveValue name="summary" value={event.summary} reveal={reveal} force={sensitive} /></p><div className="event-chips">{Object.entries(event.details ?? {}).slice(0, 3).map(([key, value]) => <span key={key}><i>{kindLabel(key)}</i> <SensitiveValue name={key} value={value} reveal={reveal} force={sensitive} /></span>)}</div></div>
    {onInspect && <button className="inspect-button" onClick={() => onInspect(event)} aria-label={`Inspect ${sensitive && !reveal ? kindLabel(event.kind) : event.title}`}><ChevronRight size={18} /></button>}
  </article>;
}

export function EventList({ events, reveal, onInspect, empty, forceSensitive = false }: { events: CaptureEvent[]; reveal: boolean; onInspect: (event: CaptureEvent) => void; empty: string; forceSensitive?: boolean }) {
  const [visibleLimit, setVisibleLimit] = useState(160);
  if (!events.length) return <EmptyState title={empty} />;
  return <div className="event-list">{events.slice(0, visibleLimit).map((event) => <EventCard key={event.id} event={event} reveal={reveal} onInspect={onInspect} forceSensitive={forceSensitive} />)}{events.length > visibleLimit && <button className="load-more" onClick={() => setVisibleLimit((value) => value + 160)}>Show {Math.min(160, events.length - visibleLimit)} more matching events</button>}</div>;
}
