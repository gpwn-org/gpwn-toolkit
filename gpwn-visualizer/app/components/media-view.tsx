"use client";

/* eslint-disable @next/next/no-img-element */
import { createElement, useState } from "react";
import { Archive, FileText, Files, Image as ImageIcon, Music, Package, Video } from "lucide-react";
import { artifactIcon, artifactPresentation, classifyEvent, formatBytes, type ArtifactFilter } from "../event-ui";
import type { CaptureArtifact, CaptureEvent } from "../model";
import { ANALYZER_API } from "../use-capture";
import { EmptyState, EventList, SectionHead, formatCount } from "./ui";

const FILTERS: Array<[ArtifactFilter, string, typeof Files, string]> = [
  ["all", "All", Files, "visible"],
  ["image", "Images", ImageIcon, "image"],
  ["video", "Video", Video, "video"],
  ["audio", "Audio", Music, "audio"],
  ["text", "Text", FileText, "text"],
  ["archive", "Archives", Archive, "archive"],
  ["download", "Other", Package, "other"],
];

function artifactUrl(artifact: CaptureArtifact) {
  if (/^https?:\/\//i.test(artifact.url)) return artifact.url;
  return `${ANALYZER_API}${artifact.url.startsWith("/") ? "" : "/"}${artifact.url}`;
}

export function ArtifactCard({ artifact }: { artifact: CaptureArtifact }) {
  const presentation = artifactPresentation(artifact);
  const icon = (size: number) => createElement(artifactIcon(presentation), { size });
  const src = artifactUrl(artifact);
  return <article className="artifact-card" data-presentation={presentation}><div className="artifact-preview">{presentation === "image" && <img src={src} alt={artifact.name} loading="lazy" />}{presentation === "video" && <video controls preload="metadata" src={src}>Video playback is unavailable.</video>}{presentation === "audio" && <div className="audio-preview">{icon(34)}<audio controls preload="metadata" src={src}>Audio playback is unavailable.</audio></div>}{["text", "archive", "download"].includes(presentation) && <div className="safe-file">{icon(38)}<span>{presentation === "text" ? "Safe preview disabled" : "Download only"}</span></div>}</div><div className="artifact-meta"><div><b title={artifact.name}>{artifact.name}</b><span>{artifact.media_type} · {formatBytes(artifact.size)}</span></div><a href={src} download={artifact.name} aria-label={`Download ${artifact.name}`}>Download</a></div><div className="artifact-evidence"><span>{artifact.complete === false ? "Incomplete capture" : "Recovered object"}</span>{artifact.frame && <span>frame {artifact.frame}</span>}</div></article>;
}

export function MediaView({ artifacts, events, reveal, onInspect, total, counts, filter, onFilterChange, loadMore, loading, complete }: {
  artifacts: CaptureArtifact[];
  events: CaptureEvent[];
  reveal: boolean;
  onInspect: (event: CaptureEvent) => void;
  total: number;
  counts: Record<string, number>;
  filter: ArtifactFilter;
  onFilterChange: (filter: ArtifactFilter) => void;
  loadMore: () => void;
  loading: boolean;
  complete: boolean;
}) {
  const [visibleLimit, setVisibleLimit] = useState(120);
  const visibleArtifacts = artifacts.slice(0, visibleLimit);
  return <div className="workspace-view"><SectionHead eyebrow="Recovered objects" title="Media & files" copy="Browse images, recordings, documents, archives, and other files recovered from the capture." />
    <div className="media-filter-panel"><div className="media-filter-label"><span>File type</span><strong>{formatCount(total)} matching files</strong></div><div className="media-filters" aria-label="Filter recovered files">{FILTERS.map(([value, label, Icon, countKey]) => <button key={value} className={filter === value ? "active" : ""} aria-pressed={filter === value} disabled={loading && filter === value} onClick={() => { setVisibleLimit(120); onFilterChange(value); }}><Icon size={16} /><span>{label}</span><b>{formatCount(counts[countKey] ?? 0)}</b></button>)}</div></div>
    {loading && !artifacts.length ? <div className="media-loading"><i /><span>Loading recovered files…</span></div> : visibleArtifacts.length ? <div className="artifact-grid">{visibleArtifacts.map((artifact) => <ArtifactCard key={artifact.id} artifact={artifact} />)}</div> : <EmptyState title={complete ? "No recovered files found" : "Recovering media and files…"} detail={complete ? "Choose another file type or run artifact extraction on a capture with supported file traffic." : "Recovered files will appear here as the analyzer finishes processing the capture."} />}
    {artifacts.length > visibleLimit && <button className="load-more" onClick={() => setVisibleLimit((value) => value + 120)}>Show more loaded files</button>}
    {artifacts.length < total && visibleLimit >= artifacts.length && <button className="load-more" disabled={loading} onClick={loadMore}>{loading ? "Loading…" : `Load more files (${formatCount(total - artifacts.length)} remaining)`}</button>}
    <h2 className="section-divider">Media session evidence</h2><EventList events={events.filter((event) => classifyEvent(event) === "rtp")} reveal={reveal} onInspect={onInspect} empty="No RTP or RTCP sessions indexed" />
  </div>;
}
