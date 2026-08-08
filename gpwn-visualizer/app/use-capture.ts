"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ArtifactFilter } from "./event-ui";
import type { ArtifactPage, CaptureArtifact, CaptureEvent, CaptureModel, EventPage } from "./model";
import { mergeById } from "./model";

export const ANALYZER_API =
  process.env.NEXT_PUBLIC_ANALYZER_URL?.replace(/\/$/, "") ?? "/analyzer-api";

const PAGE_SIZE = 1000;
export const ANALYZER_RETRY_INTERVAL_MS = 3000;
export const ARTIFACT_POLL_INTERVAL_MS = 5000;

export type AnalyzerConnection = "connecting" | "local" | "error";
export type UiAlert = { id: number; message: string };

let nextAlertId = 1;

export function shouldPollArtifacts(complete: boolean, lastPoll: number, now: number) {
  return !complete && (lastPoll === 0 || now - lastPoll >= ARTIFACT_POLL_INTERVAL_MS);
}

function artifactCategory(filter: ArtifactFilter) {
  if (filter === "all") return "visible";
  if (filter === "download") return "other";
  return filter;
}

async function requestJson<T>(url: string, timeout = 5000): Promise<T> {
  const response = await fetch(url, {
    cache: "no-store",
    signal: AbortSignal.timeout(timeout),
  });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`.trim());
  return (await response.json()) as T;
}

export function useCapture() {
  const [model, setModel] = useState<CaptureModel | null>(null);
  const [events, setEvents] = useState<CaptureEvent[]>([]);
  const [artifacts, setArtifacts] = useState<CaptureArtifact[]>([]);
  const [artifactTotal, setArtifactTotal] = useState(0);
  const [artifactCounts, setArtifactCounts] = useState<Record<string, number>>({});
  const [artifactFilter, setArtifactFilterState] = useState<ArtifactFilter>("all");
  const [artifactsComplete, setArtifactsComplete] = useState(false);
  const [connection, setConnection] = useState<AnalyzerConnection>("connecting");
  const [loadingMore, setLoadingMore] = useState(false);
  const [alerts, setAlerts] = useState<UiAlert[]>([]);
  const hasLocalModel = useRef(false);
  const loadedEventWindows = useRef(new Set<string>());
  const artifactFilterRef = useRef<ArtifactFilter>("all");
  const artifactRequest = useRef(0);

  const reportError = useCallback((message: string) => {
    setAlerts((current) => current.some((alert) => alert.message === message)
      ? current
      : [...current, { id: nextAlertId++, message }]);
  }, []);

  const dismissAlert = useCallback((id: number) => {
    setAlerts((current) => current.filter((alert) => alert.id !== id));
  }, []);

  const applyArtifactPage = useCallback((page: ArtifactPage, replace: boolean) => {
    setArtifacts((current) => replace ? page.items : mergeById(current, page.items));
    setArtifactTotal(page.total);
    setArtifactCounts(page.counts ?? {});
    if (page.complete !== undefined) setArtifactsComplete(page.complete);
  }, []);

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    let eventsLoaded = false;
    let artifactIndexComplete = false;
    let lastArtifactPoll = 0;

    const load = async () => {
      try {
        let legacyAnalyzer = false;
        let response = await fetch(`${ANALYZER_API}/api/overview`, {
          cache: "no-store",
          signal: AbortSignal.timeout(5000),
        });
        if (response.status === 404) {
          legacyAnalyzer = true;
          response = await fetch(`${ANALYZER_API}/api/model`, {
            cache: "no-store",
            signal: AbortSignal.timeout(30000),
          });
        }
        if (!response.ok) throw new Error("Analyzer unavailable");
        const next = (await response.json()) as CaptureModel;
        if (!active) return;

        const firstLocalModel = !hasLocalModel.current;
        setModel(next);
        if (firstLocalModel) {
          setEvents(next.events ?? []);
          setArtifacts([]);
          setArtifactTotal(0);
          setArtifactsComplete(false);
        } else if (legacyAnalyzer) {
          setEvents((current) => mergeById(current, next.events ?? []));
        }
        hasLocalModel.current = true;
        setConnection("local");

        const now = Date.now();
        const pollArtifacts = shouldPollArtifacts(artifactIndexComplete, lastArtifactPoll, now);
        const requests: Array<Promise<void>> = [];
        if (!eventsLoaded) {
          requests.push(requestJson<EventPage>(`${ANALYZER_API}/api/events?offset=0&limit=${PAGE_SIZE}`)
            .then((page) => {
              if (!active) return;
              eventsLoaded = true;
              setEvents((current) => mergeById(current, page.items));
            })
            .catch(() => reportError("Could not load the analyzer event index. Retry after the analyzer is ready.")));
        }
        if (pollArtifacts) {
          lastArtifactPoll = now;
          const filter = artifactFilterRef.current;
          requests.push(requestJson<ArtifactPage>(`${ANALYZER_API}/api/artifacts?offset=0&limit=${PAGE_SIZE}&category=${artifactCategory(filter)}`)
            .then((page) => {
              if (!active || filter !== artifactFilterRef.current) return;
              applyArtifactPage(page, true);
              artifactIndexComplete = page.complete ?? next.status === "ready";
            })
            .catch(() => reportError("Could not load recovered files from the analyzer.")));
        }
        await Promise.all(requests);
        timer = setTimeout(load, legacyAnalyzer ? 15000 : next.mode === "live" ? 900 : ANALYZER_RETRY_INTERVAL_MS);
      } catch {
        if (!active) return;
        setConnection("error");
        timer = setTimeout(load, ANALYZER_RETRY_INTERVAL_MS);
      }
    };

    void load();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [applyArtifactPage, reportError]);

  const setArtifactFilter = useCallback(async (filter: ArtifactFilter) => {
    artifactFilterRef.current = filter;
    setArtifactFilterState(filter);
    setArtifacts([]);
    setArtifactTotal(0);
    setLoadingMore(true);
    const requestId = ++artifactRequest.current;
    try {
      const page = await requestJson<ArtifactPage>(
        `${ANALYZER_API}/api/artifacts?offset=0&limit=${PAGE_SIZE}&category=${artifactCategory(filter)}`,
      );
      if (requestId === artifactRequest.current && filter === artifactFilterRef.current) {
        applyArtifactPage(page, true);
      }
    } catch {
      reportError("Could not apply the recovered-file filter.");
    } finally {
      if (requestId === artifactRequest.current) setLoadingMore(false);
    }
  }, [applyArtifactPage, reportError]);

  const loadMoreArtifacts = useCallback(async () => {
    setLoadingMore(true);
    const filter = artifactFilterRef.current;
    try {
      const page = await requestJson<ArtifactPage>(
        `${ANALYZER_API}/api/artifacts?offset=${artifacts.length}&limit=${PAGE_SIZE}&category=${artifactCategory(filter)}`,
      );
      if (filter === artifactFilterRef.current) applyArtifactPage(page, false);
    } catch {
      reportError("Could not load more recovered files.");
    } finally {
      setLoadingMore(false);
    }
  }, [applyArtifactPage, artifacts.length, reportError]);

  const loadEventWindow = useCallback(async (from: number, to: number) => {
    if (!hasLocalModel.current) return;
    const start = Math.max(0, Math.floor(from / 10) * 10);
    const end = Math.max(start + 10, Math.ceil(to / 10) * 10);
    const key = `${start}-${end}`;
    if (loadedEventWindows.current.has(key)) return;
    loadedEventWindows.current.add(key);
    try {
      const page = await requestJson<EventPage>(
        `${ANALYZER_API}/api/events?offset=0&limit=${PAGE_SIZE}&from=${start}&to=${end}`,
      );
      setEvents((current) => mergeById(current, page.items));
    } catch {
      loadedEventWindows.current.delete(key);
      reportError("Could not load events for this part of the timeline.");
    }
  }, [reportError]);

  return {
    model,
    events,
    artifacts,
    artifactTotal,
    artifactCounts,
    artifactFilter,
    artifactsComplete,
    connection,
    setArtifactFilter,
    loadMoreArtifacts,
    loadEventWindow,
    loadingMore,
    alerts,
    dismissAlert,
  };
}
