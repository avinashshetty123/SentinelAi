"use client";

import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { getToken, onTokenChange } from "@/lib/auth";
import { websocketUrl } from "@/lib/config";
import type { DemoRun, SecurityEvent, SimulatorStatus } from "@/types/api";

export type StreamStatus = "connecting" | "open" | "reconnecting" | "unauthorized" | "offline";

export interface StreamMessage {
  type: string;
  at?: string;
  data?: unknown;
}

interface EventStreamValue {
  status: StreamStatus;
  liveEvents: SecurityEvent[];
  lastMessageAt: string | null;
  reconnect: () => void;
}

const EventStreamContext = createContext<EventStreamValue | null>(null);
const MAX_LIVE_EVENTS = 100;
const MAX_BACKOFF_MS = 15_000;

/** Single shared WebSocket for the whole app. Persisted events arrive here and refresh cached queries. */
export function EventStreamProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<StreamStatus>("connecting");
  const [liveEvents, setLiveEvents] = useState<SecurityEvent[]>([]);
  const [lastMessageAt, setLastMessageAt] = useState<string | null>(null);
  const [generation, setGeneration] = useState(0);
  const pendingInvalidations = useRef<Set<string>>(new Set());
  const flushTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const invalidate = useCallback(
    (...keys: string[]) => {
      keys.forEach((k) => pendingInvalidations.current.add(k));
      if (flushTimer.current) return;
      // Coalesce bursts (e.g. the simulator) into one refetch wave.
      flushTimer.current = setTimeout(() => {
        const toRefresh = Array.from(pendingInvalidations.current);
        pendingInvalidations.current.clear();
        flushTimer.current = null;
        toRefresh.forEach((key) => queryClient.invalidateQueries({ queryKey: [key] }));
      }, 400);
    },
    [queryClient],
  );

  const handleMessage = useCallback(
    (message: StreamMessage) => {
      setLastMessageAt(new Date().toISOString());
      switch (message.type) {
        case "event.created": {
          const event = message.data as SecurityEvent;
          setLiveEvents((prev) => [event, ...prev.filter((e) => e.id !== event.id)].slice(0, MAX_LIVE_EVENTS));
          invalidate("events", "dashboard");
          break;
        }
        case "event.updated": {
          const event = message.data as SecurityEvent;
          setLiveEvents((prev) => prev.map((e) => (e.id === event.id ? event : e)));
          invalidate("events", "incident");
          break;
        }
        case "incident.created":
        case "incident.updated":
          invalidate("incidents", "incident", "dashboard");
          break;
        case "scan.created":
          invalidate("scans", "dashboard");
          break;
        case "demo.progress": {
          const run = message.data as DemoRun;
          queryClient.setQueryData(["demo-status", run.scenario_id], { scenario_id: run.scenario_id, run });
          break;
        }
        case "simulator.status":
          queryClient.setQueryData(["simulator"], message.data as SimulatorStatus);
          break;
        case "demo.reset":
          setLiveEvents((prev) => prev.filter((e) => e.source === "application"));
          queryClient.invalidateQueries();
          break;
        default:
          break;
      }
    },
    [invalidate, queryClient],
  );

  useEffect(() => {
    let socket: WebSocket | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let attempts = 0;
    let disposed = false;

    const connect = () => {
      if (disposed) return;
      setStatus(attempts === 0 ? "connecting" : "reconnecting");
      try {
        socket = new WebSocket(websocketUrl());
      } catch {
        scheduleRetry();
        return;
      }
      socket.onopen = () => {
        const token = getToken();
        if (token) socket?.send(JSON.stringify({ type: "auth", token }));
      };
      socket.onmessage = (ev) => {
        let message: StreamMessage;
        try {
          message = JSON.parse(String(ev.data));
        } catch {
          return;
        }
        if (message.type === "hello") {
          attempts = 0;
          setStatus("open");
          // Catch up on anything missed while disconnected.
          queryClient.invalidateQueries();
          return;
        }
        if (message.type === "ping") {
          socket?.send(JSON.stringify({ type: "pong" }));
          return;
        }
        handleMessage(message);
      };
      socket.onclose = (ev) => {
        socket = null;
        if (disposed) return;
        if (ev.code === 4401) {
          setStatus("unauthorized");
          return; // wait for a token change
        }
        scheduleRetry();
      };
      socket.onerror = () => socket?.close();
    };

    const scheduleRetry = () => {
      if (disposed) return;
      attempts += 1;
      setStatus(attempts > 6 ? "offline" : "reconnecting");
      const delay = Math.min(MAX_BACKOFF_MS, 1000 * 2 ** Math.min(attempts - 1, 4)) + Math.random() * 500;
      retryTimer = setTimeout(connect, delay);
    };

    connect();
    const unsubscribe = onTokenChange(() => setGeneration((g) => g + 1));
    return () => {
      disposed = true;
      unsubscribe();
      if (retryTimer) clearTimeout(retryTimer);
      socket?.close();
    };
  }, [generation, handleMessage, queryClient]);

  const value = useMemo<EventStreamValue>(
    () => ({ status, liveEvents, lastMessageAt, reconnect: () => setGeneration((g) => g + 1) }),
    [status, liveEvents, lastMessageAt],
  );
  return <EventStreamContext.Provider value={value}>{children}</EventStreamContext.Provider>;
}

export function useEventStream(): EventStreamValue {
  const ctx = useContext(EventStreamContext);
  if (!ctx) throw new Error("useEventStream must be used inside EventStreamProvider");
  return ctx;
}

/** Polling fallback: refetch periodically only while the live stream is down. */
export function useFallbackInterval(ms = 15_000): number | false {
  const { status } = useEventStream();
  return status === "open" ? false : ms;
}
