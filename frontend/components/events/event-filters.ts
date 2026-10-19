import type { RiskLevel, SecurityEvent } from "@/types/api";

export interface EventFilterState {
  severity: RiskLevel | "";
  event_type: string;
  source: string;
  q: string;
}

export const EMPTY_FILTERS: EventFilterState = { severity: "", event_type: "", source: "", q: "" };

/** Client-side mirror of the server filters, used to decide whether a live WebSocket event belongs in the view. */
export function matchesFilters(event: SecurityEvent, f: EventFilterState): boolean {
  if (f.severity && event.severity !== f.severity) return false;
  if (f.event_type && event.event_type !== f.event_type) return false;
  if (f.source && event.source !== f.source) return false;
  if (f.q) {
    const q = f.q.trim().toLowerCase();
    if (q && !event.description.toLowerCase().includes(q) && !event.actor.toLowerCase().includes(q)) return false;
  }
  return true;
}
