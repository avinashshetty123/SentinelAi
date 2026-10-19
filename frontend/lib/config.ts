// Public configuration only. NEXT_PUBLIC_* values are embedded in the browser bundle: never put secrets here.
const DEFAULT_API_URL = "http://localhost:8000/api/v1";

export const API_URL = (process.env.NEXT_PUBLIC_API_URL || DEFAULT_API_URL).replace(/\/+$/, "");

export function websocketUrl(): string {
  const explicit = process.env.NEXT_PUBLIC_WS_URL;
  if (explicit) return explicit;
  return `${API_URL.replace(/^http/, "ws")}/ws/events`;
}
