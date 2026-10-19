// Operator token storage (only used when the backend runs with AUTH_MODE=token).
// sessionStorage: cleared when the tab closes; never sent as a cookie, so no CSRF exposure.
const KEY = "sentinel.operatorToken";
const listeners = new Set<() => void>();

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.sessionStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null): void {
  try {
    if (token) window.sessionStorage.setItem(KEY, token);
    else window.sessionStorage.removeItem(KEY);
  } catch {
    // storage unavailable (private mode); token stays in memory only for this call
  }
  listeners.forEach((fn) => fn());
}

export function onTokenChange(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}
