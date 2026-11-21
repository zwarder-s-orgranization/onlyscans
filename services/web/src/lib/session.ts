import type { UserRole } from "@/data/workflows-workspace-data";

const KEY = "secflow.session";

export interface Session {
  accessToken: string;
  email: string;
  role: UserRole;
  expiresAt: string;
  subject?: string;
  authMode?: string;
}

export function readSession(): Session | null {
  if (typeof window === "undefined") return null;
  const raw = window.localStorage.getItem(KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Session;
    if (!parsed.accessToken || !parsed.email) return null;
    if (parsed.expiresAt && Date.parse(parsed.expiresAt) < Date.now()) {
      window.localStorage.removeItem(KEY);
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function writeSession(session: Session) {
  window.localStorage.setItem(KEY, JSON.stringify(session));
  window.dispatchEvent(new Event("secflow-auth"));
}

export function clearSession() {
  window.localStorage.removeItem(KEY);
  window.dispatchEvent(new Event("secflow-auth"));
}

export function authToken(): string | null {
  return readSession()?.accessToken ?? null;
}
