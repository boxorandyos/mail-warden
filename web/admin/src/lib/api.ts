export type SessionUser = {
  id: string;
  username: string;
  email: string;
  full_name: string;
  role: "admin" | "moderator" | "viewer" | string;
  language?: string;
  timezone?: string;
  totp_enabled?: boolean;
  auth_provider?: string;
  enabled?: boolean;
};

export type TokenPair = {
  access_token: string;
  refresh_token: string;
  session_id?: string;
};

export type LoginResponse = {
  user?: SessionUser;
  tokens?: TokenPair;
  require_password_change?: boolean;
  requires_2fa?: boolean;
  require_2fa_setup?: boolean;
  user_id?: string;
  temp_token?: string;
};

const ACCESS = "accessToken";
const REFRESH = "refreshToken";
const USER = "user";

export function loadStoredUser(): SessionUser | null {
  try {
    const raw = localStorage.getItem(USER);
    return raw ? (JSON.parse(raw) as SessionUser) : null;
  } catch {
    return null;
  }
}

export function persistSession(user: SessionUser, tokens: TokenPair) {
  localStorage.setItem(ACCESS, tokens.access_token);
  localStorage.setItem(REFRESH, tokens.refresh_token);
  localStorage.setItem(USER, JSON.stringify(user));
}

export function clearSession() {
  localStorage.removeItem(ACCESS);
  localStorage.removeItem(REFRESH);
  localStorage.removeItem(USER);
}

export function accessToken() {
  return localStorage.getItem(ACCESS) ?? "";
}

async function readBody(res: Response): Promise<string> {
  const text = await res.text();
  if (!text) return res.statusText;
  try {
    const parsed = JSON.parse(text) as { error?: string; message?: string };
    return parsed.error || parsed.message || text;
  } catch {
    return text;
  }
}

let refreshing: Promise<boolean> | null = null;

async function refreshTokens(): Promise<boolean> {
  const token = localStorage.getItem(REFRESH);
  if (!token) return false;
  const res = await fetch("/api/v1/auth/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: token })
  });
  if (!res.ok) return false;
  const data = (await res.json()) as TokenPair;
  if (!data.access_token) return false;
  localStorage.setItem(ACCESS, data.access_token);
  if (data.refresh_token) localStorage.setItem(REFRESH, data.refresh_token);
  return true;
}

type ApiOptions = RequestInit & { skipAuth?: boolean; retried?: boolean };

export async function api<T>(path: string, options: ApiOptions = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (!options.skipAuth && accessToken()) headers.set("Authorization", `Bearer ${accessToken()}`);
  const res = await fetch(path, { ...options, headers });
  if (res.status === 401 && !options.skipAuth && !options.retried) {
    refreshing ??= refreshTokens().finally(() => {
      refreshing = null;
    });
    const ok = await refreshing;
    if (ok) return api<T>(path, { ...options, retried: true });
    clearSession();
    if (!window.location.pathname.startsWith("/login")) {
      const redirect = encodeURIComponent(window.location.pathname + window.location.search);
      window.location.assign(`/login?redirect=${redirect}`);
    }
    throw new Error("session expired");
  }
  if (!res.ok) throw new Error(await readBody(res));
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export async function publicPost<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(await readBody(res));
  return (await res.json()) as T;
}
