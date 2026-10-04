const API_BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? "http://localhost:8080/api/v1";

export interface QuarantineMessage {
  id: string;
  from: string;
  to: string[];
  subject: string;
  reason: string;
  received_at: string;
  status: string;
}

export async function login(username: string, password: string): Promise<string> {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });
  if (!res.ok) {
    throw new Error("Login failed");
  }
  const data = (await res.json()) as { tokens: { access_token: string } };
  return data.tokens.access_token;
}

export async function listQuarantine(accessToken: string): Promise<QuarantineMessage[]> {
  const res = await fetch(`${API_BASE}/quarantine/messages`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  if (!res.ok) {
    throw new Error("Unable to load quarantine");
  }
  return (await res.json()) as QuarantineMessage[];
}

export async function releaseMessage(accessToken: string, id: string): Promise<void> {
  const res = await fetch(`${API_BASE}/quarantine/messages/${id}/release`, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  if (!res.ok) {
    throw new Error("Release failed");
  }
}
