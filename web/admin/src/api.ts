export interface LoginResponse {
  user: {
    id: string;
    username: string;
    email: string;
    full_name: string;
    role: string;
  };
  tokens: {
    access_token: string;
    refresh_token: string;
  };
}

export interface MessageRecord {
  id: number;
  direction: string;
  sender: string;
  recipients: string[];
  source_ip: string;
  policy_action: string;
  policy_score: number;
  observed_at: string;
}

const API_BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? "http://localhost:8080/api/v1";

export async function login(username: string, password: string): Promise<LoginResponse> {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });
  if (!res.ok) {
    throw new Error("Login failed");
  }
  return (await res.json()) as LoginResponse;
}

export async function listMessages(accessToken: string, direction = ""): Promise<MessageRecord[]> {
  const query = direction ? `?direction=${encodeURIComponent(direction)}` : "";
  const res = await fetch(`${API_BASE}/messages${query}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  });
  if (!res.ok) {
    throw new Error("Failed to load messages");
  }
  return (await res.json()) as MessageRecord[];
}

export async function listEvents(accessToken: string): Promise<Array<Record<string, unknown>>> {
  const res = await fetch(`${API_BASE}/events`, {
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  });
  if (!res.ok) {
    throw new Error("Failed to load events");
  }
  return (await res.json()) as Array<Record<string, unknown>>;
}
