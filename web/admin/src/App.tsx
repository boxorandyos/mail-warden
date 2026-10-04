import { FormEvent, useMemo, useState } from "react";
import { listEvents, listMessages, login, MessageRecord } from "./api";

type SessionState = {
  accessToken: string;
  username: string;
} | null;

export function App() {
  const [session, setSession] = useState<SessionState>(null);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [messages, setMessages] = useState<MessageRecord[]>([]);
  const [events, setEvents] = useState<Array<Record<string, unknown>>>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const grouped = useMemo(() => {
    const inbound = messages.filter((m) => m.direction === "inbound").length;
    const outbound = messages.filter((m) => m.direction === "outbound").length;
    const quarantined = messages.filter((m) => m.policy_action === "quarantine").length;
    return { inbound, outbound, quarantined };
  }, [messages]);

  async function handleLogin(e: FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const result = await login(username, password);
      setSession({ accessToken: result.tokens.access_token, username: result.user.username });
      const [loadedMessages, loadedEvents] = await Promise.all([
        listMessages(result.tokens.access_token),
        listEvents(result.tokens.access_token)
      ]);
      setMessages(loadedMessages);
      setEvents(loadedEvents);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  if (!session) {
    return (
      <main className="mw-auth-shell">
        <section className="mw-auth-card">
          <h1>Mail Warden</h1>
          <p>Administrative control plane</p>
          <form onSubmit={handleLogin} className="mw-form">
          <label>
            Username
              <input value={username} onChange={(e) => setUsername(e.target.value)} />
          </label>
          <label>
            Password
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
            <button type="submit" disabled={loading}>{loading ? "Signing in..." : "Sign in"}</button>
          </form>
          {error && <p className="mw-error">{error}</p>}
        </section>
      </main>
    );
  }

  return (
    <main className="mw-shell">
      <aside className="mw-sidebar">
        <div className="mw-sidebar-title">Mail Warden</div>
        <nav>
          <a className="active">Dashboard</a>
          <a>Messages</a>
          <a>Events</a>
          <a>Policy</a>
          <a>Identity</a>
          <a>Cluster</a>
        </nav>
      </aside>
      <section className="mw-main">
      <header className="mw-topbar">
        <h1>Admin Dashboard</h1>
        <strong>{session.username}</strong>
      </header>

      <section className="mw-stats">
        <StatCard label="Inbound Messages" value={grouped.inbound} />
        <StatCard label="Outbound Messages" value={grouped.outbound} />
        <StatCard label="Quarantined" value={grouped.quarantined} />
      </section>

      <section className="mw-panel">
        <h2>Message Tracking</h2>
        <table className="mw-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Direction</th>
              <th>Sender</th>
              <th>Action</th>
              <th>Score</th>
            </tr>
          </thead>
          <tbody>
            {messages.map((m) => (
              <tr key={m.id}>
                <td>{new Date(m.observed_at).toLocaleString()}</td>
                <td>{m.direction}</td>
                <td>{m.sender}</td>
                <td><span className={`mw-tag mw-tag-${m.policy_action}`}>{m.policy_action}</span></td>
                <td>{m.policy_score.toFixed(2)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="mw-panel">
        <h2>Recent Events</h2>
        <pre className="mw-pre">
          {JSON.stringify(events.slice(0, 20), null, 2)}
        </pre>
      </section>
      </section>
    </main>
  );
}

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="mw-stat-card">
      <div className="mw-stat-label">{label}</div>
      <div className="mw-stat-value">{value}</div>
    </div>
  );
}
