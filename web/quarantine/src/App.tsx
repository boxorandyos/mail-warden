import { FormEvent, useState } from "react";
import { listQuarantine, login, QuarantineMessage, releaseMessage } from "./api";

export function App() {
  const [token, setToken] = useState("");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [messages, setMessages] = useState<QuarantineMessage[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleLogin(e: FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const accessToken = await login(username, password);
      setToken(accessToken);
      const loaded = await listQuarantine(accessToken);
      setMessages(loaded);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  async function handleRelease(id: string) {
    try {
      await releaseMessage(token, id);
      const loaded = await listQuarantine(token);
      setMessages(loaded);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  if (!token) {
    return (
      <main className="mq-auth-shell">
        <section className="mq-auth-card">
          <h1>Mail Warden Quarantine</h1>
          <form onSubmit={handleLogin} className="mq-form">
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
          {error && <p className="mq-error">{error}</p>}
        </section>
      </main>
    );
  }

  return (
    <main className="mq-shell">
      <h1>Quarantine Messages</h1>
      <table className="mq-table">
        <thead>
          <tr>
            <th>From</th>
            <th>To</th>
            <th>Reason</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {messages.map((m) => (
            <tr key={m.id}>
              <td>{m.from}</td>
              <td>{m.to.join(", ")}</td>
              <td>{m.reason}</td>
              <td><span className={`mq-status mq-status-${m.status}`}>{m.status}</span></td>
              <td>
                {m.status === "quarantined" ? (
                  <button onClick={() => handleRelease(m.id)}>Release</button>
                ) : (
                  <span>Released</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {error && <p className="mq-error">{error}</p>}
    </main>
  );
}
