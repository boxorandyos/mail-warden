import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { canOperate, useAuth } from "../lib/auth";
import { useI18n } from "../lib/i18n";
import { Card, Dialog, Page, useAsyncError, useConfirm, useToast } from "../components/ui";

type MessageRow = {
  id: number;
  direction: string;
  sender: string;
  recipients: string[];
  policy_action: string;
  policy_score: number;
  observed_at: string;
  subject?: string;
};

type QuarantineRow = {
  id: string;
  from: string;
  to: string[];
  subject: string;
  reason: string;
  status: string;
  received_at: string;
  decision?: { action?: string; score?: number; reason?: string; signals?: { name: string; value: number }[]; explanation?: Record<string, number> };
};

type Metrics = Record<string, number>;

export function DashboardPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const [metrics, setMetrics] = useState<Metrics>({});
  const [rows, setRows] = useState<MessageRow[]>([]);
  useEffect(() => {
    api<Metrics>("/api/v1/metrics").then(setMetrics).catch(fail);
    api<MessageRow[]>("/api/v1/messages").then(setRows).catch(fail);
  }, [fail]);
  const cards = [
    ["messages_received", "Received"],
    ["messages_accepted", "Accepted"],
    ["messages_quarantined", "Quarantined"],
    ["messages_rejected", "Rejected"]
  ];
  return (
    <Page title={t("dashboard.title")} subtitle={t("dashboard.subtitle")}>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {cards.map(([key, label]) => (
          <Card key={key} title={label}>
            <div className="text-3xl font-bold">{metrics[key] ?? 0}</div>
          </Card>
        ))}
      </div>
      <Card title="Recent mail" action={<div className="flex gap-3 text-sm"><Link to="/messages">Messages</Link><Link to="/quarantine">Quarantine</Link><Link to="/policy">Policy</Link><Link to="/events">Events</Link></div>}>
        <MessageTable rows={rows.slice(0, 8)} onOpen={() => undefined} />
      </Card>
    </Page>
  );
}

export function MessagesPage() {
  const { t } = useI18n();
  const { user } = useAuth();
  const fail = useAsyncError();
  const [all, setAll] = useState(false);
  const [rows, setRows] = useState<MessageRow[]>([]);
  const [detail, setDetail] = useState<Record<string, unknown> | null>(null);
  function load(scopeAll: boolean) {
    const query = scopeAll ? "?scope=all" : "";
    api<MessageRow[]>(`/api/v1/messages${query}`).then(setRows).catch(fail);
  }
  useEffect(() => { load(false); }, []);
  return (
    <Page title={t("messages.title")} subtitle={t("messages.subtitle")} action={canOperate(user?.role) ? <ScopeSwitch all={all} onChange={(value) => { setAll(value); load(value); }} own={t("scope.own")} every={t("scope.all")} /> : undefined}>
      <Card>
        <MessageTable rows={rows} onOpen={(id) => api<Record<string, unknown>>(`/api/v1/messages/${id}`).then(setDetail).catch(fail)} />
      </Card>
      {detail && <MessageDetail detail={detail} onClose={() => setDetail(null)} title={t("detail.title")} />}
    </Page>
  );
}

export function QuarantinePage() {
  const { t } = useI18n();
  const { user } = useAuth();
  const fail = useAsyncError();
  const toast = useToast();
  const confirm = useConfirm();
  const [all, setAll] = useState(false);
  const [rows, setRows] = useState<QuarantineRow[]>([]);
  function load(scopeAll: boolean) {
    api<QuarantineRow[]>(`/api/v1/quarantine/messages${scopeAll ? "?scope=all" : ""}`).then(setRows).catch(fail);
  }
  useEffect(() => { load(false); }, []);
  async function release(row: QuarantineRow, mode: "rescan" | "bypass") {
    const ok = await confirm(
      mode === "rescan" ? t("quarantine.rescan") : t("quarantine.bypass"),
      mode === "rescan" ? t("quarantine.rescanConfirm") : t("quarantine.bypassConfirm"),
      mode === "rescan" ? t("quarantine.rescan") : t("quarantine.bypass")
    );
    if (!ok) return;
    try {
      const result = await api<{ released: boolean; decision?: { reason?: string; action?: string } }>(`/api/v1/quarantine/messages/${row.id}/release`, {
        method: "POST",
        body: JSON.stringify({ mode })
      });
      if (!result.released) toast(`${t("quarantine.held")}: ${result.decision?.action ?? ""} ${result.decision?.reason ?? ""}`.trim());
      else toast("Released", "ok");
      load(all);
    } catch (error) {
      fail(error);
    }
  }
  return (
    <Page title={t("quarantine.title")} subtitle={t("quarantine.subtitle")} action={canOperate(user?.role) ? <ScopeSwitch all={all} onChange={(value) => { setAll(value); load(value); }} own={t("scope.own")} every={t("scope.all")} /> : undefined}>
      <Card>
        <div className="overflow-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wider text-muted-foreground">
              <tr><th className="py-2">From</th><th>To</th><th>Subject</th><th>Reason</th><th>Status</th><th>Received</th><th></th></tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id} className="border-t border-border">
                  <td className="py-2 pr-3">{row.from}</td>
                  <td className="pr-3">{row.to?.join(", ")}</td>
                  <td className="pr-3">{row.subject}</td>
                  <td className="pr-3">{row.reason}</td>
                  <td className="pr-3">{row.status}</td>
                  <td className="pr-3">{formatTime(row.received_at)}</td>
                  <td className="space-x-2 whitespace-nowrap py-2 text-right">
                    {canOperate(user?.role) && row.status === "quarantined" && (
                      <>
                        <button className="border px-2 py-1" onClick={() => release(row, "rescan")}>{t("quarantine.rescan")}</button>
                        <button className="border px-2 py-1" onClick={() => release(row, "bypass")}>{t("quarantine.bypass")}</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
              {rows.length === 0 && <tr><td className="py-6 text-muted-foreground" colSpan={7}>{t("common.empty")}</td></tr>}
            </tbody>
          </table>
        </div>
      </Card>
    </Page>
  );
}

function ScopeSwitch({ all, onChange, own, every }: { all: boolean; onChange: (value: boolean) => void; own: string; every: string }) {
  return (
    <label className="flex items-center gap-2 text-sm">
      <span>{own}</span>
      <button type="button" role="switch" aria-checked={all} className={`h-6 w-11 border ${all ? "bg-primary" : "bg-muted"}`} onClick={() => onChange(!all)}>
        <span className={`block h-4 w-4 bg-background ${all ? "translate-x-6" : "translate-x-1"}`} />
      </button>
      <span>{every}</span>
    </label>
  );
}

function MessageTable({ rows, onOpen }: { rows: MessageRow[]; onOpen: (id: number) => void }) {
  return (
    <div className="overflow-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-xs uppercase tracking-wider text-muted-foreground">
          <tr><th className="py-2">From</th><th>To</th><th>Direction</th><th>Action</th><th>Score</th><th>When</th></tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id} className="cursor-pointer border-t border-border hover:bg-muted/60" onClick={() => onOpen(row.id)}>
              <td className="py-2 pr-3">{row.sender}</td>
              <td className="pr-3">{row.recipients?.join(", ")}</td>
              <td className="pr-3">{row.direction}</td>
              <td className="pr-3">{row.policy_action}</td>
              <td className="pr-3">{row.policy_score}</td>
              <td>{formatTime(row.observed_at)}</td>
            </tr>
          ))}
          {rows.length === 0 && <tr><td className="py-6 text-muted-foreground" colSpan={6}>Nothing here yet.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function MessageDetail({ detail, onClose, title }: { detail: Record<string, unknown>; onClose: () => void; title: string }) {
  const decision = (detail.decision ?? {}) as { signals?: { name: string; value: number; min: number; max: number }[]; explanation?: Record<string, number>; reason?: string; action?: string };
  return (
    <Dialog title={title} onClose={onClose}>
      <p className="text-sm">Action {decision.action} — {decision.reason}</p>
      <h3 className="mt-4 text-xs font-semibold uppercase tracking-wider">Signals</h3>
      <ul className="mt-2 space-y-1 text-sm">
        {(decision.signals ?? []).map((signal) => (
          <li key={signal.name} className="flex justify-between gap-3 font-mono text-xs"><span>{signal.name}</span><span>{signal.value} ({signal.min}..{signal.max})</span></li>
        ))}
      </ul>
      <h3 className="mt-4 text-xs font-semibold uppercase tracking-wider">Explanation</h3>
      <pre className="mt-2 overflow-auto bg-muted p-3 text-xs">{JSON.stringify(decision.explanation ?? {}, null, 2)}</pre>
      <h3 className="mt-4 text-xs font-semibold uppercase tracking-wider">Authentication and observations</h3>
      <pre className="mt-2 overflow-auto bg-muted p-3 text-xs">{JSON.stringify({ authentication: detail.authentication, urls: detail.urls, attachments: detail.attachments, decision_input: detail.decision_input }, null, 2)}</pre>
    </Dialog>
  );
}

function formatTime(value?: string) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
