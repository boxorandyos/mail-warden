import { FormEvent, useEffect, useState } from "react";
import { api } from "../lib/api";
import { useI18n } from "../lib/i18n";
import { Card, Page, inputClass, useAsyncError, useConfirm, useToast } from "../components/ui";

const ALERT_KINDS = ["availability", "backup_age", "node_stale", "job_failed"];
const POLICY_KINDS = ["require_mfa", "backup_max_age", "node_heartbeat_max_age"];

export function ServiceAccountsPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const confirm = useConfirm();
  const [rows, setRows] = useState<Array<{ id: string; name: string; role: string }>>([]);
  const [token, setToken] = useState("");
  function load() { api<typeof rows>("/api/v1/platform/service-accounts").then(setRows).catch(fail); }
  useEffect(load, []);
  async function remove(id: string) {
    if (!(await confirm(t("common.delete"), "Delete this service account?", t("common.delete")))) return;
    try { await api(`/api/v1/platform/service-accounts/${id}`, { method: "DELETE" }); load(); } catch (error) { fail(error); }
  }
  return (
    <Page title={t("nav.serviceAccounts")}>
      {token && <p className="mb-3 break-all font-mono text-xs">Token (shown once): {token}</p>}
      <Card>
        {rows.map((row) => (
          <div key={row.id} className="flex items-center justify-between border-t border-border py-2 text-sm">
            <span>{row.name} · {row.role}</span>
            <button className="border px-2 py-1" onClick={() => remove(row.id)}>{t("common.delete")}</button>
          </div>
        ))}
        <form className="mt-3 flex gap-2" onSubmit={(event) => {
          event.preventDefault();
          const data = new FormData(event.currentTarget);
          api<{ token: string }>("/api/v1/platform/service-accounts", { method: "POST", body: JSON.stringify({ name: data.get("name"), role: data.get("role") }) })
            .then((created) => { setToken(created.token); load(); })
            .catch(fail);
        }}>
          <input name="name" required className={inputClass} placeholder={t("platform.name")} />
          <select name="role" className={inputClass}><option>viewer</option><option>moderator</option><option>admin</option></select>
          <button className="border px-3">{t("platform.add")}</button>
        </form>
      </Card>
    </Page>
  );
}

export function FleetAlertsPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const [rows, setRows] = useState<Array<{ id: string; name: string; kind: string; threshold: number; enabled: boolean }>>([]);
  function load() { api<typeof rows>("/api/v1/platform/alert-rules").then(setRows).catch(fail); }
  useEffect(load, []);
  return (
    <Page title={t("nav.alerts")}>
      <Card title={t("platform.rules")}>
        {rows.map((rule) => (
          <div key={rule.id} className="flex items-center justify-between border-t border-border py-2 text-sm">
            <span>{rule.name} · {rule.kind} · {rule.threshold}</span>
            <button className="border px-2 py-1" onClick={() => api(`/api/v1/platform/alert-rules/${rule.id}`, { method: "POST", body: JSON.stringify({ enabled: !rule.enabled }) }).then(load).catch(fail)}>
              {rule.enabled ? t("platform.disable") : t("platform.enable")}
            </button>
          </div>
        ))}
        <form className="mt-3 flex flex-wrap gap-2" onSubmit={(event: FormEvent<HTMLFormElement>) => {
          event.preventDefault();
          const data = new FormData(event.currentTarget);
          api("/api/v1/platform/alert-rules", { method: "POST", body: JSON.stringify({ name: data.get("name"), kind: data.get("kind"), threshold: Number(data.get("threshold")) }) }).then(load).catch(fail);
        }}>
          <input name="name" required className={inputClass} placeholder={t("platform.name")} />
          <select name="kind" className={inputClass}>{ALERT_KINDS.map((kind) => <option key={kind}>{kind}</option>)}</select>
          <input name="threshold" type="number" min={0} required className={inputClass} placeholder="Threshold" />
          <button className="border px-3">Add rule</button>
        </form>
      </Card>
    </Page>
  );
}

export function PlatformMetricsPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const [platform, setPlatform] = useState<Record<string, unknown>>({});
  const [product, setProduct] = useState<Record<string, number>>({});
  useEffect(() => {
    api<Record<string, unknown>>("/api/v1/platform/metrics").then(setPlatform).catch(fail);
    api<Record<string, number>>("/api/v1/metrics").then(setProduct).catch(fail);
  }, [fail]);
  return (
    <Page title={t("nav.metrics")}>
      <Card title="Platform">
        <pre className="overflow-auto text-xs">{JSON.stringify(platform, null, 2)}</pre>
      </Card>
      <Card title="Mail">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {Object.entries(product).map(([key, value]) => (
            <div key={key}><div className="text-xs uppercase tracking-wider text-muted-foreground">{key.replaceAll("_", " ")}</div><div className="text-3xl font-bold">{value}</div></div>
          ))}
        </div>
      </Card>
    </Page>
  );
}

export function JobsPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const [rows, setRows] = useState<Array<{ id: string; type: string; status: string }>>([]);
  useEffect(() => { api<typeof rows>("/api/v1/platform/jobs").then(setRows).catch(fail); }, [fail]);
  return (
    <Page title={t("nav.jobs")}>
      <Card>
        {rows.map((row) => <p key={row.id} className="border-t border-border py-2 text-sm">{row.type} · {row.status}</p>)}
        {rows.length === 0 && <p className="text-sm text-muted-foreground">{t("common.empty")}</p>}
      </Card>
    </Page>
  );
}

export function RunbooksPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const [rows, setRows] = useState<Array<{ id: string; title: string }>>([]);
  function load() { api<typeof rows>("/api/v1/platform/runbooks").then(setRows).catch(fail); }
  useEffect(load, []);
  return (
    <Page title={t("nav.runbooks")}>
      <Card>
        {rows.map((row) => <p key={row.id} className="border-t border-border py-2 text-sm">{row.title}</p>)}
        <form className="mt-3 flex gap-2" onSubmit={(event: FormEvent<HTMLFormElement>) => {
          event.preventDefault();
          const data = new FormData(event.currentTarget);
          api("/api/v1/platform/runbooks", { method: "POST", body: JSON.stringify({ title: data.get("title"), body: data.get("body"), environmentId: "" }) }).then(load).catch(fail);
        }}>
          <input name="title" required className={inputClass} placeholder="Title" />
          <input name="body" className={inputClass} placeholder="Steps" />
          <button className="border px-3">{t("platform.add")}</button>
        </form>
      </Card>
    </Page>
  );
}

export function HardeningPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const [policies, setPolicies] = useState<Array<{ id: string; name: string; kind: string; enabled: boolean }>>([]);
  const [violations, setViolations] = useState<Array<{ policyName?: string; detail: string }>>([]);
  function load() {
    api<typeof policies>("/api/v1/platform/policies").then(setPolicies).catch(fail);
    api<typeof violations>("/api/v1/platform/policies/violations").then(setViolations).catch(fail);
  }
  useEffect(load, []);
  return (
    <Page title={t("nav.hardening")}>
      <Card title="Violations">
        {violations.length === 0 && <p className="text-sm text-muted-foreground">No policy violations.</p>}
        {violations.map((item, index) => <p key={index} className="border-t border-border py-2 text-sm">{item.policyName}: {item.detail}</p>)}
      </Card>
      <Card title="Policies">
        {policies.map((policy) => (
          <div key={policy.id} className="flex items-center justify-between border-t border-border py-2 text-sm">
            <span>{policy.name} · {policy.kind}</span>
            <button className="border px-2 py-1" onClick={() => api(`/api/v1/platform/policies/${policy.id}`, { method: "POST", body: JSON.stringify({ enabled: !policy.enabled }) }).then(load).catch(fail)}>
              {policy.enabled ? t("platform.disable") : t("platform.enable")}
            </button>
          </div>
        ))}
        <form className="mt-3 flex flex-wrap gap-2" onSubmit={(event: FormEvent<HTMLFormElement>) => {
          event.preventDefault();
          const data = new FormData(event.currentTarget);
          const raw = String(data.get("threshold") ?? "");
          api("/api/v1/platform/policies", { method: "POST", body: JSON.stringify({ name: data.get("name"), kind: data.get("kind"), threshold: raw === "" ? null : Number(raw) }) }).then(load).catch(fail);
        }}>
          <input name="name" required className={inputClass} placeholder={t("platform.name")} />
          <select name="kind" className={inputClass}>{POLICY_KINDS.map((kind) => <option key={kind}>{kind}</option>)}</select>
          <input name="threshold" type="number" min={0} className={inputClass} placeholder="Threshold" />
          <button className="border px-3">Add policy</button>
        </form>
      </Card>
    </Page>
  );
}

export function AuditExportPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const [rows, setRows] = useState<Array<{ actor?: string; action: string; detail?: string; createdAt: string }>>([]);
  useEffect(() => { api<typeof rows>("/api/v1/platform/audit/export").then(setRows).catch(fail); }, [fail]);
  async function download() {
    const response = await fetch("/api/v1/platform/audit/export?format=csv", { headers: { Authorization: `Bearer ${localStorage.getItem("accessToken") ?? ""}` } });
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "mail-audit.csv";
    link.click();
    URL.revokeObjectURL(url);
  }
  return (
    <Page title={t("nav.audit")} action={<button className="border px-3 py-2 text-sm" onClick={download}>Export CSV</button>}>
      <Card>
        {rows.map((row, index) => <p key={index} className="border-t border-border py-2 text-sm">{row.createdAt} · {row.actor} · {row.action} · {row.detail}</p>)}
      </Card>
    </Page>
  );
}

export function PlatformSnapshotsPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const toast = useToast();
  const [rows, setRows] = useState<Array<{ id: string; actor: string; createdAt: string }>>([]);
  function load() { api<typeof rows>("/api/v1/platform/snapshots").then(setRows).catch(fail); }
  useEffect(load, []);
  return (
    <Page title={t("nav.snapshots")} subtitle="Environments, runbooks, alert rules, and policies." action={<button className="bg-primary px-3 py-2 text-sm text-primary-foreground" onClick={() => api("/api/v1/platform/snapshots", { method: "POST", body: "{}" }).then(load).catch(fail)}>Capture</button>}>
      <Card action={<button className="border px-2 py-1 text-sm" onClick={() => api<{ length?: number } | Array<unknown>>("/api/v1/platform/sync", { method: "POST", body: "{}" }).then((result) => toast(Array.isArray(result) ? `${result.length} slaves contacted` : "Push requested", "ok")).catch(fail)}>Push to slaves</button>}>
        {rows.map((row) => (
          <div key={row.id} className="flex items-center justify-between border-t border-border py-2 text-sm">
            <span>{row.createdAt} · {row.actor}</span>
            <button className="border px-2 py-1" onClick={() => api(`/api/v1/platform/snapshots/${row.id}/apply`, { method: "POST", body: "{}" }).then(() => toast("Applied", "ok")).catch(fail)}>Apply</button>
          </div>
        ))}
      </Card>
    </Page>
  );
}

export function BackupsPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const toast = useToast();
  const confirm = useConfirm();
  const [rows, setRows] = useState<string[]>([]);
  function load() { api<{ data?: string[] }>("/api/v1/backups").then((body) => setRows(body.data ?? [])).catch(fail); }
  useEffect(load, []);
  return (
    <Page title={t("nav.backups")} subtitle="Postgres dumps written by scripts/backup.sh. The copy runs only when WARDEN_ALLOW_HOST_UPDATE=1.">
      <Card action={<button className="border px-3 py-2 text-sm" onClick={async () => {
        if (!(await confirm("Back up Postgres?", "This runs scripts/backup.sh. It stays planned until host updates are enabled.", "Back up"))) return;
        try {
          const result = await api<{ detail?: string }>("/api/v1/backups", { method: "POST", body: "{}" });
          toast(result.detail || "Backup requested", "ok");
          load();
        } catch (error) { fail(error); }
      }}>Back up</button>}>
        {rows.map((name) => <p key={name} className="border-t border-border py-2 font-mono text-sm">{name}</p>)}
        {rows.length === 0 && <p className="text-sm text-muted-foreground">{t("common.empty")}</p>}
      </Card>
    </Page>
  );
}
