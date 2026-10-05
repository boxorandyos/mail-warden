import { FormEvent, useEffect, useState } from "react";
import { api, type SessionUser } from "../lib/api";
import { canAdmin, useAuth } from "../lib/auth";
import { useI18n } from "../lib/i18n";
import { SUPPORTED_LOCALES } from "../locales";
import { Card, Dialog, Field, Page, inputClass, useAsyncError, useConfirm, useToast } from "../components/ui";

const HARD_BLOCKS = ["malware_confirmed", "exploit_confirmed", "malicious_url_critical", "protocol_abuse"];

type PolicyDoc = {
  policy: {
    inbound: { reject: number; quarantine: number };
    outbound: { reject: number; quarantine: number; throttle: { recipients_per_hour: number; unique_domains_per_hour: number } };
  };
  hard_blocks: string[];
  caps: Record<string, { min: number; max: number }>;
};

const emptyPolicy = (): PolicyDoc => ({
  policy: {
    inbound: { reject: -30, quarantine: -10 },
    outbound: { reject: -35, quarantine: -12, throttle: { recipients_per_hour: 5000, unique_domains_per_hour: 500 } }
  },
  hard_blocks: [...HARD_BLOCKS.slice(0, 3)],
  caps: {}
});

export function PolicyPage() {
  const { t } = useI18n();
  const { user } = useAuth();
  const admin = canAdmin(user?.role);
  const fail = useAsyncError();
  const toast = useToast();
  const confirm = useConfirm();
  const [policy, setPolicy] = useState<PolicyDoc>(emptyPolicy);
  const [versions, setVersions] = useState<{ id: number; version_label: string; created_at: string }[]>([]);
  function load() {
    api<PolicyDoc>("/api/v1/policy/current").then((doc) => setPolicy({ ...emptyPolicy(), ...doc, hard_blocks: doc.hard_blocks ?? [], caps: doc.caps ?? {} })).catch(fail);
    if (admin) api<typeof versions>("/api/v1/policy/versions").then(setVersions).catch(fail);
  }
  useEffect(load, []);
  async function save() {
    try {
      await api("/api/v1/policy/current", { method: "PUT", body: JSON.stringify(policy) });
      toast(t("common.save"), "ok");
      load();
    } catch (error) { fail(error); }
  }
  async function rollback(id: number) {
    if (!(await confirm(t("policy.rollback"), t("policy.rollbackConfirm"), t("policy.rollback")))) return;
    try {
      const result = await api<{ note?: string }>(`/api/v1/policy/rollback?id=${id}`, { method: "POST" });
      toast(result.note || t("policy.diskNote"), "ok");
      load();
    } catch (error) { fail(error); }
  }
  return (
    <Page title={t("policy.title")} subtitle={t("policy.subtitle")} action={admin ? <button className="bg-primary px-3 py-2 text-sm text-primary-foreground" onClick={save}>{t("common.save")}</button> : undefined}>
      <p className="border border-primary/30 bg-card px-3 py-2 text-sm">{t("policy.diskNote")}</p>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Inbound">
          <NumberField disabled={!admin} label="Reject" value={policy.policy.inbound.reject} onChange={(value) => setPolicy({ ...policy, policy: { ...policy.policy, inbound: { ...policy.policy.inbound, reject: value } } })} />
          <NumberField disabled={!admin} label="Quarantine" value={policy.policy.inbound.quarantine} onChange={(value) => setPolicy({ ...policy, policy: { ...policy.policy, inbound: { ...policy.policy.inbound, quarantine: value } } })} />
        </Card>
        <Card title="Outbound">
          <NumberField disabled={!admin} label="Reject" value={policy.policy.outbound.reject} onChange={(value) => setPolicy({ ...policy, policy: { ...policy.policy, outbound: { ...policy.policy.outbound, reject: value } } })} />
          <NumberField disabled={!admin} label="Quarantine" value={policy.policy.outbound.quarantine} onChange={(value) => setPolicy({ ...policy, policy: { ...policy.policy, outbound: { ...policy.policy.outbound, quarantine: value } } })} />
          <NumberField disabled={!admin} label="Recipients per hour" value={policy.policy.outbound.throttle.recipients_per_hour} onChange={(value) => setPolicy({ ...policy, policy: { ...policy.policy, outbound: { ...policy.policy.outbound, throttle: { ...policy.policy.outbound.throttle, recipients_per_hour: value } } } })} />
          <NumberField disabled={!admin} label="Unique domains per hour" value={policy.policy.outbound.throttle.unique_domains_per_hour} onChange={(value) => setPolicy({ ...policy, policy: { ...policy.policy, outbound: { ...policy.policy.outbound, throttle: { ...policy.policy.outbound.throttle, unique_domains_per_hour: value } } } })} />
        </Card>
      </div>
      <Card title="Hard blocks">
        <div className="flex flex-wrap gap-3">
          {HARD_BLOCKS.map((name) => (
            <label key={name} className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={policy.hard_blocks.includes(name)} disabled={!admin} onChange={(event) => {
                const hard_blocks = event.target.checked ? [...policy.hard_blocks, name] : policy.hard_blocks.filter((item) => item !== name);
                setPolicy({ ...policy, hard_blocks });
              }} />
              {name}
            </label>
          ))}
        </div>
      </Card>
      <Card title="Signal caps">
        <div className="space-y-2">
          {Object.entries(policy.caps).map(([key, cap]) => (
            <div key={key} className="grid grid-cols-[1fr_8rem_8rem] gap-2 text-sm">
              <div className="self-center font-mono text-xs">{key}</div>
              <NumberField disabled={!admin} label="Min" value={cap.min} onChange={(value) => setPolicy({ ...policy, caps: { ...policy.caps, [key]: { ...cap, min: value } } })} />
              <NumberField disabled={!admin} label="Max" value={cap.max} onChange={(value) => setPolicy({ ...policy, caps: { ...policy.caps, [key]: { ...cap, max: value } } })} />
            </div>
          ))}
        </div>
      </Card>
      {admin && (
        <Card title={t("policy.versions")}>
          <table className="w-full text-left text-sm">
            <tbody>
              {versions.map((version) => (
                <tr key={version.id} className="border-t border-border">
                  <td className="py-2">{version.version_label}</td>
                  <td>{new Date(version.created_at).toLocaleString()}</td>
                  <td className="text-right"><button className="border px-2 py-1" onClick={() => rollback(version.id)}>{t("policy.rollback")}</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </Page>
  );
}

function NumberField({ label, value, onChange, disabled }: { label: string; value: number; onChange: (value: number) => void; disabled?: boolean }) {
  const [draft, setDraft] = useState<string | null>(null);
  const shown = draft ?? (Number.isFinite(value) ? String(value) : "");
  return (
    <Field label={label}>
      <input
        className={inputClass}
        inputMode="decimal"
        disabled={disabled}
        value={shown}
        onChange={(event) => {
          const raw = event.target.value.trim();
          if (!/^-?\d*(?:\.\d*)?$/.test(raw)) return;
          setDraft(raw);
          if (raw === "" || raw === "-" || raw === "." || raw === "-.") return;
          const next = Number(raw);
          if (Number.isFinite(next)) onChange(next);
        }}
        onBlur={() => setDraft(null)}
      />
    </Field>
  );
}

type Provider = { id: string; name: string; type: string; enabled: boolean; priority: number; config: Record<string, string> };

export function IdentityPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const toast = useToast();
  const confirm = useConfirm();
  const [rows, setRows] = useState<Provider[]>([]);
  const [editing, setEditing] = useState<Provider | null>(null);
  function load() { api<Provider[]>("/api/v1/identity/providers").then(setRows).catch(fail); }
  useEffect(load, []);
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!editing) return;
    try {
      const config = Object.fromEntries(Object.entries(editing.config || {}).filter(([key, value]) => !key.endsWith("Set") && value !== "********" && value !== ""));
      await api("/api/v1/identity/providers", { method: "POST", body: JSON.stringify({ id: editing.id, name: editing.name, type: editing.type, enabled: editing.enabled, priority: editing.priority || 100, config }) });
      toast(t("common.save"), "ok");
      setEditing(null);
      load();
    } catch (error) { fail(error); }
  }
  async function remove(id: string) {
    if (!(await confirm(t("common.delete"), "Delete this identity provider?", t("common.delete")))) return;
    try { await api(`/api/v1/identity/providers/${id}`, { method: "DELETE" }); load(); } catch (error) { fail(error); }
  }
  return (
    <Page title={t("identity.title")} subtitle={t("identity.subtitle")} action={<button className="bg-primary px-3 py-2 text-sm text-primary-foreground" onClick={() => setEditing({ id: "", name: "", type: "local", enabled: true, priority: 100, config: {} })}>{t("common.create")}</button>}>
      <Card>
        <table className="w-full text-left text-sm">
          <thead><tr className="text-xs uppercase tracking-wider text-muted-foreground"><th className="py-2">Name</th><th>Type</th><th>Enabled</th><th></th></tr></thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id} className="border-t border-border">
                <td className="py-2">{row.name}</td><td>{row.type}</td><td>{row.enabled ? "yes" : "no"}</td>
                <td className="space-x-2 text-right"><button className="border px-2 py-1" onClick={() => setEditing(row)}>{t("common.edit")}</button><button className="border px-2 py-1" onClick={() => remove(row.id)}>{t("common.delete")}</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      {editing && (
        <Dialog title={editing.id ? t("common.edit") : t("common.create")} onClose={() => setEditing(null)}>
          <form className="space-y-3" onSubmit={save}>
            <Field label="Name"><input className={inputClass} value={editing.name} onChange={(event) => setEditing({ ...editing, name: event.target.value })} /></Field>
            <Field label="Type">
              <select className={inputClass} value={editing.type} onChange={(event) => setEditing({ ...editing, type: event.target.value })}>
                <option value="local">local</option><option value="ldap">ldap</option><option value="oidc">oidc</option>
              </select>
            </Field>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={editing.enabled} onChange={(event) => setEditing({ ...editing, enabled: event.target.checked })} />Enabled</label>
            {editing.type === "ldap" && ["url", "search_base", "search_filter", "bind_dn", "bind_password"].map((key) => (
              <Field key={key} label={key}><input className={inputClass} type={key.includes("password") ? "password" : "text"} value={editing.config[key] ?? ""} placeholder={key.includes("password") ? "Leave blank to keep" : ""} onChange={(event) => setEditing({ ...editing, config: { ...editing.config, [key]: event.target.value } })} /></Field>
            ))}
            {editing.type === "oidc" && ["issuer", "client_id", "client_secret", "redirect_url", "scopes"].map((key) => (
              <Field key={key} label={key}><input className={inputClass} type={key.includes("secret") ? "password" : "text"} value={editing.config[key] ?? ""} placeholder={key.includes("secret") ? "Leave blank to keep" : ""} onChange={(event) => setEditing({ ...editing, config: { ...editing.config, [key]: event.target.value } })} /></Field>
            ))}
            <button className="bg-primary px-3 py-2 text-sm text-primary-foreground">{t("common.save")}</button>
          </form>
        </Dialog>
      )}
    </Page>
  );
}

export function EventsPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const [rows, setRows] = useState<{ type: string; timestamp: string; entity_id: string; metadata: Record<string, string> }[]>([]);
  useEffect(() => { api<typeof rows>("/api/v1/events").then(setRows).catch(fail); }, [fail]);
  return (
    <Page title={t("events.title")} subtitle={t("events.subtitle")}>
      <Card>
        <table className="w-full text-left text-sm">
          <thead><tr className="text-xs uppercase tracking-wider text-muted-foreground"><th className="py-2">Time</th><th>Type</th><th>Entity</th><th>Metadata</th></tr></thead>
          <tbody>
            {rows.map((row, index) => (
              <tr key={`${row.entity_id}-${index}`} className="border-t border-border align-top">
                <td className="py-2 pr-3">{new Date(row.timestamp).toLocaleString()}</td>
                <td className="pr-3">{row.type}</td>
                <td className="pr-3">{row.entity_id}</td>
                <td className="font-mono text-xs">{JSON.stringify(row.metadata)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </Page>
  );
}

export function MetricsPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const [metrics, setMetrics] = useState<Record<string, number>>({});
  useEffect(() => { api<Record<string, number>>("/api/v1/metrics").then(setMetrics).catch(fail); }, [fail]);
  return (
    <Page title={t("metrics.title")} subtitle={t("metrics.subtitle")}>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {Object.entries(metrics).map(([key, value]) => (
          <Card key={key} title={key.replaceAll("_", " ")}><div className="text-3xl font-bold">{value}</div></Card>
        ))}
      </div>
    </Page>
  );
}

export function ClusterPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const [rows, setRows] = useState<{ id: string; name: string; advertised_addr: string; status: string; role: string; last_seen_at?: string }[]>([]);
  useEffect(() => { api<typeof rows>("/api/v1/cluster/nodes").then(setRows).catch(fail); }, [fail]);
  return (
    <Page title={t("cluster.title")} subtitle={t("cluster.subtitle")}>
      <Card>
        <table className="w-full text-left text-sm">
          <thead><tr className="text-xs uppercase tracking-wider text-muted-foreground"><th className="py-2">Name</th><th>Address</th><th>Role</th><th>Status</th><th>Last seen</th></tr></thead>
          <tbody>
            {rows.map((row) => <tr key={row.id} className="border-t border-border"><td className="py-2">{row.name}</td><td>{row.advertised_addr}</td><td>{row.role}</td><td>{row.status}</td><td>{row.last_seen_at ? new Date(row.last_seen_at).toLocaleString() : ""}</td></tr>)}
            {rows.length === 0 && <tr><td className="py-6 text-muted-foreground" colSpan={5}>{t("common.empty")}</td></tr>}
          </tbody>
        </table>
      </Card>
    </Page>
  );
}

export function MaintenancePage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const toast = useToast();
  const [note, setNote] = useState("");
  async function run(path: string, kind?: string, component?: string) {
    try {
      const result = await api<{ detail?: string; executed?: boolean; results?: Array<{ name: string; status: number }> }>(path, {
        method: "POST",
        body: JSON.stringify(component ? { component } : kind ? { kind } : {}),
      });
      const text = result.detail || (result.results ? `${result.results.length} nodes contacted` : t("cluster.scheduled"));
      setNote(text);
      toast(text, "ok");
    } catch (error) { fail(error); }
  }
  return (
    <Page title={t("maintenance.title")} subtitle={t("maintenance.subtitle")} action={
      <div className="flex flex-wrap gap-2">
        <button className="border px-3 py-2 text-sm" onClick={() => run("/api/v1/maintenance/product")}>{t("cluster.updateProduct")}</button>
        <button className="border px-3 py-2 text-sm" onClick={() => run("/api/v1/maintenance/packages")}>{t("cluster.updatePackages")}</button>
        <button className="bg-primary px-3 py-2 text-sm text-primary-foreground" onClick={() => run("/api/v1/maintenance/slaves", "product")}>{t("cluster.upgradeSlaves")}</button>
      </div>
    }>
      {note && <p className="mb-3 text-sm text-muted-foreground">{note}</p>}
      <Card title={t("cluster.runtimes")}>
        <p className="mb-3 text-sm text-muted-foreground">{t("cluster.runtimeHelp")}</p>
        <div className="flex flex-wrap gap-2">
          <button className="border px-3 py-2 text-sm" onClick={() => run("/api/v1/maintenance/runtime", undefined, "postgres")}>{t("cluster.runtimePostgres")}</button>
          <button className="border px-3 py-2 text-sm" onClick={() => run("/api/v1/maintenance/runtime", undefined, "redis")}>{t("cluster.runtimeRedis")}</button>
          <button className="border px-3 py-2 text-sm" onClick={() => run("/api/v1/maintenance/runtime", undefined, "go")}>{t("cluster.runtimeGo")}</button>
        </div>
      </Card>
    </Page>
  );
}

type Snapshot = { id: number; snapshot_type: string; created_at: string; created_by: string };

export function SnapshotsPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const toast = useToast();
  const confirm = useConfirm();
  const [rows, setRows] = useState<Snapshot[]>([]);
  function load() { api<Snapshot[]>("/api/v1/config/snapshots").then(setRows).catch(fail); }
  useEffect(load, []);
  async function create() {
    try {
      const policy = await api("/api/v1/policy/current");
      await api("/api/v1/config/snapshots", { method: "POST", body: JSON.stringify({ type: "policy", config: policy }) });
      toast(t("common.save"), "ok");
      load();
    } catch (error) { fail(error); }
  }
  async function apply(id: number) {
    if (!(await confirm(t("snapshots.apply"), t("snapshots.applyConfirm"), t("snapshots.apply")))) return;
    try {
      const result = await api<{ note?: string; restart_fields?: string[] }>(`/api/v1/config/snapshots/apply?id=${id}`, { method: "POST" });
      toast(result.note || (result.restart_fields?.length ? result.restart_fields.join(", ") : "Applied"), "ok");
    } catch (error) { fail(error); }
  }
  return (
    <Page title={t("snapshots.title")} subtitle={t("snapshots.subtitle")} action={<button className="bg-primary px-3 py-2 text-sm text-primary-foreground" onClick={create}>{t("common.create")}</button>}>
      <Card>
        <table className="w-full text-left text-sm">
          <tbody>
            {rows.map((row) => (
              <tr key={row.id} className="border-t border-border">
                <td className="py-2">{row.snapshot_type}</td>
                <td>{new Date(row.created_at).toLocaleString()}</td>
                <td className="text-right"><button className="border px-2 py-1" onClick={() => apply(row.id)}>{t("snapshots.apply")}</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </Page>
  );
}

type ServiceView = Record<string, unknown>;

export function ConfigurationPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const toast = useToast();
  const [view, setView] = useState<ServiceView | null>(null);
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [note, setNote] = useState("");
  useEffect(() => { api<ServiceView>("/api/v1/config/service").then(setView).catch(fail); }, [fail]);
  if (!view) return <Page title={t("configuration.title")}><p>{t("common.loading")}</p></Page>;
  const service = section(view, "service");
  const defaults = section(view, "defaults");
  const exchange = section(view, "exchange");
  const stores = section(view, "stores");
  const rspamd = section(view, "rspamd");
  const sandbox = section(view, "sandbox");
  const siem = section(view, "siem");
  const smtp = section(view, "smtp");
  const auth = section(view, "auth");
  const oidc = section(auth, "oidc");
  const ldap = section(view, "ldap");
  const portal = section(view, "portal");
  function setIn(group: string, key: string, value: unknown) {
    setView({ ...view, [group]: { ...section(view, group), [key]: value } });
  }
  async function save() {
    const body = {
      service: { listen: service.listen, mode: service.mode },
      defaults: { organization_id: defaults.organization_id, organization_name: defaults.organization_name },
      exchange: { smart_host: exchange.smart_host, receive_connector_name: exchange.receive_connector_name },
      stores: { redis_addr: stores.redis_addr },
      rspamd: { endpoint: rspamd.endpoint, timeout_seconds: rspamd.timeout_seconds },
      sandbox: { enabled: Boolean(sandbox.enabled), endpoint: sandbox.endpoint, timeout_seconds: sandbox.timeout_seconds, min_suspicion_hit: sandbox.min_suspicion_hit },
      siem: { enabled: Boolean(siem.enabled), webhook_url: siem.webhook_url, timeout_seconds: siem.timeout_seconds },
      smtp: { policy_listen: smtp.policy_listen },
      auth: {
        access_ttl_minutes: auth.access_ttl_minutes,
        refresh_ttl_hours: auth.refresh_ttl_hours,
        bootstrap_admin_user: auth.bootstrap_admin_user,
        bootstrap_admin_email: auth.bootstrap_admin_email,
        bootstrap_admin_full_name: auth.bootstrap_admin_full_name,
        oidc: {
          enabled: Boolean(oidc.enabled),
          issuer: oidc.issuer,
          client_id: oidc.client_id,
          redirect_url: oidc.redirect_url,
          scopes: oidc.scopes,
          email_claim: oidc.email_claim,
          name_claim: oidc.name_claim,
          groups_claim: oidc.groups_claim
        }
      },
      ldap: {
        enabled: Boolean(ldap.enabled),
        url: ldap.url,
        bind_dn: ldap.bind_dn,
        search_base: ldap.search_base,
        search_filter: ldap.search_filter,
        email_attr: ldap.email_attr,
        name_attr: ldap.name_attr,
        group_base: ldap.group_base,
        group_filter: ldap.group_filter,
        group_name_attr: ldap.group_name_attr,
        start_tls: Boolean(ldap.start_tls),
        tls_reject_unauthorized: Boolean(ldap.tls_reject_unauthorized),
        default_role: ldap.default_role,
        role_map: ldap.role_map && typeof ldap.role_map === "object" ? ldap.role_map : undefined
      },
      portal: { public_url: portal.public_url, origins: portal.origins ?? [] },
      secrets
    };
    try {
      const result = await api<{ restart_required: boolean; restart_fields: string[] }>("/api/v1/config/service", { method: "PUT", body: JSON.stringify(body) });
      setNote(result.restart_required ? `${t("configuration.restart")} ${(result.restart_fields || []).join(", ")}` : t("configuration.live"));
      toast(t("common.save"), "ok");
      setSecrets({});
      const fresh = await api<ServiceView>("/api/v1/config/service");
      setView(fresh);
    } catch (error) { fail(error); }
  }
  return (
    <Page title={t("configuration.title")} subtitle={t("configuration.subtitle")} action={<button className="bg-primary px-3 py-2 text-sm text-primary-foreground" onClick={save}>{t("common.save")}</button>}>
      {note && <p className="border border-primary/40 bg-card px-3 py-2 text-sm">{note}</p>}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Service">
          <Text label="Listen" value={String(service.listen ?? "")} onChange={(value) => setIn("service", "listen", value)} />
          <Text label="Mode" value={String(service.mode ?? "")} onChange={(value) => setIn("service", "mode", value)} />
        </Card>
        <Card title="Organization">
          <Text label="Name" value={String(defaults.organization_name ?? "")} onChange={(value) => setIn("defaults", "organization_name", value)} />
          <Text label="Organization id" value={String(defaults.organization_id ?? "")} onChange={(value) => setIn("defaults", "organization_id", Number(value))} />
        </Card>
        <Card title="Exchange">
          <Text label="Smart host" value={String(exchange.smart_host ?? "")} onChange={(value) => setIn("exchange", "smart_host", value)} />
          <Text label="Receive connector" value={String(exchange.receive_connector_name ?? "")} onChange={(value) => setIn("exchange", "receive_connector_name", value)} />
        </Card>
        <Card title="Stores">
          <Text label="Redis address" value={String(stores.redis_addr ?? "")} onChange={(value) => setIn("stores", "redis_addr", value)} />
          <Secret label="Postgres DSN" set={Boolean(stores.postgres_dsn_set)} onChange={(value) => setSecrets({ ...secrets, postgres_dsn: value })} />
        </Card>
        <Card title="Rspamd">
          <Text label="Endpoint" value={String(rspamd.endpoint ?? "")} onChange={(value) => setIn("rspamd", "endpoint", value)} />
          <Text label="Timeout seconds" value={String(rspamd.timeout_seconds ?? "")} onChange={(value) => setIn("rspamd", "timeout_seconds", Number(value))} />
        </Card>
        <Card title="Sandbox">
          <Text label="Endpoint" value={String(sandbox.endpoint ?? "")} onChange={(value) => setIn("sandbox", "endpoint", value)} />
          <Secret label="API key" set={Boolean(sandbox.api_key_set)} onChange={(value) => setSecrets({ ...secrets, sandbox_api_key: value })} />
        </Card>
        <Card title="SIEM">
          <Text label="Webhook URL" value={String(siem.webhook_url ?? "")} onChange={(value) => setIn("siem", "webhook_url", value)} />
          <Secret label="Bearer token" set={Boolean(siem.bearer_token_set)} onChange={(value) => setSecrets({ ...secrets, siem_bearer_token: value })} />
        </Card>
        <Card title="SMTP policy">
          <Text label="Listen" value={String(smtp.policy_listen ?? "")} onChange={(value) => setIn("smtp", "policy_listen", value)} />
        </Card>
        <Card title="Auth">
          <Text label="Access TTL minutes" value={String(auth.access_ttl_minutes ?? "")} onChange={(value) => setIn("auth", "access_ttl_minutes", Number(value))} />
          <Text label="Refresh TTL hours" value={String(auth.refresh_ttl_hours ?? "")} onChange={(value) => setIn("auth", "refresh_ttl_hours", Number(value))} />
          <Secret label="Access secret" set={Boolean(auth.access_secret_set)} onChange={(value) => setSecrets({ ...secrets, access_secret: value })} />
          <Secret label="Refresh secret" set={Boolean(auth.refresh_secret_set)} onChange={(value) => setSecrets({ ...secrets, refresh_secret: value })} />
        </Card>
        <Card title="OIDC">
          <Text label="Issuer" value={String(oidc.issuer ?? "")} onChange={(value) => setView({ ...view, auth: { ...auth, oidc: { ...oidc, issuer: value } } })} />
          <Text label="Client id" value={String(oidc.client_id ?? "")} onChange={(value) => setView({ ...view, auth: { ...auth, oidc: { ...oidc, client_id: value } } })} />
          <Text label="Redirect URL" value={String(oidc.redirect_url ?? "")} onChange={(value) => setView({ ...view, auth: { ...auth, oidc: { ...oidc, redirect_url: value } } })} />
          <Secret label="Client secret" set={Boolean(oidc.client_secret_set)} onChange={(value) => setSecrets({ ...secrets, oidc_client_secret: value })} />
        </Card>
        <Card title="LDAP">
          <Text label="URL" value={String(ldap.url ?? "")} onChange={(value) => setIn("ldap", "url", value)} />
          <Text label="Search base" value={String(ldap.search_base ?? "")} onChange={(value) => setIn("ldap", "search_base", value)} />
          <Text label="Bind DN" value={String(ldap.bind_dn ?? "")} onChange={(value) => setIn("ldap", "bind_dn", value)} />
          <Secret label="Bind password" set={Boolean(ldap.bind_password_set)} onChange={(value) => setSecrets({ ...secrets, ldap_bind_password: value })} />
        </Card>
        <Card title="Portal">
          <Text label="Public URL" value={String(portal.public_url ?? "")} onChange={(value) => setIn("portal", "public_url", value)} />
          <Field label="Origins">
            <textarea className={inputClass} rows={3} value={Array.isArray(portal.origins) ? (portal.origins as string[]).join("\n") : ""} onChange={(event) => setIn("portal", "origins", event.target.value.split("\n").map((line) => line.trim()).filter(Boolean))} />
          </Field>
        </Card>
      </div>
    </Page>
  );
}

function section(view: ServiceView | null, key: string): Record<string, unknown> {
  const value = view?.[key];
  return value && typeof value === "object" ? value as Record<string, unknown> : {};
}

function Text({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return <Field label={label}><input className={inputClass} value={value} onChange={(event) => onChange(event.target.value)} /></Field>;
}

function Secret({ label, set, onChange }: { label: string; set: boolean; onChange: (value: string) => void }) {
  return <Field label={`${label}${set ? " (saved)" : ""}`}><input className={inputClass} type="password" placeholder="Leave blank to keep" onChange={(event) => onChange(event.target.value)} /></Field>;
}

export function UsersPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const toast = useToast();
  const confirm = useConfirm();
  const [rows, setRows] = useState<SessionUser[]>([]);
  const [editing, setEditing] = useState<(SessionUser & { password?: string }) | null>(null);
  function load() { api<SessionUser[]>("/api/v1/users").then(setRows).catch(fail); }
  useEffect(load, []);
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!editing) return;
    const body = { username: editing.username, email: editing.email, full_name: editing.full_name, role: editing.role, password: editing.password, enabled: editing.enabled ?? true };
    try {
      if (editing.id) await api(`/api/v1/users/${editing.id}`, { method: "PUT", body: JSON.stringify(body) });
      else await api("/api/v1/users", { method: "POST", body: JSON.stringify(body) });
      toast(t("common.save"), "ok");
      setEditing(null);
      load();
    } catch (error) { fail(error); }
  }
  async function remove(id: string) {
    if (!(await confirm(t("common.delete"), "Delete this user?", t("common.delete")))) return;
    try { await api(`/api/v1/users/${id}`, { method: "DELETE" }); load(); } catch (error) { fail(error); }
  }
  const label = (role: string) => role === "moderator" ? t("role.operator") : role === "admin" ? t("role.admin") : t("role.viewer");
  return (
    <Page title={t("users.title")} subtitle={t("users.subtitle")} action={<button className="bg-primary px-3 py-2 text-sm text-primary-foreground" onClick={() => setEditing({ id: "", username: "", email: "", full_name: "", role: "viewer", enabled: true, password: "" })}>{t("common.create")}</button>}>
      <div className="grid gap-3 md:grid-cols-3">
        <Card title={t("role.admin")}><p className="text-sm text-muted-foreground">{t("role.admin.help")}</p></Card>
        <Card title={t("role.operator")}><p className="text-sm text-muted-foreground">{t("role.operator.help")}</p></Card>
        <Card title={t("role.viewer")}><p className="text-sm text-muted-foreground">{t("role.viewer.help")}</p></Card>
      </div>
      <Card>
        <table className="w-full text-left text-sm">
          <thead><tr className="text-xs uppercase tracking-wider text-muted-foreground"><th className="py-2">Username</th><th>Email</th><th>Role</th><th></th></tr></thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id} className="border-t border-border">
                <td className="py-2">{row.username}</td><td>{row.email}</td><td>{label(row.role)} <span className="text-muted-foreground">({row.role})</span></td>
                <td className="space-x-2 text-right">
                  <button className="border px-2 py-1" onClick={() => setEditing({ ...row, password: "" })}>{t("common.edit")}</button>
                  <button className="border px-2 py-1" onClick={() => remove(row.id)}>{t("common.delete")}</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      {editing && (
        <Dialog title={editing.id ? t("common.edit") : t("common.create")} onClose={() => setEditing(null)}>
          <form className="space-y-3" onSubmit={save}>
            {!editing.id && <Field label="Username"><input className={inputClass} value={editing.username} onChange={(event) => setEditing({ ...editing, username: event.target.value })} /></Field>}
            <Field label="Email"><input className={inputClass} value={editing.email} onChange={(event) => setEditing({ ...editing, email: event.target.value })} /></Field>
            <Field label="Full name"><input className={inputClass} value={editing.full_name} onChange={(event) => setEditing({ ...editing, full_name: event.target.value })} /></Field>
            <Field label="Role">
              <select className={inputClass} value={editing.role} onChange={(event) => setEditing({ ...editing, role: event.target.value })}>
                <option value="admin">{t("role.admin")} (admin)</option>
                <option value="moderator">{t("role.operator")} (moderator)</option>
                <option value="viewer">{t("role.viewer")} (viewer)</option>
              </select>
            </Field>
            <Field label="Password"><input className={inputClass} type="password" value={editing.password ?? ""} placeholder={editing.id ? "Leave blank to keep" : ""} onChange={(event) => setEditing({ ...editing, password: event.target.value })} /></Field>
            <button className="bg-primary px-3 py-2 text-sm text-primary-foreground">{t("common.save")}</button>
          </form>
        </Dialog>
      )}
    </Page>
  );
}

export function AccountPage() {
  const { t, setLocale } = useI18n();
  const { user, updateUser, logout } = useAuth();
  const admin = canAdmin(user?.role);
  const fail = useAsyncError();
  const toast = useToast();
  const [tab, setTab] = useState("profile");
  const [profile, setProfile] = useState({ email: user?.email ?? "", full_name: user?.full_name ?? "", language: user?.language || "en", timezone: user?.timezone || "UTC" });
  const [passwords, setPasswords] = useState({ current_password: "", new_password: "" });
  const [totp, setTotp] = useState<{ enabled: boolean; secret?: string; otpauth_url?: string }>({ enabled: Boolean(user?.totp_enabled) });
  const [code, setCode] = useState("");
  const [sessions, setSessions] = useState<{ id: string; created_at: string; expires_at: string; revoked_at?: string }[]>([]);
  const [audit, setAudit] = useState<{ id: number; event_type: string; object_type: string; created_at: string; detail: unknown }[]>([]);
  useEffect(() => {
    api<typeof sessions>("/api/v1/auth/sessions").then(setSessions).catch(fail);
    api<{ enabled: boolean }>("/api/v1/account/2fa").then((status) => setTotp((current) => ({ ...current, enabled: status.enabled }))).catch(fail);
    if (admin) api<typeof audit>("/api/v1/audit").then(setAudit).catch(fail);
  }, [admin, fail]);
  const tabs = ["profile", "password", "totp", "sessions", ...(admin ? ["activity"] : [])];
  return (
    <Page title={t("account.title")}>
      <div className="flex flex-wrap gap-2">
        {tabs.map((item) => (
          <button key={item} className={`border px-3 py-2 text-xs uppercase tracking-wider ${tab === item ? "bg-foreground text-background" : ""}`} onClick={() => setTab(item)}>{t(`account.${item}`)}</button>
        ))}
      </div>
      {tab === "profile" && (
        <Card title={t("account.profile")}>
          <form className="grid gap-3 md:grid-cols-2" onSubmit={async (event) => {
            event.preventDefault();
            try {
              const next = await api<SessionUser>("/api/v1/account/profile", { method: "PUT", body: JSON.stringify(profile) });
              updateUser(next);
              setLocale(next.language || "en");
              toast(t("common.save"), "ok");
            } catch (error) { fail(error); }
          }}>
            <Field label="Email"><input className={inputClass} value={profile.email} onChange={(event) => setProfile({ ...profile, email: event.target.value })} /></Field>
            <Field label="Full name"><input className={inputClass} value={profile.full_name} onChange={(event) => setProfile({ ...profile, full_name: event.target.value })} /></Field>
            <Field label="Language">
              <select className={inputClass} value={profile.language} onChange={(event) => setProfile({ ...profile, language: event.target.value })}>
                {SUPPORTED_LOCALES.map((locale) => <option key={locale.code} value={locale.code}>{locale.nativeLabel}</option>)}
              </select>
            </Field>
            <Field label="Timezone"><input className={inputClass} value={profile.timezone} onChange={(event) => setProfile({ ...profile, timezone: event.target.value })} /></Field>
            <button className="bg-primary px-3 py-2 text-sm text-primary-foreground md:col-span-2 md:w-fit">{t("common.save")}</button>
          </form>
        </Card>
      )}
      {tab === "password" && (
        <Card title={t("account.password")}>
          <form className="grid max-w-md gap-3" onSubmit={async (event) => {
            event.preventDefault();
            try {
              await api("/api/v1/account/password", { method: "POST", body: JSON.stringify(passwords) });
              setPasswords({ current_password: "", new_password: "" });
              toast(t("common.save"), "ok");
            } catch (error) { fail(error); }
          }}>
            <Field label="Current password"><input className={inputClass} type="password" value={passwords.current_password} onChange={(event) => setPasswords({ ...passwords, current_password: event.target.value })} /></Field>
            <Field label="New password"><input className={inputClass} type="password" value={passwords.new_password} onChange={(event) => setPasswords({ ...passwords, new_password: event.target.value })} /></Field>
            <button className="bg-primary px-3 py-2 text-sm text-primary-foreground">{t("common.save")}</button>
          </form>
        </Card>
      )}
      {tab === "totp" && (
        <Card title={t("account.totp")}>
          <p className="text-sm">{totp.enabled ? "Authenticator is enabled." : "Authenticator is not enabled."}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <button className="border px-3 py-2 text-sm" onClick={() => api<{ secret: string; otpauth_url: string }>("/api/v1/account/2fa/setup", { method: "POST" }).then((setup) => setTotp({ ...totp, ...setup })).catch(fail)}>Setup</button>
            <button className="border px-3 py-2 text-sm" onClick={() => api("/api/v1/account/2fa/enable", { method: "POST", body: JSON.stringify({ code }) }).then(() => { setTotp({ enabled: true }); toast(t("common.save"), "ok"); }).catch(fail)}>Enable</button>
            <button className="border px-3 py-2 text-sm" onClick={() => api("/api/v1/account/2fa/disable", { method: "POST", body: JSON.stringify({ code }) }).then(() => setTotp({ enabled: false })).catch(fail)}>Disable</button>
          </div>
          {totp.otpauth_url && <pre className="mt-3 overflow-auto bg-muted p-3 text-xs">{totp.secret}{"\n"}{totp.otpauth_url}</pre>}
          <Field label="Code"><input className={inputClass} value={code} onChange={(event) => setCode(event.target.value)} /></Field>
        </Card>
      )}
      {tab === "sessions" && (
        <Card title={t("account.sessions")} action={<button className="border px-2 py-1 text-sm" onClick={() => api("/api/v1/auth/logout-all", { method: "POST" }).then(() => logout())}>{t("account.logoutAll")}</button>}>
          <table className="w-full text-left text-sm">
            <tbody>
              {sessions.map((session) => (
                <tr key={session.id} className="border-t border-border">
                  <td className="py-2 font-mono text-xs">{session.id}</td>
                  <td>{new Date(session.created_at).toLocaleString()}</td>
                  <td>{session.revoked_at && session.revoked_at !== "0001-01-01T00:00:00Z" ? "revoked" : "active"}</td>
                  <td className="text-right"><button className="border px-2 py-1" onClick={() => api(`/api/v1/auth/sessions/${session.id}`, { method: "DELETE" }).then(() => api<typeof sessions>("/api/v1/auth/sessions").then(setSessions)).catch(fail)}>{t("account.revoke")}</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
      {tab === "activity" && admin && (
        <Card title={t("account.activity")}>
          <table className="w-full text-left text-sm">
            <tbody>
              {audit.map((row) => (
                <tr key={row.id} className="border-t border-border align-top">
                  <td className="py-2">{new Date(row.created_at).toLocaleString()}</td>
                  <td>{row.event_type}</td>
                  <td>{row.object_type}</td>
                  <td className="font-mono text-xs">{JSON.stringify(row.detail)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </Page>
  );
}

export function PlatformPage() {
  const { t } = useI18n();
  const fail = useAsyncError();
  const [error, setError] = useState("");
  const [environments, setEnvironments] = useState<Array<{ id: string; name: string }>>([]);
  const [accounts, setAccounts] = useState<Array<{ id: string; name: string; role: string }>>([]);
  const [rules, setRules] = useState<Array<{ id: string; name: string; kind: string; enabled: boolean }>>([]);
  const [token, setToken] = useState("");
  useEffect(() => {
    const report = (err: unknown) => {
      setError(err instanceof Error ? err.message : "Request failed");
      fail(err);
    };
    api<typeof environments>("/api/v1/platform/environments").then(setEnvironments).catch(report);
    api<typeof accounts>("/api/v1/platform/service-accounts").then(setAccounts).catch(report);
    api<typeof rules>("/api/v1/platform/alert-rules").then(setRules).catch(report);
  }, [fail]);
  return (
    <Page title={t("nav.platform")} subtitle={t("platform.subtitle")} action={null}>
      {error && <p className="mb-3 text-sm text-destructive">{error}</p>}
      <Card title={t("platform.environments")}>
        {environments.map((item) => <p key={item.id}>{item.name}</p>)}
        <form className="mt-2 flex gap-2" onSubmit={(event) => {
          event.preventDefault();
          const data = new FormData(event.currentTarget);
          api("/api/v1/platform/environments", { method: "POST", body: JSON.stringify({ name: data.get("name"), description: "" }) })
            .then(() => api<typeof environments>("/api/v1/platform/environments").then(setEnvironments))
            .catch(fail);
        }}>
          <input name="name" required className={inputClass} placeholder={t("platform.name")} />
          <button className="border px-3">{t("platform.add")}</button>
        </form>
      </Card>
      <Card title={t("platform.accounts")}>
        {accounts.map((item) => <p key={item.id}>{item.name} · {item.role}</p>)}
        {token && <p className="mt-2 font-mono text-xs">{token}</p>}
        <form className="mt-2 flex gap-2" onSubmit={(event) => {
          event.preventDefault();
          const data = new FormData(event.currentTarget);
          api<{ token: string }>("/api/v1/platform/service-accounts", { method: "POST", body: JSON.stringify({ name: data.get("name"), role: data.get("role") }) })
            .then((created) => {
              setToken(created.token);
              return api<typeof accounts>("/api/v1/platform/service-accounts").then(setAccounts);
            })
            .catch(fail);
        }}>
          <input name="name" required className={inputClass} placeholder={t("platform.name")} />
          <select name="role" className={inputClass}><option>viewer</option><option>moderator</option><option>admin</option></select>
          <button className="border px-3">{t("platform.add")}</button>
        </form>
      </Card>
      <Card title={t("platform.rules")}>
        {rules.map((rule) => (
          <div key={rule.id} className="flex items-center justify-between border-t border-border py-2 text-sm">
            <span>{rule.name} · {rule.kind}</span>
            <button className="border px-2 py-1" onClick={() => api(`/api/v1/platform/alert-rules/${rule.id}`, { method: "POST", body: JSON.stringify({ enabled: !rule.enabled }) }).then(() => api<typeof rules>("/api/v1/platform/alert-rules").then(setRules)).catch(fail)}>
              {rule.enabled ? t("platform.disable") : t("platform.enable")}
            </button>
          </div>
        ))}
      </Card>
    </Page>
  );
}
