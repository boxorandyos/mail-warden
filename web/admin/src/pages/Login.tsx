import { FormEvent, useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { CheckCircle2 } from "lucide-react";
import { api, publicPost, type LoginResponse } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useI18n } from "../lib/i18n";
import { Field, inputClass, useToast } from "../components/ui";

type Provider = { id: string; name: string; type: string; enabled: boolean };
type Step = "login" | "password" | "setup" | "verify";

export function LoginPage() {
  const { t } = useI18n();
  const toast = useToast();
  const { setSession } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const redirect = params.get("redirect") || "/dashboard";
  const [providers, setProviders] = useState<Provider[]>([]);
  const [providerId, setProviderId] = useState("local");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [nextPassword, setNextPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [step, setStep] = useState<Step>("login");
  const [userId, setUserId] = useState("");
  const [tempToken, setTempToken] = useState("");
  const [otp, setOtp] = useState<{ secret: string; otpauth_url: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    fetch("/api/v1/identity/login-providers")
      .then((res) => res.json())
      .then((list: Provider[]) => {
        const items = Array.isArray(list) ? list : [];
        setProviders(items);
        const local = items.find((item) => item.type === "local");
        const first = items.find((item) => item.type === "local" || item.type === "ldap");
        setProviderId(local?.id || first?.id || "local");
      })
      .catch(() => setProviders([]));
  }, []);

  useEffect(() => {
    const error = params.get("error");
    if (error) toast(error);
    const exchange = params.get("code");
    if (!exchange) return;
    setBusy(true);
    publicPost<LoginResponse>("/api/v1/auth/oidc/exchange", { code: exchange })
      .then((result) => accept(result))
      .catch((error: unknown) => toast(error instanceof Error ? error.message : "OIDC login failed"))
      .finally(() => setBusy(false));
    // accept closes over latest helpers; exchange runs once per code.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);

  function finish(result: LoginResponse) {
    if (!result.user || !result.tokens) return;
    setSession(result.user, result.tokens);
    if (result.user.language) localStorage.setItem("mail-warden.i18n.language", result.user.language);
    toast(t("login.toast.success"), "ok");
    navigate(redirect.startsWith("/") ? redirect : "/dashboard");
  }

  function accept(result: LoginResponse) {
    if (result.require_password_change && result.temp_token) {
      setUserId(result.user_id || "");
      setTempToken(result.temp_token);
      setStep("password");
      toast(t("login.toast.changePassword"), "ok");
      return;
    }
    if (result.requires_2fa && result.user_id) {
      setUserId(result.user_id);
      setStep("verify");
      toast(t("login.toast.enter2fa"), "ok");
      return;
    }
    if (result.require_2fa_setup && result.user && result.tokens) {
      setSession(result.user, result.tokens);
      setStep("setup");
      toast(t("login.toast.setup2fa"), "ok");
      void api<{ secret: string; otpauth_url: string }>("/api/v1/account/2fa/setup", { method: "POST" }).then(setOtp).catch((error: unknown) => toast(error instanceof Error ? error.message : "Setup failed"));
      return;
    }
    finish(result);
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      if (step === "verify") {
        const result = await publicPost<LoginResponse>("/api/v1/auth/verify-2fa", { user_id: userId, code });
        finish(result);
      } else if (step === "password") {
        if (nextPassword !== confirm) throw new Error("Passwords do not match");
        const result = await publicPost<LoginResponse>("/api/v1/auth/first-login/change-password", { temp_token: tempToken, new_password: nextPassword });
        accept(result);
      } else if (step === "setup") {
        await api("/api/v1/account/2fa/enable", { method: "POST", body: JSON.stringify({ code }) });
        navigate(redirect.startsWith("/") ? redirect : "/dashboard");
      } else {
        const result = await publicPost<LoginResponse>("/api/v1/auth/login", { username, password, provider_id: providerId });
        accept(result);
      }
    } catch (error) {
      toast(error instanceof Error ? error.message : "Sign-in failed");
    } finally {
      setBusy(false);
    }
  }

  const passwordProviders = providers.filter((item) => item.type === "local" || item.type === "ldap");
  const oidcProviders = providers.filter((item) => item.type === "oidc");
  const highlights = [t("login.hero.highlight1"), t("login.hero.highlight2"), t("login.hero.highlight3")];

  return (
    <div className="flex min-h-screen flex-col lg:flex-row">
      <aside className="relative min-h-[220px] overflow-hidden bg-gradient-to-br from-stone-950 via-stone-900 to-amber-950 text-stone-100 lg:w-[46%]">
        <div className="pointer-events-none absolute -left-24 top-10 h-72 w-72 rounded-full bg-amber-500/25 blur-[100px]" />
        <div className="pointer-events-none absolute -right-16 bottom-0 h-72 w-72 rounded-full bg-orange-600/30 blur-[110px]" />
        <div className="relative z-10 flex h-full flex-col justify-between px-8 py-10 lg:px-12 lg:py-14">
          <div>
            <div className="text-sm font-bold tracking-tight">{t("app.name")}</div>
            <h1 className="mt-10 max-w-md text-3xl font-bold tracking-tight text-white lg:text-4xl">{t("login.hero.title")}</h1>
            <p className="mt-3 max-w-md text-sm text-stone-300">{t("login.hero.subtitle")}</p>
            <ul className="mt-8 space-y-3">
              {highlights.map((line) => (
                <li key={line} className="flex items-start gap-2 text-sm text-stone-200">
                  <CheckCircle2 className="mt-0.5 h-4 w-4 text-amber-300" />
                  <span>{line}</span>
                </li>
              ))}
            </ul>
          </div>
          <p className="text-[11px] uppercase tracking-[0.2em] text-stone-500">{t("login.hero.badge")}</p>
        </div>
      </aside>
      <div className="flex flex-1 items-center justify-center bg-background px-4 py-12">
        <form onSubmit={onSubmit} className="w-full max-w-md space-y-4 border border-border bg-card p-6 shadow-2xl">
          <div>
            <h2 className="text-2xl font-bold tracking-tight">
              {step === "verify" ? t("login.twoFactorTitle") : step === "password" ? t("login.passwordTitle") : step === "setup" ? t("login.setupTitle") : t("login.title")}
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              {step === "verify" ? t("login.twoFactorDescription") : step === "password" ? t("login.passwordDescription") : step === "setup" ? t("login.setupDescription") : t("login.cardDescription")}
            </p>
          </div>
          {step === "login" && (
            <>
              {passwordProviders.length > 1 && (
                <Field label={t("login.provider")}>
                  <select className={inputClass} value={providerId} onChange={(event) => setProviderId(event.target.value)}>
                    {passwordProviders.map((item) => (
                      <option key={item.id} value={item.id}>{item.name}</option>
                    ))}
                  </select>
                </Field>
              )}
              <Field label={t("login.username")}>
                <input className={inputClass} value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" />
              </Field>
              <Field label={t("login.password")}>
                <input className={inputClass} type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" />
              </Field>
            </>
          )}
          {step === "password" && (
            <>
              <Field label={t("login.newPassword")}><input className={inputClass} type="password" value={nextPassword} onChange={(event) => setNextPassword(event.target.value)} /></Field>
              <Field label={t("login.confirmPassword")}><input className={inputClass} type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} /></Field>
            </>
          )}
          {(step === "verify" || step === "setup") && (
            <>
              {otp && (
                <div className="space-y-1 border border-border bg-muted p-3 text-xs">
                  <div className="break-all font-mono">{otp.otpauth_url}</div>
                  <div className="font-mono">{otp.secret}</div>
                </div>
              )}
              <Field label={t("login.code")}><input className={inputClass} inputMode="numeric" value={code} onChange={(event) => setCode(event.target.value)} /></Field>
            </>
          )}
          <button className="w-full bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground" disabled={busy}>
            {busy ? t("login.working") : step === "password" ? t("login.changePassword") : step === "setup" ? t("login.enable") : step === "verify" ? t("login.verify") : t("login.submit")}
          </button>
          {step === "setup" && (
            <button type="button" className="w-full border px-3 py-2 text-sm" onClick={() => navigate(redirect.startsWith("/") ? redirect : "/dashboard")}>{t("login.skip")}</button>
          )}
          {step === "login" && oidcProviders.map((item) => (
            <button
              key={item.id}
              type="button"
              className="w-full border px-3 py-2 text-sm"
              onClick={() => {
                const returnTo = redirect.startsWith("/") ? redirect : "/dashboard";
                window.location.assign(`/api/v1/auth/oidc/start?provider_id=${encodeURIComponent(item.id)}&return_to=${encodeURIComponent(returnTo)}`);
              }}
            >
              {t("login.oidc")} {item.name}
            </button>
          ))}
        </form>
      </div>
    </div>
  );
}
