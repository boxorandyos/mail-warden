import { useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { Check, ChevronDown, Languages, LogOut, Menu, Moon, Sun, UserRound, X } from "lucide-react";
import { canAdmin, useAuth } from "../lib/auth";
import { useI18n } from "../lib/i18n";
import { useTheme, type ThemeChoice } from "../lib/theme";
import { SUPPORTED_LOCALES } from "../locales";

type Item = { to: string; label: string; admin?: boolean };
type Section = { id: string; label: string; items?: Item[]; to?: string };

export function Shell({ children }: { children: React.ReactNode }) {
  const { t } = useI18n();
  const { user } = useAuth();
  const admin = canAdmin(user?.role);
  const sections: Section[] = [
    { id: "pulse", label: t("nav.section.pulse"), to: "/dashboard" },
    {
      id: "mail",
      label: t("nav.section.mail"),
      items: [
        { to: "/messages", label: t("nav.messages") },
        { to: "/quarantine", label: t("nav.quarantine") }
      ]
    },
    {
      id: "policy",
      label: t("nav.section.policy"),
      items: [
        { to: "/policy", label: t("nav.policy") },
        { to: "/identity", label: t("nav.identity"), admin: true }
      ]
    },
    {
      id: "telemetry",
      label: t("nav.section.telemetry"),
      items: [
        { to: "/events", label: t("nav.events") },
        { to: "/metrics", label: t("nav.metrics") }
      ]
    },
    {
      id: "control",
      label: t("nav.section.control"),
      items: [
        { to: "/configuration", label: t("nav.configuration"), admin: true },
        { to: "/users", label: t("nav.users"), admin: true },
        { to: "/cluster", label: t("nav.cluster"), admin: true },
        { to: "/snapshots", label: t("nav.snapshots"), admin: true },
        { to: "/platform", label: t("nav.platform"), admin: true }
      ]
    }
  ].map((section) => ({
    ...section,
    items: section.items?.filter((item) => !item.admin || admin)
  }));

  return (
    <div className="app-canvas min-h-screen">
      <TopBar sections={sections} />
      <main>{children}</main>
    </div>
  );
}

function TopBar({ sections }: { sections: Section[] }) {
  const [open, setOpen] = useState(false);
  const { t } = useI18n();
  return (
    <header className="sticky top-0 z-50 flex h-14 items-center border-b border-foreground/10 bg-background/95 backdrop-blur-sm">
      <div className="flex w-full items-center gap-3 px-3 md:px-5">
        <button className="border p-2 md:hidden" aria-label="Open menu" onClick={() => setOpen(true)}>
          <Menu className="h-5 w-5" />
        </button>
        <NavLink to="/dashboard" className="text-sm font-bold tracking-tight">
          {t("app.name")}
        </NavLink>
        <nav className="ml-4 hidden items-center gap-1 md:flex">
          {sections.map((section) =>
            section.to ? (
              <NavLink key={section.id} to={section.to} className={linkClass}>
                {section.label}
              </NavLink>
            ) : (
              <MenuButton key={section.id} section={section} />
            )
          )}
        </nav>
        <div className="ml-auto">
          <UserMenu />
        </div>
      </div>
      {open && (
        <div className="fixed inset-0 z-50 md:hidden">
          <button className="absolute inset-0 bg-black/40" aria-label="Close menu" onClick={() => setOpen(false)} />
          <aside className="absolute inset-y-0 left-0 flex w-[min(100%,20rem)] flex-col border-r border-border bg-background">
            <div className="flex items-center justify-between border-b px-4 py-4">
              <span className="font-bold">{t("app.name")}</span>
              <button onClick={() => setOpen(false)} aria-label="Close"><X className="h-5 w-5" /></button>
            </div>
            <nav className="flex-1 overflow-auto p-3">
              {sections.map((section) => (
                <div key={section.id} className="mb-4">
                  <div className="px-2 text-[10px] font-bold uppercase tracking-[0.2em] text-muted-foreground">{section.label}</div>
                  {section.to && <MobileLink to={section.to} label={section.label} onClick={() => setOpen(false)} />}
                  {section.items?.map((item) => (
                    <MobileLink key={item.to} to={item.to} label={item.label} onClick={() => setOpen(false)} />
                  ))}
                </div>
              ))}
            </nav>
          </aside>
        </div>
      )}
    </header>
  );
}

const linkClass = ({ isActive }: { isActive: boolean }) =>
  `border px-3 py-2 text-xs font-semibold uppercase tracking-[0.18em] ${isActive ? "border-foreground/20 bg-foreground/[0.06]" : "border-transparent text-muted-foreground hover:border-foreground/10"}`;

function MenuButton({ section }: { section: Section }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative" onMouseLeave={() => setOpen(false)}>
      <button className="flex items-center gap-1 border border-transparent px-3 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground hover:border-foreground/10 hover:text-foreground" onClick={() => setOpen((value) => !value)}>
        {section.label}
        <ChevronDown className="h-3 w-3" />
      </button>
      {open && (
        <div className="absolute left-0 top-full z-50 min-w-48 border border-border bg-card p-1 shadow-lg">
          <div className="border-b px-2 py-2 text-[10px] font-bold uppercase tracking-[0.2em] text-muted-foreground">{section.label}</div>
          {section.items?.map((item) => (
            <NavLink key={item.to} to={item.to} onClick={() => setOpen(false)} className="block px-2 py-2 text-sm hover:bg-muted">
              {item.label}
            </NavLink>
          ))}
        </div>
      )}
    </div>
  );
}

function MobileLink({ to, label, onClick }: { to: string; label: string; onClick: () => void }) {
  return (
    <NavLink to={to} onClick={onClick} className="block px-2 py-2 text-sm">
      {label}
    </NavLink>
  );
}

function UserMenu() {
  const { user, logout } = useAuth();
  const { t, locale, setLocale } = useI18n();
  const { theme, setTheme } = useTheme();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [panel, setPanel] = useState<"root" | "theme" | "language">("root");
  const role = user?.role === "moderator" ? t("role.operator") : user?.role === "admin" ? t("role.admin") : t("role.viewer");
  const themes: ThemeChoice[] = ["light", "dark", "system"];
  return (
    <div className="relative">
      <button className="flex items-center gap-2 border px-2 py-1" onClick={() => { setOpen((value) => !value); setPanel("root"); }}>
        <span className="flex h-7 w-7 items-center justify-center bg-primary text-xs font-bold text-primary-foreground">
          {(user?.full_name || user?.username || "?").slice(0, 1).toUpperCase()}
        </span>
        <span className="hidden text-left sm:block">
          <span className="block text-xs font-semibold">{user?.full_name || user?.username}</span>
          <span className="block text-[10px] uppercase tracking-wider text-muted-foreground">{role}</span>
        </span>
      </button>
      {open && (
        <div className="absolute right-0 top-full z-50 mt-1 w-64 border border-border bg-card p-1 shadow-xl">
          {panel === "root" && (
            <>
              <button className="flex w-full items-center gap-2 px-2 py-2 text-sm hover:bg-muted" onClick={() => { setOpen(false); navigate("/account"); }}>
                <UserRound className="h-4 w-4" /> {t("nav.account")}
              </button>
              <button className="flex w-full items-center gap-2 px-2 py-2 text-sm hover:bg-muted" onClick={() => setPanel("theme")}>
                {theme === "dark" ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />} {t("nav.theme")}
              </button>
              <button className="flex w-full items-center gap-2 px-2 py-2 text-sm hover:bg-muted" onClick={() => setPanel("language")}>
                <Languages className="h-4 w-4" /> {t("nav.language")}
              </button>
              <button className="flex w-full items-center gap-2 px-2 py-2 text-sm hover:bg-muted" onClick={() => { setOpen(false); void logout().then(() => navigate("/login")); }}>
                <LogOut className="h-4 w-4" /> {t("nav.signOut")}
              </button>
            </>
          )}
          {panel === "theme" && themes.map((choice) => (
            <button key={choice} className="flex w-full items-center justify-between px-2 py-2 text-sm hover:bg-muted" onClick={() => setTheme(choice)}>
              {t(`theme.${choice}`)} {theme === choice && <Check className="h-4 w-4" />}
            </button>
          ))}
          {panel === "language" && SUPPORTED_LOCALES.map((item) => (
            <button key={item.code} className="flex w-full items-center justify-between px-2 py-2 text-sm hover:bg-muted" onClick={() => setLocale(item.code)}>
              <span>{item.nativeLabel} <span className="text-muted-foreground">({item.label})</span></span>
              {locale === item.code && <Check className="h-4 w-4" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
