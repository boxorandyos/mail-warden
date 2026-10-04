import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

type Toast = { id: number; text: string; tone: "ok" | "err" };
const ToastContext = createContext<(text: string, tone?: "ok" | "err") => void>(() => undefined);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: string, tone: "ok" | "err" = "err") => {
    const id = Date.now() + Math.random();
    setToasts((current) => [...current, { id, text, tone }]);
    setTimeout(() => setToasts((current) => current.filter((item) => item.id !== id)), 4200);
  }, []);
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[80] flex w-[min(24rem,calc(100%-2rem))] flex-col gap-2">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`pointer-events-auto border px-3 py-2 text-sm shadow-lg ${toast.tone === "ok" ? "border-primary/40 bg-card" : "border-destructive/50 bg-card"}`}
          >
            {toast.text}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}

type ConfirmRequest = {
  title: string;
  body: string;
  confirmLabel: string;
  resolve: (ok: boolean) => void;
};

const ConfirmContext = createContext<(title: string, body: string, confirmLabel?: string) => Promise<boolean>>(async () => false);

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [request, setRequest] = useState<ConfirmRequest | null>(null);
  const ask = useCallback((title: string, body: string, confirmLabel = "Confirm") => {
    return new Promise<boolean>((resolve) => setRequest({ title, body, confirmLabel, resolve }));
  }, []);
  const close = (ok: boolean) => {
    request?.resolve(ok);
    setRequest(null);
  };
  return (
    <ConfirmContext.Provider value={ask}>
      {children}
      {request && (
        <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/40 p-4">
          <div className="w-full max-w-md border border-border bg-card p-5 shadow-2xl" role="dialog" aria-modal="true">
            <h2 className="text-lg font-semibold">{request.title}</h2>
            <p className="mt-2 text-sm text-muted-foreground">{request.body}</p>
            <div className="mt-5 flex justify-end gap-2">
              <button className="border px-3 py-2 text-sm" onClick={() => close(false)}>Cancel</button>
              <button className="bg-primary px-3 py-2 text-sm text-primary-foreground" onClick={() => close(true)}>
                {request.confirmLabel}
              </button>
            </div>
          </div>
        </div>
      )}
    </ConfirmContext.Provider>
  );
}

export function useConfirm() {
  return useContext(ConfirmContext);
}

export function Dialog({
  title,
  children,
  onClose
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
}) {
  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 p-4" onMouseDown={onClose}>
      <div className="max-h-[90vh] w-full max-w-3xl overflow-auto border border-border bg-card p-5 shadow-2xl" role="dialog" aria-modal="true" onMouseDown={(event) => event.stopPropagation()}>
        <div className="mb-4 flex items-center justify-between gap-3">
          <h2 className="text-lg font-semibold">{title}</h2>
          <button className="border px-2 py-1 text-xs uppercase tracking-wider" onClick={onClose}>Close</button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function Card({ title, children, action }: { title?: string; children: ReactNode; action?: ReactNode }) {
  return (
    <section className="border border-border bg-card shadow-sm">
      {(title || action) && (
        <header className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
          <h2 className="text-sm font-semibold uppercase tracking-[0.14em]">{title}</h2>
          {action}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block space-y-1 text-sm">
      <span className="text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">{label}</span>
      {children}
    </label>
  );
}

export const inputClass = "w-full border border-input bg-background px-3 py-2 text-sm outline-none focus:border-primary";

export function Page({ title, subtitle, children, action }: { title: string; subtitle?: string; children: ReactNode; action?: ReactNode }) {
  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-4 px-4 py-6 md:px-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{title}</h1>
          {subtitle && <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{subtitle}</p>}
        </div>
        {action}
      </header>
      {children}
    </div>
  );
}

export function useAsyncError() {
  const toast = useToast();
  return useMemo(
    () => (error: unknown) => toast(error instanceof Error ? error.message : "Request failed"),
    [toast]
  );
}
