import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { clearSession, loadStoredUser, persistSession, type SessionUser, type TokenPair, api } from "./api";

type AuthValue = {
  user: SessionUser | null;
  setSession: (user: SessionUser, tokens: TokenPair) => void;
  updateUser: (user: SessionUser) => void;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<SessionUser | null>(loadStoredUser);
  const value = useMemo<AuthValue>(
    () => ({
      user,
      setSession: (next, tokens) => {
        persistSession(next, tokens);
        setUser(next);
      },
      updateUser: (next) => {
        const tokens = {
          access_token: localStorage.getItem("accessToken") ?? "",
          refresh_token: localStorage.getItem("refreshToken") ?? ""
        };
        persistSession(next, tokens);
        setUser(next);
      },
      logout: async () => {
        const refresh = localStorage.getItem("refreshToken");
        try {
          if (refresh) await api("/api/v1/auth/logout", { method: "POST", body: JSON.stringify({ refresh_token: refresh }) });
        } catch {
          /* the local session still ends */
        }
        clearSession();
        setUser(null);
      }
    }),
    [user]
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("auth missing");
  return value;
}

export function canOperate(role?: string) {
  return role === "admin" || role === "moderator";
}

export function canAdmin(role?: string) {
  return role === "admin";
}
