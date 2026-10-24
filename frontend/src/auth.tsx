import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, setCsrf, type ApiError, type User } from "./api";

type Me = { user: User; csrf_token: string; restriction: string | null; permissions: string[] };
type Ctx = {
  me: Me | null; loading: boolean; refresh: () => Promise<void>; can: (p: string) => boolean;
  signIn: (email: string, password: string, totp?: string) => Promise<void>; signOut: () => Promise<void>;
};
const AuthCtx = createContext<Ctx>(null as unknown as Ctx);
export const useAuth = () => useContext(AuthCtx);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const m = await api<Me>("GET", "/auth/me");
      setCsrf(m.csrf_token);
      setMe(m);
    } catch (e) {
      if ((e as ApiError).status === 401) setMe(null);
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  const signIn = async (email: string, password: string, totp?: string) => {
    await api("POST", "/auth/login", { email, password, totp_code: totp || null });
    await refresh();
  };
  const signOut = async () => {
    try { await api("POST", "/auth/logout"); } finally { setMe(null); setCsrf(""); }
  };
  const can = (p: string) => !!me?.permissions.includes(p);

  return <AuthCtx.Provider value={{ me, loading, refresh, can, signIn, signOut }}>{children}</AuthCtx.Provider>;
}
