import { useCallback, useEffect, useState, type ReactNode } from "react";
import type { ApiError } from "./api";
import { useAuth } from "./auth";

export function errText(e: unknown): string {
  return (e as ApiError)?.message ?? "Something went wrong.";
}

export function useLoad<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const { refresh } = useAuth();
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const load = useCallback(async () => {
    setLoading(true);
    try { setData(await fn()); setError(""); }
    catch (e) {
      if ((e as ApiError).status === 401) void refresh(); // session ended: return to sign in
      setError(errText(e));
    } finally { setLoading(false); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { void load(); }, [load]);
  return { data, error, loading, reload: load };
}

export function Page({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <>
      <header className="page-head"><h1>{title}</h1><div className="actions">{actions}</div></header>
      {children}
    </>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint && <small className="muted">{hint}</small>}
    </label>
  );
}

export const Notice = ({ kind = "info", children }: { kind?: "info" | "error" | "ok"; children: ReactNode }) => (
  <div className={`notice ${kind}`} role={kind === "error" ? "alert" : "status"}>{children}</div>
);
