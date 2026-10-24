export type ApiError = { status: number; code: string; message: string; restriction?: string };

let csrf = "";
export const setCsrf = (t: string) => { csrf = t; };

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrf;
  const res = await fetch(`/api${path}`, {
    method, headers, credentials: "same-origin", body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch { /* non-JSON error page */ }
  if (!res.ok) {
    let d = data?.detail;
    if (Array.isArray(d)) d = { code: "validation", message: d.map((e: any) => `${(e.loc || []).slice(1).join(".")}: ${e.msg}`).join("; ") };
    const err: ApiError = {
      status: res.status, code: d?.code ?? "error", message: d?.message ?? "Request failed.", restriction: d?.restriction,
    };
    throw err;
  }
  return data as T;
}

export type User = {
  id: string; email: string; display_name: string; role: string; is_active: boolean; mfa_enabled: boolean;
  must_change_password: boolean; last_login_at: string | null; created_at: string;
};
export type Asset = {
  id: string; name: string; asset_type: string; environment: string; description: string; host: string | null;
  port: number | null; database_name: string | null; secret_ref: string | null; created_at: string; updated_at: string;
  monitoring_status: string; last_event_at: string | null;
};
export type AuditEvent = {
  seq: number; ts: string; actor_label: string | null; action: string; outcome: string;
  target_type: string | null; target_id: string | null; ip: string | null; details: Record<string, unknown>; hash: string;
};

export const ROLE_LABEL: Record<string, string> = {
  platform_admin: "Platform administrator", security_analyst: "Security analyst",
  incident_responder: "Incident responder", auditor: "Auditor",
};
export const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "Never");
