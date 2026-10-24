import { useState, type FormEvent } from "react";
import { api, fmt, type Asset } from "../api";
import { useAuth } from "../auth";
import { Field, Notice, Page, errText, useLoad } from "../ui";

const TYPES = ["postgresql", "application", "api", "cloud_environment", "server", "identity_provider"];
const TYPE_LABEL: Record<string, string> = {
  postgresql: "PostgreSQL database", application: "Application", api: "API", cloud_environment: "Cloud environment",
  server: "Server", identity_provider: "Identity provider",
};
const ENVS = ["production", "staging", "development", "test"];
const blank = { name: "", asset_type: "postgresql", environment: "production", description: "", host: "", port: "", database_name: "", secret_ref: "" };

export default function Assets() {
  const { can } = useAuth();
  const [q, setQ] = useState(""); const [env, setEnv] = useState("");
  const { data, error, reload } = useLoad(() => api<Asset[]>("GET", `/assets?${new URLSearchParams({ ...(q && { q }), ...(env && { environment: env }) })}`), [q, env]);
  const [form, setForm] = useState<(typeof blank & { id?: string }) | null>(null);
  const [formError, setFormError] = useState("");

  const edit = (a: Asset) => { setFormError(""); setForm({ id: a.id, name: a.name, asset_type: a.asset_type, environment: a.environment, description: a.description, host: a.host ?? "", port: a.port?.toString() ?? "", database_name: a.database_name ?? "", secret_ref: a.secret_ref ?? "" }); };

  const save = async (e: FormEvent) => {
    e.preventDefault(); if (!form) return; setFormError("");
    const { id, ...f } = form;
    const body = { ...f, port: f.port ? Number(f.port) : null, host: f.host || null, database_name: f.database_name || null, secret_ref: f.secret_ref || null };
    try { await (id ? api("PUT", `/assets/${id}`, body) : api("POST", "/assets", body)); setForm(null); await reload(); }
    catch (err) { setFormError(errText(err)); }
  };
  const remove = async (a: Asset) => {
    if (!window.confirm(`Remove ${a.name}? Its history stays in the audit log.`)) return;
    try { await api("DELETE", `/assets/${a.id}`); await reload(); } catch (err) { window.alert(errText(err)); }
  };
  const set = (k: string) => (e: { target: { value: string } }) => setForm((f) => (f ? { ...f, [k]: e.target.value } : f));

  return (
    <Page title="Protected assets" actions={can("assets:write") && <button className="primary" onClick={() => { setFormError(""); setForm({ ...blank }); }}>Register asset</button>}>
      <div className="toolbar">
        <input type="search" placeholder="Search by name" aria-label="Search assets" value={q} onChange={(e) => setQ(e.target.value)} />
        <select aria-label="Environment" value={env} onChange={(e) => setEnv(e.target.value)}>
          <option value="">All environments</option>{ENVS.map((x) => <option key={x}>{x}</option>)}
        </select>
      </div>
      {error && <Notice kind="error">{error}</Notice>}
      {form && (
        <form className="panel" onSubmit={save}>
          <h2>{form.id ? "Edit asset" : "Register asset"}</h2>
          {formError && <Notice kind="error">{formError}</Notice>}
          <div className="grid">
            <Field label="Name"><input required maxLength={120} value={form.name} onChange={set("name")} /></Field>
            <Field label="Type"><select value={form.asset_type} onChange={set("asset_type")}>{TYPES.map((t) => <option key={t} value={t}>{TYPE_LABEL[t]}</option>)}</select></Field>
            <Field label="Environment"><select value={form.environment} onChange={set("environment")}>{ENVS.map((t) => <option key={t}>{t}</option>)}</select></Field>
            <Field label="Host"><input value={form.host} onChange={set("host")} placeholder="db.internal.example.com" /></Field>
            <Field label="Port"><input type="number" min={1} max={65535} value={form.port} onChange={set("port")} /></Field>
            <Field label="Database name"><input value={form.database_name} onChange={set("database_name")} /></Field>
            <Field label="Secret reference" hint="The name of the credential in your secrets manager. Never paste the password here."><input value={form.secret_ref} onChange={set("secret_ref")} placeholder="vault/orders/readonly" /></Field>
            <Field label="Description"><input maxLength={1000} value={form.description} onChange={set("description")} /></Field>
          </div>
          <div className="row"><button className="primary">Save asset</button><button type="button" onClick={() => setForm(null)}>Cancel</button></div>
        </form>
      )}
      <section className="panel flush">
        <table>
          <thead><tr><th>Name</th><th>Type</th><th>Environment</th><th>Monitoring</th><th>Last event</th><th>Registered</th>{can("assets:write") && <th><span className="sr">Actions</span></th>}</tr></thead>
          <tbody>
            {data?.map((a) => (
              <tr key={a.id}>
                <td><strong>{a.name}</strong>{a.host && <div className="muted small">{a.host}{a.port ? `:${a.port}` : ""}{a.database_name ? ` / ${a.database_name}` : ""}</div>}</td>
                <td>{TYPE_LABEL[a.asset_type]}</td>
                <td><span className={`tag env-${a.environment}`}>{a.environment}</span></td>
                <td><span className="tag muted-tag">Not configured</span></td>
                <td className="muted">{fmt(a.last_event_at)}</td>
                <td className="muted">{fmt(a.created_at)}</td>
                {can("assets:write") && <td className="right"><button className="link" onClick={() => edit(a)}>Edit</button> <button className="link danger" onClick={() => void remove(a)}>Remove</button></td>}
              </tr>
            ))}
            {data?.length === 0 && <tr><td colSpan={7} className="empty">No assets match. {can("assets:write") ? "Register your first protected asset to begin." : "Ask an administrator to register one."}</td></tr>}
          </tbody>
        </table>
      </section>
    </Page>
  );
}
