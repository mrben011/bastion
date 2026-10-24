import { useState, type FormEvent } from "react";
import { ROLE_LABEL, api, fmt, type User } from "../api";
import { useAuth } from "../auth";
import { Field, Notice, Page, errText, useLoad } from "../ui";

const ROLES = Object.keys(ROLE_LABEL);

export default function Users() {
  const { can, me } = useAuth();
  const { data, error, reload } = useLoad(() => api<User[]>("GET", "/users"));
  const [adding, setAdding] = useState(false);
  const [f, setF] = useState({ email: "", display_name: "", role: "security_analyst", initial_password: "" });
  const [formError, setFormError] = useState(""); const [actionError, setActionError] = useState("");
  const manage = can("users:manage");

  const add = async (e: FormEvent) => {
    e.preventDefault(); setFormError("");
    try { await api("POST", "/users", f); setAdding(false); setF({ email: "", display_name: "", role: "security_analyst", initial_password: "" }); await reload(); }
    catch (err) { setFormError(errText(err)); }
  };
  const act = async (fn: () => Promise<unknown>, confirm?: string) => {
    if (confirm && !window.confirm(confirm)) return;
    setActionError("");
    try { await fn(); await reload(); } catch (err) { setActionError(errText(err)); }
  };

  return (
    <Page title="People and access" actions={manage && <button className="primary" onClick={() => setAdding(true)}>Add person</button>}>
      {(error || actionError) && <Notice kind="error">{error || actionError}</Notice>}
      {adding && (
        <form className="panel" onSubmit={add}>
          <h2>Add person</h2>
          {formError && <Notice kind="error">{formError}</Notice>}
          <div className="grid">
            <Field label="Name"><input required value={f.display_name} onChange={(e) => setF({ ...f, display_name: e.target.value })} /></Field>
            <Field label="Email"><input type="email" required value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></Field>
            <Field label="Role"><select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>{ROLES.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}</select></Field>
            <Field label="Temporary password" hint="They must replace it at first sign-in. Share it through a separate secure channel."><input type="password" autoComplete="new-password" required value={f.initial_password} onChange={(e) => setF({ ...f, initial_password: e.target.value })} /></Field>
          </div>
          <div className="row"><button className="primary">Add person</button><button type="button" onClick={() => setAdding(false)}>Cancel</button></div>
        </form>
      )}
      <section className="panel flush">
        <table>
          <thead><tr><th>Person</th><th>Role</th><th>Verification</th><th>Last sign-in</th><th>Status</th>{manage && <th><span className="sr">Actions</span></th>}</tr></thead>
          <tbody>
            {data?.map((u) => (
              <tr key={u.id}>
                <td><strong>{u.display_name}</strong><div className="muted small">{u.email}</div></td>
                <td>{manage && u.id !== me?.user.id ? (
                  <select aria-label={`Role for ${u.email}`} value={u.role} onChange={(e) => void act(() => api("PATCH", `/users/${u.id}`, { role: e.target.value }), `Change ${u.email} to ${ROLE_LABEL[e.target.value]}? Their sessions will end.`)}>
                    {ROLES.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
                  </select>) : ROLE_LABEL[u.role]}</td>
                <td>{u.mfa_enabled ? "On" : <span className="muted">Off</span>}</td>
                <td className="muted">{fmt(u.last_login_at)}</td>
                <td><span className={`tag ${u.is_active ? "ok-tag" : "muted-tag"}`}>{u.is_active ? "Active" : "Deactivated"}</span></td>
                {manage && (
                  <td className="right">
                    {u.id !== me?.user.id && <>
                      <button className="link" onClick={() => void act(() => api("PATCH", `/users/${u.id}`, { is_active: !u.is_active }), u.is_active ? `Deactivate ${u.email}? Their sessions will end.` : undefined)}>{u.is_active ? "Deactivate" : "Reactivate"}</button>{" "}
                      <button className="link" onClick={() => void act(() => api("POST", `/users/${u.id}/reset-mfa`), `Reset two-step verification for ${u.email}? They will be signed out.`)}>Reset verification</button>{" "}
                      <button className="link" onClick={() => void act(() => api("POST", `/users/${u.id}/revoke-sessions`))}>Sign out everywhere</button>
                    </>}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </Page>
  );
}
