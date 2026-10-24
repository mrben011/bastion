import { useState, type FormEvent } from "react";
import { ROLE_LABEL, api, fmt } from "../api";
import { useAuth } from "../auth";
import { Field, Notice, Page, errText } from "../ui";

export default function Account() {
  const { me } = useAuth();
  const [cur, setCur] = useState(""); const [next, setNext] = useState("");
  const [msg, setMsg] = useState(""); const [error, setError] = useState("");
  if (!me) return null;
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setMsg(""); setError("");
    try { await api("POST", "/auth/change-password", { current_password: cur, new_password: next }); setMsg("Password changed. Your other sessions were signed out."); setCur(""); setNext(""); }
    catch (err) { setError(errText(err)); }
  };
  return (
    <Page title="My account">
      <section className="panel">
        <dl className="kv">
          <dt>Name</dt><dd>{me.user.display_name}</dd>
          <dt>Email</dt><dd>{me.user.email}</dd>
          <dt>Role</dt><dd>{ROLE_LABEL[me.user.role]}</dd>
          <dt>Two-step verification</dt><dd>{me.user.mfa_enabled ? "On" : "Off"}</dd>
          <dt>Last sign-in</dt><dd>{fmt(me.user.last_login_at)}</dd>
        </dl>
      </section>
      <form className="panel narrow" onSubmit={submit}>
        <h2>Change password</h2>
        {msg && <Notice kind="ok">{msg}</Notice>}{error && <Notice kind="error">{error}</Notice>}
        <Field label="Current password"><input type="password" autoComplete="current-password" required value={cur} onChange={(e) => setCur(e.target.value)} /></Field>
        <Field label="New password" hint="At least 12 characters."><input type="password" autoComplete="new-password" required value={next} onChange={(e) => setNext(e.target.value)} /></Field>
        <button className="primary">Change password</button>
      </form>
    </Page>
  );
}
