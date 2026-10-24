import { useState, type FormEvent } from "react";
import type { ApiError } from "../api";
import { useAuth } from "../auth";
import { Field, Notice, errText } from "../ui";

export default function Login() {
  const { signIn } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needCode, setNeedCode] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true); setError("");
    try { await signIn(email, password, needCode ? code : undefined); }
    catch (err) {
      if ((err as ApiError).code === "mfa_required") setNeedCode(true);
      else { setError(errText(err)); setCode(""); }
    } finally { setBusy(false); }
  };

  return (
    <div className="center">
      <form className="card login" onSubmit={submit}>
        <h1>Bastion</h1>
        <p className="muted">Sign in to your security console.</p>
        {error && <Notice kind="error">{error}</Notice>}
        <Field label="Email"><input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} disabled={needCode} /></Field>
        <Field label="Password"><input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} disabled={needCode} /></Field>
        {needCode && (
          <Field label="Authenticator code" hint="The 6-digit code from your authenticator app.">
            <input inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6} required autoFocus value={code} onChange={(e) => setCode(e.target.value)} />
          </Field>
        )}
        <button className="primary" disabled={busy}>{busy ? "Signing in" : needCode ? "Verify and sign in" : "Sign in"}</button>
        {needCode && <button type="button" className="link" onClick={() => { setNeedCode(false); setCode(""); }}>Use a different account</button>}
      </form>
    </div>
  );
}
