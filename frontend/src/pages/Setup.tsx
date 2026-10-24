import { useState, type FormEvent } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { Field, Notice, errText } from "../ui";

function ChangePassword({ onDone }: { onDone: () => void }) {
  const [cur, setCur] = useState(""); const [next, setNext] = useState(""); const [error, setError] = useState("");
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setError("");
    try { await api("POST", "/auth/change-password", { current_password: cur, new_password: next }); onDone(); }
    catch (err) { setError(errText(err)); }
  };
  return (
    <form className="card" onSubmit={submit}>
      <h1>Choose a new password</h1>
      <p className="muted">An administrator set your temporary password. Replace it before continuing.</p>
      {error && <Notice kind="error">{error}</Notice>}
      <Field label="Temporary password"><input type="password" autoComplete="current-password" required value={cur} onChange={(e) => setCur(e.target.value)} /></Field>
      <Field label="New password" hint="At least 12 characters. A passphrase works well."><input type="password" autoComplete="new-password" required value={next} onChange={(e) => setNext(e.target.value)} /></Field>
      <button className="primary">Save password</button>
    </form>
  );
}

type Enroll = { secret: string; otpauth_uri: string; qr_svg: string };

function EnrollMfa({ onDone }: { onDone: () => void }) {
  const [enroll, setEnroll] = useState<Enroll | null>(null);
  const [code, setCode] = useState(""); const [error, setError] = useState("");
  const start = async () => { try { setEnroll(await api<Enroll>("POST", "/auth/mfa/enroll")); } catch (e) { setError(errText(e)); } };
  const confirm = async (e: FormEvent) => {
    e.preventDefault(); setError("");
    try { await api("POST", "/auth/mfa/confirm", { code }); onDone(); } catch (err) { setError(errText(err)); }
  };
  return (
    <div className="card">
      <h1>Set up two-step verification</h1>
      <p className="muted">Your role requires an authenticator app. Scan the code, then enter the 6-digit number it shows.</p>
      {error && <Notice kind="error">{error}</Notice>}
      {!enroll ? <button className="primary" onClick={() => void start()}>Create my authenticator code</button> : (
        <form onSubmit={confirm}>
          <div className="qr" aria-label="QR code for your authenticator app" dangerouslySetInnerHTML={{ __html: enroll.qr_svg }} />
          <p className="small">Cannot scan? Enter this key manually:</p>
          <p className="mono keybox">{enroll.secret}</p>
          <Field label="Authenticator code"><input inputMode="numeric" pattern="\d{6}" maxLength={6} required autoFocus value={code} onChange={(e) => setCode(e.target.value)} /></Field>
          <button className="primary">Turn on verification</button>
        </form>
      )}
    </div>
  );
}

export default function Setup() {
  const { me, refresh, signOut } = useAuth();
  return (
    <div className="center">
      <div className="stack">
        {me?.restriction === "password_change" ? <ChangePassword onDone={() => void refresh()} /> : <EnrollMfa onDone={() => void refresh()} />}
        <button className="link" onClick={() => void signOut()}>Sign out</button>
      </div>
    </div>
  );
}
