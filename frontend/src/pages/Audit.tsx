import { useState } from "react";
import { api, fmt, type AuditEvent } from "../api";
import { useAuth } from "../auth";
import { Notice, Page, errText, useLoad } from "../ui";

type Verify = { valid: boolean; checked: number; first_bad_seq: number | null; reason: string | null; head_seq?: number; head_hash?: string };

export default function Audit() {
  const { can } = useAuth();
  const [outcome, setOutcome] = useState(""); const [action, setAction] = useState("");
  const { data, error, reload } = useLoad(
    () => api<AuditEvent[]>("GET", `/audit?${new URLSearchParams({ limit: "100", ...(outcome && { outcome }), ...(action && { action }) })}`), [outcome, action]);
  const [result, setResult] = useState<Verify | null>(null); const [vErr, setVErr] = useState(""); const [busy, setBusy] = useState(false);

  const verify = async () => {
    setBusy(true); setVErr("");
    try { setResult(await api<Verify>("GET", "/audit/verify")); await reload(); } catch (e) { setVErr(errText(e)); } finally { setBusy(false); }
  };

  return (
    <Page title="Audit and integrity" actions={can("audit:verify") && <button className="primary" disabled={busy} onClick={() => void verify()}>{busy ? "Checking" : "Verify audit chain"}</button>}>
      {vErr && <Notice kind="error">{vErr}</Notice>}
      {result && (result.valid
        ? <Notice kind="ok">Checked {result.checked} events. Every hash matches and no events are missing. This proves the log has not been edited inside this database. Independent anchoring arrives in Milestone 3.</Notice>
        : <Notice kind="error">The chain is broken at event {result.first_bad_seq}: {result.reason}. Treat the audit store as compromised and investigate.</Notice>)}
      <div className="toolbar">
        <select aria-label="Outcome" value={outcome} onChange={(e) => setOutcome(e.target.value)}>
          <option value="">All outcomes</option><option value="success">Success</option><option value="failure">Failure</option><option value="denied">Denied</option>
        </select>
        <input type="search" placeholder="Action, for example auth. or asset." aria-label="Filter by action prefix" value={action} onChange={(e) => setAction(e.target.value)} />
      </div>
      {error && <Notice kind="error">{error}</Notice>}
      <section className="panel flush">
        <table>
          <thead><tr><th>#</th><th>Time</th><th>Who</th><th>Action</th><th>Outcome</th><th>Details</th></tr></thead>
          <tbody>
            {data?.map((e) => (
              <tr key={e.seq}>
                <td className="mono muted">{e.seq}</td>
                <td className="muted nowrap">{fmt(e.ts)}</td>
                <td>{e.actor_label ?? "system"}<div className="muted small mono">{e.ip}</div></td>
                <td className="mono">{e.action}</td>
                <td><span className={`tag out-${e.outcome}`}>{e.outcome}</span></td>
                <td className="small muted">{Object.entries(e.details).map(([k, v]) => `${k}: ${String(v)}`).join(", ")}</td>
              </tr>
            ))}
            {data?.length === 0 && <tr><td colSpan={6} className="empty">No events match these filters.</td></tr>}
          </tbody>
        </table>
      </section>
    </Page>
  );
}
