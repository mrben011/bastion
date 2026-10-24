import { api } from "../api";
import { Notice, Page, useLoad } from "../ui";

type Overview = {
  organization: { name: string };
  assets: { total: number; by_environment: Record<string, number>; monitored: number };
  users: { active: number }; sessions: { active: number };
  activity_24h: { audit_events: number; failed_logins: number; denied_actions: number };
  audit_chain_head: { seq: number; hash: string } | null;
  modules: { name: string; status: string; milestone: number }[];
  data_notice: string;
};

const Stat = ({ label, value, tone }: { label: string; value: number | string; tone?: "warn" }) => (
  <div className="stat"><span className={`num ${tone ?? ""}`}>{value}</span><span className="muted">{label}</span></div>
);

export default function Overview() {
  const { data, error, loading } = useLoad(() => api<Overview>("GET", "/overview"));
  return (
    <Page title={data ? `${data.organization.name}` : "Overview"}>
      {error && <Notice kind="error">{error}</Notice>}
      {loading && !data && <p className="muted">Loading</p>}
      {data && (
        <>
          <Notice>{data.data_notice}</Notice>
          <section className="stats" aria-label="Current counts">
            <Stat label="Registered assets" value={data.assets.total} />
            <Stat label="Assets with monitoring" value={data.assets.monitored} />
            <Stat label="Active people" value={data.users.active} />
            <Stat label="Signed-in sessions" value={data.sessions.active} />
            <Stat label="Failed sign-ins, 24 hours" value={data.activity_24h.failed_logins} tone={data.activity_24h.failed_logins ? "warn" : undefined} />
            <Stat label="Denied actions, 24 hours" value={data.activity_24h.denied_actions} tone={data.activity_24h.denied_actions ? "warn" : undefined} />
          </section>
          <div className="two">
            <section className="panel">
              <h2>Audit log head</h2>
              {data.audit_chain_head ? (
                <>
                  <p>Event {data.audit_chain_head.seq} is the latest link in the hash chain.</p>
                  <p className="mono hash">{data.audit_chain_head.hash}</p>
                  <p className="muted small">Run a full check from Audit and integrity.</p>
                </>
              ) : <p className="muted">No events recorded yet.</p>}
            </section>
            <section className="panel">
              <h2>Build status</h2>
              <ul className="ledger">
                {data.modules.map((m) => (
                  <li key={m.name}>
                    <span className={`dot ${m.status}`} aria-hidden />
                    <span>{m.name}</span>
                    <span className="muted small">{m.status === "implemented" ? "Built" : `Milestone ${m.milestone}`}</span>
                  </li>
                ))}
              </ul>
            </section>
          </div>
        </>
      )}
    </Page>
  );
}
