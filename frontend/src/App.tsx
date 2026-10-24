import { useEffect, useState } from "react";
import { ROLE_LABEL } from "./api";
import { useAuth } from "./auth";
import Account from "./pages/Account";
import Assets from "./pages/Assets";
import Audit from "./pages/Audit";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import Setup from "./pages/Setup";
import Users from "./pages/Users";

const NAV = [
  { id: "overview", label: "Overview", perm: "overview:read" },
  { id: "assets", label: "Protected assets", perm: "assets:read" },
  { id: "users", label: "People and access", perm: "users:read" },
  { id: "audit", label: "Audit and integrity", perm: "audit:read" },
  { id: "account", label: "My account", perm: "overview:read" },
];
const PLANNED = ["Incidents", "Response", "AI analyst"];

function useRoute() {
  const read = () => window.location.hash.replace("#/", "") || "overview";
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const h = () => setRoute(read());
    window.addEventListener("hashchange", h);
    return () => window.removeEventListener("hashchange", h);
  }, []);
  return route;
}

export default function App() {
  const { me, loading, can, signOut } = useAuth();
  const route = useRoute();
  if (loading) return <div className="center muted">Loading</div>;
  if (!me) return <Login />;
  if (me.restriction) return <Setup />;

  const allowed = NAV.filter((n) => can(n.perm));
  const current = allowed.find((n) => n.id === route) ?? allowed[0];

  return (
    <div className="shell">
      <nav className="rail" aria-label="Main">
        <div className="brand">Bastion</div>
        <ul>
          {allowed.map((n) => (
            <li key={n.id}>
              <a href={`#/${n.id}`} aria-current={current?.id === n.id ? "page" : undefined}>{n.label}</a>
            </li>
          ))}
        </ul>
        <div className="planned">
          <p className="muted small">Planned</p>
          <ul>{PLANNED.map((p) => <li key={p} className="disabled" title="Not built yet">{p}</li>)}</ul>
        </div>
        <div className="who">
          <strong>{me.user.display_name}</strong>
          <span className="muted small">{ROLE_LABEL[me.user.role] ?? me.user.role}</span>
          <button className="link" onClick={() => void signOut()}>Sign out</button>
        </div>
      </nav>
      <main id="main">
        {current?.id === "overview" && <Overview />}
        {current?.id === "assets" && <Assets />}
        {current?.id === "users" && <Users />}
        {current?.id === "audit" && <Audit />}
        {current?.id === "account" && <Account />}
      </main>
    </div>
  );
}
