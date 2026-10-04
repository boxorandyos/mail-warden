import { Navigate, Outlet, Route, Routes, useLocation } from "react-router-dom";
import { Shell } from "./components/Shell";
import { accessToken } from "./lib/api";
import { useAuth } from "./lib/auth";
import { AccountPage, ClusterPage, ConfigurationPage, EventsPage, IdentityPage, MetricsPage, PolicyPage, SnapshotsPage, UsersPage } from "./pages/AdminPages";
import { LoginPage } from "./pages/Login";
import { DashboardPage, MessagesPage, QuarantinePage } from "./pages/MailPages";

function Guard() {
  const { user } = useAuth();
  const location = useLocation();
  if (!user || !accessToken()) {
    const redirect = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/login?redirect=${redirect}`} replace />;
  }
  return (
    <Shell>
      <Outlet />
    </Shell>
  );
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<Guard />}>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/messages" element={<MessagesPage />} />
        <Route path="/quarantine" element={<QuarantinePage />} />
        <Route path="/policy" element={<PolicyPage />} />
        <Route path="/identity" element={<IdentityPage />} />
        <Route path="/events" element={<EventsPage />} />
        <Route path="/metrics" element={<MetricsPage />} />
        <Route path="/configuration" element={<ConfigurationPage />} />
        <Route path="/users" element={<UsersPage />} />
        <Route path="/cluster" element={<ClusterPage />} />
        <Route path="/snapshots" element={<SnapshotsPage />} />
        <Route path="/account" element={<AccountPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
