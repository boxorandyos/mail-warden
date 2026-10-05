import { Navigate, Outlet, Route, Routes, useLocation } from "react-router-dom";
import { Shell } from "./components/Shell";
import { accessToken } from "./lib/api";
import { useAuth } from "./lib/auth";
import { AccountPage, ClusterPage, ConfigurationPage, EventsPage, IdentityPage, MaintenancePage, PlatformPage, PolicyCopiesPage, PolicyPage, UsersPage } from "./pages/AdminPages";
import { AuditExportPage, BackupsPage, FleetAlertsPage, HardeningPage, JobsPage, PlatformMetricsPage, PlatformSnapshotsPage, RunbooksPage, ServiceAccountsPage } from "./pages/FleetPages";
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
        <Route path="/policy-copies" element={<PolicyCopiesPage />} />
        <Route path="/identity" element={<IdentityPage />} />
        <Route path="/events" element={<EventsPage />} />
        <Route path="/alerts" element={<FleetAlertsPage />} />
        <Route path="/metrics" element={<PlatformMetricsPage />} />
        <Route path="/configuration" element={<ConfigurationPage />} />
        <Route path="/users" element={<UsersPage />} />
        <Route path="/nodes" element={<ClusterPage />} />
        <Route path="/cluster" element={<Navigate to="/nodes" replace />} />
        <Route path="/maintenance" element={<MaintenancePage />} />
        <Route path="/snapshots" element={<PlatformSnapshotsPage />} />
        <Route path="/backups" element={<BackupsPage />} />
        <Route path="/jobs" element={<JobsPage />} />
        <Route path="/runbooks" element={<RunbooksPage />} />
        <Route path="/hardening" element={<HardeningPage />} />
        <Route path="/audit" element={<AuditExportPage />} />
        <Route path="/service-accounts" element={<ServiceAccountsPage />} />
        <Route path="/platform" element={<PlatformPage />} />
        <Route path="/account" element={<AccountPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
