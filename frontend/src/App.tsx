import { Box, CircularProgress, CssBaseline, ThemeProvider } from "@mui/material";
import { Route, Routes, Navigate } from "react-router-dom";
import { lazy, Suspense, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { getDRMode } from "./api/dr";
import { buildTheme } from "./theme";
import { useUIStore } from "./store/ui";
import { AppLayout } from "./components/AppLayout";
import { ProtectedRoute } from "./components/ProtectedRoute";
// Eager: the first-paint pages (login/bootstrap) and the post-login landing.
import { DashboardPage } from "./pages/DashboardPage";
import { LoginPage } from "./pages/LoginPage";
import { BootstrapPage } from "./pages/BootstrapPage";

// Lazy: every other page is its own chunk, so heavy deps (xterm, CodeMirror,
// the data grid, the scan-report viewer) load only when their page is opened.
const named = <T,>(p: Promise<T>, key: keyof T) => p.then((m) => ({ default: m[key] as React.ComponentType }));
const HostsPage = lazy(() => named(import("./pages/HostsPage"), "HostsPage"));
const UsersPage = lazy(() => named(import("./pages/UsersPage"), "UsersPage"));
const TenantsPage = lazy(() => named(import("./pages/TenantsPage"), "TenantsPage"));
const RolesPage = lazy(() => named(import("./pages/RolesPage"), "RolesPage"));
const GroupsPage = lazy(() => named(import("./pages/GroupsPage"), "GroupsPage"));
const SettingsPage = lazy(() => named(import("./pages/SettingsPage"), "SettingsPage"));
const AuditPage = lazy(() => named(import("./pages/AuditPage"), "AuditPage"));
const ApprovalsPage = lazy(() => named(import("./pages/ApprovalsPage"), "ApprovalsPage"));
const SessionsPage = lazy(() => named(import("./pages/SessionsPage"), "SessionsPage"));
const TerminalPage = lazy(() => named(import("./pages/TerminalPage"), "TerminalPage"));
const RdpPage = lazy(() => named(import("./pages/RdpPage"), "RdpPage"));
const TerminalsPage = lazy(() => named(import("./pages/TerminalsPage"), "TerminalsPage"));
const FilesPage = lazy(() => named(import("./pages/FilesPage"), "FilesPage"));
const SecurityPage = lazy(() => named(import("./pages/SecurityPage"), "SecurityPage"));
const JobsPage = lazy(() => named(import("./pages/JobsPage"), "JobsPage"));
const EnrollmentPage = lazy(() => named(import("./pages/EnrollmentPage"), "EnrollmentPage"));
const CertificatesPage = lazy(() => named(import("./pages/CertificatesPage"), "CertificatesPage"));
const AssistantPage = lazy(() => named(import("./pages/AssistantPage"), "AssistantPage"));
const ServiceAccountsPage = lazy(() => named(import("./pages/ServiceAccountsPage"), "ServiceAccountsPage"));
const ReportsPage = lazy(() => named(import("./pages/ReportsPage"), "ReportsPage"));
const WatchSessionPage = lazy(() => named(import("./pages/WatchSessionPage"), "WatchSessionPage"));
const VulnerabilitiesPage = lazy(() => named(import("./pages/VulnerabilitiesPage"), "VulnerabilitiesPage"));
const HelpPage = lazy(() => named(import("./pages/HelpPage"), "HelpPage"));
const AccessReviewsPage = lazy(() => named(import("./pages/AccessReviewsPage"), "AccessReviewsPage"));
const AutomationPage = lazy(() => named(import("./pages/AutomationPage"), "AutomationPage"));
const SchedulesPage = lazy(() => named(import("./pages/SchedulesPage"), "SchedulesPage"));
const HealthPage = lazy(() => named(import("./pages/HealthPage"), "HealthPage"));
const VaultPage = lazy(() => named(import("./pages/VaultPage"), "VaultPage"));
const DatabasesPage = lazy(() => named(import("./pages/DatabasesPage"), "DatabasesPage"));
const LifecyclePage = lazy(() => named(import("./pages/LifecyclePage"), "LifecyclePage"));
const CommandPolicyPage = lazy(() => named(import("./pages/CommandPolicyPage"), "CommandPolicyPage"));
const AccessPolicyPage = lazy(() => named(import("./pages/AccessPolicyPage"), "AccessPolicyPage"));
const KubernetesPage = lazy(() => named(import("./pages/KubernetesPage"), "KubernetesPage"));
const BehaviorPage = lazy(() => named(import("./pages/BehaviorPage"), "BehaviorPage"));
const SitesPage = lazy(() => named(import("./pages/SitesPage"), "SitesPage"));
const DisasterRecoveryPage = lazy(() => named(import("./pages/DisasterRecoveryPage"), "DisasterRecoveryPage"));

function PageFallback() {
  return (
    <Box sx={{ display: "flex", justifyContent: "center", alignItems: "center", height: "60vh" }}>
      <CircularProgress />
    </Box>
  );
}

const StandbyConsole = lazy(() => named(import("./pages/StandbyConsole"), "StandbyConsole"));

// Root component. Public routes (login, bootstrap) sit outside the guarded
// AppLayout; every other route requires authentication and, where relevant, a
// specific backend permission. Backend remains the sole authorization authority.
export function App() {
  const mode = useUIStore((s) => s.mode);
  const theme = useMemo(() => buildTheme(mode), [mode]);

  // Detect a read-only DR standby BEFORE any normal flow: the replica database
  // can't service login/session writes, so the entire app is replaced by the
  // break-glass standby console. /dr/mode is unauthenticated and works on a replica.
  const { data: drMode, isLoading: drLoading } = useQuery({
    queryKey: ["dr-mode"], queryFn: getDRMode, retry: false, staleTime: 30_000,
  });

  if (drLoading) {
    return (
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <PageFallback />
      </ThemeProvider>
    );
  }
  if (drMode?.standby) {
    return (
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Suspense fallback={<PageFallback />}>
          <StandbyConsole />
        </Suspense>
      </ThemeProvider>
    );
  }

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Suspense fallback={<PageFallback />}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/bootstrap" element={<BootstrapPage />} />

          {/* Standalone tabs — each opened in its own browser tab. */}
          <Route
            path="/terminals/:hostId"
            element={<ProtectedRoute permission="Host.Connect"><TerminalPage /></ProtectedRoute>}
          />
          {/* Federated terminal: a host on a remote site, proxied through the hub. */}
          <Route
            path="/sites/:siteId/terminals/:hostId"
            element={<ProtectedRoute permission="Host.Connect"><TerminalPage /></ProtectedRoute>}
          />
          <Route
            path="/desktop/:hostId"
            element={<ProtectedRoute permission="Host.Connect"><RdpPage /></ProtectedRoute>}
          />
          <Route
            path="/files/:hostId"
            element={<ProtectedRoute permission="File.Transfer"><FilesPage /></ProtectedRoute>}
          />
          {/* Federated file browser: a host on a remote site, proxied through the hub. */}
          <Route
            path="/sites/:siteId/files/:hostId"
            element={<ProtectedRoute permission="File.Transfer"><FilesPage /></ProtectedRoute>}
          />
          <Route
            path="/sessions/:id/watch"
            element={<ProtectedRoute permission="Session.Watch"><WatchSessionPage /></ProtectedRoute>}
          />

          <Route element={<ProtectedRoute />}>
            <Route element={<AppLayout />}>
              <Route index element={<DashboardPage />} />
              <Route path="ask" element={<ProtectedRoute permission="Assistant.Use"><AssistantPage /></ProtectedRoute>} />
              <Route path="terminals" element={<ProtectedRoute permission="Host.Connect"><TerminalsPage /></ProtectedRoute>} />
              <Route path="hosts" element={<ProtectedRoute permission="Host.View"><HostsPage /></ProtectedRoute>} />
              <Route path="tenants" element={<TenantsPage />} />
              <Route path="sessions" element={<ProtectedRoute permission="Session.Replay"><SessionsPage /></ProtectedRoute>} />
              <Route path="automation" element={<ProtectedRoute permission="Playbook.Edit"><AutomationPage /></ProtectedRoute>} />
              <Route path="playbooks" element={<Navigate to="/automation" replace />} />
              <Route path="schedules" element={<ProtectedRoute permission="Schedule.Manage"><SchedulesPage /></ProtectedRoute>} />
              <Route path="approvals" element={<ApprovalsPage />} />
              <Route path="audit" element={<ProtectedRoute permission="Audit.View"><AuditPage /></ProtectedRoute>} />
              <Route path="reports" element={<ProtectedRoute permission="Audit.View"><ReportsPage /></ProtectedRoute>} />
              <Route path="behavior" element={<ProtectedRoute permission="Audit.View"><BehaviorPage /></ProtectedRoute>} />
              <Route path="access-reviews" element={<ProtectedRoute permission="AccessReview.Manage"><AccessReviewsPage /></ProtectedRoute>} />
              <Route path="users" element={<ProtectedRoute permission="User.Edit"><UsersPage /></ProtectedRoute>} />
              <Route path="roles" element={<ProtectedRoute permission="Role.Edit"><RolesPage /></ProtectedRoute>} />
              <Route path="groups" element={<ProtectedRoute permission="Group.Edit"><GroupsPage /></ProtectedRoute>} />
              <Route path="sites" element={<ProtectedRoute permission="Federation.Manage"><SitesPage /></ProtectedRoute>} />
              <Route path="service-accounts" element={<ProtectedRoute permission="ServiceAccount.Manage"><ServiceAccountsPage /></ProtectedRoute>} />
              <Route path="vault" element={<ProtectedRoute permission="Credential.View"><VaultPage /></ProtectedRoute>} />
              <Route path="databases" element={<ProtectedRoute permission="Database.Connect"><DatabasesPage /></ProtectedRoute>} />
              <Route path="kubernetes" element={<ProtectedRoute permission="Kubernetes.Access"><KubernetesPage /></ProtectedRoute>} />
              <Route path="enrollment" element={<ProtectedRoute permission="Host.Enroll"><EnrollmentPage /></ProtectedRoute>} />
              <Route path="certificates" element={<ProtectedRoute permission="Certificate.Manage"><CertificatesPage /></ProtectedRoute>} />
              <Route path="lifecycle" element={<ProtectedRoute permission="System.Configure"><LifecyclePage /></ProtectedRoute>} />
              <Route path="command-policy" element={<ProtectedRoute permission="CommandPolicy.Manage"><CommandPolicyPage /></ProtectedRoute>} />
              <Route path="access-policies" element={<ProtectedRoute permission="AccessPolicy.Manage"><AccessPolicyPage /></ProtectedRoute>} />
              <Route path="disaster-recovery" element={<ProtectedRoute permission="DR.Manage"><DisasterRecoveryPage /></ProtectedRoute>} />
              <Route path="security" element={<SecurityPage />} />
              <Route path="vulnerabilities" element={<ProtectedRoute permission="Host.Scan"><VulnerabilitiesPage /></ProtectedRoute>} />
              <Route path="jobs" element={<ProtectedRoute permission="System.Configure"><JobsPage /></ProtectedRoute>} />
              {/* The System Health UI lives at /system-health, not /health: nginx proxies
                  the exact path /health to the backend liveness endpoint (for infra probes),
                  which would otherwise shadow this page on a hard load/refresh. */}
              <Route path="system-health" element={<ProtectedRoute permission="System.Configure"><HealthPage /></ProtectedRoute>} />
              <Route path="settings" element={<ProtectedRoute permission="System.Configure"><SettingsPage /></ProtectedRoute>} />
              <Route path="help" element={<HelpPage />} />
              <Route path="help/:slug" element={<HelpPage />} />
            </Route>
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </ThemeProvider>
  );
}
