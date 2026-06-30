import { Box, CircularProgress, CssBaseline, ThemeProvider } from "@mui/material";
import { Route, Routes, Navigate } from "react-router-dom";
import { lazy, Suspense, useMemo } from "react";
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
const RolesPage = lazy(() => named(import("./pages/RolesPage"), "RolesPage"));
const GroupsPage = lazy(() => named(import("./pages/GroupsPage"), "GroupsPage"));
const SettingsPage = lazy(() => named(import("./pages/SettingsPage"), "SettingsPage"));
const AuditPage = lazy(() => named(import("./pages/AuditPage"), "AuditPage"));
const ApprovalsPage = lazy(() => named(import("./pages/ApprovalsPage"), "ApprovalsPage"));
const SessionsPage = lazy(() => named(import("./pages/SessionsPage"), "SessionsPage"));
const TerminalPage = lazy(() => named(import("./pages/TerminalPage"), "TerminalPage"));
const TerminalsPage = lazy(() => named(import("./pages/TerminalsPage"), "TerminalsPage"));
const FilesPage = lazy(() => named(import("./pages/FilesPage"), "FilesPage"));
const SecurityPage = lazy(() => named(import("./pages/SecurityPage"), "SecurityPage"));
const JobsPage = lazy(() => named(import("./pages/JobsPage"), "JobsPage"));
const EnrollmentPage = lazy(() => named(import("./pages/EnrollmentPage"), "EnrollmentPage"));
const CertificatesPage = lazy(() => named(import("./pages/CertificatesPage"), "CertificatesPage"));
const AssistantPage = lazy(() => named(import("./pages/AssistantPage"), "AssistantPage"));
const PlaybooksPage = lazy(() => named(import("./pages/PlaybooksPage"), "PlaybooksPage"));
const SchedulesPage = lazy(() => named(import("./pages/SchedulesPage"), "SchedulesPage"));

function PageFallback() {
  return (
    <Box sx={{ display: "flex", justifyContent: "center", alignItems: "center", height: "60vh" }}>
      <CircularProgress />
    </Box>
  );
}

// Root component. Public routes (login, bootstrap) sit outside the guarded
// AppLayout; every other route requires authentication and, where relevant, a
// specific backend permission. Backend remains the sole authorization authority.
export function App() {
  const mode = useUIStore((s) => s.mode);
  const theme = useMemo(() => buildTheme(mode), [mode]);

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
          <Route
            path="/files/:hostId"
            element={<ProtectedRoute permission="File.Transfer"><FilesPage /></ProtectedRoute>}
          />

          <Route element={<ProtectedRoute />}>
            <Route element={<AppLayout />}>
              <Route index element={<DashboardPage />} />
              <Route path="ask" element={<ProtectedRoute permission="Assistant.Use"><AssistantPage /></ProtectedRoute>} />
              <Route path="terminals" element={<ProtectedRoute permission="Host.Connect"><TerminalsPage /></ProtectedRoute>} />
              <Route path="hosts" element={<ProtectedRoute permission="Host.View"><HostsPage /></ProtectedRoute>} />
              <Route path="sessions" element={<ProtectedRoute permission="Session.Replay"><SessionsPage /></ProtectedRoute>} />
              <Route path="playbooks" element={<ProtectedRoute permission="Playbook.Edit"><PlaybooksPage /></ProtectedRoute>} />
              <Route path="schedules" element={<ProtectedRoute permission="Schedule.Manage"><SchedulesPage /></ProtectedRoute>} />
              <Route path="approvals" element={<ApprovalsPage />} />
              <Route path="audit" element={<ProtectedRoute permission="Audit.View"><AuditPage /></ProtectedRoute>} />
              <Route path="users" element={<ProtectedRoute permission="User.Edit"><UsersPage /></ProtectedRoute>} />
              <Route path="roles" element={<ProtectedRoute permission="Role.Edit"><RolesPage /></ProtectedRoute>} />
              <Route path="groups" element={<ProtectedRoute permission="Group.Edit"><GroupsPage /></ProtectedRoute>} />
              <Route path="enrollment" element={<ProtectedRoute permission="Host.Enroll"><EnrollmentPage /></ProtectedRoute>} />
              <Route path="certificates" element={<ProtectedRoute permission="Certificate.Manage"><CertificatesPage /></ProtectedRoute>} />
              <Route path="security" element={<SecurityPage />} />
              <Route path="jobs" element={<ProtectedRoute permission="System.Configure"><JobsPage /></ProtectedRoute>} />
              <Route path="settings" element={<ProtectedRoute permission="System.Configure"><SettingsPage /></ProtectedRoute>} />
            </Route>
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </ThemeProvider>
  );
}
