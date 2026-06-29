import { CssBaseline, ThemeProvider } from "@mui/material";
import { Route, Routes, Navigate } from "react-router-dom";
import { useMemo } from "react";
import { buildTheme } from "./theme";
import { useUIStore } from "./store/ui";
import { AppLayout } from "./components/AppLayout";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { DashboardPage } from "./pages/DashboardPage";
import { HostsPage } from "./pages/HostsPage";
import { LoginPage } from "./pages/LoginPage";
import { BootstrapPage } from "./pages/BootstrapPage";
import { UsersPage } from "./pages/UsersPage";
import { RolesPage } from "./pages/RolesPage";
import { GroupsPage } from "./pages/GroupsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { AuditPage } from "./pages/AuditPage";
import { ApprovalsPage } from "./pages/ApprovalsPage";
import { SessionsPage } from "./pages/SessionsPage";
import { TerminalPage } from "./pages/TerminalPage";
import { TerminalsPage } from "./pages/TerminalsPage";
import { FilesPage } from "./pages/FilesPage";
import { SecurityPage } from "./pages/SecurityPage";
import { JobsPage } from "./pages/JobsPage";
import { EnrollmentPage } from "./pages/EnrollmentPage";
import { CertificatesPage } from "./pages/CertificatesPage";
import { AssistantPage } from "./pages/AssistantPage";
import { PlaybooksPage } from "./pages/PlaybooksPage";

// Root component. Public routes (login, bootstrap) sit outside the guarded
// AppLayout; every other route requires authentication and, where relevant, a
// specific backend permission. Backend remains the sole authorization authority.
export function App() {
  const mode = useUIStore((s) => s.mode);
  const theme = useMemo(() => buildTheme(mode), [mode]);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
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
    </ThemeProvider>
  );
}
