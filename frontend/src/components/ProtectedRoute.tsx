import { useEffect, type ReactNode } from "react";
import { Box, CircularProgress, Paper, Typography } from "@mui/material";
import { Navigate, Outlet } from "react-router-dom";
import { useAuthStore } from "../store/auth";
import { ChangePasswordGate } from "./ChangePasswordGate";

interface ProtectedRouteProps {
  // Optional permission key required to view the route. Super Admins and the
  // Admin.All wildcard always pass (see useAuthStore.has).
  permission?: string;
  children?: ReactNode;
}

// Route guard. Restores the session on first mount, redirects unauthenticated
// users to /login, and renders a 403 panel when a required permission is absent.
export function ProtectedRoute({ permission, children }: ProtectedRouteProps) {
  const user = useAuthStore((s) => s.user);
  const loaded = useAuthStore((s) => s.loaded);
  const restore = useAuthStore((s) => s.restore);
  const has = useAuthStore((s) => s.has);

  useEffect(() => {
    if (!loaded) void restore();
  }, [loaded, restore]);

  if (!loaded) {
    return (
      <Box
        sx={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <CircularProgress />
      </Box>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  // The backend blocks all non-auth endpoints for an account flagged to change
  // its password; show the change screen in place of any protected route.
  if (user.mustChangePassword) {
    return <ChangePasswordGate />;
  }

  if (permission && !has(permission)) {
    return (
      <Box sx={{ p: 3 }}>
        <Paper variant="outlined" sx={{ p: 4 }}>
          <Typography variant="h5" gutterBottom>
            403 — Forbidden
          </Typography>
          <Typography color="text.secondary">
            You do not have permission to view this page.
          </Typography>
        </Paper>
      </Box>
    );
  }

  return <>{children ?? <Outlet />}</>;
}
