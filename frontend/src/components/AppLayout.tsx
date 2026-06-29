import {
  AppBar, Box, CssBaseline, Drawer, IconButton, List, ListItemButton,
  ListItemIcon, ListItemText, Toolbar, Typography, Tooltip,
} from "@mui/material";
import DnsIcon from "@mui/icons-material/Dns";
import TerminalIcon from "@mui/icons-material/Terminal";
import DashboardIcon from "@mui/icons-material/Dashboard";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import HistoryIcon from "@mui/icons-material/History";
import ApprovalIcon from "@mui/icons-material/HowToReg";
import GavelIcon from "@mui/icons-material/Gavel";
import PeopleIcon from "@mui/icons-material/People";
import SecurityIcon from "@mui/icons-material/Security";
import GroupWorkIcon from "@mui/icons-material/GroupWork";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import SettingsIcon from "@mui/icons-material/Settings";
import ShieldIcon from "@mui/icons-material/Shield";
import PlaylistPlayIcon from "@mui/icons-material/PlaylistPlay";
import WorkHistoryIcon from "@mui/icons-material/WorkHistory";
import DarkModeIcon from "@mui/icons-material/DarkMode";
import LightModeIcon from "@mui/icons-material/LightMode";
import MenuIcon from "@mui/icons-material/Menu";
import LogoutIcon from "@mui/icons-material/Logout";
import { Link as RouterLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useUIStore } from "../store/ui";
import { useAuthStore } from "../store/auth";
import { useAppName, useDocumentTitle } from "../api/branding";

const DRAWER_WIDTH = 232;

const NAV = [
  { to: "/", label: "Dashboard", icon: <DashboardIcon /> },
  { to: "/ask", label: "Ask", icon: <SmartToyIcon />, perm: "Assistant.Use" },
  { to: "/hosts", label: "Hosts", icon: <DnsIcon /> },
  { to: "/terminals", label: "Terminals", icon: <TerminalIcon /> },
  { to: "/sessions", label: "Session Replay", icon: <HistoryIcon /> },
  { to: "/playbooks", label: "Playbooks", icon: <PlaylistPlayIcon />, perm: "Playbook.Edit" },
  { to: "/approvals", label: "Approvals", icon: <ApprovalIcon /> },
  { to: "/audit", label: "Audit", icon: <GavelIcon /> },
  { to: "/users", label: "Users", icon: <PeopleIcon /> },
  { to: "/roles", label: "Roles", icon: <SecurityIcon /> },
  { to: "/groups", label: "Groups", icon: <GroupWorkIcon /> },
  { to: "/enrollment", label: "Enrollment", icon: <CloudUploadIcon /> },
  { to: "/certificates", label: "Certificates", icon: <VpnKeyIcon /> },
  { to: "/security", label: "Security", icon: <ShieldIcon /> },
  { to: "/jobs", label: "Jobs", icon: <WorkHistoryIcon /> },
  { to: "/settings", label: "Settings", icon: <SettingsIcon /> },
];

// Application chrome: top bar + persistent navigation drawer. The routed page
// renders into <Outlet/>.
export function AppLayout() {
  const { pathname } = useLocation();
  const mode = useUIStore((s) => s.mode);
  const toggleMode = useUIStore((s) => s.toggleMode);
  const sidebarOpen = useUIStore((s) => s.sidebarOpen);
  const toggleSidebar = useUIStore((s) => s.toggleSidebar);
  const logout = useAuthStore((s) => s.logout);
  const username = useAuthStore((s) => s.user?.username);
  const has = useAuthStore((s) => s.has);
  const navigate = useNavigate();
  const appName = useAppName();
  useDocumentTitle();

  const handleLogout = async () => {
    await logout();
    navigate("/login", { replace: true });
  };

  return (
    <Box sx={{ display: "flex" }}>
      <CssBaseline />
      <AppBar position="fixed" sx={{ zIndex: (t) => t.zIndex.drawer + 1 }}>
        <Toolbar variant="dense">
          <Tooltip title={sidebarOpen ? "Hide sidebar" : "Show sidebar"}>
            <IconButton color="inherit" edge="start" onClick={toggleSidebar} sx={{ mr: 1 }}>
              <MenuIcon />
            </IconButton>
          </Tooltip>
          <TerminalIcon sx={{ mr: 1 }} />
          <Typography variant="h6" sx={{ flexGrow: 1, fontWeight: 600 }}>
            {appName}
          </Typography>
          <Tooltip title="Toggle theme">
            <IconButton color="inherit" onClick={toggleMode}>
              {mode === "dark" ? <LightModeIcon /> : <DarkModeIcon />}
            </IconButton>
          </Tooltip>
          {username && (
            <Typography variant="body2" sx={{ ml: 1, mr: 0.5, opacity: 0.85 }}>
              {username}
            </Typography>
          )}
          <Tooltip title="Sign out">
            <IconButton color="inherit" onClick={handleLogout}>
              <LogoutIcon />
            </IconButton>
          </Tooltip>
        </Toolbar>
      </AppBar>
      <Drawer
        variant="permanent"
        open={sidebarOpen}
        sx={{
          width: sidebarOpen ? DRAWER_WIDTH : 0,
          flexShrink: 0,
          whiteSpace: "nowrap",
          "& .MuiDrawer-paper": {
            width: sidebarOpen ? DRAWER_WIDTH : 0,
            boxSizing: "border-box",
            overflowX: "hidden",
            transition: (t) =>
              t.transitions.create("width", {
                easing: t.transitions.easing.sharp,
                duration: t.transitions.duration.enteringScreen,
              }),
          },
        }}
      >
        <Toolbar variant="dense" />
        <Box sx={{ overflow: "auto" }}>
          <List dense>
            {NAV.filter((item) => !item.perm || has(item.perm)).map((item) => {
              const selected =
                item.to === "/" ? pathname === "/" : pathname.startsWith(item.to);
              return (
                <ListItemButton
                  key={item.to}
                  component={RouterLink}
                  to={item.to}
                  selected={selected}
                >
                  <ListItemIcon sx={{ minWidth: 36 }}>{item.icon}</ListItemIcon>
                  <ListItemText primary={item.label} />
                </ListItemButton>
              );
            })}
          </List>
        </Box>
      </Drawer>
      <Box component="main" sx={{ flexGrow: 1, minWidth: 0, p: 3, mt: 6 }}>
        <Outlet />
      </Box>
    </Box>
  );
}
