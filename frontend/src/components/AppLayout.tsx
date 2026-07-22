import {
  AppBar, Badge, Box, Button, Chip, CssBaseline, Drawer, IconButton, List, ListItemButton,
  ListItemIcon, ListItemText, MenuItem, Select, Toolbar, Typography, Tooltip,
} from "@mui/material";
import DnsIcon from "@mui/icons-material/Dns";
import TerminalIcon from "@mui/icons-material/Terminal";
import DashboardIcon from "@mui/icons-material/Dashboard";
import ApartmentIcon from "@mui/icons-material/Apartment";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import HistoryIcon from "@mui/icons-material/History";
import ApprovalIcon from "@mui/icons-material/HowToReg";
import GavelIcon from "@mui/icons-material/Gavel";
import PeopleIcon from "@mui/icons-material/People";
import SecurityIcon from "@mui/icons-material/Security";
import GroupWorkIcon from "@mui/icons-material/GroupWork";
import ApiIcon from "@mui/icons-material/Api";
import AssessmentIcon from "@mui/icons-material/Assessment";
import BugReportIcon from "@mui/icons-material/BugReport";
import HelpOutlineIcon from "@mui/icons-material/HelpOutline";
import FactCheckIcon from "@mui/icons-material/FactCheck";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import KeyIcon from "@mui/icons-material/Key";
import StorageIcon from "@mui/icons-material/Storage";
import HubIcon from "@mui/icons-material/Hub";
import InsightsIcon from "@mui/icons-material/Insights";
import SettingsIcon from "@mui/icons-material/Settings";
import HourglassBottomIcon from "@mui/icons-material/HourglassBottom";
import PolicyIcon from "@mui/icons-material/Policy";
import SyncAltIcon from "@mui/icons-material/SyncAlt";
import ShieldIcon from "@mui/icons-material/Shield";
import PlaylistPlayIcon from "@mui/icons-material/PlaylistPlay";
import ScheduleIcon from "@mui/icons-material/Schedule";
import WorkHistoryIcon from "@mui/icons-material/WorkHistory";
import MonitorHeartIcon from "@mui/icons-material/MonitorHeart";
import DarkModeIcon from "@mui/icons-material/DarkMode";
import LightModeIcon from "@mui/icons-material/LightMode";
import MenuIcon from "@mui/icons-material/Menu";
import LogoutIcon from "@mui/icons-material/Logout";
import ExitToAppIcon from "@mui/icons-material/ExitToApp";
import { Link as RouterLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useUIStore } from "../store/ui";
import { getFederationMode, listSites } from "../api/federation";
import { useAuthStore } from "../store/auth";
import { useAppName, useDocumentTitle } from "../api/branding";
import { getTimezone } from "../api/timezone";
import { listTenants } from "../api/tenants";
import { listAssistantApprovals } from "../api/assistant";
import { setDisplayTimezone } from "../lib/datetime";

const DRAWER_WIDTH = 232;

// Each item's `perm` mirrors the permission its route enforces in App.tsx, so the
// menu shows a link only if the user can actually open the page. Items without a
// `perm` (Dashboard, Approvals, Security) are available to every authenticated
// user, matching their unguarded routes. The backend remains the sole
// authorization authority — this filtering is cosmetic.
const NAV: Array<{ to: string; label: string; icon: React.ReactNode; perm?: string; providerOnly?: boolean; hubOnly?: boolean }> = [
  { to: "/tenants", label: "Tenants", icon: <ApartmentIcon />, providerOnly: true },
  { to: "/", label: "Dashboard", icon: <DashboardIcon /> },
  { to: "/sites", label: "Sites", icon: <HubIcon />, perm: "Federation.Manage", hubOnly: true },
  { to: "/ask", label: "Ask", icon: <SmartToyIcon />, perm: "Assistant.Use" },
  { to: "/hosts", label: "Hosts", icon: <DnsIcon />, perm: "Host.View" },
  { to: "/terminals", label: "Terminals", icon: <TerminalIcon />, perm: "Host.Connect" },
  { to: "/sessions", label: "Session Replay", icon: <HistoryIcon />, perm: "Session.Replay" },
  { to: "/automation", label: "Automation", icon: <PlaylistPlayIcon />, perm: "Playbook.Edit" },
  { to: "/schedules", label: "Schedules", icon: <ScheduleIcon />, perm: "Schedule.Manage" },
  { to: "/approvals", label: "Approvals", icon: <ApprovalIcon /> },
  { to: "/audit", label: "Audit", icon: <GavelIcon />, perm: "Audit.View" },
  { to: "/reports", label: "Reports", icon: <AssessmentIcon />, perm: "Audit.View" },
  { to: "/behavior", label: "Behavior", icon: <InsightsIcon />, perm: "Audit.View" },
  { to: "/access-reviews", label: "Access Reviews", icon: <FactCheckIcon />, perm: "AccessReview.Manage" },
  { to: "/users", label: "Users", icon: <PeopleIcon />, perm: "User.Edit" },
  { to: "/roles", label: "Roles", icon: <SecurityIcon />, perm: "Role.Edit" },
  { to: "/groups", label: "Groups", icon: <GroupWorkIcon />, perm: "Group.Edit" },
  { to: "/service-accounts", label: "Service Accounts", icon: <ApiIcon />, perm: "ServiceAccount.Manage" },
  { to: "/vault", label: "Credentials", icon: <KeyIcon />, perm: "Credential.View" },
  { to: "/databases", label: "Databases", icon: <StorageIcon />, perm: "Database.Connect" },
  { to: "/kubernetes", label: "Kubernetes", icon: <HubIcon />, perm: "Kubernetes.Access" },
  { to: "/enrollment", label: "Enrollment", icon: <CloudUploadIcon />, perm: "Host.Enroll" },
  { to: "/certificates", label: "Certificates", icon: <VpnKeyIcon />, perm: "Certificate.Manage" },
  { to: "/lifecycle", label: "Expiry & Rotation", icon: <HourglassBottomIcon />, perm: "System.Configure" },
  { to: "/security", label: "Security", icon: <ShieldIcon /> },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: <BugReportIcon />, perm: "Host.Scan" },
  { to: "/command-policy", label: "Command Control", icon: <PolicyIcon />, perm: "CommandPolicy.Manage" },
  { to: "/access-policies", label: "Access Policies", icon: <GavelIcon />, perm: "AccessPolicy.Manage" },
  { to: "/jobs", label: "Jobs", icon: <WorkHistoryIcon />, perm: "System.Configure" },
  { to: "/system-health", label: "Health", icon: <MonitorHeartIcon />, perm: "System.Configure" },
  { to: "/disaster-recovery", label: "Disaster Recovery", icon: <SyncAltIcon />, perm: "DR.Manage" },
  { to: "/settings", label: "Settings", icon: <SettingsIcon />, perm: "System.Configure" },
  { to: "/help", label: "Help", icon: <HelpOutlineIcon /> },
];

// Application chrome: top bar + persistent navigation drawer. The routed page
// renders into <Outlet/>.
export function AppLayout() {
  const { pathname } = useLocation();
  // Load the app-wide display timezone and apply it before rendering child pages
  // so every timestamp formats in the configured zone. Re-applies if it changes.
  const { data: tz } = useQuery({ queryKey: ["timezone"], queryFn: getTimezone });
  setDisplayTimezone(tz);
  const has = useAuthStore((s) => s.has);
  const showProvider = useAuthStore((s) => s.multiTenancy && s.isProviderAdmin);
  const activeTenant = useAuthStore((s) => s.activeTenant);
  const switchTenant = useAuthStore((s) => s.switchTenant);
  const qc = useQueryClient();
  const navigate = useNavigate();
  // Federation role: hub-only navigation + the site selector appear only on a hub.
  const { data: fedMode } = useQuery({ queryKey: ["fed-mode"], queryFn: getFederationMode, staleTime: 300_000 });
  const isHub = fedMode === "hub";
  const siteScope = useUIStore((s) => s.siteScope);
  const setSiteScope = useUIStore((s) => s.setSiteScope);
  const { data: fedSites = [] } = useQuery({
    queryKey: ["fed-sites-nav"], queryFn: listSites, enabled: isHub, refetchInterval: 10000,
  });
  const changeScope = (id: string | null) => {
    setSiteScope(id);
    // Every cached query was fetched against the previous scope; drop them so pages
    // refetch against the newly selected site (or the hub).
    void qc.invalidateQueries();
  };
  // While switched into a customer tenant, resolve its name so it can be shown on every
  // page. Reuses the ["tenants"] cache the Tenants console already populates; gated so we
  // only fetch when actually inside a tenant.
  const { data: tenants } = useQuery({
    queryKey: ["tenants"], queryFn: listTenants, enabled: !!activeTenant,
  });
  const activeTenantName = tenants?.find((t) => t.id === activeTenant)?.name;
  // One-click return to the provider's own view: clear the tenant header, refetch every
  // query under the restored context, and land on the dashboard. Mirrors the Tenants
  // console's "Return to your tenant" action so both entry points behave identically.
  const exitTenant = () => {
    switchTenant(null);
    void qc.invalidateQueries();
    navigate("/");
  };
  // Pending assistant-action approvals awaiting this user (approvers only), shown
  // as a badge on the Ask nav item.
  const { data: pendingApprovals = [] } = useQuery({
    queryKey: ["assistant-approvals-nav"],
    queryFn: listAssistantApprovals,
    enabled: has("Assistant.Approve"),
    refetchInterval: 60000,
  });
  const mode = useUIStore((s) => s.mode);
  const toggleMode = useUIStore((s) => s.toggleMode);
  const sidebarOpen = useUIStore((s) => s.sidebarOpen);
  const toggleSidebar = useUIStore((s) => s.toggleSidebar);
  const logout = useAuthStore((s) => s.logout);
  const username = useAuthStore((s) => s.user?.username);
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
          {activeTenant && (
            <Box sx={{ display: "flex", alignItems: "center", mr: 1 }}>
              <Tooltip title="You are acting inside this customer tenant — click to manage tenants">
                <Chip
                  size="small" color="warning" clickable component={RouterLink} to="/tenants"
                  icon={<ApartmentIcon />}
                  label={activeTenantName ? `Tenant: ${activeTenantName}` : "In customer tenant"}
                  sx={{ mr: 0.5, fontWeight: 600, maxWidth: 280, "& .MuiChip-label": { overflow: "hidden", textOverflow: "ellipsis" } }}
                />
              </Tooltip>
              <Tooltip title="Return to your provider view">
                <Button
                  color="inherit" size="small" startIcon={<ExitToAppIcon />}
                  onClick={exitTenant} sx={{ whiteSpace: "nowrap" }}
                >
                  Exit
                </Button>
              </Tooltip>
            </Box>
          )}
          {isHub && (
            <Tooltip title="Manage a federated site — every page targets it until you switch back">
              <Select
                size="small" variant="standard" disableUnderline
                value={siteScope ?? "hub"}
                onChange={(e) => changeScope(e.target.value === "hub" ? null : String(e.target.value))}
                sx={{
                  mr: 2, minWidth: 150, color: "inherit",
                  ".MuiSelect-icon": { color: "inherit" },
                  ...(siteScope ? { bgcolor: "warning.dark", px: 1, borderRadius: 1 } : {}),
                }}
              >
                <MenuItem value="hub">◎ Hub (local)</MenuItem>
                {fedSites.filter((s) => s.status === "active").map((s) => (
                  <MenuItem key={s.id} value={s.id}>
                    {s.linkState === "up" ? "🟢" : "🔴"} {s.name}
                  </MenuItem>
                ))}
              </Select>
            </Tooltip>
          )}
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
            {NAV.filter((item) => (!item.perm || has(item.perm)) && (!item.providerOnly || showProvider) && (!item.hubOnly || isHub)).map((item) => {
              const selected =
                item.to === "/" ? pathname === "/" : pathname.startsWith(item.to);
              return (
                <ListItemButton
                  key={item.to}
                  component={RouterLink}
                  to={item.to}
                  selected={selected}
                >
                  <ListItemIcon sx={{ minWidth: 36 }}>
                    {item.to === "/ask" && pendingApprovals.length > 0
                      ? <Badge color="warning" badgeContent={pendingApprovals.length}>{item.icon}</Badge>
                      : item.icon}
                  </ListItemIcon>
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
