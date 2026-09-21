import {
  AppBar, Badge, Box, Button, Chip, Collapse, CssBaseline, Divider, Drawer, IconButton, List, ListItemButton,
  ListItemIcon, ListItemText, MenuItem, Select, Toolbar, Typography, Tooltip,
} from "@mui/material";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import DnsIcon from "@mui/icons-material/Dns";
import ViewInArIcon from "@mui/icons-material/ViewInAr";
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
import AlbumIcon from "@mui/icons-material/Album";
import HelpOutlineIcon from "@mui/icons-material/HelpOutline";
import FactCheckIcon from "@mui/icons-material/FactCheck";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import KeyIcon from "@mui/icons-material/Key";
import StorageIcon from "@mui/icons-material/Storage";
import ArticleIcon from "@mui/icons-material/Article";
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
import { useFleetEvents } from "../api/events";
import { listTenants } from "../api/tenants";
import { assistantStatus, listAssistantApprovals } from "../api/assistant";
import { setDisplayTimezone } from "../lib/datetime";

const DRAWER_WIDTH = 232;

// The navigation, grouped.
//
// This was thirty-five items in one flat list, in the order they happened to be
// built. Finding anything meant reading all of it, and the list only grows --
// every feature added another line, and the ones an operator uses hourly sat
// between ones they touch twice a year.
//
// Grouped by what someone is trying to DO, not by which subsystem implements
// it: "I need to reach a machine", "I need to prove who did what", "I need to
// change who can do it". That is why Credentials sits with Certificates rather
// than with Users, and why Imaging and Enrollment are together -- both are how
// a machine comes to exist here.
//
// Each item's `perm` mirrors the permission its route enforces in App.tsx, so
// the sidebar shows exactly what the user can actually open. Items with no
// `perm` (Dashboard, Approvals, Security, Help) are available to every
// authenticated user.
interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
  perm?: string;
  providerOnly?: boolean;
  hubOnly?: boolean;
  // Hidden until the AI assistant is actually configured. Unlike the flags above,
  // which describe who you are, this describes whether the destination exists: with
  // no model server set up, Ask is a permanent link to a page whose only content is
  // an explanation that an administrator has not set it up. On a fresh install that
  // is every deployment, and the permission is granted by default — so the first
  // thing a new operator sees in the sidebar is a feature that does nothing.
  assistantOnly?: boolean;
  // Hidden unless this deployment actually has the subsystem (from /auth/me
  // `features`). A permanent link to a page whose only content explains that nobody
  // deployed the thing is clutter with a permission check on it.
  //
  // Only DEPLOYMENT-level absence belongs here. "Configured but empty" is not the
  // same as "not available" — hiding Databases because none are registered would
  // remove the only route to registering the first one.
  feature?: string;
}

// Shown above the sections, always. These are the entry points rather than
// destinations: where you land, what you ask, and the two scope switchers that
// change what everything else means.
export const NAV_TOP: NavItem[] = [
  { to: "/tenants", label: "Tenants", icon: <ApartmentIcon />, providerOnly: true },
  { to: "/", label: "Dashboard", icon: <DashboardIcon /> },
  { to: "/sites", label: "Sites", icon: <HubIcon />, perm: "Federation.Manage", hubOnly: true },
  { to: "/ask", label: "Ask", icon: <SmartToyIcon />, perm: "Assistant.Use", assistantOnly: true },
];

// Personal, not administrative: what is waiting for you, your own sign-in
// security, and the manual. Rendered after the sections without a heading of
// their own, because a heading over three unrelated personal items is more
// clutter, not less.
//
// Two of these were previously mixed into the administrative list. "Security"
// in particular sat between Vulnerabilities and Imaging and reads there as the
// fleet's security posture -- it is this user's two-factor and passkeys, which
// is why it is now named for what it is. Approvals had no permission attached,
// so wherever it was grouped, that group appeared for every user in the
// product.
export const NAV_BOTTOM: NavItem[] = [
  { to: "/approvals", label: "Approvals", icon: <ApprovalIcon /> },
  { to: "/security", label: "My Account", icon: <ShieldIcon /> },
  { to: "/help", label: "Help", icon: <HelpOutlineIcon /> },
];

export const NAV_SECTIONS: Array<{ title: string; items: NavItem[] }> = [
  {
    // Reaching machines, and what happened while you were there. Session Replay
    // belongs here rather than under compliance: it is the recording of the
    // thing directly above it, and it is looked for right after using it.
    title: "Access",
    items: [
      { to: "/hosts", label: "Hosts", icon: <DnsIcon />, perm: "Host.View" },
      // Beside Hosts, because a stack is a property of the host that runs it and
      // the two questions -- "what is this machine" and "what should it be
      // running" -- are asked together.
      { to: "/stacks", label: "Containers", icon: <ViewInArIcon />, perm: "Host.View" },
      { to: "/terminals", label: "Terminals", icon: <TerminalIcon />, perm: "Host.Connect" },
      { to: "/databases", label: "Databases", icon: <StorageIcon />, perm: "Database.Connect" },
      { to: "/kubernetes", label: "Kubernetes", icon: <HubIcon />, perm: "Kubernetes.Access" },
      { to: "/logs", label: "Logs", icon: <ArticleIcon />, perm: "Logs.View", feature: "logs" },
      { to: "/sessions", label: "Session Replay", icon: <HistoryIcon />, perm: "Session.Replay" },
    ],
  },
  {
    title: "Automation",
    items: [
      { to: "/automation", label: "Automation", icon: <PlaylistPlayIcon />, perm: "Playbook.Edit" },
      { to: "/schedules", label: "Schedules", icon: <ScheduleIcon />, perm: "Schedule.Manage" },
      { to: "/jobs", label: "Jobs", icon: <WorkHistoryIcon />, perm: "System.Configure" },
    ],
  },
  {
    // How a machine comes to exist here at all: imaged, or enrolled.
    title: "Provisioning",
    items: [
      { to: "/imaging", label: "Imaging", icon: <AlbumIcon />, perm: "Imaging.View", feature: "imaging" },
      { to: "/enrollment", label: "Enrollment", icon: <CloudUploadIcon />, perm: "Host.Enroll" },
    ],
  },
  {
    title: "Security",
    items: [
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: <BugReportIcon />, perm: "Host.Scan" },
      { to: "/vault", label: "Credentials", icon: <KeyIcon />, perm: "Credential.View" },
      { to: "/certificates", label: "Certificates", icon: <VpnKeyIcon />, perm: "Certificate.Manage" },
      { to: "/lifecycle", label: "Expiry & Rotation", icon: <HourglassBottomIcon />, perm: "System.Configure" },
    ],
  },
  {
    // Who exists and what they may do. Approvals is here because it is the
    // moment policy is applied to a person, not a report about it afterwards.
    title: "Identity & Policy",
    items: [
      { to: "/users", label: "Users", icon: <PeopleIcon />, perm: "User.Edit" },
      { to: "/roles", label: "Roles", icon: <SecurityIcon />, perm: "Role.Edit" },
      { to: "/groups", label: "Groups", icon: <GroupWorkIcon />, perm: "Group.Edit" },
      { to: "/service-accounts", label: "Service Accounts", icon: <ApiIcon />, perm: "ServiceAccount.Manage" },
      { to: "/access-policies", label: "Access Policies", icon: <GavelIcon />, perm: "AccessPolicy.Manage" },
      { to: "/command-policy", label: "Command Control", icon: <PolicyIcon />, perm: "CommandPolicy.Manage" },
    ],
  },
  {
    // Proving what happened, to someone who was not there.
    title: "Compliance",
    items: [
      { to: "/audit", label: "Audit", icon: <GavelIcon />, perm: "Audit.View" },
      { to: "/reports", label: "Reports", icon: <AssessmentIcon />, perm: "Audit.View" },
      { to: "/behavior", label: "Behavior", icon: <InsightsIcon />, perm: "Audit.View" },
      { to: "/access-reviews", label: "Access Reviews", icon: <FactCheckIcon />, perm: "AccessReview.Manage" },
    ],
  },
  {
    // The deployment itself, rather than what it manages.
    title: "System",
    items: [
      { to: "/system-health", label: "Health", icon: <MonitorHeartIcon />, perm: "System.Configure" },
      { to: "/disaster-recovery", label: "Disaster Recovery", icon: <SyncAltIcon />, perm: "DR.Manage" },
      { to: "/settings", label: "Settings", icon: <SettingsIcon />, perm: "System.Configure" },
    ],
  },
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

  // App-wide live updates: the backend broadcasts host.status on every probe and
  // session start/end over the events WebSocket. Subscribing here (the shell is
  // mounted on every authenticated page) means any open host list — Dashboard,
  // Terminals, Hosts — reflects a host coming online/offline within seconds, from a
  // single connection, without the user refreshing. Cheap: it only marks the shared
  // queries stale, so react-query refetches just the lists that are actually mounted.
  useFleetEvents((e) => {
    if (e.type === "host.status") {
      void qc.invalidateQueries({ queryKey: ["hosts"] });
      void qc.invalidateQueries({ queryKey: ["host"] }); // single-host detail (Terminal view chip)
      void qc.invalidateQueries({ queryKey: ["dash-insights"] });
    } else if (e.type?.startsWith("session")) {
      void qc.invalidateQueries({ queryKey: ["sessions"] });
    }
  });

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
  // Is the assistant set up at all? Asked only of users who could open it, and only
  // to decide whether the link is worth showing. While the answer is unknown the item
  // stays hidden: showing it and removing it a moment later is worse than showing it
  // slightly late, and an unreachable status endpoint is not a reason to advertise a
  // feature that may not exist.
  const { data: assistantSettings } = useQuery({
    queryKey: ["assistant-configured-nav"],
    queryFn: assistantStatus,
    enabled: has("Assistant.Use"),
    staleTime: 5 * 60_000,
    retry: false,
  });
  const assistantConfigured = assistantSettings?.enabled === true;
  const features = useAuthStore((s) => s.features);
  const mode = useUIStore((s) => s.mode);
  const toggleMode = useUIStore((s) => s.toggleMode);
  const sidebarOpen = useUIStore((s) => s.sidebarOpen);
  const toggleSidebar = useUIStore((s) => s.toggleSidebar);
  const logout = useAuthStore((s) => s.logout);
  const username = useAuthStore((s) => s.user?.username);
  const appName = useAppName();
  useDocumentTitle();

  const collapsed = useUIStore((s) => s.navCollapsed);
  const toggleNavSection = useUIStore((s) => s.toggleNavSection);

  // Is the subsystem behind this entry present in this deployment?
  //
  // Hidden only when the backend says it is absent. An older backend sends no
  // `features` at all, and hiding working pages because a field was missing is a
  // worse failure than showing one that explains itself — so absence means
  // "unknown", not "off". (Ask goes the other way: its status endpoint always
  // answers on a current backend, and a link that appears and then vanishes is
  // worse than one that appears a moment late.)
  //
  // A function rather than an inline clause: written inline it needed a `||`, which
  // binds looser than the `&&` chain around it and quietly made EVERY entry visible.
  const deployed = (f?: string) => f === undefined || features[f] !== false;

  // Shown only if the user could actually open it. The sidebar has always
  // mirrored the routes' own permission checks rather than keeping a second
  // list, so a route that gains a permission cannot leave a dead link behind.
  const visible = (item: NavItem) =>
    (!item.perm || has(item.perm)) &&
    (!item.providerOnly || showProvider) &&
    (!item.hubOnly || isHub) &&
    (!item.assistantOnly || assistantConfigured) &&
    deployed(item.feature);

  // "/" would prefix-match every path, so it alone is matched exactly.
  const isSelected = (to: string) =>
    to === "/" ? pathname === "/" : pathname.startsWith(to);

  const renderItem = (item: NavItem) => (
    <ListItemButton
      key={item.to}
      component={RouterLink}
      to={item.to}
      selected={isSelected(item.to)}
      sx={{ py: 0.4 }}
    >
      <ListItemIcon sx={{ minWidth: 36 }}>
        {item.to === "/ask" && pendingApprovals.length > 0
          ? <Badge color="warning" badgeContent={pendingApprovals.length}>{item.icon}</Badge>
          : item.icon}
      </ListItemIcon>
      <ListItemText primary={item.label} />
    </ListItemButton>
  );

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
            {NAV_TOP.filter(visible).map(renderItem)}
            {NAV_SECTIONS.map((section) => {
              const items = section.items.filter(visible);
              // A section whose every item is hidden by permission must not
              // leave its heading behind. An empty "Compliance" tells a user
              // with no compliance access only that something exists which they
              // cannot have.
              if (items.length === 0) return null;
              // The section holding the current page is always open, whatever
              // was collapsed before: navigating into a page and finding the
              // menu around it shut is disorienting, and it happens on every
              // deep link and every reload.
              const hasActive = items.some((i) => isSelected(i.to));
              const open = hasActive || !collapsed.includes(section.title);
              return (
                <Box key={section.title}>
                  <ListItemButton
                    onClick={() => toggleNavSection(section.title)}
                    sx={{ py: 0.25 }}
                  >
                    <ListItemText
                      primary={section.title}
                      primaryTypographyProps={{
                        variant: "overline",
                        sx: { fontSize: 11, letterSpacing: 1, opacity: 0.65 },
                      }}
                    />
                    {open ? <ExpandLessIcon fontSize="small" sx={{ opacity: 0.5 }} />
                          : <ExpandMoreIcon fontSize="small" sx={{ opacity: 0.5 }} />}
                  </ListItemButton>
                  <Collapse in={open} timeout="auto" unmountOnExit>
                    <List dense disablePadding>
                      {items.map(renderItem)}
                    </List>
                  </Collapse>
                </Box>
              );
            })}
            <Divider sx={{ my: 0.5 }} />
            {NAV_BOTTOM.filter(visible).map(renderItem)}
          </List>
        </Box>
      </Drawer>
      <Box component="main" sx={{ flexGrow: 1, minWidth: 0, p: 3, mt: 6 }}>
        <Outlet />
      </Box>
    </Box>
  );
}
