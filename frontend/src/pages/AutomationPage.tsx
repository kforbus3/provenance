import { useState } from "react";
import { Box, Tab, Tabs } from "@mui/material";
import { useAuthStore } from "../store/auth";
import { PlaybooksPage } from "./PlaybooksPage";
import { ScriptsPage } from "./ScriptsPage";

// Automation groups the two host-automation surfaces in one place: Ansible
// playbooks (Linux hosts) and PowerShell scripts (Windows hosts). Each tab is shown
// only when the user can author that kind; the route itself is guarded on either.
export function AutomationPage() {
  const has = useAuthStore((s) => s.has);
  const canPlaybooks = has("Playbook.Edit");
  const canScripts = has("Script.Edit");

  // Default to whichever the user can access (playbooks first).
  const [tab, setTab] = useState<"playbooks" | "scripts">(canPlaybooks ? "playbooks" : "scripts");

  return (
    <Box>
      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
        {canPlaybooks && <Tab label="Ansible Playbooks" value="playbooks" />}
        {canScripts && <Tab label="PowerShell Scripts" value="scripts" />}
      </Tabs>
      {tab === "playbooks" && canPlaybooks && <PlaybooksPage />}
      {tab === "scripts" && canScripts && <ScriptsPage />}
    </Box>
  );
}
