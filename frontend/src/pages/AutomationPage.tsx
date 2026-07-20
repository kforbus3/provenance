import { useState } from "react";
import { Box, Tab, Tabs } from "@mui/material";
import { useAuthStore } from "../store/auth";
import { PlaybooksPage } from "./PlaybooksPage";
import { ScriptsPage } from "./ScriptsPage";
import { AdhocCommandPage } from "./AdhocCommandPage";

// Automation groups the host-automation surfaces in one place: Ansible playbooks
// (Linux), PowerShell scripts (Windows), and ad-hoc shell commands (Linux). Each
// tab is shown only when the user can use that kind; the route is guarded on any.
export function AutomationPage() {
  const has = useAuthStore((s) => s.has);
  const canPlaybooks = has("Playbook.Edit");
  const canScripts = has("Script.Edit");
  const canCommand = has("Command.Run");

  // Default to whichever the user can access (playbooks first).
  const [tab, setTab] = useState<"playbooks" | "scripts" | "command">(
    canPlaybooks ? "playbooks" : canScripts ? "scripts" : "command",
  );

  return (
    <Box>
      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
        {canPlaybooks && <Tab label="Ansible Playbooks" value="playbooks" />}
        {canScripts && <Tab label="PowerShell Scripts" value="scripts" />}
        {canCommand && <Tab label="Ad-hoc Command" value="command" />}
      </Tabs>
      {tab === "playbooks" && canPlaybooks && <PlaybooksPage />}
      {tab === "scripts" && canScripts && <ScriptsPage />}
      {tab === "command" && canCommand && <AdhocCommandPage />}
    </Box>
  );
}
