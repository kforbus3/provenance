import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { DataGrid } from "@mui/x-data-grid";
import { HostsToolbar, enrolLoggingMessage } from "./HostsPage";

// "Send logs to collector" runs the imported enrollment playbook over the selection.
// Two things must hold: the action is reachable from Bulk actions, and what the
// operator is told afterwards matches what actually happened.

describe("Send logs to collector", () => {
  it("is offered in the bulk-actions menu and reports the chosen action", () => {
    const onBulk = vi.fn();
    // Inside a DataGrid: the toolbar is a grid slot and uses grid context, so it
    // cannot be rendered on its own.
    render(
      <DataGrid
        rows={[]}
        columns={[{ field: "hostname" }]}
        slots={{ toolbar: HostsToolbar }}
        slotProps={{
          toolbar: {
            selectedCount: 3,
            onNew: () => {},
            onDelete: () => {},
            onRefresh: () => {},
            onBulk,
          } as never,
        }}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /Bulk actions \(3\)/ }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Send logs to collector" }));
    expect(onBulk).toHaveBeenCalledWith("sendLogs");
  });

  // A skipped host that is not named is a host the operator believes is sending logs.
  it("names skipped hosts and keeps the message on screen", () => {
    const { text, sticky } = enrolLoggingMessage({
      playbook: "Enroll Syslog To Aldgate",
      hostCount: 4,
      skipped: [{ hostname: "coreswitch", reason: "RouterOS device" }],
    });
    expect(text).toContain("Enrolling 4 host(s)");
    expect(text).toContain("coreswitch");
    expect(text).toContain("RouterOS device");
    expect(sticky).toBe(true);
  });

  // Every host skipped means nothing ran at all. Saying "Enrolling 0 host(s)" would
  // read as success.
  it("says nothing ran when every selected host was skipped", () => {
    const { text, sticky } = enrolLoggingMessage({
      playbook: "Enroll Syslog To Aldgate",
      hostCount: 0,
      skipped: [{ hostname: "coreswitch", reason: "RouterOS device" }],
    });
    expect(text).toMatch(/^Nothing to enroll/);
    expect(text).toContain("coreswitch");
    expect(sticky).toBe(true);
  });

  it("is a plain, dismissable confirmation when nothing was skipped", () => {
    const { text, sticky } = enrolLoggingMessage({
      playbook: "Enroll Syslog To Aldgate", hostCount: 6, skipped: [],
    });
    expect(text).toContain("Enrolling 6 host(s) into log collection");
    expect(sticky).toBe(false);
  });
});
