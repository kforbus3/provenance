import { describe, it, expect, vi } from "vitest";
import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { DataGrid } from "@mui/x-data-grid";
import { HostsToolbar, ACCOUNT_RE } from "./HostsPage";

// The migrate action could only ever target the default account: the UI never sent a
// name, so on a fleet already on that account it was a no-op everywhere. The name field
// is what makes the backend's existing capability reachable.

describe("migrate login account", () => {
  it("is reachable from the bulk menu", () => {
    const onBulk = vi.fn();
    render(
      <DataGrid
        rows={[]}
        columns={[{ field: "hostname" }]}
        slots={{ toolbar: HostsToolbar }}
        slotProps={{
          toolbar: {
            selectedCount: 2,
            onNew: () => {},
            onDelete: () => {},
            onRefresh: () => {},
            onBulk,
          } as never,
        }}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /Bulk actions \(2\)/ }));
    fireEvent.click(screen.getByRole("menuitem", { name: /Migrate login account/ }));
    expect(onBulk).toHaveBeenCalledWith("migrateAccount");
  });

  // This pattern is a copy of accountName in the Go service, which bounds what reaches
  // useradd/userdel in a root shell on a managed host. A client copy that drifts LOOSER
  // than the server's would offer the operator input the backend then rejects; drifting
  // stricter would hide names that are actually valid. These cases mirror the Go test.
  it("accepts the same account names the backend does", () => {
    for (const ok of ["prov", "fleet", "svc-prov", "_x", "a", "a0-_"]) {
      expect(ACCOUNT_RE.test(ok), `${ok} should be accepted`).toBe(true);
    }
    for (const bad of [
      "",            // empty
      "Prov",        // uppercase
      "0prov",       // leading digit
      "-prov",       // leading hyphen
      "prov account",// space
      "prov;rm -rf /", // shell metacharacters — the reason the bound exists
      "a".repeat(32), // one over the cap
    ]) {
      expect(ACCOUNT_RE.test(bad), `${bad} should be rejected`).toBe(false);
    }
  });
});
