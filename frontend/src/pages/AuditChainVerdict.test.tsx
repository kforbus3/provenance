import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";

import { AuditChainVerdict } from "./AuditChainVerdict";
import { useAuthStore } from "../store/auth";

// Acknowledging a break makes the verdict stop saying "broken" on purpose: a verdict
// that can only ever say BROKEN stops being read, and then a real break arrives at an
// indicator everybody has learned to ignore.
//
// The cost of that, if nothing else changes, is a screen that says "Audit chain is
// intact." over rows that do not verify. The first production chain examined after the
// pre-0106 foreign key was dropped had 3,054 of them out of 5,521, from a handful of
// accounts being deleted over three months.

vi.mock("../api/audit", async (orig) => ({
  ...(await orig<object>()),
  scanAuditChain: vi.fn(),
  acknowledgeChainRange: vi.fn(),
}));

import { acknowledgeChainRange, scanAuditChain } from "../api/audit";

function renderVerdict(result: object, permissions = ["System.Configure"], isSuperAdmin = false) {
  useAuthStore.setState({
    user: { id: "1", username: "keith" },
    permissions, isSuperAdmin, loaded: true, restore: vi.fn(),
  } as never);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <AuditChainVerdict result={result as never} />
    </QueryClientProvider>,
  );
}

const RANGE = {
  fromSeq: 2, toSeq: 5380, covered: 3054, coveredCount: 3054,
  by: "keith", note: "deleted accounts nulled actor_id before 0106", at: "2026-09-21T00:00:00Z",
};

const SCAN = {
  rows: 5521, breakCount: 3054, acknowledgedCount: 0, firstSeq: 2, lastSeq: 5380,
  breaks: [], truncated: true, noActorCount: 3054, unlinkedCount: 0, unexplainedCount: 0,
};

beforeEach(() => vi.clearAllMocks());

describe("AuditChainVerdict", () => {
  it("does not call a chain with acknowledged breaks intact", () => {
    renderVerdict({ intact: true, brokenAtSeq: 0, acknowledgedRanges: [RANGE] });
    expect(screen.queryByText("Audit chain is intact.")).not.toBeInTheDocument();
    // The count must appear: an operator who has done the investigation should see a
    // calm, accurate statement of scale, not an alarm and not a clean bill of health.
    expect(screen.getByText(/3,054 recorded exceptions/)).toBeInTheDocument();
    // And the recorded account of why is on screen, not hidden behind a click: it is
    // the only thing that distinguishes this from an unexplained break.
    expect(screen.getByText(/nulled actor_id before 0106/)).toBeInTheDocument();
  });

  it("says intact only when nothing fails to verify", () => {
    renderVerdict({ intact: true, brokenAtSeq: 0 });
    expect(screen.getByText("Audit chain is intact.")).toBeInTheDocument();
  });

  it("reports a broken chain and offers a diagnosis rather than a bare failure", async () => {
    (scanAuditChain as ReturnType<typeof vi.fn>).mockResolvedValue(SCAN);
    renderVerdict({ intact: false, brokenAtSeq: 2 });
    expect(screen.getByText(/broken at sequence 2/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Diagnose/ }));
    await waitFor(() =>
      expect(screen.getByText(/3,054 of 5,521 rows do not verify/)).toBeInTheDocument());
    // The reassuring half of the diagnosis is as important as the alarming half: no
    // broken link means no row was removed or reordered.
    expect(screen.getByText(/no row was removed, inserted or reordered/)).toBeInTheDocument();
  });

  it("will not offer a bulk acknowledgement when a break has a broken link", async () => {
    (scanAuditChain as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...SCAN, unlinkedCount: 4,
    });
    renderVerdict({ intact: false, brokenAtSeq: 2 });
    fireEvent.click(screen.getByRole("button", { name: /Diagnose/ }));
    await waitFor(() => expect(screen.getByText(/rows were removed/)).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /Acknowledge/ })).not.toBeInTheDocument();
  });

  it("will not offer a bulk acknowledgement for breaks it cannot explain", async () => {
    (scanAuditChain as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...SCAN, unexplainedCount: 7, noActorCount: 3047,
    });
    renderVerdict({ intact: false, brokenAtSeq: 2 });
    fireEvent.click(screen.getByRole("button", { name: /Diagnose/ }));
    await waitFor(() => expect(screen.getByText(/Investigate those individually/)).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /Acknowledge/ })).not.toBeInTheDocument();
  });

  it("requires a note before it will record an acknowledgement", async () => {
    (scanAuditChain as ReturnType<typeof vi.fn>).mockResolvedValue(SCAN);
    (acknowledgeChainRange as ReturnType<typeof vi.fn>).mockResolvedValue({
      fromSeq: 2, toSeq: 5380, coveredCount: 3054, evidenceSeq: 5522,
    });
    renderVerdict({ intact: false, brokenAtSeq: 2 });
    fireEvent.click(screen.getByRole("button", { name: /Diagnose/ }));
    await waitFor(() => screen.getByRole("button", { name: /Acknowledge 3,054 rows/ }));
    fireEvent.click(screen.getByRole("button", { name: /Acknowledge 3,054 rows/ }));

    const record = screen.getByRole("button", { name: /Record acknowledgement/ });
    expect(record).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/What was investigated/), {
      target: { value: "traced to accounts deleted in June; no links broken" },
    });
    expect(record).toBeEnabled();
    fireEvent.click(record);
    await waitFor(() => expect(acknowledgeChainRange).toHaveBeenCalledWith(
      2, 5380, "traced to accounts deleted in June; no links broken"));
  });

  // A super administrator holds every permission implicitly, so the account here has
  // to be an ordinary one or the check would pass without checking anything.
  it("does not offer the acknowledgement to somebody who may not configure the instance", async () => {
    (scanAuditChain as ReturnType<typeof vi.fn>).mockResolvedValue(SCAN);
    renderVerdict({ intact: false, brokenAtSeq: 2 }, ["Audit.View"], false);
    fireEvent.click(screen.getByRole("button", { name: /Diagnose/ }));
    await waitFor(() => screen.getByText(/3,054 of 5,521 rows do not verify/));
    expect(screen.queryByRole("button", { name: /Acknowledge/ })).not.toBeInTheDocument();
  });
});
