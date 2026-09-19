import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, beforeEach, vi } from "vitest";

import { LogsPage } from "./LogsPage";
import * as logsApi from "../api/logs";

// "No logs matched" and "no collector configured" render as the same empty
// table and are completely different problems -- one is a query to widen, the
// other is a deployment step nobody has done. Telling them apart is most of
// what makes this page usable, so it is what these tests cover.

vi.mock("../api/logs", async () => {
  const actual = await vi.importActual<typeof logsApi>("../api/logs");
  return {
    ...actual, logStatus: vi.fn(), logHosts: vi.fn(), searchLogs: vi.fn(),
    openLogConsole: vi.fn(),
  };
});

const entry = (over: Partial<logsApi.LogEntry> = {}): logsApi.LogEntry => ({
  timestamp: "2026-09-18T04:30:00Z", host: "k3s", program: "sshd",
  severity: "error", severityCode: 3, message: "connection refused", ...over,
});

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}><LogsPage /></QueryClientProvider>);
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(logsApi.logStatus).mockResolvedValue({ configured: true, reachable: true, hostsSending: 17 });
  vi.mocked(logsApi.logHosts).mockResolvedValue([{ key: "k3s", count: 754 }, { key: "docker", count: 149 }]);
  vi.mocked(logsApi.searchLogs).mockResolvedValue({
    total: 1, entries: [entry()], byHost: [{ key: "k3s", count: 1 }],
    bySeverity: [{ key: "error", count: 1 }], tookMs: 4,
  });
});

describe("LogsPage", () => {
  it("says how to configure a collector when there is none", async () => {
    vi.mocked(logsApi.logStatus).mockResolvedValue({ configured: false, hint: "point at a collector" });
    renderPage();
    expect(await screen.findByText(/No log collector is configured/)).toBeInTheDocument();
    expect(screen.getByText(/PROV_ALDGATE_URL/)).toBeInTheDocument();
    // And it must not pretend to search.
    expect(logsApi.searchLogs).not.toHaveBeenCalled();
  });

  it("distinguishes an empty collector from an unmatched query", async () => {
    vi.mocked(logsApi.logStatus).mockResolvedValue({ configured: true, reachable: true, hostsSending: 0 });
    vi.mocked(logsApi.searchLogs).mockResolvedValue({
      total: 0, entries: [], byHost: [], bySeverity: [], tookMs: 2,
    });
    renderPage();
    expect(await screen.findByText(/no host has sent anything yet/)).toBeInTheDocument();
  });

  it("suggests widening when hosts are sending but nothing matched", async () => {
    vi.mocked(logsApi.searchLogs).mockResolvedValue({
      total: 0, entries: [], byHost: [], bySeverity: [], tookMs: 2,
    });
    renderPage();
    expect(await screen.findByText(/Nothing matched/)).toBeInTheDocument();
  });

  it("renders a log line with its host, program and severity", async () => {
    renderPage();
    expect(await screen.findByText("connection refused")).toBeInTheDocument();
    expect(screen.getAllByText("k3s").length).toBeGreaterThan(0);
    expect(screen.getByText("sshd")).toBeInTheDocument();
  });

  it("does not re-query on every keystroke", async () => {
    renderPage();
    await screen.findByText("connection refused");
    const before = vi.mocked(logsApi.searchLogs).mock.calls.length;
    const box = screen.getByLabelText(/Search messages/);
    fireEvent.change(box, { target: { value: "refused" } });
    fireEvent.change(box, { target: { value: "refused conn" } });
    // Typing alone must not hit a search cluster.
    expect(vi.mocked(logsApi.searchLogs).mock.calls.length).toBe(before);
    fireEvent.click(screen.getByRole("button", { name: /^Search$/ }));
    await waitFor(() =>
      expect(vi.mocked(logsApi.searchLogs).mock.calls.length).toBeGreaterThan(before));
    const calls = vi.mocked(logsApi.searchLogs).mock.calls;
    const last = calls[calls.length - 1]?.[0];
    expect(last?.q).toBe("refused conn");
  });

  // The console signs itself in, which means the session has to be minted BEFORE
  // the tab opens. Opening first and minting afterwards lands the person on a 401
  // from nginx -- which looks exactly like the console being broken.
  it("mints a console session before opening the console", async () => {
    vi.mocked(logsApi.openLogConsole).mockResolvedValue({
      consoleBase: "/aldgate", tier: "view", expiresAt: "2026-09-19T12:00:00Z",
    });
    const opened: string[] = [];
    vi.spyOn(window, "open").mockImplementation((url) => {
      opened.push(String(url));
      return null;
    });

    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /Open log console/ }));

    await waitFor(() => expect(vi.mocked(logsApi.openLogConsole)).toHaveBeenCalled());
    await waitFor(() => expect(opened).toEqual(["/aldgate/"]));
  });

  // A console that cannot be opened must say so. The usual cause is a collector
  // whose console credentials were never copied into Provenance, and the fix is
  // one sentence long -- but a button that silently does nothing tells nobody.
  it("says why when the console cannot be opened", async () => {
    vi.mocked(logsApi.openLogConsole).mockRejectedValue(
      new Error("the console's credentials are not configured"));
    vi.spyOn(window, "open").mockImplementation(() => null);

    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /Open log console/ }));

    expect(await screen.findByText(/credentials are not configured/)).toBeInTheDocument();
  });

  // The exact shape the server used to return for a host with nothing in the
  // window. keith hit this filtering by "docker": React called .map on null,
  // unmounted the tree, and the page went blank with no error anywhere.
  it("does not blank out when the server sends null aggregations", async () => {
    vi.mocked(logsApi.searchLogs).mockResolvedValue({
      total: 0, entries: [],
      byHost: null as unknown as logsApi.LogBucket[],
      bySeverity: null as unknown as logsApi.LogBucket[],
      tookMs: 19,
    });
    renderPage();
    // The page must still render its own furniture rather than disappearing.
    expect(await screen.findByText(/Nothing matched/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Search$/ })).toBeInTheDocument();
  });
});
