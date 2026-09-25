import "@testing-library/jest-dom/vitest";
import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SchedulesPage } from "./SchedulesPage";
import * as api from "../api/schedules";
import { vi } from "vitest";
import type { Schedule } from "../api/schedules";

// Every schedule on this fleet read "started", forever: lastStatus records what
// FIRING did and never changes afterwards. A playbook schedule that failed six nights
// running looked exactly like one that worked — on the page an operator opens to find
// out which.

function sched(over: Partial<Schedule>): Schedule {
  return {
    id: over.id ?? "s1", name: "Weekly Apt Upgrade", kind: "playbook", enabled: true,
    targetKind: "group", targetName: "HomeNetServers",
    recurrence: { kind: "weekly", hour: 7, minute: 0, weekday: 5 } as never,
    lastRunAt: "2026-09-18T07:00:00Z", lastStatus: "started",
    createdAt: "", updatedAt: "", ...over,
  } as Schedule;
}

function renderWith(schedules: Schedule[]) {
  vi.spyOn(api, "listSchedules").mockResolvedValue(schedules);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}><SchedulesPage /></QueryClientProvider>);
}

describe("what a schedule's last run actually did", () => {
  it("shows the outcome of the runs it produced, not just that it fired", async () => {
    renderWith([
      sched({ id: "a", name: "Weekly Apt Upgrade", lastOutcome: "failed" }),
      sched({ id: "b", name: "Apt Cache Update", lastOutcome: "completed" }),
    ]);
    expect(await screen.findByText("failed")).toBeInTheDocument();
    expect(screen.getByText("completed")).toBeInTheDocument();
    // "started" was the old answer for both, and it must not be the visible one now.
    expect(screen.queryByText(/\(started\)/)).not.toBeInTheDocument();
  });

  it("falls back to the firing status when the firing produced nothing", async () => {
    // A vulndb refresh creates no run record, and a firing with no hosts never got
    // one either. Inventing "completed" for those would be a claim about work that
    // never happened.
    renderWith([sched({ id: "c", kind: "vulndb", name: "VulnDBUpdate", lastStatus: "started" })]);
    expect(await screen.findByText(/\(started\)/)).toBeInTheDocument();
  });

  it("says how many hosts of a batch worked", async () => {
    // One host of seventeen failing and every host failing are different mornings.
    // The night gitlab's scan failed, nothing on this page said so.
    renderWith([sched({ id: "e", kind: "vulnscan", name: "VulnScan", lastOutcome: "failed", lastRunTotal: 17, lastRunOk: 16 })]);
    expect(await screen.findByText("failed 16/17")).toBeInTheDocument();
  });

  it("shows a CVE refresh's own result once it reports one", async () => {
    // The refresh writes its result onto the firing; the backend derives the verdict.
    renderWith([sched({ id: "f", kind: "vulndb", name: "VulnDBUpdate", lastStatus: "failed: grype database: timeout", lastOutcome: "failed", lastRunTotal: 0 })]);
    expect(await screen.findByText("failed")).toBeInTheDocument();
  });

  it("says when the schedule's target has been deleted", async () => {
    renderWith([sched({ id: "g", kind: "vulnscan", name: "VulnScanWindows", targetKind: "host", targetName: "winserv1", enabled: false, targetMissing: true })]);
    expect(await screen.findByText("host deleted")).toBeInTheDocument();
  });

  it("says skipped rather than inventing a verdict", async () => {
    renderWith([sched({ id: "d", lastStatus: "skipped: no hosts" })]);
    expect(await screen.findByText(/skipped: no hosts/)).toBeInTheDocument();
  });
});
