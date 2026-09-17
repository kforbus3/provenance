import "@testing-library/jest-dom/vitest";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as React from "react";

// Every page is query-driven, and nothing until now checked that a page can
// MOUNT. The failure this catches is the one that reaches production intact: a
// component that reads `data.something` before the query resolves, throws on
// first render, and shows the operator a blank screen with the error only in the
// console. Type-checking does not catch it (the field exists, the object is
// undefined at runtime) and no other test renders these pages at all.
//
// One file rather than forty, because the assertion is the same for all of them
// and forty near-identical files is a maintenance cost with no extra signal.

// The single seam: every api/*.ts module goes through this axios instance.
//
// Partially mocked: only `api` is replaced. The module also exports token and
// tenant helpers that the auth store calls at import time, and stubbing the
// whole module breaks the store before any page renders.
vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const empty = async () => ({ data: {} });
  return {
    ...actual,
    api: {
      get: empty, post: empty, put: empty, patch: empty, delete: empty,
      defaults: { headers: { common: {} } },
      interceptors: { request: { use: () => 0 }, response: { use: () => 0 } },
    },
  };
});

// Eagerly import every page module. import.meta.glob is resolved at build time
// by vite, so a page added later is covered without editing this file — which is
// the property that makes a smoke test worth having.
// The negative pattern is load-bearing. An eager glob of "./*.tsx" also imports
// every ./*.test.tsx, and importing a test file EXECUTES its describe/it calls
// inside this one — so the rest of the suite silently re-ran here, under this
// file's api mock, and 17 of them failed for reasons that had nothing to do
// with the pages.
const modules = import.meta.glob(["./*.tsx", "!./*.test.tsx"], {
  eager: true,
}) as Record<string, Record<string, unknown>>;

// Only components the ROUTER renders, and only those it renders with no props.
// Every one of these is mounted by navigating to a URL, so a crash here is a
// blank screen for an operator. Sub-components exported from the same files are
// excluded deliberately: they take props, and rendering them bare would
// manufacture failures that say nothing about the product.
const ROUTED = new Set([
  "AccessPolicyPage", "AccessReviewsPage", "ApprovalsPage", "AssistantPage",
  "AuditPage", "AutomationPage", "BehaviorPage", "BootstrapPage",
  "CertificatesPage", "CommandPolicyPage", "DashboardPage", "DatabasesPage",
  "DisasterRecoveryPage", "EnrollmentPage", "FilesPage", "GroupsPage",
  "HealthPage", "HelpPage", "HostsPage", "ImagingPage", "JobsPage",
  "KubernetesPage", "LifecyclePage", "LoginPage", "RdpPage", "ReportsPage",
  "RolesPage", "SchedulesPage", "SecurityPage", "ServiceAccountsPage",
  "SessionsPage", "SettingsPage", "SitesPage", "StacksPage", "TenantsPage",
  "TerminalPage", "TerminalsPage", "UsersPage", "VaultPage",
  "VulnerabilitiesPage", "WatchSessionPage",
]);

function Harness({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return (
    <MemoryRouter>
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    </MemoryRouter>
  );
}

const pages = Object.entries(modules)
  .flatMap(([path, mod]) =>
    Object.entries(mod)
      .filter(([name, v]) => typeof v === "function" && ROUTED.has(name))
      .map(([name, v]) => ({ path, name, C: v as React.ComponentType })));

describe("every page mounts", () => {
  let errors: string[] = [];
  beforeEach(() => {
    errors = [];
    // React reports render errors through console.error rather than throwing
    // out of render(), so a page that failed would otherwise pass silently.
    vi.spyOn(console, "error").mockImplementation((...a: unknown[]) => {
      errors.push(a.map(String).join(" "));
    });
  });
  afterEach(() => { cleanup(); vi.restoreAllMocks(); });

  it("covers every routed page", () => {
    // Guards the glob AND the list: if either drifts, this file would "pass"
    // while rendering nothing, which is the failure mode of every smoke test
    // that has ever quietly stopped working.
    const found = new Set(pages.map((p) => p.name));
    const missing = [...ROUTED].filter((n) => !found.has(n));
    expect(missing, `not reached by the glob: ${missing.join(", ")}`).toHaveLength(0);
  });

  it.each(pages.map((p) => [`${p.path.replace("./", "")} → ${p.name}`, p] as const))(
    "%s renders without throwing",
    (_label, p) => {
      expect(() => render(<Harness><p.C /></Harness>)).not.toThrow();
      const fatal = errors.filter((e) =>
        /Cannot read (properties|property)|is not a function|is not iterable|undefined is not/.test(e));
      expect(fatal, fatal[0] ?? "").toHaveLength(0);
    },
  );
});
