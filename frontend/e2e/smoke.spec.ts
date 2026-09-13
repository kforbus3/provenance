import { test, expect } from "@playwright/test";

const USER = process.env.E2E_USER ?? "e2euser";
const PASS = process.env.E2E_PASS ?? "E2e-Pass-12345!";

// Core journey: the app loads, an existing user signs in, the dashboard renders,
// and the host inventory is reachable — i.e. "see hosts and connect" works.
test("sign in and reach the host inventory", async ({ page }) => {
  await page.goto("/");

  // Unauthenticated visitors are routed to the sign-in form (users already exist).
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();

  await page.getByLabel("Username").fill(USER);
  await page.getByLabel("Password").fill(PASS);
  await page.getByRole("button", { name: "Sign in" }).click();

  // Landing dashboard.
  await expect(page.getByRole("heading", { name: "Provenance Overview" })).toBeVisible();

  // Navigate to the host inventory via the side nav.
  await page.getByText("Hosts", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Host Inventory" })).toBeVisible();
});

test("unauthenticated access redirects to login", async ({ page }) => {
  await page.goto("/audit");
  await expect(page).toHaveURL(/\/login$/);
});
