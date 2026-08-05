#!/usr/bin/env node
// Audit production dependencies, with documented exceptions.
//
// `npm audit --audit-level=high` is the usual way to get a green build, and it
// is the wrong one: it hides every moderate finding to tolerate one, including
// moderates that arrive later and do apply. This fails on anything at moderate
// or above unless it is named in audit-allowlist.json with a reason.
//
// The allowlist is checked in both directions. An entry that no longer matches
// anything is an error, not a convenience: it means the advisory was fixed and
// the exception is now a claim about nothing. An entry past its review date is
// an error too, so "we looked at this once" cannot decay into "nobody has
// looked at this in a year".
//
// Usage: node scripts/audit.mjs [--json]

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const SEVERITY_ORDER = ["info", "low", "moderate", "high", "critical"];
const FAIL_AT = SEVERITY_ORDER.indexOf("moderate");

function runAudit() {
  try {
    // npm audit exits non-zero when it finds anything, which is not an error
    // for our purposes — the report on stdout is what we want either way.
    return execFileSync("npm", ["audit", "--omit=dev", "--json"], {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
    });
  } catch (err) {
    if (err.stdout) return err.stdout;
    throw err;
  }
}

function loadAllowlist() {
  const raw = JSON.parse(readFileSync(join(root, "audit-allowlist.json"), "utf8"));
  return raw.allow ?? [];
}

// findings flattens npm's report into one row per advisory, keeping the
// package it was found through so a message can name it.
function findings(report) {
  const out = [];
  for (const [name, v] of Object.entries(report.vulnerabilities ?? {})) {
    for (const via of v.via ?? []) {
      if (typeof via !== "object") continue; // a string via is a transitive pointer
      out.push({
        package: name,
        id: via.url?.split("/").pop() ?? via.source?.toString() ?? "unknown",
        title: via.title ?? "",
        severity: via.severity ?? v.severity ?? "unknown",
        url: via.url ?? "",
      });
    }
  }
  return out;
}

const report = JSON.parse(runAudit());
const allow = loadAllowlist();
const all = findings(report);

const today = new Date().toISOString().slice(0, 10);
const problems = [];
const excused = [];

for (const f of all) {
  const rule = allow.find((a) => a.id === f.id);
  if (!rule) {
    if (SEVERITY_ORDER.indexOf(f.severity) >= FAIL_AT) problems.push(f);
    continue;
  }
  if (rule.review && rule.review < today) {
    problems.push({ ...f, note: `allowlist entry expired on ${rule.review} — re-assess it` });
    continue;
  }
  excused.push({ ...f, reason: rule.reason });
}

// An exception for something that no longer exists is stale documentation with
// the authority of a security decision. Fail on it.
for (const rule of allow) {
  if (!all.some((f) => f.id === rule.id)) {
    problems.push({
      package: rule.package ?? "?",
      id: rule.id,
      severity: "stale",
      title: "allowlisted advisory no longer reported — remove this entry",
      url: "",
    });
  }
}

for (const e of excused) {
  console.log(`ALLOWED  ${e.severity.padEnd(8)} ${e.package}  ${e.id}`);
  console.log(`         ${e.title}`);
  console.log(`         reason: ${e.reason.slice(0, 160)}${e.reason.length > 160 ? "…" : ""}`);
}

if (problems.length === 0) {
  console.log(`\nOK — ${all.length} advisory/advisories reported, ${excused.length} allowlisted, none unaccounted for.`);
  process.exit(0);
}

console.error("\nUnaccounted-for advisories:\n");
for (const p of problems) {
  console.error(`  ${p.severity.padEnd(8)} ${p.package}  ${p.id}`);
  if (p.title) console.error(`           ${p.title}`);
  if (p.note) console.error(`           ${p.note}`);
  if (p.url) console.error(`           ${p.url}`);
}
console.error(
  "\nFix it, or add it to frontend/audit-allowlist.json with a reason and a review date.",
);
process.exit(1);
