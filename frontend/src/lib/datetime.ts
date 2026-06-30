// Central date/time formatting. Every timestamp in the UI goes through these
// helpers so a single configured display timezone applies app-wide. The zone is
// a module singleton set once at app load (see AppLayout); when empty, the
// browser's local zone is used.

let displayTz: string | undefined;

/** Set the app-wide display timezone (IANA name; falsy = browser local). */
export function setDisplayTimezone(tz?: string | null) {
  displayTz = tz || undefined;
}

/** The configured display timezone, or undefined for browser-local. */
export function getDisplayTimezone(): string | undefined {
  return displayTz;
}

function parse(value?: string | null): Date | null {
  if (!value) return null;
  const d = new Date(value);
  return isNaN(d.getTime()) ? null : d;
}

function opts(extra?: Intl.DateTimeFormatOptions): Intl.DateTimeFormatOptions {
  return { timeZone: displayTz, ...extra };
}

/** Date + time, e.g. "6/29/2026, 9:22:25 PM". */
export function formatDateTime(value?: string | null, extra?: Intl.DateTimeFormatOptions, empty = "—"): string {
  const d = parse(value);
  return d ? d.toLocaleString(undefined, opts(extra)) : empty;
}

/** Date only. */
export function formatDate(value?: string | null, empty = "—"): string {
  const d = parse(value);
  return d ? d.toLocaleDateString(undefined, opts()) : empty;
}

/** Time only. */
export function formatTime(value?: string | null, empty = "—"): string {
  const d = parse(value);
  return d ? d.toLocaleTimeString(undefined, opts()) : empty;
}

/** The list of IANA timezones for a picker (falls back to a small set). */
export function supportedTimezones(): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (k: string) => string[] };
  if (typeof intl.supportedValuesOf === "function") {
    try {
      return intl.supportedValuesOf("timeZone");
    } catch {
      /* fall through */
    }
  }
  return [
    "UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
    "Europe/London", "Europe/Paris", "Europe/Berlin", "Asia/Tokyo", "Australia/Sydney",
  ];
}

/** Best guess of the browser's own timezone, for display as the default. */
export function browserTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}
