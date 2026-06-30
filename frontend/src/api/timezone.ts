import { api } from "./client";

// The display timezone is a system-wide setting that controls how every
// timestamp in the UI is rendered (and how schedule clock-times are interpreted
// on the server). Empty means "use the browser's local zone".

export async function getTimezone(): Promise<string> {
  const { data } = await api.get<{ timezone: string }>("/api/v1/timezone");
  return data.timezone ?? "";
}

export async function saveTimezone(timezone: string): Promise<void> {
  await api.put("/api/v1/timezone", { timezone });
}
