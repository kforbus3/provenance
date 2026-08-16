import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { getVersion } from "./client";

// Default brand name; matches the backend fallback when no branding is set.
export const DEFAULT_APP_NAME = "Moorgate";

// useAppName returns the configured application/brand name. It reads the public
// /version endpoint (also used by the dashboard), so it works pre-auth on the
// login and bootstrap screens and shares one cache entry app-wide.
export function useAppName(): string {
  const { data } = useQuery({ queryKey: ["version"], queryFn: getVersion, staleTime: 60_000 });
  return data?.appName?.trim() || DEFAULT_APP_NAME;
}

// useDocumentTitle keeps the browser tab title in sync with the brand name.
// Pass a page prefix (e.g. a hostname) to render "<prefix> — <appName>".
export function useDocumentTitle(prefix?: string): void {
  const appName = useAppName();
  useEffect(() => {
    document.title = prefix ? `${prefix} — ${appName}` : appName;
  }, [prefix, appName]);
}
