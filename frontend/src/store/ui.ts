import { create } from "zustand";
import { persist } from "zustand/middleware";

type Mode = "light" | "dark";

interface UIState {
  mode: Mode;
  toggleMode: () => void;
  setMode: (m: Mode) => void;
  sidebarOpen: boolean;
  toggleSidebar: () => void;
  setSidebarOpen: (open: boolean) => void;
  // siteScope: when set (a federation site id), the whole UI operates against
  // that remote site — API calls are transparently proxied through the hub.
  // null = the hub itself. Persisted so terminal/file tabs inherit it.
  siteScope: string | null;
  setSiteScope: (id: string | null) => void;
}

// currentSiteScope exposes the persisted scope to non-React code (the axios
// interceptor) without importing the React store hook there.
export function currentSiteScope(): string | null {
  return useUIStore.getState().siteScope;
}

// Persisted UI preferences (theme mode, sidebar visibility). Survives reloads
// via localStorage.
export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      mode: "dark",
      toggleMode: () => set((s) => ({ mode: s.mode === "dark" ? "light" : "dark" })),
      setMode: (m) => set({ mode: m }),
      sidebarOpen: true,
      toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),
      setSidebarOpen: (open) => set({ sidebarOpen: open }),
      siteScope: null,
      setSiteScope: (id) => set({ siteScope: id }),
    }),
    { name: "fleet-ui" },
  ),
);
