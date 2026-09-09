// Shared display formatting.

/** formatBytes renders a byte count as B/KB/MB/GB/TB.
 *
 * This was three byte-identical copies, in RdpRecordingsPanel, SessionsPage and
 * FilesPage — all showing the size of the same kind of thing (a recording, a
 * transfer, a file), so they must agree.
 *
 * Two other byte formatters in the tree are deliberately NOT folded in here:
 * AssistantPage rounds to one decimal only below 10, and SettingsPage renders
 * KB below a megabyte and MB above. Both put different text on screen, and
 * unifying them would be a change to what the user sees dressed up as a
 * cleanup. */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${units[i]}`;
}
