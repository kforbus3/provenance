// Handing a blob to the browser as a file.
//
// This existed twelve times: create an object URL, make an anchor, set
// `download`, append it, click it, remove it, revoke the URL. Four of those
// copies also re-implemented the same Content-Disposition filename regex.
//
// None of them were wrong, which is the point — the risk is not that one copy
// has a bug today, it is that the sequence has an easy-to-miss step. Revoking
// the object URL is the one people drop, and dropping it leaks the whole blob
// for the life of the page: on a page that exports a few large SBOMs or
// recordings, that is the tab's memory.

/** filenameFrom reads the server's chosen filename out of a Content-Disposition
 * header, falling back to a caller-supplied name.
 *
 * The server is the better source: it knows the report's real date range and
 * the host's real name. The fallback covers a proxy that strips the header. */
export function filenameFrom(contentDisposition: string | undefined, fallback: string): string {
  return (contentDisposition ?? "").match(/filename="?([^"]+)"?/)?.[1] || fallback;
}

/** saveBlob prompts the browser to save `blob` as `filename`. */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Always, and not only on the happy path: the blob stays in memory until it
  // is revoked, however the click went.
  URL.revokeObjectURL(url);
}

/** saveResponse saves an axios blob response, preferring the filename the
 * server sent over the fallback. */
export function saveResponse(
  data: BlobPart,
  type: string,
  headers: Record<string, unknown>,
  fallback: string,
): void {
  saveBlob(new Blob([data], { type }),
    filenameFrom(headers["content-disposition"] as string | undefined, fallback));
}
