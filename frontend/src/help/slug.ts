// Heading -> anchor id. MUST match scripts/build-help.mjs slugify exactly so that
// search/TOC anchors line up with the ids the Markdown renderer assigns to headings.
export function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/`/g, "")
    .replace(/[^\w\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-");
}
