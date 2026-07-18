import { helpDocs } from "./help-content";

export interface SearchResult {
  slug: string;
  docTitle: string;
  heading: string;
  anchor: string;
  snippet: string;
  score: number;
}

// Flatten every doc section into a search index once, at module load.
const index = helpDocs.flatMap((d) =>
  d.sections.map((s) => ({
    slug: d.slug,
    docTitle: d.title,
    heading: s.heading,
    anchor: s.anchor,
    text: s.text,
    hay: (d.title + " " + s.heading + " " + s.text).toLowerCase(),
  })),
);

// searchHelp ranks sections: a match must contain every query token somewhere;
// heading and title hits weigh more than body hits.
export function searchHelp(query: string): SearchResult[] {
  const q = query.trim().toLowerCase();
  if (q.length < 2) return [];
  const tokens = q.split(/\s+/).filter(Boolean);
  const out: SearchResult[] = [];
  for (const e of index) {
    let score = 0;
    let all = true;
    for (const t of tokens) {
      if (!e.hay.includes(t)) {
        all = false;
        break;
      }
      if (e.heading.toLowerCase().includes(t)) score += 5;
      if (e.docTitle.toLowerCase().includes(t)) score += 2;
      score += 1;
    }
    if (!all) continue;
    const pos = e.text.toLowerCase().indexOf(tokens[0]);
    let snippet: string;
    if (pos >= 0) {
      const start = Math.max(0, pos - 40);
      snippet = (start > 0 ? "…" : "") + e.text.slice(start, start + 180).trim() + "…";
    } else {
      snippet = e.text.slice(0, 180).trim() + "…";
    }
    out.push({ slug: e.slug, docTitle: e.docTitle, heading: e.heading, anchor: e.anchor, snippet, score });
  }
  return out.sort((a, b) => b.score - a.score).slice(0, 40);
}
