import { createElement, useEffect, useMemo, useState, type ReactNode } from "react";
import { Link as RouterLink, useNavigate, useParams, useLocation } from "react-router-dom";
import {
  Box, InputAdornment, Link as MuiLink, List, ListItemButton, ListItemText, ListSubheader,
  Paper, TextField, Typography,
} from "@mui/material";
import SearchIcon from "@mui/icons-material/Search";
import ClearIcon from "@mui/icons-material/Clear";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { helpDocs } from "../help/help-content";
import { searchHelp } from "../help/search";
import { slugify } from "../help/slug";

const byCategory = (() => {
  const cats = new Map<string, typeof helpDocs>();
  for (const d of [...helpDocs].sort((a, b) => a.order - b.order)) {
    if (!cats.has(d.category)) cats.set(d.category, []);
    cats.get(d.category)!.push(d);
  }
  return [...cats.entries()];
})();

function nodeText(children: ReactNode): string {
  if (typeof children === "string") return children;
  if (Array.isArray(children)) return children.map(nodeText).join("");
  if (children && typeof children === "object" && "props" in children) {
    return nodeText((children as { props: { children?: ReactNode } }).props.children);
  }
  return "";
}

// In-app help browser: sidebar of guides + full-text section search + rendered
// Markdown with anchored, deep-linkable headings.
export function HelpPage() {
  const { slug } = useParams<{ slug?: string }>();
  const navigate = useNavigate();
  const { hash } = useLocation();
  const [query, setQuery] = useState("");

  const doc = useMemo(
    () => helpDocs.find((d) => d.slug === slug) ?? [...helpDocs].sort((a, b) => a.order - b.order)[0],
    [slug],
  );
  const results = useMemo(() => searchHelp(query), [query]);
  const searching = query.trim().length >= 2;

  // Scroll to the anchored heading on load / navigation.
  useEffect(() => {
    if (searching) return;
    const id = hash ? decodeURIComponent(hash.slice(1)) : "";
    const scroll = () => {
      if (id) document.getElementById(id)?.scrollIntoView?.({ behavior: "smooth" });
      else document.getElementById("help-content-top")?.scrollIntoView?.();
    };
    const t = setTimeout(scroll, 50); // let Markdown render first
    return () => clearTimeout(t);
  }, [doc, hash, searching]);

  const mdComponents = useMemo(() => {
    const heading = (tag: string) => (props: { children?: ReactNode }) =>
      createElement(tag, { id: slugify(nodeText(props.children)) }, props.children);
    return {
      h1: heading("h1"), h2: heading("h2"), h3: heading("h3"),
      h4: heading("h4"), h5: heading("h5"), h6: heading("h6"),
      a: ({ href, children }: { href?: string; children?: ReactNode }) => {
        if (href?.startsWith("/help")) return <MuiLink component={RouterLink} to={href}>{children}</MuiLink>;
        if (href?.startsWith("#")) {
          return (
            <MuiLink component="button" type="button" sx={{ verticalAlign: "baseline" }}
              onClick={() => document.getElementById(decodeURIComponent(href.slice(1)))?.scrollIntoView?.({ behavior: "smooth" })}>
              {children}
            </MuiLink>
          );
        }
        return <MuiLink href={href} target="_blank" rel="noopener noreferrer">{children}</MuiLink>;
      },
    };
  }, []);

  return (
    <Box sx={{ display: "flex", height: "calc(100vh - 112px)", gap: 2 }}>
      {/* Sidebar: search + guide list */}
      <Paper variant="outlined" sx={{ width: 280, flexShrink: 0, overflowY: "auto", display: "flex", flexDirection: "column" }}>
        <Box sx={{ p: 1.5, position: "sticky", top: 0, bgcolor: "background.paper", zIndex: 1 }}>
          <TextField
            fullWidth size="small" placeholder="Search help…" value={query}
            onChange={(e) => setQuery(e.target.value)}
            InputProps={{
              startAdornment: <InputAdornment position="start"><SearchIcon fontSize="small" /></InputAdornment>,
              endAdornment: query ? (
                <InputAdornment position="end">
                  <ClearIcon fontSize="small" sx={{ cursor: "pointer" }} onClick={() => setQuery("")} />
                </InputAdornment>
              ) : null,
            }}
          />
        </Box>
        <List dense sx={{ pt: 0 }}>
          {byCategory.map(([cat, docs]) => (
            <li key={cat}>
              <ul style={{ padding: 0 }}>
                <ListSubheader disableSticky sx={{ lineHeight: "2rem" }}>{cat}</ListSubheader>
                {docs.map((d) => (
                  <ListItemButton key={d.slug} selected={!searching && d.slug === doc.slug}
                    onClick={() => { setQuery(""); navigate(`/help/${d.slug}`); }}>
                    <ListItemText primary={d.title} />
                  </ListItemButton>
                ))}
              </ul>
            </li>
          ))}
        </List>
      </Paper>

      {/* Content or search results */}
      <Paper variant="outlined" sx={{ flexGrow: 1, overflowY: "auto", p: { xs: 2, md: 4 } }}>
        {searching ? (
          <Box sx={{ maxWidth: 760 }}>
            <Typography variant="h6" sx={{ mb: 1 }}>
              {results.length} result{results.length === 1 ? "" : "s"} for “{query.trim()}”
            </Typography>
            {results.map((r, i) => (
              <Box key={`${r.slug}-${r.anchor}-${i}`} sx={{ mb: 2 }}>
                <MuiLink component="button" type="button" sx={{ textAlign: "left", display: "block" }}
                  onClick={() => { setQuery(""); navigate(`/help/${r.slug}#${r.anchor}`); }}>
                  <Typography variant="subtitle2" component="span">{r.heading}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>· {r.docTitle}</Typography>
                </MuiLink>
                <Typography variant="body2" color="text.secondary">{r.snippet}</Typography>
              </Box>
            ))}
            {results.length === 0 && <Typography color="text.secondary">No matches.</Typography>}
          </Box>
        ) : (
          <Box id="help-content-top" sx={{ maxWidth: 820, "& > :first-of-type": { mt: 0 }, ...mdSx }}>
            <Markdown remarkPlugins={[remarkGfm]} components={mdComponents}>{doc.markdown}</Markdown>
          </Box>
        )}
      </Paper>
    </Box>
  );
}

const mdSx = {
  "& h1": { fontSize: "1.7rem", mt: 3, mb: 1.5, scrollMarginTop: "12px" },
  "& h2": { fontSize: "1.35rem", mt: 3, mb: 1, pb: 0.5, borderBottom: 1, borderColor: "divider", scrollMarginTop: "12px" },
  "& h3": { fontSize: "1.12rem", mt: 2.5, mb: 0.5, scrollMarginTop: "12px" },
  "& h4": { fontSize: "1rem", mt: 2, mb: 0.5, scrollMarginTop: "12px" },
  "& p": { lineHeight: 1.7, my: 1.25 },
  "& ul, & ol": { pl: 3, my: 1 },
  "& li": { my: 0.5, lineHeight: 1.6 },
  "& code": { fontFamily: "monospace", bgcolor: "action.hover", px: 0.5, py: 0.1, borderRadius: 0.5, fontSize: "0.88em" },
  "& pre": { bgcolor: "action.hover", p: 1.5, borderRadius: 1, overflowX: "auto", my: 1.5 },
  "& pre code": { bgcolor: "transparent", p: 0, fontSize: "0.85em" },
  "& table": { borderCollapse: "collapse", my: 1.5, display: "block", overflowX: "auto", width: "max-content", maxWidth: "100%" },
  "& th, & td": { border: 1, borderColor: "divider", px: 1, py: 0.5, textAlign: "left", verticalAlign: "top", fontSize: "0.9rem" },
  "& th": { bgcolor: "action.hover" },
  "& blockquote": { borderLeft: 4, borderColor: "warning.light", pl: 2, ml: 0, my: 1.5, color: "text.secondary" },
  "& hr": { border: 0, borderTop: 1, borderColor: "divider", my: 2 },
  "& a": { color: "primary.main" },
} as const;
