// Generates a single self-contained offline .guac recording player at
// public/guac-player.html by inlining guacamole-common-js into the template. Run via
// `npm run build:guac-player` after upgrading guacamole-common-js.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const libPath = join(here, "..", "node_modules", "guacamole-common-js", "dist", "esm", "guacamole-common.js");
const templatePath = join(here, "guac-player.template.html");
const outPath = join(here, "..", "public", "guac-player.html");

// The ESM build is a plain script defining a global `Guacamole`, plus a single trailing
// `export default Guacamole;`. Strip that one line so it runs as a classic <script>.
let lib = readFileSync(libPath, "utf8");
const before = lib.length;
lib = lib.replace(/\n?export default Guacamole;\s*$/m, "\n/* export stripped for standalone use */\n");
if (lib.length === before) {
  console.error("WARNING: did not find `export default Guacamole;` to strip — library format may have changed.");
}
if (lib.includes("</script")) {
  throw new Error("guacamole-common-js contains a literal </script — cannot inline safely.");
}

const template = readFileSync(templatePath, "utf8");
if (!template.includes("/*__GUACAMOLE_LIB__*/")) {
  throw new Error("template is missing the /*__GUACAMOLE_LIB__*/ placeholder");
}
// Function replacer so `$` sequences in the library aren't treated as replacement patterns.
const html = template.replace("/*__GUACAMOLE_LIB__*/", () => lib);

writeFileSync(outPath, html);
console.log(`wrote ${outPath} (${(html.length / 1024).toFixed(0)} KiB)`);
