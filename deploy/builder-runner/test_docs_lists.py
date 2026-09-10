"""The assistant and the in-app help must cover the same documentation.

gendocs.go's own comment has always said its list "must match
frontend/scripts/build-help.mjs". It did not. gendocs had 12 entries, build-help
had 20, and imaging.md was in NEITHER — so the in-app Help had no imaging page
and "Ask Provenance" could not answer a single question about images, rollouts,
LUKS or A/B updates. Half the product, invisible in both places a user asks.

Nothing catches that. Both generators run cleanly over whatever list they are
given; a doc that is missing from both is simply never mentioned, and the only
symptom is a help page that does not exist and an assistant that says it does not
know.

A comment saying two lists must match is not a mechanism for making them match.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
HELP = os.path.join(ROOT, "frontend/scripts/build-help.mjs")
GEN = os.path.join(ROOT, "backend/internal/assistant/gendocs.go")
DOCS = os.path.join(ROOT, "docs")

failures = []
checks = 0


def check(name, cond, detail=""):
    global checks
    checks += 1
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        if detail:
            print(detail)
        failures.append(name)


print("== the assistant and the in-app help cover the same docs ==")

if not (os.path.exists(HELP) and os.path.exists(GEN)):
    check("both generators are present", False)
else:
    help_docs = set(re.findall(r'\{\s*file:\s*"([^"]+)"', open(HELP, encoding="utf-8").read()))
    gen_src = open(GEN, encoding="utf-8").read()
    block = re.search(r"var curated = \[\]struct\{ File, Title string \}\{(.*?)\n\}", gen_src, re.S)
    gen_docs = set(re.findall(r'"([^"]+\.md)"', block.group(1))) if block else set()

    check("found both lists", bool(help_docs) and bool(gen_docs),
          f"        parsed help={len(help_docs)} assistant={len(gen_docs)}; if either "
          "declaration changed shape, fix this check rather than deleting it.")

    only_help = sorted(help_docs - gen_docs)
    only_gen = sorted(gen_docs - help_docs)
    detail = ""
    if only_help:
        detail += "        in the in-app help but not the assistant: " + ", ".join(only_help) + "\n"
    if only_gen:
        detail += "        in the assistant but not the in-app help: " + ", ".join(only_gen) + "\n"
    check("the two lists are identical", not only_help and not only_gen, detail)

    # Every listed doc must exist, or a generator silently emits nothing for it.
    missing = sorted(d for d in help_docs | gen_docs if not os.path.exists(os.path.join(DOCS, d)))
    check("every listed doc exists in docs/", not missing,
          "        listed but absent: " + ", ".join(missing) if missing else "")

    # The one that started this. Imaging is half the product; a user asking about
    # a rollout should not be told there is no documentation.
    check("imaging.md is covered", "imaging.md" in help_docs and "imaging.md" in gen_docs,
          "        Imaging is half of what this product does. Leaving it out means "
          "the Help page has no imaging section and the assistant cannot answer "
          "anything about images, rollouts, LUKS or A/B updates.")

print()
if failures:
    print(f"FAILED ({len(failures)})")
    sys.exit(1)
print(f"all {checks} documentation-coverage checks passed")
