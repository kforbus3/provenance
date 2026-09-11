"""The product spells it "enroll", everywhere.

Enrollment is this product's central verb: the Go package is `enrollment`, the
route is POST /hosts/{id}/enroll, the permission is Host.Enroll, and the code
uses the US spelling 327 times against 5 of the British one. So `enrol`,
`enrols` and `enrolment` are simply wrong here, however correct they are in
other prose.

They slipped in anyway — including into the v1.0.0 release notes, on the line
describing what the product does — and they are unusually hard to notice two
ways round.

A spell-checker will not flag them: both spellings are real words, and running
aspell over the release notes returned two dozen legitimate coinages (rauc,
goroutine, allowlist, LUKS) with nothing to separate a genuine error from the
noise.

And checking the obvious way does not work either. Counting "enrolled" — 77
occurrences — looks like decisive evidence of the convention and proves nothing,
because "enrolled" is spelled identically in both dialects. The forms that
actually differ are the ones below, and they are the only ones worth counting.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))

# Generated from docs/ and rebuilt, so fixing the source fixes these.
# This file necessarily contains the words it looks for, in its pattern and in
# the explanation of why they are wrong.
SKIP_FILES = {"docs_generated.go", "help-content.ts", "test_spelling.py"}
SKIP_DIRS = {".git", "node_modules", "output", "dist", "vendor"}

WRONG = re.compile(r"\b(enrol|enrols|enrolment|enrolments)\b", re.I)

hits = []
for base in ("docs", "backend", "frontend/src", "server", "builder", "deploy"):
    for dirpath, dirs, files in os.walk(os.path.join(ROOT, base)):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f in SKIP_FILES or not f.endswith((".md", ".go", ".ts", ".tsx", ".sh", ".py")):
                continue
            path = os.path.join(dirpath, f)
            try:
                for i, line in enumerate(open(path, encoding="utf-8", errors="ignore"), 1):
                    if WRONG.search(line):
                        hits.append((os.path.relpath(path, ROOT), i, line.strip()[:90]))
            except OSError:
                pass
for p in (os.path.join(ROOT, "README.md"), os.path.join(ROOT, "CONTRIBUTING.md")):
    if os.path.exists(p):
        for i, line in enumerate(open(p, encoding="utf-8"), 1):
            if WRONG.search(line):
                hits.append((os.path.basename(p), i, line.strip()[:90]))

print('== the product spells it "enroll" ==')
if hits:
    print(f"  FAIL  {len(hits)} British spelling(s) of the product's central verb:")
    for f, i, line in hits[:12]:
        print(f"          {f}:{i}  {line}")
    if len(hits) > 12:
        print(f"          … and {len(hits) - 12} more")
    print('        Use enroll / enrolls / enrollment. The package, the route')
    print("        (/hosts/{id}/enroll) and the permission (Host.Enroll) all do.")
    sys.exit(1)
print("  PASS  no enrol / enrols / enrolment")
print()
print("all 1 spelling checks passed")
