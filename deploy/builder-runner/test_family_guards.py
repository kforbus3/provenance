"""Every family-specific command in build-image.sh must sit inside a family guard.

Why this exists, in the user's words: "I'm getting tired of finding these one off
issues each time."

build-image.sh builds for two distribution families out of one script. The
failure mode is always the same shape -- a line that is only correct for Debian
runs for AlmaLinux too -- and the feedback loop is a 30-minute image build that
dies on line N, gets fixed, and dies on line N+400 next time. Found serially,
one build per bug, that is days.

They are all findable statically. A line that writes /etc/apt or runs
update-initramfs is wrong for the rpm family no matter what it is doing, unless
it is inside a branch that only the deb family reaches. So this walks the
script's if/else/fi structure, tracks which family each line can execute for,
and fails on any family-specific line that is not guarded.

What it caught the first time it ran, both live bugs, neither reported by any
build yet:
  - /etc/apt/sources.list written for both families (the build dies outright)
  - /etc/initramfs-tools/initramfs.conf appended for both, in a branch where
    the rpm path had already deleted that directory

Escape hatch: a trailing "# family-ok: <reason>" on the line. Use it when a
family-specific token appears somewhere genuinely harmless -- and say why, so
the next person can tell a considered exception from a silenced failure.
"""

import os
import re
import sys

# Tokens that only make sense for one family, as an executed command or a path
# in the target root. Deliberately narrow: a token that also appears in ordinary
# prose or in a package name produces false positives, and a check people learn
# to ignore is worse than no check.
DEB_ONLY = [
    "/etc/apt",
    "apt-get ",
    "apt-mark ",
    "dpkg ",
    "dpkg-divert",
    "debootstrap ",
    "update-initramfs",
    "/etc/initramfs-tools",
    "/etc/cryptsetup-initramfs",
    "debconf-set-selections",
]

RPM_ONLY = [
    "/etc/yum.repos.d",
    "dnf ",
    "dracut ",
    "grub2-install",
    "grub2-mkconfig",
    "rpm --root",
    "rpm -q",
]

# `$GRUB_INSTALL` and friends hold the per-family binary name and are the correct
# way to spell this, so they must not trip anything above.

HEREDOC = re.compile(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?")
FAMILY_EQ = re.compile(r'\$(?:\{)?FAMILY(?:\})?"?\s*(=|!=)\s*"?(deb|rpm)')


def family_of(condition: str):
    """Which family a condition constrains to, or None if it does not."""
    m = FAMILY_EQ.search(condition)
    if not m:
        return None
    op, fam = m.group(1), m.group(2)
    if op == "=":
        return fam
    return "rpm" if fam == "deb" else "deb"


def other(fam):
    if fam is None:
        return None
    return "rpm" if fam == "deb" else "deb"


def scan(path):
    """Yield (lineno, text, active_family) for every executable line.

    active_family is 'deb'/'rpm' when the enclosing guards restrict the line to
    one family, else None.
    """
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    stack = []          # one frame per open `if`: {"fam": .., "orig": ..}
    heredoc_end = None
    out = []

    for i, raw in enumerate(lines, 1):
        # Heredoc bodies are data, not code. They also contain text that looks
        # like shell, so counting `if`/`fi` through them corrupts the stack --
        # which is how a checker like this quietly stops meaning anything.
        if heredoc_end is not None:
            if raw.strip() == heredoc_end:
                heredoc_end = None
            continue

        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue

        active = next((f["fam"] for f in reversed(stack) if f["fam"]), None)
        out.append((i, raw, active))

        h = HEREDOC.search(raw)
        if h:
            heredoc_end = h.group(1)

        # Structure. Order matters: `elif` before `if`, `fi` before everything.
        if re.match(r"^fi\b", stripped):
            if stack:
                stack.pop()
        elif re.match(r"^elif\b", stripped):
            if stack:
                fam = family_of(stripped)
                stack[-1]["fam"] = fam
        elif re.match(r"^else\b", stripped):
            if stack:
                # A two-branch if on the family: the else is the other family.
                # Only when the if itself constrained one, otherwise unknown.
                stack[-1]["fam"] = other(stack[-1]["orig"])
        elif re.match(r"^if\b", stripped):
            fam = family_of(stripped)
            stack.append({"fam": fam, "orig": fam})

    return out


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "..", "..", "builder", "build-image.sh")
    if not os.path.exists(path):
        print(f"  FAIL  build-image.sh not found at {path}")
        return 1

    problems = []
    checked = 0

    for lineno, raw, active in scan(path):
        if "family-ok" in raw:
            continue
        code = raw.split(" #")[0]

        for tok in DEB_ONLY:
            if tok in code:
                checked += 1
                if active != "deb":
                    problems.append((
                        lineno, tok, "deb", active,
                        "runs for the rpm family, which has no such path or command",
                    ))
                break
        else:
            for tok in RPM_ONLY:
                if tok in code:
                    checked += 1
                    if active != "rpm":
                        problems.append((
                            lineno, tok, "rpm", active,
                            "runs for the deb family, which has no such path or command",
                        ))
                    break

    print(f"== family guards in build-image.sh ({checked} family-specific lines) ==")
    if not problems:
        print(f"  PASS  all {checked} are inside a matching family guard")
        return 0

    for lineno, tok, want, active, why in problems:
        where = f"guarded to {active}" if active else "NOT inside any family guard"
        print(f"  FAIL  line {lineno}: {tok!r} is {want}-only but is {where}")
        print(f"        {why}")
    print()
    print(f"FAILED ({len(problems)}) — each of these is a build that dies, or an "
          f"image that is silently wrong, for one of the two families.")
    print("If a line is genuinely fine, append '# family-ok: <reason>'.")
    return 1


def check_state_models():
    """The UI's writable-state values must be ones the builder accepts.

    The dropdown offered "paths"; build-image.sh accepts overlay|stateful|
    appliance and dies on anything else. So the only non-default writable-state
    option in the product failed every build it was used for, and had done since
    it shipped -- while the builder's own `stateful` branch was separately dead
    on an unbound $FAMILY. A user-facing choice whose second branch was never
    built is exactly what this pins.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    sh = os.path.join(here, "..", "..", "builder", "build-image.sh")
    tsx = os.path.join(here, "..", "..", "frontend", "src", "pages", "imaging",
                       "WritableState.tsx")
    if not (os.path.exists(sh) and os.path.exists(tsx)):
        print("  FAIL  cannot find build-image.sh and WritableState.tsx to compare")
        return 1

    body = open(sh, encoding="utf-8").read()
    m = re.search(r"--state-model: unknown model .*?\(expected: ([^)]*)\)", body)
    if not m:
        print("  FAIL  could not find the builder's list of accepted state models")
        return 1
    accepted = {x.strip() for x in m.group(1).split(",") if x.strip()}

    offered = set(re.findall(r'<MenuItem value="([a-z-]+)">', open(tsx, encoding="utf-8").read()))

    bad = offered - accepted
    print(f"== writable-state vocabulary ==")
    print(f"  builder accepts: {sorted(accepted)}")
    print(f"  UI offers:       {sorted(offered)}")
    if bad:
        print(f"  FAIL  the UI offers {sorted(bad)}, which the builder refuses -- "
              f"choosing it fails the build")
        return 1
    print("  PASS  every value the UI offers is one the builder accepts")
    return 0


if __name__ == "__main__":
    sys.exit(main() | check_state_models())
