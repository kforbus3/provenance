"""The failure a machine reports must be the failure, not the advice about it.

An A/B update failed on a real machine and the rollout recorded:

    also failed, check free space in /var/tmp and that the server

That is the third line of a four-line explanation, cut off mid-sentence, about a
problem the machine did not have. The actual error was five lines higher in the
same output:

    LastError: Failed mounting bundle: Failed to open /dev/mapper/control

Two separate mistakes produced it, and each is worth its own check.

ab-agent picked the error with `grep -iE 'error|failed' | tail -1`. ab-update
prints human-facing advice AFTER the error it is advising about, and every line of
that advice contains "failed", so the LAST match was always a fragment of the
advice. The rule has to prefer RAUC's own LastError line, and otherwise the FIRST
match.

And ab-update's advice was wrong: it matched the device-mapper failure with its
"dm table|verity|nbd|mounting bundle|streaming" branch and called it a streaming
problem, sending the operator to check free space -- which was fine -- while
ruling out the real cause in the same sentence. The specific case has to be
checked before the general one.
"""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OVERLAY = os.path.join(HERE, "..", "..", "builder", "overlay", "usr", "local", "sbin")
AGENT = os.path.join(OVERLAY, "ab-agent.sh")
UPDATE = os.path.join(OVERLAY, "ab-update.sh")

failures = []
checks = 0


def check(name, cond):
    global checks
    checks += 1
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        failures.append(name)


# The real output, verbatim, that produced the bad report.
REAL_OUTPUT = """installing
  0% Installing
 20% Verifying signature done.
 30% Checking manifest contents done.
100% Installing failed.
LastError: Failed mounting bundle: Failed to open /dev/mapper/control: No such file or directory
Installing `http://192.168.50.1/bundles/x.raucb` failed
  This is a streaming problem, not a problem with the bundle. The
  download-and-install retry above should have avoided it; if that
  also failed, check free space in /var/tmp and that the server
  serves the whole file."""


def sh(script, arg):
    # sh, not bash: the imaging-test target runs this on python:3.13-alpine, which
    # has busybox and no bash. The rules under test are POSIX anyway -- printf,
    # grep, head, tail -- and running them under the shell the image actually has
    # is closer to the machine than running them under one it does not.
    return subprocess.run(["sh", "-c", script, "_", arg],
                          capture_output=True, text=True).stdout.strip()


print("== the reported error is the error, not the advice ==")

if not (os.path.exists(AGENT) and os.path.exists(UPDATE)):
    check("the A/B scripts are where this test expects them "
          "(mount the repo root, not deploy/builder-runner)", False)
    print(f"\n{checks - len(failures)} passed, {len(failures)} failed")
    sys.exit(1)

agent = open(AGENT, encoding="utf-8").read()

# Comments stripped before looking for the old rule. The fix quotes the rule it
# replaced, in order to explain it, and a check that cannot tell an explanation
# from the code fails on the comment that documents the fix -- which is how the
# spelling checker in this suite ends up unable to name the word it forbids.
code = "\n".join(
    ln for ln in agent.splitlines() if not ln.lstrip().startswith("#"))

# The rule that produced the bad report must be gone from the code.
check("the error is no longer taken from the LAST matching line",
      not re.search(r"grep -iE '?error\|failed'? \| tail -1", code))
check("RAUC's own LastError is preferred", "LastError:" in agent)

# And the rule in the script must actually pick the right line out of the real
# output. Extracted and run rather than eyeballed: a rule that reads correctly and
# selects the wrong line is exactly what shipped.
first = sh('printf "%s\\n" "$1" | grep -oiE "LastError:.*" | head -1', REAL_OUTPUT)
check("it selects the mount failure from the real output",
      "Failed mounting bundle" in first and "/dev/mapper/control" in first)
check("it does not select the advice", "free space" not in first)

# The old rule, for contrast: if this ever stops being wrong the bug was not real.
old = sh('printf "%s\\n" "$1" | grep -iE "error|failed" | tail -1', REAL_OUTPUT)
check("the old rule really did select the advice (the bug was real)",
      "free space" in old)

print("== a missing device-mapper is diagnosed as itself ==")

update = open(UPDATE, encoding="utf-8").read()

i_dm = update.find("/dev/mapper/control|load dm table")
i_stream = update.find("dm table|verity|nbd|mounting bundle|streaming")
check("there is a branch for the device-mapper errors", i_dm != -1)
check("it is checked BEFORE the streaming branch that also matches them",
      i_dm != -1 and i_stream != -1 and i_dm < i_stream)
check("it names the modules to load", "dm_mod dm_verity" in update)
check("it says the bundle is not the problem",
      "signature verified before this failed" in update
      or "bundle is fine" in update)

print(f"\n{checks - len(failures)} passed, {len(failures)} failed")
sys.exit(1 if failures else 0)
