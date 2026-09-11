"""Writable-state option combinations that cannot work must be refused at build time.

The question that produced this check: what happens to a package installed after
imaging, when the machine changes slots?

The honest answer depends on the state model, and two of the three models already
give it at the keyboard -- `stateful` and `appliance` mount the root read-only, so
`dnf install` fails in front of whoever typed it. Only `overlay` accepts the
write and discards it at the next slot change, weeks later, on a machine nobody
is looking at.

That much is by design: with one upper shared by both slots, the package database
would otherwise survive a slot change describing the *other* slot's image, so it
is reset, and the files it no longer accounts for are reset with it. Keeping
either half is worse than losing both -- keep the files and nothing patches them
again, keep the database and every later transaction reasons from a package list
that is not what is installed.

What was not by design is that the build script accepted the arguments that ask
for exactly those broken halves. `--keep-path /usr` cancels the reset of /usr,
so an update installs a new slot whose binaries are never seen and reports
success; `--keep-path /var/lib/rpm` keeps a database describing software that is
not there. Both built cleanly and produced a machine that looks healthy from
every angle except the version it is running.

Three live bugs were found while closing that hole, none of them reported by any
build:

  - `--keep-path` and `--reset-on-update` were parsed into the same variables the
    state model assigns a hundred lines later, so `--state-model stateful
    --keep-path /srv/x` was accepted, stored, and silently thrown away.

  - the family package-database paths were appended ~550 lines below the model
    block rather than inside it, so `stateful` -- which names those three paths
    itself -- shipped a state.conf listing each of them twice, and `appliance`
    got three redundant children of the /var it already resets.

  - `appliance` carried a `keep /etc/cryptsetup-keys.d` that it never reset, so
    the keep protecting LUKS enrollment was a no-op there and absent everywhere
    that *did* reset /etc.

The guards run on the arguments alone, so `--check-only` can exercise them
without root and without building anything.
"""

import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
SCRIPT = os.path.join(ROOT, "builder", "build-image.sh")

failures = []
checks = 0


def check(name, cond, detail=""):
    global checks
    checks += 1
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        if detail:
            for line in detail.strip().splitlines():
                print(f"        {line}")
        failures.append(name)


def run(*args):
    """build-image.sh --check-only with these options."""
    p = subprocess.run(
        ["sh", SCRIPT, "--check-only", *args],
        capture_output=True, text=True, timeout=120,
    )
    out = re.sub(r"\x1b\[[0-9;]*m", "", p.stdout + p.stderr)
    return p.returncode, out


def refused(name, args, because):
    """These options must not build, and the reason must be the one we mean."""
    rc, out = run(*args)
    check(f"refused: {name}", rc != 0 and because in out,
          f"exit={rc}\n{out}" if (rc == 0 or because not in out) else "")


def accepted(name, args):
    rc, out = run(*args)
    check(f"accepted: {name}", rc == 0, f"exit={rc}\n{out}")
    return out


print("== combinations that cannot produce a coherent machine are refused ==")

# The two that motivated all of this. Both are the same failure -- the machine
# goes on serving its own copy of something the update replaced -- reached
# through the keep list instead of through a missing binary.
refused("keeping /usr, which cancels the reset that lets an update be seen",
        ["--distro", "debian", "--keep-path", "/usr"],
        "cancels the reset entirely")
refused("keeping the rpm database, which would then describe the other slot",
        ["--distro", "almalinux", "--suite", "9", "--keep-path", "/var/lib/rpm"],
        "cancels the reset entirely")
refused("keeping the dpkg database",
        ["--distro", "debian", "--keep-path", "/var/lib/dpkg"],
        "cancels the reset entirely")

# A keep outside every reset path is not merely useless. ab-overlay implements a
# keep by moving the path out of the store and back around the clearing, and the
# failing branch of that mv drops it -- so it is a way to lose data that was
# never at risk, described in state.conf as protection.
refused("keeping a path nothing resets (overlay)",
        ["--distro", "debian", "--keep-path", "/opt"],
        "keeps nothing")
refused("keeping /usr/local under stateful, which does not reset /usr",
        ["--distro", "debian", "--state-model", "stateful",
         "--keep-path", "/usr/local"],
        "keeps nothing")

print()
print("== the combinations that do work still build ==")

accepted("the default overlay image", ["--distro", "debian"])
accepted("the default rpm overlay image", ["--distro", "almalinux", "--suite", "9"])
accepted("a carve-out inside a path the operator resets",
         ["--distro", "debian", "--state-model", "stateful",
          "--reset-on-update", "/srv", "--keep-path", "/srv/keepme"])

print()
print("== the operator's path flags reach every model ==")

# The bug: --keep-path appended to KEEP_PATHS during parsing, and `stateful` and
# `appliance` then assigned that variable, discarding it without a word.
for model in ("overlay", "stateful", "appliance"):
    out = accepted(
        f"--reset-on-update /srv survives --state-model {model}",
        ["--distro", "debian", "--state-model", model, "--reset-on-update", "/srv"],
    )
    check(f"  and appears in the {model} manifest",
          "reset-on-update /srv" in out, out)

print()
print("== the default keep is the only one the image does not populate ==")

# /usr/local is kept by default because the FHS reserves it for local
# administration and neither family ships a regular file into it. Verified when
# this was written: `dpkg -S /usr/local` matches no package, and AlmaLinux 9 owns
# 34 paths under it, every one a directory. That property is the whole reason the
# default is safe, so it is asserted rather than assumed.
out = accepted("overlay keeps /usr/local by default", ["--distro", "debian"])
check("the default manifest keeps /usr/local", "keep /usr/local" in out, out)

print()
print("== the package database is listed once, by the model that owns it ==")

for distro, suite, dbpath in (("debian", None, "/var/lib/dpkg"),
                              ("almalinux", "9", "/var/lib/rpm")):
    base = ["--distro", distro] + (["--suite", suite] if suite else [])
    for model in ("overlay", "stateful", "appliance"):
        out = accepted(f"{distro} {model} builds", base + ["--state-model", model])
        n = len([l for l in out.splitlines() if l.strip() == f"reset-on-update {dbpath}"])
        if model == "appliance":
            # /var is reset wholesale; naming children of it again is noise that
            # reads as a considered decision.
            check(f"{distro} {model}: no redundant {dbpath} under the /var reset",
                  n == 0, out)
        else:
            check(f"{distro} {model}: {dbpath} reset exactly once (was twice)",
                  n == 1, out)

print()
print("== resetting /etc on an encrypted image keeps the LUKS enrollment ==")

# The key is written to /etc/cryptsetup-keys.d by enrollment *after* the build,
# so it exists only in the writable layer: a reset of /etc takes it and the
# machine comes up asking for a passphrase nobody is there to type.
out = accepted("appliance, encrypted, resetting /etc",
               ["--distro", "debian", "--state-model", "appliance",
                "--encrypt", "--luks-passphrase", "x",
                "--reset-on-update", "/etc"])
check("the enrollment keep is added automatically",
      "keep /etc/cryptsetup-keys.d" in out, out)

out = accepted("overlay, encrypted, resetting /etc",
               ["--distro", "debian", "--encrypt", "--luks-passphrase", "x",
                "--reset-on-update", "/etc"])
check("and for whichever other model resets /etc",
      "keep /etc/cryptsetup-keys.d" in out, out)

# Unencrypted, there is no enrollment to protect and the keep would be a no-op --
# which the rule above refuses. Adding it unconditionally would fail the build.
out = accepted("unencrypted, resetting /etc",
               ["--distro", "debian", "--reset-on-update", "/etc"])
check("but not on an unencrypted image, where it would keep nothing",
      "keep /etc/cryptsetup-keys.d" not in out, out)

print()
print("== a keep that holds files the image ships is REPORTED, not refused ==")


def shadowing_report(root, keeps):
    """Run build-image.sh's own keep_shadowing_report against a fixture tree.

    Lifted out of the script rather than reimplemented: a second copy of the rule
    would agree with itself while both drifted from what the build actually does.
    """
    src = open(SCRIPT, encoding="utf-8").read()
    m = re.search(r"^keep_shadowing_report\(\) \{.*?^\}", src, re.S | re.M)
    if not m:
        return None
    prog = m.group(0) + '\nkeep_shadowing_report "$@"\n'
    p = subprocess.run(["sh", "-c", prog, "sh", root, *keeps],
                       capture_output=True, text=True, timeout=60)
    return p.stdout.strip()


with tempfile.TemporaryDirectory() as td:
    # A tree shaped like the real thing: /usr/local exists and is empty, the way
    # both families ship it, and /var/lib/dpkg holds a database file.
    os.makedirs(os.path.join(td, "usr/local/bin"))
    os.makedirs(os.path.join(td, "var/lib/dpkg"))
    with open(os.path.join(td, "var/lib/dpkg/status"), "w") as f:
        f.write("Package: base-files\n")

    rep = shadowing_report(td, ["/usr/local"])
    check("extracted keep_shadowing_report from build-image.sh", rep is not None)
    if rep is not None:
        check("an empty /usr/local shadows nothing, so the default passes",
              rep == "", f"got: {rep!r}")

        rep = shadowing_report(td, ["/var/lib/dpkg"])
        check("a keep holding a shipped file is reported",
              "/var/lib/dpkg" in rep, f"got: {rep!r}")

        # It must NOT fail the build. This was a die() and it refused the
        # default image: the builder ships the A/B helper scripts into
        # /usr/local/sbin, and /usr/local is the default keep, so every build
        # stopped with
        #
        #   ERROR: keep path(s) contain files this image ships:
        #          /usr/local(/usr/local/sbin/ab-slot-pending.sh)
        #
        # The reasoning was wrong, not just the threshold. A keep moves the path
        # aside out of the STORE -- the upper -- and puts it back; the image's
        # copy is in the LOWER. A file the image ships at a kept path is shadowed
        # only once the MACHINE writes it, which is not knowable at build time.
        src = open(SCRIPT, encoding="utf-8").read()
        i = src.find("_shadowed=$(keep_shadowing_report")
        check("keep_shadowing_report found in build-image.sh", i != -1)
        if i != -1:
            after = src[i:i + 700]
            check("a shipped file inside a kept path warns rather than dying",
                  "die " not in after and 'warn "' in after, after[:300])

        rep = shadowing_report(td, ["/does/not/exist"])
        check("a keep the image does not create at all is not reported",
              rep == "", f"got: {rep!r}")

print()
print("== encryption options that do nothing are refused too ==")

# Every one of these used to be parsed, stored, and never read: the whole
# encryption validation sat inside `if [ "$ENCRYPT" = true ]`, so without
# --encrypt the flags were silently dropped. --unlock was not even checked for
# being one of the four accepted words.
#
# This is the worst direction for this particular mistake to fail in. An operator
# who asks for TPM unlock and forgets --encrypt got an unencrypted disk and no
# indication the flag had been ignored -- an image *less* protected than the
# command line describes, which is exactly the belief you do not want someone
# holding about a machine they are about to ship somewhere.
refused("--unlock without --encrypt",
        ["--distro", "debian", "--unlock", "tpm2"],
        "has no effect without --encrypt")
refused("--luks-passphrase without --encrypt",
        ["--distro", "debian", "--luks-passphrase", "hunter2"],
        "has no effect without --encrypt")
refused("--tang-url without --encrypt",
        ["--distro", "debian", "--tang-url", "https://tang.example"],
        "has no effect without")

# The default value of --unlock is a real word, so the guard has to distinguish
# "the operator asked for keyfile" from "nobody said anything" -- otherwise it
# would refuse every unencrypted build there is.
accepted("an ordinary unencrypted image, which never mentions unlocking",
         ["--distro", "debian"])

accepted("encrypted with a passphrase-derived keyfile",
         ["--distro", "debian", "--encrypt", "--luks-passphrase", "x"])
accepted("encrypted with TPM unlock",
         ["--distro", "debian", "--encrypt", "--luks-passphrase", "x",
          "--unlock", "tpm2"])
refused("tang unlock with no server to ask",
        ["--distro", "debian", "--encrypt", "--luks-passphrase", "x",
         "--unlock", "tang"],
        "requires --tang-url")
refused("an unlock method that does not exist",
        ["--distro", "debian", "--encrypt", "--luks-passphrase", "x",
         "--unlock", "magic"],
        "must be passphrase|keyfile|tpm2|tang")

# An option that belongs to one unlock method and was given with another. Both
# of these were read only on the branch that matches their method, so the value
# was silently dropped -- and on flags whose job is to narrow what can open the
# disk, a silent drop loosens exactly what the operator was tightening.
refused("--tpm2-pcrs with a non-TPM unlock method",
        ["--distro", "debian", "--encrypt", "--luks-passphrase", "x",
         "--tpm2-pcrs", "0,7"],
        "only applies to --unlock tpm2")
refused("--tpm2-pcrs with no encryption at all",
        ["--distro", "debian", "--tpm2-pcrs", "0,7"],
        "has no effect without")
refused("--tang-url with TPM unlock",
        ["--distro", "debian", "--encrypt", "--luks-passphrase", "x",
         "--unlock", "tpm2", "--tang-url", "https://tang.example"],
        "only applies to --unlock tang")
accepted("--tpm2-pcrs with the method it belongs to",
         ["--distro", "debian", "--encrypt", "--luks-passphrase", "x",
          "--unlock", "tpm2", "--tpm2-pcrs", "0,7"])
accepted("--tang-url with the method it belongs to",
         ["--distro", "debian", "--encrypt", "--luks-passphrase", "x",
          "--unlock", "tang", "--tang-url", "https://tang.example"])

# The passphrase also has an environment form, which the imaging sidecar uses
# instead of the flag -- it sets LUKS_PASS in the builder container's env and
# passes --encrypt without --luks-passphrase. So the "no effect" guard keys on
# the flag having been given, not on the variable being non-empty: keying on the
# value would refuse every encrypted build the UI runs, and every unencrypted one
# that happened to inherit the variable from the sidecar's own environment.
rc, out = subprocess.run(
    ["sh", SCRIPT, "--check-only", "--distro", "debian", "--encrypt"],
    capture_output=True, text=True, env={**os.environ, "LUKS_PASS": "from-env"},
    timeout=120,
).returncode, ""
check("LUKS_PASS from the environment still satisfies --encrypt", rc == 0)

rc = subprocess.run(
    ["sh", SCRIPT, "--check-only", "--distro", "debian"],
    capture_output=True, text=True, env={**os.environ, "LUKS_PASS": "from-env"},
    timeout=120,
).returncode
check("an inherited LUKS_PASS does not refuse an unencrypted build", rc == 0)

print()
print("== the dialog's copy of the reset lists matches the builder's ==")

# The build dialog refuses these combinations in the moment rather than after a
# thirty-minute build, which needs a copy of what each model resets. A copy that
# drifts is worse than no copy: it would refuse a combination the builder accepts,
# or accept one it refuses, and either way the dialog would be lying about a
# property of the image that cannot be changed afterwards.
#
# So the copy is checked against the builder itself -- not against a list written
# down here, which would be a third copy to drift.
TS = os.path.join(ROOT, "frontend/src/pages/imaging/writable-state.ts")

ts_src = open(TS, encoding="utf-8").read()
m = re.search(r"MODEL_RESET_PATHS: Record<string, string\[\]> = \{(.*?)^\};",
              ts_src, re.S | re.M)
check("found MODEL_RESET_PATHS in writable-state.ts", m is not None)

if m:
    ts_table = {}
    for mm in re.finditer(r"(\w+):\s*\[(.*?)\]", m.group(1), re.S):
        ts_table[mm.group(1)] = set(re.findall(r'"([^"]+)"', mm.group(2)))

    for model in ("overlay", "stateful", "appliance"):
        # Ask the builder what it resets, for both families, since the dialog
        # does not know which distribution is selected and lists both.
        from_builder = set()
        for distro, suite in (("debian", None), ("almalinux", "9")):
            base = ["--distro", distro] + (["--suite", suite] if suite else [])
            rc, out = run(*base, "--state-model", model)
            if rc != 0:
                check(f"builder reports {model} resets for {distro}", False, out)
                continue
            for line in out.splitlines():
                if line.startswith("reset-on-update "):
                    from_builder.add(line.split(None, 1)[1].strip())

        ours = ts_table.get(model, set())
        check(f"{model}: the dialog lists exactly what the builder resets",
              ours == from_builder,
              f"dialog has:  {sorted(ours)}\n"
              f"builder has: {sorted(from_builder)}\n"
              f"only in dialog:  {sorted(ours - from_builder)}\n"
              f"only in builder: {sorted(from_builder - ours)}")

print()
if failures:
    print(f"FAILED ({len(failures)})")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print(f"all {checks} writable-state guard checks passed")
