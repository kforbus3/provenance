"""--image-size is GiB, and nothing refused a value meant as MiB.

build-image.sh documents GiB and has a "too small" check. It has nothing at the
other end, so `image_size: "6144"` -- six gigabytes in anyone's head -- was
accepted as 6144 GiB on a volume with 17 GiB free. The build created a 6 TiB
sparse file, debootstrapped into it, built both slots, wrote the SBOM and reached
step 15 of 16 before starting to compress, at which point zstd began reading six
terabytes of mostly zeros and the build looked hung.

Sparseness is why nothing failed earlier: the blocks were not there yet. The
apparent size is still what compression reads, what a download streams, and what
a copy needs.
"""

import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("PROJECT_DIR", "/project")

import orchestrator  # noqa: E402

failures = []
checks = 0


def check(name, cond):
    global checks
    checks += 1
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        failures.append(name)


def refuses(image_size, free_gib=17, isdir=True):
    """Run the guard with a pretend output volume; True if it refused."""
    real_usage, real_isdir = shutil.disk_usage, os.path.isdir
    shutil.disk_usage = lambda _p: os.statvfs_result if False else type(
        "U", (), {"free": int(free_gib * 1024**3), "total": 0, "used": 0})()
    os.path.isdir = lambda _p: isdir
    try:
        orchestrator._refuse_image_larger_than_the_disk(image_size)
        return False
    except ValueError:
        return True
    finally:
        shutil.disk_usage, os.path.isdir = real_usage, real_isdir


print('== --image-size is GiB, and a value meant as MiB must be refused ==')

check("6144 (meant as MiB) is refused on a 17 GiB volume", refuses("6144"))
check("a size just over the free space is refused", refuses("18"))

print("== sizes that fit are allowed ==")

check("8 GiB on a 17 GiB volume is allowed", not refuses("8"))
check("auto is always allowed", not refuses("auto", free_gib=1))
check("an empty size is always allowed", not refuses("", free_gib=1))
check("0 means auto and is allowed", not refuses("0", free_gib=1))
check("None is allowed", not refuses(None, free_gib=1))

print("== nonsense is refused rather than passed to the shell ==")

check("a non-numeric size is refused", refuses("6GB"))
check("a negative size is refused", refuses("-4"))

print("== and the guard never blocks a build for want of a directory ==")

check("no output directory yet: not refused", not refuses("4096", isdir=False))

print(f"\n{checks - len(failures)} passed, {len(failures)} failed")
sys.exit(1 if failures else 0)
