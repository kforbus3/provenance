#!/bin/bash
#
# Turn a root filesystem's package list into an SBOM, in the two formats anyone
# is going to ask for.
#
#   ./make-sbom.sh --root /mnt --name debian-trixie-ab --version 2026.09.02-1200 \
#                  --distro debian --arch amd64 --out /output/debian-trixie-ab.img
#
# Writes <out>.spdx.json, <out>.cdx.json and <out>.packages.tsv, and leaves a
# copy of the package list inside the root filesystem at
# /usr/lib/flipside/packages.tsv.
#
# Why this exists: an image sidecar recorded the distro, the suite, the profile
# and the sizes, and nothing at all about what was *in* the image. So "which of
# our images carry the vulnerable openssl" could only be answered by mounting
# every one of them in turn, and questions that need answering under time
# pressure are exactly the ones that must not require a maintenance window.
#
# Deliberately built from dpkg's own database rather than by scanning the
# filesystem: dpkg is the authority on what was installed on a Debian system,
# and a scanner would disagree with it in both directions. The list is captured
# while the slot is still mounted, which is the only moment it can be read
# without booting the thing.
#
# No python, no jq, no network. This runs inside the builder container, and a
# dependency added here is a dependency in every build. The fields emitted are
# package names, versions and architectures, whose character sets are defined by
# Debian policy and contain nothing JSON would need escaped -- and the one that
# does not conform is dropped with a warning rather than silently corrupting the
# document.
set -euo pipefail

ROOT=""; NAME=""; VERSION=""; DISTRO="debian"; ARCH=""; OUT=""; SUITE=""

log() { echo -e "\033[0;32m[sbom]\033[0m $*"; }
warn() { echo -e "\033[0;33m[sbom] WARNING:\033[0m $*" >&2; }
die() { echo -e "\033[0;31m[sbom] ERROR:\033[0m $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --root)    ROOT="$2"; shift 2;;
        --name)    NAME="$2"; shift 2;;
        --version) VERSION="$2"; shift 2;;
        --distro)  DISTRO="$2"; shift 2;;
        --suite)   SUITE="$2"; shift 2;;
        --arch)    ARCH="$2"; shift 2;;
        --out)     OUT="$2"; shift 2;;
        -h|--help) sed -n '2,12p' "$0"; exit 0;;
        *) die "unknown option '$1'";;
    esac
done

[ -n "$ROOT" ] || die "--root is required"
[ -d "$ROOT" ] || die "no such directory: $ROOT"
[ -n "$OUT" ]  || die "--out is required"
NAME="${NAME:-$(basename "$OUT")}"
VERSION="${VERSION:-unknown}"
ARCH="${ARCH:-$(dpkg --print-architecture 2>/dev/null || echo unknown)}"
CREATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- the package list --------------------------------------------------------
#
# `dpkg-query --admindir` reads the target root's database with the *builder's*
# dpkg, so this works without entering the chroot -- which matters because the
# slot may be from a different architecture, and because a bundle's source slot
# is mounted read-only.
ADMINDIR="$ROOT/var/lib/dpkg"
[ -d "$ADMINDIR" ] || die "$ROOT has no dpkg database at var/lib/dpkg"

TSV="${OUT}.packages.tsv"
# -f with an explicit status filter: dpkg-query lists packages that are merely
# `deinstall`ed (config files left behind) as well as installed ones, and an
# SBOM that names software which is not present is worse than no SBOM. `${db:Status-Status}`
# is the field that separates them.
dpkg-query --admindir="$ADMINDIR" -W \
    -f='${db:Status-Status}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' \
    2>/dev/null | awk -F'\t' 'BEGIN{OFS="\t"} $1=="installed" {print $2,$3,$4,$5,$6}' \
    | sort > "$TSV.tmp"

COUNT="$(wc -l < "$TSV.tmp" | tr -d ' ')"
[ "$COUNT" -gt 0 ] || die "dpkg reported no installed packages in $ROOT -- refusing to \
write an SBOM that says this image is empty"
mv "$TSV.tmp" "$TSV"
log "$COUNT packages"

# A copy inside the image, so the question can also be asked of a running
# machine, and so a bundle built from this image carries it along.
if install -d -m755 "$ROOT/usr/lib/flipside" 2>/dev/null; then
    install -m644 "$TSV" "$ROOT/usr/lib/flipside/packages.tsv" 2>/dev/null \
        || warn "could not write the package list into the image (read-only?)"
fi

# --- shared helpers ----------------------------------------------------------
#
# Debian policy: package names are [a-z0-9][a-z0-9+-.]+, versions are
# [A-Za-z0-9.+:~-] (plus a leading epoch digit and colon), architectures are
# [a-z0-9-]. None of that needs JSON escaping. Anything else is a package this
# tool does not understand well enough to describe, so it is dropped loudly
# rather than emitted into a document that then fails to parse at the far end.
NAMESPACE="$DISTRO"
case "$DISTRO" in debian|ubuntu) ;; *) NAMESPACE="debian";; esac

emit_awk() {
    awk -F'\t' -v ns="$NAMESPACE" -v mode="$1" -v created="$CREATED" \
        -v docname="$NAME" -v docver="$VERSION" -v docarch="$ARCH" \
        -v suite="$SUITE" -v distro="$DISTRO" '
    function ok(s) { return s ~ /^[A-Za-z0-9][A-Za-z0-9.+:~_-]*$/ }
    function purl(p, v, a) { return "pkg:deb/" ns "/" p "@" v "?arch=" a }
    BEGIN {
        n = 0
        if (mode == "spdx") {
            print "{"
            print "  \"spdxVersion\": \"SPDX-2.3\","
            print "  \"dataLicense\": \"CC0-1.0\","
            print "  \"SPDXID\": \"SPDXRef-DOCUMENT\","
            print "  \"name\": \"" docname "\","
            # A namespace has to be unique per document. The image name plus the
            # build version is exactly that, and unlike a random UUID it is
            # reproducible -- two SBOMs of the same build compare equal.
            print "  \"documentNamespace\": \"https://flipside.invalid/spdx/" docname "-" docver "\","
            print "  \"creationInfo\": {"
            print "    \"created\": \"" created "\","
            print "    \"creators\": [\"Tool: flipside-make-sbom\", \"Organization: Flipside\"]"
            print "  },"
            print "  \"packages\": ["
        } else {
            print "{"
            print "  \"bomFormat\": \"CycloneDX\","
            print "  \"specVersion\": \"1.5\","
            print "  \"version\": 1,"
            print "  \"metadata\": {"
            print "    \"timestamp\": \"" created "\","
            print "    \"tools\": [{\"vendor\": \"Flipside\", \"name\": \"make-sbom\"}],"
            print "    \"component\": {"
            print "      \"type\": \"operating-system\","
            print "      \"bom-ref\": \"flipside-image\","
            print "      \"name\": \"" docname "\","
            print "      \"version\": \"" docver "\""
            if (distro != "" && suite != "")
                print "      , \"description\": \"" distro " " suite " (" docarch ")\""
            print "    }"
            print "  },"
            print "  \"components\": ["
        }
    }
    {
        pkg = $1; ver = $2; arch = $3
        if (!ok(pkg) || !ok(ver) || !ok(arch)) {
            print "make-sbom: skipping unrepresentable package \"" pkg "\"" > "/dev/stderr"
            next
        }
        n++
        if (n > 1) print ","
        if (mode == "spdx") {
            printf "    {\n"
            printf "      \"SPDXID\": \"SPDXRef-Package-%d\",\n", n
            printf "      \"name\": \"%s\",\n", pkg
            printf "      \"versionInfo\": \"%s\",\n", ver
            printf "      \"downloadLocation\": \"NOASSERTION\",\n"
            printf "      \"filesAnalyzed\": false,\n"
            printf "      \"licenseConcluded\": \"NOASSERTION\",\n"
            printf "      \"licenseDeclared\": \"NOASSERTION\",\n"
            printf "      \"copyrightText\": \"NOASSERTION\",\n"
            printf "      \"externalRefs\": [{\n"
            printf "        \"referenceCategory\": \"PACKAGE-MANAGER\",\n"
            printf "        \"referenceType\": \"purl\",\n"
            printf "        \"referenceLocator\": \"%s\"\n", purl(pkg, ver, arch)
            printf "      }]\n"
            printf "    }"
        } else {
            printf "    {\n"
            printf "      \"type\": \"library\",\n"
            printf "      \"bom-ref\": \"%s\",\n", purl(pkg, ver, arch)
            printf "      \"name\": \"%s\",\n", pkg
            printf "      \"version\": \"%s\",\n", ver
            printf "      \"purl\": \"%s\"\n", purl(pkg, ver, arch)
            printf "    }"
        }
        ids[n] = n
    }
    END {
        print ""
        print "  ]"
        if (mode == "spdx") {
            print "  , \"relationships\": ["
            for (i = 1; i <= n; i++) {
                printf "    {\"spdxElementId\": \"SPDXRef-DOCUMENT\", \"relatedSpdxElement\": \"SPDXRef-Package-%d\", \"relationshipType\": \"DESCRIBES\"}", i
                if (i < n) print ","; else print ""
            }
            print "  ]"
        }
        print "}"
    }' "$TSV"
}

emit_awk spdx > "${OUT}.spdx.json"
emit_awk cyclonedx > "${OUT}.cdx.json"

log "wrote $(basename "${OUT}.spdx.json"), $(basename "${OUT}.cdx.json") and \
$(basename "$TSV")"
echo "$COUNT"
