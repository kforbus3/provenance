#!/bin/bash
#
# Build a bootable Debian or Ubuntu A/B disk image (optionally LUKS-encrypted).
#
# Layout (GPT, hybrid BIOS + UEFI boot):
#   p1  bios_grub  (1 MiB, raw)        GRUB BIOS core
#   p2  ESP        (vfat, label EFI)   EFI system partition (GRUB at removable path)
#   p3  BOOT       (ext4, label BOOT)  shared /boot + kernel + grubenv (always plaintext)
#   p4  rootfs-a   root slot A         (ext4, or LUKS2 + ext4 when --encrypt)
#   p5  rootfs-b   root slot B         (copy of A)
#   p6  overlay    persistent data     (grows to fill the disk on first boot)
#
# Runs inside the privileged builder container (see Dockerfile).
set -euo pipefail

# --- Defaults (override via flags or environment) ---
DISTRO="${DISTRO:-}"                    # debian | ubuntu (empty = auto-detect from suite)
SUITE="${SUITE:-trixie}"
ARCH="${ARCH:-amd64}"
MIRROR="${MIRROR:-}"                    # empty = distro default
HOSTNAME_="${HOSTNAME_:-}"              # empty = <distro>-ab
USERNAME="${USERNAME:-debian}"
PASSWORD="${PASSWORD:-debian}"
ROOT_SIZE="${ROOT_SIZE:-}"              # empty = profile default (3072, or the
                                        # desktop floor); see MIN_ROOT below
BOOT_SIZE="${BOOT_SIZE:-}"              # empty = profile default (512, or the
                                        # desktop floor); see MIN_BOOT below
ESP_SIZE="${ESP_SIZE:-128}"
OVERLAY_MIN="${OVERLAY_MIN:-}"          # empty = from the state model; see below
IMAGE_SIZE="${IMAGE_SIZE:-auto}"        # GiB, or "auto" = smallest possible
OUTPUT="${OUTPUT:-}"                    # empty = /output/<distro>-<suite>-ab.img
EXTRA_PACKAGES="${EXTRA_PACKAGES:-}"
# What this build calls itself. Written into the image as
# /usr/lib/flipside/version, which is what a running machine reports to the
# control plane -- so two builds of the same suite are distinguishable, which
# os-release alone cannot do. make-bundle.sh replaces it with the bundle's
# version, so an updated slot reports the bundle it was installed from.
IMAGE_VERSION="${IMAGE_VERSION:-}"      # empty = UTC build timestamp
# UEFI Secure Boot. `auto` installs the signed shim and GRUB and uses them if
# the suite has them, which every current Debian and Ubuntu does; `on` fails the
# build if they cannot be had, so a fleet that requires Secure Boot cannot be
# handed an image that quietly does not support it; `off` is the old layout.
#
# A Secure Boot image also boots fine with Secure Boot switched off, and the
# BIOS path is untouched either way -- shim simply runs GRUB without verifying
# it. So there is no image this costs anything.
SECURE_BOOT="${SECURE_BOOT:-auto}"      # auto | on | off
# Build profile: what the image is *for*, spelled as a named package set rather
# than a list everyone retypes. minimal is exactly the base system this project
# has always built -- the flag only names it, so existing builds change in
# nothing. server and desktop add to it; see the profile resolution below.
PROFILE="${PROFILE:-minimal}"           # minimal | server | desktop
DESKTOP_ENV="${DESKTOP_ENV:-}"          # desktop profile only; empty = gnome
DESKTOP_SET=false                       # was --desktop given explicitly?
OVERLAY_D="${OVERLAY_D:-/overlay.d}"     # your files, copied over the whole root
RUN_SCRIPT="${RUN_SCRIPT:-}"             # script run inside the chroot at the end
OWN_PATHS="${OWN_PATHS:-}"               # paths the image owns; see image-owned.list
SSH_PUBKEY="${SSH_PUBKEY:-}"
# --- writable-state layout (see the state manifest, further down) ------------
# The default model is the one this project started with: the whole root is a
# single overlay over the A/B slot, shared by both slots, and the paths the
# distribution owns are cleared from it whenever the slot changes.
STATE_MODEL="${STATE_MODEL:-overlay}"
# Whether the two slots share the overlay's upper layer. Shared is the default
# and the historical behaviour; per-slot gives each slot its own, so a change
# made in one cannot stop the other from booting. See --slot-private-upper.
UPPER_MODE="${UPPER_MODE:-shared}"
MOUNT_DIRECTIVES="overlay /"
EXTRA_MOUNTS=""                          # from --persist/--slot-private/--volatile
# Cleared from the writable state on a slot change. Everything the distribution
# owns: a copy of these from the previous release would shadow the one the
# update just installed, and nothing in the running system would say so.
# The package-database directories are appended once the family is known, a few
# hundred lines down -- they are the one part of this list that differs, and
# naming only Debian's here meant an rpm machine kept the PREVIOUS release's
# /var/lib/rpm on the overlay after an update, shadowing the database that came
# with the new slot. `rpm -qa` would then describe software that is not
# installed, which is precisely the failure this list exists to prevent, and it
# is silent.
RESET_PATHS="/usr /bin /sbin /lib /lib32 /lib64 /libx32 /boot"
# Held back from that clearing. /usr/local sits inside /usr but is reserved by
# the FHS for locally installed software, so it is the machine's, not the
# image's -- clearing /usr wholesale used to take it, and a script left in
# /usr/local/bin vanished on the first update with nothing said.
KEEP_PATHS="/usr/local"
# What --reset-on-update and --keep-path added, held apart from the two lists
# above until the state model has set its own. See the parser.
USER_RESET_PATHS=""
USER_KEEP_PATHS=""
SSH_KEY_ONLY="${SSH_KEY_ONLY:-false}"
COMPRESS="${COMPRESS:-zstd}"
CHECK_ONLY=false
# Encryption
ENCRYPT="${ENCRYPT:-false}"
UNLOCK="${UNLOCK:-keyfile}"             # passphrase | keyfile | tpm2 | tang
# Whether --unlock was actually given. The default above is a real value, so
# without this an unencrypted image cannot tell "operator asked for tpm2" from
# "nobody said anything", and refusing the second would refuse every build.
UNLOCK_SET=false
# Likewise for the passphrase and the tang server. Both also have an environment
# form (LUKS_PASS, TANG_URL) that the imaging sidecar's container inherits from
# its own environment, so "is it non-empty" cannot stand in for "did somebody ask
# for this" -- an ambient value would refuse every unencrypted build the UI runs.
LUKS_PASS_SET=false
TANG_URL_SET=false
TPM2_PCRS_SET=false
# RAUC is built from source on the RPM family -- there is no package for it in
# base or EPEL. Pinned rather than tracking a branch: this is the component that
# decides whether a machine can be updated at all, and it should change when
# somebody chooses to change it.
RAUC_VERSION="${RAUC_VERSION:-v1.13}"
LUKS_PASS="${LUKS_PASS:-}"
TANG_URL="${TANG_URL:-}"
# Which TPM PCRs a tpm2 binding is sealed against. 7 is the Secure Boot policy
# state: stable across kernel and initramfs changes, so a binding survives an
# A/B update. Sealing to the PCRs that measure the boot chain itself (8, 9)
# would break on every update, and would differ between the normal and recovery
# GRUB entries -- making the recovery entries the one thing that cannot unlock.
TPM2_PCRS="${TPM2_PCRS:-7}"

usage() {
    cat <<EOF
Usage: $0 [options]
  --distro NAME           debian|ubuntu|almalinux|rocky (default: auto-detect from --suite)
  --suite NAME            Debian/Ubuntu codename, or an RPM major version
                          (default: $SUITE; e.g. trixie, bookworm, noble, jammy, 9, 10)
  --arch ARCH             Architecture (default: $ARCH)
  --mirror URL            APT mirror (default: distro's primary mirror)
  --hostname NAME         Image hostname (default: $HOSTNAME_)
  --username NAME         Login user to create (default: $USERNAME)
  --password PASS         Password for that user (default: $USERNAME)
  --profile NAME          minimal|server|desktop (default: minimal, which is
                          exactly the base system with nothing added).
                          server adds a small headless-admin set; desktop
                          installs a full graphical environment.
  --desktop ENV           Desktop environment for --profile desktop (default:
                          gnome). Debian: gnome kde xfce mate cinnamon lxqt;
                          Ubuntu: gnome kde xfce mate lxqt.
  --root-size MiB         Size of each root slot (default: 3072, raised to the
                          distro/profile minimum -- a desktop build needs
                          10240; see the docs)
  --boot-size MiB         Size of the shared /boot partition (default: 512;
                          a desktop build defaults to 2048 -- it holds three
                          copies of a firmware-heavy kernel+initramfs)
  --image-size GiB|auto   Total image size (default: auto = smallest possible;
                          the overlay partition expands to fill the target disk
                          on first boot either way)
  --output PATH           Output image path
  --packages "a b c"      Extra packages to install
  --overlay-dir DIR       Directory copied over the image root (default: $OVERLAY_D)
  --run-script FILE       Shell script run inside the chroot after packages
  --own-path PATH         Path the image owns: cleared from the persistent
                          overlay on update so the image version wins.
                          Repeatable. Everything in --overlay-dir is implied.

 Writable state -- what the machine can change, and what the A/B slots share.
 By default the whole root is one overlay shared by both slots. These carve
 exceptions out of that; all are repeatable and take absolute paths.
  --persist PATH          Bind PATH to its own directory on the overlay
                          partition: still shared by both slots, but outside
                          the overlay, so an update never shadows it.
  --slot-private PATH     Give each slot its own PATH. Nothing written here in
                          one slot is visible from the other -- use it for
                          state tied to the release, e.g. /var/lib/docker.
  --volatile PATH[:SIZE]  tmpfs over PATH: not shared, not kept across a
                          reboot. SIZE caps it (e.g. /var/tmp:256M).
  --reset-on-update PATH  Also clear PATH from writable state when the slot
                          changes, so the new release starts from its own copy.
  --keep-path PATH        Hold PATH back from that clearing, even when it sits
                          inside something being cleared (as /usr/local does).
  --state-model NAME      overlay|stateful|appliance (default: $STATE_MODEL).
                          overlay   whole root overlaid, shared by both slots
                          stateful  root read-only; /home /var /usr/local persist
                          appliance root read-only; only /data survives an update
  --slot-private-upper    Give each slot its OWN overlay upper layer instead of
                          one shared by both. A config change applied while
                          running A then cannot stop B from booting, so the
                          other slot is a real fallback and not just an older
                          OS. The cost is that the slots share nothing the
                          overlay covers -- including /home and /etc -- so pair
                          it with --persist for what should stay shared.
                          Not the default, and it cannot be turned on or off by
                          an update: the machine records which layout it was
                          imaged with and refuses a change at boot.
  --overlay-min MiB       Overlay partition size as built. It expands to fill
                          the disk on first boot, so this only has to hold what
                          the manifest seeds before that happens (default: 256,
                          or 1024 when anything is persisted).
  --ssh-pubkey FILE       Authorized SSH key file for the user
  --ssh-authorized-key K  Authorized SSH key passed inline
  --ssh-key-only          Disable SSH password auth (requires an SSH key)
  --version STR           What this build calls itself; reported by each
                          machine to the control plane (default: build time)
  --secure-boot MODE      auto|on|off (default: $SECURE_BOOT). auto uses the
                          distribution's signed shim and GRUB when the suite has
                          them; on fails the build if it cannot; off keeps the
                          old unsigned layout. A Secure Boot image also boots
                          with Secure Boot disabled.
  --check-only            Validate the options and exit; build nothing.
  --compress MODE         zstd|gzip|none (default: $COMPRESS)
  --encrypt               LUKS2-encrypt the root slots and overlay
  --unlock METHOD         passphrase|keyfile|tpm2|tang (default: $UNLOCK)
  --luks-passphrase PASS  LUKS passphrase (recovery + setup); required with --encrypt
  --luks-passphrase-file F  Read the passphrase from a file (or - for stdin) instead.
                          Prefer this over --luks-passphrase: an argument is visible
                          in \`ps\` to every user on the build host.
  --tang-url URL          Tang server URL (required for --unlock tang)
  --tpm2-pcrs LIST        PCRs to seal to with --unlock tpm2 (default: $TPM2_PCRS)
  -h, --help              Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --distro) DISTRO="$2"; shift 2;;
        --suite) SUITE="$2"; shift 2;;
        --arch) ARCH="$2"; shift 2;;
        --mirror) MIRROR="$2"; shift 2;;
        --hostname) HOSTNAME_="$2"; shift 2;;
        --username) USERNAME="$2"; shift 2;;
        --password) PASSWORD="$2"; shift 2;;
        --root-size) ROOT_SIZE="$2"; shift 2;;
        --boot-size) BOOT_SIZE="$2"; shift 2;;
        --image-size) IMAGE_SIZE="$2"; shift 2;;
        --output) OUTPUT="$2"; shift 2;;
        --version) IMAGE_VERSION="$2"; shift 2;;
        --secure-boot) SECURE_BOOT="$2"; shift 2;;
        --packages) EXTRA_PACKAGES="$2"; shift 2;;
        --profile) PROFILE="$2"; shift 2;;
        --desktop) DESKTOP_ENV="$2"; DESKTOP_SET=true; shift 2;;
        --overlay-dir) OVERLAY_D="$2"; shift 2;;
        --run-script) RUN_SCRIPT="$2"; shift 2;;
        --own-path) OWN_PATHS="$OWN_PATHS $2"; shift 2;;
        --state-model)     STATE_MODEL="$2"; shift 2;;
        --slot-private-upper) UPPER_MODE=per-slot; shift;;
        --overlay-min)     OVERLAY_MIN="$2"; shift 2;;
        --persist)         EXTRA_MOUNTS="$EXTRA_MOUNTS
persist $2"; shift 2;;
        --slot-private)    EXTRA_MOUNTS="$EXTRA_MOUNTS
slot-private $2"; shift 2;;
        --volatile)        # PATH or PATH:SIZE -- the manifest wants them apart
            EXTRA_MOUNTS="$EXTRA_MOUNTS
volatile ${2%%:*} $(case "$2" in *:*) echo "${2##*:}";; esac)"; shift 2;;
        # Collected separately from the model's own lists and merged after it
        # has chosen them. Appending to RESET_PATHS/KEEP_PATHS directly meant
        # `--state-model stateful --keep-path /srv` was parsed, stored, and then
        # thrown away by the model's `KEEP_PATHS=""` a hundred lines later --
        # accepted without complaint and absent from the image.
        --reset-on-update) USER_RESET_PATHS="$USER_RESET_PATHS $2"; shift 2;;
        --keep-path)       USER_KEEP_PATHS="$USER_KEEP_PATHS $2"; shift 2;;
        --ssh-pubkey) SSH_PUBKEY="$(cat "$2")"; shift 2;;
        --ssh-authorized-key) SSH_PUBKEY="$2"; shift 2;;
        --ssh-key-only) SSH_KEY_ONLY=true; shift;;
        # Validate the options and exit without building. See the block that
        # acts on it, after the last argument-only check.
        --check-only) CHECK_ONLY=true; shift;;
        --compress) COMPRESS="$2"; shift 2;;
        --encrypt) ENCRYPT=true; shift;;
        --unlock) UNLOCK="$2"; UNLOCK_SET=true; shift 2;;
        --luks-passphrase) LUKS_PASS="$2"; LUKS_PASS_SET=true; shift 2;;
        --luks-passphrase-file)
            # Only the first line, and without its newline: a passphrase pasted
            # into a file almost always ends with one, and including it produces
            # a container that rejects the passphrase the operator believes they
            # set -- discovered at an initramfs prompt, not here.
            if [ "$2" = "-" ]; then IFS= read -r LUKS_PASS || true
            else
                [ -r "$2" ] || die "--luks-passphrase-file: cannot read '$2'"
                IFS= read -r LUKS_PASS < "$2" || true
            fi
            [ -n "$LUKS_PASS" ] || die "--luks-passphrase-file: '$2' is empty"
            LUKS_PASS_SET=true
            shift 2;;
        --tang-url) TANG_URL="$2"; TANG_URL_SET=true; shift 2;;
        --tpm2-pcrs) TPM2_PCRS="$2"; TPM2_PCRS_SET=true; shift 2;;
        -h|--help) usage; exit 0;;
        *) echo "Unknown option: $1" >&2; usage; exit 1;;
    esac
done

log()  { echo -e "\033[0;32m[build]\033[0m $*"; }
warn() { echo -e "\033[1;33m[build]\033[0m $*"; }
die()  { echo -e "\033[0;31m[build] ERROR:\033[0m $*" >&2; exit 1; }

# Cap the open-file limit before any package manager runs.
#
# rpm closes every file descriptor from 3 up to the soft RLIMIT_NOFILE between
# fork() and exec() of a scriptlet. Docker hands containers whatever the daemon
# inherited, and on a host with LimitNOFILE=infinity that is 1073741816 -- so the
# first package with a scriptlet spins a billion close() calls at 100% CPU and
# the build appears to hang forever, always at glibc, the first RPM in the
# bootstrap that has one. It is not the storage, the distro, or the CPU: the same
# transaction into a plain directory in a stock rockylinux:9 container hangs the
# same way, and it does not reproduce where the daemon sets a sane limit.
#
# Both limits, not just the soft one. Lowering the soft limit alone gets the
# bootstrap past glibc and then hangs again a few packages later, because rpm
# raises the soft limit back to the hard one before it closes anything -- so a
# hard limit still in the billions is the same bug with a longer fuse. That is
# worth stating plainly because "it got further" reads like progress and is not.
#
# Soft first: the kernel rejects a hard limit below the current soft limit, so
# lowering the ceiling before the floor fails with EINVAL and leaves both huge.
#
# 65536 is generous -- a build needing more open files than that has a different
# problem -- and dpkg has no such loop, but the limit is absurd for either family.
NOFILE_CAP=65536
NOFILE_PREV="$(ulimit -Sn)"
if [ "$NOFILE_PREV" = unlimited ] || [ "$NOFILE_PREV" -gt "$NOFILE_CAP" ] 2>/dev/null; then
    ulimit -S -n "$NOFILE_CAP" 2>/dev/null || true
    ulimit -H -n "$NOFILE_CAP" 2>/dev/null || true
    if [ "$(ulimit -Hn)" = "$NOFILE_CAP" ] && [ "$(ulimit -Sn)" = "$NOFILE_CAP" ]; then
        log "open-file limit capped at $NOFILE_CAP soft and hard (was $NOFILE_PREV)"
    else
        warn "open-file limit is soft=$(ulimit -Sn) hard=$(ulimit -Hn); rpm scriptlets may take hours"
    fi
fi

# Machine-readable progress. The web UI parses these lines into a progress bar;
# on a terminal they read as ordinary step markers. Emitted in addition to the
# human log so neither consumer depends on parsing prose.
BUILD_STEP=0
# The number of step() calls this run will actually make.
#
# Hardcoded at 14 until a real build reported "[progress] 15/14" -- steps had
# been added over time and the constant was never moved, so the bar overran and
# the label read as if the build had lost count. Derived now, because a hand-kept
# total is a thing that goes stale silently: the only symptom is a progress bar,
# which nobody treats as a bug worth chasing.
#
# 15 always run. The two GRUB branches are either/or, so they count once. The
# other two depend on options that are known before anything is built.
BUILD_STEPS=15
[ -d "$OVERLAY_D" ] && [ -n "$(ls -A "$OVERLAY_D" 2>/dev/null)" ] && BUILD_STEPS=$((BUILD_STEPS + 1))
[ -n "$RUN_SCRIPT" ] && BUILD_STEPS=$((BUILD_STEPS + 1))
step() {
    BUILD_STEP=$((BUILD_STEP + 1))
    printf '[progress] %d/%d %s\n' "$BUILD_STEP" "$BUILD_STEPS" "$1"
    log "$1"
}

# --- Resolve the distro FAMILY ------------------------------------------------
#
# The A/B root itself is shared between the families rather than reimplemented:
# the same two scripts run under both harnesses (see /usr/lib/ab/initramfs), with
# initramfs-tools invoking them from local-bottom/init-premount and dracut from
# its own modules in usr/lib/dracut/modules.d. What differs between the harnesses
# is how a script gets INTO the initramfs and what the mounted root is called --
# not what the script does.
#
# Everything below branches on the family rather than on the distro: the
# difference between Debian and Ubuntu is a mirror and two package names, while
# the difference between either and AlmaLinux is the bootstrapper, the package
# manager, the initramfs generator and the bootloader's name. Two variables kept
# apart because they answer different questions.
#
# The A/B layout, partitioning, LUKS, the state manifest, the update keyring and
# the per-slot kernel staging are the same either way, which is why this is one
# script with branches rather than two scripts that would drift.
case "$DISTRO" in
    debian|ubuntu)        FAMILY=deb;;
    almalinux|rocky|rhel) FAMILY=rpm;;
    *) die "--distro must be debian, ubuntu, almalinux or rocky (got '$DISTRO')";;
esac

# Resolved BEFORE the writable-state layout below, which branches on it.
# It used to sit 130 lines further down, so `--state-model stateful` read
# $FAMILY before it existed and died on `FAMILY: unbound variable` -- for
# every distribution, making that model unreachable from the day it shipped.
# --- Resolve the writable-state layout --------------------------------------
#
# Validated here, before anything is built, because every one of these mistakes
# is otherwise discovered at a boot prompt on a machine that has already been
# imaged. A manifest is applied by an initramfs with no way to ask a question
# and nobody watching, so it has to be right before it ships.
# A model is a starting manifest, not a mode: --persist and friends append to
# whichever one is chosen. The three differ in one thing -- how much of the root
# a machine is allowed to write to -- and that is the axis every other A/B
# system picks a point on too.
ROOT_FLAG=rw                   # what GRUB passes for the root slot
case "$STATE_MODEL" in
    overlay)
        # The whole root is one overlay shared by both slots, and the paths the
        # distribution owns -- /usr, /bin, /sbin, /lib*, /boot and the package
        # database -- are clawed back on a slot change. Everything else a person
        # does to the machine survives an update: /etc, /home, /opt, /srv, /var
        # and /usr/local are all still there afterwards, which is what makes this
        # the right default for a general-purpose fleet.
        #
        # `apt install` is NOT in that set, and this comment claimed for a long
        # time that it was. It is not a carve-out that was forgotten; it cannot
        # work here. A package writes into /usr and records itself in the package
        # database, and with one upper shared by both slots that database would
        # survive a slot change describing the other slot's image -- so it is
        # reset, and the files it no longer accounts for are reset with it.
        # Keeping either half is worse than losing both: keep the files and
        # nothing patches them again, keep the database and every later
        # transaction reasons from a package list that is not what is installed.
        # Both are refused at the top of this script for exactly that reason.
        #
        # Packages a machine needs permanently belong in the image. The other two
        # models make that unmissable by mounting the root read-only, so the
        # install fails in front of whoever typed it; this one accepts the write
        # and discards it at the next slot change, which is the same answer
        # delivered weeks late.
        :;;
    stateful)
        # /usr is the image's and cannot be written at all, so nothing a machine
        # does can shadow a binary the update just delivered. What a machine
        # owns is enumerated instead: /home, /var, /usr/local and the rest are
        # real directories on the overlay partition, and /etc is a small overlay
        # so the image can still ship config that wins. This is the shape
        # ChromeOS uses.
        ROOT_FLAG=ro
        MOUNT_DIRECTIVES="overlay /etc
persist /home
persist /root
persist /srv
persist /opt
persist /usr/local
persist /var"
        if [ "$FAMILY" = rpm ]; then
            RESET_PATHS="/var/lib/rpm /var/lib/dnf /var/cache/dnf"
        else
            RESET_PATHS="/var/lib/dpkg /var/lib/apt /var/cache/apt"
        fi
        KEEP_PATHS=""
        ;;
    appliance)
        # Only /data survives an update. /etc stays editable because an operator
        # has to be able to configure the thing, but /var reverts to the image's
        # copy on every slot change, so the machine cannot accumulate state the
        # next release did not expect. This is the shape Android and the
        # RAUC/Mender reference layouts use, and `apt install` does not survive
        # it -- deliberately.
        ROOT_FLAG=ro
        MOUNT_DIRECTIVES="overlay /etc
overlay /var
persist /data"
        RESET_PATHS="/var"
        # No keeps. This model does not reset /etc -- an operator has to be able
        # to configure the thing -- so the LUKS-enrollment keep that used to sit
        # here carved nothing out of anything. It is applied from the reset list
        # now, above, where it fires for whichever model actually resets /etc.
        KEEP_PATHS=""
        ;;
    *) die "--state-model: unknown model '$STATE_MODEL' (expected: overlay, stateful, appliance)";;
esac

# The package database is the one family-specific part of the distribution-owned
# paths cleared on a slot change, and only the overlay model needs it added: the
# other two set a complete list of their own just above. It used to be appended
# 550 lines further down, unconditionally, which was wrong twice over -- stateful
# names these exact three paths itself, so state.conf shipped each of them twice,
# and appliance already resets the whole of /var, so it got three redundant
# children of a path it was clearing anyway.
#
# The comment there justified the distance by saying the list is built before the
# arguments naming the distribution are parsed. That was true of the defaults at
# the top of the file, but not here: --distro has been parsed and FAMILY resolved
# for ninety lines by this point. Being here is what lets the validation below
# see the finished list -- checking a keep path against a reset list that is
# still missing three entries is how `--keep-path /var/lib/rpm` got refused with
# a message saying it was not inside anything that gets reset.
if [ "$STATE_MODEL" = overlay ]; then
    if [ "$FAMILY" = rpm ]; then
        RESET_PATHS="$RESET_PATHS /var/lib/rpm /var/lib/dnf /var/cache/dnf"
    else
        RESET_PATHS="$RESET_PATHS /var/lib/dpkg /var/lib/apt /var/cache/apt"
    fi
fi

# Now the operator's own additions, on top of whichever list the model settled
# on. Last, so that every model honours the flags rather than only the one whose
# defaults happen not to be reassigned.
RESET_PATHS="$RESET_PATHS$USER_RESET_PATHS"
KEEP_PATHS="$KEEP_PATHS$USER_KEEP_PATHS"

MOUNT_DIRECTIVES="$MOUNT_DIRECTIVES$EXTRA_MOUNTS"

while read -r _verb _mp _arg; do
    [ -n "$_verb" ] || continue
    case "$_mp" in
        /) die "--$_verb: / is the whole root; that is what --state-model decides";;
        /*) ;;
        *) die "--$_verb: path must be absolute (got '$_mp')";;
    esac
    case "$_mp" in
        */) die "--$_verb: drop the trailing slash from '$_mp'";;
        *..*) die "--$_verb: '..' is not allowed in '$_mp'";;
    esac
done <<EOF
$(printf '%s\n' "$EXTRA_MOUNTS" | grep -v '^[[:space:]]*$')
EOF

# Two directives on one path is not a merge, it is a race: whichever the
# initramfs applies second silently wins, and from inside the running machine
# there is no way to tell which one that was. Checked across the model's own
# directives too, so `--state-model stateful --persist /var` is caught rather
# than quietly overriding half of the model.
_dupes=$(printf '%s\n' "$MOUNT_DIRECTIVES" | awk 'NF >= 2 { print $2 }' | sort | uniq -d)
[ -z "$_dupes" ] || die "more than one directive for: $(echo $_dupes); pick one per path"

# Nested overlays would each need their own lower bind, which the engine does
# not do. No model produces one; this catches a future one that tries.
_ovl=$(printf '%s\n' "$MOUNT_DIRECTIVES" | awk '$1 == "overlay" { print $2 }')
for _a in $_ovl; do for _b in $_ovl; do
    if [ "$_a" != "$_b" ]; then
        # "/" needs saying separately: "$_b"/* expands to "//*" for it, which
        # matches nothing, so the one case that matters most would slip through.
        if [ "$_b" = "/" ]; then die "overlay '$_a' nests inside overlay '/'"; fi
        case "$_a" in "$_b"/*) die "overlay '$_a' nests inside overlay '$_b'";; esac
    fi
done; done

for _p in $RESET_PATHS $KEEP_PATHS; do
    case "$_p" in
        /*) ;;
        *) die "--reset-on-update/--keep-path: path must be absolute (got '$_p')";;
    esac
done

# Resetting /etc on an encrypted image would take the LUKS enrollment with it.
# The unlock key is written to /etc/cryptsetup-keys.d *after* the build, by
# enrollment on the machine, so it lives in the writable layer and nowhere in
# the image -- a reset clears it and the machine comes up asking for a
# passphrase nobody is there to type. The appliance model used to carry this
# keep unconditionally, which was a no-op there because appliance does not reset
# /etc; attached to the condition instead, so it appears exactly when it does
# something and every model gets it.
if [ "$ENCRYPT" = true ]; then
    for _r in $RESET_PATHS; do
        case /etc/cryptsetup-keys.d in
            "$_r"|"$_r"/*)
                case " $KEEP_PATHS " in
                    *" /etc/cryptsetup-keys.d "*) ;;
                    *) KEEP_PATHS="$KEEP_PATHS /etc/cryptsetup-keys.d"
                       log "  keeping /etc/cryptsetup-keys.d: $_r is reset and this image is encrypted";;
                esac;;
        esac
    done
fi

# A keep is a carve-out from a reset, and only from a reset. ab-overlay moves
# each keep path aside into /ab-rw/.keep, clears the reset paths, and moves it
# back; a keep that is not inside any reset path carves nothing out. It is a mv
# of live data out of the store and back on every single slot change, for no
# effect -- and on the failing branch of that mv the script drops the path
# (ab-overlay's `mv ... || remove_path`). So it is not merely useless, it is a
# way to lose data that was never at risk. It also reads in state.conf as
# protection the machine is not giving.
#
# Equality is the case that matters most. `--keep-path /usr` cancels the reset
# of /usr outright: the upper's /usr goes on shadowing the lower, and an update
# installs a new slot whose binaries are never seen. That is exactly the shape
# of the klibc `rm` bug recorded in ab-overlay -- an update that reports success
# and changes nothing -- reached this time through the build arguments rather
# than a missing binary. Refused rather than warned about, because the machine
# that results looks healthy from every angle except the version it is running.
for _k in $KEEP_PATHS; do
    _inside=""
    for _r in $RESET_PATHS; do
        [ "$_k" = "$_r" ] && die "--keep-path $_k is also reset on update, so the keep
    cancels the reset entirely. An update would leave the running slot's $_k
    shadowing the one it just installed, and the machine would report success
    while continuing to run the old release.
    Keep something *inside* it instead (e.g. $_k/local), or drop the reset."
        case "$_k" in "$_r"/*) _inside=1;; esac
    done
    [ -n "$_inside" ] || die "--keep-path $_k is not inside any path that is reset on
    update, so it keeps nothing -- $_k already survives a slot change under
    --state-model $STATE_MODEL.
    Paths reset on update are:$(for _r in $RESET_PATHS; do printf ' %s' "$_r"; done)"
done

# --slot-private-upper only means anything if something is overlaid. Every model
# here overlays at least one path, so this is a guard against a future one that
# does not -- where the flag would otherwise be accepted, do nothing, and leave
# the operator believing the slots were separated when they were not.
if [ "$UPPER_MODE" = per-slot ] && [ -z "$_ovl" ]; then
    die "--slot-private-upper: state model '$STATE_MODEL' overlays nothing, so there
    is no upper layer to give each slot. Use --slot-private for individual paths."
fi

# --- Validate options ---
#
# Moved up from where it used to sit, 550 lines below, so that it runs before
# --check-only returns: these rules depend on the arguments and nothing else, so
# there is no reason to reach them only on a build that has already started
# fetching packages.
if [ "$SSH_KEY_ONLY" = true ] && [ -z "$SSH_PUBKEY" ]; then
    die "--ssh-key-only requires an SSH key (--ssh-pubkey or --ssh-authorized-key)"
fi
USE_KEYFILE=false
if [ "$ENCRYPT" = true ]; then
    [ -n "$LUKS_PASS" ] || die "--encrypt requires --luks-passphrase"
    case "$UNLOCK" in
        passphrase) ;;
        keyfile|tpm2|tang) USE_KEYFILE=true;;
        *) die "--unlock must be passphrase|keyfile|tpm2|tang";;
    esac
    [ "$UNLOCK" = tang ] && [ -z "$TANG_URL" ] && die "--unlock tang requires --tang-url"
    # PCRs are what a TPM seals the key against; no other unlock method has
    # anything to seal. Given alongside one of the others the value was simply
    # never read, which on a flag whose whole job is to narrow what can open the
    # disk is a silent loosening of the thing the operator was tightening.
    [ "$TPM2_PCRS_SET" = true ] && [ "$UNLOCK" != tpm2 ] && \
        die "--tpm2-pcrs only applies to --unlock tpm2 (this image uses '$UNLOCK').
    PCRs are what the TPM seals the key against, and nothing else seals anything."
    [ "$TANG_URL_SET" = true ] && [ "$UNLOCK" != tang ] && \
        die "--tang-url only applies to --unlock tang (this image uses '$UNLOCK').
    Nothing else contacts a tang server, so the URL would never be read."
else
    # Everything above is reached only when the image is encrypted, so without
    # --encrypt these options were parsed, stored, and never looked at again --
    # including --unlock, which was not even checked for being one of the four
    # words. An operator who asks for TPM unlock and does not ask for encryption
    # got an unencrypted disk and no indication that the flag had been dropped,
    # which is the worst possible direction for this particular mistake to fail
    # in: the image is *less* protected than the command line describes.
    #
    # --luks-passphrase is worth refusing for a second reason. A passphrase on a
    # command line is in the shell history and the process table of whatever ran
    # it; spending that to configure nothing is a secret disclosed for no benefit.
    [ "$UNLOCK_SET" = true ] && die "--unlock $UNLOCK has no effect without --encrypt.
    The disk would not be encrypted, so there would be nothing to unlock. Add
    --encrypt, or drop --unlock."
    [ "$LUKS_PASS_SET" = true ] && die "--luks-passphrase has no effect without --encrypt.
    Add --encrypt, or drop the passphrase -- and treat it as disclosed either way,
    because it reached the shell history and the process table to do nothing."
    [ "$TANG_URL_SET" = true ] && die "--tang-url has no effect without --encrypt --unlock tang."
    [ "$TPM2_PCRS_SET" = true ] && die "--tpm2-pcrs has no effect without --encrypt --unlock tpm2."
fi

# --check-only stops here, having done every check that depends on the arguments
# alone and none that depend on the build host. Two jobs.
#
# It lets the writable-state options be validated without a 30-minute build and
# without root, which is what makes the combination rules testable at all -- the
# alternative is asserting that a message appears in the first few lines of a
# real build and killing it, on a host where a half-built image means leftover
# loop devices and mounts.
#
# And it gives the API one way to tell an operator their combination is refused
# *before* it queues the build, without a second copy of these rules in Go or
# TypeScript that drifts from this one. The rule that runs is the rule that
# decides.
if [ "$CHECK_ONLY" = true ]; then
    echo "state-model $STATE_MODEL"
    echo "upper $([ "$UPPER_MODE" = per-slot ] && echo per-slot || echo shared)"
    printf '%s\n' "$MOUNT_DIRECTIVES" | grep -v '^[[:space:]]*$' | sed 's/^/mount /'
    for _r in $RESET_PATHS; do echo "reset-on-update $_r"; done
    for _k in $KEEP_PATHS;  do echo "keep $_k"; done
    log "options check passed (no image was built)"
    exit 0
fi

# How big the overlay partition has to be *as built*, before the machine ever
# runs. It normally ships at its minimum and first-boot-expand grows it to fill
# the disk -- which is what keeps an image small enough to stream over PXE.
#
# But a `persist` or `slot-private` directive seeds its store from the image
# during the initramfs, which is before first-boot-expand has run: the partition
# has been grown by the imager, the filesystem inside it has not. Seeding /var
# into a 256 MiB filesystem fills it partway through, and what came out the other
# side was a machine with a truncated /var, no /usr/local, and nothing said.
if [ -z "$OVERLAY_MIN" ]; then
    if printf '%s\n' "$MOUNT_DIRECTIVES" | grep -qE '^(persist|slot-private) '; then
        OVERLAY_MIN=1024
    else
        OVERLAY_MIN=256
    fi
fi

# --- Resolve distro (auto-detect from suite when not given) ---
if [ -z "$DISTRO" ]; then
    case "$SUITE" in
        bionic|focal|jammy|noble|oracular|plucky|questing|resolute) DISTRO=ubuntu;;
        # An RPM suite is a bare major version. "9" is not a Debian codename and
        # never will be, so it is unambiguous -- but the default stays Debian, so
        # an unrecognised codename fails as a Debian suite rather than silently
        # becoming something else.
        8|9|10) DISTRO=almalinux;;
        *) DISTRO=debian;;
    esac
fi


# --- CPU baseline ------------------------------------------------------------
#
# RHEL 10 raised its baseline to x86-64-v3, so every binary in an el10 image --
# including the ones rpm runs as scriptlets during the build -- needs AVX2, BMI2
# and FMA. Those arrived with Haswell in 2013.
#
# Without this check the failure is not an error at all. dnf installs el10's
# glibc, runs its scriptlet, and the process spins in userspace forever: no
# message, no exit, no child, just 100% of a core at package 11 of 122. Two
# forty-minute hangs and a hypervisor reboot went into finding that out once.
#
# Checked against the BUILDER's CPU because that is where the scriptlets execute.
# It is also the machines' problem -- an image needing v3 will not boot on a v2
# machine either -- which the message says, because a builder that happens to be
# newer than the fleet would otherwise produce images nothing can run.
cpu_level() {
    # The levels are cumulative and defined by the psABI. Only x86 has them.
    local f="/proc/cpuinfo" lvl=1
    # No flags line at all means this is not an x86 CPU, so the question does not
    # apply -- an arm64 builder producing an amd64 image runs the target's binaries
    # under emulation and never executes them on this processor. Distinguished
    # from "x86 but too old" (0) because they need opposite answers: unknown must
    # not fail the build, and used to, since the flag scan below found nothing on
    # an arm64 host and reported the oldest possible x86.
    grep -q "^flags" "$f" 2>/dev/null || { echo -1; return; }
    grep -q " lm " "$f" 2>/dev/null || { echo 0; return; }
    for x in cx16 lahf_lm popcnt sse4_1 sse4_2 ssse3; do
        grep -qm1 " $x " "$f" 2>/dev/null || { echo 1; return; }
    done
    lvl=2
    for x in avx avx2 bmi1 bmi2 f16c fma abm movbe xsave; do
        grep -qm1 " $x " "$f" 2>/dev/null || { echo 2; return; }
    done
    lvl=3
    for x in avx512f avx512bw avx512cd avx512dq avx512vl; do
        grep -qm1 " $x " "$f" 2>/dev/null || { echo 3; return; }
    done
    echo 4
}

# What the target needs. Only the RPM family has raised its floor so far; Debian
# and Ubuntu still build for the original baseline.
REQUIRED_CPU_LEVEL=1
if [ "$FAMILY" = rpm ] && [ "$ARCH" = amd64 ]; then
    case "$SUITE" in
        10|11|12) REQUIRED_CPU_LEVEL=3;;
        9)        REQUIRED_CPU_LEVEL=2;;
    esac
fi

if [ "$ARCH" = amd64 ] && [ "$REQUIRED_CPU_LEVEL" -gt 1 ]; then
    HAVE_CPU_LEVEL="$(cpu_level)"
    if [ "$HAVE_CPU_LEVEL" -lt 0 ]; then
        warn "not an x86 build host, so the $DISTRO $SUITE CPU baseline
    (x86-64-v${REQUIRED_CPU_LEVEL}) cannot be checked here. The image will build under
    emulation; whether it RUNS is a property of the machines you deploy it to."
    elif [ "$HAVE_CPU_LEVEL" -lt "$REQUIRED_CPU_LEVEL" ]; then
        # `|| true` on both: a build host whose /proc/cpuinfo has no "model name"
        # line makes this pipeline fail, and under `set -e -o pipefail` a failed
        # assignment ends the script -- before the die below can say anything. The
        # symptom was a build that exited 1 having printed nothing at all, which is
        # the worst possible output from a check whose entire job is to explain.
        _model="$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed "s/^ *//" || true)"
        _missing=""
        for x in avx avx2 bmi1 bmi2 fma movbe abm; do
            grep -qm1 " $x " /proc/cpuinfo 2>/dev/null || _missing="$_missing $x"
        done
        die "$DISTRO $SUITE needs x86-64-v${REQUIRED_CPU_LEVEL}; this CPU provides v${HAVE_CPU_LEVEL}.

    CPU:     ${_model:-unknown}
    Missing:${_missing:- (see /proc/cpuinfo)}

    Nothing can be configured around this -- it is the processor, not the
    hypervisor. If this is a VM, check the CPU type is 'host' first, but a chip
    older than Haswell (2013) cannot provide v3 at all.

    Build $DISTRO 9 instead, which needs only v2. Note that machines imaged from
    a v3 image would need v3 themselves, so this is the fleet's constraint as
    much as the builder's."
    fi
    [ "$HAVE_CPU_LEVEL" -ge 0 ] && \
        log "CPU baseline: x86-64-v${HAVE_CPU_LEVEL} available, v${REQUIRED_CPU_LEVEL} required"
fi

# RPM images are new. The A/B overlay root and the LUKS bootstrap key now have
# dracut modules (usr/lib/dracut/modules.d), and the script behind each is the
# same one the deb family runs -- but no RPM image has been booted on real
# hardware yet, and a hook that runs at the wrong moment is not something a build
# can detect.
#
# Said out loud rather than refused, because both ways this can be wrong are
# recoverable rather than fatal: a mis-ordered LUKS hook falls back to prompting
# for the passphrase, and a missing overlay boots the slot read-only, which
# `ab.state=off` does deliberately. Neither leaves a machine that will not start.
if [ "$FAMILY" = rpm ]; then
    log "NOTE: $DISTRO images are newly supported and have not been booted on real
    hardware yet. The A/B overlay and LUKS-key dracut modules are included and the
    initramfs is checked for them, but if either hook runs at the wrong moment the
    symptoms are a passphrase prompt at boot (LUKS) or a read-only root with no
    slot selection (overlay) -- both recoverable, neither silent."
fi
# --- Resolve the build profile -----------------------------------------------
#
# Validated here, before anything is allocated or built, for the same reason the
# state manifest is: a wrong profile/desktop combination discovered after
# debootstrap has already cost twenty minutes, and the refusal has to happen
# while there is still a person at the other end to read it.
#
# PROFILE_PACKAGES joins the base --no-install-recommends install.
# DESKTOP_PACKAGES is installed in its own apt run WITH recommends -- see the
# chroot setup script for why the difference is the whole feature.
PROFILE_PACKAGES=""
DESKTOP_PACKAGES=""
case "$PROFILE" in
    minimal)
        # Exactly the base system, as this builder has always produced it. The
        # flag names today's behaviour; it must never add to it.
        ;;
    server)
        # What a headless server still lacks after the base install. The base
        # already ships openssh-server, curl, sudo and ca-certificates (see the
        # chroot setup script), so this is deliberately short:
        #   rsync  moving files and backups on/off the machine
        #   htop   "what is this machine doing right now"
        #   less   reading logs without an editor (minbase has no pager)
        #   nano   editing config over SSH without vi knowledge
        #   tmux   a shell that survives the SSH session dropping
        # Anything beyond this belongs in --packages, not baked into the
        # profile -- and notably NOT qemu-guest-agent: these images deploy to
        # real machines as often as VMs.
        if [ "$FAMILY" = rpm ]; then
            # Same five tools. less and nano are not in a minimal RPM install
            # either, and htop is in EPEL, which the RAUC build enables anyway.
            PROFILE_PACKAGES="rsync htop less nano tmux"
        else
            PROFILE_PACKAGES="rsync htop less nano tmux"
        fi
        ;;
    desktop)
        DESKTOP_ENV="${DESKTOP_ENV:-gnome}"
        # Each distro curates its own desktop metapackages, under different
        # names, and not every environment exists on both -- so the refusal
        # lists what IS available for the distro being built rather than
        # leaving the caller to guess a spelling.
        case "$DISTRO" in
            debian) DE_AVAILABLE="gnome kde xfce mate cinnamon lxqt";;
            ubuntu) DE_AVAILABLE="gnome kde xfce mate lxqt";;
            # What this family ships as groups. Fewer than Debian offers, and
            # naming one it does not have fails inside the chroot rather than here.
            almalinux|rocky|rhel) DE_AVAILABLE="gnome kde xfce";;
            *) die "--distro must be debian, ubuntu, almalinux or rocky (got '$DISTRO')";;
        esac
        case "$DISTRO/$DESKTOP_ENV" in
            almalinux/gnome|rocky/gnome|rhel/gnome) DESKTOP_META="Workstation";;
            almalinux/kde|rocky/kde|rhel/kde)       DESKTOP_META="KDE Plasma Workspaces";;
            almalinux/xfce|rocky/xfce|rhel/xfce)    DESKTOP_META="Xfce";;
            debian/gnome)    DESKTOP_META="task-gnome-desktop";;
            debian/kde)      DESKTOP_META="task-kde-desktop";;
            debian/xfce)     DESKTOP_META="task-xfce-desktop";;
            debian/mate)     DESKTOP_META="task-mate-desktop";;
            debian/cinnamon) DESKTOP_META="task-cinnamon-desktop";;
            debian/lxqt)     DESKTOP_META="task-lxqt-desktop";;
            ubuntu/gnome)    DESKTOP_META="ubuntu-desktop-minimal";;
            ubuntu/kde)      DESKTOP_META="kde-plasma-desktop";;
            ubuntu/xfce)     DESKTOP_META="xubuntu-core";;
            ubuntu/mate)     DESKTOP_META="ubuntu-mate-core";;
            ubuntu/lxqt)     DESKTOP_META="lubuntu-desktop";;
            *) die "--desktop: no '$DESKTOP_ENV' desktop for $DISTRO.
    Available for $DISTRO: $DE_AVAILABLE";;
        esac
        # network-manager explicitly, though most of the metas recommend it:
        # this profile exists for desktops and laptops, and a laptop without
        # NetworkManager has wifi hardware and no way to join a network from
        # the desktop it just logged in to. Redundant where the meta already
        # brings it, which costs nothing.
        DESKTOP_PACKAGES="$DESKTOP_META network-manager"
        # Debian only: firmware for the wifi/graphics hardware laptops actually
        # have. The image's sources.list already carries non-free-firmware (it
        # is written for every Debian build, further down), so these install
        # without touching the sources. Ubuntu needs none of this --
        # linux-image-generic hard-depends on linux-firmware, so every Ubuntu
        # image already ships the full firmware set.
        if [ "$DISTRO" = debian ]; then
            DESKTOP_PACKAGES="$DESKTOP_PACKAGES firmware-linux firmware-iwlwifi firmware-realtek firmware-atheros"
        fi
        ;;
    *) die "--profile must be minimal, server or desktop (got '$PROFILE')";;
esac
# Refused rather than ignored: someone who typed --desktop kde wanted a desktop
# image, and silently building a minimal one would only be discovered at a
# console login prompt on deployed hardware.
if [ "$DESKTOP_SET" = true ] && [ "$PROFILE" != desktop ]; then
    die "--desktop only means anything with --profile desktop (profile is '$PROFILE')"
fi

# Everything that differs between architectures is decided here rather than
# scattered through the build. amd64 keeps the hybrid BIOS+UEFI boot the fleet
# relies on; arm64 has no BIOS to fall back to and is UEFI-only, with its own
# GRUB target and fallback binary name.
case "$ARCH" in
    amd64)
        GRUB_PKGS="grub-pc grub-pc-bin grub-efi-amd64-bin"
        GRUB_EFI_TARGET="x86_64-efi"
        # Signed by Microsoft (shim) and by the distribution (GRUB). The
        # firmware trusts Microsoft's key; shim carries the distribution's and
        # verifies GRUB with it; GRUB verifies the kernel through shim's
        # protocol. Debian and Ubuntu both ship signed kernels by default, so
        # the chain is complete without anything of ours being signed -- which
        # is the whole reason to use theirs rather than enroll our own key on
        # every machine.
        SB_SHIM="shimx64.efi.signed"
        SB_GRUB="grubx64.efi.signed"
        SB_GRUB_DIR="x86_64-efi-signed"
        SB_MM="mmx64.efi.signed"
        SB_BOOT_NAME="BOOTX64.EFI"
        SB_GRUB_NAME="grubx64.efi"
        SB_MM_NAME="mmx64.efi"
        SB_PKGS="shim-signed grub-efi-amd64-signed"
        GRUB_BIOS=1
        QEMU_ARCH="x86_64"
        ;;
    arm64)
        GRUB_PKGS="grub-efi-arm64 grub-efi-arm64-bin"
        GRUB_EFI_TARGET="arm64-efi"
        SB_SHIM="shimaa64.efi.signed"
        SB_GRUB="grubaa64.efi.signed"
        SB_GRUB_DIR="arm64-efi-signed"
        SB_MM="mmaa64.efi.signed"
        SB_BOOT_NAME="BOOTAA64.EFI"
        SB_GRUB_NAME="grubaa64.efi"
        SB_MM_NAME="mmaa64.efi"
        SB_PKGS="shim-signed grub-efi-arm64-signed"
        GRUB_BIOS=0
        QEMU_ARCH="aarch64"
        ;;
    *) die "--arch must be amd64 or arm64 (got '$ARCH')";;
esac

# Cross-building needs the target architecture's interpreter registered with
# binfmt_misc on the host; the builder image ships the static qemu binaries but
# cannot register them itself. Checked here so the failure is one clear line
# rather than "Exec format error" a thousand lines into debootstrap.
# host_arch reports the builder's own architecture in this script's vocabulary
# (amd64/arm64). `dpkg --print-architecture` was the only way this was asked, and
# there is no dpkg in an RPM builder -- the check would have died on the probe
# rather than on the thing it was probing for.
host_arch() {
    case "$(uname -m)" in
        x86_64)  echo amd64;;
        aarch64) echo arm64;;
        *)       uname -m;;
    esac
}
HOST_ARCH="$(host_arch)"
if [ "$ARCH" != "$HOST_ARCH" ]; then
    if [ ! -e "/proc/sys/fs/binfmt_misc/qemu-${QEMU_ARCH}" ]; then
        die "building $ARCH on $HOST_ARCH needs binfmt support.
    Register the interpreters on the build host once:
        Debian/Ubuntu:  apt install qemu-user-static binfmt-support
        or:             docker run --privileged --rm tonistiigi/binfmt --install all"
    fi
    log "Cross-building $ARCH via qemu-${QEMU_ARCH} (binfmt registered)"
fi

case "$DISTRO" in
    debian)
        MIRROR="${MIRROR:-http://deb.debian.org/debian}"
        KERNEL_PKG="linux-image-${ARCH}"
        DEBOOTSTRAP_OPTS=""
        ;;
    ubuntu)
        MIRROR="${MIRROR:-http://archive.ubuntu.com/ubuntu}"
        # Ubuntu's generic kernel (linux-image-<arch> is Debian-only); rauc lives
        # in universe, so debootstrap and APT must enable it.
        KERNEL_PKG="linux-image-generic"
        DEBOOTSTRAP_OPTS="--components=main,universe"
        [ -f /usr/share/keyrings/ubuntu-archive-keyring.gpg ] && \
            DEBOOTSTRAP_OPTS="$DEBOOTSTRAP_OPTS --keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg"
        # Newer Ubuntu suites may postdate the builder's debootstrap; every Ubuntu
        # suite script is a symlink to the generic 'gutsy' script anyway.
        if [ ! -e "/usr/share/debootstrap/scripts/$SUITE" ] && [ -e /usr/share/debootstrap/scripts/gutsy ]; then
            ln -s gutsy "/usr/share/debootstrap/scripts/$SUITE"
        fi
        ;;
    almalinux|rocky|rhel)
        # The suite IS the major version for this family: there are no codenames,
        # and dnf wants --releasever. Default to the current stable rather than
        # guessing from a codename that does not exist.
        case "$SUITE" in
            ''|stable) SUITE=9;;
        esac
        case "$SUITE" in
            8|9|10) ;;
            *) die "--suite for $DISTRO must be a major version (8, 9 or 10), got '$SUITE'";;
        esac
        # One kernel package, named the same on every RPM distro, for every
        # architecture -- none of Debian's linux-image-<arch>/-generic split.
        KERNEL_PKG="kernel"
        # The release package carries the repo definitions and the GPG keys, so
        # it is what makes an empty installroot into a distribution. Its name is
        # the only thing that differs between these three.
        # The release package, and where to get it from.
        #
        # It cannot come from the builder's own repositories: a Rocky builder has
        # no almalinux-release and never will, so bootstrapping Alma from it fails
        # with "No match for argument: almalinux-release". The builder's
        # distribution should not decide which distributions it can build, so the
        # bootstrap repository points at the TARGET's mirror and the release
        # package comes from there.
        case "$DISTRO" in
            almalinux)
                # TWO packages, not one. AlmaLinux splits the repository
                # definitions out into almalinux-repos, and installing the release
                # package alone fails with "nothing provides almalinux-repos" --
                # so the installroot would have a distribution identity and no
                # repositories to install the distribution from.
                RELEASE_PKG="almalinux-release almalinux-repos"
                BOOTSTRAP_BASE="https://repo.almalinux.org/almalinux"
                ;;
            rocky)
                # Rocky ships its repo definitions inside rocky-release.
                RELEASE_PKG="rocky-release"
                BOOTSTRAP_BASE="https://dl.rockylinux.org/pub/rocky"
                ;;
            rhel)
                # No public mirror to bootstrap from; RHEL needs an entitled one.
                RELEASE_PKG="redhat-release"
                BOOTSTRAP_BASE=""
                ;;
        esac
        # RPM arch names, which differ from this script's own vocabulary.
        case "$ARCH" in
            amd64) RPM_ARCH="x86_64";;
            arm64) RPM_ARCH="aarch64";;
        esac
        # Empty by default: dnf reads the mirror list out of the release package,
        # which is what handles mirror selection and failover. A MIRROR here is
        # for a local mirror and overrides that.
        MIRROR="${MIRROR:-}"
        DEBOOTSTRAP_OPTS=""
        ;;
esac
# A build with no version given still gets one. An unversioned image is one the
# control plane cannot reason about: a rollout finishes when every machine
# reports the target version, and machines that all report the same string for
# two different builds can never be told apart.
IMAGE_VERSION="${IMAGE_VERSION:-$(date -u +%Y.%m.%d-%H%M)}"

case "$SECURE_BOOT" in
    auto|on|off) ;;
    *) die "--secure-boot must be auto, on or off (got '$SECURE_BOOT')";;
esac
# Installed in their own apt run rather than folded into the main one, because
# what happens when they are missing differs by mode. `on` must fail the build:
# a fleet that requires Secure Boot cannot be handed an image that quietly does
# not support it. `auto` must carry on: an unusual suite without signed shim
# packages should still produce a working image, just not a Secure Boot one.
#
# Additive either way -- with Secure Boot switched off in firmware, an image
# carrying shim boots exactly as it did before, and the BIOS path is untouched.
SB_SETUP=""
# The installer command differs, the policy does not. Templating the command
# keeps the three secure-boot modes -- and the reasoning about them -- in one
# place instead of two copies that would drift.
if [ "$FAMILY" = rpm ]; then
    PKG_INSTALL="dnf -y install --setopt=install_weak_deps=False"
else
    PKG_INSTALL="apt-get install -y --no-install-recommends"
fi
case "$SECURE_BOOT" in
    on)   SB_SETUP="${PKG_INSTALL} ${SB_PKGS}";;
    auto) SB_SETUP="${PKG_INSTALL} ${SB_PKGS} || \
              echo 'NOTE: no signed shim/GRUB in this suite; Secure Boot will be unsupported' >&2";;
esac
# Minimum workable root slot, measured per distro. Ubuntu's linux-image-generic
# hard-depends on linux-firmware and linux-modules-extra (~1.7 GiB installed),
# which Debian's linux-image-amd64 does not — so the same 3 GiB slot that is
# comfortable on Debian overflows on Ubuntu partway through initramfs
# generation. Enforced below rather than left to fail deep in a dpkg run.
case "$DISTRO" in
    ubuntu) MIN_ROOT=5120;;
    # The RPM family needs the same headroom, for a different reason. There is no
    # rauc package for it, so the toolchain to build one -- gcc, meson, ninja, git
    # and eight -devel packages -- is installed INTO the slot, used, and removed.
    # It is transient but it has to fit, on top of a base install that is already
    # larger than Debian's minbase. A 3 GiB slot runs out partway through that and
    # fails as "No space left on device" twenty minutes in, which is a true
    # message about the wrong thing.
    almalinux|rocky|rhel) MIN_ROOT=5120;;
    *)      MIN_ROOT=2560;;
esac
# A desktop environment is several GiB installed before the user's first login
# -- Debian's task-gnome-desktop with its recommends is the largest -- and a
# slot that cannot hold it fails as "No space left on device" an hour into dpkg,
# not here. Raise the floor for the profile the same way it is raised for
# Ubuntu's kernel: the caller asked for a desktop image, and a slot too small to
# hold one is never what they wanted.
if [ "$PROFILE" = desktop ]; then
    [ "$MIN_ROOT" -lt 10240 ] && MIN_ROOT=10240
fi
# The BOOT partition holds THREE copies of the kernel and initramfs: the
# versioned originals where dpkg puts them, and the per-slot /A and /B copies
# that make rollback carry its own kernel. A desktop initramfs is several
# times a minimal one -- MODULES=most pulls the DRM drivers in, and with them
# the amdgpu/nvidia firmware this profile installs -- so the historical 512
# overflows at the per-slot copy with a bare ENOSPC. Found in the field on the
# first real desktop build (2026-08-17), one line after "No error reported."
MIN_BOOT=512
if [ "$PROFILE" = desktop ]; then
    MIN_BOOT=2048
fi

OS_PRETTY="$(tr '[:lower:]' '[:upper:]' <<< "${DISTRO:0:1}")${DISTRO:1}"
HOSTNAME_="${HOSTNAME_:-${DISTRO}-ab}"
OUTPUT="${OUTPUT:-/output/${DISTRO}-${SUITE}-ab.img}"
# A bare filename means "in the output directory". Without this it lands in the
# builder's working directory instead, which is inside the container: the build
# reports success, and the image is thrown away with the container.
case "$OUTPUT" in /*) ;; *) OUTPUT="/output/${OUTPUT}";; esac

# systemd-resolved became a separate package in Debian 12 / Ubuntu 23.10; on
# older suites it ships inside systemd itself.
RESOLVED_PKG="systemd-resolved"
case "$SUITE" in bionic|focal|jammy) RESOLVED_PKG="";; esac

# --- family package names -----------------------------------------------------
#
# The arch block above named the Debian packages, because that is the only
# vocabulary it had. Rename them here, where the family is known. Kept in one
# place rather than spread through the arch cases so that adding an architecture
# and adding a distribution stay separate jobs.
# How this image's initramfs reaches the shared A/B scripts, for the state
# manifest that ships inside the image. Naming the other family's harness in a
# file left in /etc is how somebody later concludes the wrong one is in use --
# which the rpm branch's own `rm -rf /etc/initramfs-tools` exists to prevent.
if [ "$FAMILY" = rpm ]; then
    AB_HOOK_DESC="dracut hooks (usr/lib/dracut/modules.d/90ab-overlay)"
else
    AB_HOOK_DESC="initramfs-tools (etc/initramfs-tools/scripts/local-bottom/ab-overlay)"
fi

if [ "$FAMILY" = rpm ]; then
    case "$ARCH" in
        amd64)
            # grub2-pc is BIOS, grub2-efi-x64 + efibootmgr is UEFI. Both, because
            # the image does not know which firmware the machine it lands on has,
            # and the whole point is that it lands on machines.
            #
            # grub2-efi-x64-modules is not optional and not implied. The plain
            # grub2-efi-x64 package ships ZERO files under /usr/lib/grub -- it is
            # only the prebuilt signed binary -- so grub2-install has no
            # x86_64-efi/modinfo.sh to read and dies at the last step of the
            # build. `install_weak_deps=False` means it can never arrive by
            # accident. Verified with `dnf repoquery -l` on almalinux:9.
            GRUB_PKGS="grub2-pc grub2-efi-x64 grub2-efi-x64-modules grub2-tools efibootmgr"
            SB_PKGS="shim-x64 grub2-efi-x64"
            # Where this family's signed chain actually lives. The packages install
            # straight onto the ESP rather than into /usr/lib/shim as Debian's do,
            # and the names carry no ".signed" suffix.
            SB_SHIM="shimx64.efi"
            SB_GRUB="grubx64.efi"
            SB_MM="mmx64.efi"
            SB_GRUB_DIR=""            # not used on this family; the ESP is the source
            ;;
        arm64)
            # No BIOS on arm64, so no grub2-pc.
            GRUB_PKGS="grub2-efi-aa64 grub2-efi-aa64-modules grub2-tools efibootmgr"
            SB_PKGS="shim-aa64 grub2-efi-aa64"
            SB_SHIM="shimaa64.efi"
            SB_GRUB="grubaa64.efi"
            SB_MM="mmaa64.efi"
            SB_GRUB_DIR=""
            ;;
    esac
    # Present and named the same across this family.
    RESOLVED_PKG="systemd-resolved"
    # systemd-networkd is NOT PACKAGED for this family -- `dnf provides
    # */systemd-networkd.service` finds nothing on AlmaLinux 9. NetworkManager is
    # how these distributions do DHCP, so that is what gets installed and enabled,
    # and the networkd .network file is not written at all. Enabling a unit that
    # does not exist would fail the chroot script; making that failure non-fatal
    # would be worse, shipping a machine with no DHCP client and SSH as the only
    # way in.
    NETWORK_PKG="NetworkManager"
    NETWORK_UNIT="NetworkManager"
    # grub2-install, not grub-install. Same program, different name, and calling
    # the wrong one fails with "command not found" at the point where the image
    # gets its bootloader -- the last step, after everything expensive.
    GRUB_INSTALL="grub2-install"
    # /boot/grub2, not /boot/grub, and grub2-editenv, not grub-editenv. Every
    # place that writes grub.cfg or touches grubenv has to use these: the core
    # image grub2-install produces has prefix=($root)/grub2 baked in, so writing
    # the config to /boot/grub gives a clean build and a `grub rescue>` prompt.
    GRUBDIR="grub2"
    GRUB_EDITENV="grub2-editenv"
else
    GRUB_INSTALL="grub-install"
    GRUBDIR="grub"
    GRUB_EDITENV="grub-editenv"
    NETWORK_PKG=""
    NETWORK_UNIT="systemd-networkd"
fi

# The default slot is the historical 3072 MiB, lifted straight to the floor
# where the floor is higher -- so a default desktop or Ubuntu build starts at a
# size that fits rather than starting small and being raised with a warning
# about a number nobody typed. An explicit --root-size (or ROOT_SIZE in the
# environment) is honoured, subject only to the raise below.
if [ -z "$ROOT_SIZE" ]; then
    ROOT_SIZE=3072
    [ "$ROOT_SIZE" -lt "$MIN_ROOT" ] && ROOT_SIZE="$MIN_ROOT"
fi
# Same shape for the boot partition: the historical 512 unless the profile's
# floor is higher, an explicit value honoured subject to the raise below.
if [ -z "$BOOT_SIZE" ]; then
    BOOT_SIZE="$MIN_BOOT"
elif [ "$BOOT_SIZE" -lt "$MIN_BOOT" ]; then
    warn "boot partition ${BOOT_SIZE} MiB cannot hold three desktop-sized kernel+initramfs copies; using ${MIN_BOOT} MiB"
    BOOT_SIZE="$MIN_BOOT"
fi

# Raise rather than refuse: the caller asked for an image, and a slot too small
# to hold the OS is never what they wanted. The image still auto-sizes and the
# overlay still expands on first boot, so the only visible effect is a larger
# file — much better than failing 15 minutes in.
if [ "$ROOT_SIZE" -lt "$MIN_ROOT" ]; then
    warn "root slot ${ROOT_SIZE} MiB is below the ${MIN_ROOT} MiB minimum for $OS_PRETTY; using ${MIN_ROOT} MiB"
    ROOT_SIZE="$MIN_ROOT"
fi

OVERLAY_DIR="$(cd "$(dirname "$0")/overlay" && pwd)"
RAW="${OUTPUT%.img}.img"
WORK="$(mktemp -d)"
MNT="$WORK/mnt"
BOOTMNT="$WORK/mnt/boot"
KEYDIR="$WORK/keys"
LOOP=""
MAPPERS=()

cleanup() {
    set +e
    mountpoint -q "$MNT/dev/pts" && umount "$MNT/dev/pts"
    # The first two are the package-cache bind mount -- apt's for the deb family,
    # dnf's for the rpm one. Both are listed rather than the one this build used,
    # because cleanup runs on paths that may not be mounted anyway (mountpoint -q
    # guards each) and because a trap that has to know which family it is in is a
    # trap that gets this wrong. They are nested under $MNT and must come off
    # before $MNT itself, or the final umount fails and the loop device stays
    # attached -- which is how a failed build leaves the host with a leaked loop.
    for m in etc/resolv.conf var/cache/apt/archives var/cache/dnf dev proc sys boot/efi boot var/lib/overlay; do # family-ok: both families' cache paths on purpose; each is mountpoint-guarded
        mountpoint -q "$MNT/$m" && umount "$MNT/$m"
    done
    mountpoint -q "$WORK/b" && umount "$WORK/b"
    mountpoint -q "$MNT" && umount "$MNT"
    for m in "${MAPPERS[@]}"; do
        [ -e "/dev/mapper/$m" ] && cryptsetup close "$m" 2>/dev/null
    done
    [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

log "Building image  distro=$DISTRO suite=$SUITE  profile=$PROFILE$([ "$PROFILE" = desktop ] && echo "/$DESKTOP_ENV")  encrypt=$ENCRYPT  unlock=$([ "$ENCRYPT" = true ] && echo "$UNLOCK" || echo n/a)  ssh-key-only=$SSH_KEY_ONLY"

E_START=2
E_END=$((E_START + ESP_SIZE))
B_END=$((E_END + BOOT_SIZE))
A_END=$((B_END + ROOT_SIZE))
BB_END=$((A_END + ROOT_SIZE))
MIN_MIB=$((BB_END + OVERLAY_MIN + 1))   # +1 MiB tail for the backup GPT
if [ "$IMAGE_SIZE" = auto ]; then
    TOTAL_MIB=$MIN_MIB
    log "Auto image size: ${TOTAL_MIB} MiB (overlay expands to fill the target disk on first boot)"
else
    TOTAL_MIB=$((IMAGE_SIZE * 1024))
    [ "$TOTAL_MIB" -ge "$MIN_MIB" ] || \
        die "--image-size ${IMAGE_SIZE}G too small: layout needs ${MIN_MIB} MiB (reduce --root-size, or use --image-size auto)"
fi
rm -f "$RAW"
truncate -s "${TOTAL_MIB}M" "$RAW"

step "Partitioning (GPT, hybrid BIOS+UEFI, A/B)"
parted -s "$RAW" mklabel gpt
parted -s "$RAW" mkpart bios     1MiB ${E_START}MiB
parted -s "$RAW" set 1 bios_grub on
parted -s "$RAW" mkpart ESP      fat32 ${E_START}MiB ${E_END}MiB
parted -s "$RAW" set 2 esp on
parted -s "$RAW" mkpart BOOT     ext4 ${E_END}MiB    ${B_END}MiB
parted -s "$RAW" mkpart rootfs-a ext4 ${B_END}MiB    ${A_END}MiB
parted -s "$RAW" mkpart rootfs-b ext4 ${A_END}MiB    ${BB_END}MiB
parted -s "$RAW" mkpart overlay  ext4 ${BB_END}MiB   100%

# Docker gives this container a private /dev that no udev populates, so the loop
# device the kernel hands out often has no node here and losetup fails with
# "device node /dev/loopN (7:N) is lost. You may use mknod(1) to recover it."
# Create the nodes ourselves. (Docker Desktop pre-creates loop0-3 in its VM,
# which is why this can appear to work on a Mac and fail on a Linux host — and
# why it would fail anywhere once those four are busy.)
modprobe loop 2>/dev/null || true
[ -e /dev/loop-control ] || mknod /dev/loop-control c 10 237 2>/dev/null || true
for i in $(seq 0 15); do
    [ -e "/dev/loop$i" ] || mknod "/dev/loop$i" b 7 "$i" 2>/dev/null || true
done

LOOP="$(losetup -f --show -P "$RAW")" || die \
    "could not attach a loop device. The builder needs --privileged and a host
kernel with the loop module available (modprobe loop)."
log "Loop device: $LOOP"
partprobe "$LOOP" 2>/dev/null || true
LOOP_BASE="$(basename "$LOOP")"
for n in 1 2 3 4 5 6; do
    node="${LOOP}p${n}"
    [ -b "$node" ] && continue
    sysdev="/sys/class/block/${LOOP_BASE}p${n}/dev"
    for _ in 1 2 3 4 5; do [ -f "$sysdev" ] && break; sleep 0.3; done
    [ -f "$sysdev" ] && { mm="$(cat "$sysdev")"; mknod "$node" b "${mm%:*}" "${mm#*:}"; }
done
P_ESP="${LOOP}p2"; P_BOOT="${LOOP}p3"; P_A="${LOOP}p4"; P_B="${LOOP}p5"; P_OVL="${LOOP}p6"
[ -b "$P_BOOT" ] || { echo "partition nodes missing under $LOOP" >&2; ls -l ${LOOP}* >&2; exit 1; }

# --- Set up encryption (or plain) backing devices ---
# DEV_* is the device we mkfs/mount (a mapper when encrypted). BOOT is always plain.
DEV_A="$P_A"; DEV_B="$P_B"; DEV_OVL="$P_OVL"
if [ "$ENCRYPT" = true ]; then
    log "Encrypting root slots and overlay (LUKS2)"
    mkdir -p "$KEYDIR"
    [ "$USE_KEYFILE" = true ] && { head -c 4096 /dev/urandom > "$KEYDIR/keyfile"; chmod 400 "$KEYDIR/keyfile"; }
    # Use PBKDF2 (not memory-hard Argon2id) so the root volume can be unlocked in
    # the low-memory early-boot initramfs on any target. The high-entropy keyfile
    # / TPM / Tang key makes KDF hardness irrelevant; the passphrase slot still
    # gets strong iteration counts.
    PBKDF_OPTS="--pbkdf pbkdf2 --pbkdf-force-iterations 200000"
    luks_setup() {  # $1=partition $2=mapper-name
        printf '%s' "$LUKS_PASS" | cryptsetup luksFormat --type luks2 $PBKDF_OPTS --batch-mode "$1" -
        printf '%s' "$LUKS_PASS" | cryptsetup open "$1" "$2" -
        MAPPERS+=("$2")
        if [ "$USE_KEYFILE" = true ]; then
            printf '%s' "$LUKS_PASS" | cryptsetup luksAddKey $PBKDF_OPTS --key-file=- "$1" "$KEYDIR/keyfile"
        fi
    }
    # Build-time mapper names, unique to this build. NOT the names the installed
    # system uses -- those are fixed (luks-rootfs-a and friends) and written
    # into crypttab and rauc/system.conf further down, where they have to be
    # stable. These only exist while the builder is writing the image.
    #
    # They used to be the same names, which failed two ways. A build killed
    # before its cleanup trap ran left the mappings behind, and every later
    # build died on "Device luks-rootfs-a already exists." Worse, building an
    # image on a machine that is itself an A/B system would collide with that
    # machine's own live root mapping -- and the cleanup would then close it.
    #
    # Random rather than $$: containers share the host's device-mapper
    # namespace, and two concurrent builds are quite likely to both be PID 7.
    MAPTAG="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    for _m in "abbuild-${MAPTAG}-a" "abbuild-${MAPTAG}-b" "abbuild-${MAPTAG}-ovl"; do
        [ -e "/dev/mapper/$_m" ] && die "mapper $_m already exists; rerun the build"
    done
    luks_setup "$P_A"   "abbuild-${MAPTAG}-a"
    luks_setup "$P_B"   "abbuild-${MAPTAG}-b"
    luks_setup "$P_OVL" "abbuild-${MAPTAG}-ovl"
    DEV_A="/dev/mapper/abbuild-${MAPTAG}-a"
    DEV_B="/dev/mapper/abbuild-${MAPTAG}-b"
    DEV_OVL="/dev/mapper/abbuild-${MAPTAG}-ovl"
fi

step "Formatting filesystems"
# The builder runs Debian trixie, whose mke2fs (1.47.x) enables orphan_file and
# metadata_csum_seed by default. GRUB 2.06 — what Ubuntu 22.04 ships — cannot
# read either, so grub-install dies with a bare "error: unknown filesystem"; the
# target's own older e2fsprogs would fail to fsck them too. Debian trixie's GRUB
# 2.12 copes, which is exactly why this only ever broke Ubuntu images. Turning
# both off costs nothing measurable and keeps images readable by older tooling.
# ...but only the ones THIS mke2fs knows about. Rocky 9 ships e2fsprogs 1.46.5,
# which predates orphan_file entirely, and mke2fs rejects a feature name it does
# not recognise -- so hardcoding the list turned "make the image readable by older
# tooling" into "cannot format a filesystem at all" on the older tooling.
#
# Each is probed against a throwaway sparse file with -n, which reports what would
# be done and creates nothing. A feature this mke2fs has never heard of is one it
# also does not enable, so dropping it from the list is not a compromise: the
# reason for disabling it does not exist here.
EXT4_PROBE="$WORK/.mke2fs-probe"
: > "$EXT4_PROBE"
truncate -s 16M "$EXT4_PROBE" 2>/dev/null || dd if=/dev/zero of="$EXT4_PROBE" bs=1M count=16 2>/dev/null
EXT4_COMPAT=""
for _feat in orphan_file metadata_csum_seed; do
    if mke2fs -n -q -F -O "^$_feat" "$EXT4_PROBE" >/dev/null 2>&1; then
        EXT4_COMPAT="${EXT4_COMPAT:+$EXT4_COMPAT,}^$_feat"
    else
        log "mke2fs does not know '$_feat'; it cannot enable it either, so nothing to disable"
    fi
done
rm -f "$EXT4_PROBE"
# -O with an empty argument is not the same as omitting it, so the flag is built
# rather than the value.
EXT4_OPTS=""
[ -n "$EXT4_COMPAT" ] && EXT4_OPTS="-O $EXT4_COMPAT"

mkfs.vfat -F32 -n EFI    "$P_ESP" >/dev/null
mkfs.ext4 -q $EXT4_OPTS -L BOOT     "$P_BOOT"
mkfs.ext4 -q $EXT4_OPTS -L rootfs-a "$DEV_A"
mkfs.ext4 -q $EXT4_OPTS -L rootfs-b "$DEV_B"
mkfs.ext4 -q $EXT4_OPTS -L overlay  "$DEV_OVL"

step "Mounting root slot A"
mkdir -p "$MNT"
mount "$DEV_A" "$MNT"
mkdir -p "$BOOTMNT" "$MNT/var/lib/overlay"
mount "$P_BOOT" "$BOOTMNT"
mkdir -p "$BOOTMNT/efi"
mount "$P_ESP" "$BOOTMNT/efi"
mount "$DEV_OVL" "$MNT/var/lib/overlay"

step "Bootstrapping $OS_PRETTY $SUITE ($ARCH)"
if [ "$FAMILY" = deb ]; then
    debootstrap --arch="$ARCH" --variant=minbase $DEBOOTSTRAP_OPTS \
        --include=systemd-sysv,ifupdown,netbase \
        "$SUITE" "$MNT" "$MIRROR"
else
    # dnf --installroot is this family's debootstrap. The release package is what
    # turns an empty directory into a distribution: it carries the repository
    # definitions and, more importantly, the GPG keys those repositories are
    # verified against.
    #
    # --nogpgcheck applies to THIS transaction only, and only because the keys
    # arrive inside the very package being installed -- there is nothing to
    # verify against until it lands. Every transaction after this one, including
    # the whole package install below, is verified normally. Installing the
    # release package on its own first, rather than alongside everything else,
    # is what keeps that window to one package.
    # A repository defined here, not one of the builder's. --repofrompath is what
    # makes the builder's own distribution irrelevant to which distributions it
    # can build.
    BOOTSTRAP_URL="${MIRROR:-$BOOTSTRAP_BASE/$SUITE/BaseOS/$RPM_ARCH/os}"
    [ -n "$BOOTSTRAP_URL" ] || die "no bootstrap mirror for $DISTRO — pass --mirror with a BaseOS repository URL"
    RPM_REPO_ARGS="--repofrompath=abbootstrap,$BOOTSTRAP_URL --disablerepo=* --enablerepo=abbootstrap"
    dnf -y --installroot="$MNT" --releasever="$SUITE" \
        --setopt=install_weak_deps=False --nogpgcheck $RPM_REPO_ARGS \
        install $RELEASE_PKG \
        || die "could not bootstrap $DISTRO $SUITE from $BOOTSTRAP_URL.
    Check the mirror is reachable and that $SUITE is a release it carries for $RPM_ARCH."

    # The release package put its GPG keys INSIDE the installroot, but the repo
    # definitions reference them as file:///etc/pki/rpm-gpg/..., and dnf resolves
    # a file:// URI against the BUILDER's root -- not the installroot it is
    # populating. So the next transaction looks for the key where it is not:
    #
    #   Curl error (37): Couldn't read a file:// file for
    #   file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-10
    #
    # Copying them out is what makes the URI resolve, and importing them into the
    # installroot's own rpmdb is what makes the packages actually checked against
    # them. Both, because either alone is a transaction that either cannot read
    # the key or does not verify with it.
    #
    # This is also what lets one builder build any release of any RPM distro: the
    # keys come from the release package each time rather than from whatever the
    # builder happens to ship. Building Rocky 10 on a Rocky 9 builder is exactly
    # the case that found this, and it is the normal case, not an odd one.
    mkdir -p /etc/pki/rpm-gpg
    cp -a "$MNT"/etc/pki/rpm-gpg/. /etc/pki/rpm-gpg/ 2>/dev/null || true
    rpm --root="$MNT" --import "$MNT"/etc/pki/rpm-gpg/RPM-GPG-KEY-* 2>/dev/null || true

    # Now the keys are in place, so everything else is verified. Verified for
    # real: with the wrong key present this transaction is refused, which is the
    # only thing that makes the --nogpgcheck above a one-package window rather
    # than a habit.
    # No $RPM_REPO_ARGS here: the release package has just defined the real
    # repositories inside the installroot, and those are the ones with the whole
    # distribution in them. The bootstrap repo was BaseOS alone and exists only to
    # get that package.
    dnf -y --installroot="$MNT" --releasever="$SUITE" \
        --setopt=install_weak_deps=False \
        install dnf systemd passwd \
        || die "could not install the base system into the installroot"
fi

step "Binding pseudo-filesystems for chroot"
mount --bind /dev "$MNT/dev"
mount --bind /dev/pts "$MNT/dev/pts"
mount -t proc proc "$MNT/proc"
mount -t sysfs sys "$MNT/sys"

# upper and work are the overlay root's two layers. There is no third
# directory: a "persistent" one was created here and never used by anything,
# which read as a supported place to put data that nothing would have kept.
#
# With --slot-private-upper there is one pair per slot instead of one pair, and
# both are created here rather than left to the initramfs: an empty upper-B on a
# freshly imaged disk is what makes "boot the other slot" a clean state rather
# than a directory the engine has to invent on a machine that may be in trouble.
if [ "$UPPER_MODE" = per-slot ]; then
    mkdir -p "$MNT/var/lib/overlay/upper-A" "$MNT/var/lib/overlay/work-A" \
             "$MNT/var/lib/overlay/upper-B" "$MNT/var/lib/overlay/work-B"
else
    mkdir -p "$MNT/var/lib/overlay/upper" "$MNT/var/lib/overlay/work"
fi

step "Writing base configuration"
echo "$HOSTNAME_" > "$MNT/etc/hostname"
cat > "$MNT/etc/hosts" <<EOF
127.0.0.1   localhost
127.0.1.1   $HOSTNAME_
::1         localhost ip6-localhost ip6-loopback
EOF

cat > "$MNT/etc/fstab" <<EOF
# <file system>            <mount point>      <type> <options>      <dump> <pass>
LABEL=BOOT                 /boot              ext4   defaults       0      2
LABEL=EFI                  /boot/efi          vfat   umask=0077     0      1
# The initramfs already mounts this and binds it here before switching root,
# so the entry is x-systemd.automount-free and marked nofail: it is a no-op
# on an overlay-root boot, and the real mount when booted with ab.overlay=off.
LABEL=overlay              /var/lib/overlay   ext4   defaults,nofail 0     2
tmpfs                      /tmp               tmpfs  defaults       0      0
EOF

# Repository configuration, which is the one piece of base config that has no
# common spelling between the families.
#
# The rpm family needs nothing written here: the distribution's *-release package
# installed during the bootstrap ships /etc/yum.repos.d/*.repo already, pointing
# at the vendor mirrorlist and resolving $releasever from the /etc/os-release
# that came with it. Writing apt's file for that family is not merely useless --
# an rpm root has no /etc/apt at all, so the redirect dies and takes the build
# with it, which is exactly what it did.
if [ "$FAMILY" = deb ]; then
    if [ "$DISTRO" = ubuntu ]; then
        cat > "$MNT/etc/apt/sources.list" <<EOF
deb $MIRROR $SUITE main universe
deb $MIRROR ${SUITE}-updates main universe
deb http://security.ubuntu.com/ubuntu ${SUITE}-security main universe
EOF
    else
        cat > "$MNT/etc/apt/sources.list" <<EOF
deb $MIRROR $SUITE main contrib non-free-firmware
deb $MIRROR ${SUITE}-updates main contrib non-free-firmware
deb http://security.debian.org/debian-security ${SUITE}-security main contrib non-free-firmware
EOF
    fi
fi

# DHCP on every wired interface. networkd for the deb family; the rpm family has
# no systemd-networkd package at all (not a different name -- `dnf provides
# */systemd-networkd.service` finds nothing on el9), so NetworkManager does it,
# and its default behaviour for an unconfigured wired device is already DHCP.
#
# Writing the .network file for both families and enabling networkd on neither
# would leave an rpm machine with no DHCP client, unreachable over the SSH that
# is the only way into it.
if [ "$FAMILY" = deb ]; then
    cat > "$MNT/etc/systemd/network/10-dhcp.network" <<EOF
[Match]
Name=en* eth*

[Network]
DHCP=yes
EOF
fi

# --- crypttab + key material (before installing the initramfs) ---
CRYPT_PACKAGES=""
if [ "$ENCRYPT" = true ]; then
    if [ "$FAMILY" = rpm ]; then
        # dracut ships the crypt module itself, so there is no separate hook
        # package to install -- cryptsetup-initramfs is initramfs-tools' and has
        # no counterpart here.
        CRYPT_PACKAGES="cryptsetup"
    else
        CRYPT_PACKAGES="cryptsetup cryptsetup-initramfs"
    fi
    # Both auto-unlock methods go through clevis, because clevis-initramfs is
    # the only one of the available mechanisms that Debian's initramfs-tools
    # can call at unlock time. tpm2 used to use systemd-cryptenroll and write
    # `tpm2-device=auto` into crypttab -- a systemd-cryptsetup option, which
    # this initrd is not and never invokes. Enrollment succeeded, the keyslot
    # was real, and nothing in the boot path could use it. See luks-enroll.sh.
    # No explicit libtss2-*: clevis-tpm2 depends on tpm2-tools, which pulls the
    # whole TCTI set including the device one. The old list named
    # libtss2-tcti-device0, which no longer exists in trixie and installs today
    # only through a transitional Provides on libtss2-tcti-device0t64 -- a name
    # that will rot. Depending on clevis-tpm2 is the durable spelling.
    if [ "$FAMILY" = rpm ]; then
        # clevis-dracut rather than clevis-initramfs, and clevis-pin-tpm2 carries
        # the TPM2 pin on this family.
        [ "$UNLOCK" = tpm2 ] && CRYPT_PACKAGES="$CRYPT_PACKAGES clevis clevis-luks clevis-dracut clevis-pin-tpm2 tpm2-tools"
        [ "$UNLOCK" = tang ] && CRYPT_PACKAGES="$CRYPT_PACKAGES clevis clevis-luks clevis-dracut curl"
    else
        [ "$UNLOCK" = tpm2 ] && CRYPT_PACKAGES="$CRYPT_PACKAGES clevis clevis-luks clevis-initramfs clevis-tpm2 tpm2-tools"
        [ "$UNLOCK" = tang ] && CRYPT_PACKAGES="$CRYPT_PACKAGES clevis clevis-luks clevis-initramfs curl"
    fi

    if [ "$USE_KEYFILE" = true ]; then
        # Bootstrap unlock. For tpm2/tang this only bootstraps the first boot;
        # the enrollment service then binds the TPM/Tang and reaps this key.
        #
        # The key lives on the BOOT partition, not in the root slot. It used to
        # be installed into /etc/cryptsetup-keys.d/ and pulled into the initramfs
        # by KEYFILE_PATTERN -- which made it part of the image, and therefore
        # part of every bundle built from that image. `head -c 4096 /dev/urandom`
        # runs per build, so a bundle delivered the *builder's* key and its
        # initramfs then tried it against this machine's volumes:
        #
        #   No key available with this passphrase.
        #   cryptsetup: ERROR: luks-rootfs-a: maximum number of tries exceeded
        #   ALERT!  LABEL=rootfs-b does not exist.  Dropping to a shell!
        #
        # Same disease as the crypttab UUIDs above, in the key material rather
        # than the addressing: an update must not carry anything that belongs to
        # one disk. BOOT is shared by both slots and is not part of a bundle, so
        # a key there survives an update; scripts/init-premount/ab-luks-key
        # copies it into the initramfs at boot, before cryptroot runs.
        #
        # No new exposure: the keyfile was already sitting on this same plaintext
        # partition, inside the initramfs. It is now there once instead of once
        # per initramfs, and it stops being copied into every image built.
        install -d -m700 "$BOOTMNT/ab-keys"
        install -m400 "$KEYDIR/keyfile" "$BOOTMNT/ab-keys/luks.key"
        KEYREF_A=/cryptkey/luks.key
        KEYREF_B=/cryptkey/luks.key
        KEYREF_OVL=/cryptkey/luks.key
    else
        KEYREF_A=none; KEYREF_B=none; KEYREF_OVL=none
    fi

    NETOPT=""
    [ "$UNLOCK" = tang ] && NETOPT=",_netdev"
    # `initramfs` on every entry is what actually gets these devices unlocked
    # early. cryptsetup-initramfs otherwise includes only the device it resolves
    # as root at build time -- which is slot A, because that is what the builder
    # is standing in. Without the option, booting slot B cannot unlock its own
    # root, and the overlay is not opened until well after the switch to root,
    # far too late to serve as root's upper layer.
    #
    # PARTLABEL, not the LUKS UUID. `cryptsetup luksUUID` returns a value created
    # by that luksFormat, so a crypttab written from it describes the loopback
    # file this build happened to use and nothing else. That is fine for the
    # machine imaged from it, and fatal for an update: a bundle carries this
    # rootfs *and* the initramfs generated from it, so installing one built from
    # a different image hands the machine three UUIDs that exist nowhere on its
    # disk. It boots to
    #
    #   cryptsetup: Waiting for encrypted source device UUID=...
    #
    # forever, on all three volumes at once, and the only clue that this is about
    # provenance rather than encryption is that *none* of them resolve.
    #
    # The partition labels come from `parted mkpart` above, are identical in
    # every build, and survive being written to a disk because they live in the
    # GPT. Debian resolves PARTLABEL= with blkid rather than a udev symlink
    # (/lib/cryptsetup/functions, _resolve_device_spec), so it works this early.
    # system.conf already addressed the slots this way; this is the same rule --
    # nothing unique to one disk belongs in an image that gets copied.
    # The option that marks an entry for the initramfs is spelled differently by
    # the two harnesses: initramfs-tools reads `initramfs`, systemd-cryptsetup
    # (which is what dracut uses) reads `x-initrd.attach`. Both are emitted -- each
    # ignores the other's as an unknown option -- rather than branching, so the
    # file is identical on both families and there is one less thing to keep in
    # step. Without the systemd spelling an encrypted RHEL machine reaches the
    # dracut emergency shell with no unlock rule at all.
    CRYPTOPTS="luks,discard,initramfs,x-initrd.attach"
    cat > "$MNT/etc/crypttab" <<EOF
# <name>          <device>                 <keyfile>     <options>
#
# Addressed by partition label so this file is true on any machine imaged from
# any build. Do not "fix" these to UUIDs: see build-image.sh for what that costs.
luks-rootfs-a     PARTLABEL=rootfs-a       $KEYREF_A     $CRYPTOPTS$NETOPT
luks-rootfs-b     PARTLABEL=rootfs-b       $KEYREF_B     $CRYPTOPTS$NETOPT
luks-overlay      PARTLABEL=overlay        $KEYREF_OVL   $CRYPTOPTS$NETOPT
EOF
fi

# The desktop metas get their own apt run WITH recommends -- the opposite of
# every other install here, and the difference is the whole feature. Debian's
# task-* packages and Ubuntu's flavour metas carry most of the actual desktop
# (xorg, the display manager, network-manager, the applications) as Recommends,
# because that is how tasksel installs them; under --no-install-recommends
# task-xfce-desktop unpacks a few hundred kilobytes of metapackage and the
# "desktop" image boots to a console. Kept out of the base line so the base
# system itself still takes no recommends.
#
# set-default is belt and braces: the display manager's postinst normally flips
# the default target, but "normally" is not a boot guarantee, and a desktop
# image that comes up at a text console looks exactly like a failed build to
# whoever is standing at the machine.
#
# No backticks or $( ) in this fragment: the heredoc below is unquoted, so they
# would be command substitution executed by the builder, not text.
# networkd is disabled again for this profile because the desktop install
# brings NetworkManager, and two DHCP clients managing the same NIC fight over
# the address -- networkd is enabled a few lines earlier in the same script, so
# the fragment runs after it and simply wins. NM covers wired and wifi both,
# which is the point on a laptop; the 10-dhcp.network file stays behind, inert,
# for anyone who deliberately re-enables networkd.
DESKTOP_SETUP=""
if [ "$PROFILE" = desktop ]; then
    if [ "$FAMILY" = rpm ]; then
        # Groups, not metapackages: this family expresses "a desktop" as a group.
        #
        # $DESKTOP_META quoted and on its own, NOT $DESKTOP_PACKAGES. The group
        # names here are multi-word ("KDE Plasma Workspaces"), so an unquoted
        # expansion word-splits into "Module or Group 'Plasma' does not exist" --
        # and DESKTOP_PACKAGES has Debian's `network-manager` appended to it,
        # which is neither a group nor the right spelling of the package on this
        # family. NetworkManager is already installed and enabled for every rpm
        # image, so there is nothing extra to add here.
        DESKTOP_SETUP="dnf -y group install \"${DESKTOP_META}\"
systemctl set-default graphical.target"
    else
        DESKTOP_SETUP="apt-get install -y ${DESKTOP_PACKAGES}
systemctl set-default graphical.target
systemctl disable systemd-networkd"
    fi
fi

step "Installing kernel, bootloader, and tooling in chroot"
# Keep APT's downloaded .debs OUT of the root slot. Ubuntu pulls ~460 MB of
# archives (linux-firmware and linux-modules-extra dominate), and holding those
# alongside the unpacked files is enough on its own to exhaust a 3 GiB slot —
# initramfs generation then dies with a bare "No space left on device". The
# cache lives on the builder's own filesystem instead and is discarded after.
# PKGCACHE_MNT is remembered rather than re-derived at teardown. The teardown
# used to name the apt path outright, so an rpm build -- which binds the dnf
# directory instead -- tried to unmount something that was never mounted and
# died there, right after the longest step in the build.
if [ "$FAMILY" = deb ]; then
    PKGCACHE="$WORK/aptcache"
    PKGCACHE_MNT="$MNT/var/cache/apt/archives"
else
    # Same reasoning, different directory: dnf's cache is as large as apt's and
    # would come out of the same slot.
    PKGCACHE="$WORK/dnfcache"
    PKGCACHE_MNT="$MNT/var/cache/dnf"
fi
mkdir -p "$PKGCACHE" "$PKGCACHE_MNT"
mount --bind "$PKGCACHE" "$PKGCACHE_MNT"

# DNS for the package install, which runs INSIDE the image.
#
# A chroot keeps the builder's network namespace but not its /etc, so the
# resolver config has to be there or nothing resolves. debootstrap copies the
# builder's in by itself; `dnf --installroot` does not, so the rpm family had no
# /etc/resolv.conf at all and every chroot transaction died on
# "Could not resolve host: mirrors.almalinux.org".
#
# Bind-mounted, NOT copied, and that half matters for the family that already
# worked: debootstrap's copy is left behind in the finished image, so every
# Debian image built here has shipped the BUILDER's nameserver as a static file
# -- on this host, the build container sees the LAN's resolver and a `search`
# domain, so the images work on that subnet and have no DNS anywhere else.
# systemd-resolved never corrects it, because it only takes over /etc/resolv.conf
# when that path is a symlink. A bind mount leaves nothing to ship.
#
# Removed first: the file may be a regular file (debootstrap's copy) or a
# dangling symlink into /run (what systemd-resolved's package leaves), and a bind
# mount onto a dangling symlink fails.
rm -f "$MNT/etc/resolv.conf"
: > "$MNT/etc/resolv.conf"
mount --bind /etc/resolv.conf "$MNT/etc/resolv.conf"

if [ "$FAMILY" = rpm ]; then
cat > "$MNT/tmp/setup.sh" <<CHROOT
set -euo pipefail

# dracut, not initramfs-tools: it is what an RPM distribution generates an initrd
# with, and the kernel package expects it to be there.
#
# tar and gzip are here because RAUC needs them to apply an update, and nothing
# else in this image does. A bundle's payload is rootfs.tar.gz -- rauc's ext4
# handler makes a fresh filesystem and shells out to \`tar\` to extract into it --
# so an image without tar can be built, booted and imaged onto machines, and can
# never be updated:
#
#   Failed updating slot rootfs.1: failed to start tar extract:
#   Failed to execute child process "tar" (No such file or directory)
#
# after a full download and a verified signature, at 99%.
#
# This is a family difference, not an oversight in the abstract: tar is Essential
# on Debian, so debootstrap always provides it and the deb path never had to ask.
# \`dnf --installroot\` installs what it is told and nothing else. gzip happened to
# arrive as somebody else's dependency, which is not the same as being required.
#
# The profile and caller-supplied packages are NOT in this transaction. The
# server profile asks for htop, which is in EPEL only (confirmed: it is in no
# base el9 repository), and EPEL is not enabled until the RAUC section below --
# so putting them here failed the whole first transaction with "Unable to find a
# match: htop", naming a monitoring tool for what was really an ordering
# mistake. They are installed after EPEL and CRB instead.
dnf -y install --setopt=install_weak_deps=False \
    ${KERNEL_PKG} dracut ${GRUB_PKGS} \
    openssh-server sudo ca-certificates curl \
    ${RESOLVED_PKG} ${NETWORK_PKG} cloud-utils-growpart gdisk parted e2fsprogs \
    tar gzip \
    ${CRYPT_PACKAGES}

# --- RAUC, built from source -------------------------------------------------
#
# There is no rauc package for this family: not in base, not in EPEL. Verified,
# not assumed -- \`dnf list rauc\` on a stock Rocky 9 with EPEL enabled returns
# "No matching Packages". So the A/B update mechanism, which is the whole point
# of the image, has to be built.
#
# It is built INSIDE the image and then the toolchain is removed, rather than
# built on the builder and copied in: rauc links against this distribution's
# glib, openssl, curl and libnl, and a binary built elsewhere would be linked
# against another distribution's versions of all four.
#
# CRB (CodeReady Builder) carries meson, ninja and several -devel packages and is
# not enabled by default. EPEL is needed for its own reasons and enabling it
# first is what makes CRB's name resolvable on all of these.
dnf -y install epel-release || true
dnf -y install 'dnf-command(config-manager)' || true
dnf config-manager --set-enabled crb 2>/dev/null || \
    dnf config-manager --set-enabled powertools 2>/dev/null || true

# Now that EPEL is on, the packages that needed it. Held back from the base
# transaction above rather than moving EPEL earlier, because the base system
# should not depend on a third-party repository being reachable.
if [ -n "${PROFILE_PACKAGES}${EXTRA_PACKAGES}" ]; then
    dnf -y install --setopt=install_weak_deps=False \
        ${PROFILE_PACKAGES} ${EXTRA_PACKAGES}
fi

RAUC_BUILD_PKGS="meson ninja-build gcc git glib2-devel openssl-devel libcurl-devel \
    json-glib-devel dbus-devel systemd-devel libnl3-devel libfdisk-devel"
dnf -y install --setopt=install_weak_deps=False \$RAUC_BUILD_PKGS

git clone --depth 1 --branch "${RAUC_VERSION}" https://github.com/rauc/rauc.git /tmp/rauc
cd /tmp/rauc
meson setup build --prefix=/usr -Dsystemd=enabled -Dservice=true
ninja -C build
ninja -C build install
cd /
rm -rf /tmp/rauc

# The same check the deb path makes, and for the same reason: without the D-Bus
# service file, "rauc install" and "rauc status" both fail with "de.pengutronix.rauc
# was not provided by any .service files" -- so the machine can never be updated,
# and nothing says why until somebody tries.
if [ ! -e /usr/share/dbus-1/system-services/de.pengutronix.rauc.service ]; then
    echo "ERROR: RAUC built but its D-Bus service file is missing; this image could never be updated" >&2
    exit 1
fi
rauc --version

# Keep the libraries rauc actually links against.
#
# rauc is built from source here, so rpm has no record that anything needs its
# runtime libraries. dnf's clean_requirements_on_remove is on by default, so
# \`dnf remove \$RAUC_BUILD_PKGS\` takes the base libraries out along with the
# -devel packages that pulled them in -- json-glib in particular. Confirmed on a
# stock AlmaLinux 9: installing json-glib-devel then removing it leaves no
# json-glib behind, before autoremove is even reached. The image
# builds, verifies, boots and images machines perfectly; the breakage appears
# later, on a machine, in the middle of an update:
#
#   rauc: error while loading shared libraries: libjson-glib-1.0.so.0:
#   cannot open shared object file: No such file or directory
#
# and the machine cannot be updated by the mechanism that exists to update it.
#
# Derived from the binary rather than listed by hand: rauc gains and drops
# dependencies between releases, and a hand-kept list is one somebody has to
# remember to change. Marking them explicitly installed is what makes autoremove
# leave them alone.
RAUC_RUNTIME_PKGS="\$(ldd /usr/bin/rauc 2>/dev/null | awk '/=> \\//{print \$3}' \
    | xargs -r rpm -qf --queryformat '%{NAME}\\n' 2>/dev/null | sort -u | tr '\\n' ' ')"
if [ -n "\$RAUC_RUNTIME_PKGS" ]; then
    echo "rauc runtime packages kept: \$RAUC_RUNTIME_PKGS"
    dnf -y mark install \$RAUC_RUNTIME_PKGS 2>/dev/null || true
fi

# The toolchain is build-time only. Left in, it is several hundred megabytes of
# compiler in every image and a larger attack surface on every machine.
dnf -y remove \$RAUC_BUILD_PKGS || true
dnf -y autoremove || true
dnf clean all

# Verified AFTER the cleanup, not before.
#
# The check above ran before the removal, so it proved the build worked and
# nothing proved the image did. This is the one that matters: it asks whether
# the rauc that ships can still start, on the image as it will actually be
# written to a disk. Loading the shared libraries is the whole point -- \`rauc
# --version\` fails exactly the way a machine mid-update fails.
if ! rauc --version >/dev/null 2>&1; then
    echo "ERROR: rauc no longer runs after the build toolchain was removed:" >&2
    rauc --version >&2 || true
    echo "  Its runtime libraries were taken out by dnf autoremove. rauc is built" >&2
    echo "  from source, so rpm does not know anything needs them." >&2
    exit 1
fi

${SB_SETUP}

systemctl enable sshd ${NETWORK_UNIT} systemd-resolved

${DESKTOP_SETUP}

# wheel, not sudo: this family's sudoers grants %wheel, and a user in a group
# that grants nothing is a machine nobody can escalate on.
useradd -m -s /bin/bash -G wheel "${USERNAME}"
echo "${USERNAME}:${PASSWORD}" | chpasswd
passwd -l root
CHROOT
else
cat > "$MNT/tmp/setup.sh" <<CHROOT
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
# initramfs-tools is explicit: Debian kernels depend on it, Ubuntu kernels only
# recommend it, and without it no initrd.img is generated for GRUB to load.
apt-get install -y --no-install-recommends \
    ${KERNEL_PKG} initramfs-tools ${GRUB_PKGS} \
    openssh-server sudo ca-certificates curl \
    ${RESOLVED_PKG} cloud-guest-utils gdisk parted e2fsprogs \
    rauc ${CRYPT_PACKAGES} ${PROFILE_PACKAGES} ${EXTRA_PACKAGES}

# Debian splits RAUC in two: the rauc package is the command, rauc-service is
# the D-Bus service it talks to. With only the former, "rauc install" and
# "rauc status" both fail with "de.pengutronix.rauc was not provided by any
# .service files" -- so the machine can never be updated, and nothing says why
# until someone tries. Best-effort because not every suite packages it
# separately; where it does not, the service is part of the rauc package.
#
# No backticks anywhere in this block: the heredoc below is unquoted, so they
# would be command substitution executed by the builder, not text.
if apt-cache show rauc-service >/dev/null 2>&1; then
    apt-get install -y --no-install-recommends rauc-service
fi
if [ ! -e /usr/share/dbus-1/system-services/de.pengutronix.rauc.service ]; then
    echo "WARNING: RAUC's D-Bus service is missing; 'rauc install' will not work" >&2
fi

${SB_SETUP}

systemctl enable ssh systemd-networkd systemd-resolved

${DESKTOP_SETUP}

useradd -m -s /bin/bash -G sudo "${USERNAME}"
echo "${USERNAME}:${PASSWORD}" | chpasswd
passwd -l root
CHROOT
fi
if ! chroot "$MNT" bash /tmp/setup.sh; then
    used="$(df -Pm "$MNT" | awk 'NR==2 {print $3}')"
    avail="$(df -Pm "$MNT" | awk 'NR==2 {print $4}')"
    if [ "${avail:-1}" -lt 64 ]; then
        die "the root slot filled up while installing packages (${used} MiB used, \
${avail} MiB free in a ${ROOT_SIZE} MiB slot).
Rebuild with a larger --root-size — $OS_PRETTY $SUITE needs about ${MIN_ROOT} MiB \
for the base system, kernel and initramfs before any extra packages."
    fi
    die "package installation failed in the chroot (see the package manager output above)"
fi
rm -f "$MNT/tmp/setup.sh"
# $PKGCACHE, not $APTCACHE. The rpm work renamed the variable where it is set
# and missed it here, and `set -u` turns a stale name into a fatal at exactly
# this line -- for BOTH families, so every build has been dying here since,
# immediately after the longest step. Nothing caught it because the rpm builds
# were still failing earlier than this and no deb image had been built since.
umount "$PKGCACHE_MNT"
rm -rf "$PKGCACHE"
# The resolver goes back to being systemd-resolved's, which both families
# enable. A symlink rather than a file, because that is the only form resolved
# will manage -- so the deployed machine uses the DNS its own DHCP lease gives
# it instead of whatever the builder happened to be pointed at.
umount "$MNT/etc/resolv.conf"
rm -f "$MNT/etc/resolv.conf"
ln -sf ../run/systemd/resolve/stub-resolv.conf "$MNT/etc/resolv.conf"

# Every machine imaged from this build must get its own identity. Blank the
# machine-id and drop the build-time SSH host keys; machine-identity.service
# regenerates them on first boot and persists them in the overlay so they
# survive A/B slot switches and updates.
step "Resetting machine identity (machine-id, SSH host keys)"
truncate -s0 "$MNT/etc/machine-id"
install -d "$MNT/var/lib/dbus"
ln -sf /etc/machine-id "$MNT/var/lib/dbus/machine-id"
rm -f "$MNT"/etc/ssh/ssh_host_*

# --- SSH key + key-only hardening ---
if [ -n "$SSH_PUBKEY" ]; then
    log "Installing SSH authorized key for $USERNAME"
    install -d -m700 "$MNT/home/$USERNAME/.ssh"
    echo "$SSH_PUBKEY" > "$MNT/home/$USERNAME/.ssh/authorized_keys"
    chmod 600 "$MNT/home/$USERNAME/.ssh/authorized_keys"
    chroot "$MNT" chown -R "$USERNAME:$USERNAME" "/home/$USERNAME/.ssh"
fi
if [ "$SSH_KEY_ONLY" = true ]; then
    log "Disabling SSH password authentication (key-only)"
    install -d -m755 "$MNT/etc/ssh/sshd_config.d"
    cat > "$MNT/etc/ssh/sshd_config.d/50-key-only.conf" <<EOF
# Key-only SSH (set at build time by --ssh-key-only)
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
EOF
    # A drop-in only counts if sshd_config Includes the directory, and EL8's
    # openssh 8.0p1 does not -- the Include arrives in EL9. Without this the
    # build logs "Disabling SSH password authentication", ships the file, and
    # every machine still accepts the build-time password. A hardening step that
    # silently does nothing is worse than one that was never offered.
    if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' \
            "$MNT/etc/ssh/sshd_config" 2>/dev/null; then
        # First line: sshd takes the FIRST value of a keyword, so an Include
        # placed after an existing PasswordAuthentication would lose to it.
        sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$MNT/etc/ssh/sshd_config" \
            || die "--ssh-key-only: could not make sshd read the drop-in, and the
    image would ship with password authentication still enabled."
        log "Added the sshd_config.d Include (this release of sshd lacked it)"
    fi
fi

step "Applying overlay files (RAUC, GRUB, first-boot expand, LUKS enroll)"
cp -a "$OVERLAY_DIR"/etc/. "$MNT/etc/"
cp -a "$OVERLAY_DIR"/usr/. "$MNT/usr/"

# The two boot scripts live at /usr/lib/ab/initramfs and are shared by both
# initramfs harnesses -- dracut's module-setup.sh installs them from there, and
# initramfs-tools needs them under its own tree, so for that family they are
# placed rather than duplicated in the repository. One source: this is the code
# that decides whether a machine's writable state exists, and two copies would
# diverge exactly once, on whichever family nobody had booted lately.
if [ "$FAMILY" = deb ]; then
    mkdir -p "$MNT/etc/initramfs-tools/scripts/local-bottom" \
             "$MNT/etc/initramfs-tools/scripts/init-premount"
    cp "$MNT/usr/lib/ab/initramfs/ab-overlay" \
       "$MNT/etc/initramfs-tools/scripts/local-bottom/ab-overlay"
    cp "$MNT/usr/lib/ab/initramfs/ab-luks-key" \
       "$MNT/etc/initramfs-tools/scripts/init-premount/ab-luks-key"
    # initramfs-tools silently ignores a script that is not executable, which
    # would leave the root overlay off with nothing in the log to say why.
    chmod 0755 "$MNT/etc/initramfs-tools/scripts/local-bottom/ab-overlay" \
               "$MNT/etc/initramfs-tools/scripts/init-premount/ab-luks-key" \
               "$MNT/etc/initramfs-tools/hooks/ab-luks-key" \
               "$MNT/etc/initramfs-tools/hooks/ab-overlay" 2>/dev/null || true
else
    # dracut reads its modules from here; the hook scripts are installed by their
    # module-setup.sh at initramfs build time. The initramfs-tools tree is not
    # copied into an RPM image -- it would be inert, and inert files in /etc are
    # how somebody later concludes the wrong harness is in use.
    rm -rf "$MNT/etc/initramfs-tools" # family-ok: removing the OTHER family's tree is the point
    chmod 0755 "$MNT/usr/lib/dracut/modules.d/90ab-overlay/module-setup.sh" \
               "$MNT/usr/lib/dracut/modules.d/91ab-luks-key/module-setup.sh" 2>/dev/null || true
fi
chmod 0755 "$MNT/usr/lib/ab/initramfs/ab-overlay" \
           "$MNT/usr/lib/ab/initramfs/ab-luks-key" 2>/dev/null || true
# RAUC bundles are only accepted by systems with a matching compatible string.
sed -i "s/^compatible=.*/compatible=${DISTRO}-ab/" "$MNT/etc/rauc/system.conf"
# RAUC reads and writes the boot environment itself, so it needs the same path
# the bootloader was installed with. The shipped file names Debian's; left
# uncorrected, RAUC on an RHEL machine reads an env block GRUB never looks at,
# reports every slot "boot status: bad", and refuses to mark one primary -- an
# update that installs and can then never be activated.
sed -i "s#^grubenv=.*#grubenv=/boot/${GRUBDIR}/grubenv#" "$MNT/etc/rauc/system.conf"
if [ "$FAMILY" = rpm ]; then
    # RAUC's grub backend execs `grub-editenv` by that exact name, and this family
    # ships only grub2-editenv. The shipped ab-* scripts resolve the name at
    # runtime (see usr/lib/ab/grubenv-lib.sh), but RAUC is a compiled binary and
    # cannot be taught, so the name has to exist. Without it every update
    # installs and then cannot be marked primary.
    ln -sf grub2-editenv "$MNT/usr/bin/grub-editenv"
fi
# On an encrypted image the partition IS the LUKS container, so leaving RAUC
# pointed at /dev/disk/by-partlabel/rootfs-* would have it make a filesystem
# straight over the LUKS header -- destroying the slot rather than updating
# it. Point it at the unlocked mappings instead; the initramfs opens all of
# them (every crypttab entry carries the `initramfs` option), so both slots
# are present at runtime, not just the booted one.

# --- your files, and the paths the image owns -------------------------------
#
# Copied over the WHOLE root, not just etc/ and usr/ like the project's own
# overlay above, and applied after it so your version of a file wins.
#
# Everything shipped here is also recorded as image-owned. That is the half that
# makes "override whatever is on the machine" true rather than merely intended:
# the root filesystem is an overlay, and a file already present in the machine's
# upper layer shadows the image's copy -- so an update would install your
# /etc/hosts and the machine would keep using its own. Recording the path lets
# the initramfs drop that shadowing copy on the next update, at which point the
# image's version is what the machine actually reads.
OWNED_LIST="$MNT/usr/lib/ab/image-owned.list"
mkdir -p "$(dirname "$OWNED_LIST")"
: > "$OWNED_LIST"

if [ -d "$OVERLAY_D" ] && [ -n "$(ls -A "$OVERLAY_D" 2>/dev/null)" ]; then
    step "Applying your overlay from $OVERLAY_D"
    # The directory's own README explains the directory; it is not part of the
    # image, and copying it would put a stray /README.md on every machine.
    ( cd "$OVERLAY_D" && tar -cf - --exclude=./README.md . ) | tar -xf - -C "$MNT"
    # Record every file (not directory): clearing a whole directory from the
    # upper layer would delete machine-local files that live alongside yours --
    # dropping every netplan on the machine when you only shipped one.
    ( cd "$OVERLAY_D" && find . \( -type f -o -type l \) ! -name README.md ) \
        | sed 's|^\.||' | sort >> "$OWNED_LIST"
    log "  $(wc -l < "$OWNED_LIST") file(s) will override the machine's own copies on update"
fi

for p in $OWN_PATHS; do
    case "$p" in
        /*) printf '%s\n' "$p" >> "$OWNED_LIST";;
        *)  die "--own-path must be absolute (got '$p')";;
    esac
done
if [ -s "$OWNED_LIST" ]; then
    sort -u "$OWNED_LIST" -o "$OWNED_LIST"
fi

# --- the state manifest ------------------------------------------------------
#
# Where the machine's writable state lives. The initramfs applies this rather
# than deciding for itself, so the layout is a property of the image and an
# update can change it in the same step that ships the software expecting it.
#
# The default reproduces what the initramfs used to hardcode: the whole root is
# one overlay over the slot, and the paths the distribution owns are cleared
# from it on a slot change so an old release cannot shadow the new one.
#
# Mount directives are emitted parent-first. The initramfs applies them in file
# order and does not sort -- it has busybox and a bad day is a machine that does
# not boot, whereas this has coreutils and can simply get the order right.
STATE_CONF="$MNT/usr/lib/ab/state.conf"
step "Writing the state manifest ($STATE_MODEL, upper layer $UPPER_MODE)"
if [ "$UPPER_MODE" = per-slot ]; then
    log "  Each slot gets its own upper layer, so a change made in one cannot"
    log "  stop the other from booting -- and the two share nothing the overlay"
    log "  covers. Use --persist for what should stay shared (e.g. /home)."
fi

# Every directive needs its mountpoint to exist in the image.
#
# Under the default model the initramfs can just create a missing one, because
# the root is writable. Under stateful and appliance it is not, and `mkdir` on a
# read-only root fails -- which is how `persist /data` on an appliance image
# turned into a directive that silently did nothing, on the one path the whole
# model exists to provide. The image is where a mountpoint belongs anyway: it is
# part of the filesystem layout, not of the machine's state.
while read -r _verb _mp _arg; do
    [ -n "$_mp" ] || continue
    [ "$_mp" = "/" ] && continue
    if [ ! -d "$MNT$_mp" ]; then
        mkdir -p "$MNT$_mp"
        log "  created mountpoint $_mp (the image did not have one)"
    fi
done <<EOF
$(printf '%s\n' "$MOUNT_DIRECTIVES" | grep -v '^[[:space:]]*$')
EOF
{
    echo "# Generated by build-image.sh -- how this image lays out writable state."
    echo "# Applied at boot by /usr/lib/ab/initramfs/ab-overlay, which this image's"
    echo "# initramfs runs from ${AB_HOOK_DESC}."
    echo "model $STATE_MODEL"
    # Emitted only when it is not the default, so the manifest on an ordinary
    # image reads exactly as it always has -- and so the line's presence is
    # itself the answer to "is this one of the per-slot-upper images?".
    if [ "$UPPER_MODE" = per-slot ]; then
        echo "# Each slot has its own overlay upper layer (upper-A / upper-B):"
        echo "# nothing written while running one slot is visible from the other."
        echo "upper per-slot"
    fi
    echo ""
    printf '%s\n' "$MOUNT_DIRECTIVES" | grep -v '^$' | \
        awk '{ n = gsub("/", "/", $2); print n, $0 }' | sort -k1,1n -k3,3 | cut -d' ' -f2-
    echo ""
    for p in $RESET_PATHS;  do echo "reset-on-update $p"; done
    for p in $KEEP_PATHS;   do echo "keep $p"; done
} > "$STATE_CONF"
log "  $(grep -cvE '^\s*(#|$)' "$STATE_CONF") directive(s)"

# Does any keep path shadow a file this image ships? The structural check above
# ran on the arguments; this one runs on the real tree, and it is the check that
# generalises -- it needs no list of paths that are safe to keep, because it
# asks the image instead.
#
# The reason a keep is safe at all is that the image ships nothing there, so
# holding the machine's copy across a slot change cannot hide anything the
# update delivered. /usr/local is the default keep precisely because both
# families reserve it for local administration and neither ships a regular file
# into it -- verified, not assumed: `dpkg -S /usr/local` matches no package, and
# AlmaLinux owns 34 paths under it, every one a directory.
#
# Turn that around and it is the whole rule. A keep path containing a file from
# the image is a promise to go on serving this machine's copy of that file
# forever, including after an update replaces it -- which is the silent-stale
# failure again, scoped to a subtree. `--keep-path /var/lib/rpm` is the one that
# looks most reasonable and is worst: the database would survive describing the
# other slot's package set, so every subsequent dnf transaction reasons from a
# manifest of software that is not installed.
#
# Directories are fine and are why this counts regular files only: a keep path
# has to exist in the image for the machine to have written under it.
#
# A function so it can be lifted out and run against a fixture tree by
# test_state_model_guards.py: the test extracts this definition from this file
# and calls it, so what the test exercises is this code rather than a second
# copy of it that can agree with itself while both are wrong.
keep_shadowing_report() {
    _root="$1"; shift
    for _k in "$@"; do
        [ -d "$_root$_k" ] || continue
        _hit=$(find "$_root$_k" -type f -print -quit 2>/dev/null)
        [ -n "$_hit" ] && printf ' %s(%s)' "$_k" "${_hit#$_root}"
    done
}

#
# Reported, not refused. This started as a hard failure and that was wrong: it
# failed the DEFAULT image on its own `keep /usr/local`, because this builder
# ships the A/B helper scripts (ab-update, ab-agent, ab-sync-boot and the rest)
# into /usr/local/sbin. No image could be built at all.
#
# The reasoning behind the failure did not survive contact with what a keep
# actually does. A keep moves the path aside out of the STORE -- the upper layer
# -- clears the reset paths, and puts it back. The image's copy is in the LOWER.
# So a file the image ships at a kept path is shadowed only if the MACHINE has
# also written that file; until it does, the keep moves nothing and the image's
# new copy is what the machine reads.
#
# Whether the machine has written there is not knowable when the image is built,
# so a hard failure was condemning a configuration on a precondition rather than
# a defect.
#
# It is still worth saying, because the case it warns about is real and silent:
# edit /usr/local/sbin/ab-update.sh on a machine and that edit lives in the upper,
# is held across every slot change by this keep, and shadows every future image's
# copy of it -- so the script that applies updates stops being updatable, with
# nothing said.
_shadowed=$(keep_shadowing_report "$MNT" $KEEP_PATHS)
if [ -n "$_shadowed" ]; then
    warn "the image ships files inside a kept path:$_shadowed"
    warn "  A keep holds the MACHINE's copy across a slot change. These files are"
    warn "  the image's, so they update normally -- unless someone edits one on a"
    warn "  machine, after which that machine keeps its own copy forever and never"
    warn "  sees another image's. Worth knowing for /usr/local/sbin/ab-*."
fi

# Will the seeding actually fit? Everything above is a guess made before
# debootstrap ran; this is the measurement, made against the real tree, and it
# is a hard failure rather than a warning. The alternative is an image that
# builds cleanly and produces a machine with a half-copied /var -- which is not
# a crash, boots, and looks almost right.
SEED_KIB=0
while read -r _verb _mp _arg; do
    case "$_verb" in persist|slot-private) ;; *) continue;; esac
    [ -d "$MNT$_mp" ] || continue
    _k=$(du -sk "$MNT$_mp" 2>/dev/null | cut -f1)
    [ -n "$_k" ] || continue
    # A slot-private path is seeded once per slot, so it lands twice.
    [ "$_verb" = slot-private ] && _k=$((_k * 2))
    SEED_KIB=$((SEED_KIB + _k))
done <<EOF
$(printf '%s\n' "$MOUNT_DIRECTIVES" | grep -v '^[[:space:]]*$')
EOF

if [ "$SEED_KIB" -gt 0 ]; then
    AVAIL_KIB=$(df -Pk "$MNT/var/lib/overlay" | awk 'NR==2 {print $4}')
    # 25% headroom: the machine writes to these stores from the moment it boots,
    # and an overlay partition that is exactly full at first boot is one that
    # fails on the first log line instead of during the copy.
    NEED_KIB=$((SEED_KIB * 5 / 4))
    log "  seeds ${SEED_KIB} KiB into the overlay at first boot (${AVAIL_KIB} KiB free)"
    if [ "$NEED_KIB" -gt "$AVAIL_KIB" ]; then
        die "the overlay partition is too small for what this manifest seeds.
    It holds $((AVAIL_KIB / 1024)) MiB and needs about $((NEED_KIB / 1024)) MiB at first boot,
    before first-boot-expand has grown the filesystem.
    Rebuild with --overlay-min $(( (NEED_KIB / 1024) + 256 ))"
    fi
fi

if [ "$ENCRYPT" = true ]; then
    sed -i "s|^device=/dev/disk/by-partlabel/rootfs-a|device=/dev/mapper/luks-rootfs-a|; \
            s|^device=/dev/disk/by-partlabel/rootfs-b|device=/dev/mapper/luks-rootfs-b|" \
        "$MNT/etc/rauc/system.conf"
fi
chmod +x "$MNT/usr/local/sbin/first-boot-expand.sh" "$MNT/usr/local/sbin/luks-enroll.sh" \
         "$MNT/usr/local/sbin/luks-enroll-reap.sh" \
         "$MNT/usr/local/sbin/ab-mark-good.sh" "$MNT/usr/local/sbin/machine-identity.sh" \
         "$MNT/usr/local/sbin/ab-overlay-diff.sh" "$MNT/usr/local/sbin/ab-checkin.sh" \
         "$MNT/usr/local/sbin/ab-update.sh" "$MNT/usr/local/sbin/ab-sync-boot.sh" \
         "$MNT/usr/local/sbin/ab-slot-pending.sh" \
         "$MNT/usr/local/sbin/ab-health-check.sh" \
         "$MNT/usr/local/sbin/ab-agent.sh" \
         "$MNT/usr/local/sbin/ab-kernel-hook.sh"
# The others are only ever run by systemd; this one is run by a person, so it
# gets a name without the extension and a place on the default PATH.
ln -sf ab-overlay-diff.sh "$MNT/usr/local/sbin/ab-overlay-diff"
ln -sf ab-update.sh       "$MNT/usr/local/sbin/ab-update"
ln -sf ab-sync-boot.sh    "$MNT/usr/local/sbin/ab-sync-boot"
ln -sf ab-agent.sh        "$MNT/usr/local/sbin/ab-agent"

# What this slot is running, written where the running system can read it and
# where a bundle built from this image will carry it along. It is the only way
# a machine can tell the server which build it is on: nothing else on a booted
# system records that, and os-release names the Debian release, which every
# build of this image shares. make-bundle.sh overwrites it with the bundle's
# own version, so a slot always describes what was actually installed into it
# -- including after a rollback, since the other slot keeps its own copy.
install -d -m755 "$MNT/usr/lib/flipside"
printf '%s\n' "$IMAGE_VERSION" > "$MNT/usr/lib/flipside/version"

# Recovery is the thing nobody remembers under pressure, so the machine says it
# on every login rather than leaving it to documentation on another computer.
cat > "$MNT/etc/motd" <<'MOTD'

  A/B image-based system.  The image is read-only underneath, and everything
  written since imaging lives on the overlay partition. How much of the root
  that covers is set by the image: see /usr/lib/ab/state.conf.

    ab-overlay-diff        what this machine changed, and what it hides
    ab-overlay-diff -a     include added and deleted files
    ab-update              install an update into the other slot
    ab-update --status     which slot is running, and what is on the other

  Recovery is in the GRUB menu at boot (hold Shift / press Esc):
    "reset writable state"   start clean, keeping a copy in
                             /var/lib/overlay/*.prev
    "image as written"       boot the image with no writable state at all

MOTD

# --- keep apt from destroying the A/B boot configuration --------------------
#
# grub.cfg here is written by this builder and understood by RAUC: slot order,
# try counters, per-slot kernels, the recovery entries. update-grub regenerates
# it from /etc/grub.d and knows about none of that, and Debian calls update-grub
# from /etc/kernel/postinst.d/zz-update-grub on every kernel install and from
# the grub packages own postinst on upgrade. One "apt upgrade" that pulls a
# kernel would therefore replace the A/B configuration with a generic one --
# no rauc.slot=, no slot selection, no recovery entries -- and the machine would
# come up, if at all, with A/B silently dead.
#
# Diverting the binary covers every caller at once, which grubbing about in
# individual hooks does not: kernel hooks, package postinsts, and anyone typing
# it by hand all get the same answer.
mkdir -p "$MNT/usr/local/sbin"
if [ "$FAMILY" = deb ]; then
    chroot "$MNT" dpkg-divert --local --rename --add /usr/sbin/update-grub >/dev/null
    NOGRUB_PATH="$MNT/usr/sbin/update-grub"
else
    # No dpkg-divert here. The equivalent caller is grub2-mkconfig, which this
    # family's kernel install runs through /etc/kernel/postinst.d and through
    # kernel-install; the real binary is moved aside by hand and the stub takes
    # its name, which covers every caller the same way the divert does.
    #
    # grub2-mkconfig, not update-grub: the name is different, so a divert of a
    # name that does not exist here would have silently protected nothing.
    if [ -e "$MNT/usr/sbin/grub2-mkconfig" ] && [ ! -e "$MNT/usr/sbin/grub2-mkconfig.distrib" ]; then
        mv "$MNT/usr/sbin/grub2-mkconfig" "$MNT/usr/sbin/grub2-mkconfig.distrib"
    fi
    NOGRUB_PATH="$MNT/usr/sbin/grub2-mkconfig"
fi
# $NOGRUB_NAME so the message names the binary the caller actually invoked;
# hard-coding "update-grub" made the stub claim to be a command that does not
# exist on this family.
NOGRUB_NAME="$(basename "$NOGRUB_PATH")"
cat > "$NOGRUB_PATH" <<NOGRUB
#!/bin/sh
# Deliberately does nothing. This is an A/B image: the bootloader config is part
# of the image and is replaced by re-imaging, not regenerated on the machine.
# Regenerating it would drop slot selection, the rauc.slot= parameters and the
# recovery entries, leaving a machine that boots -- until you need to roll back.
#
# The real one is still there as /usr/sbin/${NOGRUB_NAME}.distrib if you genuinely
# need it, but expect to re-image afterwards.
echo "${NOGRUB_NAME}: skipped; this is an A/B image whose grub config is managed by the image." >&2
exit 0
NOGRUB
# $NOGRUB_PATH, not the hard-coded Debian path -- which does not exist on the rpm
# family, so `set -e` ended the build here. And the chmod is load-bearing either
# way: `cat >` creates the stub 0644, so every caller would get "Permission
# denied" instead of the intended no-op.
chmod 0755 "$NOGRUB_PATH"

# A kernel installed by apt is inert here -- GRUB boots the slot's own copy,
# which only a bundle replaces. The hook does not wire the two together on
# purpose: a kernel swapped in underneath a running slot would no longer match
# the root filesystem it was built against. It says so instead, because the
# alternative is a machine that reboots on the old kernel with no explanation.
# -D, and a different directory per family. /etc/kernel/postinst.d is
# initramfs-tools' convention and does not exist in an rpm root; `install` does
# not create parent directories, so this ended the build. The rpm equivalent is
# a kernel-install plugin, which takes (COMMAND KVER ENTRY_DIR) rather than
# apt's (KVER PATH) -- the shared script ignores its arguments and only prints,
# so the same file serves both.
if [ "$FAMILY" = deb ]; then
    install -D -m0755 "$OVERLAY_DIR/usr/local/sbin/ab-kernel-hook.sh" \
        "$MNT/etc/kernel/postinst.d/zz-ab-kernel-notice"
else
    install -D -m0755 "$OVERLAY_DIR/usr/local/sbin/ab-kernel-hook.sh" \
        "$MNT/etc/kernel/install.d/95-ab-kernel-notice.install"
fi

# ab-health-check is WantedBy=boot-complete.target, which ab-mark-good Requires
# -- so enabling it is what makes the checks gate the blessing. With no checks
# installed it passes immediately and nothing changes.
chroot "$MNT" systemctl enable first-boot-expand.service ab-mark-good.service \
                                ab-health-check.service \
                                machine-identity.service ab-checkin.service
# The recurring control-plane check-in. ab-checkin.service stays alongside it
# and is not replaced: that one fires once, at boot, and is what records "this
# machine booted what you gave it" in the provisioning history. The timer
# answers the different question of what is true now. Enabling the *timer*, not
# the service -- enabling the service would run one check-in at boot and never
# again, which is the behaviour this is here to fix.
chroot "$MNT" systemctl enable ab-agent.timer
# The directory is part of the image's layout, so a check dropped in through
# overlay.d has somewhere to land and `ls` on a running machine answers "none".
install -d -m755 "$MNT/etc/ab/health.d"

# RAUC only installs bundles signed by a certificate in this keyring, and the
# keyring is baked into the image -- so a machine can never be updated by a
# bundle signed after it was built unless that certificate was already inside.
# The signing key is generated once by make-bundle.sh and kept; using it here
# means images and bundles from this repo work together with no extra step.
# Falling back to the CA bundle keeps unsigned-update-free behaviour for images
# built before any key existed, rather than failing the build.
# --- your customization script ----------------------------------------------
#
# Runs inside the chroot, after packages and both overlays, so it can enable a
# unit that was just installed, add a user, or write a file that depends on the
# hostname. Not everything is a file, which is why the overlay alone is not
# enough.
#
# It runs with the image's own filesystem as / but the builder's kernel, so
# anything needing a running system (systemctl start, a daemon) will not work --
# systemctl enable does, because it only writes symlinks.
if [ -n "$RUN_SCRIPT" ]; then
    [ -f "$RUN_SCRIPT" ] || die "--run-script: no such file: $RUN_SCRIPT"
    step "Running your customization script in the chroot"
    install -m0755 "$RUN_SCRIPT" "$MNT/tmp/ab-custom.sh"

    # Give it a resolver, the same way the package install got one.
    #
    # The build bind-mounts the host's /etc/resolv.conf for its own dnf/apt work
    # and then, hundreds of lines earlier than this, replaces it with the symlink
    # a booted machine wants -- ../run/systemd/resolve/stub-resolv.conf, which
    # resolves to nothing inside a chroot. So by the time a customization script
    # runs, the image has no working DNS, and the most ordinary script anybody
    # would write dies on:
    #
    #   Curl error (6): Couldn't resolve host name for
    #   https://mirrors.almalinux.org/mirrorlist/9/crb
    #
    # which reads as a network problem with the build host rather than as
    # something the build did to the chroot on purpose.
    #
    # Restored afterwards, so the image still ships the symlink systemd-resolved
    # expects rather than a copy of the builder's resolver -- that was its own
    # bug once: a machine that resolved names only as long as the build host's
    # DNS server was reachable from wherever it ended up.
    _rs_bound=0
    if [ -e /etc/resolv.conf ]; then
        rm -f "$MNT/etc/resolv.conf"
        : > "$MNT/etc/resolv.conf"
        if mount --bind /etc/resolv.conf "$MNT/etc/resolv.conf"; then
            _rs_bound=1
        else
            log "  WARNING: could not give the chroot a resolver; a script that"
            log "           needs the network will fail to resolve names"
        fi
    fi
    _rs_restore() {
        [ "$_rs_bound" = 1 ] || return 0
        umount "$MNT/etc/resolv.conf" 2>/dev/null || true
        rm -f "$MNT/etc/resolv.conf"
        ln -sf ../run/systemd/resolve/stub-resolv.conf "$MNT/etc/resolv.conf"
    }

    if ! chroot "$MNT" /tmp/ab-custom.sh; then
        rm -f "$MNT/tmp/ab-custom.sh"
        _rs_restore
        die "your --run-script failed (see its output above); the image was not finished"
    fi
    rm -f "$MNT/tmp/ab-custom.sh"
    _rs_restore
fi

# --- the certificate that decides whether this machine can ever be updated ----
#
# This has to be right at build time or not at all: the keyring is inside the
# image, and a machine that shipped without the cert cannot be given it by an
# update, because the update is the thing it will not accept. The first image
# built here shipped before any key existed, so its keyring was the fallback
# below, and the bundle it was sent months later failed with
#
#   signature verification failed: Verify error: self-signed certificate
#
# which reads like a bad bundle rather than an image that never trusted anything.
#
# So generate the key here when it is missing rather than warning about it.
# make-bundle.sh already does exactly this on the first bundle; doing it in
# whichever runs first means an image and the bundles for it always agree, and
# the ordering trap -- build image, build bundle, discover the image predates
# the key -- stops existing. Same parameters as make-bundle.sh on purpose.
RAUC_CERT="${RAUC_CERT:-/output/rauc-keys/cert.pem}"
RAUC_KEYDIR="$(dirname "$RAUC_CERT")"
if [ ! -f "$RAUC_CERT" ] && [ "$RAUC_CERT" = "/output/rauc-keys/cert.pem" ]; then
    log "No update signing key yet; generating one in $RAUC_KEYDIR"
    log "  Keep it: every image built from here trusts this certificate, and"
    log "  replacing it orphans every machine already deployed."
    mkdir -p "$RAUC_KEYDIR"
    openssl req -x509 -newkey rsa:4096 -nodes -sha256 -days 3650 \
        -keyout "$RAUC_KEYDIR/key.pem" -out "$RAUC_CERT" \
        -subj "/O=flipside/CN=A-B Update Signing" >/dev/null 2>&1 \
        || log "WARNING: could not generate a signing key"
    chmod 600 "$RAUC_KEYDIR/key.pem" 2>/dev/null || true
fi

KEYRING_FP=""
if [ -f "$RAUC_CERT" ]; then
    log "Trusting the update signing certificate ($RAUC_CERT)"
    cp "$RAUC_CERT" "$MNT/etc/rauc/keyring.pem"
elif [ ! -f "$MNT/etc/rauc/keyring.pem" ]; then
    # An empty keyring, not the public CA bundle. The old fallback copied
    # ca-certificates.crt in, which does not merely fail to help -- it means the
    # machine accepts a bundle signed by anything chaining to any of ~150 public
    # CAs. "Trusts nobody" is the only honest answer when there is no key, and
    # it fails at the first install attempt instead of at the wrong one.
    log "WARNING: no signing certificate at $RAUC_CERT and none could be generated."
    log "         This image ships an empty keyring and will refuse every update"
    log "         bundle until it is rebuilt against a certificate."
    : > "$MNT/etc/rauc/keyring.pem"
fi

# Read while the slot is still mounted, and recorded in the sidecar below. It is
# the one property of an image that cannot be discovered afterwards without
# mounting it, cannot be changed once the machine is deployed, and decides
# whether any bundle will ever install on it. Empty means this image trusts
# nothing, which is worth being able to see without booting the thing.
KEYRING_FP="$(openssl x509 -in "$MNT/etc/rauc/keyring.pem" -noout -fingerprint -sha256 2>/dev/null \
              | sed 's/.*=//' || true)"
log "Update keyring fingerprint: ${KEYRING_FP:-<none — this image accepts no updates>}"

# Configure first-boot TPM/Tang enrollment.
if [ "$ENCRYPT" = true ] && { [ "$UNLOCK" = tpm2 ] || [ "$UNLOCK" = tang ]; }; then
    log "Enabling first-boot LUKS enrollment ($UNLOCK)"
    cat > "$MNT/etc/luks-enroll.conf" <<EOF
METHOD=$UNLOCK
TANG_URL=$TANG_URL
TPM2_PCRS=$TPM2_PCRS
EOF
    # Both phases are enabled here; which one does anything is decided by the
    # stamps in /var/lib, via ConditionPathExists on the units. Phase 2 is inert
    # until phase 1 has bound and staged, and both are inert once enrollment is
    # complete -- so enabling them unconditionally costs a condition check.
    chroot "$MNT" systemctl enable luks-enroll.service luks-enroll-reap.service
fi

# Rebuild the initramfs so it includes cryptsetup, crypttab, and any keyfiles.
# These config files belong to cryptsetup-initramfs / initramfs-tools, which only
# exist now that the chroot package install has run.
#
# deb only, and not merely because dracut ignores these files. The rpm branch
# above deletes /etc/initramfs-tools outright once the dracut modules are in
# place, so the UMASK append below does not write a useless line for that family
# -- it redirects into a directory that is not there, and `set -e` ends the build
# on the spot. Both settings have no dracut counterpart that needs writing:
# dracut reads the whole crypttab rather than needing to be told to, and creates
# the initramfs 0600 already.
if [ "$ENCRYPT" = true ] && [ "$FAMILY" = deb ]; then
    log "Configuring and rebuilding initramfs with cryptsetup support"
    install -d "$MNT/etc/cryptsetup-initramfs"
    # Force ALL crypttab devices into the initramfs so it can unlock whichever
    # A/B slot GRUB selects (not just the slot that was root at build time).
    echo 'CRYPTSETUP=y' >> "$MNT/etc/cryptsetup-initramfs/conf-hook"
    if [ "$USE_KEYFILE" = true ]; then
        # No KEYFILE_PATTERN. There is deliberately no key in the image to bake
        # in: init-premount/ab-luks-key fetches this machine's key from the BOOT
        # partition at boot, so the initramfs a bundle delivers carries no key
        # material at all and works on whichever machine installs it.
        #
        # UMASK stays: the initramfs is world-readable by default, and while the
        # key is no longer in it, the crypttab and the rest of the boot path are
        # not things to publish either.
        echo 'UMASK=0077' >> "$MNT/etc/initramfs-tools/initramfs.conf"
    fi
fi

# The initramfs is generated when the kernel package is installed, which happens
# before the overlay files are copied in -- so it has to be rebuilt here or the
# root-overlay script simply would not be in it. This used to run only for
# encrypted images, which would have left every unencrypted image booting
# without the overlay and no clue as to why.
log "Rebuilding initramfs (root overlay, and cryptsetup where enabled)"
if [ "$FAMILY" = deb ]; then
    chroot "$MNT" update-initramfs -u
else
    # dracut is told the kernel version explicitly. Left to itself it uses the
    # RUNNING kernel's version, which in a chroot on a build host is the BUILD
    # HOST's kernel -- so it would generate an initramfs for a kernel that is not
    # in this image, name it after a version this image does not have, and the
    # machine would find no initrd for the kernel it actually boots.
    KVER_FOR_DRACUT="$(ls "$MNT/lib/modules" 2>/dev/null | head -1)"
    [ -n "$KVER_FOR_DRACUT" ] || die "no kernel modules directory in the image; the kernel package did not install"
    # --add, rather than trusting check() to opt them in. An A/B image whose
    # initramfs quietly lacks the overlay module boots read-only with nothing in
    # the log to say why, and that is the whole failure this module exists to
    # prevent -- so inclusion is stated, not inferred.
    # --no-hostonly is not optional for a mass-imaging tool. This family's dracut
    # defaults to hostonly=yes, which trims the initramfs to the drivers the
    # machine it is running on needs -- and the machine it is running on is the
    # BUILDER, whose storage and network controllers are a virtio set that a
    # physical target does not have. The image builds, and every machine that is
    # not the build host drops to an emergency shell unable to find its own root.
    # Exactly the same class of mistake as --kver above: something read from the
    # build environment that belongs to the target.
    #
    # --no-hostonly-cmdline as well, or dracut bakes the builder's root= and
    # rd.luks.* into the initramfs as a default cmdline.
    # --install /etc/crypttab, because --no-hostonly means dracut will not copy
    # it: that copy is gated on hostonly, and grub.cfg passes no rd.luks.* to
    # replace it. Without the file the initramfs has no idea which containers to
    # open, /dev/mapper/luks-rootfs-a never appears, and the machine sits in the
    # dracut emergency shell -- after a completely clean build. Switching to
    # hostonly to obtain the copy is not the fix: hostonly rewrites and filters
    # crypttab against the BUILDER's devices, and would drop the PARTLABEL= specs
    # this file deliberately uses so the image is true on any machine.
    DRACUT_EXTRA=""
    [ "$ENCRYPT" = true ] && DRACUT_EXTRA="--install /etc/crypttab"
    chroot "$MNT" dracut --force --no-hostonly --no-hostonly-cmdline \
        --kver "$KVER_FOR_DRACUT" \
        --add "ab-overlay ab-luks-key" \
        $DRACUT_EXTRA \
        "/boot/initramfs-${KVER_FOR_DRACUT}.img"
    # dracut does not fail when a module it was told to add contributed nothing,
    # so the initramfs is asked afterwards what is actually in it.
    #
    # The hook FILE, matched on the .sh suffix -- not the module name. Grepping
    # lsinitrd for "ab-overlay" passed on every image ever built, because the
    # module name appears in the module list whether or not any hook was
    # installed under a name dracut will source. That check could not fail, which
    # is why nothing noticed that the hook never ran.
    # A herestring, NOT `printf ... | grep -q`. With `set -o pipefail` (line 14)
    # that pipeline reports FAILURE even when the pattern matches: grep -q exits
    # the moment it finds one, printf takes SIGPIPE on the rest of a 200KB
    # listing, and pipefail surfaces printf's status as the pipeline's. The
    # checks below then fail on a perfectly good initramfs -- which is exactly
    # what happened, and cost a build: the hooks were present and this said they
    # were not. The listing is already in a variable, so there is no reason for a
    # pipe at all.
    _initrd_files="$(chroot "$MNT" lsinitrd "/boot/initramfs-${KVER_FOR_DRACUT}.img" 2>/dev/null || true)"
    if ! grep -qE "hooks/pre-pivot/.*ab-overlay\.sh" <<<"$_initrd_files"; then
        die "the generated initramfs has no runnable A/B overlay hook
    (looked for hooks/pre-pivot/*ab-overlay.sh). dracut sources only *.sh from a
    hook directory, so a hook installed under any other name is inert. Without it
    the machine boots read-only with no slot selection, which looks like a working
    image until you need to roll back."
    fi
    # The same argument for the unlock path. ab-luks-key depends() on dracut's
    # crypt module, so crypt arrives transitively -- which means it also leaves
    # transitively, if that dependency is ever edited. An encrypted image whose
    # initramfs cannot open a LUKS volume is not a degraded image, it is a brick,
    # and it is a clean build right up until someone boots it.
    if [ "$ENCRYPT" = true ]; then
        if ! grep -qE "cryptsetup|/crypt" <<<"$_initrd_files"; then
            die "this image is encrypted but the generated initramfs has no crypt
    support in it, so nothing can unlock the root filesystem at boot. The machine
    would reach an emergency shell every time."
        fi
        # And the rule it unlocks BY. crypt support with no crypttab is an
        # initramfs that can open LUKS containers and does not know which ones.
        if ! grep -qE "etc/crypttab" <<<"$_initrd_files"; then
            die "the initramfs has crypt support but no /etc/crypttab, so nothing
    tells it which volumes to unlock. --no-hostonly means dracut does not copy the
    file; --install /etc/crypttab is what puts it there."
        fi
        if ! grep -qE "hooks/initqueue/settled/.*ab-luks-key\.sh" <<<"$_initrd_files"; then
            die "the generated initramfs has no runnable LUKS bootstrap-key hook
    (looked for hooks/initqueue/settled/*ab-luks-key.sh). Without it the machine
    cannot fetch its own key from the BOOT partition and every boot stops at a
    passphrase prompt nobody is there to answer."
        fi
        # And the unit that makes it run IN TIME. The hook alone runs after the
        # cryptsetup units have already asked, so a volume that is not the root
        # gets one attempt, finds no keyfile and prompts -- which is exactly what
        # happened, with the correct key sitting on the machine's own BOOT
        # partition. Present-and-too-late looked identical to present-and-working
        # in every check until somebody booted it.
        if ! grep -qE "sysinit\.target\.wants/ab-luks-key\.service" <<<"$_initrd_files"; then
            die "the generated initramfs has the LUKS key hook but nothing ordered
    before cryptsetup-pre.target to run it in time. The volumes that are not the
    root slot will each get one attempt, find no keyfile, and stop at a passphrase
    prompt. Check that 91ab-luks-key/ab-luks-key.service was installed."
        fi
    fi
fi

# The ESP stub every signed GRUB needs, wherever its prefix happens to point.
#
# A vendor-signed GRUB has its prefix compiled in and cannot be told otherwise
# without rebuilding it -- which would mean signing it, which is the thing being
# avoided. It looks for $prefix/grub.cfg on the partition it was loaded from, so
# that file has to exist and hand off to the real configuration on BOOT.
#
# Written for every distribution's prefix rather than this build's, because the
# prefix is baked into a binary this build did not produce, and five 400-byte
# files cost nothing next to a machine that stops at a `grub rescue>` prompt
# because the one that was written was the other one.
write_esp_stubs() {
    local prefix_dir
    for prefix_dir in debian ubuntu almalinux rocky redhat; do
        mkdir -p "$BOOTMNT/efi/EFI/$prefix_dir"
        cat > "$BOOTMNT/efi/EFI/$prefix_dir/grub.cfg" <<STUB
# Written by the Flipside image builder. Not the real configuration.
#
# Everything that decides what boots -- slot order, try counters, the recovery
# entries -- lives on the BOOT partition, which is also where an update writes.
# Keeping the real file there means this one never has to change.
search --no-floppy --label BOOT --set=root
if [ -e (\$root)/$GRUBDIR/grub.cfg ]; then
    set prefix=(\$root)/$GRUBDIR
    configfile (\$root)/$GRUBDIR/grub.cfg
else
    echo "Flipside: no /$GRUBDIR/grub.cfg on the partition labelled BOOT."
    echo "The ESP was found and this stub ran, so firmware and shim are fine;"
    echo "the BOOT partition is missing, unlabelled, or its config was removed."
    sleep 30
fi
STUB
    done
}

if [ "$GRUB_BIOS" = 1 ]; then
    step "Installing GRUB (BIOS + UEFI) and writing A/B config"
    chroot "$MNT" "$GRUB_INSTALL" --target=i386-pc --boot-directory=/boot --recheck "$LOOP"
else
    step "Installing GRUB (UEFI) and writing A/B config"
fi
# --removable puts GRUB at the firmware's fallback path -- BOOTX64.EFI on amd64,
# BOOTAA64.EFI on arm64 -- so any UEFI firmware boots it without an NVRAM entry.
# Required for mass imaging, where NVRAM cannot be prepared per machine.
#
# The rpm family does not do this, and it is not a naming difference. Red Hat
# patches grub2-install to REFUSE an EFI target outright:
#
#   grub2-install: error: This utility should not be used for EFI platforms
#   because it does not support UEFI Secure Boot.
#
# The refusal is the correct behaviour and the reason is the whole design of
# this family's boot chain: the EFI bootloader is a PREBUILT, VENDOR-SIGNED
# binary shipped by grub2-efi-x64, already sitting on the ESP at
# /boot/efi/EFI/<distro>/grubx64.efi. Generating one locally -- which is what
# --force would do -- produces an unsigned image that no machine with Secure
# Boot enabled will run, trading the one property this family gives for free.
#
# So for rpm the ESP is populated from those packaged binaries instead, just
# below. BIOS is unaffected: grub2-install --target=i386-pc is not patched and
# has already run above.
if [ "$FAMILY" = deb ]; then
    chroot "$MNT" "$GRUB_INSTALL" --target="$GRUB_EFI_TARGET" --efi-directory=/boot/efi \
        --boot-directory=/boot --removable --no-nvram
else
    # The packaged binaries land on the ESP when the package is installed, which
    # happened in the chroot with /boot/efi already mounted. Verify rather than
    # assume: if they are not there, nothing else in this build puts a UEFI
    # bootloader on the disk and the image simply does not boot on UEFI.
    _esp_src="$MNT/boot/efi/EFI/$DISTRO"
    [ -f "$_esp_src/$SB_GRUB" ] || die "no packaged UEFI bootloader at
    $_esp_src/$SB_GRUB. This family installs it from grub2-efi-* rather than
    generating one, so without it the image has no UEFI boot path at all.
    Check that $GRUB_PKGS installed successfully."
    # The fallback path, so firmware boots it with no NVRAM entry. If Secure Boot
    # is in play the block below overwrites BOOTX64.EFI with shim, which then
    # chain-loads this same grubx64.efi -- so this is correct either way and the
    # image still boots when the shim is unavailable or Secure Boot is off.
    install -D -m0644 "$_esp_src/$SB_GRUB" "$BOOTMNT/efi/EFI/BOOT/$SB_GRUB_NAME"
    install -D -m0644 "$_esp_src/$SB_GRUB" "$BOOTMNT/efi/EFI/BOOT/$SB_BOOT_NAME"
    # The stub the packaged GRUB will look for. Written here rather than only in
    # the Secure Boot block below, because this bootloader is on the ESP whether
    # Secure Boot is on, off, or unavailable -- and without the stub it reaches a
    # `grub rescue>` prompt in every one of those cases.
    write_esp_stubs
    log "UEFI: installed the distribution's signed GRUB at the removable path"
fi

# --- UEFI Secure Boot --------------------------------------------------------
#
# On the deb family grub-install has just written its own UNSIGNED GRUB to the
# removable path, and under Secure Boot the firmware refuses to run it -- which
# is why every previous release said "disable Secure Boot" -- and on a lot of estates that is a policy
# no, not an inconvenience: the machines this project images for desktops and
# laptops are exactly the ones where it is mandated.
#
# The fix is to use the distribution's chain rather than enroll a key of our own
# on every machine:
#
#   firmware --(Microsoft key)--> shim --(distro key, built into shim)--> GRUB
#           --(shim lock protocol)--> kernel, which Debian and Ubuntu sign
#
# Nothing of ours needs signing, and nothing needs enrolling. shim goes at the
# removable path so a mass-imaged machine boots with no NVRAM entry, exactly as
# before; shim then loads grubx64.efi from beside itself.
SECURE_BOOT_ACTIVE=false
if [ "$SECURE_BOOT" != off ]; then
    # The signed shim is versioned in some releases (shimx64.efi.signed.latest)
    # and not in others. Take the first that exists rather than hard-coding one
    # spelling and discovering the other in a year.
    #
    # The two families ship the signed chain in entirely different places. Debian
    # puts it under /usr/lib/shim and /usr/lib/grub/<target>-signed; the RHEL
    # packages install straight onto the ESP at /boot/efi/EFI/<distro>/ (verified
    # with `dnf repoquery -l shim-x64 grub2-efi-x64` on almalinux:9). Searching
    # only Debian's locations meant `--secure-boot auto` found nothing on every
    # RHEL image, left the unsigned grub2-install output in place, warned, and
    # recorded "secure_boot": false -- a clean build that cannot boot on any
    # machine with Secure Boot on.
    sb_shim=""
    sb_grub=""
    if [ "$FAMILY" = rpm ]; then
        _esp="$MNT/boot/efi/EFI/$DISTRO"
        for candidate in "$_esp/$SB_SHIM" "$_esp/shim.efi"; do
            [ -f "$candidate" ] && { sb_shim="$candidate"; break; }
        done
        [ -f "$_esp/$SB_GRUB" ] && sb_grub="$_esp/$SB_GRUB"
        SB_SEARCHED="$_esp/$SB_SHIM and $_esp/$SB_GRUB"
    else
        # The signed shim is versioned in some releases (shimx64.efi.signed.latest)
        # and not in others. Take the first that exists rather than hard-coding one
        # spelling and discovering the other in a year.
        for candidate in "$MNT/usr/lib/shim/$SB_SHIM" \
                         "$MNT/usr/lib/shim/${SB_SHIM}.latest" \
                         "$MNT/usr/lib/shim/${SB_SHIM%.signed}"; do
            [ -f "$candidate" ] && { sb_shim="$candidate"; break; }
        done
        [ -f "$MNT/usr/lib/grub/$SB_GRUB_DIR/$SB_GRUB" ] && \
            sb_grub="$MNT/usr/lib/grub/$SB_GRUB_DIR/$SB_GRUB"
        SB_SEARCHED="/usr/lib/shim/$SB_SHIM and /usr/lib/grub/$SB_GRUB_DIR/$SB_GRUB"
    fi

    if [ -n "$sb_shim" ] && [ -f "$sb_grub" ]; then
        install -D -m0644 "$sb_shim" "$BOOTMNT/efi/EFI/BOOT/$SB_BOOT_NAME"
        install -D -m0644 "$sb_grub" "$BOOTMNT/efi/EFI/BOOT/$SB_GRUB_NAME"
        # MokManager, for enrolling a key by hand at the console. Not needed for
        # this chain -- shim already trusts the distribution's GRUB -- but shim
        # looks for it when verification fails, and without it the failure is a
        # bare "Security Policy Violation" and a dead machine rather than a
        # prompt that explains itself.
        for mm in "$MNT/usr/lib/shim/$SB_MM" "$MNT/usr/lib/shim/${SB_MM%.signed}" \
                  "$MNT/boot/efi/EFI/$DISTRO/$SB_MM"; do
            [ -f "$mm" ] && { install -D -m0644 "$mm" "$BOOTMNT/efi/EFI/BOOT/$SB_MM_NAME"; break; }
        done

        # The distribution's signed GRUB has its prefix compiled in and cannot
        # be told otherwise without rebuilding it, which would mean signing it,
        # which is the thing being avoided. It looks for $prefix/grub.cfg on the
        # partition it was loaded from -- the ESP -- so that file has to exist
        # and hand off to the real configuration on BOOT.
        #
        # Written to both /EFI/debian and /EFI/ubuntu: the prefix differs by
        # distribution, it is baked into a binary this build does not produce,
        # and two 200-byte files cost nothing next to a machine that drops to a
        # GRUB rescue prompt because the one that was written was the other one.
        write_esp_stubs
        SECURE_BOOT_ACTIVE=true
        log "Secure Boot: shim + signed GRUB installed at the removable path"
    elif [ "$SECURE_BOOT" = on ]; then
        die "--secure-boot on, but this suite provided no signed shim or GRUB.
    Looked for $SB_SEARCHED.
    Build with --secure-boot auto to fall back, or off to stop asking."
    else
        warn "No signed shim or GRUB in this suite; this image needs Secure Boot"
        warn "disabled in firmware. Everything else about it is unchanged."
    fi
fi
# The rescue entry is excluded explicitly. RPM kernel installs leave a
# `vmlinuz-0-rescue-<machineid>` on /boot, and it sorts ahead of the real kernel
# -- so `head -n1` would stage the rescue image into both slots and the machine
# would boot a kernel with no modules for the hardware it is on.
KVER="$(ls "$BOOTMNT" | sed -n 's/^vmlinuz-//p' | grep -v '^0-rescue' | head -n1)"
[ -n "$KVER" ] || die "no kernel found on BOOT partition"
log "Kernel version: $KVER"

# The initramfs is named differently by the two harnesses -- initramfs-tools
# writes initrd.img-<ver>, dracut writes initramfs-<ver>.img -- so it is probed
# rather than assumed. Getting this wrong is not a bad copy, it is a `du` that
# fails under `set -e -o pipefail` and a slot with no initrd at all.
if [ -f "$BOOTMNT/initrd.img-$KVER" ]; then
    INITRD_SRC="$BOOTMNT/initrd.img-$KVER"
elif [ -f "$BOOTMNT/initramfs-$KVER.img" ]; then
    INITRD_SRC="$BOOTMNT/initramfs-$KVER.img"
else
    die "no initramfs for $KVER on the BOOT partition (looked for
    initrd.img-$KVER and initramfs-$KVER.img). Without one no slot can boot."
fi

# Each slot gets its own copy of the kernel and initramfs, under a name that
# never changes. /boot is a single shared partition, so without this both slots
# boot the same kernel -- and an update could not deliver a new one without
# replacing the kernel the *running* slot depends on, which would break rollback
# the moment the new slot failed. Per-slot copies mean an update writes only the
# inactive slot's kernel, and falling back to the old slot falls back to its
# kernel too.
#
# The names carry no version, so grub.cfg never has to change: an update
# replaces /A/vmlinuz in place. The versioned originals stay where dpkg put them
# at the top of /boot, because that is where the kernel packages and
# update-initramfs expect to find them.
# Checked before copying, because the copy's own failure mode is a bare
# "No space left on device" halfway through writing /B/initrd.img -- the
# first real desktop build died exactly there, one line after GRUB said
# "No error reported". Say what is too big and which knob fixes it.
KIMG_KB=$(du -k "$BOOTMNT/vmlinuz-$KVER" | cut -f1)
IIMG_KB=$(du -k "$INITRD_SRC" | cut -f1)
NEED_KB=$(( 2 * (KIMG_KB + IIMG_KB) + 8192 ))   # two slot copies + slack
FREE_KB=$(df -Pk "$BOOTMNT" | awk 'NR==2 {print $4}')
if [ "$FREE_KB" -lt "$NEED_KB" ]; then
    die "the ${BOOT_SIZE} MiB /boot partition cannot hold per-slot copies of this kernel+initramfs
    (initramfs alone is $((IIMG_KB / 1024)) MiB; /boot needs three copies of both and has $((FREE_KB / 1024)) MiB free).
    Rebuild with --boot-size $(( (NEED_KB - FREE_KB) / 1024 + BOOT_SIZE + 64 )) or larger.
    Desktop-profile initramfs images carry DRM drivers and their firmware, which is most of the size."
fi
for sl in A B; do
    mkdir -p "$BOOTMNT/$sl"
    cp -a "$BOOTMNT/vmlinuz-$KVER"    "$BOOTMNT/$sl/vmlinuz"
    cp -a "$INITRD_SRC" "$BOOTMNT/$sl/initrd.img"
done
log "Per-slot kernels staged: /A and /B"

# grub2-install creates /boot/grub2 and never /boot/grub, so the directory has
# to exist under the name THIS family's core image was built to look for. The
# prefix is compiled into core.img: write the config to the other spelling and
# the build is clean and the machine stops at a `grub rescue>` prompt.
mkdir -p "$BOOTMNT/$GRUBDIR"
sed -e "s/__KVER__/$KVER/g" -e "s/__OS__/$OS_PRETTY/g" -e "s/__ROOTFLAG__/$ROOT_FLAG/g" \
    "$OVERLAY_DIR/boot/grub/grub.cfg" > "$BOOTMNT/$GRUBDIR/grub.cfg"
# An unsubstituted placeholder reaches the kernel as a bogus command-line word
# and the root is silently mounted with the default flags, which under a
# read-only model is a machine that boots and then cannot write anywhere.
if grep -q '__ROOTFLAG__\|__OS__\|__KVER__' "$BOOTMNT/$GRUBDIR/grub.cfg"; then
    die "grub.cfg still contains an unsubstituted placeholder"
fi
chroot "$MNT" "$GRUB_EDITENV" "/boot/$GRUBDIR/grubenv" create
# A_OK/B_OK alongside the try counters: RAUC's grub backend reads ORDER,
# <slot>_TRY and <slot>_OK, and without the _OK variables it reports every
# slot as "boot status: bad" and refuses to mark one primary -- so an update
# installs and then cannot be activated. grub.cfg honours them too, so a slot
# explicitly marked bad is skipped rather than booted into a known failure.
# _PROVEN=1 on both: the two slots are byte-identical copies of this build, so
# putting the first boot on probation could only ever fall back to the same
# software that just failed. Probation is armed by ab-slot-pending.sh when an
# update actually changes a slot, which is the only time a fallback means
# anything.
chroot "$MNT" "$GRUB_EDITENV" "/boot/$GRUBDIR/grubenv" set ORDER="A B" \
    A_TRY=0 B_TRY=0 A_OK=1 B_OK=1 A_PROVEN=1 B_PROVEN=1

# Read while the slot is still mounted -- the only moment the package list can
# be taken without booting the image or mounting it again. Written against $RAW
# because $OUT is not decided until after compression; the sidecars are renamed
# to match below. The copy this leaves inside the root filesystem is picked up
# by the slot sync just below, so both slots carry it.
step "Recording what is in this image (SBOM)"
SBOM_PACKAGES=0
if [ -x "$(dirname "$0")/make-sbom.sh" ]; then
    SBOM_PACKAGES="$("$(dirname "$0")/make-sbom.sh" --root "$MNT" --out "$RAW" \
        --name "$(basename "${RAW%.img}")" --version "$IMAGE_VERSION" \
        --distro "$DISTRO" --suite "$SUITE" --arch "$ARCH" | tail -1)" || {
        # An image is still a perfectly good image without an SBOM beside it,
        # and failing the build here would trade a real artifact for a metadata
        # file. It is loud, though: an SBOM nobody notices is missing is the
        # same as one that was never asked for.
        warn "could not generate an SBOM for this image; it is built and usable,"
        warn "but nothing records what is inside it."
        SBOM_PACKAGES=0
    }
fi

step "Syncing root slot A -> slot B"
umount "$MNT/dev/pts" "$MNT/dev" "$MNT/proc" "$MNT/sys"
umount "$MNT/var/lib/overlay"
umount "$BOOTMNT/efi"
umount "$BOOTMNT"
mkdir -p "$WORK/b"
mount "$DEV_B" "$WORK/b"
rsync -aHAX --numeric-ids "$MNT"/ "$WORK/b"/
umount "$WORK/b"
umount "$MNT"

# Close LUKS mappers before detaching the loop device.
if [ "$ENCRYPT" = true ]; then
    for m in "${MAPPERS[@]}"; do cryptsetup close "$m" 2>/dev/null || true; done
    MAPPERS=()
fi
losetup -d "$LOOP"; LOOP=""

log "Image built: $RAW"
case "$COMPRESS" in
    zstd) step "Compressing with zstd (slowest step on a large image)"; zstd -f -19 -T0 --rm "$RAW" -o "${RAW}.zst"; OUT="${RAW}.zst";;
    gzip) step "Compressing with gzip"; gzip -f "$RAW"; OUT="${RAW}.gz";;
    none) step "Skipping compression"; OUT="$RAW";;
    *) warn "Unknown compression '$COMPRESS', leaving raw"; step "Skipping compression"; OUT="$RAW";;
esac

step "Writing SHA256 checksum and metadata sidecars"
# The SBOM was written beside $RAW before the slot was unmounted; compression
# renamed the image out from under it. Move the three files rather than
# regenerate them -- the filesystem they describe no longer exists in a form
# anything can read.
if [ "$OUT" != "$RAW" ]; then
    for ext in spdx.json cdx.json packages.tsv; do
        [ -f "${RAW}.${ext}" ] && mv "${RAW}.${ext}" "${OUT}.${ext}"
    done
fi
( cd "$(dirname "$OUT")" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256" )
cat > "${OUT}.json" <<EOF
{
  "distro": "$DISTRO",
  "version": "$IMAGE_VERSION",
  "suite": "$SUITE",
  "arch": "$ARCH",
  "profile": "$PROFILE",
  "desktop": "$DESKTOP_ENV",
  "hostname": "$HOSTNAME_",
  "username": "$USERNAME",
  "image_size_gib": $(awk "BEGIN{printf \"%.2f\", $TOTAL_MIB/1024}"),
  "image_size_mib": $TOTAL_MIB,
  "root_size_mib": $ROOT_SIZE,
  "state_model": "$STATE_MODEL",
  "slot_private_upper": $([ "$UPPER_MODE" = per-slot ] && echo true || echo false),
  "encrypted": $ENCRYPT,
  "update_keyring_sha256": "$KEYRING_FP",
  "packages": $SBOM_PACKAGES,
  "secure_boot": $SECURE_BOOT_ACTIVE,
  "sbom": "$([ "$SBOM_PACKAGES" -gt 0 ] && echo "spdx+cyclonedx" || echo none)",
  "unlock": "$([ "$ENCRYPT" = true ] && echo "$UNLOCK" || echo none)",
  "compress": "$COMPRESS",
  "created": "$(date -u +%FT%TZ)"
}
EOF

step "Done"
[ "$ENCRYPT" = true ] && log "Encryption: LUKS2, unlock=$UNLOCK (passphrase is also enrolled for recovery)"
ls -lh "$OUT" "${OUT}.sha256" "${OUT}.json"
