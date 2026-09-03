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
RESET_PATHS="/usr /bin /sbin /lib /lib32 /lib64 /libx32 /boot
             /var/lib/dpkg /var/lib/apt /var/cache/apt"
# Held back from that clearing. /usr/local sits inside /usr but is reserved by
# the FHS for locally installed software, so it is the machine's, not the
# image's -- clearing /usr wholesale used to take it, and a script left in
# /usr/local/bin vanished on the first update with nothing said.
KEEP_PATHS="/usr/local"
SSH_KEY_ONLY="${SSH_KEY_ONLY:-false}"
COMPRESS="${COMPRESS:-zstd}"
# Encryption
ENCRYPT="${ENCRYPT:-false}"
UNLOCK="${UNLOCK:-keyfile}"             # passphrase | keyfile | tpm2 | tang
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
  --distro NAME           debian|ubuntu (default: auto-detect from --suite)
  --suite NAME            Debian/Ubuntu suite (default: $SUITE; e.g. trixie, bookworm, noble, jammy)
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
        --reset-on-update) RESET_PATHS="$RESET_PATHS $2"; shift 2;;
        --keep-path)       KEEP_PATHS="$KEEP_PATHS $2"; shift 2;;
        --ssh-pubkey) SSH_PUBKEY="$(cat "$2")"; shift 2;;
        --ssh-authorized-key) SSH_PUBKEY="$2"; shift 2;;
        --ssh-key-only) SSH_KEY_ONLY=true; shift;;
        --compress) COMPRESS="$2"; shift 2;;
        --encrypt) ENCRYPT=true; shift;;
        --unlock) UNLOCK="$2"; shift 2;;
        --luks-passphrase) LUKS_PASS="$2"; shift 2;;
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
            shift 2;;
        --tang-url) TANG_URL="$2"; shift 2;;
        --tpm2-pcrs) TPM2_PCRS="$2"; shift 2;;
        -h|--help) usage; exit 0;;
        *) echo "Unknown option: $1" >&2; usage; exit 1;;
    esac
done

log()  { echo -e "\033[0;32m[build]\033[0m $*"; }
warn() { echo -e "\033[1;33m[build]\033[0m $*"; }
die()  { echo -e "\033[0;31m[build] ERROR:\033[0m $*" >&2; exit 1; }

# Machine-readable progress. The web UI parses these lines into a progress bar;
# on a terminal they read as ordinary step markers. Emitted in addition to the
# human log so neither consumer depends on parsing prose.
BUILD_STEP=0
BUILD_STEPS=14
step() {
    BUILD_STEP=$((BUILD_STEP + 1))
    printf '[progress] %d/%d %s\n' "$BUILD_STEP" "$BUILD_STEPS" "$1"
    log "$1"
}

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
        # distribution owns are clawed back on a slot change. Everything a
        # person does to the machine survives an update, including `apt install`
        # -- which is the point on a general-purpose Debian fleet, and the
        # reason this is the default.
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
        RESET_PATHS="/var/lib/dpkg /var/lib/apt /var/cache/apt"
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
        # LUKS enrolment writes the unlock key here after the image was built.
        # Reverting /etc would undo it and the machine would come up asking for
        # a passphrase with nobody there to type it.
        KEEP_PATHS="/etc/cryptsetup-keys.d"
        ;;
    *) die "--state-model: unknown model '$STATE_MODEL' (expected: overlay, stateful, appliance)";;
esac

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

# --slot-private-upper only means anything if something is overlaid. Every model
# here overlays at least one path, so this is a guard against a future one that
# does not -- where the flag would otherwise be accepted, do nothing, and leave
# the operator believing the slots were separated when they were not.
if [ "$UPPER_MODE" = per-slot ] && [ -z "$_ovl" ]; then
    die "--slot-private-upper: state model '$STATE_MODEL' overlays nothing, so there
    is no upper layer to give each slot. Use --slot-private for individual paths."
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
        *) DISTRO=debian;;
    esac
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
        PROFILE_PACKAGES="rsync htop less nano tmux"
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
            *) die "--distro must be debian or ubuntu (got '$DISTRO')";;
        esac
        case "$DISTRO/$DESKTOP_ENV" in
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
        # is the whole reason to use theirs rather than enrol our own key on
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
if [ "$ARCH" != "$(dpkg --print-architecture)" ]; then
    if [ ! -e "/proc/sys/fs/binfmt_misc/qemu-${QEMU_ARCH}" ]; then
        die "building $ARCH on $(dpkg --print-architecture) needs binfmt support.
    Run once on the host:  docker run --privileged --rm tonistiigi/binfmt --install all"
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
    *) die "--distro must be debian or ubuntu";;
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
case "$SECURE_BOOT" in
    on)   SB_SETUP="apt-get install -y --no-install-recommends ${SB_PKGS}";;
    auto) SB_SETUP="apt-get install -y --no-install-recommends ${SB_PKGS} || \
              echo 'NOTE: no signed shim/GRUB in this suite; Secure Boot will be unsupported' >&2";;
esac
# Minimum workable root slot, measured per distro. Ubuntu's linux-image-generic
# hard-depends on linux-firmware and linux-modules-extra (~1.7 GiB installed),
# which Debian's linux-image-amd64 does not — so the same 3 GiB slot that is
# comfortable on Debian overflows on Ubuntu partway through initramfs
# generation. Enforced below rather than left to fail deep in a dpkg run.
case "$DISTRO" in
    ubuntu) MIN_ROOT=5120;;
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

# --- Validate options ---
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
    # var/cache/apt/archives is the APT cache bind mount; it is nested under
    # $MNT and must come off before $MNT itself, or the final umount fails and
    # the loop device stays attached.
    for m in var/cache/apt/archives dev proc sys boot/efi boot var/lib/overlay; do
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
EXT4_COMPAT="^orphan_file,^metadata_csum_seed"
mkfs.vfat -F32 -n EFI    "$P_ESP" >/dev/null
mkfs.ext4 -q -O "$EXT4_COMPAT" -L BOOT     "$P_BOOT"
mkfs.ext4 -q -O "$EXT4_COMPAT" -L rootfs-a "$DEV_A"
mkfs.ext4 -q -O "$EXT4_COMPAT" -L rootfs-b "$DEV_B"
mkfs.ext4 -q -O "$EXT4_COMPAT" -L overlay  "$DEV_OVL"

step "Mounting root slot A"
mkdir -p "$MNT"
mount "$DEV_A" "$MNT"
mkdir -p "$BOOTMNT" "$MNT/var/lib/overlay"
mount "$P_BOOT" "$BOOTMNT"
mkdir -p "$BOOTMNT/efi"
mount "$P_ESP" "$BOOTMNT/efi"
mount "$DEV_OVL" "$MNT/var/lib/overlay"

step "Bootstrapping $OS_PRETTY $SUITE ($ARCH)"
debootstrap --arch="$ARCH" --variant=minbase $DEBOOTSTRAP_OPTS \
    --include=systemd-sysv,ifupdown,netbase \
    "$SUITE" "$MNT" "$MIRROR"

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

cat > "$MNT/etc/systemd/network/10-dhcp.network" <<EOF
[Match]
Name=en* eth*

[Network]
DHCP=yes
EOF

# --- crypttab + key material (before installing the initramfs) ---
CRYPT_PACKAGES=""
if [ "$ENCRYPT" = true ]; then
    CRYPT_PACKAGES="cryptsetup cryptsetup-initramfs"
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
    [ "$UNLOCK" = tpm2 ] && CRYPT_PACKAGES="$CRYPT_PACKAGES clevis clevis-luks clevis-initramfs clevis-tpm2 tpm2-tools"
    [ "$UNLOCK" = tang ] && CRYPT_PACKAGES="$CRYPT_PACKAGES clevis clevis-luks clevis-initramfs curl"

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
    cat > "$MNT/etc/crypttab" <<EOF
# <name>          <device>                 <keyfile>     <options>
#
# Addressed by partition label so this file is true on any machine imaged from
# any build. Do not "fix" these to UUIDs: see build-image.sh for what that costs.
luks-rootfs-a     PARTLABEL=rootfs-a       $KEYREF_A     luks,discard,initramfs$NETOPT
luks-rootfs-b     PARTLABEL=rootfs-b       $KEYREF_B     luks,discard,initramfs$NETOPT
luks-overlay      PARTLABEL=overlay        $KEYREF_OVL   luks,discard,initramfs$NETOPT
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
    DESKTOP_SETUP="apt-get install -y ${DESKTOP_PACKAGES}
systemctl set-default graphical.target
systemctl disable systemd-networkd"
fi

step "Installing kernel, bootloader, and tooling in chroot"
# Keep APT's downloaded .debs OUT of the root slot. Ubuntu pulls ~460 MB of
# archives (linux-firmware and linux-modules-extra dominate), and holding those
# alongside the unpacked files is enough on its own to exhaust a 3 GiB slot —
# initramfs generation then dies with a bare "No space left on device". The
# cache lives on the builder's own filesystem instead and is discarded after.
APTCACHE="$WORK/aptcache"
mkdir -p "$APTCACHE" "$MNT/var/cache/apt/archives"
mount --bind "$APTCACHE" "$MNT/var/cache/apt/archives"

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
if ! chroot "$MNT" bash /tmp/setup.sh; then
    used="$(df -Pm "$MNT" | awk 'NR==2 {print $3}')"
    avail="$(df -Pm "$MNT" | awk 'NR==2 {print $4}')"
    if [ "${avail:-1}" -lt 64 ]; then
        die "the root slot filled up while installing packages (${used} MiB used, \
${avail} MiB free in a ${ROOT_SIZE} MiB slot).
Rebuild with a larger --root-size — $OS_PRETTY $SUITE needs about ${MIN_ROOT} MiB \
for the base system, kernel and initramfs before any extra packages."
    fi
    die "package installation failed in the chroot (see the apt/dpkg output above)"
fi
rm -f "$MNT/tmp/setup.sh"
umount "$MNT/var/cache/apt/archives"
rm -rf "$APTCACHE"

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
fi

step "Applying overlay files (RAUC, GRUB, first-boot expand, LUKS enroll)"
cp -a "$OVERLAY_DIR"/etc/. "$MNT/etc/"
# initramfs-tools silently ignores a script that is not executable, which would
# leave the root overlay off with nothing in the log to say why.
chmod 0755 "$MNT/etc/initramfs-tools/scripts/local-bottom/ab-overlay" \
           "$MNT/etc/initramfs-tools/scripts/init-premount/ab-luks-key" \
           "$MNT/etc/initramfs-tools/hooks/ab-luks-key" \
           "$MNT/etc/initramfs-tools/hooks/ab-overlay" 2>/dev/null || true
cp -a "$OVERLAY_DIR"/usr/. "$MNT/usr/"
# RAUC bundles are only accepted by systems with a matching compatible string.
sed -i "s/^compatible=.*/compatible=${DISTRO}-ab/" "$MNT/etc/rauc/system.conf"
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
    echo "# Applied by /etc/initramfs-tools/scripts/local-bottom/ab-overlay at boot."
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
chroot "$MNT" dpkg-divert --local --rename --add /usr/sbin/update-grub >/dev/null
cat > "$MNT/usr/sbin/update-grub" <<'NOGRUB'
#!/bin/sh
# Deliberately does nothing. This is an A/B image: /boot/grub/grub.cfg is part
# of the image and is replaced by re-imaging, not regenerated on the machine.
# Regenerating it would drop slot selection, the rauc.slot= parameters and the
# recovery entries, leaving a machine that boots -- until you need to roll back.
#
# The real one is still there as /usr/sbin/update-grub.distrib if you genuinely
# need it, but expect to re-image afterwards.
echo "update-grub: skipped; this is an A/B image whose grub.cfg is managed by the image." >&2
exit 0
NOGRUB
chmod 0755 "$MNT/usr/sbin/update-grub"

# A kernel installed by apt is inert here -- GRUB boots the slot's own copy,
# which only a bundle replaces. The hook does not wire the two together on
# purpose: a kernel swapped in underneath a running slot would no longer match
# the root filesystem it was built against. It says so instead, because the
# alternative is a machine that reboots on the old kernel with no explanation.
install -m0755 "$OVERLAY_DIR/usr/local/sbin/ab-kernel-hook.sh" \
    "$MNT/etc/kernel/postinst.d/zz-ab-kernel-notice"

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
    if ! chroot "$MNT" /tmp/ab-custom.sh; then
        rm -f "$MNT/tmp/ab-custom.sh"
        die "your --run-script failed (see its output above); the image was not finished"
    fi
    rm -f "$MNT/tmp/ab-custom.sh"
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
if [ "$ENCRYPT" = true ]; then
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
chroot "$MNT" update-initramfs -u

if [ "$GRUB_BIOS" = 1 ]; then
    step "Installing GRUB (BIOS + UEFI) and writing A/B config"
    chroot "$MNT" grub-install --target=i386-pc --boot-directory=/boot --recheck "$LOOP"
else
    step "Installing GRUB (UEFI) and writing A/B config"
fi
# --removable puts GRUB at the firmware's fallback path -- BOOTX64.EFI on amd64,
# BOOTAA64.EFI on arm64 -- so any UEFI firmware boots it without an NVRAM entry.
# Required for mass imaging, where NVRAM cannot be prepared per machine. Secure
# Boot must be disabled.
chroot "$MNT" grub-install --target="$GRUB_EFI_TARGET" --efi-directory=/boot/efi \
    --boot-directory=/boot --removable --no-nvram

# --- UEFI Secure Boot --------------------------------------------------------
#
# grub-install has just written its own unsigned GRUB to the removable path.
# Under Secure Boot the firmware refuses to run it, which is why every previous
# release said "disable Secure Boot" -- and on a lot of estates that is a policy
# no, not an inconvenience: the machines this project images for desktops and
# laptops are exactly the ones where it is mandated.
#
# The fix is to use the distribution's chain rather than enrol a key of our own
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
    sb_shim=""
    for candidate in "$MNT/usr/lib/shim/$SB_SHIM" \
                     "$MNT/usr/lib/shim/${SB_SHIM}.latest" \
                     "$MNT/usr/lib/shim/${SB_SHIM%.signed}"; do
        [ -f "$candidate" ] && { sb_shim="$candidate"; break; }
    done
    sb_grub="$MNT/usr/lib/grub/$SB_GRUB_DIR/$SB_GRUB"

    if [ -n "$sb_shim" ] && [ -f "$sb_grub" ]; then
        install -D -m0644 "$sb_shim" "$BOOTMNT/efi/EFI/BOOT/$SB_BOOT_NAME"
        install -D -m0644 "$sb_grub" "$BOOTMNT/efi/EFI/BOOT/$SB_GRUB_NAME"
        # MokManager, for enrolling a key by hand at the console. Not needed for
        # this chain -- shim already trusts the distribution's GRUB -- but shim
        # looks for it when verification fails, and without it the failure is a
        # bare "Security Policy Violation" and a dead machine rather than a
        # prompt that explains itself.
        for mm in "$MNT/usr/lib/shim/$SB_MM" "$MNT/usr/lib/shim/${SB_MM%.signed}"; do
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
        for prefix_dir in debian ubuntu; do
            mkdir -p "$BOOTMNT/efi/EFI/$prefix_dir"
            cat > "$BOOTMNT/efi/EFI/$prefix_dir/grub.cfg" <<'STUB'
# Written by the Flipside image builder. Not the real configuration.
#
# The distribution's signed GRUB looks here because its prefix is compiled in.
# Everything that decides what boots -- slot order, try counters, the recovery
# entries -- lives on the BOOT partition, which is also where an update writes.
# Keeping the real file there means this one never has to change.
search --no-floppy --label BOOT --set=root
if [ -e ($root)/grub/grub.cfg ]; then
    set prefix=($root)/grub
    configfile ($root)/grub/grub.cfg
else
    echo "Flipside: no /grub/grub.cfg on the partition labelled BOOT."
    echo "The ESP was found and this stub ran, so firmware and shim are fine;"
    echo "the BOOT partition is missing, unlabelled, or its config was removed."
    sleep 30
fi
STUB
        done
        SECURE_BOOT_ACTIVE=true
        log "Secure Boot: shim + signed GRUB installed at the removable path"
    elif [ "$SECURE_BOOT" = on ]; then
        die "--secure-boot on, but this suite provided no signed shim or GRUB.
    Looked for /usr/lib/shim/$SB_SHIM and /usr/lib/grub/$SB_GRUB_DIR/$SB_GRUB.
    Build with --secure-boot auto to fall back, or off to stop asking."
    else
        warn "No signed shim or GRUB in this suite; this image needs Secure Boot"
        warn "disabled in firmware. Everything else about it is unchanged."
    fi
fi
KVER="$(ls "$BOOTMNT" | sed -n 's/^vmlinuz-//p' | head -n1)"
[ -n "$KVER" ] || die "no kernel found on BOOT partition"
log "Kernel version: $KVER"

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
IIMG_KB=$(du -k "$BOOTMNT/initrd.img-$KVER" | cut -f1)
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
    cp -a "$BOOTMNT/initrd.img-$KVER" "$BOOTMNT/$sl/initrd.img"
done
log "Per-slot kernels staged: /A and /B"

sed -e "s/__KVER__/$KVER/g" -e "s/__OS__/$OS_PRETTY/g" -e "s/__ROOTFLAG__/$ROOT_FLAG/g" \
    "$OVERLAY_DIR/boot/grub/grub.cfg" > "$BOOTMNT/grub/grub.cfg"
# An unsubstituted placeholder reaches the kernel as a bogus command-line word
# and the root is silently mounted with the default flags, which under a
# read-only model is a machine that boots and then cannot write anywhere.
if grep -q '__ROOTFLAG__\|__OS__\|__KVER__' "$BOOTMNT/grub/grub.cfg"; then
    die "grub.cfg still contains an unsubstituted placeholder"
fi
chroot "$MNT" grub-editenv /boot/grub/grubenv create
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
chroot "$MNT" grub-editenv /boot/grub/grubenv set ORDER="A B" \
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
