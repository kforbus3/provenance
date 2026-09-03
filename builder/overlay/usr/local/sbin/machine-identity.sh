#!/bin/bash
# Give each imaged machine its own identity, shared across the A/B slots.
#
# The image ships with a blank /etc/machine-id and no SSH host keys (both are
# stripped at build time so every machine isn't a bit-for-bit identity clone).
# On each boot this restores the machine's identity from the persistent overlay
# partition, generating and storing it first if this is a brand-new machine.
# Because the overlay is shared by both root slots, the identity survives A/B
# updates and slot switches. Best-effort: never fails the boot.
set -u

STATE=/var/lib/overlay/persistent/identity
mkdir -p "$STATE" 2>/dev/null || exit 0
chmod 700 "$STATE"

# --- SSH host keys ---
if compgen -G "$STATE/ssh_host_*_key" >/dev/null; then
    # A/B twin slot or later boot: adopt the stored keys (idempotent).
    cp -a "$STATE"/ssh_host_* /etc/ssh/ 2>/dev/null
else
    ssh-keygen -A >/dev/null 2>&1
    cp -a /etc/ssh/ssh_host_* "$STATE"/ 2>/dev/null
fi

# --- hostname ---
#
# Assigned per MAC in the web UI and carried here by the imager on the BOOT
# partition, because an image cannot hold it: every machine written from one
# image would answer to the same name.
#
# Stored alongside the machine-id and host keys rather than just written to
# /etc/hostname, for the same reasons. /etc is part of the root, so under the
# default model it lands in the overlay's upper layer -- which an image-owned
# file could later shadow, and which is *per slot* on an image built with
# --slot-private-upper, so a name set while running A would not exist in B.
# Re-applied from the store on every boot, so it is right in both slots and
# survives updates.
#
# Re-imaging rewrites the whole disk including the overlay, so the store is
# empty afterwards and the newly assigned name is adopted. That is the intent:
# re-imaging a machine is how you change what it is.
DEPLOY=/boot/ab-deploy.json
if [ ! -s "$STATE/hostname" ] && [ -r "$DEPLOY" ]; then
    assigned="$(sed -n 's/.*"hostname"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$DEPLOY")"
    if [ -n "$assigned" ]; then
        printf '%s\n' "$assigned" > "$STATE/hostname" 2>/dev/null
    fi
fi

if [ -s "$STATE/hostname" ]; then
    want="$(cat "$STATE/hostname" 2>/dev/null)"
    if [ -n "$want" ]; then
        # Only write when it differs: this runs every boot, and on the default
        # model each write is a copy-up into the overlay.
        if [ "$(cat /etc/hostname 2>/dev/null)" != "$want" ]; then
            printf '%s\n' "$want" > /etc/hostname 2>/dev/null
        fi
        # systemd read /etc/hostname long before this unit runs, so the file
        # alone would not take effect until the next boot. Set the running one
        # too. `hostname` rather than hostnamectl: this is early, and
        # hostnamectl needs systemd-hostnamed over D-Bus.
        [ "$(hostname 2>/dev/null)" = "$want" ] || hostname "$want" 2>/dev/null
        # /etc/hosts still names whatever the image was built as, which makes
        # sudo and anything else resolving the local name wait for a timeout.
        if [ -w /etc/hosts ] && ! grep -qE "^127\.0\.1\.1[[:space:]]+$want\$" /etc/hosts 2>/dev/null; then
            if grep -qE "^127\.0\.1\.1[[:space:]]" /etc/hosts 2>/dev/null; then
                sed -i "s/^127\.0\.1\.1[[:space:]].*/127.0.1.1\t$want/" /etc/hosts 2>/dev/null
            else
                printf '127.0.1.1\t%s\n' "$want" >> /etc/hosts 2>/dev/null
            fi
        fi
    fi
fi

# --- machine-id ---
# systemd generates a fresh id early in boot when /etc/machine-id is blank.
if [ -s "$STATE/machine-id" ]; then
    if ! cmp -s "$STATE/machine-id" /etc/machine-id; then
        # First boot of the other slot: adopt the machine's stored id.
        # Fully effective from the next boot of this slot; harmless meanwhile.
        cp "$STATE/machine-id" /etc/machine-id 2>/dev/null
    fi
elif [ -s /etc/machine-id ]; then
    cp /etc/machine-id "$STATE/machine-id" 2>/dev/null
fi

exit 0
