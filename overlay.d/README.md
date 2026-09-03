# Your files, copied into every image built from this checkout

Anything here is copied over the image's root filesystem, preserving paths:

    overlay.d/etc/hosts                    ->  /etc/hosts
    overlay.d/etc/netplan/10-corp.yaml     ->  /etc/netplan/10-corp.yaml
    overlay.d/usr/local/bin/site-check     ->  /usr/local/bin/site-check
    overlay.d/opt/agent/agent.conf         ->  /opt/agent/agent.conf

It is applied *after* the project's own overlay, so your version of a file wins
over the default this repo ships.

File permissions are preserved, so a script shipped `0644` is a script that does
not run on the machine.

You do not have to edit this directory by hand: the web UI's **Image Files**
page manages exactly these files, and the Build page opens the same manager in a
dialog. It is the same directory either way.

## These files also override the machine

Every file here is recorded in the image as image-owned. The root filesystem on
a deployed machine is an overlay, so a file the machine has written at the same
path would normally shadow the image's copy — an update would install your
`/etc/hosts` and the machine would carry on reading its own, with nothing to say
so. Being image-owned means the machine's copy at that exact path is dropped on
the update that delivers yours.

Same path: the image wins. Anything else in the same directory is untouched, so
shipping one netplan file does not remove the machine's others. Use
`--own-path` to claim a path you are not shipping a file for.

## What does not belong here

Per-machine identity (hostnames, SSH host keys, machine-id) — those are
generated on first boot and live in the overlay on purpose. This is for
fleet-wide configuration that should be part of the image and replaced by every
update.

Everything in this directory except this README is gitignored, so site-specific
configuration does not end up committed.
