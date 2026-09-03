FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        dnsmasq ipxe iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Stage the iPXE network bootloaders into the TFTP root.
#
# ipxe-arm64.efi is what lets an arm64 machine netboot at all. Debian's ipxe
# package ships binaries for other architectures than the one it is installed
# on, so this needs no cross-build and no download: an amd64 provisioning
# server can hand an arm64 machine its bootloader.
RUN mkdir -p /srv/tftp \
    && cp /usr/lib/ipxe/undionly.kpxe  /srv/tftp/ \
    && cp /usr/lib/ipxe/ipxe.efi       /srv/tftp/ \
    && cp /usr/lib/ipxe/ipxe-arm64.efi /srv/tftp/ \
    && cp /usr/lib/ipxe/snponly.efi    /srv/tftp/ 2>/dev/null || true

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
