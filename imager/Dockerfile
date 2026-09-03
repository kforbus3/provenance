# Imager builder: produces the netboot kernel + initramfs.
FROM debian:trixie-slim

# The kernel package has to match the architecture this container is built for:
# the imager is a kernel + initramfs the target machine executes, so an amd64
# imager is unbootable on an arm64 machine no matter how it is served.
ARG KERNEL_PKG=linux-image-amd64
RUN apt-get update && apt-get install -y --no-install-recommends \
        ${KERNEL_PKG} \
        busybox-static \
        gdisk \
        zstd \
        xz-utils \
        cpio \
        gzip \
        kmod \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /imager
COPY build-imager.sh verify-initramfs.sh init udhcpc.script /imager/
RUN chmod +x /imager/build-imager.sh /imager/verify-initramfs.sh

VOLUME /output
ENTRYPOINT ["/imager/build-imager.sh"]
