# Provenance test fabric — jump host.
#
# Debian/Ubuntu base running OpenSSH plus userspace WireGuard (wireguard-go).
# The jump host is the hub of the WireGuard overlay; the backend reaches it
# at jumphost:22 and ProxyJumps onward to the managed hosts over wg0.

# Build wireguard-go from source so we do not depend on distro packaging.
FROM golang:1.23-alpine AS wgbuild
RUN apk add --no-cache git make
RUN git clone --depth=1 https://git.zx2c4.com/wireguard-go /src \
 && make -C /src
# Produces /src/wireguard-go

FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-server \
      wireguard-tools \
      openvpn \
      iproute2 \
      iptables \
      sudo \
      ca-certificates \
      curl \
 && rm -rf /var/lib/apt/lists/*

# OpenVPN 2.6, from backports, and asserted rather than assumed.
#
# Ubuntu 22.04 ships 2.5, which derives data-channel keys with the TLS 1.0 PRF. A
# FIPS-mode managed host is forbidden from using it, and 2.6's replacement (the TLS
# Exporter) has to be supported by BOTH ends -- so a FIPS host connecting to a 2.5
# server completes the TLS handshake, receives its overlay address, and then carries
# nothing:
#
#   TLS Error: PRF calculation failed ... the policy does not allow it (e.g. running in
#   FIPS mode). The peer did not announce support for the modern TLS Export feature
#
# The tunnel device sits there with the right address while the server logs an
# inactivity timeout every two minutes, and every visible symptom is on the managed
# host. The final awk is the point of this block: it fails the BUILD if the installed
# openvpn is still older than 2.6, because an image that quietly shipped 2.5 is exactly
# how this was missed.
RUN apt-get update \
 && apt-get install -y --no-install-recommends -t jammy-backports openvpn \
 && rm -rf /var/lib/apt/lists/* \
 && openvpn --version | head -1 \
 && openvpn --version | head -1 \
      | awk '{split($2,v,"."); exit !(v[1]>2 || (v[1]==2 && v[2]>=6))}'

COPY --from=wgbuild /src/wireguard-go /usr/local/bin/wireguard-go

# Login user that the Provenance CA-signed certificates map to. Passwordless sudo
# so the enrollment flow can add WireGuard peers (wg set) on the jump host.
RUN useradd -m -s /bin/bash prov \
 && echo 'prov ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/prov \
 && chmod 0440 /etc/sudoers.d/prov

# sshd privilege-separation dir, principals mapping, and the fleet CA
# placeholder that the enrollment flow replaces with the real CA pubkey.
# The file name must match the ACCOUNT name: sshd resolves
# AuthorizedPrincipalsFile through %u. Both principal spellings are listed because
# certificates carry both while any host is still on the pre-rename names.
RUN mkdir -p /run/sshd /etc/ssh/auth_principals \
 && printf 'prov\nfleet\n' > /etc/ssh/auth_principals/prov \
 && printf '# Placeholder for the Provenance user CA public key.\n# The enrollment flow overwrites this file with the real CA key.\n' \
      > /etc/ssh/prov_ca.pub

COPY sshd_prov.conf /etc/ssh/sshd_config.d/00-prov.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# 51820/udp = WireGuard overlay; 1194/udp = OpenVPN overlay (FIPS, selectable per host).
EXPOSE 22 51820/udp 1194/udp
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
