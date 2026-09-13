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

COPY --from=wgbuild /src/wireguard-go /usr/local/bin/wireguard-go

# Login user that the fleet CA-signed certificates map to. Passwordless sudo so
# the enrollment flow can add WireGuard peers (wg set) on the jump host.
RUN useradd -m -s /bin/bash fleet \
 && echo 'fleet ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/prov \
 && chmod 0440 /etc/sudoers.d/prov

# sshd privilege-separation dir, principals mapping, and the fleet CA
# placeholder that the enrollment flow replaces with the real CA pubkey.
RUN mkdir -p /run/sshd /etc/ssh/auth_principals \
 && printf 'fleet\n' > /etc/ssh/auth_principals/prov \
 && printf '# Placeholder for the Provenance user CA public key.\n# The enrollment flow overwrites this file with the real CA key.\n' \
      > /etc/ssh/prov_ca.pub

COPY sshd_prov.conf /etc/ssh/sshd_config.d/00-prov.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# 51820/udp = WireGuard overlay; 1194/udp = OpenVPN overlay (FIPS, selectable per host).
EXPOSE 22 51820/udp 1194/udp
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
