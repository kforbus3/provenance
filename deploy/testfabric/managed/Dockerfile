# Provenance test fabric — managed host.
#
# Parameterized base image (ubuntu:22.04 or rockylinux:9). Runs OpenSSH
# trusting the fleet user CA, plus userspace WireGuard (wireguard-go) peered
# with the jump host. The 'prov' user has passwordless sudo.

ARG BASE_IMAGE=ubuntu:22.04

# Build wireguard-go from source so the same image works on both Debian-
# and RHEL-family bases without relying on distro WireGuard packaging.
FROM golang:1.23-alpine AS wgbuild
RUN apk add --no-cache git make
RUN git clone --depth=1 https://git.zx2c4.com/wireguard-go /src \
 && make -C /src
# Produces /src/wireguard-go

FROM ${BASE_IMAGE}

# Install OpenSSH, wireguard-tools, iproute, and sudo across apt/dnf bases.
RUN if command -v apt-get >/dev/null 2>&1; then \
      export DEBIAN_FRONTEND=noninteractive; \
      apt-get update && \
      apt-get install -y --no-install-recommends \
        openssh-server wireguard-tools iproute2 iptables sudo ca-certificates && \
      rm -rf /var/lib/apt/lists/*; \
    elif command -v dnf >/dev/null 2>&1; then \
      dnf -y install epel-release && \
      dnf -y install openssh-server wireguard-tools iproute iptables sudo && \
      dnf clean all; \
    else \
      echo "unsupported base image: no apt-get or dnf" >&2; exit 1; \
    fi

COPY --from=wgbuild /src/wireguard-go /usr/local/bin/wireguard-go

# Two login accounts (matching enrollment): 'prov' has passwordless sudo;
# 'prov-login' is login-only (no sudo). Provenance CA-signed certs map to each by
# principal (prov / prov-login).
RUN useradd -m -s /bin/bash prov \
 && useradd -m -s /bin/bash prov-login \
 && echo 'prov ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/prov \
 && chmod 0440 /etc/sudoers.d/prov

# sshd privilege-separation dir, principals mapping, and Provenance CA placeholder.
RUN mkdir -p /run/sshd /etc/ssh/auth_principals \
 && printf 'prov\nfleet\n' > /etc/ssh/auth_principals/prov \
 && printf 'prov-login\n' > /etc/ssh/auth_principals/prov-login \
 && printf '# Placeholder for the Provenance user CA public key.\n# The enrollment flow overwrites this file with the real CA key.\n' \
      > /etc/ssh/prov_ca.pub

COPY sshd_prov.conf /etc/ssh/sshd_config.d/00-prov.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22 51820/udp
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
