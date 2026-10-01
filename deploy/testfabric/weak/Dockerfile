# A deliberately weak network target for the test fabric and `make netscan-e2e`.
#
# Every weakness here is one the network scan MUST report. A scan of hosts with
# nothing wrong with them returns nothing, and so does a broken scanner -- the two
# are indistinguishable, so the scanner is tested against something it has to find:
#
#   6379/tcp  Redis with no authentication and protected mode off  (exposed-redis)
#   443/tcp   nginx accepting TLS 1.0 and 1.1                       (deprecated-tls)
#   80/tcp    a web root exposing .git/config                       (git-config)
#
# NEVER run this anywhere but an isolated test network.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends redis-server nginx openssl \
    && rm -rf /var/lib/apt/lists/*
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=weak-target" \
      -keyout /etc/ssl/private/weak.key -out /etc/ssl/certs/weak.crt \
    && mkdir -p /var/www/weak/.git \
    && printf '[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote "origin"]\n\turl = https://example.invalid/weak.git\n' > /var/www/weak/.git/config \
    && echo '<html><body>weak-target</body></html>' > /var/www/weak/index.html
COPY nginx.conf /etc/nginx/sites-enabled/default
COPY entrypoint.sh /entrypoint.sh
EXPOSE 80 443 6379
CMD ["/entrypoint.sh"]
