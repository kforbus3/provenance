FROM nginx:stable-alpine

# envsubst ships in the gettext package.
RUN apk add --no-cache gettext

COPY nginx.conf.tmpl /nginx.conf.tmpl
COPY nginx-updates.conf.tmpl /nginx-updates.conf.tmpl
COPY boot.ipxe.tmpl /boot.ipxe.tmpl
COPY default.ipxe.tmpl /default.ipxe.tmpl
COPY unassigned.ipxe.tmpl /unassigned.ipxe.tmpl
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
