#!/bin/sh
set -e
redis-server --protected-mode no --bind 0.0.0.0 --daemonize yes
exec nginx -g 'daemon off;'
