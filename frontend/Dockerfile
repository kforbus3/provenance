# syntax=docker/dockerfile:1
# Build the React app and serve it via nginx, which also reverse-proxies the
# API + WebSocket traffic so the browser sees a single origin.
#
# NOTE: the build context is the repository root (see deploy/compose), not the
# frontend/ directory. The in-app help bundle is generated at build time from the
# repo-root docs/ (scripts/build-help.mjs), so docs/ must be present in the image
# — hence the repo-root context and the `COPY docs/` below.

FROM node:22-alpine AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
# The help build step (npm prebuild) reads ../../docs relative to /app/scripts,
# i.e. /docs in the image. Without this, help ships empty and the Help page fails.
COPY docs/ /docs/
RUN npm run build

FROM nginx:1.27-alpine AS runtime
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
