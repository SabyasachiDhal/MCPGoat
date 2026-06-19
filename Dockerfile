# syntax=docker/dockerfile:1
# MCPGoat — lightweight, self-contained image.
# The builder bundles the server (esbuild) into one ~1.2 MB file; the runtime
# stage is a clean Alpine with ONLY the `node` binary copied in (no npm,
# corepack, headers, or node_modules) plus curl/ping for the RCE challenge.

# ---- builder: install deps and bundle to a single file ----
FROM node:24-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run bundle

# ---- runtime: bare Alpine + the node binary + the bundle ----
FROM alpine:3.22 AS runtime
# libstdc++ is node's only shared-lib dependency; curl/ping serve the RCE challenge.
RUN apk add --no-cache libstdc++ curl iputils \
 && addgroup -S app && adduser -S app -G app
COPY --from=node:24-alpine /usr/local/bin/node /usr/local/bin/node
WORKDIR /app
ENV NODE_ENV=production \
    NODE_NO_WARNINGS=1 \
    HOST=0.0.0.0 \
    PORT=7332 \
    MCPGOAT_LEVEL=easy
COPY --from=builder /app/bundle ./bundle
COPY workspace ./workspace
COPY vault ./vault
EXPOSE 7332
# Run unprivileged. The intentional RCE challenge still works, but as non-root.
USER app
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:7332/api/state >/dev/null 2>&1 || exit 1
CMD ["node", "bundle/server.mjs"]
