# TrueMed Backend API — production image
#
# Multi-stage so the runtime image contains no build toolchain and no dev
# dependencies. Node 20 LTS on Alpine, pinned to a minor version: "node:20" would
# silently change under a rebuild, and a QR verification service whose crypto
# runtime moves without anyone noticing is not something to hand to CDSCO.
#
# Built and run from the backend/ directory:
#   docker build -t truemed-api:1.0.0 .
#   docker run --rm -p 8080:8080 --env-file .env truemed-api:1.0.0

# ─── Stage 1: dependencies ──────────────────────────────────────────────────
FROM node:20.18-alpine3.20 AS deps

WORKDIR /app

# Copy only the manifests first. This layer is then cached across every source
# change, so editing a route does not reinstall node_modules.
COPY package.json package-lock.json* ./

# `npm ci` installs exactly what the lockfile says, which is the difference
# between a reproducible image and "it worked last Tuesday". `--omit=dev` leaves
# the test tooling out — there is none to speak of, since tests use node:test.
# If no lockfile is present yet, fall back to `npm install` so a fresh clone can
# still build.
RUN if [ -f package-lock.json ]; then \
      npm ci --omit=dev; \
    else \
      echo "WARNING: no package-lock.json; falling back to npm install" >&2; \
      npm install --omit=dev --no-audit --no-fund; \
    fi

# ─── Stage 2: runtime ───────────────────────────────────────────────────────
FROM node:20.18-alpine3.20 AS runtime

# wget is used by HEALTHCHECK below; curl is not in the base image.
# dumb-init gives the container a real PID 1 that forwards SIGTERM, so
# `docker stop` triggers graceful shutdown instead of a 10-second kill.
#
# Deliberately not pinned to an apk revision: Alpine drops old revisions from the
# repository index, so a pin like `=1.2.5-r3` turns into a hard build failure a
# few months later. The base image tag is pinned instead, which is what actually
# determines reproducibility here.
RUN apk add --no-cache dumb-init

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0 \
    LOG_PRETTY=0 \
    NODE_OPTIONS=--enable-source-maps

WORKDIR /app

# The base image already ships an unprivileged `node` user (uid 1000). Running as
# root inside a container is one container-escape CVE away from being root on the
# host, and this service parses attacker-supplied QR strings for a living.
COPY --chown=node:node --from=deps /app/node_modules ./node_modules
COPY --chown=node:node package.json ./
COPY --chown=node:node src ./src
COPY --chown=node:node db ./db

# Trust bundle and root public key are mounted at runtime, not baked in: they
# change when a manufacturer is added, and baking them would mean rebuilding the
# image to onboard a company.
#   docker run -v $(pwd)/keys:/app/keys:ro ...
RUN mkdir -p /app/keys && chown node:node /app/keys

USER node

EXPOSE 8080

# /readyz reports dependency health (database, cache, chaincode); /healthz only
# reports that the process is alive. The readiness probe is the right one for a
# container health check, because an API that cannot reach Postgres should not
# receive traffic.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget --quiet --tries=1 --spider "http://127.0.0.1:${PORT}/readyz" || exit 1

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/server.js"]
