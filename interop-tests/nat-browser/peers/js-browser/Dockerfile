# js-browser /webrtc interop peer for the double-NAT topology.
#
# js-libp2p running in stock Chrome (same selenium base as the rust wasm peer)
# with the browser's native RTCPeerConnection - no node-datachannel polyfill.
# The page (src/page.js) is bundled with esbuild; driver.mjs serves it over
# loopback, drives Chrome via playwright-core and does the redis rendezvous.
#
# Build with this directory as context:
#
#   docker build -t natwebrtc-peer-js-browser peers/js-browser

FROM node:22-slim AS bundler

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY src ./src
RUN npm run bundle \
    # esbuild (and the rest of the devDependencies) are only needed for bundling.
    && npm prune --omit=dev --no-audit --no-fund

FROM selenium/standalone-chrome:125.0

USER root
# Node 22 for the driver; the selenium base (ubuntu jammy) ships an ancient node.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

COPY --from=bundler /app/node_modules /app/node_modules
COPY --from=bundler /app/dist /app/dist
COPY driver.mjs package.json /app/
RUN chown -R seluser:seluser /app

USER seluser
WORKDIR /app

ENTRYPOINT ["node", "/app/driver.mjs"]
CMD ["dialer"]
