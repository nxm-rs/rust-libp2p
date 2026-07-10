FROM node:22-slim

WORKDIR /app

# node-datachannel ships prebuilt binaries for linux x64/arm64 glibc, so no
# toolchain is needed; ca-certificates keeps npm happy behind TLS proxies.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY src ./src

# Fail the build early if the webrtc stack cannot even be constructed.
RUN node src/smoke.js

ENV COORD_FILE=/coord/dial_addr \
    TEST_TIMEOUT_SECS=180

ENTRYPOINT ["node", "src/index.js"]
CMD ["dialer"]
