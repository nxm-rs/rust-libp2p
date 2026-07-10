# rust-native /webrtc interop peer for the double-NAT topology.
#
# Runs the rust interop harness binary (`interop-tests/src/bin/native_ping.rs`):
# redis rendezvous on the `listenerAddr` key, external relay via `relay_addr`,
# STUN/TURN via `ice_server` - all provided by docker-compose.nat.yml.
#
# The binary is compiled statically on the host (see build-images.sh) and COPYed
# in - no dockerized cargo build. Build with the nat-browser directory as context:
#
#   docker build -f peers/rust-native/Dockerfile -t natwebrtc-peer-rust-native .
FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY bin/native_ping /usr/local/bin/native_ping
COPY peers/rust-native/entrypoint.sh /usr/local/bin/peer-entrypoint.sh
RUN chmod +x /usr/local/bin/peer-entrypoint.sh

ENV transport=webrtc \
    ip=0.0.0.0 \
    RUST_BACKTRACE=1

ENTRYPOINT ["/usr/local/bin/peer-entrypoint.sh"]
CMD ["dialer"]
