# rust-wasm-browser /webrtc interop peer for the double-NAT topology.
#
# Runs the `wasm_ping` wrapper (interop-tests/src/bin/wasm_ping.rs) on top of the
# stock Chrome + chromedriver that ship in the selenium image: the wrapper serves
# the embedded wasm-pack bundle of libp2p-webrtc-websys to a headless Chrome it
# spawns via chromedriver, proxies redis for the page, threads `ice_server` and
# `relay_addr` from the env into the page, and prints the browser's selected ICE
# candidate pair (via the /ice endpoint) plus the final ping report.
#
# The binary is compiled statically on the host with the wasm bundle embedded
# (see build-images.sh) and COPYed in - no dockerized cargo/wasm-pack build.
# Build with the nat-browser directory as context:
#
#   docker build -f peers/rust-wasm/Dockerfile -t natwebrtc-peer-rust-wasm .
FROM selenium/standalone-chrome:125.0

COPY bin/wasm_ping /usr/local/bin/wasm_ping
COPY peers/rust-wasm/entrypoint.sh /usr/local/bin/peer-entrypoint.sh

USER root
RUN chmod +x /usr/local/bin/peer-entrypoint.sh /usr/local/bin/wasm_ping
USER seluser

ENV transport=webrtc \
    ip=0.0.0.0 \
    RUST_BACKTRACE=1

ENTRYPOINT ["/usr/local/bin/peer-entrypoint.sh"]
CMD ["dialer"]
