#!/bin/bash
#
# Browser -> rust-native interop runner.
#
# Mirrors run.sh, but instead of building/running the go-libp2p echo-server in a
# container, it runs the *native* rust WebTransport echo server example
# (transports/webtransport/examples/echo_server.rs) in the background. The wasm
# test suite discovers the server's multiaddr over HTTP on 127.0.0.1:4455, so it
# does not care whether the server is the go one or the native one.

set -u

# cd to this script directory
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

echo "Tests: $PWD"

# Start the native echo server (serves its multiaddr on 127.0.0.1:4455).
cargo run --quiet -p libp2p-webtransport --example echo_server &
server_pid=$!

cleanup() {
    kill "$server_pid" 2> /dev/null
    wait "$server_pid" 2> /dev/null
}
trap cleanup EXIT

# Wait for the discovery endpoint to come up (max ~30s).
for _ in $(seq 1 150); do
    if curl --silent --fail --max-time 1 http://127.0.0.1:4455/ > /dev/null 2>&1; then
        break
    fi
    sleep 0.2
done

# Run the browser tests against the native server.
wasm-pack test --chrome --headless
exit_code=$?

exit $exit_code
