#!/bin/bash
#
# go-libp2p -> rust-native interop runner.
#
# Runs the native rust WebTransport echo server example
# (transports/webtransport/examples/echo_server.rs) in the background, which
# serves its multiaddr on 127.0.0.1:4455, then builds and runs the go-libp2p
# WebTransport dialer in wt-client/ against it. The dialer prints CONNECT_OK on
# a successful connection (including the Noise handshake / peer-id check) and a
# non-zero exit code otherwise.

set -u

# cd to this script directory
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

echo "Tests: $PWD"

# Build the go client.
(cd wt-client && go build -o wt-client .) || exit 1

# Build the native echo server *before* backgrounding it. On a cold CI cache the
# libp2p-webtransport/quinn stack can take longer to compile than the dialer's
# discovery timeout; building up-front ensures the timeout only covers server
# startup, not compilation.
cargo build --quiet -p libp2p-webtransport --example echo_server || exit 1

# Start the native echo server (serves its multiaddr on 127.0.0.1:4455).
cargo run --quiet -p libp2p-webtransport --example echo_server &
server_pid=$!

cleanup() {
    kill "$server_pid" 2> /dev/null
    wait "$server_pid" 2> /dev/null
}
trap cleanup EXIT

# Wait for the discovery endpoint to come up (max ~30s) before dialing, so the go
# client only attempts discovery/connect once the server is actually listening.
for _ in $(seq 1 150); do
    if curl --silent --fail --max-time 1 http://127.0.0.1:4455/ > /dev/null 2>&1; then
        break
    fi
    sleep 0.2
done

# Run the go dialer; it discovers the multiaddr from 127.0.0.1:4455 itself.
output="$(./wt-client/wt-client -discover -timeout 40s)"
exit_code=$?
echo "$output"

if [ "$exit_code" -ne 0 ]; then
    echo "go-libp2p failed to dial the native WebTransport server"
    exit "$exit_code"
fi

case "$output" in
    CONNECT_OK*) exit 0 ;;
    *)
        echo "unexpected output from wt-client"
        exit 1
        ;;
esac
