// wt-client is a minimal go-libp2p WebTransport dialer used as an interop harness
// for the `go-libp2p -> rust-native` cell of the WebTransport interop matrix.
//
// It is the counterpart of the native rust echo server
// (`transports/webtransport/examples/echo_server.rs`): given a WebTransport
// multiaddr (including `/certhash` and `/p2p/<peer>`), it constructs a go-libp2p
// host with only the WebTransport transport enabled, dials the target, and reports
// the outcome on stdout:
//
//	CONNECT_OK peer=<peer-id>      - the connection (incl. Noise handshake) succeeded
//	CONNECT_FAILED: <err>          - dialing failed
//
// The multiaddr can be passed as the first CLI argument, or, when invoked with
// `-discover`, fetched from the HTTP discovery endpoint on 127.0.0.1:4455 that the
// native echo server serves (mirroring the discovery used by the browser harness).
//
// Usage:
//
//	wt-client <multiaddr>
//	wt-client -discover
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	webtransport "github.com/libp2p/go-libp2p/p2p/transport/webtransport"
	"github.com/multiformats/go-multiaddr"
)

const discoveryURL = "http://127.0.0.1:4455/"

func main() {
	discover := flag.Bool("discover", false, "fetch the target multiaddr from the HTTP discovery endpoint on 127.0.0.1:4455 instead of taking it as an argument")
	timeout := flag.Duration("timeout", 20*time.Second, "overall timeout for discovery + connect")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var addr string
	if *discover {
		var err error
		addr, err = fetchAddr(ctx)
		if err != nil {
			fmt.Println("DISCOVER_FAILED:", err)
			os.Exit(1)
		}
	} else {
		if flag.NArg() < 1 {
			fmt.Println("usage: wt-client [-discover] [-timeout=20s] <multiaddr>")
			os.Exit(2)
		}
		addr = flag.Arg(0)
	}

	ma, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		fmt.Println("BAD_ADDR:", err)
		os.Exit(2)
	}
	info, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		fmt.Println("BAD_P2P:", err)
		os.Exit(2)
	}

	h, err := libp2p.New(
		libp2p.Transport(webtransport.New),
		libp2p.NoListenAddrs,
	)
	if err != nil {
		fmt.Println("HOST_ERR:", err)
		os.Exit(1)
	}
	defer h.Close()

	if err := h.Connect(ctx, *info); err != nil {
		fmt.Println("CONNECT_FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("CONNECT_OK peer=", info.ID.String())
}

// fetchAddr polls the discovery endpoint until the server reports a multiaddr or
// the context expires.
func fetchAddr(ctx context.Context) (string, error) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		addr, err := tryFetchAddr(ctx)
		if err == nil && addr != "" {
			return addr, nil
		}
		if err != nil {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			if lastErr != nil {
				return "", fmt.Errorf("discovery endpoint never responded: %w", lastErr)
			}
			return "", fmt.Errorf("discovery endpoint never responded: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func tryFetchAddr(ctx context.Context) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}
