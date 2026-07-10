// Copyright 2026 Protocol Labs.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Shared QUIC endpoint with ALPN-routed connection acceptance.
//!
//! A [`SharedQuicEndpoint`] owns one [`quinn::Endpoint`] (one UDP socket, one port) and lets
//! several protocols co-listen on it. Each protocol registers the ALPN it serves together with a
//! complete [`quinn::ServerConfig`] (carrying that protocol's own certificate and client-auth
//! verifier) and a channel on which it receives inbound connections. The accept loop peeks the
//! ALPN offered in the client's Initial packet, accepts the connection with the matching
//! `ServerConfig` via [`quinn::Incoming::accept_with`], and hands the resulting
//! [`quinn::Connecting`] to the registered channel. This mirrors go-libp2p's `quicreuse`.
//!
//! # Safety property
//!
//! The ALPN peek is only a routing HINT. Each registered `ServerConfig` independently enforces
//! its own ALPN allowlist and its own verifier, so a wrong, absent, or maliciously crafted peek
//! can at worst route to a config whose handshake then fails with an ALPN mismatch. It can never
//! downgrade authentication: the client-auth policy is fixed by the selected `ServerConfig`
//! before the handshake starts, not negotiated by the hint.
//!
//! Two further invariants are enforced at [`register`](SharedQuicEndpoint::register) /
//! [`update_server_config`](SharedQuicEndpoint::update_server_config) time so the property above
//! cannot be undermined by a misconfigured registration:
//!
//! * A route's declared ALPN allowlist must contain the ALPN it is registered under (a config that
//!   could never complete a handshake for its own key is rejected), and
//! * No two routes may declare overlapping allowlists. If two routes both accepted the same ALPN,
//!   the peek could route a connection offering it to either handshake, making the client-auth
//!   policy for that ALPN non-deterministic. Rejecting the overlap keeps each ALPN bound to exactly
//!   one auth policy.
//!
//! The fallback for an absent or unknown offered ALPN is the explicitly designated *default route*
//! (see [`register`](SharedQuicEndpoint::register)'s `default` flag), not a positional accident of
//! registration order: the mutual-auth `libp2p`/QUIC route stays the fallback even if a
//! no-client-auth route (e.g. WebTransport) is registered on the same endpoint first.
//!
//! # Denial-of-service posture
//!
//! The ClientHello parse behind [`quinn::Incoming::alpn`] runs inside quinn after its retry and
//! address-validation handling of the Initial packet. On top of that, this crate only reads the
//! hint when more than one ALPN is registered; a single-protocol endpoint takes the direct
//! accept path with no peek-dependent branching.
//!
//! # Migration note: dropping the quinn fork
//!
//! `Incoming::alpn()` / `Incoming::server_name()` are a best-effort peek carried by our pinned
//! `quinn`/`quinn-proto` fork (see `[patch.crates-io]` in the workspace `Cargo.toml`). They are a
//! stopgap: the peek reads only the first Initial packet, so a ClientHello that spans multiple
//! packets (large post-quantum key shares, extra extensions) can peek empty and misroute.
//!
//! The upstream replacement is quinn PR #2671 ("staged ClientHello acceptor for `ServerConfig`
//! selection", closes quinn-rs/quinn#2024; prerequisite #2701 rustls-0.24), which buffers the
//! full ClientHello and hands it to an acceptor callback that returns the `ServerConfig` — fixing
//! the large-ClientHello misroute. Do NOT describe this as "upstreaming `Incoming::alpn()`": the
//! upstream API is a staged acceptor, not the peek accessor.
//!
//! Cutting over is a single ATOMIC change, not a bare `[patch]` drop: quinn 0.11.11's `Incoming`
//! has no `alpn()`/`server_name()`, so removing the patch without simultaneously rewriting this
//! crate's accept loop (`route_incoming`) onto the staged-acceptor API will not compile. Because
//! the staged acceptor changes the routing input (whole ClientHello vs. first-packet peek), the
//! cutover also needs end-to-end re-validation against the interop suites.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use std::{
    fmt,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex, MutexGuard},
};

use futures::channel::mpsc;

/// Errors raised by [`SharedQuicEndpoint`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An I/O error occurred while creating the endpoint.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The ALPN is already registered on this endpoint.
    #[error("ALPN {0:?} is already registered on this endpoint")]
    DuplicateAlpn(AlpnProtocol),
    /// The ALPN is not registered on this endpoint.
    #[error("ALPN {0:?} is not registered on this endpoint")]
    UnknownAlpn(AlpnProtocol),
    /// The route key ALPN is not contained in the `ServerConfig`'s own ALPN allowlist, so the
    /// config could never complete a handshake for the ALPN it is registered under.
    #[error("route key ALPN {0:?} is not in its own ServerConfig ALPN allowlist")]
    RouteKeyNotInAllowlist(AlpnProtocol),
    /// The `ServerConfig`'s ALPN allowlist overlaps an already-registered route's allowlist. Two
    /// routes accepting the same ALPN would let the peek route a connection to either handshake,
    /// so the auth policy for that ALPN would no longer be deterministic.
    #[error("ALPN {0:?} is already served by another registered route's ServerConfig allowlist")]
    OverlappingAllowlist(AlpnProtocol),
}

/// An ALPN protocol identifier, displayed as ASCII where possible.
#[derive(Clone, PartialEq, Eq)]
pub struct AlpnProtocol(pub Vec<u8>);

impl fmt::Debug for AlpnProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match std::str::from_utf8(&self.0) {
            Ok(s) => write!(f, "{s}"),
            Err(_) => write!(f, "{:02x?}", self.0),
        }
    }
}

/// A shared QUIC endpoint: one [`quinn::Endpoint`], one UDP socket, one port, with inbound
/// connections routed to the protocol that registered the offered ALPN.
///
/// Dropping the holder stops the accept loop but leaves established connections running; they
/// keep the underlying endpoint driver alive until they close.
pub struct SharedQuicEndpoint {
    endpoint: quinn::Endpoint,
    socket: UdpSocket,
    routes: Arc<Mutex<RouteTable>>,
    local_addr: SocketAddr,
    accept_task: tokio::task::JoinHandle<()>,
}

impl fmt::Debug for SharedQuicEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedQuicEndpoint")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl SharedQuicEndpoint {
    /// Creates a shared endpoint on the given socket and spawns its accept loop.
    ///
    /// Must be called within a tokio runtime. The endpoint starts without any registered ALPN
    /// and does not accept connections until the first [`register`](Self::register) call.
    pub fn new(endpoint_config: quinn::EndpointConfig, socket: UdpSocket) -> Result<Self, Error> {
        let socket_clone = socket.try_clone()?;
        let endpoint =
            quinn::Endpoint::new(endpoint_config, None, socket, Arc::new(quinn::TokioRuntime))?;
        let local_addr = endpoint.local_addr()?;
        let routes = Arc::new(Mutex::new(RouteTable { routes: Vec::new() }));
        let accept_task = tokio::spawn(accept_loop(endpoint.clone(), Arc::clone(&routes)));
        Ok(Self {
            endpoint,
            socket: socket_clone,
            routes,
            local_addr,
            accept_task,
        })
    }

    /// Convenience constructor binding a new UDP socket on `addr` with default endpoint config.
    pub fn bind(addr: SocketAddr) -> Result<Self, Error> {
        Self::new(quinn::EndpointConfig::default(), UdpSocket::bind(addr)?)
    }

    /// The local address the underlying socket is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Clones the underlying UDP socket, e.g. to send raw packets alongside QUIC traffic.
    ///
    /// The clone shares the file description with the endpoint's socket, so datagrams sent on
    /// it originate from the shared port.
    pub fn try_clone_socket(&self) -> std::io::Result<UdpSocket> {
        self.socket.try_clone()
    }

    /// Closes all connections on the endpoint immediately and stops accepting new ones.
    ///
    /// Intended for a holder owned by a single protocol. On a genuinely shared endpoint prefer
    /// [`unregister`](Self::unregister), which leaves the other protocols' connections running.
    pub fn close(&self, error_code: quinn::VarInt, reason: &[u8]) {
        self.endpoint.close(error_code, reason);
    }

    /// Registers a protocol on this endpoint: inbound connections offering `alpn` are accepted
    /// with `server_config` and delivered on `sink`.
    ///
    /// `allowlist` is the set of ALPNs `server_config` will complete a handshake for (i.e. its
    /// rustls `alpn_protocols`); it must contain `alpn`. Registering a second protocol promotes
    /// the endpoint to mixed mode, in which the offered ALPN is peeked to select the route.
    ///
    /// `default` designates this route as the fallback for connections whose offered ALPN is
    /// absent or matches no route. Exactly the route registered with `default == true` receives
    /// those connections (its own `ServerConfig` still decides whether they may complete the
    /// handshake), regardless of registration order. This is how the mutual-auth `libp2p`/QUIC
    /// route stays the fallback even when a no-client-auth route is registered first. If no route
    /// is registered as default, the first-registered route is used as a last resort.
    ///
    /// Errors if `alpn` is already registered ([`Error::DuplicateAlpn`]), if `allowlist` does not
    /// contain `alpn` ([`Error::RouteKeyNotInAllowlist`]), or if `allowlist` overlaps another
    /// registered route's allowlist ([`Error::OverlappingAllowlist`]).
    pub fn register(
        &self,
        alpn: Vec<u8>,
        allowlist: Vec<Vec<u8>>,
        server_config: Arc<quinn::ServerConfig>,
        sink: mpsc::Sender<quinn::Connecting>,
        default: bool,
    ) -> Result<(), Error> {
        let mut table = lock(&self.routes);
        if table.routes.iter().any(|r| r.alpn == alpn) {
            return Err(Error::DuplicateAlpn(AlpnProtocol(alpn)));
        }
        validate_allowlist(&alpn, &allowlist, &table.routes, None)?;
        table.routes.push(Route {
            alpn,
            allowlist,
            server_config,
            sink,
            default,
        });
        self.sync_endpoint_config(&table);
        Ok(())
    }

    /// Removes a registered protocol. Connections already handed to its sink are unaffected.
    ///
    /// If the designated default protocol is removed, the fallback reverts to the first remaining
    /// route until another default is registered. Removing the last protocol stops the endpoint
    /// accepting connections.
    pub fn unregister(&self, alpn: &[u8]) {
        let mut table = lock(&self.routes);
        table.routes.retain(|r| r.alpn != alpn);
        self.sync_endpoint_config(&table);
    }

    /// Replaces the `ServerConfig` (and its declared `allowlist`) for a registered ALPN, e.g. on
    /// certificate rotation. Affects new inbound connections only.
    ///
    /// The same invariants as [`register`](Self::register) are re-checked against the other
    /// routes: `allowlist` must contain `alpn` and must not overlap another route's allowlist.
    ///
    /// Errors if `alpn` is not registered ([`Error::UnknownAlpn`]).
    pub fn update_server_config(
        &self,
        alpn: &[u8],
        allowlist: Vec<Vec<u8>>,
        server_config: Arc<quinn::ServerConfig>,
    ) -> Result<(), Error> {
        let mut table = lock(&self.routes);
        let Some(index) = table.routes.iter().position(|r| r.alpn == alpn) else {
            return Err(Error::UnknownAlpn(AlpnProtocol(alpn.to_vec())));
        };
        // Exclude the route being updated from the overlap check: it is expected to still serve
        // its own key ALPN.
        validate_allowlist(alpn, &allowlist, &table.routes, Some(index))?;
        table.routes[index].allowlist = allowlist;
        table.routes[index].server_config = server_config;
        self.sync_endpoint_config(&table);
        Ok(())
    }

    /// Dials a raw QUIC connection from the shared socket.
    ///
    /// `client_config` carries the dialling protocol's own ALPN and verifier; `server_name` is
    /// the SNI offered to the remote.
    pub fn dial_quic(
        &self,
        addr: SocketAddr,
        client_config: quinn::ClientConfig,
        server_name: &str,
    ) -> Result<quinn::Connecting, quinn::ConnectError> {
        self.endpoint.connect_with(client_config, addr, server_name)
    }

    /// Keeps the endpoint-level `ServerConfig` aligned with the default route.
    ///
    /// Routing always accepts with an explicit per-route config, but quinn only produces
    /// [`quinn::Incoming`] events (and generates retry tokens) while an endpoint-level config is
    /// set, so it must be present exactly while at least one route is registered.
    fn sync_endpoint_config(&self, table: &RouteTable) {
        self.endpoint.set_server_config(
            table
                .default_index()
                .map(|i| table.routes[i].server_config.as_ref().clone()),
        );
    }
}

/// Checks the allowlist invariants for a route about to be (re)registered under `alpn`:
/// the allowlist must contain the route key, and must not overlap any other route's allowlist.
/// `skip` is the index of the route being updated in place, excluded from the overlap scan.
fn validate_allowlist(
    alpn: &[u8],
    allowlist: &[Vec<u8>],
    routes: &[Route],
    skip: Option<usize>,
) -> Result<(), Error> {
    if !allowlist.iter().any(|a| a == alpn) {
        return Err(Error::RouteKeyNotInAllowlist(AlpnProtocol(alpn.to_vec())));
    }
    for (i, route) in routes.iter().enumerate() {
        if Some(i) == skip {
            continue;
        }
        if let Some(clash) = allowlist.iter().find(|a| route.allowlist.contains(a)) {
            return Err(Error::OverlappingAllowlist(AlpnProtocol(clash.clone())));
        }
    }
    Ok(())
}

impl Drop for SharedQuicEndpoint {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

struct RouteTable {
    routes: Vec<Route>,
}

impl RouteTable {
    /// Index of the fallback route for absent/unknown offered ALPNs: the explicitly designated
    /// default route, or the first remaining route if the default was unregistered, or `None`
    /// when no route is registered.
    fn default_index(&self) -> Option<usize> {
        if self.routes.is_empty() {
            return None;
        }
        Some(self.routes.iter().position(|r| r.default).unwrap_or(0))
    }

    fn select(&self, offered: &[Vec<u8>], default: usize) -> usize {
        select_route(
            offered,
            self.routes.iter().map(|r| r.alpn.as_slice()),
            default,
        )
    }
}

/// Index of the route serving the offered ALPN list: the route whose ALPN equals the first
/// offered protocol, else the designated `default` route.
fn select_route<'a>(
    offered: &[Vec<u8>],
    registered: impl Iterator<Item = &'a [u8]>,
    default: usize,
) -> usize {
    match offered.first() {
        Some(first) => registered
            .enumerate()
            .find_map(|(i, alpn)| (alpn == first.as_slice()).then_some(i))
            // Absent or unknown ALPN: fall back to the default route. Its `ServerConfig`
            // still enforces its own ALPN allowlist, so this cannot mis-authenticate.
            .unwrap_or(default),
        None => default,
    }
}

struct Route {
    /// The ALPN this route is registered (and routed) under.
    alpn: Vec<u8>,
    /// The full set of ALPNs this route's `ServerConfig` will complete a handshake for. Contains
    /// `alpn` and never overlaps another route's allowlist (enforced at registration).
    allowlist: Vec<Vec<u8>>,
    server_config: Arc<quinn::ServerConfig>,
    sink: mpsc::Sender<quinn::Connecting>,
    /// Whether this is the designated default (fallback) route for absent/unknown ALPNs.
    default: bool,
}

/// Locks ignoring poisoning: the table is only mutated by panic-free operations, and the accept
/// path must never panic.
fn lock(routes: &Mutex<RouteTable>) -> MutexGuard<'_, RouteTable> {
    routes.lock().unwrap_or_else(|e| e.into_inner())
}

async fn accept_loop(endpoint: quinn::Endpoint, routes: Arc<Mutex<RouteTable>>) {
    while let Some(incoming) = endpoint.accept().await {
        route_incoming(incoming, &routes);
    }
}

fn route_incoming(incoming: quinn::Incoming, routes: &Mutex<RouteTable>) {
    let mut table = lock(routes);

    // A dropped receiver means the registering protocol is gone; prune so the default
    // fallback always lands on a live route.
    table.routes.retain(|r| !r.sink.is_closed());

    let Some(default) = table.default_index() else {
        tracing::debug!(remote=%incoming.remote_address(), "no registered ALPN, refusing");
        incoming.refuse();
        return;
    };

    // Only consult the peeked hint in mixed mode; a single-protocol endpoint accepts directly.
    let index = if table.routes.len() > 1 {
        table.select(incoming.alpn(), default)
    } else {
        default
    };

    let route = &mut table.routes[index];
    let server_config = Arc::clone(&route.server_config);
    match incoming.accept_with(server_config) {
        Ok(connecting) => {
            if let Err(e) = route.sink.try_send(connecting) {
                // Dropping the `Connecting` aborts the connection. Deliberately no
                // backpressure: waiting here would let one slow protocol stall the accept
                // loop for all the others.
                tracing::debug!(
                    alpn=?AlpnProtocol(route.alpn.clone()),
                    full=%e.is_full(),
                    "inbound connection dropped, sink unavailable"
                );
            }
        }
        Err(e) => {
            // The selected `ServerConfig` already rejected the connection, e.g. its ALPN
            // allowlist does not contain what the client offered. quinn has told the client.
            tracing::debug!("failed to accept inbound connection: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGISTERED: &[&[u8]] = &[b"libp2p", b"h3"];

    fn select_with_default(offered: &[&[u8]], default: usize) -> usize {
        let offered = offered.iter().map(|a| a.to_vec()).collect::<Vec<_>>();
        select_route(&offered, REGISTERED.iter().copied(), default)
    }

    fn select(offered: &[&[u8]]) -> usize {
        select_with_default(offered, 0)
    }

    #[test]
    fn matching_alpn_selects_its_route() {
        assert_eq!(select(&[b"libp2p"]), 0);
        assert_eq!(select(&[b"h3"]), 1);
    }

    #[test]
    fn first_offered_protocol_wins() {
        assert_eq!(select(&[b"h3", b"libp2p"]), 1);
    }

    #[test]
    fn absent_alpn_selects_default() {
        assert_eq!(select(&[]), 0);
    }

    #[test]
    fn unknown_alpn_selects_default() {
        assert_eq!(select(&[b"other"]), 0);
    }

    #[test]
    fn matching_alpn_ignores_default() {
        // A concretely offered, registered ALPN always wins over the fallback, whatever the
        // designated default index is.
        assert_eq!(select_with_default(&[b"libp2p"], 1), 0);
        assert_eq!(select_with_default(&[b"h3"], 0), 1);
    }

    #[test]
    fn absent_or_unknown_alpn_honours_nonzero_default() {
        // The fallback follows the designated default route, not positional index 0: e.g. when
        // the mutual-auth route was registered second, absent/unknown ALPNs still land on it.
        assert_eq!(select_with_default(&[], 1), 1);
        assert_eq!(select_with_default(&[b"other"], 1), 1);
    }
}
