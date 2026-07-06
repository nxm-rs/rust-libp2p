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
//! # Denial-of-service posture
//!
//! The ClientHello parse behind [`quinn::Incoming::alpn`] runs inside quinn after its retry and
//! address-validation handling of the Initial packet. On top of that, this crate only reads the
//! hint when more than one ALPN is registered; a single-protocol endpoint takes the direct
//! accept path with no peek-dependent branching.

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
    /// The first registered protocol is the default: connections with an absent or unknown
    /// offered ALPN are routed to it (its `ServerConfig` still decides whether they may
    /// complete the handshake). Registering a further ALPN promotes the endpoint to mixed mode,
    /// in which the offered ALPN is peeked to select the route.
    ///
    /// Errors if `alpn` is already registered.
    pub fn register(
        &self,
        alpn: Vec<u8>,
        server_config: Arc<quinn::ServerConfig>,
        sink: mpsc::Sender<quinn::Connecting>,
    ) -> Result<(), Error> {
        let mut table = lock(&self.routes);
        if table.routes.iter().any(|r| r.alpn == alpn) {
            return Err(Error::DuplicateAlpn(AlpnProtocol(alpn)));
        }
        table.routes.push(Route {
            alpn,
            server_config,
            sink,
        });
        self.sync_endpoint_config(&table);
        Ok(())
    }

    /// Removes a registered protocol. Connections already handed to its sink are unaffected.
    ///
    /// If the default (first-registered) protocol is removed, the next registered one becomes
    /// the default. Removing the last protocol stops the endpoint accepting connections.
    pub fn unregister(&self, alpn: &[u8]) {
        let mut table = lock(&self.routes);
        table.routes.retain(|r| r.alpn != alpn);
        self.sync_endpoint_config(&table);
    }

    /// Replaces the `ServerConfig` for a registered ALPN, e.g. on certificate rotation.
    /// Affects new inbound connections only.
    ///
    /// Errors if `alpn` is not registered.
    pub fn update_server_config(
        &self,
        alpn: &[u8],
        server_config: Arc<quinn::ServerConfig>,
    ) -> Result<(), Error> {
        let mut table = lock(&self.routes);
        match table.routes.iter_mut().find(|r| r.alpn == alpn) {
            Some(route) => {
                route.server_config = server_config;
                self.sync_endpoint_config(&table);
                Ok(())
            }
            None => Err(Error::UnknownAlpn(AlpnProtocol(alpn.to_vec()))),
        }
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
                .routes
                .first()
                .map(|r| r.server_config.as_ref().clone()),
        );
    }
}

impl Drop for SharedQuicEndpoint {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

struct RouteTable {
    /// Registration order is significant: the first route is the default.
    routes: Vec<Route>,
}

impl RouteTable {
    fn select(&self, offered: &[Vec<u8>]) -> usize {
        select_route(offered, self.routes.iter().map(|r| r.alpn.as_slice()))
    }
}

/// Index of the route serving the offered ALPN list: the route whose ALPN equals the first
/// offered protocol, else the default (first-registered) route.
fn select_route<'a>(offered: &[Vec<u8>], registered: impl Iterator<Item = &'a [u8]>) -> usize {
    match offered.first() {
        Some(first) => registered
            .enumerate()
            .find_map(|(i, alpn)| (alpn == first.as_slice()).then_some(i))
            // Absent or unknown ALPN: fall back to the default route. Its `ServerConfig`
            // still enforces its own ALPN allowlist, so this cannot mis-authenticate.
            .unwrap_or(0),
        None => 0,
    }
}

struct Route {
    alpn: Vec<u8>,
    server_config: Arc<quinn::ServerConfig>,
    sink: mpsc::Sender<quinn::Connecting>,
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

    if table.routes.is_empty() {
        tracing::debug!(remote=%incoming.remote_address(), "no registered ALPN, refusing");
        incoming.refuse();
        return;
    }

    // Only consult the peeked hint in mixed mode; a single-protocol endpoint accepts directly.
    let index = if table.routes.len() > 1 {
        table.select(incoming.alpn())
    } else {
        0
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

    fn select(offered: &[&[u8]]) -> usize {
        let offered = offered.iter().map(|a| a.to_vec()).collect::<Vec<_>>();
        select_route(&offered, REGISTERED.iter().copied())
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
}
