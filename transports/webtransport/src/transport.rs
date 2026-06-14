// Copyright 2024 Protocol Labs.
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

use std::{
    collections::HashSet,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use futures::{future::BoxFuture, prelude::*, ready, stream::SelectAll};
use if_watch::{IfEvent, tokio::IfWatcher};
use libp2p_core::{
    Endpoint as CoreEndpoint, Multiaddr,
    multiaddr::Protocol,
    transport::{DialOpts, ListenerId, PortUse, TransportError, TransportEvent},
    upgrade::OutboundConnectionUpgrade,
};
use libp2p_identity::{Keypair, PeerId};
use socket2::{Domain, Socket, Type};
use wtransport::{
    ClientConfig, ServerConfig,
    endpoint::{ConnectOptions, Endpoint, SessionRequest, endpoint_side::Server},
    error::ConnectionError,
    tls::Sha256Digest,
};

use crate::{
    Connecting, Error,
    certificate::{CertHash, MULTIHASH_SHA256_CODE},
    config::Config,
    connection::{Connection, WEBTRANSPORT_PATH},
};

pub struct Transport {
    config: Config,

    listeners: SelectAll<Listener>,
    /// Waker to poll the transport again when a new listener is added.
    waker: Option<Waker>,
}

impl Transport {
    pub fn new(config: Config) -> Self {
        Transport {
            config,
            listeners: SelectAll::new(),
            waker: None,
        }
    }
}

impl libp2p_core::Transport for Transport {
    type Output = (PeerId, Connection);
    type Error = Error;
    type ListenerUpgrade = Connecting;
    type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        let (socket_addr, _peer_id) = multiaddr_to_socketaddr(&addr)
            .ok_or_else(|| TransportError::MultiaddrNotSupported(addr.clone()))?;
        let socket = create_socket(socket_addr).map_err(Self::Error::from)?;

        let server_tls_config = self.config.server_tls_config();
        let quic_transport_config = self.config.get_quic_transport_config();

        let config = ServerConfig::builder()
            .with_bind_socket(socket.try_clone().unwrap())
            .with_custom_tls_and_transport(server_tls_config, quic_transport_config)
            .build();

        let endpoint =
            wtransport::Endpoint::server(config).map_err(|e| TransportError::Other(e.into()))?;
        let keypair = &self.config.keypair;
        let cert_hashes = self.config.cert_hashes();
        let handshake_timeout = self.config.handshake_timeout;

        tracing::debug!("Listening on {:?}, listenerId {}", &socket, &id);

        let listener = Listener::new(
            id,
            socket,
            endpoint,
            keypair,
            cert_hashes,
            handshake_timeout,
        )?;
        self.listeners.push(listener);

        if let Some(waker) = self.waker.take() {
            waker.wake();
        }

        Ok(())
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        if let Some(listener) = self.listeners.iter_mut().find(|l| l.listener_id == id) {
            // Close the listener, which will eventually finish its stream.
            // `SelectAll` removes streams once they are finished.
            listener.close(Ok(()));

            tracing::debug!("Listener {id} was removed");

            true
        } else {
            false
        }
    }

    /// Dials a WebTransport address.
    ///
    /// Two behaviours are non-obvious:
    ///
    /// * A genuine coordinated hole-punch — `DialOpts { role: Endpoint::Listener, port_use:
    ///   PortUse::New, .. }` — is rejected synchronously with [`Error::HolePunchingUnsupported`]:
    ///   `wtransport` only exposes `connect` on a *client* endpoint, which always binds a fresh
    ///   socket, so dialing from the listener's socket is impossible.
    /// * [`PortUse::Reuse`] (the default for ordinary dials, and what DCUtR's `override_role()`
    ///   emits as `(Listener, Reuse)`) cannot be honoured; it is downgraded best-effort to a fresh
    ///   ephemeral socket and logged at `trace`.
    fn dial(
        &mut self,
        addr: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        // Return `MultiaddrNotSupported` for non-WebTransport addresses so that transport
        // combinators (e.g. `OrTransport`) keep trying other transports for this address.
        let (socket_addr, cert_hashes, expected_peer_id) = multiaddr_to_dial_addr(&addr)
            .ok_or_else(|| TransportError::MultiaddrNotSupported(addr.clone()))?;

        // libp2p WebTransport servers use short-lived self-signed certificates. Without the
        // certificate hash(es) in the multiaddr the dialer cannot pin the server's certificate,
        // so dialing is impossible.
        if cert_hashes.is_empty() {
            return Err(TransportError::Other(Error::MissingCerthashes));
        }

        // Branch on the (role, port_use) tuple, matching libp2p-quic. Only a genuine coordinated
        // hole-punch — role == Listener AND port_use == New — needs to dial from the listener's
        // socket, which `wtransport` cannot do. `(Listener, Reuse)` is what DCUtR's
        // `override_role()` emits and what quic treats as a normal reuse dial; we serve it as an
        // ordinary fresh-socket dial.
        match (opts.role, opts.port_use) {
            (CoreEndpoint::Listener, PortUse::New) => {
                return Err(TransportError::Other(Error::HolePunchingUnsupported));
            }
            (_, PortUse::Reuse) => {
                // `PortUse::Reuse` (the default for ordinary dials) cannot be honoured:
                // `wtransport` binds a fresh socket per client endpoint and offers no way to share
                // the listener's socket without two quinn endpoints racing recv() on one fd.
                // Best-effort downgrade to a fresh ephemeral socket; logged at `trace` because it
                // is the expected default path, not an exceptional event.
                tracing::trace!(
                    %addr,
                    "WebTransport ignores PortUse::Reuse; dialing from a fresh ephemeral socket"
                );
            }
            _ => {}
        }

        let keypair = self.config.keypair.clone();
        let handshake_timeout = self.config.handshake_timeout;

        Ok(async move {
            let connect = connect(socket_addr, cert_hashes, expected_peer_id, keypair);
            futures::pin_mut!(connect);
            match future::select(connect, futures_timer::Delay::new(handshake_timeout)).await {
                future::Either::Left((res, _)) => res,
                future::Either::Right(((), _)) => Err(Error::HandshakeTimedOut),
            }
        }
        .boxed())
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        if let Poll::Ready(Some(ev)) = self.listeners.poll_next_unpin(cx) {
            return Poll::Ready(ev);
        }

        self.waker = Some(cx.waker().clone());

        Poll::Pending
    }
}

/// Listener for incoming connections.
struct Listener {
    /// Id of the listener.
    listener_id: ListenerId,
    /// Endpoint
    endpoint: Arc<Endpoint<Server>>,
    /// Watcher for network interface changes.
    /// None if we are only listening on a single interface.
    if_watcher: Option<IfWatcher>,
    /// A future to poll new incoming connections.
    accept: BoxFuture<'static, Result<SessionRequest, ConnectionError>>,
    /// Timeout for connection establishment on inbound connections.
    handshake_timeout: Duration,
    /// Whether the listener was closed and the stream should terminate.
    is_closed: bool,
    /// Pending event to reported.
    pending_event: Option<<Self as Stream>::Item>,
    /// The stream must be to awaken after it has been closed to deliver the last event.
    close_listener_waker: Option<Waker>,

    keypair: Keypair,

    cert_hashes: Vec<CertHash>,
}

impl Listener {
    fn new(
        listener_id: ListenerId,
        socket: UdpSocket,
        endpoint: Endpoint<Server>,
        keypair: &Keypair,
        cert_hashes: Vec<CertHash>,
        handshake_timeout: Duration,
    ) -> Result<Self, Error> {
        let endpoint = Arc::new(endpoint);
        let c_endpoint = Arc::clone(&endpoint);
        let accept = Self::accept(c_endpoint, listener_id).boxed();

        let if_watcher;
        let pending_event;
        let local_addr = socket.local_addr()?;
        if local_addr.ip().is_unspecified() {
            if_watcher = Some(IfWatcher::new()?);
            pending_event = None;
        } else {
            if_watcher = None;
            let ma = socketaddr_to_multiaddr_with_hashes(&local_addr, &cert_hashes);
            pending_event = Some(TransportEvent::NewAddress {
                listener_id,
                listen_addr: ma,
            })
        }

        Ok(Listener {
            listener_id,
            endpoint,
            if_watcher,
            accept,
            handshake_timeout,
            is_closed: false,
            pending_event,
            close_listener_waker: None,
            keypair: keypair.clone(),
            cert_hashes,
        })
    }

    async fn accept(
        endpoint: Arc<Endpoint<Server>>,
        id: ListenerId,
    ) -> Result<SessionRequest, ConnectionError> {
        let incoming_session = endpoint.accept().await;

        tracing::debug!(
            "Listener {id} got incoming session from {}",
            incoming_session.remote_address()
        );

        incoming_session.await
    }

    /// Report the listener as closed in a [`TransportEvent::ListenerClosed`] and
    /// terminate the stream.
    fn close(&mut self, reason: Result<(), Error>) {
        if self.is_closed {
            return;
        }
        self.endpoint.close(From::from(0u32), &[]);
        self.pending_event = Some(TransportEvent::ListenerClosed {
            listener_id: self.listener_id,
            reason,
        });
        self.is_closed = true;

        // Wake the stream to deliver the last event.
        if let Some(waker) = self.close_listener_waker.take() {
            waker.wake();
        }
    }

    fn socket_addr(&self) -> SocketAddr {
        self.endpoint
            .local_addr()
            .expect("Cannot fail because the socket is bound")
    }

    fn noise_config(&self) -> libp2p_noise::Config {
        let res = libp2p_noise::Config::new(&self.keypair).expect("Getting a noise config");
        let set = self.cert_hashes.iter().cloned().collect::<HashSet<_>>();

        res.with_webtransport_certhashes(set)
    }

    fn poll_if_addr(&mut self, cx: &mut Context<'_>) -> Poll<<Self as Stream>::Item> {
        let endpoint_addr = self.socket_addr();
        let Some(if_watcher) = self.if_watcher.as_mut() else {
            return Poll::Pending;
        };
        loop {
            match ready!(if_watcher.poll_if_event(cx)) {
                Ok(IfEvent::Up(inet)) => {
                    if let Some(listen_addr) =
                        ip_to_listen_addr(&endpoint_addr, inet.addr(), &self.cert_hashes)
                    {
                        tracing::debug!(
                            address=%listen_addr,
                            "New listen address"
                        );
                        return Poll::Ready(TransportEvent::NewAddress {
                            listener_id: self.listener_id,
                            listen_addr,
                        });
                    }
                }
                Ok(IfEvent::Down(inet)) => {
                    if let Some(listen_addr) =
                        ip_to_listen_addr(&endpoint_addr, inet.addr(), &self.cert_hashes)
                    {
                        tracing::debug!(
                            address=%listen_addr,
                            "Expired listen address"
                        );
                        return Poll::Ready(TransportEvent::AddressExpired {
                            listener_id: self.listener_id,
                            listen_addr,
                        });
                    }
                }
                Err(err) => {
                    return Poll::Ready(TransportEvent::ListenerError {
                        listener_id: self.listener_id,
                        error: err.into(),
                    });
                }
            }
        }
    }
}

impl Stream for Listener {
    type Item = TransportEvent<<Transport as libp2p_core::Transport>::ListenerUpgrade, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(event) = self.pending_event.take() {
                return Poll::Ready(Some(event));
            }
            if self.is_closed {
                return Poll::Ready(None);
            }
            if let Poll::Ready(event) = self.poll_if_addr(cx) {
                return Poll::Ready(Some(event));
            }

            match self.accept.poll_unpin(cx) {
                Poll::Ready(Ok(session_request)) => {
                    tracing::debug!(
                        "Listener {} got session request={:?}",
                        &self.listener_id,
                        session_request.path()
                    );

                    let endpoint = Arc::clone(&self.endpoint);
                    self.accept = Self::accept(endpoint, self.listener_id).boxed();
                    let local_addr =
                        socketaddr_to_multiaddr_with_hashes(&self.socket_addr(), &self.cert_hashes);

                    let remote_addr = session_request.remote_address();
                    let send_back_addr = socketaddr_to_multiaddr(&remote_addr);
                    let noise = self.noise_config();

                    let event = TransportEvent::Incoming {
                        upgrade: Connecting::new(session_request, noise, self.handshake_timeout),
                        local_addr,
                        send_back_addr,
                        listener_id: self.listener_id,
                    };
                    return Poll::Ready(Some(event));
                }
                Poll::Ready(Err(connection_error)) => {
                    tracing::error!("Got the error {}", connection_error);
                    self.close(Err(Error::Connection(connection_error)));

                    continue;
                }
                Poll::Pending => {
                    tracing::debug!("Listener {} pending", &self.listener_id);
                }
            };

            match &self.close_listener_waker {
                None => self.close_listener_waker = Some(cx.waker().clone()),
                Some(waker) => {
                    if !waker.will_wake(cx.waker()) {
                        self.close_listener_waker = Some(cx.waker().clone())
                    }
                }
            }

            return Poll::Pending;
        }
    }
}

impl fmt::Debug for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listener")
            .field("listener_id", &self.listener_id)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("is_closed", &self.is_closed)
            .field("pending_event", &self.pending_event)
            .finish()
    }
}

fn create_socket(socket_addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(socket_addr),
        Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if socket_addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }

    socket.bind(&socket_addr.into())?;

    Ok(socket.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SocketFamily {
    Ipv4,
    Ipv6,
}

impl SocketFamily {
    fn is_same(a: &IpAddr, b: &IpAddr) -> bool {
        matches!(
            (a, b),
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
        )
    }
}

impl From<IpAddr> for SocketFamily {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => SocketFamily::Ipv4,
            IpAddr::V6(_) => SocketFamily::Ipv6,
        }
    }
}

/// Turn an [`IpAddr`] reported by the interface watcher into a
/// listen-address for the endpoint.
///
/// For this, the `ip` is combined with the port that the endpoint
/// is actually bound.
///
/// Returns `None` if the `ip` is not the same socket family as the
/// address that the endpoint is bound to.
fn ip_to_listen_addr(
    endpoint_addr: &SocketAddr,
    ip: IpAddr,
    hashes: &[CertHash],
) -> Option<Multiaddr> {
    // True if either both addresses are Ipv4 or both Ipv6.
    if !SocketFamily::is_same(&endpoint_addr.ip(), &ip) {
        return None;
    }
    let socket_addr = SocketAddr::new(ip, endpoint_addr.port());
    Some(socketaddr_to_multiaddr_with_hashes(&socket_addr, hashes))
}

/// Turns an IP address and port into the corresponding WebTransport multiaddr.
fn socketaddr_to_multiaddr(socket_addr: &SocketAddr) -> Multiaddr {
    Multiaddr::empty()
        .with(socket_addr.ip().into())
        .with(Protocol::Udp(socket_addr.port()))
        .with(Protocol::QuicV1)
        .with(Protocol::WebTransport)
}

fn socketaddr_to_multiaddr_with_hashes(socket_addr: &SocketAddr, hashes: &[CertHash]) -> Multiaddr {
    let mut res = socketaddr_to_multiaddr(socket_addr);

    if !hashes.is_empty() {
        let mut vec = hashes.to_owned();
        res = res.with(Protocol::Certhash(
            vec.pop().expect("Gets the last element"),
        ));
        if !vec.is_empty() {
            res = res.with(Protocol::Certhash(
                vec.pop().expect("Gets the last element"),
            ));
        };
    }

    res
}

/// Tries to turn a Webtransport multiaddress into a UDP [`SocketAddr`]. Returns None if the format
/// of the multiaddr is wrong.
fn multiaddr_to_socketaddr(addr: &Multiaddr) -> Option<(SocketAddr, Option<PeerId>)> {
    let mut iter = addr.iter();
    let proto1 = iter.next()?;
    let proto2 = iter.next()?;
    let proto3 = iter.next()?;

    if !matches!(proto3, Protocol::QuicV1) {
        tracing::error!("Cannot listen on a non QUIC address {addr}");
        return None;
    }

    let mut peer_id = None;
    let mut is_webtransport = false;
    for proto in iter {
        match proto {
            Protocol::P2p(id) => {
                peer_id = Some(id);
            }
            Protocol::WebTransport if !is_webtransport => {
                is_webtransport = true;
            }
            Protocol::Certhash(_) => {
                tracing::error!(
                    "Cannot listen on a specific certhash for WebTransport address {addr}"
                );
                return None;
            }
            _ => return None,
        }
    }

    if !is_webtransport {
        tracing::error!("Listening address {addr} should be followed by `/webtransport`");
        return None;
    }

    match (proto1, proto2) {
        (Protocol::Ip4(ip), Protocol::Udp(port)) => {
            Some((SocketAddr::new(ip.into(), port), peer_id))
        }
        (Protocol::Ip6(ip), Protocol::Udp(port)) => {
            Some((SocketAddr::new(ip.into(), port), peer_id))
        }
        _ => None,
    }
}

/// Dials a libp2p WebTransport server.
///
/// Builds a wtransport client that pins the server's self-signed certificate by its SHA-256
/// hash(es), connects to the well-known libp2p WebTransport endpoint, and runs the libp2p Noise
/// handshake (as the initiator) over the first bidirectional stream to authenticate the remote
/// [`PeerId`].
async fn connect(
    socket_addr: SocketAddr,
    cert_hashes: Vec<CertHash>,
    expected_peer_id: Option<PeerId>,
    keypair: Keypair,
) -> Result<(PeerId, Connection), Error> {
    // Always bind a fresh ephemeral local UDP socket of the same address family as the remote;
    // `PortUse::Reuse` is unsupported by design (see `Transport::dial`), since `wtransport`'s
    // client endpoint cannot share the listener's socket.
    let bind_addr: SocketAddr = if socket_addr.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };

    // Pin the server's plain self-signed certificate by its SHA-256 hash(es), exactly like a
    // browser's `serverCertificateHashes`. The libp2p identity is authenticated separately over
    // Noise, so no certificate-embedded identity is required (this is what lets us interoperate
    // with go-libp2p and browser endpoints).
    let digests = cert_hashes
        .iter()
        .map(certhash_to_digest)
        .collect::<Result<Vec<_>, _>>()?;

    let client_config = ClientConfig::builder()
        .with_bind_address(bind_addr)
        .with_server_certificate_hashes(digests)
        .build();

    let endpoint = Endpoint::client(client_config)?;

    // Some libp2p WebTransport servers (notably go-libp2p, and browsers) speak the older
    // WebTransport-over-HTTP/3 draft-02 and require this header on the CONNECT request. wtransport
    // itself does not send it, so we add it explicitly; servers that don't need it ignore it.
    //
    // The field name MUST be lowercase: HTTP/3 (RFC 9114 §4.2) requires lowercase field names on
    // the wire, and go-libp2p (quic-go) rejects the CONNECT stream otherwise. (wtransport encodes
    // the name verbatim rather than lowercasing it.)
    let url = format!("https://{socket_addr}{WEBTRANSPORT_PATH}");
    let options = ConnectOptions::builder(&url)
        .add_header("sec-webtransport-http3-draft02", "1")
        .build();
    let connection = endpoint.connect(options).await?;

    // The first bidirectional stream carries the libp2p Noise handshake directly (no
    // multistream-select). The dialer is the Noise initiator.
    let (send, recv) = connection.open_bi().await?.await?;
    let stream = crate::Stream::new(send, recv);

    let noise = noise_config(&keypair, &cert_hashes)?;
    let (peer_id, _) = noise.upgrade_outbound(stream, "").await?;

    if let Some(expected) = expected_peer_id
        && expected != peer_id
    {
        return Err(Error::UnknownRemotePeerId);
    }

    tracing::debug!(
        "Dialed connection with sessionId={}",
        connection.session_id()
    );

    Ok((peer_id, Connection::new(connection)))
}

/// Build a Noise config carrying the expected WebTransport certificate hashes, so that the
/// initiator verifies (inside the authenticated channel) that the server reports a superset of
/// the hashes advertised in its multiaddr.
fn noise_config(
    keypair: &Keypair,
    cert_hashes: &[CertHash],
) -> Result<libp2p_noise::Config, Error> {
    let set = cert_hashes.iter().cloned().collect::<HashSet<_>>();
    Ok(libp2p_noise::Config::new(keypair)?.with_webtransport_certhashes(set))
}

/// Convert a libp2p certhash multihash (SHA-256) into a wtransport [`Sha256Digest`] for
/// certificate pinning.
fn certhash_to_digest(hash: &CertHash) -> Result<Sha256Digest, Error> {
    if hash.code() != MULTIHASH_SHA256_CODE {
        return Err(Error::UnsupportedCerthash);
    }
    let digest: [u8; 32] = hash
        .digest()
        .try_into()
        .map_err(|_| Error::UnsupportedCerthash)?;

    Ok(Sha256Digest::new(digest))
}

/// Tries to turn a WebTransport dial multiaddr into a UDP [`SocketAddr`], the advertised
/// certificate hashes, and an optional expected [`PeerId`]. Returns `None` if the multiaddr is not
/// a WebTransport address.
fn multiaddr_to_dial_addr(addr: &Multiaddr) -> Option<(SocketAddr, Vec<CertHash>, Option<PeerId>)> {
    let mut iter = addr.iter();
    let proto1 = iter.next()?;
    let proto2 = iter.next()?;
    let proto3 = iter.next()?;

    if !matches!(proto3, Protocol::QuicV1) {
        return None;
    }

    let mut peer_id = None;
    let mut is_webtransport = false;
    let mut cert_hashes = Vec::new();
    for proto in iter {
        match proto {
            Protocol::P2p(id) => peer_id = Some(id),
            Protocol::WebTransport if !is_webtransport => is_webtransport = true,
            Protocol::Certhash(hash) => cert_hashes.push(hash),
            _ => return None,
        }
    }

    if !is_webtransport {
        return None;
    }

    let socket_addr = match (proto1, proto2) {
        (Protocol::Ip4(ip), Protocol::Udp(port)) => SocketAddr::new(ip.into(), port),
        (Protocol::Ip6(ip), Protocol::Udp(port)) => SocketAddr::new(ip.into(), port),
        _ => return None,
    };

    Some((socket_addr, cert_hashes, peer_id))
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use futures::future::poll_fn;
    use libp2p_core::Transport as CoreTransport;
    use time::{OffsetDateTime, ext::NumericalDuration};

    use super::*;
    use crate::certificate::Certificate;

    fn generate_keypair_and_cert() -> (Keypair, Certificate) {
        let keypair = Keypair::generate_ed25519();
        let not_before = OffsetDateTime::now_utc().checked_sub(1.days()).unwrap();
        let cert = Certificate::generate(not_before).expect("Generate certificate");

        (keypair, cert)
    }

    /// Build a transport plus a dialable WebTransport multiaddr (with a real `/certhash`) that
    /// passes the `multiaddr_to_dial_addr` / `MissingCerthashes` guards, so `dial()`'s
    /// `(role, port_use)` branching can be exercised without any network I/O.
    fn transport_and_dial_addr() -> (Transport, Multiaddr) {
        let (keypair, cert) = generate_keypair_and_cert();
        let hashes = vec![cert.cert_hash()];
        let addr = socketaddr_to_multiaddr_with_hashes(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001),
            &hashes,
        );
        let config = Config::new(&keypair, cert);
        (Transport::new(config), addr)
    }

    fn dial_opts(role: CoreEndpoint, port_use: PortUse) -> DialOpts {
        DialOpts { role, port_use }
    }

    #[test]
    fn dial_holepunch_new_port_rejected() {
        let (mut transport, addr) = transport_and_dial_addr();
        let res = transport.dial(addr, dial_opts(CoreEndpoint::Listener, PortUse::New));
        assert!(matches!(
            res,
            Err(TransportError::Other(Error::HolePunchingUnsupported))
        ));
    }

    #[test]
    fn dial_listener_reuse_proceeds() {
        // Guards the F1 fix: `(Listener, Reuse)` (what DCUtR emits) must NOT be a hole-punch error.
        let (mut transport, addr) = transport_and_dial_addr();
        let res = transport.dial(addr, dial_opts(CoreEndpoint::Listener, PortUse::Reuse));
        assert!(res.is_ok());
    }

    #[test]
    fn dial_dialer_reuse_proceeds() {
        let (mut transport, addr) = transport_and_dial_addr();
        let res = transport.dial(addr, dial_opts(CoreEndpoint::Dialer, PortUse::Reuse));
        assert!(res.is_ok());
    }

    #[test]
    fn dial_dialer_new_proceeds() {
        let (mut transport, addr) = transport_and_dial_addr();
        let res = transport.dial(addr, dial_opts(CoreEndpoint::Dialer, PortUse::New));
        assert!(res.is_ok());
    }

    #[test]
    fn dial_missing_certhash_errors_first() {
        let (keypair, cert) = generate_keypair_and_cert();
        let mut transport = Transport::new(Config::new(&keypair, cert));
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/4001/quic-v1/webtransport"
            .parse()
            .unwrap();
        // Even a `(Listener, New)` dial must hit the certhash guard first.
        let res = transport.dial(addr, dial_opts(CoreEndpoint::Listener, PortUse::New));
        assert!(matches!(
            res,
            Err(TransportError::Other(Error::MissingCerthashes))
        ));
    }

    #[test]
    fn dial_non_webtransport_addr_unsupported() {
        let (keypair, cert) = generate_keypair_and_cert();
        let mut transport = Transport::new(Config::new(&keypair, cert));
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/4001/quic-v1".parse().unwrap();
        let res = transport.dial(addr, dial_opts(CoreEndpoint::Dialer, PortUse::Reuse));
        assert!(matches!(res, Err(TransportError::MultiaddrNotSupported(_))));
    }

    #[test]
    fn error_holepunch_display() {
        assert_eq!(
            Error::HolePunchingUnsupported.to_string(),
            "WebTransport does not support dialing as a listener (hole punching)"
        );
    }

    #[test]
    fn multiaddr_to_dial_addr_matrix() {
        // Happy path: socket addr + one certhash + peer id.
        let (_keypair, cert) = generate_keypair_and_cert();
        let hash = cert.cert_hash();
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let addr = socketaddr_to_multiaddr_with_hashes(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001),
            std::slice::from_ref(&hash),
        )
        .with(Protocol::P2p(peer));
        let (sa, hashes, pid) = multiaddr_to_dial_addr(&addr).expect("dialable");
        assert_eq!(sa, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001));
        assert_eq!(hashes, vec![hash]);
        assert_eq!(pid, Some(peer));

        // No certhash: still parses, with an empty hash set and no peer id.
        let no_hash: Multiaddr = "/ip4/127.0.0.1/udp/4001/quic-v1/webtransport"
            .parse()
            .unwrap();
        let (_, hashes, pid) = multiaddr_to_dial_addr(&no_hash).expect("dialable");
        assert!(hashes.is_empty());
        assert!(pid.is_none());

        // Not a WebTransport address.
        assert!(
            multiaddr_to_dial_addr(&"/ip4/127.0.0.1/udp/4001/quic-v1".parse().unwrap()).is_none()
        );
        // TCP base is rejected.
        assert!(multiaddr_to_dial_addr(&"/ip4/127.0.0.1/tcp/4001".parse().unwrap()).is_none());
        // Double `/webtransport` is rejected.
        assert!(
            multiaddr_to_dial_addr(
                &"/ip4/127.0.0.1/udp/4001/quic-v1/webtransport/webtransport"
                    .parse()
                    .unwrap()
            )
            .is_none()
        );
        // DNS base is rejected.
        assert!(
            multiaddr_to_dial_addr(
                &"/dns4/example.com/udp/4001/quic-v1/webtransport"
                    .parse()
                    .unwrap()
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn test_close_listener() {
        let (keypair, cert) = generate_keypair_and_cert();
        let config = Config::new(&keypair, cert);
        let mut transport = Transport::new(config);

        assert!(
            poll_fn(|cx| Pin::new(&mut transport).as_mut().poll(cx))
                .now_or_never()
                .is_none()
        );

        // Run test twice to check that there is no unexpected behaviour if `Transport.listener`
        // is temporarily empty.
        for _ in 0..2 {
            let id = ListenerId::next();
            transport
                .listen_on(
                    id,
                    "/ip4/0.0.0.0/udp/0/quic-v1/webtransport".parse().unwrap(),
                )
                .unwrap();

            match poll_fn(|cx| Pin::new(&mut transport).as_mut().poll(cx)).await {
                TransportEvent::NewAddress {
                    listener_id,
                    listen_addr,
                } => {
                    assert_eq!(listener_id, id);
                    assert!(
                        matches!(listen_addr.iter().next(), Some(Protocol::Ip4(a)) if !a.is_unspecified())
                    );
                    assert!(
                        matches!(listen_addr.iter().nth(1), Some(Protocol::Udp(port)) if port != 0)
                    );
                    assert!(matches!(listen_addr.iter().nth(2), Some(Protocol::QuicV1)));
                }
                e => panic!("Unexpected event: {e:?}"),
            }
            assert!(transport.remove_listener(id), "Expect listener to exist.");
            match poll_fn(|cx| Pin::new(&mut transport).as_mut().poll(cx)).await {
                TransportEvent::ListenerClosed {
                    listener_id,
                    reason: Ok(()),
                } => {
                    assert_eq!(listener_id, id);
                }
                e => panic!("Unexpected event: {e:?}"),
            }
            // Poll once again so that the listener has the chance to return `Poll::Ready(None)` and
            // be removed from the list of listeners.
            assert!(
                poll_fn(|cx| Pin::new(&mut transport).as_mut().poll(cx))
                    .now_or_never()
                    .is_none()
            );
            assert!(transport.listeners.is_empty());
        }
    }

    #[test]
    fn socket_to_multiaddr() {
        let (_keypair, cert) = generate_keypair_and_cert();
        let certs = vec![cert.cert_hash()];
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let res = socketaddr_to_multiaddr_with_hashes(&addr, &certs);

        assert!(multiaddr_to_socketaddr(&res.to_string().parse::<Multiaddr>().unwrap()).is_none());
    }

    #[test]
    fn multiaddr_to_udp_conversion() {
        assert!(
            multiaddr_to_socketaddr(&"/ip4/127.0.0.1/udp/1234".parse::<Multiaddr>().unwrap())
                .is_none()
        );

        assert!(
            multiaddr_to_socketaddr(
                &"/ip4/127.0.0.1/udp/1234/quic-v1"
                    .parse::<Multiaddr>()
                    .unwrap()
            )
            .is_none()
        );

        assert_eq!(
            multiaddr_to_socketaddr(
                &"/ip4/127.0.0.1/udp/12345/quic-v1/webtransport"
                    .parse::<Multiaddr>()
                    .unwrap()
            ),
            Some((
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
                None
            ))
        );
        assert_eq!(
            multiaddr_to_socketaddr(
                &"/ip4/255.255.255.255/udp/8080/quic-v1/webtransport"
                    .parse::<Multiaddr>()
                    .unwrap()
            ),
            Some((
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)), 8080),
                None
            ))
        );
        assert_eq!(
            multiaddr_to_socketaddr(
                &"/ip4/127.0.0.1/udp/55148/quic-v1/webtransport/p2p/12D3KooW9xk7Zp1gejwfwNpfm6L9zH5NL4Bx5rm94LRYJJHJuARZ"
                    .parse::<Multiaddr>()
                    .unwrap()
            ),
            Some((SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 55148),
                  Some("12D3KooW9xk7Zp1gejwfwNpfm6L9zH5NL4Bx5rm94LRYJJHJuARZ".parse().unwrap())))
        );
        assert_eq!(
            multiaddr_to_socketaddr(
                &"/ip6/::1/udp/12345/quic-v1/webtransport"
                    .parse::<Multiaddr>()
                    .unwrap()
            ),
            Some((
                SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 12345),
                None
            ))
        );
        assert_eq!(
            multiaddr_to_socketaddr(
                &"/ip6/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/udp/8080/quic-v1/webtransport"
                    .parse::<Multiaddr>()
                    .unwrap()
            ),
            Some((
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(
                        65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
                    )),
                    8080,
                ),
                None
            ))
        );
    }
}
