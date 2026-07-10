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
    collections::{HashSet, VecDeque},
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
use time::OffsetDateTime;
use wtransport::{
    ClientConfig, ServerConfig,
    endpoint::{ConnectOptions, Endpoint, SessionRequest, endpoint_side::Server},
    error::ConnectionError,
    tls::Sha256Digest,
};

use crate::{
    Connecting, Error,
    certificate::{
        CERT_VALID_PERIOD, CLOCK_SKEW_ALLOWANCE, CertHash, Certificate, MULTIHASH_SHA256_CODE,
    },
    config::{Config, QuicParams, alpn_protocols},
    connection::{Connection, WEBTRANSPORT_PATH},
};

/// How long before the active certificate's `not_after` the listener generates and rotates to a
/// successor. Chosen well above the clock-skew allowance so rotation always completes while the
/// outgoing certificate is still servable to in-flight dialers.
const ROTATE_BEFORE_EXPIRY: time::Duration = CLOCK_SKEW_ALLOWANCE;

/// Bounded backoff after a certificate-*generation* failure, so a persistent failure cannot busy-
/// loop the listener or emit `ListenerError` faster than this interval. Rotation never closes the
/// listener on a transient failure.
const GENERATION_FAILURE_BACKOFF: Duration = Duration::from_secs(30);

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

    /// Start listening on `addr`.
    ///
    /// `addr` must be of the form `/ip{4,6}/<ip>/udp/<port>/quic-v1/webtransport` and may
    /// optionally end with `/p2p/<peer-id>`. If a `/p2p/<peer-id>` is present it **must** equal the
    /// local peer id; a foreign peer id (or an address carrying more than one `/p2p/`) is rejected
    /// with [`TransportError::MultiaddrNotSupported`] so transport combinators keep trying. The
    /// advertised `/certhash` components are managed by the listener and must not be supplied here.
    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        let (socket_addr, peer_id) = multiaddr_to_socketaddr(&addr)
            .ok_or_else(|| TransportError::MultiaddrNotSupported(addr.clone()))?;

        // A listen address may optionally carry our own `/p2p/<peer-id>` (e.g. when an advertised
        // address is round-tripped back into `listen_on`). Accept an absent or matching peer id;
        // reject a genuinely foreign one as unsupported (combinator-friendly) rather than binding
        // it under the wrong identity. Note this is a *new* policy: neither QUIC nor TCP
        // validate the listen-side `/p2p/`.
        if let Some(peer_id) = peer_id {
            let local_peer_id = self.config.keypair.public().to_peer_id();
            if peer_id != local_peer_id {
                return Err(TransportError::MultiaddrNotSupported(addr));
            }
        }

        let socket = create_socket(socket_addr).map_err(Self::Error::from)?;

        let server_tls_config = self.config.server_tls_config();
        let quic_transport_config = self.config.get_quic_transport_config();

        // Hand the single bound socket to wtransport; do not clone it. The bound address is read
        // back from the endpoint below.
        let config = ServerConfig::builder()
            .with_bind_socket(socket)
            .with_custom_tls_and_transport(server_tls_config, quic_transport_config)
            .build();

        let endpoint =
            wtransport::Endpoint::server(config).map_err(|e| TransportError::Other(e.into()))?;
        let local_addr = endpoint
            .local_addr()
            .map_err(|e| TransportError::Other(Error::from(e)))?;
        let keypair = &self.config.keypair;
        // The listener owns its own copy of the certificate set and QUIC config so it can rebuild
        // the endpoint TLS config during rotation without holding the (non-`Clone`) `Config`.
        let certs = self.config.certs().to_vec();
        let quic_params = self.config.quic_params();
        let handshake_timeout = self.config.handshake_timeout;

        tracing::debug!("Listening on {local_addr}, listenerId {id}");

        let listener = Listener::new(
            id,
            local_addr,
            endpoint,
            keypair,
            certs,
            quic_params,
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
    /// The bound local address, cached from [`Endpoint::local_addr`] at construction. Used to make
    /// [`Self::socket_addr`] infallible and to supply the bind address to the rebuilt
    /// [`ServerConfig`] on rotation (where [`Endpoint::reload_config`] with `rebind = false`
    /// ignores it, so no socket is rebound and live connections are preserved).
    local_addr: SocketAddr,
    /// Watcher for network interface changes.
    /// None if we are only listening on a single interface.
    if_watcher: Option<IfWatcher>,
    /// A future to poll new incoming connections.
    accept: BoxFuture<'static, Result<SessionRequest, ConnectionError>>,
    /// Timeout for connection establishment on inbound connections.
    handshake_timeout: Duration,
    /// Whether the listener was closed and the stream should terminate.
    is_closed: bool,
    /// Pending events to report, drained front-first. Rotation enqueues an `AddressExpired`
    /// followed by a `NewAddress`; `close()` enqueues the final `ListenerClosed` last.
    pending_events: VecDeque<<Self as Stream>::Item>,
    /// The stream must be to awaken after it has been closed to deliver the last event.
    close_listener_waker: Option<Waker>,

    keypair: Keypair,

    /// The live certificate set (current [+ next]), sorted by `not_before` ascending; `certs[0]`
    /// is the active/served certificate. Expired certificates are removed promptly (their key
    /// material is zeroized on drop); the most recently expired hash is retained only in
    /// `last_hash` for the Noise set.
    certs: Vec<Certificate>,
    /// The most recently expired certificate hash, advertised only over Noise (per the spec
    /// SHOULD) and never in the multiaddr.
    last_hash: Option<CertHash>,
    /// Cached advertised hash set, ordered `[last?, current, next]`. The multiaddr uses only the
    /// last two entries (current + next); the Noise set uses all of them. Recomputed on rotation.
    cert_hashes: Vec<CertHash>,
    /// QUIC transport parameters, retained to rebuild the full `ServerConfig` on rotation.
    quic_params: QuicParams,
    /// Fires when the active certificate should be rotated. Actively polled every `poll_next` pass
    /// so an idle listener still wakes to rotate.
    rotation_timer: futures_timer::Delay,
    /// Clock used by rotation. Production reads [`OffsetDateTime::now_utc`]; tests inject a clock
    /// so rotation can be exercised in bounded (sub-second) time.
    now_fn: Box<dyn Fn() -> OffsetDateTime + Send>,
}

impl Listener {
    /// Build a listener around an already-bound endpoint.
    ///
    /// Takes `local_addr` (the endpoint's bound address, read by the caller from
    /// [`Endpoint::local_addr`]) rather than the [`UdpSocket`]: the socket is owned by the endpoint
    /// and the listener never needs it directly. Caching the address here keeps
    /// [`Self::socket_addr`] infallible and lets rotation rebuild the [`ServerConfig`] without
    /// touching the socket.
    #[allow(clippy::too_many_arguments)]
    fn new(
        listener_id: ListenerId,
        local_addr: SocketAddr,
        endpoint: Endpoint<Server>,
        keypair: &Keypair,
        certs: Vec<Certificate>,
        quic_params: QuicParams,
        handshake_timeout: Duration,
    ) -> Result<Self, Error> {
        let endpoint = Arc::new(endpoint);
        let c_endpoint = Arc::clone(&endpoint);
        let accept = Self::accept(c_endpoint, listener_id).boxed();

        // Initial advertised set: no expired generation yet, so just the live certs.
        let cert_hashes: Vec<CertHash> = certs.iter().map(|c| c.cert_hash()).collect();

        let mut pending_events = VecDeque::new();
        let if_watcher;
        if local_addr.ip().is_unspecified() {
            if_watcher = Some(IfWatcher::new()?);
        } else {
            if_watcher = None;
            let ma = socketaddr_to_multiaddr_with_hashes(&local_addr, &cert_hashes);
            pending_events.push_back(TransportEvent::NewAddress {
                listener_id,
                listen_addr: ma,
            });
        }

        let rotation_timer =
            futures_timer::Delay::new(rotation_delay(&certs, OffsetDateTime::now_utc()));

        Ok(Listener {
            listener_id,
            endpoint,
            local_addr,
            if_watcher,
            accept,
            handshake_timeout,
            is_closed: false,
            pending_events,
            close_listener_waker: None,
            keypair: keypair.clone(),
            certs,
            last_hash: None,
            cert_hashes,
            quic_params,
            rotation_timer,
            now_fn: Box::new(OffsetDateTime::now_utc),
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
        // Stop rotation: do not enqueue further address events, and ensure `ListenerClosed` is the
        // last event delivered. Any address events already queued ahead of it still drain first.
        self.is_closed = true;
        self.pending_events
            .push_back(TransportEvent::ListenerClosed {
                listener_id: self.listener_id,
                reason,
            });

        // Wake the stream to deliver the last event.
        if let Some(waker) = self.close_listener_waker.take() {
            waker.wake();
        }
    }

    /// The bound local address. Infallible: cached from [`Endpoint::local_addr`] at construction,
    /// so this is reachable on every inbound session and interface event without a per-connection
    /// `.expect()`.
    fn socket_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn noise_config(&self) -> libp2p_noise::Config {
        let res = libp2p_noise::Config::new(&self.keypair).expect("Getting a noise config");
        let set = self.cert_hashes.iter().cloned().collect::<HashSet<_>>();

        res.with_webtransport_certhashes(set)
    }

    #[cfg(test)]
    fn active_cert_hash(&self) -> CertHash {
        self.certs[0].cert_hash()
    }

    /// The set of hashes advertised in the multiaddr (the last two of `cert_hashes`).
    #[cfg(test)]
    fn multiaddr_hash_set(&self) -> HashSet<CertHash> {
        self.cert_hashes.iter().rev().take(2).copied().collect()
    }

    /// The set of hashes advertised over Noise (all of `cert_hashes`).
    #[cfg(test)]
    fn noise_hash_set(&self) -> HashSet<CertHash> {
        self.cert_hashes.iter().copied().collect()
    }

    /// The multiaddrs for the current bind, one per applicable interface.
    ///
    /// For a specified bind that is just the single bound address; for an unspecified bind it is
    /// one address per matching-family interface known to the `IfWatcher`. Uses the current
    /// advertised `cert_hashes` (so the multiaddr carries the live current+next certificate
    /// hashes).
    fn listen_addresses(&self) -> Vec<Multiaddr> {
        let endpoint_addr = self.socket_addr();
        match &self.if_watcher {
            None => vec![socketaddr_to_multiaddr_with_hashes(
                &endpoint_addr,
                &self.cert_hashes,
            )],
            Some(if_watcher) => if_watcher
                .iter()
                .filter_map(|inet| {
                    ip_to_listen_addr(&endpoint_addr, inet.addr(), &self.cert_hashes)
                })
                .collect(),
        }
    }

    /// Drive certificate rotation. Polls the rotation timer (registering its waker so an idle
    /// listener still wakes), and when it fires either rotates to a fresh certificate set or, on a
    /// generation failure, emits a `ListenerError` and re-arms with a bounded backoff. Never closes
    /// the listener and never empties / serves an expired certificate.
    fn poll_rotation(&mut self, cx: &mut Context<'_>) {
        // A closed listener does not rotate.
        if self.is_closed {
            return;
        }

        // Register the timer waker every pass; only act when it actually fires.
        if Pin::new(&mut self.rotation_timer).poll(cx).is_pending() {
            return;
        }

        let now = (self.now_fn)();
        match self.rotate(now) {
            Ok(()) => {
                // Re-arm to the next deadline derived solely from the local clock + cert validity.
                self.rotation_timer = futures_timer::Delay::new(rotation_delay(&self.certs, now));
            }
            Err(error) => {
                tracing::warn!(
                    listener = %self.listener_id,
                    %error,
                    "WebTransport certificate generation failed; retaining current set, backing off"
                );
                // Retain the current set and re-arm with a bounded backoff (no busy loop, listener
                // stays open).
                self.pending_events
                    .push_back(TransportEvent::ListenerError {
                        listener_id: self.listener_id,
                        error,
                    });
                self.rotation_timer = futures_timer::Delay::new(GENERATION_FAILURE_BACKOFF);
            }
        }
    }

    /// Perform one rotation tick at `now`.
    ///
    /// Partitions expired certificates out of the live set (keeping the most recent one's hash in
    /// the Noise-only `last_hash`), generates a successor when the set lacks a current+next pair or
    /// the active certificate nears expiry, rebuilds and hot-swaps the endpoint TLS config, then
    /// recomputes `cert_hashes` and enqueues `AddressExpired`/`NewAddress` if the advertised set
    /// changed. On certificate-generation failure the set is left untouched and the error is
    /// returned. Invariants: `certs` is never emptied and `certs[0]` is always currently valid.
    fn rotate(&mut self, now: OffsetDateTime) -> Result<(), Error> {
        let old_hashes = self.cert_hashes.clone();
        let old_addrs = self.listen_addresses();

        // 1. Partition expired certificates out of the live set, but never drop the last one. Keep
        //    the most-recently-expired hash for the Noise set.
        if self.certs.len() > 1 {
            // Certs are sorted ascending by not_before; expiry order matches.
            while self.certs.len() > 1 && self.certs[0].not_after() <= now {
                let expired = self.certs.remove(0);
                self.last_hash = Some(expired.cert_hash());
                // `expired` (and its zeroizing key) is dropped here.
            }
        }

        // 2. Ensure we have a successor: generate one when there is no `next` cert, or the active
        //    cert is within the rotate threshold of expiry. Generation is the only fallible path.
        let need_next = self.certs.len() < 2;
        let active_near_expiry = self.certs[0].not_after() - ROTATE_BEFORE_EXPIRY <= now;
        if need_next || active_near_expiry {
            // Anchor the new cert sequentially after the latest existing one (with skew overlap),
            // but never before `now - CLOCK_SKEW_ALLOWANCE` (so a far-forward clock jump still
            // produces a currently-valid certificate rather than an already-expired one).
            let latest_not_after = self
                .certs
                .iter()
                .map(|c| c.not_after())
                .max()
                .expect("certs is non-empty");
            let anchored = latest_not_after - 2i32 * CLOCK_SKEW_ALLOWANCE;
            let floor = now - CLOCK_SKEW_ALLOWANCE;
            let next_not_before = anchored.max(floor);
            let next = Certificate::generate_with_validity(next_not_before, CERT_VALID_PERIOD)
                .map_err(|e| {
                    Error::Io(io::Error::other(format!("certificate generation: {e:?}")))
                })?;
            self.certs.push(next);
            self.certs.sort_by_key(|c| c.not_before());
        }

        // 3. If, after a forward clock jump, certs[0] is itself expired, drop it now that a fresh
        //    successor exists. Never leave the set empty.
        while self.certs.len() > 1 && self.certs[0].not_after() <= now {
            let expired = self.certs.remove(0);
            self.last_hash = Some(expired.cert_hash());
        }

        // 4. Recompute the advertised hash set ordered `[last?, current, next]`.
        let mut new_hashes = Vec::with_capacity(self.certs.len() + 1);
        if let Some(last) = self.last_hash {
            // Only keep the expired hash in the Noise set while it is genuinely "recent"; once it
            // is no longer among the live certs it is harmless, but drop it if it duplicates a live
            // hash (it never should).
            if !self.certs.iter().any(|c| c.cert_hash() == last) {
                new_hashes.push(last);
            } else {
                self.last_hash = None;
            }
        }
        new_hashes.extend(self.certs.iter().map(|c| c.cert_hash()));

        // Nothing changed (e.g. timer fired early): no swap, no events.
        if new_hashes == old_hashes {
            return Ok(());
        }

        // 5. Atomic swap, in order: rebuild full ServerConfig -> reload_config(.., false) -> update
        //    cert_hashes -> emit AddressExpired then NewAddress. Update `cert_hashes` together with
        //    the reload so no inbound handshake completes for a cert whose hash is absent from the
        //    Noise set. With rebind=false the reload only swaps the TLS/QUIC config and leaves the
        //    socket and live connections intact.
        let tls = libp2p_tls::make_webtransport_server_config(
            self.certs[0].certificate_der(),
            &self.certs[0].private_key_der(),
            alpn_protocols(),
        );
        // `reload_config(.., false)` ignores the bind address (it does not rebind the socket), so
        // we pass the cached `local_addr` purely to satisfy the builder; no socket is
        // created or cloned and live connections are preserved.
        let server_config = ServerConfig::builder()
            .with_bind_address(self.local_addr)
            .with_custom_tls_and_transport(tls, self.quic_params.build())
            .build();

        self.endpoint.reload_config(server_config, false)?;
        self.cert_hashes = new_hashes;

        // 6. Re-advertise: AddressExpired(old) then NewAddress(new), per interface.
        for addr in old_addrs {
            self.pending_events
                .push_back(TransportEvent::AddressExpired {
                    listener_id: self.listener_id,
                    listen_addr: addr,
                });
        }
        for addr in self.listen_addresses() {
            self.pending_events.push_back(TransportEvent::NewAddress {
                listener_id: self.listener_id,
                listen_addr: addr,
            });
        }

        Ok(())
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
            // Drive certificate rotation first so its waker is registered and any address events it
            // enqueues are picked up by the drain below.
            self.poll_rotation(cx);

            if let Some(event) = self.pending_events.pop_front() {
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
            .field("pending_events", &self.pending_events)
            .field("cert_hashes", &self.cert_hashes)
            .finish()
    }
}

/// Compute how long to wait before the next rotation tick, given the live certificate set and the
/// current time. The deadline is `active.not_after - ROTATE_BEFORE_EXPIRY`, clamped to zero (so an
/// already-due rotation fires immediately on the next poll). Derived solely from the local clock
/// and certificate validity — never from peer input.
fn rotation_delay(certs: &[Certificate], now: OffsetDateTime) -> Duration {
    let active = &certs[0];
    let deadline = active.not_after() - ROTATE_BEFORE_EXPIRY;
    let remaining = deadline - now;
    if remaining.is_positive() {
        remaining.try_into().unwrap_or(Duration::ZERO)
    } else {
        Duration::ZERO
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

/// Build a WebTransport listen multiaddr carrying up to the **last two** certificate hashes of
/// `hashes`.
///
/// This implements the multiaddr side of the Noise(3)/multiaddr(2) split: `cert_hashes` is ordered
/// `[last?, current, next]`, so taking the last two emits exactly the live current+next hashes and
/// deliberately omits any recently-expired (`last`) hash, which lives only in the Noise set. The
/// order of the two emitted `/certhash` components is not load-bearing — dialers pin both and the
/// Noise verification is an order-insensitive subset check.
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
                // Reject more than one `/p2p/`: with multiple components the "last wins" behaviour
                // would let an appended second `/p2p/` flip the identity check the caller performs.
                if peer_id.is_some() {
                    tracing::error!("WebTransport listen address {addr} has multiple /p2p/ ids");
                    return None;
                }
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
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::{
            Arc as StdArc,
            atomic::{AtomicI64, Ordering},
        },
    };

    use futures::future::poll_fn;
    use libp2p_core::Transport as CoreTransport;
    use time::{Duration as TimeDuration, OffsetDateTime, ext::NumericalDuration};

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

    /// A per-test clock the rotation engine reads via the `now_fn` seam. Each listener gets its own
    /// handle, so concurrently-running tests never contend on a shared clock.
    #[derive(Clone)]
    struct TestClock(StdArc<AtomicI64>);

    impl TestClock {
        fn new(t: OffsetDateTime) -> Self {
            Self(StdArc::new(AtomicI64::new(t.unix_timestamp_nanos() as i64)))
        }
        fn set(&self, t: OffsetDateTime) {
            self.0
                .store(t.unix_timestamp_nanos() as i64, Ordering::SeqCst);
        }
        fn now_fn(&self) -> Box<dyn Fn() -> OffsetDateTime + Send> {
            let inner = self.0.clone();
            Box::new(move || {
                OffsetDateTime::from_unix_timestamp_nanos(inner.load(Ordering::SeqCst) as i128)
                    .unwrap()
            })
        }
    }

    /// Build a `Listener` bound to an ephemeral loopback port with the given certificate set and a
    /// fresh injected clock set to `now`. Returns the listener and its clock handle.
    fn build_listener_with_clock(
        certs: Vec<Certificate>,
        now: OffsetDateTime,
    ) -> (Listener, TestClock) {
        let clock = TestClock::new(now);
        let keypair = Keypair::generate_ed25519();
        let socket_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = create_socket(socket_addr).unwrap();

        let tls = libp2p_tls::make_webtransport_server_config(
            certs[0].certificate_der(),
            &certs[0].private_key_der(),
            alpn_protocols(),
        );
        let quic_params = Config::new(&keypair, certs[0].clone()).quic_params();
        let server_config = ServerConfig::builder()
            .with_bind_socket(socket)
            .with_custom_tls_and_transport(tls, quic_params.build())
            .build();
        let endpoint = wtransport::Endpoint::server(server_config).unwrap();
        let local_addr = endpoint.local_addr().unwrap();

        let mut listener = Listener::new(
            ListenerId::next(),
            local_addr,
            endpoint,
            &keypair,
            certs,
            quic_params,
            Duration::from_secs(5),
        )
        .unwrap();
        listener.now_fn = clock.now_fn();
        // Drain the initial NewAddress so tests observe only rotation-induced events.
        let _ = listener.pending_events.pop_front();
        (listener, clock)
    }

    /// Convenience for tests that drive `rotate(now)` directly and do not advance the clock through
    /// `poll_next` (so the clock handle is unused).
    fn build_listener(certs: Vec<Certificate>, now: OffsetDateTime) -> Listener {
        build_listener_with_clock(certs, now).0
    }

    // A short served validity for tests. Must exceed `2 * CLOCK_SKEW_ALLOWANCE` so the
    // sequential-windows-with-skew model is well-formed, and exceed `ROTATE_BEFORE_EXPIRY` so the
    // initial active cert is not already "due".
    const TEST_VALIDITY: TimeDuration = TimeDuration::hours(4);

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

    // B2: listening on a concrete loopback address yields a NewAddress with that IP and a nonzero
    // (kernel-assigned) port, derived from endpoint.local_addr() — no try_clone, no panic path.
    #[tokio::test]
    async fn listen_on_concrete_addr() {
        let (keypair, cert) = generate_keypair_and_cert();
        let mut transport = Transport::new(Config::new(&keypair, cert));
        transport
            .listen_on(
                ListenerId::next(),
                "/ip4/127.0.0.1/udp/0/quic-v1/webtransport".parse().unwrap(),
            )
            .unwrap();
        match poll_fn(|cx| Pin::new(&mut transport).as_mut().poll(cx)).await {
            TransportEvent::NewAddress { listen_addr, .. } => {
                assert!(matches!(
                    listen_addr.iter().next(),
                    Some(Protocol::Ip4(a)) if a == Ipv4Addr::LOCALHOST
                ));
                assert!(matches!(
                    listen_addr.iter().nth(1),
                    Some(Protocol::Udp(port)) if port != 0
                ));
            }
            e => panic!("unexpected event: {e:?}"),
        }
    }

    // B2: listening on the IPv6 unspecified address binds without panicking (uses the IfWatcher
    // path). We only assert the listen call succeeds.
    #[tokio::test]
    async fn listen_on_ipv6_unspecified() {
        let (keypair, cert) = generate_keypair_and_cert();
        let mut transport = Transport::new(Config::new(&keypair, cert));
        transport
            .listen_on(
                ListenerId::next(),
                "/ip6/::/udp/0/quic-v1/webtransport".parse().unwrap(),
            )
            .expect("listening on the ipv6 unspecified address succeeds");
    }

    // B10: a listen address without `/p2p/` is accepted (the common case).
    #[tokio::test]
    async fn listen_on_without_p2p_ok() {
        let (keypair, cert) = generate_keypair_and_cert();
        let mut transport = Transport::new(Config::new(&keypair, cert));
        transport
            .listen_on(
                ListenerId::next(),
                "/ip4/127.0.0.1/udp/0/quic-v1/webtransport".parse().unwrap(),
            )
            .expect("address without /p2p/ is accepted");
    }

    // B10: a listen address carrying the *local* peer id is accepted.
    #[tokio::test]
    async fn listen_on_with_matching_p2p_ok() {
        let (keypair, cert) = generate_keypair_and_cert();
        let local_peer_id = keypair.public().to_peer_id();
        let mut transport = Transport::new(Config::new(&keypair, cert));
        let addr: Multiaddr =
            format!("/ip4/127.0.0.1/udp/0/quic-v1/webtransport/p2p/{local_peer_id}")
                .parse()
                .unwrap();
        transport
            .listen_on(ListenerId::next(), addr)
            .expect("address with the local /p2p/ is accepted");
    }

    // B10/F2: a listen address carrying a *foreign* peer id is rejected as MultiaddrNotSupported
    // (combinator-friendly), not bound under the wrong identity.
    #[tokio::test]
    async fn listen_on_with_foreign_p2p_rejected() {
        let (keypair, cert) = generate_keypair_and_cert();
        let mut transport = Transport::new(Config::new(&keypair, cert));
        let foreign = Keypair::generate_ed25519().public().to_peer_id();
        let addr: Multiaddr = format!("/ip4/127.0.0.1/udp/0/quic-v1/webtransport/p2p/{foreign}")
            .parse()
            .unwrap();
        let res = transport.listen_on(ListenerId::next(), addr.clone());
        assert!(
            matches!(res, Err(TransportError::MultiaddrNotSupported(a)) if a == addr),
            "foreign /p2p/ must be MultiaddrNotSupported"
        );
    }

    // B10/F3: a listen address with more than one `/p2p/` is rejected outright (no last-wins flip).
    #[tokio::test]
    async fn listen_on_with_two_p2p_rejected() {
        let (keypair, cert) = generate_keypair_and_cert();
        let local_peer_id = keypair.public().to_peer_id();
        let other = Keypair::generate_ed25519().public().to_peer_id();
        let mut transport = Transport::new(Config::new(&keypair, cert));
        // Even though the *last* /p2p/ matches the local id, the doubled /p2p/ must be rejected.
        let addr: Multiaddr =
            format!("/ip4/127.0.0.1/udp/0/quic-v1/webtransport/p2p/{other}/p2p/{local_peer_id}")
                .parse()
                .unwrap();
        let res = transport.listen_on(ListenerId::next(), addr.clone());
        assert!(
            matches!(res, Err(TransportError::MultiaddrNotSupported(a)) if a == addr),
            "doubled /p2p/ must be MultiaddrNotSupported"
        );
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

    // ---- Certificate rotation engine (R-series) ----

    /// Build an initial current+next set with short windows anchored at `now`, mirroring
    /// `Config::generate` but with `TEST_VALIDITY` so the active cert is genuinely near expiry.
    fn short_current_next(now: OffsetDateTime) -> Vec<Certificate> {
        let current_nb = now - CLOCK_SKEW_ALLOWANCE;
        let current = Certificate::generate_with_validity(current_nb, TEST_VALIDITY).unwrap();
        let next_nb = current.not_after() - 2i32 * CLOCK_SKEW_ALLOWANCE;
        let next = Certificate::generate_with_validity(next_nb, TEST_VALIDITY).unwrap();
        let mut v = vec![current, next];
        v.sort_by_key(|c| c.not_before());
        v
    }

    fn multiaddr_hashes(ma: &Multiaddr) -> Vec<CertHash> {
        ma.iter()
            .filter_map(|p| match p {
                Protocol::Certhash(h) => Some(h),
                _ => None,
            })
            .collect()
    }

    // R1: the initial NewAddress carries exactly two certhashes for a generated set.
    #[tokio::test]
    async fn initial_address_has_two_certhashes() {
        let now = OffsetDateTime::now_utc();
        let certs = short_current_next(now);
        let keypair = Keypair::generate_ed25519();
        let mut transport = Transport::new(Config::new_with_certs(&keypair, certs).unwrap());
        transport
            .listen_on(
                ListenerId::next(),
                "/ip4/127.0.0.1/udp/0/quic-v1/webtransport".parse().unwrap(),
            )
            .unwrap();
        match poll_fn(|cx| Pin::new(&mut transport).as_mut().poll(cx)).await {
            TransportEvent::NewAddress { listen_addr, .. } => {
                assert_eq!(multiaddr_hashes(&listen_addr).len(), 2);
            }
            e => panic!("unexpected event: {e:?}"),
        }
    }

    // R2/R3/R7: a rotation past the active cert's window promotes `next`, mints a fresh successor,
    // keeps the just-expired hash only in the Noise set, and serves the new active cert.
    #[tokio::test]
    async fn rotate_promotes_next_and_mints_successor() {
        let now = OffsetDateTime::now_utc();
        let certs = short_current_next(now);
        let old_current_hash = certs[0].cert_hash();
        let old_next_hash = certs[1].cert_hash();
        let mut listener = build_listener(certs, now);

        // Advance past the original current cert's expiry (still within next's window).
        let later = now + TEST_VALIDITY + TimeDuration::seconds(1);
        listener.rotate(later).expect("rotation succeeds");

        // Active is now the old `next`; multiaddr advertises current+next (2 hashes), neither is
        // the expired old current.
        assert_eq!(listener.active_cert_hash(), old_next_hash);
        let live: Vec<_> = listener.certs.iter().map(|c| c.cert_hash()).collect();
        assert!(live.contains(&old_next_hash));
        assert!(!live.contains(&old_current_hash));
        // A fresh successor appeared.
        assert_eq!(listener.certs.len(), 2);

        // Noise set ⊇ multiaddr set, and the recently-expired hash lives only in the Noise set.
        let multiaddr_set = listener.multiaddr_hash_set();
        let noise_set = listener.noise_hash_set();
        assert!(multiaddr_set.is_subset(&noise_set));
        assert!(noise_set.contains(&old_current_hash));
        assert!(!multiaddr_set.contains(&old_current_hash));
        assert_eq!(multiaddr_set.len(), 2);
        assert!(noise_set.len() >= 3);
    }

    // R4: post-rotation Noise set is exactly last+current+next and is a superset of the 2-hash
    // multiaddr set (membership, not positional order).
    #[tokio::test]
    async fn noise_set_superset_of_multiaddr_set() {
        let now = OffsetDateTime::now_utc();
        let certs = short_current_next(now);
        let mut listener = build_listener(certs, now);
        listener
            .rotate(now + TEST_VALIDITY + TimeDuration::seconds(1))
            .unwrap();

        let multiaddr_set = listener.multiaddr_hash_set();
        let noise_set = listener.noise_hash_set();
        assert_eq!(multiaddr_set.len(), 2);
        assert_eq!(noise_set.len(), 3);
        assert!(multiaddr_set.is_subset(&noise_set));
    }

    // R6: no rotation events / no swap before the active cert nears expiry.
    #[tokio::test]
    async fn no_rotation_when_not_due() {
        let now = OffsetDateTime::now_utc();
        // Full-length current+next set, so the active cert is far from its rotate threshold.
        let keypair = Keypair::generate_ed25519();
        let config = Config::generate(&keypair, now).unwrap();
        let certs = config.certs().to_vec();
        let mut listener = build_listener(certs, now);
        let before = listener.cert_hashes.clone();

        // The timer is armed well in the future.
        let delay = rotation_delay(&listener.certs, now);
        assert!(
            delay > Duration::from_secs(60 * 60 * 24),
            "rotation not imminent"
        );

        // Calling rotate at `now` must be a no-op: nothing expired, active not near expiry.
        listener.rotate(now).unwrap();
        assert_eq!(listener.cert_hashes, before, "no swap, no event");
        assert!(listener.pending_events.is_empty());
    }

    // R5/R13: rotating when *all* certs are expired regenerates rather than emptying, and never
    // panics on `certs[0]`. The active cert post-rotation is currently valid.
    #[tokio::test]
    async fn rotate_all_expired_regenerates_never_empty() {
        let now = OffsetDateTime::now_utc();
        let certs = short_current_next(now);
        let mut listener = build_listener(certs, now);

        // Jump far past every window.
        let far = now + TimeDuration::days(60);
        listener.rotate(far).expect("regeneration succeeds");

        assert!(!listener.certs.is_empty(), "set must never be empty");
        let active = &listener.certs[0];
        assert!(
            active.not_before() <= far && far < active.not_after(),
            "active cert must be currently valid after a far-forward jump"
        );
    }

    // R2 (event ordering via the stream): when rotation fires it emits AddressExpired then
    // NewAddress with the same listener id.
    #[tokio::test]
    async fn rotation_emits_address_expired_then_new_address() {
        let now = OffsetDateTime::now_utc();
        let certs = short_current_next(now);
        let (mut listener, clock) = build_listener_with_clock(certs, now);
        let id = listener.listener_id;

        // Arm the timer to fire immediately and advance the clock past the active window.
        listener.rotation_timer = futures_timer::Delay::new(Duration::ZERO);
        clock.set(now + TEST_VALIDITY + TimeDuration::seconds(1));

        let ev1 = poll_fn(|cx| Pin::new(&mut listener).poll_next(cx)).await;
        let ev2 = poll_fn(|cx| Pin::new(&mut listener).poll_next(cx)).await;

        match (ev1, ev2) {
            (
                Some(TransportEvent::AddressExpired { listener_id: a, .. }),
                Some(TransportEvent::NewAddress {
                    listener_id: b,
                    listen_addr,
                }),
            ) => {
                assert_eq!(a, id);
                assert_eq!(b, id);
                assert_eq!(multiaddr_hashes(&listen_addr).len(), 2);
            }
            other => panic!("unexpected events: {other:?}"),
        }
    }

    // R8: queued address events drain before ListenerClosed, and none are dropped.
    #[tokio::test]
    async fn close_delivers_listener_closed_last() {
        let now = OffsetDateTime::now_utc();
        let certs = short_current_next(now);
        let mut listener = build_listener(certs, now);
        let id = listener.listener_id;

        // Rotate to enqueue AddressExpired + NewAddress, then close (enqueues ListenerClosed).
        listener
            .rotate(now + TEST_VALIDITY + TimeDuration::seconds(1))
            .unwrap();
        listener.close(Ok(()));

        let e1 = poll_fn(|cx| Pin::new(&mut listener).poll_next(cx)).await;
        let e2 = poll_fn(|cx| Pin::new(&mut listener).poll_next(cx)).await;
        let e3 = poll_fn(|cx| Pin::new(&mut listener).poll_next(cx)).await;
        let e4 = poll_fn(|cx| Pin::new(&mut listener).poll_next(cx)).await;

        assert!(matches!(e1, Some(TransportEvent::AddressExpired { .. })));
        assert!(matches!(e2, Some(TransportEvent::NewAddress { .. })));
        assert!(matches!(
            e3,
            Some(TransportEvent::ListenerClosed { listener_id, reason: Ok(()) }) if listener_id == id
        ));
        assert!(e4.is_none(), "stream terminates after ListenerClosed");
    }

    // R10: the multiaddr helper emits exactly two /certhash even when handed a 3-element slice
    // (asserting the multiaddr/Noise split, not a global cap).
    #[test]
    fn multiaddr_emits_two_of_three_hashes() {
        let now = OffsetDateTime::now_utc();
        let a = Certificate::generate(now).unwrap();
        let b = Certificate::generate(now).unwrap();
        let c = Certificate::generate(now).unwrap();
        // Order is [last, current, next]; multiaddr should take the last two (current+next).
        let hashes = vec![a.cert_hash(), b.cert_hash(), c.cert_hash()];
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
        let ma = socketaddr_to_multiaddr_with_hashes(&addr, &hashes);
        let emitted = multiaddr_hashes(&ma);
        assert_eq!(emitted.len(), 2);
        // The expired `last` (a) is excluded; current+next (b, c) are present.
        assert!(!emitted.contains(&a.cert_hash()));
        assert!(emitted.contains(&b.cert_hash()));
        assert!(emitted.contains(&c.cert_hash()));
    }

    // ---- Negative / malformed dial-address parsing (N-series) ----

    /// Build a WebTransport dial multiaddr with `n` distinct certhashes.
    fn dial_addr_with_n_certhashes(n: usize) -> Multiaddr {
        let now = OffsetDateTime::now_utc();
        let mut ma: Multiaddr = "/ip4/127.0.0.1/udp/4433/quic-v1/webtransport"
            .parse()
            .unwrap();
        for _ in 0..n {
            ma.push(Protocol::Certhash(
                Certificate::generate(now).unwrap().cert_hash(),
            ));
        }
        ma
    }

    // N1: a two-certhash dial addr parses both hashes.
    #[test]
    fn dial_two_certhashes() {
        let (_, hashes, _) =
            multiaddr_to_dial_addr(&dial_addr_with_n_certhashes(2)).expect("parses");
        assert_eq!(hashes.len(), 2);
    }

    // N2: a three-certhash dial addr collects all three (unbounded dial vec).
    #[test]
    fn dial_three_certhashes() {
        let (_, hashes, _) =
            multiaddr_to_dial_addr(&dial_addr_with_n_certhashes(3)).expect("parses");
        assert_eq!(hashes.len(), 3);
    }

    // N3: a dial address with zero certhashes parses (empty vec) — the transport rejects it later
    // with MissingCerthashes (asserted in the dial path).
    #[test]
    fn dial_zero_certhashes_rejected_by_transport() {
        let (keypair, cert) = generate_keypair_and_cert();
        let mut transport = Transport::new(Config::new(&keypair, cert));
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/4433/quic-v1/webtransport"
            .parse()
            .unwrap();
        let res = transport.dial(
            addr,
            DialOpts {
                role: libp2p_core::Endpoint::Dialer,
                port_use: libp2p_core::transport::PortUse::Reuse,
            },
        );
        assert!(
            matches!(res, Err(TransportError::Other(Error::MissingCerthashes))),
            "expected MissingCerthashes"
        );
    }

    // N4: a listen address with an embedded /certhash is rejected.
    #[test]
    fn listen_addr_with_certhash_rejected() {
        assert!(multiaddr_to_socketaddr(&dial_addr_with_n_certhashes(1)).is_none());
    }

    // N5/N6: a non-SHA256 / wrong-length certhash is rejected by certhash_to_digest.
    #[test]
    fn non_sha256_certhash_rejected() {
        // Identity multihash (code 0x00), 4-byte digest — not SHA-256.
        let bad = CertHash::wrap(0x00, &[1, 2, 3, 4]).unwrap();
        assert!(matches!(
            certhash_to_digest(&bad),
            Err(Error::UnsupportedCerthash)
        ));

        // Wrong-length SHA-256 digest (correct code, 4 bytes instead of 32).
        let wrong_len = CertHash::wrap(MULTIHASH_SHA256_CODE, &[1, 2, 3, 4]).unwrap();
        assert!(matches!(
            certhash_to_digest(&wrong_len),
            Err(Error::UnsupportedCerthash)
        ));
    }
}
