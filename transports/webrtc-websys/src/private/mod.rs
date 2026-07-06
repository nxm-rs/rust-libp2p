//! Private-to-private WebRTC transport for the browser.
//!
//! Establishes `/webrtc` connections between two NAT'd peers: SDP offers, answers and
//! trickled ICE candidates are exchanged over a signalling stream on an existing relayed
//! connection, then the browser's ICE stack opens a direct connection. The DTLS
//! handshake authenticates the remote against the certificate fingerprint carried in the
//! exchanged SDP; the peer identity is the one authenticated on the relayed connection,
//! so no further handshake runs on the direct connection.

mod upgrade;

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

use futures::prelude::*;
use libp2p_core::{
    multiaddr::{Multiaddr, Protocol},
    transport::{DialOpts, ListenerId, TransportError, TransportEvent},
};
use libp2p_identity::PeerId;
pub use libp2p_webrtc_utils::signaling::Behaviour;
use libp2p_webrtc_utils::signaling::{Control, IncomingStreams, parse_webrtc_signaling_addr};

use crate::{Connection, Error};

/// Configuration of the private-to-private WebRTC transport.
#[derive(Debug, Clone)]
pub struct Config {
    /// ICE server urls handed to the browser, e.g. `stun:stun.example.net:3478`.
    ice_servers: Vec<String>,
    /// Time budget for the whole signalling, ICE and DTLS exchange of one connection.
    handshake_timeout: Duration,
}

impl Config {
    pub fn new() -> Self {
        Self {
            ice_servers: Vec::new(),
            handshake_timeout: Duration::from_secs(20),
        }
    }

    /// Add an ICE server, typically a STUN endpoint of the form `stun:<host>:<port>`.
    ///
    /// Without at least one, only host candidates are gathered, which is enough on a
    /// shared network but not across NATs.
    pub fn with_ice_server(mut self, url: impl Into<String>) -> Self {
        self.ice_servers.push(url.into());
        self
    }

    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns a `/webrtc` transport together with the signalling behaviour driving it.
///
/// The behaviour must be installed in the same swarm as the transport: it exchanges the
/// SDP and ICE messages over relayed connections on behalf of the transport.
pub fn new(config: Config) -> (Transport, Behaviour) {
    let (behaviour, control, incoming) = Behaviour::new();

    (
        Transport {
            config,
            control,
            incoming: Some(incoming),
            listener: None,
        },
        behaviour,
    )
}

/// A private-to-private WebRTC transport, created via [`new`].
pub struct Transport {
    config: Config,
    control: Control,
    /// Inbound signalling streams, until a listener takes them.
    incoming: Option<IncomingStreams>,
    listener: Option<ListenStream>,
}

impl libp2p_core::Transport for Transport {
    type Output = (PeerId, Connection);
    type Error = Error;
    type ListenerUpgrade = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;
    type Dial = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        if !is_webrtc_listen_addr(&addr) {
            return Err(TransportError::MultiaddrNotSupported(addr));
        }

        let incoming = self
            .incoming
            .take()
            .ok_or(TransportError::Other(Error::Connection(
                "the webrtc transport supports a single listener".to_owned(),
            )))?;

        self.listener = Some(ListenStream::new(id, addr, self.config.clone(), incoming));

        Ok(())
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        match self.listener {
            Some(ref mut listener) if listener.listener_id == id => {
                listener.close();
                true
            }
            _ => false,
        }
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        if let Some(listener) = self.listener.as_mut() {
            match listener.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => return Poll::Ready(event),
                Poll::Ready(None) => {
                    // Reclaim the stream source so a new listener can be started.
                    self.incoming = self.listener.take().and_then(|l| l.into_incoming());
                }
                Poll::Pending => {}
            }
        }

        Poll::Pending
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        _dial_opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        // The signalling roles are fixed by who opens the signalling stream, so a dial
        // is performed the same way regardless of the requested connection role.
        let (relayed_addr, peer) = parse_webrtc_signaling_addr(&addr)
            .ok_or_else(|| TransportError::MultiaddrNotSupported(addr.clone()))?;
        let peer = peer.ok_or(TransportError::MultiaddrNotSupported(addr))?;

        let mut control = self.control.clone();
        let config = self.config.clone();

        Ok(async move {
            let signaling = control.open_stream(peer, relayed_addr).await?;
            let connection = upgrade::outbound(signaling, config).await?;

            Ok((peer, connection))
        }
        .boxed())
    }
}

/// A stream of incoming `/webrtc` connections, fed by inbound signalling streams.
struct ListenStream {
    listener_id: ListenerId,
    listen_addr: Multiaddr,
    config: Config,
    incoming: Option<IncomingStreams>,
    /// Pending event to report before processing incoming streams.
    pending_event: Option<<Self as Stream>::Item>,
    /// Set once the listener should terminate after reporting the contained event.
    report_closed: Option<Option<<Self as Stream>::Item>>,
    close_waker: Option<Waker>,
}

impl ListenStream {
    fn new(
        listener_id: ListenerId,
        listen_addr: Multiaddr,
        config: Config,
        incoming: IncomingStreams,
    ) -> Self {
        ListenStream {
            listener_id,
            listen_addr: listen_addr.clone(),
            config,
            incoming: Some(incoming),
            pending_event: Some(TransportEvent::NewAddress {
                listener_id,
                listen_addr,
            }),
            report_closed: None,
            close_waker: None,
        }
    }

    fn close(&mut self) {
        if self.report_closed.is_some() {
            return;
        }

        self.report_closed = Some(Some(TransportEvent::ListenerClosed {
            listener_id: self.listener_id,
            reason: Ok(()),
        }));

        if let Some(waker) = self.close_waker.take() {
            waker.wake();
        }
    }

    fn into_incoming(self) -> Option<IncomingStreams> {
        self.incoming
    }
}

impl Stream for ListenStream {
    type Item = TransportEvent<<Transport as libp2p_core::Transport>::ListenerUpgrade, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(event) = self.pending_event.take() {
                return Poll::Ready(Some(event));
            }

            if let Some(closed) = self.report_closed.as_mut() {
                return Poll::Ready(closed.take());
            }

            if let Some(incoming) = self.incoming.as_mut() {
                match incoming.poll_next_unpin(cx) {
                    Poll::Ready(Some((peer, signaling))) => {
                        let config = self.config.clone();
                        let upgrade = async move {
                            let connection = upgrade::inbound(signaling, config).await?;

                            Ok((peer, connection))
                        }
                        .boxed();

                        return Poll::Ready(Some(TransportEvent::Incoming {
                            listener_id: self.listener_id,
                            upgrade,
                            local_addr: self.listen_addr.clone(),
                            send_back_addr: Multiaddr::empty()
                                .with(Protocol::WebRTC)
                                .with(Protocol::P2p(peer)),
                        }));
                    }
                    Poll::Ready(None) => {
                        // The signalling behaviour was dropped; no more streams will
                        // arrive.
                        self.incoming = None;
                        self.close();
                        continue;
                    }
                    Poll::Pending => {}
                }
            }

            self.close_waker = Some(cx.waker().clone());

            return Poll::Pending;
        }
    }
}

/// A `/webrtc` listen address: bare `/webrtc`, or a relayed multiaddr ending in
/// `/p2p-circuit/webrtc`.
fn is_webrtc_listen_addr(addr: &Multiaddr) -> bool {
    let mut protocols: Vec<Protocol> = addr.iter().collect();

    if !matches!(protocols.pop(), Some(Protocol::WebRTC)) {
        return false;
    }

    matches!(protocols.last(), None | Some(Protocol::P2pCircuit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_webrtc_listen_addrs() {
        for addr in [
            "/webrtc",
            "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWGQTQuV6JfgpKpc847NMsxaFnKXDEpkN5kbeH1REW41BR/p2p-circuit/webrtc",
        ] {
            assert!(is_webrtc_listen_addr(&addr.parse().unwrap()), "{addr}");
        }
    }

    #[test]
    fn rejects_non_webrtc_listen_addrs() {
        for addr in [
            "/ip4/127.0.0.1/udp/4001/webrtc-direct",
            "/ip4/127.0.0.1/tcp/4001/webrtc",
            "/ip4/127.0.0.1/tcp/4001/p2p-circuit",
        ] {
            assert!(!is_webrtc_listen_addr(&addr.parse().unwrap()), "{addr}");
        }
    }

    #[test]
    fn dial_addr_roundtrip() {
        let target: PeerId = "12D3KooWNpDk9w6WrEEcdsEH1y47W71S36yFjw4sd3j7omzgCSMS"
            .parse()
            .unwrap();
        let addr: Multiaddr = format!(
            "/ip4/127.0.0.1/tcp/4001/ws/p2p/12D3KooWGQTQuV6JfgpKpc847NMsxaFnKXDEpkN5kbeH1REW41BR/p2p-circuit/webrtc/p2p/{target}"
        )
        .parse()
        .unwrap();

        let (relayed, peer) = parse_webrtc_signaling_addr(&addr).unwrap();

        assert_eq!(peer, Some(target));
        assert!(relayed.iter().any(|p| p == Protocol::P2pCircuit));
        assert!(!relayed.iter().any(|p| p == Protocol::WebRTC));
    }
}
