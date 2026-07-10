//! Swarm integration for the WebRTC signalling protocol.
//!
//! [`Behaviour`] runs `/webrtc-signaling/0.0.1` streams on relayed connections only:
//! [`Control`] opens outbound signalling streams for a dialing WebRTC transport, dialing
//! the relayed multiaddr first if no relayed connection to the peer exists, and
//! [`IncomingStreams`] yields signalling streams opened by remote peers.

use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};

use either::Either;
use futures::{
    SinkExt, StreamExt,
    channel::{mpsc, oneshot},
    future,
};
use libp2p_core::{
    Endpoint, Multiaddr, multiaddr::Protocol, transport::PortUse, upgrade::DeniedUpgrade,
};
use libp2p_identity::PeerId;
use libp2p_swarm::{
    ConnectionDenied, ConnectionHandler, ConnectionHandlerEvent, ConnectionId, NetworkBehaviour,
    NotifyHandler, StreamUpgradeError, SubstreamProtocol, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
    dial_opts::{DialOpts, PeerCondition},
    handler::{ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound},
};

use super::{Signaling, SignalingProtocol};

/// A signalling exchange running on a stream of a relayed connection.
pub type SignalingStream = Signaling<libp2p_swarm::Stream>;

/// Maximum number of inbound signalling streams buffered before new ones are dropped.
const MAX_BUFFERED_INBOUND_STREAMS: usize = 8;

/// Error opening an outbound signalling stream via [`Control::open_stream`].
#[derive(Debug, thiserror::Error)]
pub enum OpenStreamError {
    #[error("the signalling behaviour is no longer part of a swarm")]
    BehaviourGone,
    #[error("failed to establish a relayed connection to the peer")]
    DialFailed,
    #[error("the remote does not support the signalling protocol")]
    UnsupportedProtocol,
    #[error("signalling stream negotiation timed out")]
    Timeout,
    #[error("IO error during signalling stream negotiation: {0}")]
    Io(#[from] io::Error),
}

/// Opens outbound signalling streams through the [`Behaviour`].
///
/// Cheap to clone; typically owned by the WebRTC transport.
#[derive(Debug, Clone)]
pub struct Control {
    sender: mpsc::Sender<OpenRequest>,
}

impl Control {
    /// Open a signalling stream to `peer` over a relayed connection.
    ///
    /// Dials `relayed_addr` first if no relayed connection to `peer` exists yet.
    pub async fn open_stream(
        &mut self,
        peer: PeerId,
        relayed_addr: Multiaddr,
    ) -> Result<SignalingStream, OpenStreamError> {
        let (response, receiver) = oneshot::channel();

        self.sender
            .send(OpenRequest {
                peer,
                relayed_addr,
                response,
            })
            .await
            .map_err(|_| OpenStreamError::BehaviourGone)?;

        receiver.await.map_err(|_| OpenStreamError::BehaviourGone)?
    }
}

/// Signalling streams opened by remote peers, in the order they arrived.
///
/// The remote peer id is the one authenticated on the relayed connection carrying the
/// stream.
pub struct IncomingStreams {
    receiver: mpsc::Receiver<(PeerId, SignalingStream)>,
}

impl futures::Stream for IncomingStreams {
    type Item = (PeerId, SignalingStream);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_next_unpin(cx)
    }
}

impl fmt::Debug for IncomingStreams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingStreams").finish_non_exhaustive()
    }
}

/// A request from a [`Control`] for a signalling stream to `peer`.
struct OpenRequest {
    peer: PeerId,
    relayed_addr: Multiaddr,
    response: oneshot::Sender<Result<SignalingStream, OpenStreamError>>,
}

impl fmt::Debug for OpenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenRequest")
            .field("peer", &self.peer)
            .field("relayed_addr", &self.relayed_addr)
            .finish_non_exhaustive()
    }
}

/// [`NetworkBehaviour`] driving the WebRTC signalling protocol on relayed connections.
pub struct Behaviour {
    requests: mpsc::Receiver<OpenRequest>,
    incoming: mpsc::Sender<(PeerId, SignalingStream)>,
    /// Established relayed connections, per peer.
    relayed_connections: HashMap<PeerId, Vec<ConnectionId>>,
    /// Requests waiting for a relayed connection we dialed, keyed by dial connection id.
    pending_dials: HashMap<ConnectionId, Vec<OpenRequest>>,
    queued_events: VecDeque<ToSwarm<Infallible, Command>>,
}

impl Behaviour {
    /// Returns the behaviour together with the handles the WebRTC transport uses to open
    /// and accept signalling streams.
    pub fn new() -> (Self, Control, IncomingStreams) {
        let (request_sender, request_receiver) = mpsc::channel(0);
        let (incoming_sender, incoming_receiver) = mpsc::channel(MAX_BUFFERED_INBOUND_STREAMS);

        (
            Behaviour {
                requests: request_receiver,
                incoming: incoming_sender,
                relayed_connections: HashMap::new(),
                pending_dials: HashMap::new(),
                queued_events: VecDeque::new(),
            },
            Control {
                sender: request_sender,
            },
            IncomingStreams {
                receiver: incoming_receiver,
            },
        )
    }

    fn on_request(&mut self, request: OpenRequest) {
        if let Some(connection_id) = self
            .relayed_connections
            .get(&request.peer)
            .and_then(|connections| connections.first())
        {
            self.queued_events.push_back(ToSwarm::NotifyHandler {
                peer_id: request.peer,
                handler: NotifyHandler::One(*connection_id),
                event: Command::OpenStream {
                    response: request.response,
                },
            });
            return;
        }

        let opts = DialOpts::peer_id(request.peer)
            .addresses(vec![request.relayed_addr.clone()])
            .condition(PeerCondition::Always)
            .build();
        self.pending_dials
            .entry(opts.connection_id())
            .or_default()
            .push(request);
        self.queued_events.push_back(ToSwarm::Dial { opts });
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Handler;
    type ToSwarm = Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let relayed = is_relayed(local_addr);
        if relayed {
            self.relayed_connections
                .entry(peer)
                .or_default()
                .push(connection_id);
        }

        Ok(Handler::new(relayed))
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let relayed = is_relayed(addr);
        if relayed {
            self.relayed_connections
                .entry(peer)
                .or_default()
                .push(connection_id);
        }

        let mut handler = Handler::new(relayed);

        for request in self
            .pending_dials
            .remove(&connection_id)
            .unwrap_or_default()
        {
            if relayed && request.peer == peer {
                handler.on_behaviour_event(Command::OpenStream {
                    response: request.response,
                });
            } else {
                let _ = request.response.send(Err(OpenStreamError::DialFailed));
            }
        }

        Ok(handler)
    }

    fn on_swarm_event(&mut self, event: libp2p_swarm::behaviour::FromSwarm) {
        use libp2p_swarm::behaviour::FromSwarm;

        match event {
            FromSwarm::ConnectionClosed(closed) => {
                if let Some(connections) = self.relayed_connections.get_mut(&closed.peer_id) {
                    connections.retain(|id| *id != closed.connection_id);
                    if connections.is_empty() {
                        self.relayed_connections.remove(&closed.peer_id);
                    }
                }
            }
            FromSwarm::DialFailure(failure) => {
                for request in self
                    .pending_dials
                    .remove(&failure.connection_id)
                    .unwrap_or_default()
                {
                    let _ = request.response.send(Err(OpenStreamError::DialFailed));
                }
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            Event::InboundStream(stream) => {
                if self.incoming.try_send((peer, stream)).is_err() {
                    tracing::debug!(
                        %peer,
                        "Dropping inbound signalling stream: no transport is accepting them"
                    );
                }
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        loop {
            if let Some(event) = self.queued_events.pop_front() {
                return Poll::Ready(event);
            }

            match self.requests.poll_next_unpin(cx) {
                Poll::Ready(Some(request)) => {
                    self.on_request(request);
                    continue;
                }
                // All `Control`s are gone; incoming streams may still arrive.
                Poll::Ready(None) | Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn is_relayed(addr: &Multiaddr) -> bool {
    addr.iter().any(|protocol| protocol == Protocol::P2pCircuit)
}

/// Commands from the [`Behaviour`] to a [`Handler`].
pub enum Command {
    OpenStream {
        response: oneshot::Sender<Result<SignalingStream, OpenStreamError>>,
    },
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::OpenStream { .. } => f.debug_struct("OpenStream").finish_non_exhaustive(),
        }
    }
}

/// Events from a [`Handler`] to the [`Behaviour`].
pub enum Event {
    InboundStream(SignalingStream),
}

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::InboundStream(_) => f.debug_struct("InboundStream").finish_non_exhaustive(),
        }
    }
}

/// Connection handler negotiating signalling streams.
///
/// Streams are only offered and accepted on relayed connections.
pub struct Handler {
    relayed: bool,
    queued_events: VecDeque<
        ConnectionHandlerEvent<
            SignalingProtocol,
            <Handler as ConnectionHandler>::OutboundOpenInfo,
            Event,
        >,
    >,
}

impl Handler {
    fn new(relayed: bool) -> Self {
        Handler {
            relayed,
            queued_events: VecDeque::new(),
        }
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = Command;
    type ToBehaviour = Event;
    type InboundProtocol = Either<SignalingProtocol, DeniedUpgrade>;
    type OutboundProtocol = SignalingProtocol;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = oneshot::Sender<Result<SignalingStream, OpenStreamError>>;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        if self.relayed {
            SubstreamProtocol::new(Either::Left(SignalingProtocol), ())
        } else {
            SubstreamProtocol::new(Either::Right(DeniedUpgrade), ())
        }
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {
            Command::OpenStream { response } => {
                self.queued_events
                    .push_back(ConnectionHandlerEvent::OutboundSubstreamRequest {
                        protocol: SubstreamProtocol::new(SignalingProtocol, response),
                    });
            }
        }
    }

    fn poll(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        if let Some(event) = self.queued_events.pop_front() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol, ..
            }) => match protocol {
                future::Either::Left(stream) => {
                    self.queued_events
                        .push_back(ConnectionHandlerEvent::NotifyBehaviour(
                            Event::InboundStream(stream),
                        ));
                }
                // Streams on non-relayed connections are denied and thus never negotiate.
                future::Either::Right(infallible) => libp2p_core::util::unreachable(infallible),
            },
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol,
                info,
            }) => {
                let _ = info.send(Ok(protocol));
            }
            ConnectionEvent::DialUpgradeError(DialUpgradeError { info, error }) => {
                let error = match error {
                    StreamUpgradeError::Apply(infallible) => {
                        libp2p_core::util::unreachable(infallible)
                    }
                    StreamUpgradeError::NegotiationFailed => OpenStreamError::UnsupportedProtocol,
                    StreamUpgradeError::Timeout => OpenStreamError::Timeout,
                    StreamUpgradeError::Io(error) => OpenStreamError::Io(error),
                };
                let _ = info.send(Err(error));
            }
            _ => {}
        }
    }
}
