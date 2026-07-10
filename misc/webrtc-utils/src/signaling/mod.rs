//! Implementation of the `/webrtc-signaling/0.0.1` protocol.
//!
//! The protocol runs over a stream on an existing relayed connection and negotiates a
//! direct WebRTC connection: the dialer sends an SDP offer, the listener replies with an
//! SDP answer, then both sides trickle ICE candidates until the exchange is closed.
//!
//! Messages are protobuf-encoded and prefixed with their length in bytes, encoded as an
//! unsigned varint per the multiformats spec.

mod behaviour;

use std::{collections::VecDeque, convert::Infallible, io, iter};

use asynchronous_codec::{BytesMut, Framed};
pub use behaviour::{Behaviour, Control, IncomingStreams, OpenStreamError, SignalingStream};
use futures::{
    AsyncRead, AsyncWrite, SinkExt, StreamExt, future,
    stream::{SplitSink, SplitStream},
};
use libp2p_core::{
    Multiaddr,
    multiaddr::Protocol,
    upgrade::{InboundUpgrade, OutboundUpgrade, UpgradeInfo},
};
use libp2p_identity::PeerId;

use crate::proto::{SignalingMessage, SignalingMessageType};

/// Protocol id of the WebRTC signalling protocol.
pub const PROTOCOL_NAME: &str = "/webrtc-signaling/0.0.1";

/// Maximum length in bytes of a signalling message, excluding the length prefix.
///
/// SDP documents and ICE candidates are at most a few kilobytes each.
pub const MAX_MESSAGE_LEN: usize = 16 * 1024;

/// A message exchanged on a signalling stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// An SDP offer, sent by the dialer.
    Offer(String),
    /// An SDP answer, sent by the listener.
    Answer(String),
    /// A trickled ICE candidate, `None` once the sender has no further candidates.
    IceCandidate(Option<String>),
}

impl Message {
    fn into_proto(self) -> SignalingMessage {
        match self {
            Message::Offer(sdp) => SignalingMessage {
                r#type: Some(SignalingMessageType::SdpOffer as i32),
                data: Some(sdp),
            },
            Message::Answer(sdp) => SignalingMessage {
                r#type: Some(SignalingMessageType::SdpAnswer as i32),
                data: Some(sdp),
            },
            Message::IceCandidate(candidate) => SignalingMessage {
                r#type: Some(SignalingMessageType::IceCandidate as i32),
                data: candidate,
            },
        }
    }

    fn try_from_proto(message: SignalingMessage) -> Result<Self, Error> {
        let message_type = message
            .r#type
            .and_then(|t| SignalingMessageType::try_from(t).ok())
            .ok_or(Error::Protocol("missing or unknown message type"))?;

        match message_type {
            SignalingMessageType::SdpOffer => Ok(Message::Offer(
                message.data.ok_or(Error::Protocol("offer without SDP"))?,
            )),
            SignalingMessageType::SdpAnswer => Ok(Message::Answer(
                message.data.ok_or(Error::Protocol("answer without SDP"))?,
            )),
            // An absent, empty or JSON `null` payload signals the end of candidates.
            SignalingMessageType::IceCandidate => Ok(Message::IceCandidate(
                message
                    .data
                    .filter(|data| !data.is_empty() && data != "null"),
            )),
        }
    }
}

/// Codec turning [`Message`]s into length-prefixed protobuf frames and back.
#[derive(Debug, Clone)]
pub struct Codec {
    inner: prost_codec::Codec<SignalingMessage>,
}

impl Default for Codec {
    fn default() -> Self {
        Self {
            inner: prost_codec::Codec::new(MAX_MESSAGE_LEN),
        }
    }
}

impl asynchronous_codec::Encoder for Codec {
    type Item<'a> = Message;
    type Error = Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.inner.encode(item.into_proto(), dst)?;
        Ok(())
    }
}

impl asynchronous_codec::Decoder for Codec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.inner
            .decode(src)?
            .map(Message::try_from_proto)
            .transpose()
    }
}

/// Error produced while driving a signalling exchange.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("signalling stream closed unexpectedly")]
    UnexpectedEof,
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
}

impl From<prost_codec::Error> for Error {
    fn from(error: prost_codec::Error) -> Self {
        Error::Io(error.into())
    }
}

/// Upgrade that negotiates the signalling protocol on a stream of a relayed connection.
#[derive(Debug, Clone, Copy, Default)]
pub struct SignalingProtocol;

impl UpgradeInfo for SignalingProtocol {
    type Info = &'static str;
    type InfoIter = iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(PROTOCOL_NAME)
    }
}

impl<C> InboundUpgrade<C> for SignalingProtocol
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Signaling<C>;
    type Error = Infallible;
    type Future = future::Ready<Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, stream: C, _: Self::Info) -> Self::Future {
        future::ready(Ok(Signaling::new(stream)))
    }
}

impl<C> OutboundUpgrade<C> for SignalingProtocol
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Signaling<C>;
    type Error = Infallible;
    type Future = future::Ready<Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, stream: C, _: Self::Info) -> Self::Future {
        future::ready(Ok(Signaling::new(stream)))
    }
}

/// A freshly opened signalling stream, before any message has been exchanged.
#[derive(Debug)]
pub struct Signaling<S> {
    framed: Framed<S, Codec>,
}

impl<S> Signaling<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S) -> Self {
        Self {
            framed: Framed::new(stream, Codec::default()),
        }
    }

    /// Dialer role: send the SDP offer and wait for the remote answer.
    ///
    /// Candidates the remote trickles before its answer are buffered and yielded first
    /// by the returned [`CandidateExchange`].
    pub async fn send_offer(
        mut self,
        sdp: String,
    ) -> Result<(String, CandidateExchange<S>), Error> {
        self.framed.send(Message::Offer(sdp)).await?;

        let mut pending = VecDeque::new();
        loop {
            match self.framed.next().await.ok_or(Error::UnexpectedEof)?? {
                Message::Answer(answer) => {
                    return Ok((
                        answer,
                        CandidateExchange {
                            framed: self.framed,
                            pending,
                        },
                    ));
                }
                Message::IceCandidate(candidate) => pending.push_back(candidate),
                Message::Offer(_) => return Err(Error::Protocol("unexpected offer")),
            }
        }
    }

    /// Listener role: wait for the remote SDP offer.
    pub async fn recv_offer(mut self) -> Result<(String, PendingAnswer<S>), Error> {
        match self.framed.next().await.ok_or(Error::UnexpectedEof)?? {
            Message::Offer(offer) => Ok((
                offer,
                PendingAnswer {
                    framed: self.framed,
                },
            )),
            _ => Err(Error::Protocol("expected offer as first message")),
        }
    }
}

/// A signalling stream whose offer has been received but not yet answered.
#[derive(Debug)]
pub struct PendingAnswer<S> {
    framed: Framed<S, Codec>,
}

impl<S> PendingAnswer<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Send the SDP answer, moving the exchange into the trickle-ICE phase.
    pub async fn send_answer(mut self, sdp: String) -> Result<CandidateExchange<S>, Error> {
        self.framed.send(Message::Answer(sdp)).await?;

        Ok(CandidateExchange {
            framed: self.framed,
            pending: VecDeque::new(),
        })
    }
}

/// The trickle-ICE phase of a signalling exchange.
///
/// Use [`CandidateExchange::split`] to send and receive candidates concurrently.
#[derive(Debug)]
pub struct CandidateExchange<S> {
    framed: Framed<S, Codec>,
    pending: VecDeque<Option<String>>,
}

impl<S> CandidateExchange<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Send a local ICE candidate to the remote.
    pub async fn send_candidate(&mut self, candidate: String) -> Result<(), Error> {
        self.framed
            .send(Message::IceCandidate(Some(candidate)))
            .await
    }

    /// Tell the remote that no further local candidates will follow.
    pub async fn send_end_of_candidates(&mut self) -> Result<(), Error> {
        self.framed.send(Message::IceCandidate(None)).await
    }

    /// Next remote ICE candidate.
    ///
    /// `None` once the remote signalled the end of its candidates or closed the stream.
    pub async fn next_candidate(&mut self) -> Result<Option<String>, Error> {
        if let Some(candidate) = self.pending.pop_front() {
            return Ok(candidate);
        }

        match self.framed.next().await {
            None => Ok(None),
            Some(message) => match message? {
                Message::IceCandidate(candidate) => Ok(candidate),
                _ => Err(Error::Protocol("unexpected SDP message during trickle")),
            },
        }
    }

    /// Split into independently usable sending and receiving halves.
    pub fn split(self) -> (CandidateSender<S>, CandidateReceiver<S>) {
        let (sink, stream) = self.framed.split();

        (
            CandidateSender { sink },
            CandidateReceiver {
                stream,
                pending: self.pending,
            },
        )
    }

    /// Close the signalling stream.
    pub async fn close(mut self) -> Result<(), Error> {
        self.framed.close().await
    }
}

/// Sending half of a [`CandidateExchange`].
#[derive(Debug)]
pub struct CandidateSender<S> {
    sink: SplitSink<Framed<S, Codec>, Message>,
}

impl<S> CandidateSender<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Send a local ICE candidate to the remote.
    pub async fn send_candidate(&mut self, candidate: String) -> Result<(), Error> {
        self.sink.send(Message::IceCandidate(Some(candidate))).await
    }

    /// Tell the remote that no further local candidates will follow.
    pub async fn send_end_of_candidates(&mut self) -> Result<(), Error> {
        self.sink.send(Message::IceCandidate(None)).await
    }

    /// Close the signalling stream.
    pub async fn close(mut self) -> Result<(), Error> {
        self.sink.close().await
    }
}

/// Receiving half of a [`CandidateExchange`].
#[derive(Debug)]
pub struct CandidateReceiver<S> {
    stream: SplitStream<Framed<S, Codec>>,
    pending: VecDeque<Option<String>>,
}

impl<S> CandidateReceiver<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Next remote ICE candidate.
    ///
    /// `None` once the remote signalled the end of its candidates or closed the stream.
    pub async fn next_candidate(&mut self) -> Result<Option<String>, Error> {
        if let Some(candidate) = self.pending.pop_front() {
            return Ok(candidate);
        }

        match self.stream.next().await {
            None => Ok(None),
            Some(message) => match message? {
                Message::IceCandidate(candidate) => Ok(candidate),
                _ => Err(Error::Protocol("unexpected SDP message during trickle")),
            },
        }
    }
}

/// Parse a `<relayed-multiaddr>/webrtc/p2p/<peer-id>` address.
///
/// Returns the relayed address to dial for signalling together with the target peer, or
/// `None` if the address does not end in `/p2p-circuit/webrtc` with an optional trailing
/// `/p2p/<peer-id>`.
pub fn parse_webrtc_signaling_addr(addr: &Multiaddr) -> Option<(Multiaddr, Option<PeerId>)> {
    let mut protocols: Vec<Protocol> = addr.iter().collect();

    let peer_id = match protocols.last()? {
        Protocol::P2p(peer_id) => {
            let peer_id = *peer_id;
            protocols.pop();
            Some(peer_id)
        }
        _ => None,
    };

    if !matches!(protocols.pop()?, Protocol::WebRTC) {
        return None;
    }
    if !matches!(protocols.last()?, Protocol::P2pCircuit) {
        return None;
    }

    let mut relayed: Multiaddr = protocols.into_iter().collect();
    if let Some(peer_id) = peer_id {
        relayed.push(Protocol::P2p(peer_id));
    }

    Some((relayed, peer_id))
}

#[cfg(test)]
mod tests {
    use asynchronous_codec::{Decoder as _, Encoder as _};
    use futures::{executor::block_on, future::join};

    use super::*;

    fn roundtrip(message: Message) {
        let mut codec = Codec::default();
        let mut buffer = BytesMut::new();

        codec.encode(message.clone(), &mut buffer).unwrap();
        let decoded = codec.decode(&mut buffer).unwrap().unwrap();

        assert_eq!(decoded, message);
        assert!(buffer.is_empty());
    }

    #[test]
    fn offer_roundtrip() {
        roundtrip(Message::Offer("v=0\r\no=- 0 0 IN IP4 127.0.0.1".to_owned()));
    }

    #[test]
    fn answer_roundtrip() {
        roundtrip(Message::Answer("v=0\r\ns=-".to_owned()));
    }

    #[test]
    fn candidate_roundtrip() {
        roundtrip(Message::IceCandidate(Some(
            r#"{"candidate":"candidate:1 1 UDP 2130706431 192.0.2.1 54321 typ host"}"#.to_owned(),
        )));
        roundtrip(Message::IceCandidate(None));
    }

    /// Length-prefixed wire format per the spec: an unsigned-varint length followed by a
    /// protobuf message with `optional Type type = 1` and `optional string data = 2`.
    #[test]
    fn wire_format_fixtures() {
        let fixtures = [
            (
                Message::Offer("v=0".to_owned()),
                &[0x07, 0x08, 0x00, 0x12, 0x03, b'v', b'=', b'0'][..],
            ),
            (
                Message::Answer("v=0".to_owned()),
                &[0x07, 0x08, 0x01, 0x12, 0x03, b'v', b'=', b'0'][..],
            ),
            (
                Message::IceCandidate(Some("abc".to_owned())),
                &[0x07, 0x08, 0x02, 0x12, 0x03, b'a', b'b', b'c'][..],
            ),
            (Message::IceCandidate(None), &[0x02, 0x08, 0x02][..]),
        ];

        for (message, expected) in fixtures {
            let mut codec = Codec::default();
            let mut buffer = BytesMut::new();

            codec.encode(message.clone(), &mut buffer).unwrap();
            assert_eq!(&buffer[..], expected);

            let decoded = codec.decode(&mut buffer).unwrap().unwrap();
            assert_eq!(decoded, message);
        }
    }

    #[test]
    fn end_of_candidates_normalisation() {
        for data in [None, Some(String::new()), Some("null".to_owned())] {
            let message = Message::try_from_proto(SignalingMessage {
                r#type: Some(SignalingMessageType::IceCandidate as i32),
                data,
            })
            .unwrap();

            assert_eq!(message, Message::IceCandidate(None));
        }
    }

    #[test]
    fn rejects_unknown_message_type() {
        for r#type in [None, Some(3)] {
            let result = Message::try_from_proto(SignalingMessage {
                r#type,
                data: Some("v=0".to_owned()),
            });

            assert!(matches!(result, Err(Error::Protocol(_))));
        }
    }

    #[test]
    fn protocol_name_matches_spec() {
        assert_eq!(PROTOCOL_NAME, "/webrtc-signaling/0.0.1");
        assert_eq!(
            SignalingProtocol.protocol_info().next(),
            Some("/webrtc-signaling/0.0.1")
        );
    }

    #[test]
    fn parse_signaling_addr() {
        let target: PeerId = "12D3KooWNpDk9w6WrEEcdsEH1y47W71S36yFjw4sd3j7omzgCSMS"
            .parse()
            .unwrap();
        let addr: Multiaddr = format!(
            "/ip4/127.0.0.1/tcp/4001/ws/p2p/12D3KooWGQTQuV6JfgpKpc847NMsxaFnKXDEpkN5kbeH1REW41BR/p2p-circuit/webrtc/p2p/{target}"
        )
        .parse()
        .unwrap();

        let (relayed, peer_id) = parse_webrtc_signaling_addr(&addr).unwrap();

        assert_eq!(
            relayed,
            format!(
                "/ip4/127.0.0.1/tcp/4001/ws/p2p/12D3KooWGQTQuV6JfgpKpc847NMsxaFnKXDEpkN5kbeH1REW41BR/p2p-circuit/p2p/{target}"
            )
            .parse()
            .unwrap()
        );
        assert_eq!(peer_id, Some(target));
    }

    #[test]
    fn parse_signaling_addr_without_peer_id() {
        let addr: Multiaddr =
            "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWGQTQuV6JfgpKpc847NMsxaFnKXDEpkN5kbeH1REW41BR/p2p-circuit/webrtc"
                .parse()
                .unwrap();

        let (relayed, peer_id) = parse_webrtc_signaling_addr(&addr).unwrap();

        assert_eq!(
            relayed,
            "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWGQTQuV6JfgpKpc847NMsxaFnKXDEpkN5kbeH1REW41BR/p2p-circuit"
                .parse()
                .unwrap()
        );
        assert_eq!(peer_id, None);
    }

    #[test]
    fn rejects_non_signaling_addrs() {
        let addrs = [
            "/ip4/127.0.0.1/udp/4001/webrtc-direct",
            "/ip4/127.0.0.1/tcp/4001/webrtc",
            "/ip4/127.0.0.1/tcp/4001/p2p-circuit",
        ];

        for addr in addrs {
            let addr: Multiaddr = addr.parse().unwrap();
            assert!(parse_webrtc_signaling_addr(&addr).is_none(), "{addr}");
        }
    }

    #[test]
    fn full_exchange_over_in_memory_relayed_stream() {
        let (dialer_io, listener_io) = futures_ringbuf::Endpoint::pair(4096, 4096);

        let dialer = async move {
            let (answer, exchange) = Signaling::new(dialer_io)
                .send_offer("v=0 offer".to_owned())
                .await
                .unwrap();
            assert_eq!(answer, "v=0 answer");

            let (mut sender, mut receiver) = exchange.split();

            let send = async {
                sender
                    .send_candidate("dialer-candidate-1".to_owned())
                    .await
                    .unwrap();
                sender
                    .send_candidate("dialer-candidate-2".to_owned())
                    .await
                    .unwrap();
                sender.send_end_of_candidates().await.unwrap();
                sender.close().await.unwrap();
            };
            let recv = async {
                let mut candidates = Vec::new();
                while let Some(candidate) = receiver.next_candidate().await.unwrap() {
                    candidates.push(candidate);
                }
                candidates
            };

            join(send, recv).await.1
        };

        let listener = async move {
            let (offer, pending) = Signaling::new(listener_io).recv_offer().await.unwrap();
            assert_eq!(offer, "v=0 offer");

            let exchange = pending.send_answer("v=0 answer".to_owned()).await.unwrap();
            let (mut sender, mut receiver) = exchange.split();

            let send = async {
                sender
                    .send_candidate("listener-candidate-1".to_owned())
                    .await
                    .unwrap();
                sender.send_end_of_candidates().await.unwrap();
                sender.close().await.unwrap();
            };
            let recv = async {
                let mut candidates = Vec::new();
                while let Some(candidate) = receiver.next_candidate().await.unwrap() {
                    candidates.push(candidate);
                }
                candidates
            };

            join(send, recv).await.1
        };

        let (dialer_got, listener_got) = block_on(join(dialer, listener));

        assert_eq!(dialer_got, vec!["listener-candidate-1"]);
        assert_eq!(
            listener_got,
            vec!["dialer-candidate-1", "dialer-candidate-2"]
        );
    }

    /// Candidates the listener trickles before its answer must not be lost by the dialer.
    #[test]
    fn candidates_trickled_before_answer_are_buffered() {
        let (dialer_io, listener_io) = futures_ringbuf::Endpoint::pair(4096, 4096);

        let listener = async move {
            let mut framed = Framed::new(listener_io, Codec::default());

            match framed.next().await.unwrap().unwrap() {
                Message::Offer(_) => {}
                other => panic!("expected offer, got {other:?}"),
            }

            framed
                .send(Message::IceCandidate(Some("early-candidate".to_owned())))
                .await
                .unwrap();
            framed
                .send(Message::Answer("v=0 answer".to_owned()))
                .await
                .unwrap();
            framed.send(Message::IceCandidate(None)).await.unwrap();
            framed.close().await.unwrap();
        };

        let dialer = async move {
            let (answer, mut exchange) = Signaling::new(dialer_io)
                .send_offer("v=0 offer".to_owned())
                .await
                .unwrap();
            assert_eq!(answer, "v=0 answer");

            assert_eq!(
                exchange.next_candidate().await.unwrap(),
                Some("early-candidate".to_owned())
            );
            assert_eq!(exchange.next_candidate().await.unwrap(), None);
        };

        block_on(join(dialer, listener));
    }

    /// A listener must reject a stream that does not start with an offer.
    #[test]
    fn listener_rejects_non_offer_first_message() {
        let (dialer_io, listener_io) = futures_ringbuf::Endpoint::pair(4096, 4096);

        let bad_dialer = async move {
            let mut framed = Framed::new(dialer_io, Codec::default());
            framed
                .send(Message::Answer("v=0".to_owned()))
                .await
                .unwrap();
        };

        let listener = async move {
            let result = Signaling::new(listener_io).recv_offer().await;
            assert!(matches!(result, Err(Error::Protocol(_))));
        };

        block_on(join(bad_dialer, listener));
    }
}
