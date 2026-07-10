//! Offer, answer and trickle-ICE exchange for private-to-private WebRTC connections.
//!
//! Unlike the webrtc-direct handshake, no SDP munging happens and the browser's DTLS
//! stack verifies the certificate fingerprint carried in the genuine remote SDP, so no
//! further authentication happens on the established connection.

use std::time::Duration;

use futures::{
    channel::{mpsc, oneshot},
    future::{self, Either},
    pin_mut,
    prelude::*,
};
use libp2p_timer::Delay;
use libp2p_webrtc_utils::signaling::{self, SignalingStream};
use send_wrapper::SendWrapper;
use wasm_bindgen::{JsCast, closure::Closure};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    RtcDataChannel, RtcDataChannelInit, RtcIceCandidateInit, RtcPeerConnectionIceEvent, RtcSdpType,
    RtcSessionDescriptionInit,
};

use super::Config;
use crate::{Connection, Error, connection::RtcPeerConnection};

/// Established connections use the certificate hash algorithm of this fingerprint.
const SHA_256: &str = "sha-256";

/// Establishes the connection for a dialer: sends the offer, applies the answer and
/// trickles ICE candidates until the connection is up.
pub(crate) async fn outbound(
    signaling: SignalingStream,
    config: Config,
) -> Result<Connection, Error> {
    let fut = SendWrapper::new(outbound_inner(signaling, config));
    fut.await
}

async fn outbound_inner(signaling: SignalingStream, config: Config) -> Result<Connection, Error> {
    let peer_connection =
        RtcPeerConnection::new_with_ice_servers(SHA_256.to_owned(), &config.ice_servers).await?;

    let handshake = async {
        let (candidates, _candidate_handler) = register_candidate_handler(&peer_connection);
        // Must be created before the offer for the SDP to contain a data channel.
        let (init_channel, ready) = InitChannel::create(&peer_connection);

        let offer = peer_connection.create_offer().await?;
        tracing::debug!(offer=%offer, "created SDP offer for outbound connection");
        // Setting the local description starts candidate gathering.
        peer_connection
            .set_local_description(session_description(RtcSdpType::Offer, &offer))
            .await?;

        let (answer_sdp, exchange) = signaling.send_offer(offer).await?;
        tracing::debug!(answer=%answer_sdp, "received SDP answer for outbound connection");
        peer_connection
            .set_remote_description(session_description(RtcSdpType::Answer, &answer_sdp))
            .await?;

        exchange_candidates(&peer_connection, exchange, candidates, ready).await?;

        // Free stream id 0 for the muxer before handing the connection over.
        init_channel.close();

        Ok(())
    };

    complete(&peer_connection, handshake, config.handshake_timeout).await?;

    Ok(Connection::new(peer_connection))
}

/// Establishes the connection for a listener: applies the offer, sends the answer and
/// trickles ICE candidates until the connection is up.
pub(crate) async fn inbound(
    signaling: SignalingStream,
    config: Config,
) -> Result<Connection, Error> {
    let fut = SendWrapper::new(inbound_inner(signaling, config));
    fut.await
}

async fn inbound_inner(signaling: SignalingStream, config: Config) -> Result<Connection, Error> {
    let peer_connection =
        RtcPeerConnection::new_with_ice_servers(SHA_256.to_owned(), &config.ice_servers).await?;

    let handshake = async {
        let (candidates, _candidate_handler) = register_candidate_handler(&peer_connection);
        let (init_channel, ready) = InitChannel::create(&peer_connection);

        let (offer_sdp, pending_answer) = signaling.recv_offer().await?;
        tracing::debug!(offer=%offer_sdp, "received SDP offer for inbound connection");
        peer_connection
            .set_remote_description(session_description(RtcSdpType::Offer, &offer_sdp))
            .await?;

        let answer = peer_connection.create_answer().await?;
        tracing::debug!(answer=%answer, "created SDP answer for inbound connection");
        // Setting the local description starts candidate gathering.
        peer_connection
            .set_local_description(session_description(RtcSdpType::Answer, &answer))
            .await?;
        let exchange = pending_answer.send_answer(answer).await?;

        exchange_candidates(&peer_connection, exchange, candidates, ready).await?;

        init_channel.close();

        Ok(())
    };

    complete(&peer_connection, handshake, config.handshake_timeout).await?;

    Ok(Connection::new(peer_connection))
}

/// Runs `handshake` against `timeout`, closing the peer connection on failure.
async fn complete(
    peer_connection: &RtcPeerConnection,
    handshake: impl Future<Output = Result<(), Error>>,
    timeout: Duration,
) -> Result<(), Error> {
    pin_mut!(handshake);

    let result = match future::select(handshake, Delay::new(timeout)).await {
        Either::Left((result, _)) => result,
        Either::Right(((), _)) => Err(Error::HandshakeTimeout),
    };

    if result.is_err() {
        peer_connection.inner().close();
    }

    result
}

fn session_description(sdp_type: RtcSdpType, sdp: &str) -> RtcSessionDescriptionInit {
    let description = RtcSessionDescriptionInit::new(sdp_type);
    description.set_sdp(sdp);
    description
}

/// Forwards local ICE candidates as JSON into a channel, `None` marking the end of
/// candidates.
///
/// The returned guard unregisters the browser callback on drop so late events never hit
/// a freed closure.
fn register_candidate_handler(
    peer_connection: &RtcPeerConnection,
) -> (mpsc::Receiver<Option<String>>, CandidateHandlerGuard) {
    // Each cloned sender gets a guaranteed slot, so candidates are never dropped.
    let (sender, receiver) = mpsc::channel(0);

    let closure = Closure::new(move |event: RtcPeerConnectionIceEvent| {
        let mut sender = sender.clone();

        let message = match event.candidate() {
            Some(candidate) => {
                match js_sys::JSON::stringify(&candidate.to_json())
                    .ok()
                    .and_then(|json| json.as_string())
                {
                    Some(json) => Some(json),
                    None => {
                        tracing::debug!("Failed to serialize local ICE candidate");
                        return;
                    }
                }
            }
            None => None,
        };

        if let Err(error) = sender.try_send(message) {
            tracing::debug!(%error, "Dropping local ICE candidate");
        }
    });

    let connection = peer_connection.inner().clone();
    connection.set_onicecandidate(Some(closure.as_ref().unchecked_ref()));

    (
        receiver,
        CandidateHandlerGuard {
            connection,
            _closure: closure,
        },
    )
}

struct CandidateHandlerGuard {
    connection: web_sys::RtcPeerConnection,
    _closure: Closure<dyn FnMut(RtcPeerConnectionIceEvent)>,
}

impl Drop for CandidateHandlerGuard {
    fn drop(&mut self) {
        self.connection.set_onicecandidate(None);
    }
}

/// The negotiated data channel both sides use to detect that the connection is up.
///
/// Unregisters the browser callback on drop so late events never hit a freed closure.
struct InitChannel {
    channel: RtcDataChannel,
    _closure: Closure<dyn FnMut()>,
}

impl InitChannel {
    fn create(peer_connection: &RtcPeerConnection) -> (Self, oneshot::Receiver<()>) {
        let options = RtcDataChannelInit::new();
        options.set_negotiated(true);
        options.set_id(0);

        let channel = peer_connection
            .inner()
            .create_data_channel_with_data_channel_dict("init", &options);

        let (sender, receiver) = oneshot::channel();
        let mut sender = Some(sender);
        let closure = Closure::new(move || {
            if let Some(sender) = sender.take() {
                let _ = sender.send(());
            }
        });
        channel.set_onopen(Some(closure.as_ref().unchecked_ref()));

        (
            Self {
                channel,
                _closure: closure,
            },
            receiver,
        )
    }

    fn close(self) {
        self.channel.close();
    }
}

impl Drop for InitChannel {
    fn drop(&mut self) {
        self.channel.set_onopen(None);
    }
}

/// Trickles candidates in both directions until the connection is established.
///
/// Signalling failures during the trickle are not fatal by themselves: the outcome is
/// decided by the connection coming up before the caller's timeout expires.
async fn exchange_candidates<S>(
    peer_connection: &RtcPeerConnection,
    exchange: signaling::CandidateExchange<S>,
    mut local_candidates: mpsc::Receiver<Option<String>>,
    ready: oneshot::Receiver<()>,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut sender, mut receiver) = exchange.split();

    let forward_local = async move {
        while let Some(candidate) = local_candidates.next().await {
            match candidate {
                Some(candidate) => sender.send_candidate(candidate).await?,
                None => {
                    sender.send_end_of_candidates().await?;
                    break;
                }
            }
        }

        Ok::<_, signaling::Error>(())
    }
    .fuse();

    let apply_remote = async {
        while let Some(candidate) = receiver.next_candidate().await? {
            tracing::trace!(%candidate, "received remote ICE candidate");
            if let Err(error) = JsFuture::from(
                peer_connection
                    .inner()
                    .add_ice_candidate_with_opt_rtc_ice_candidate_init(Some(&parse_candidate(
                        &candidate,
                    ))),
            )
            .await
            {
                tracing::debug!(?error, "Failed to apply remote ICE candidate");
            }
        }

        Ok::<_, signaling::Error>(())
    }
    .fuse();

    let ready = ready.fuse();
    pin_mut!(forward_local, apply_remote, ready);

    loop {
        futures::select! {
            result = ready => {
                return result
                    .map_err(|_| Error::Connection("init data channel closed before opening".to_owned()));
            }
            result = forward_local => {
                if let Err(error) = result {
                    tracing::debug!(%error, "Failed to trickle local ICE candidates");
                }
            }
            result = apply_remote => {
                if let Err(error) = result {
                    tracing::debug!(%error, "Failed to receive remote ICE candidates");
                }
            }
        }
    }
}

/// Parses a trickled candidate, either candidate init JSON or a bare candidate line.
fn parse_candidate(data: &str) -> RtcIceCandidateInit {
    match js_sys::JSON::parse(data) {
        Ok(value) if value.is_object() => value.unchecked_into(),
        _ => RtcIceCandidateInit::new(data),
    }
}
