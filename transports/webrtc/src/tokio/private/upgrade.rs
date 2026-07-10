//! Offer, answer and trickle-ICE exchange for private-to-private WebRTC connections.
//!
//! Unlike the webrtc-direct handshake, both sides run a full ICE agent and the DTLS
//! handshake verifies the certificate fingerprint carried in the genuine remote SDP, so
//! no further authentication happens on the established connection.

use std::{sync::Arc, time::Duration};

use futures::{
    channel::{mpsc, oneshot},
    future::{self, Either},
    pin_mut,
    prelude::*,
};
use futures_timer::Delay;
use libp2p_webrtc_utils::signaling::{self, SignalingStream};
use webrtc::{
    api::{APIBuilder, setting_engine::SettingEngine},
    data_channel::{RTCDataChannel, data_channel_init::RTCDataChannelInit},
    ice_transport::{ice_candidate::RTCIceCandidateInit, ice_server::RTCIceServer},
    peer_connection::{
        RTCPeerConnection, configuration::RTCConfiguration,
        sdp::session_description::RTCSessionDescription,
    },
};

use super::Config;
use crate::tokio::{Connection, error::Error};

/// Establishes the connection for a dialer: sends the offer, applies the answer and
/// trickles ICE candidates until the connection is up.
pub(crate) async fn outbound(
    signaling: SignalingStream,
    config: &Config,
) -> Result<Connection, Error> {
    let peer_connection = new_peer_connection(config).await?;

    let handshake = async {
        let candidates = register_candidate_handler(&peer_connection);
        let (init_channel, ready) = create_init_channel(&peer_connection).await?;

        let offer = peer_connection.create_offer(None).await?;
        tracing::debug!(offer=%offer.sdp, "created SDP offer for outbound connection");
        // Setting the local description starts candidate gathering.
        peer_connection.set_local_description(offer.clone()).await?;

        let (answer_sdp, exchange) = signaling.send_offer(offer.sdp).await?;
        tracing::debug!(answer=%answer_sdp, "received SDP answer for outbound connection");
        let answer = RTCSessionDescription::answer(answer_sdp)?;
        peer_connection.set_remote_description(answer).await?;

        exchange_candidates(&peer_connection, exchange, candidates, ready).await?;

        // Free stream id 0 for the muxer before handing the connection over.
        init_channel.close().await?;

        Ok(())
    };

    complete(&peer_connection, handshake, config.handshake_timeout).await?;

    Ok(Connection::new(peer_connection).await)
}

/// Establishes the connection for a listener: applies the offer, sends the answer and
/// trickles ICE candidates until the connection is up.
pub(crate) async fn inbound(
    signaling: SignalingStream,
    config: &Config,
) -> Result<Connection, Error> {
    let peer_connection = new_peer_connection(config).await?;

    let handshake = async {
        let candidates = register_candidate_handler(&peer_connection);
        let (init_channel, ready) = create_init_channel(&peer_connection).await?;

        let (offer_sdp, pending_answer) = signaling.recv_offer().await?;
        tracing::debug!(offer=%offer_sdp, "received SDP offer for inbound connection");
        let offer = RTCSessionDescription::offer(offer_sdp)?;
        peer_connection.set_remote_description(offer).await?;

        let answer = peer_connection.create_answer(None).await?;
        tracing::debug!(answer=%answer.sdp, "created SDP answer for inbound connection");
        // Setting the local description starts candidate gathering.
        peer_connection
            .set_local_description(answer.clone())
            .await?;
        let exchange = pending_answer.send_answer(answer.sdp).await?;

        exchange_candidates(&peer_connection, exchange, candidates, ready).await?;

        init_channel.close().await?;

        Ok(())
    };

    complete(&peer_connection, handshake, config.handshake_timeout).await?;

    Ok(Connection::new(peer_connection).await)
}

/// Runs `handshake` against `timeout`, closing the peer connection on failure.
async fn complete(
    peer_connection: &RTCPeerConnection,
    handshake: impl Future<Output = Result<(), Error>>,
    timeout: Duration,
) -> Result<(), Error> {
    pin_mut!(handshake);

    let result = match future::select(handshake, Delay::new(timeout)).await {
        Either::Left((result, _)) => result,
        Either::Right(((), _)) => Err(Error::HandshakeTimeout),
    };

    if result.is_err()
        && let Err(error) = peer_connection.close().await
    {
        tracing::debug!(%error, "Failed to close WebRTC peer connection");
    }

    result
}

async fn new_peer_connection(config: &Config) -> Result<RTCPeerConnection, Error> {
    let mut setting_engine = SettingEngine::default();
    setting_engine.detach_data_channels();

    let ice_servers = if config.ice_servers.is_empty() {
        Vec::new()
    } else {
        vec![RTCIceServer {
            urls: config.ice_servers.clone(),
            ..RTCIceServer::default()
        }]
    };

    // No certificate is configured: an ephemeral one is generated per connection and
    // its fingerprint is exchanged in the SDP.
    let connection = APIBuilder::new()
        .with_setting_engine(setting_engine)
        .build()
        .new_peer_connection(RTCConfiguration {
            ice_servers,
            ..RTCConfiguration::default()
        })
        .await?;

    Ok(connection)
}

/// Forwards local ICE candidates into a channel, `None` marking the end of candidates.
fn register_candidate_handler(
    peer_connection: &RTCPeerConnection,
) -> mpsc::Receiver<Option<String>> {
    // Each cloned sender gets a guaranteed slot, so sends never block the ICE agent.
    let (sender, receiver) = mpsc::channel(0);

    peer_connection.on_ice_candidate(Box::new(move |candidate| {
        let mut sender = sender.clone();

        Box::pin(async move {
            let message = match candidate {
                Some(candidate) => match candidate.to_json() {
                    Ok(init) => match serde_json::to_string(&init) {
                        Ok(json) => Some(json),
                        Err(error) => {
                            tracing::debug!(%error, "Failed to serialize local ICE candidate");
                            return;
                        }
                    },
                    Err(error) => {
                        tracing::debug!(%error, "Failed to convert local ICE candidate");
                        return;
                    }
                },
                None => None,
            };

            let _ = sender.send(message).await;
        })
    }));

    receiver
}

/// Creates the negotiated data channel both sides use to detect that the connection is
/// up, and a receiver resolving once it opens.
async fn create_init_channel(
    peer_connection: &RTCPeerConnection,
) -> Result<(Arc<RTCDataChannel>, oneshot::Receiver<()>), Error> {
    let channel = peer_connection
        .create_data_channel(
            "init",
            Some(RTCDataChannelInit {
                negotiated: Some(0),
                ..RTCDataChannelInit::default()
            }),
        )
        .await?;

    let (sender, receiver) = oneshot::channel();
    channel.on_open(Box::new(move || {
        let _ = sender.send(());
        Box::pin(async {})
    }));

    Ok((channel, receiver))
}

/// Trickles candidates in both directions until the connection is established.
///
/// Signalling failures during the trickle are not fatal by themselves: the outcome is
/// decided by the connection coming up before the caller's timeout expires.
async fn exchange_candidates<S>(
    peer_connection: &RTCPeerConnection,
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
            if let Err(error) = peer_connection
                .add_ice_candidate(parse_candidate(&candidate))
                .await
            {
                tracing::debug!(%error, "Failed to apply remote ICE candidate");
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
                    .map_err(|_| Error::Internal("init data channel closed before opening".to_owned()));
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
fn parse_candidate(data: &str) -> RTCIceCandidateInit {
    serde_json::from_str(data).unwrap_or_else(|_| RTCIceCandidateInit {
        candidate: data.to_owned(),
        ..RTCIceCandidateInit::default()
    })
}
