use std::{str::FromStr, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use futures::{FutureExt, StreamExt};
use libp2p::{
    Multiaddr, identify,
    identity::Keypair,
    multiaddr::Protocol,
    ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent, behaviour::toggle::Toggle},
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

mod arch;
#[cfg(not(target_arch = "wasm32"))]
pub mod relay_server;

use arch::{Instant, RedisClient, build_swarm, init_logger, webrtc_private};

#[allow(clippy::too_many_arguments)]
pub async fn run_test(
    transport: &str,
    ip: &str,
    is_dialer: bool,
    test_timeout_seconds: u64,
    redis_addr: &str,
    sec_protocol: Option<String>,
    muxer: Option<String>,
    relay_addr: Option<String>,
    ice_server: Option<String>,
) -> Result<Report> {
    init_logger();

    let test_timeout = Duration::from_secs(test_timeout_seconds);
    let transport = transport.parse().context("Couldn't parse transport")?;
    let sec_protocol = sec_protocol
        .map(|sec_protocol| {
            sec_protocol
                .parse()
                .context("Couldn't parse security protocol")
        })
        .transpose()?;
    let muxer = muxer
        .map(|sec_protocol| {
            sec_protocol
                .parse()
                .context("Couldn't parse muxer protocol")
        })
        .transpose()?;

    let redis_client = RedisClient::new(redis_addr).context("Could not connect to redis")?;

    // Build the transport from the passed ENV var.
    let (mut swarm, local_addr) =
        build_swarm(ip, transport, sec_protocol, muxer, ice_server, build_behaviour).await?;

    tracing::info!(local_peer=%swarm.local_peer_id(), "Running ping test");

    // See https://github.com/libp2p/rust-libp2p/issues/4071.
    #[cfg(not(target_arch = "wasm32"))]
    let maybe_id = if transport == Transport::WebRtcDirect {
        Some(swarm.listen_on(local_addr.parse()?)?)
    } else {
        None
    };
    #[cfg(target_arch = "wasm32")]
    let maybe_id = None;

    // Run a ping interop test. Based on `is_dialer`, either dial the address
    // retrieved via `listenAddr` key over the redis connection. Or wait to be pinged and have
    // `dialerDone` key ready on the redis connection.
    match is_dialer {
        true => {
            let result: Vec<String> = redis_client
                .blpop("listenerAddr", test_timeout.as_secs())
                .await?;
            let other = result
                .get(1)
                .context("Failed to wait for listener to be ready")?;

            let handshake_start = Instant::now();

            swarm.dial(other.parse::<Multiaddr>()?)?;
            tracing::info!(listener=%other, "Test instance, dialing multiaddress");

            // A `/webrtc` dial also establishes a relayed connection for signalling, and
            // ping runs on both. Only a ping on the direct connection proves the
            // transport works, so wait for it and filter ping results by connection.
            let webrtc_connection = if transport == Transport::Webrtc {
                let connection_id = loop {
                    match swarm.next().await {
                        Some(SwarmEvent::ConnectionEstablished {
                            connection_id,
                            endpoint,
                            ..
                        }) if endpoint
                            .get_remote_address()
                            .iter()
                            .any(|protocol| protocol == Protocol::WebRTC) =>
                        {
                            break connection_id;
                        }
                        _ => continue,
                    }
                };
                tracing::info!("Direct /webrtc connection established");
                Some(connection_id)
            } else {
                None
            };

            let rtt = loop {
                if let Some(SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event {
                    connection,
                    result: Ok(rtt),
                    ..
                }))) = swarm.next().await
                {
                    if webrtc_connection.is_some_and(|id| id != connection) {
                        continue;
                    }
                    tracing::info!(?rtt, "Ping successful");
                    break rtt.as_micros() as f32 / 1000.;
                }
            };

            let handshake_plus_ping = handshake_start.elapsed().as_micros() as f32 / 1000.;
            Ok(Report {
                handshake_plus_one_rtt_millis: handshake_plus_ping,
                ping_rtt_millis: rtt,
            })
        }
        false if transport == Transport::Webrtc => {
            // A `/webrtc` listener is reachable through a relay: reserve a slot, accept
            // incoming signalling streams and advertise the relayed webrtc multiaddr.
            let relay_addr: Multiaddr = relay_addr
                .context("the webrtc listener requires a relay address")?
                .parse()?;
            ensure!(
                matches!(relay_addr.iter().last(), Some(Protocol::P2p(_))),
                "the relay address must end in /p2p/<relay-peer-id>"
            );

            swarm.listen_on(relay_addr.clone().with(Protocol::P2pCircuit))?;

            loop {
                match swarm.next().await {
                    Some(SwarmEvent::Behaviour(BehaviourEvent::RelayClient(
                        relay::client::Event::ReservationReqAccepted { .. },
                    ))) => break,
                    Some(event) => tracing::debug!("{event:?}"),
                    None => bail!("Swarm terminated while waiting for a relay reservation"),
                }
            }

            swarm.listen_on("/webrtc".parse()?)?;

            let advertised = relay_addr
                .with(Protocol::P2pCircuit)
                .with(Protocol::WebRTC)
                .with(Protocol::P2p(*swarm.local_peer_id()));
            tracing::info!(
                address=%advertised,
                "Test instance, listening for incoming connections on address"
            );
            redis_client
                .rpush("listenerAddr", advertised.to_string())
                .await?;

            // Drive the swarm until the test runner kills us.
            futures::future::select(
                async move {
                    loop {
                        let event = swarm.next().await.unwrap();

                        tracing::debug!("{event:?}");
                    }
                }
                .boxed(),
                arch::sleep(test_timeout),
            )
            .await;

            // The loop never ends so if we get here, we hit the timeout.
            bail!("Test should have been killed by the test runner!");
        }
        false => {
            // Listen if we haven't done so already.
            // This is a hack until https://github.com/libp2p/rust-libp2p/issues/4071 is fixed at which point we can do this unconditionally here.
            let id = match maybe_id {
                None => swarm.listen_on(local_addr.parse()?)?,
                Some(id) => id,
            };

            tracing::info!(
                address=%local_addr,
                "Test instance, listening for incoming connections on address"
            );

            loop {
                if let Some(SwarmEvent::NewListenAddr {
                    listener_id,
                    address,
                }) = swarm.next().await
                {
                    if address.to_string().contains("127.0.0.1") {
                        continue;
                    }
                    if listener_id == id {
                        let ma = format!("{address}/p2p/{}", swarm.local_peer_id());
                        redis_client.rpush("listenerAddr", ma.clone()).await?;
                        break;
                    }
                }
            }

            // Drive Swarm while we await for `dialerDone` to be ready.
            futures::future::select(
                async move {
                    loop {
                        let event = swarm.next().await.unwrap();

                        tracing::debug!("{event:?}");
                    }
                }
                .boxed(),
                arch::sleep(test_timeout),
            )
            .await;

            // The loop never ends so if we get here, we hit the timeout.
            bail!("Test should have been killed by the test runner!");
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn run_test_wasm(
    transport: &str,
    ip: &str,
    is_dialer: bool,
    test_timeout_secs: u64,
    base_url: &str,
    sec_protocol: Option<String>,
    muxer: Option<String>,
    relay_addr: Option<String>,
    ice_server: Option<String>,
) -> Result<(), JsValue> {
    let result = run_test(
        transport,
        ip,
        is_dialer,
        test_timeout_secs,
        base_url,
        sec_protocol,
        muxer,
        relay_addr,
        ice_server,
    )
    .await;
    tracing::info!(?result, "Sending test result");
    reqwest::Client::new()
        .post(&format!("http://{}/results", base_url))
        .json(&result.map_err(|e| e.to_string()))
        .send()
        .await?
        .error_for_status()
        .map_err(|e| format!("Sending test result failed: {e}"))?;

    Ok(())
}

/// A request to redis proxy that will pop the value from the list
/// and will wait for it being inserted until a timeout is reached.
#[derive(serde::Deserialize, serde::Serialize)]
pub struct BlpopRequest {
    pub key: String,
    pub timeout: u64,
}

/// A request to redis proxy that will push the value onto the list. A browser
/// listener uses it to publish its advertised multiaddr.
#[derive(serde::Deserialize, serde::Serialize)]
pub struct RpushRequest {
    pub key: String,
    pub value: String,
}

/// A report generated by the test
#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Report {
    #[serde(rename = "handshakePlusOneRTTMillis")]
    handshake_plus_one_rtt_millis: f32,
    #[serde(rename = "pingRTTMilllis")]
    ping_rtt_millis: f32,
}

/// Supported transports by rust-libp2p.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Transport {
    Tcp,
    QuicV1,
    WebRtcDirect,
    Webrtc,
    Ws,
    Webtransport,
}

impl FromStr for Transport {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "tcp" => Self::Tcp,
            "quic-v1" => Self::QuicV1,
            "webrtc-direct" => Self::WebRtcDirect,
            "webrtc" => Self::Webrtc,
            "ws" => Self::Ws,
            "webtransport" => Self::Webtransport,
            other => bail!("unknown transport {other}"),
        })
    }
}

/// Supported stream multiplexers by rust-libp2p.
#[derive(Clone, Debug)]
pub enum Muxer {
    Mplex,
    Yamux,
}

impl FromStr for Muxer {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "mplex" => Self::Mplex,
            "yamux" => Self::Yamux,
            other => bail!("unknown muxer {other}"),
        })
    }
}

/// Supported security protocols by rust-libp2p.
#[derive(Clone, Debug)]
pub enum SecProtocol {
    Noise,
    Tls,
}

impl FromStr for SecProtocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "noise" => Self::Noise,
            "tls" => Self::Tls,
            other => bail!("unknown security protocol {other}"),
        })
    }
}

#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    relay_client: Toggle<relay::client::Behaviour>,
    signaling: Toggle<webrtc_private::Behaviour>,
}

/// The behaviours only a `/webrtc` swarm carries, paired with its transports.
pub(crate) struct WebrtcBehaviours {
    pub(crate) relay_client: relay::client::Behaviour,
    pub(crate) signaling: webrtc_private::Behaviour,
}

pub(crate) fn build_behaviour(key: &Keypair, webrtc: Option<WebrtcBehaviours>) -> Behaviour {
    let (relay_client, signaling) = match webrtc {
        Some(behaviours) => (Some(behaviours.relay_client), Some(behaviours.signaling)),
        None => (None, None),
    };

    Behaviour {
        ping: ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(1))),
        // Need to include identify until https://github.com/status-im/nim-libp2p/issues/924 is resolved.
        identify: identify::Behaviour::new(identify::Config::new(
            "/interop-tests".to_owned(),
            key.public(),
        )),
        relay_client: Toggle::from(relay_client),
        signaling: Toggle::from(signaling),
    }
}
