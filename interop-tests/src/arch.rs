// Native re-exports
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use libp2p_webrtc::tokio::private as webrtc_private;
// Wasm re-exports
#[cfg(target_arch = "wasm32")]
pub(crate) use libp2p_webrtc_websys::private as webrtc_private;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use native::{Instant, RedisClient, build_swarm, init_logger, sleep};
#[cfg(target_arch = "wasm32")]
pub(crate) use wasm::{Instant, RedisClient, build_swarm, init_logger, sleep};

#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod native {
    use std::time::Duration;

    use anyhow::{Context, Result, bail};
    use futures::{FutureExt, future::BoxFuture};
    use libp2p::{
        Transport as _,
        core::{muxing::StreamMuxerBox, upgrade::Version},
        identity::Keypair,
        noise, relay,
        swarm::{self, NetworkBehaviour, Swarm},
        tcp, tls, websocket, yamux,
    };
    use libp2p_mplex as mplex;
    use libp2p_webrtc as webrtc;
    use redis::AsyncCommands;
    use tracing_subscriber::EnvFilter;

    use super::webrtc_private;
    use crate::{Muxer, SecProtocol, Transport, WebrtcBehaviours};

    pub(crate) type Instant = std::time::Instant;

    pub(crate) fn init_logger() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();
    }

    pub(crate) fn sleep(duration: Duration) -> BoxFuture<'static, ()> {
        tokio::time::sleep(duration).boxed()
    }

    pub(crate) async fn build_swarm<B: NetworkBehaviour>(
        ip: &str,
        transport: Transport,
        sec_protocol: Option<SecProtocol>,
        muxer: Option<Muxer>,
        behaviour_constructor: impl FnOnce(&Keypair, Option<WebrtcBehaviours>) -> B,
    ) -> Result<(Swarm<B>, String)> {
        let (swarm, addr) = match (transport, sec_protocol, muxer) {
            (Transport::QuicV1, None, None) => (
                libp2p::SwarmBuilder::with_new_identity()
                    .with_tokio()
                    .with_quic()
                    .with_behaviour(|key| behaviour_constructor(key, None))?
                    .build(),
                format!("/ip4/{ip}/udp/0/quic-v1"),
            ),
            (Transport::Tcp, Some(SecProtocol::Tls), Some(Muxer::Mplex)) => (
                libp2p::SwarmBuilder::with_new_identity()
                    .with_tokio()
                    .with_tcp(
                        tcp::Config::default(),
                        tls::Config::new,
                        mplex::Config::default,
                    )?
                    .with_behaviour(|key| behaviour_constructor(key, None))?
                    .build(),
                format!("/ip4/{ip}/tcp/0"),
            ),
            (Transport::Tcp, Some(SecProtocol::Tls), Some(Muxer::Yamux)) => (
                libp2p::SwarmBuilder::with_new_identity()
                    .with_tokio()
                    .with_tcp(
                        tcp::Config::default(),
                        tls::Config::new,
                        yamux::Config::default,
                    )?
                    .with_behaviour(|key| behaviour_constructor(key, None))?
                    .build(),
                format!("/ip4/{ip}/tcp/0"),
            ),
            (Transport::Tcp, Some(SecProtocol::Noise), Some(Muxer::Mplex)) => (
                libp2p::SwarmBuilder::with_new_identity()
                    .with_tokio()
                    .with_tcp(
                        tcp::Config::default(),
                        noise::Config::new,
                        mplex::Config::default,
                    )?
                    .with_behaviour(|key| behaviour_constructor(key, None))?
                    .build(),
                format!("/ip4/{ip}/tcp/0"),
            ),
            (Transport::Tcp, Some(SecProtocol::Noise), Some(Muxer::Yamux)) => (
                libp2p::SwarmBuilder::with_new_identity()
                    .with_tokio()
                    .with_tcp(
                        tcp::Config::default(),
                        noise::Config::new,
                        yamux::Config::default,
                    )?
                    .with_behaviour(|key| behaviour_constructor(key, None))?
                    .build(),
                format!("/ip4/{ip}/tcp/0"),
            ),
            (Transport::Ws, Some(SecProtocol::Tls), Some(Muxer::Mplex)) => (
                libp2p::SwarmBuilder::with_new_identity()
                    .with_tokio()
                    .with_websocket(tls::Config::new, mplex::Config::default)
                    .await?
                    .with_behaviour(|key| behaviour_constructor(key, None))?
                    .build(),
                format!("/ip4/{ip}/tcp/0/ws"),
            ),
            (Transport::Ws, Some(SecProtocol::Tls), Some(Muxer::Yamux)) => (
                libp2p::SwarmBuilder::with_new_identity()
                    .with_tokio()
                    .with_websocket(tls::Config::new, yamux::Config::default)
                    .await?
                    .with_behaviour(|key| behaviour_constructor(key, None))?
                    .build(),
                format!("/ip4/{ip}/tcp/0/ws"),
            ),
            (Transport::Ws, Some(SecProtocol::Noise), Some(Muxer::Mplex)) => (
                libp2p::SwarmBuilder::with_new_identity()
                    .with_tokio()
                    .with_websocket(noise::Config::new, mplex::Config::default)
                    .await?
                    .with_behaviour(|key| behaviour_constructor(key, None))?
                    .build(),
                format!("/ip4/{ip}/tcp/0/ws"),
            ),
            (Transport::Ws, Some(SecProtocol::Noise), Some(Muxer::Yamux)) => (
                libp2p::SwarmBuilder::with_new_identity()
                    .with_tokio()
                    .with_websocket(noise::Config::new, yamux::Config::default)
                    .await?
                    .with_behaviour(|key| behaviour_constructor(key, None))?
                    .build(),
                format!("/ip4/{ip}/tcp/0/ws"),
            ),
            (Transport::WebRtcDirect, None, None) => (
                libp2p::SwarmBuilder::with_new_identity()
                    .with_tokio()
                    .with_other_transport(|key| {
                        Ok(webrtc::tokio::Transport::new(
                            key.clone(),
                            webrtc::tokio::Certificate::generate(&mut rand::thread_rng())?,
                        ))
                    })?
                    .with_behaviour(|key| behaviour_constructor(key, None))?
                    .build(),
                format!("/ip4/{ip}/udp/0/webrtc-direct"),
            ),
            (Transport::Webrtc, None, None) => {
                // The DTLS stack resolves the process-level rustls crypto provider,
                // which fails when the dependency graph enables more than one backend,
                // so pin one explicitly.
                let _ = rustls::crypto::ring::default_provider().install_default();

                let key = Keypair::generate_ed25519();
                let local_peer_id = key.public().to_peer_id();

                let (relay_transport, relay_client) = relay::client::new(local_peer_id);

                let mut config = webrtc_private::Config::new();
                if let Ok(url) = std::env::var("ice_server") {
                    config = config.with_ice_server(url);
                }
                let (webrtc_transport, signaling) = webrtc_private::new(config);

                // The relay is reached over plain TCP or websockets; the signalling
                // stream then runs on the relayed connection.
                let tcp_transport =
                    tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
                let ws_transport = websocket::Config::new(tcp::tokio::Transport::new(
                    tcp::Config::default().nodelay(true),
                ));

                let relayed_transport = relay_transport
                    .or_transport(ws_transport)
                    .or_transport(tcp_transport)
                    .upgrade(Version::V1)
                    .authenticate(noise::Config::new(&key)?)
                    .multiplex(yamux::Config::default());

                let transport = webrtc_transport
                    .map(|(peer_id, connection), _| (peer_id, StreamMuxerBox::new(connection)))
                    .or_transport(
                        relayed_transport
                            .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer))),
                    )
                    .map(|either_output, _| either_output.into_inner())
                    .boxed();

                let behaviour = behaviour_constructor(
                    &key,
                    Some(WebrtcBehaviours {
                        relay_client,
                        signaling,
                    }),
                );

                (
                    Swarm::new(
                        transport,
                        behaviour,
                        local_peer_id,
                        swarm::Config::with_tokio_executor()
                            .with_idle_connection_timeout(Duration::from_secs(60)),
                    ),
                    "/webrtc".to_owned(),
                )
            }
            (t, s, m) => bail!("Unsupported combination: {t:?} {s:?} {m:?}"),
        };
        Ok((swarm, addr))
    }

    pub(crate) struct RedisClient(redis::Client);

    impl RedisClient {
        pub(crate) fn new(redis_addr: &str) -> Result<Self> {
            Ok(Self(
                redis::Client::open(redis_addr).context("Could not connect to redis")?,
            ))
        }

        pub(crate) async fn blpop(&self, key: &str, timeout: u64) -> Result<Vec<String>> {
            let mut conn = self.0.get_async_connection().await?;
            Ok(conn.blpop(key, timeout as f64).await?)
        }

        pub(crate) async fn rpush(&self, key: &str, value: String) -> Result<()> {
            let mut conn = self.0.get_async_connection().await?;
            conn.rpush(key, value).await.map_err(Into::into)
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) mod wasm {
    use std::time::Duration;

    use anyhow::{Context, Result, bail};
    use futures::future::{BoxFuture, FutureExt};
    use libp2p::{
        Transport as _,
        core::{muxing::StreamMuxerBox, upgrade::Version},
        identity::Keypair,
        noise, relay,
        swarm::{self, NetworkBehaviour, Swarm},
        websocket_websys, webtransport_websys, yamux,
    };
    use libp2p_mplex as mplex;
    use libp2p_webrtc_websys as webrtc_websys;

    use super::webrtc_private;
    use crate::{BlpopRequest, Muxer, RpushRequest, SecProtocol, Transport, WebrtcBehaviours};

    pub(crate) type Instant = web_time::Instant;

    pub(crate) fn init_logger() {
        console_error_panic_hook::set_once();
        wasm_logger::init(wasm_logger::Config::default());
        // libp2p logs via `tracing`, which the `log` shim above does not capture.
        let _ = tracing_wasm::try_set_as_global_default();
    }

    pub(crate) fn sleep(duration: Duration) -> BoxFuture<'static, ()> {
        libp2p_timer::Delay::new(duration).boxed()
    }

    pub(crate) async fn build_swarm<B: NetworkBehaviour>(
        ip: &str,
        transport: Transport,
        sec_protocol: Option<SecProtocol>,
        muxer: Option<Muxer>,
        behaviour_constructor: impl FnOnce(&Keypair, Option<WebrtcBehaviours>) -> B,
    ) -> Result<(Swarm<B>, String)> {
        Ok(match (transport, sec_protocol, muxer) {
            (Transport::Webtransport, None, None) => (
                libp2p::SwarmBuilder::with_new_identity()
                    .with_wasm_bindgen()
                    .with_other_transport(|local_key| {
                        webtransport_websys::Transport::new(webtransport_websys::Config::new(
                            &local_key,
                        ))
                    })?
                    .with_behaviour(|key| behaviour_constructor(key, None))?
                    .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(5)))
                    .build(),
                format!("/ip4/{ip}/udp/0/quic/webtransport"),
            ),
            (Transport::Ws, Some(SecProtocol::Noise), Some(Muxer::Mplex)) => (
                libp2p::SwarmBuilder::with_new_identity()
                    .with_wasm_bindgen()
                    .with_other_transport(|local_key| {
                        Ok(websocket_websys::Transport::default()
                            .upgrade(Version::V1Lazy)
                            .authenticate(
                                noise::Config::new(&local_key)
                                    .context("failed to initialise noise")?,
                            )
                            .multiplex(mplex::Config::new()))
                    })?
                    .with_behaviour(|key| behaviour_constructor(key, None))?
                    .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(5)))
                    .build(),
                format!("/ip4/{ip}/tcp/0/tls/ws"),
            ),
            (Transport::Ws, Some(SecProtocol::Noise), Some(Muxer::Yamux)) => (
                libp2p::SwarmBuilder::with_new_identity()
                    .with_wasm_bindgen()
                    .with_other_transport(|local_key| {
                        Ok(websocket_websys::Transport::default()
                            .upgrade(Version::V1Lazy)
                            .authenticate(
                                noise::Config::new(&local_key)
                                    .context("failed to initialise noise")?,
                            )
                            .multiplex(yamux::Config::default()))
                    })?
                    .with_behaviour(|key| behaviour_constructor(key, None))?
                    .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(5)))
                    .build(),
                format!("/ip4/{ip}/tcp/0/tls/ws"),
            ),
            (Transport::WebRtcDirect, None, None) => (
                libp2p::SwarmBuilder::with_new_identity()
                    .with_wasm_bindgen()
                    .with_other_transport(|local_key| {
                        webrtc_websys::Transport::new(webrtc_websys::Config::new(&local_key))
                    })?
                    .with_behaviour(|key| behaviour_constructor(key, None))?
                    .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(5)))
                    .build(),
                format!("/ip4/{ip}/udp/0/webrtc-direct"),
            ),
            (Transport::Webrtc, None, None) => {
                let key = Keypair::generate_ed25519();
                let local_peer_id = key.public().to_peer_id();

                let (relay_transport, relay_client) = relay::client::new(local_peer_id);
                let (webrtc_transport, signaling) =
                    webrtc_private::new(webrtc_private::Config::new());

                // The relay is reached over websockets; the signalling stream then runs
                // on the relayed connection.
                let relayed_transport = relay_transport
                    .or_transport(websocket_websys::Transport::default())
                    .upgrade(Version::V1)
                    .authenticate(noise::Config::new(&key).context("failed to initialise noise")?)
                    .multiplex(yamux::Config::default());

                let transport = webrtc_transport
                    .map(|(peer_id, connection), _| (peer_id, StreamMuxerBox::new(connection)))
                    .or_transport(
                        relayed_transport
                            .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer))),
                    )
                    .map(|either_output, _| either_output.into_inner())
                    .boxed();

                let behaviour = behaviour_constructor(
                    &key,
                    Some(WebrtcBehaviours {
                        relay_client,
                        signaling,
                    }),
                );

                (
                    Swarm::new(
                        transport,
                        behaviour,
                        local_peer_id,
                        swarm::Config::with_wasm_executor()
                            .with_idle_connection_timeout(Duration::from_secs(60)),
                    ),
                    "/webrtc".to_owned(),
                )
            }
            (t, s, m) => bail!("Unsupported combination: {t:?} {s:?} {m:?}"),
        })
    }

    pub(crate) struct RedisClient(String);

    impl RedisClient {
        pub(crate) fn new(base_url: &str) -> Result<Self> {
            Ok(Self(base_url.to_owned()))
        }

        pub(crate) async fn blpop(&self, key: &str, timeout: u64) -> Result<Vec<String>> {
            let res = reqwest::Client::new()
                .post(&format!("http://{}/blpop", self.0))
                .json(&BlpopRequest {
                    key: key.to_owned(),
                    timeout,
                })
                .send()
                .await?
                .json()
                .await?;
            Ok(res)
        }

        pub(crate) async fn rpush(&self, key: &str, value: String) -> Result<()> {
            reqwest::Client::new()
                .post(format!("http://{}/rpush", self.0))
                .json(&RpushRequest {
                    key: key.to_owned(),
                    value,
                })
                .send()
                .await?
                .error_for_status()?;
            Ok(())
        }
    }
}
