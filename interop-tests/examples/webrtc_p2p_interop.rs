//! Standalone private-to-private `/webrtc` interop binary.
//!
//! Two roles, selected by the `MODE` env var or the first CLI argument:
//!
//! - `listener`: runs an in-process Circuit Relay v2 server on
//!   `/ip4/0.0.0.0/tcp/<RELAY_PORT>/ws` and, as a second swarm, a `/webrtc` listener
//!   that reserves a slot on that relay. The full dialable address
//!   `<relay-ws-addr>/p2p/<relay-id>/p2p-circuit/webrtc/p2p/<listener-id>` is written
//!   to the file given by `COORD_FILE` and printed to stdout. The relay advertises the
//!   address from `EXTERNAL_IP` (IP or DNS name), never loopback, so peers in other
//!   containers can reach it.
//! - `dialer`: polls `COORD_FILE` for the address, dials it, waits for a
//!   `ConnectionEstablished` whose remote address contains `/webrtc`, and for a
//!   successful ping on that direct connection. Prints `INTEROP_OK` and exits 0 on
//!   success, `INTEROP_FAIL: <reason>` and exits 1 otherwise.
//!
//! Environment variables:
//!
//! - `MODE`: `listener` or `dialer` (fallback when no CLI argument is given).
//! - `COORD_FILE`: path used to hand the dial address over (default
//!   `/coord/dial_addr`), typically a shared docker volume.
//! - `EXTERNAL_IP`: the address the relay advertises (default `127.0.0.1`).
//! - `RELAY_PORT`: fixed websocket port of the relay (default `4455`).
//! - `TEST_TIMEOUT_SECS`: overall dialer timeout and listener setup timeout
//!   (default `180`).
//! - `ICE_SERVER`: optional STUN/TURN url passed to the webrtc transport.
//! - `RUST_LOG`: standard `tracing` filter for verbose diagnostics.
//!
//! The relayed hop uses noise + yamux over websockets/TCP, exactly like
//! `interop-tests/src/arch.rs`; the direct connection is the private-to-private
//! `/webrtc` transport from `libp2p_webrtc::tokio::private`.

use std::{net::IpAddr, path::PathBuf, process::exit, time::Duration};

use anyhow::{Context, Result, bail};
use futures::StreamExt;
use libp2p::{
    Multiaddr, Swarm, SwarmBuilder, Transport as _,
    core::{muxing::StreamMuxerBox, upgrade::Version},
    dns, identify,
    identity::Keypair,
    multiaddr::Protocol,
    noise, ping, relay,
    swarm::{self, NetworkBehaviour, SwarmEvent},
    tcp, websocket, yamux,
};
use libp2p_webrtc::tokio::private as webrtc_private;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    // The DTLS stack resolves the process-level rustls crypto provider, which fails
    // when the dependency graph enables more than one backend, so pin one explicitly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = Config::from_env()?;
    tracing::info!(
        ?config,
        "Starting webrtc private-to-private interop instance"
    );

    match config.mode {
        Mode::Listener => run_listener(config).await,
        Mode::Dialer => {
            match tokio::time::timeout(config.test_timeout, run_dialer(&config)).await {
                Ok(Ok(rtt)) => {
                    println!("INTEROP_OK rtt_ms={}", rtt.as_micros() as f64 / 1000.0);
                    exit(0);
                }
                Ok(Err(e)) => {
                    println!("INTEROP_FAIL: {e:#}");
                    exit(1);
                }
                Err(_) => {
                    println!(
                        "INTEROP_FAIL: timed out after {}s",
                        config.test_timeout.as_secs()
                    );
                    exit(1);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    Listener,
    Dialer,
}

#[derive(Debug)]
struct Config {
    mode: Mode,
    coord_file: PathBuf,
    external_ip: String,
    relay_port: u16,
    test_timeout: Duration,
    ice_server: Option<String>,
}

impl Config {
    fn from_env() -> Result<Self> {
        let mode = std::env::args()
            .nth(1)
            .or_else(|| std::env::var("MODE").ok())
            .context("pass a mode as the first argument or via MODE: listener | dialer")?;
        let mode = match mode.trim_start_matches("--").to_ascii_lowercase().as_str() {
            "listener" | "listen" => Mode::Listener,
            "dialer" | "dial" => Mode::Dialer,
            other => bail!("unknown mode {other:?}, expected listener | dialer"),
        };

        Ok(Self {
            mode,
            coord_file: std::env::var("COORD_FILE")
                .unwrap_or_else(|_| "/coord/dial_addr".to_owned())
                .into(),
            external_ip: std::env::var("EXTERNAL_IP").unwrap_or_else(|_| "127.0.0.1".to_owned()),
            relay_port: std::env::var("RELAY_PORT")
                .unwrap_or_else(|_| "4455".to_owned())
                .parse()
                .context("RELAY_PORT must be a port number")?,
            test_timeout: Duration::from_secs(
                std::env::var("TEST_TIMEOUT_SECS")
                    .unwrap_or_else(|_| "180".to_owned())
                    .parse()
                    .context("TEST_TIMEOUT_SECS must be an integer")?,
            ),
            ice_server: std::env::var("ICE_SERVER").ok(),
        })
    }
}

#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    relay: relay::Behaviour,
    identify: identify::Behaviour,
}

#[derive(NetworkBehaviour)]
struct ClientBehaviour {
    relay_client: relay::client::Behaviour,
    signaling: webrtc_private::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
}

/// Runs the relay server swarm plus the `/webrtc` listener swarm in one process.
async fn run_listener(config: Config) -> Result<()> {
    let relay_addr = spawn_relay(&config).await?;
    tracing::info!(relay=%relay_addr, "Relay up, starting /webrtc listener");

    let mut swarm = build_client(&config)?;
    let listener_peer_id = *swarm.local_peer_id();

    // Reserve a slot on the relay; the reservation carries the signalling channel for
    // incoming `/webrtc` connections.
    swarm.listen_on(relay_addr.clone().with(Protocol::P2pCircuit))?;

    let reservation = async {
        loop {
            match swarm.next().await {
                Some(SwarmEvent::Behaviour(ClientBehaviourEvent::RelayClient(
                    relay::client::Event::ReservationReqAccepted { .. },
                ))) => break Ok(()),
                Some(event) => tracing::debug!("listener: {event:?}"),
                None => bail!("listener swarm terminated while waiting for a reservation"),
            }
        }
    };
    tokio::time::timeout(config.test_timeout, reservation)
        .await
        .context("timed out waiting for the relay reservation")??;

    swarm.listen_on("/webrtc".parse()?)?;

    let advertised = relay_addr
        .with(Protocol::P2pCircuit)
        .with(Protocol::WebRTC)
        .with(Protocol::P2p(listener_peer_id));
    publish_addr(&config.coord_file, &advertised)?;
    println!("LISTENING_ON={advertised}");
    tracing::info!(address=%advertised, "Listener ready, address published");

    // Drive the listener swarm until the harness kills the process.
    loop {
        let event = swarm.next().await.context("listener swarm terminated")?;
        tracing::debug!("listener: {event:?}");
    }
}

/// Spawns the relay swarm; returns its external multiaddr ending in `/p2p/<relay-id>`.
async fn spawn_relay(config: &Config) -> Result<Multiaddr> {
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_websocket(noise::Config::new, yamux::Config::default)
        .await?
        .with_behaviour(|key| RelayBehaviour {
            relay: relay::Behaviour::new(key.public().to_peer_id(), relay::Config::default()),
            identify: identify::Behaviour::new(identify::Config::new(
                "/webrtc-interop".to_owned(),
                key.public(),
            )),
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    let relay_peer_id = *swarm.local_peer_id();
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}/ws", config.relay_port).parse()?)?;

    let listening = async {
        loop {
            match swarm.next().await {
                Some(SwarmEvent::NewListenAddr { address, .. }) => break Ok(address),
                Some(event) => tracing::debug!("relay: {event:?}"),
                None => bail!("relay swarm terminated while binding"),
            }
        }
    };
    let bound: Multiaddr = tokio::time::timeout(config.test_timeout, listening)
        .await
        .context("timed out waiting for the relay to bind")??;
    tracing::info!(bound=%bound, peer_id=%relay_peer_id, "Relay bound");

    // Advertise the container-external address, never loopback: other containers dial
    // `EXTERNAL_IP`, and the relay embeds this address in reservation vouchers.
    let external = external_ws_addr(&config.external_ip, config.relay_port)?;
    swarm.add_external_address(external.clone());
    tracing::info!(external=%external, "Relay advertising external address");

    tokio::spawn(async move {
        loop {
            match swarm.next().await {
                Some(event) => tracing::debug!("relay: {event:?}"),
                None => {
                    tracing::error!("relay swarm terminated");
                    break;
                }
            }
        }
    });

    Ok(external.with(Protocol::P2p(relay_peer_id)))
}

/// `/ip4|ip6|dns4/<external>/tcp/<port>/ws` depending on what `EXTERNAL_IP` holds.
fn external_ws_addr(external: &str, port: u16) -> Result<Multiaddr> {
    let base = match external.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => Multiaddr::empty().with(Protocol::Ip4(ip)),
        Ok(IpAddr::V6(ip)) => Multiaddr::empty().with(Protocol::Ip6(ip)),
        Err(_) => Multiaddr::empty().with(Protocol::Dns4(external.into())),
    };
    Ok(base
        .with(Protocol::Tcp(port))
        .with(Protocol::Ws("/".into())))
}

/// Builds the `/webrtc` client swarm: the relayed hop runs noise + yamux over
/// websockets or TCP, matching `interop-tests/src/arch.rs`.
fn build_client(config: &Config) -> Result<Swarm<ClientBehaviour>> {
    let key = Keypair::generate_ed25519();
    let local_peer_id = key.public().to_peer_id();

    let (relay_transport, relay_client) = relay::client::new(local_peer_id);

    let mut webrtc_config = webrtc_private::Config::new();
    if let Some(url) = &config.ice_server {
        webrtc_config = webrtc_config.with_ice_server(url.clone());
    }
    let (webrtc_transport, signaling) = webrtc_private::new(webrtc_config);

    // The relay is reached over plain TCP or websockets (with DNS resolution so
    // `EXTERNAL_IP` may be a hostname); the signalling stream then runs on the relayed
    // connection.
    let tcp_transport = dns::tokio::Transport::system(tcp::tokio::Transport::new(
        tcp::Config::default().nodelay(true),
    ))?;
    let ws_transport = websocket::Config::new(dns::tokio::Transport::system(
        tcp::tokio::Transport::new(tcp::Config::default().nodelay(true)),
    )?);

    let relayed_transport = relay_transport
        .or_transport(ws_transport)
        .or_transport(tcp_transport)
        .upgrade(Version::V1)
        .authenticate(noise::Config::new(&key)?)
        .multiplex(yamux::Config::default());

    let transport = webrtc_transport
        .map(|(peer_id, connection), _| (peer_id, StreamMuxerBox::new(connection)))
        .or_transport(
            relayed_transport.map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer))),
        )
        .map(|either_output, _| either_output.into_inner())
        .boxed();

    let behaviour = ClientBehaviour {
        relay_client,
        signaling,
        ping: ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(1))),
        identify: identify::Behaviour::new(identify::Config::new(
            "/webrtc-interop".to_owned(),
            key.public(),
        )),
    };

    Ok(Swarm::new(
        transport,
        behaviour,
        local_peer_id,
        swarm::Config::with_tokio_executor().with_idle_connection_timeout(Duration::from_secs(60)),
    ))
}

/// Dials the published address and returns the RTT of the first successful ping on the
/// direct `/webrtc` connection.
async fn run_dialer(config: &Config) -> Result<Duration> {
    let addr = wait_for_addr(&config.coord_file).await?;
    let listener_peer_id = match addr.iter().last() {
        Some(Protocol::P2p(peer_id)) => peer_id,
        _ => bail!("dial address must end in /p2p/<listener-peer-id>: {addr}"),
    };

    let mut swarm = build_client(config)?;
    tracing::info!(address=%addr, "Dialing listener");
    swarm.dial(addr)?;

    // A `/webrtc` dial also establishes a relayed connection for signalling, and ping
    // runs on both. Only a ping on the direct connection proves the transport works.
    let webrtc_connection = loop {
        match swarm.next().await.context("dialer swarm terminated")? {
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } if peer_id == listener_peer_id
                && endpoint
                    .get_remote_address()
                    .iter()
                    .any(|protocol| protocol == Protocol::WebRTC) =>
            {
                break connection_id;
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                bail!("outgoing connection to {peer_id:?} failed: {error}")
            }
            event => tracing::debug!("dialer: {event:?}"),
        }
    };
    tracing::info!("Direct /webrtc connection established");

    loop {
        match swarm.next().await.context("dialer swarm terminated")? {
            SwarmEvent::Behaviour(ClientBehaviourEvent::Ping(ping::Event {
                connection,
                result: Ok(rtt),
                ..
            })) if connection == webrtc_connection => {
                tracing::info!(?rtt, "Ping over /webrtc successful");
                break Ok(rtt);
            }
            event => tracing::debug!("dialer: {event:?}"),
        }
    }
}

/// Polls `COORD_FILE` until it contains a parseable multiaddr.
async fn wait_for_addr(path: &PathBuf) -> Result<Multiaddr> {
    loop {
        match tokio::fs::read_to_string(path).await {
            Ok(contents) => {
                let contents = contents.trim();
                if !contents.is_empty() {
                    if let Ok(addr) = contents.parse::<Multiaddr>() {
                        return Ok(addr);
                    }
                    tracing::warn!(?contents, "COORD_FILE holds an unparseable multiaddr");
                }
            }
            Err(e) => tracing::debug!(path=%path.display(), "COORD_FILE not readable yet: {e}"),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Writes the address atomically (write + rename) so the dialer never reads a torn file.
fn publish_addr(path: &PathBuf, addr: &Multiaddr) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, format!("{addr}\n"))
        .with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}
