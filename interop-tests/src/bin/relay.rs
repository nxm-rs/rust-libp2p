//! Standalone Circuit Relay v2 node for the NAT interop topology.
//!
//! A `/webrtc` listener behind NAT reserves a slot here and the signalling stream for
//! incoming connections runs over the relayed connection. The node listens on
//! websockets so browser peers can reach it, advertises `EXTERNAL_IP` (never the bind
//! address) and derives its identity from `RELAY_SEED`, so the full multiaddr,
//! including the `/p2p/<peer-id>` suffix, is known ahead of time and can be wired
//! statically into a docker compose file.
//!
//! Environment variables:
//!
//! - `EXTERNAL_IP`: IP or DNS name the relay advertises (default `127.0.0.1`).
//! - `RELAY_PORT`: fixed websocket listen port (default `4455`).
//! - `RELAY_SEED`: byte repeated into the ed25519 secret key (default `42`).
//! - `RUST_LOG`: standard `tracing` filter for verbose diagnostics.

use std::net::IpAddr;

use anyhow::{Context, Result};
use futures::StreamExt;
use libp2p::{
    Multiaddr, SwarmBuilder, identify, identity,
    multiaddr::Protocol,
    noise, relay,
    swarm::NetworkBehaviour,
    yamux,
};
use tracing_subscriber::EnvFilter;

#[derive(NetworkBehaviour)]
struct Behaviour {
    relay: relay::Behaviour,
    identify: identify::Behaviour,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let external_ip = std::env::var("EXTERNAL_IP").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port: u16 = std::env::var("RELAY_PORT")
        .unwrap_or_else(|_| "4455".to_owned())
        .parse()
        .context("RELAY_PORT must be a port number")?;
    let seed: u8 = std::env::var("RELAY_SEED")
        .unwrap_or_else(|_| "42".to_owned())
        .parse()
        .context("RELAY_SEED must fit in a byte")?;

    let keypair = identity::Keypair::ed25519_from_bytes([seed; 32])
        .context("failed to derive the relay identity from RELAY_SEED")?;

    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_websocket(noise::Config::new, yamux::Config::default)
        .await?
        .with_behaviour(|key| Behaviour {
            relay: relay::Behaviour::new(key.public().to_peer_id(), relay::Config::default()),
            identify: identify::Behaviour::new(identify::Config::new(
                "/interop-tests".to_owned(),
                key.public(),
            )),
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(std::time::Duration::from_secs(60)))
        .build();

    let local_peer_id = *swarm.local_peer_id();
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{port}/ws").parse()?)?;

    // Advertise the container-external address: peers dial `EXTERNAL_IP` and the relay
    // embeds this address in reservation vouchers.
    let external = external_ws_addr(&external_ip, port);
    swarm.add_external_address(external.clone());
    let advertised = external.with(Protocol::P2p(local_peer_id));
    println!("RELAY_LISTENING_ON={advertised}");
    tracing::info!(address=%advertised, "Relay ready");

    loop {
        let event = swarm.next().await.context("relay swarm terminated")?;
        tracing::debug!("relay: {event:?}");
    }
}

/// `/ip4|ip6|dns4/<external>/tcp/<port>/ws` depending on what `EXTERNAL_IP` holds.
fn external_ws_addr(external: &str, port: u16) -> Multiaddr {
    let base = match external.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => Multiaddr::empty().with(Protocol::Ip4(ip)),
        Ok(IpAddr::V6(ip)) => Multiaddr::empty().with(Protocol::Ip6(ip)),
        Err(_) => Multiaddr::empty().with(Protocol::Dns4(external.into())),
    };
    base.with(Protocol::Tcp(port))
        .with(Protocol::Ws("/".into()))
}
