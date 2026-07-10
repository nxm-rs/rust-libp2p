//! In-process Circuit Relay v2 node backing the `/webrtc` tests.
//!
//! A `/webrtc` listener is only reachable through a relay, so the listener side of the
//! test spawns one and embeds its multiaddr in the advertised webrtc multiaddr. The
//! relay listens on websockets so that browser peers and other implementations can
//! reach it.

use anyhow::{Context, Result};
use futures::StreamExt;
use libp2p::{
    Multiaddr, SwarmBuilder, identify,
    multiaddr::Protocol,
    noise, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    yamux,
};

#[derive(NetworkBehaviour)]
struct Behaviour {
    relay: relay::Behaviour,
    identify: identify::Behaviour,
}

/// Spawns a relay listening on a websocket multiaddr on `ip`.
///
/// Returns the relay's multiaddr including its `/p2p/<peer-id>` suffix. When `ip` is
/// `0.0.0.0`, the first non-loopback listen address is returned, so the relay is
/// reachable from other hosts on the network.
pub async fn spawn(ip: &str) -> Result<Multiaddr> {
    let mut swarm = SwarmBuilder::with_new_identity()
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
    swarm.listen_on(format!("/ip4/{ip}/tcp/0/ws").parse()?)?;

    let require_non_loopback = ip == "0.0.0.0";
    let address = loop {
        match swarm.next().await.context("relay swarm terminated")? {
            SwarmEvent::NewListenAddr { address, .. }
                if !(require_non_loopback && address.to_string().contains("127.0.0.1")) =>
            {
                break address;
            }
            _ => continue,
        }
    };

    swarm.add_external_address(address.clone());
    tracing::info!(address=%address, peer_id=%local_peer_id, "Relay listening");

    tokio::spawn(async move {
        loop {
            let event = swarm.next().await;
            tracing::debug!("relay: {event:?}");
        }
    });

    Ok(address.with(Protocol::P2p(local_peer_id)))
}
