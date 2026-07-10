//! End-to-end test for the private-to-private WebRTC transport: two nodes with a
//! reservation on a shared relay establish a direct connection via signalling and ICE,
//! then exchange stream data over it.

use std::time::Duration;

use libp2p_core::{
    multiaddr::Protocol,
    muxing::StreamMuxerBox,
    transport::{Transport as _, upgrade::Version},
};
use libp2p_identity as identity;
use libp2p_ping as ping;
use libp2p_plaintext as plaintext;
use libp2p_relay as relay;
use libp2p_swarm::{Config, NetworkBehaviour, Swarm, SwarmEvent};
use libp2p_swarm_test::SwarmExt as _;
use libp2p_webrtc::tokio::private;
use tracing_subscriber::EnvFilter;

#[tokio::test]
#[ignore = "opens real UDP sockets and runs a full ICE exchange; run with --ignored"]
async fn two_nodes_connect_via_relay_signalling() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let mut relay = build_relay();
    let (_, relay_tcp_addr) = relay.listen().with_tcp_addr_external().await;
    let relay_peer_id = *relay.local_peer_id();
    tokio::spawn(relay.loop_on_next());

    let mut listener = build_client();
    let mut dialer = build_client();
    let listener_peer_id = *listener.local_peer_id();

    // The listener reserves a slot on the relay and accepts `/webrtc` connections.
    let listener_relayed_addr = relay_tcp_addr
        .clone()
        .with(Protocol::P2p(relay_peer_id))
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(listener_peer_id));
    listener.listen_on(listener_relayed_addr).unwrap();
    listener.listen_on("/webrtc".parse().unwrap()).unwrap();

    listener
        .wait(|event| match event {
            SwarmEvent::Behaviour(ClientEvent::RelayClient(
                relay::client::Event::ReservationReqAccepted { .. },
            )) => Some(()),
            _ => None,
        })
        .await;
    tokio::spawn(listener.loop_on_next());

    // Dial `<relay>/p2p-circuit/webrtc/p2p/<listener>`: the transport opens a
    // signalling stream over the relayed connection, then both sides run ICE.
    let webrtc_addr = relay_tcp_addr
        .with(Protocol::P2p(relay_peer_id))
        .with(Protocol::P2pCircuit)
        .with(Protocol::WebRTC)
        .with(Protocol::P2p(listener_peer_id));
    dialer.dial(webrtc_addr).unwrap();

    let webrtc_connection_id = dialer
        .wait(|event| match event {
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
                Some(connection_id)
            }
            _ => None,
        })
        .await;

    // A successful ping on the direct connection proves stream data flows both ways.
    dialer
        .wait(|event| match event {
            SwarmEvent::Behaviour(ClientEvent::Ping(ping::Event {
                connection,
                result: Ok(_),
                ..
            })) if connection == webrtc_connection_id => Some(()),
            _ => None,
        })
        .await;
}

fn build_relay() -> Swarm<relay::Behaviour> {
    Swarm::new_ephemeral_tokio(|identity| {
        relay::Behaviour::new(identity.public().to_peer_id(), relay::Config::default())
    })
}

#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p_swarm::derive_prelude")]
struct Client {
    relay_client: relay::client::Behaviour,
    signaling: private::Behaviour,
    ping: ping::Behaviour,
}

fn build_client() -> Swarm<Client> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = local_key.public().to_peer_id();

    let (relay_transport, relay_client) = relay::client::new(local_peer_id);
    let (webrtc_transport, signaling) = private::new(private::Config::new());

    let relayed_transport = relay_transport
        .or_transport(libp2p_tcp::tokio::Transport::default())
        .upgrade(Version::V1)
        .authenticate(plaintext::Config::new(&local_key))
        .multiplex(libp2p_yamux::Config::default());

    let transport = webrtc_transport
        .map(|(peer_id, connection), _| (peer_id, StreamMuxerBox::new(connection)))
        .or_transport(
            relayed_transport.map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer))),
        )
        .map(|either_output, _| either_output.into_inner())
        .boxed();

    Swarm::new(
        transport,
        Client {
            relay_client,
            signaling,
            ping: ping::Behaviour::default(),
        },
        local_peer_id,
        Config::with_tokio_executor().with_idle_connection_timeout(Duration::from_secs(60)),
    )
}
