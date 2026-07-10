//! Live browser test for the private-to-private WebRTC transport: two swarms in the
//! same page reserve a slot on an external relay, then establish a direct `/webrtc`
//! connection via signalling and ICE and exchange ping data over it.
//!
//! Requires a running relay reachable from the browser, e.g. the relay-server example,
//! whose websocket multiaddr (including `/p2p/<relay-peer-id>`) must be provided via
//! the `WEBRTC_PRIVATE_RELAY_ADDR` environment variable at compile time.

#![cfg(target_family = "wasm")]

use std::time::Duration;

use futures::StreamExt;
use libp2p_core::{
    Multiaddr, Transport as _, multiaddr::Protocol, muxing::StreamMuxerBox,
    transport::upgrade::Version,
};
use libp2p_identity::Keypair;
use libp2p_ping as ping;
use libp2p_relay as relay;
use libp2p_swarm::{Config, NetworkBehaviour, Swarm, SwarmEvent};
use libp2p_webrtc_websys::private;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
#[ignore = "requires a live relay server, see the module docs"]
async fn two_browser_peers_connect_via_relay_signalling() {
    let Some(relay_addr) = option_env!("WEBRTC_PRIVATE_RELAY_ADDR") else {
        panic!("set WEBRTC_PRIVATE_RELAY_ADDR to the relay's websocket multiaddr");
    };
    let relay_addr: Multiaddr = relay_addr.parse().unwrap();
    assert!(
        matches!(relay_addr.iter().last(), Some(Protocol::P2p(_))),
        "relay multiaddr must end in /p2p/<relay-peer-id>"
    );

    let mut listener = build_client();
    let mut dialer = build_client();
    let listener_peer_id = *listener.local_peer_id();

    // The listener reserves a slot on the relay and accepts `/webrtc` connections.
    let listener_relayed_addr = relay_addr
        .clone()
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(listener_peer_id));
    listener.listen_on(listener_relayed_addr).unwrap();
    listener.listen_on("/webrtc".parse().unwrap()).unwrap();

    loop {
        if let SwarmEvent::Behaviour(ClientEvent::RelayClient(
            relay::client::Event::ReservationReqAccepted { .. },
        )) = listener.next().await.unwrap()
        {
            break;
        }
    }
    wasm_bindgen_futures::spawn_local(async move {
        loop {
            listener.next().await;
        }
    });

    // Dial `<relay>/p2p-circuit/webrtc/p2p/<listener>`: the transport opens a
    // signalling stream over the relayed connection, then both sides run ICE.
    let webrtc_addr = relay_addr
        .with(Protocol::P2pCircuit)
        .with(Protocol::WebRTC)
        .with(Protocol::P2p(listener_peer_id));
    dialer.dial(webrtc_addr).unwrap();

    let webrtc_connection_id = loop {
        match dialer.next().await.unwrap() {
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
            _ => {}
        }
    };

    // A successful ping on the direct connection proves stream data flows both ways.
    loop {
        match dialer.next().await.unwrap() {
            SwarmEvent::Behaviour(ClientEvent::Ping(ping::Event {
                connection,
                result: Ok(_),
                ..
            })) if connection == webrtc_connection_id => break,
            _ => {}
        }
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p_swarm::derive_prelude")]
struct Client {
    relay_client: relay::client::Behaviour,
    signaling: private::Behaviour,
    ping: ping::Behaviour,
}

fn build_client() -> Swarm<Client> {
    let local_key = Keypair::generate_ed25519();
    let local_peer_id = local_key.public().to_peer_id();

    let (relay_transport, relay_client) = relay::client::new(local_peer_id);
    let (webrtc_transport, signaling) = private::new(private::Config::new());

    let relayed_transport = relay_transport
        .or_transport(libp2p_websocket_websys::Transport::default())
        .upgrade(Version::V1)
        .authenticate(libp2p_noise::Config::new(&local_key).unwrap())
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
        Config::with_wasm_executor().with_idle_connection_timeout(Duration::from_secs(60)),
    )
}
