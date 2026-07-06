mod proto {
    #![allow(unreachable_pub)]
    include!("generated/mod.rs");
    pub use self::{
        webrtc_pb::{Message, message::Flag},
        webrtc_signaling_pb::{Message as SignalingMessage, message::Type as SignalingMessageType},
    };
}

mod fingerprint;
pub mod noise;
pub mod sdp;
pub mod signaling;
mod stream;
mod transport;

pub use fingerprint::{Fingerprint, SHA256};
pub use stream::{DropListener, MAX_MSG_LEN, Stream};
pub use transport::parse_webrtc_dial_addr;
