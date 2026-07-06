// Copyright 2024 Protocol Labs.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::{
    FutureExt,
    future::{BoxFuture, Either, Select, select},
    ready,
};
use futures_timer::Delay;
use libp2p_core::upgrade::InboundConnectionUpgrade;
use libp2p_identity::PeerId;
use wtransport::endpoint::{IncomingSessionFuture, SessionRequest};

use crate::{Connection, Error};

pub(crate) const WEBTRANSPORT_PATH: &str = "/.well-known/libp2p-webtransport?type=noise";

/// A Webtransport connection currently being negotiated.
pub struct Connecting {
    connecting: Select<BoxFuture<'static, Result<(PeerId, Connection), Error>>, Delay>,
}

impl Connecting {
    /// Negotiates a WebTransport session over a QUIC connection routed to this transport by the
    /// shared endpoint holder. `timeout` covers the whole inbound handshake: QUIC completion,
    /// the HTTP/3 CONNECT exchange, and the Noise authentication.
    pub fn new(
        connecting: quinn::Connecting,
        noise_config: libp2p_noise::Config,
        timeout: Duration,
    ) -> Self {
        Connecting {
            connecting: select(
                Self::handshake(connecting, noise_config).boxed(),
                Delay::new(timeout),
            ),
        }
    }

    async fn handshake(
        connecting: quinn::Connecting,
        noise_config: libp2p_noise::Config,
    ) -> Result<(PeerId, Connection), Error> {
        let session_request = IncomingSessionFuture::with_quic_connecting(connecting).await?;

        tracing::debug!(
            path = session_request.path(),
            remote = %session_request.remote_address(),
            "incoming WebTransport session request"
        );

        Self::session_handshake(session_request, noise_config).await
    }

    async fn session_handshake(
        session_request: SessionRequest,
        noise_config: libp2p_noise::Config,
    ) -> Result<(PeerId, Connection), Error> {
        let path = session_request.path();
        if path != WEBTRANSPORT_PATH {
            return Err(Error::UnexpectedPath(String::from(path)));
        }
        match session_request.accept().await {
            Ok(wtransport_connection) => {
                // The client SHOULD start the handshake right after sending the CONNECT request,
                // without waiting for the server's response.
                let peer_id = Self::noise_auth(wtransport_connection.clone(), noise_config).await?;

                tracing::debug!(
                    "Accepted connection with sessionId={}",
                    wtransport_connection.session_id()
                );

                let connection = Connection::new(wtransport_connection);
                Ok((peer_id, connection))
            }
            Err(connection_error) => Err(Error::Connection(connection_error)),
        }
    }

    async fn noise_auth(
        connection: wtransport::Connection,
        noise_config: libp2p_noise::Config,
    ) -> Result<PeerId, Error> {
        let (send, recv) = connection.accept_bi().await?;
        let stream = crate::Stream::new(send, recv);
        let (peer_id, _) = noise_config.upgrade_inbound(stream, "").await?;

        Ok(peer_id)
    }
}

impl Future for Connecting {
    type Output = Result<(PeerId, Connection), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (peer_id, connection) = match ready!(self.connecting.poll_unpin(cx)) {
            Either::Right(_) => return Poll::Ready(Err(Error::HandshakeTimedOut)),
            Either::Left((res, _)) => res?,
        };

        Poll::Ready(Ok((peer_id, connection)))
    }
}
