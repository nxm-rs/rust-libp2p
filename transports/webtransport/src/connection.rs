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
    pin::Pin,
    task::{Context, Poll},
};

pub(crate) use connecting::{Connecting, WEBTRANSPORT_PATH};
use futures::{FutureExt, future::BoxFuture, ready};
use libp2p_core::{StreamMuxer, muxing::StreamMuxerEvent};
use wtransport::{RecvStream, SendStream, error::ConnectionError};

use crate::Error;
pub use crate::connection::stream::Stream;

mod connecting;
mod stream;

/// State for a single opened Webtransport connection.
pub struct Connection {
    /// Underlying connection.
    connection: wtransport::Connection,
    /// Future for accepting a new incoming bidirectional stream.
    incoming: Option<BoxFuture<'static, Result<(SendStream, RecvStream), ConnectionError>>>,
    /// Future for opening a new outgoing bidirectional stream.
    outgoing: Option<BoxFuture<'static, Result<(SendStream, RecvStream), Error>>>,
    /// Future to wait for the connection to be closed.
    closing: Option<BoxFuture<'static, ConnectionError>>,
}

impl Connection {
    pub(crate) fn new(connection: wtransport::Connection) -> Self {
        Self {
            connection,
            incoming: None,
            outgoing: None,
            closing: None,
        }
    }
}

impl StreamMuxer for Connection {
    type Substream = Stream;
    type Error = Error;

    fn poll_inbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();

        let incoming = this.incoming.get_or_insert_with(|| {
            let connection = this.connection.clone();
            async move { connection.accept_bi().await }.boxed()
        });

        let (send, recv) = ready!(incoming.poll_unpin(cx))?;
        this.incoming.take();
        let stream = Stream::new(send, recv);
        Poll::Ready(Ok(stream))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();

        let closing = this.closing.get_or_insert_with(|| {
            this.connection.close(From::from(0u32), &[]);
            let connection = this.connection.clone();
            async move { connection.closed().await }.boxed()
        });

        match ready!(closing.poll_unpin(cx)) {
            // Expected error given that `connection.close` was called above.
            ConnectionError::LocallyClosed => {}
            error => return Poll::Ready(Err(Error::Connection(error))),
        };

        Poll::Ready(Ok(()))
    }

    fn poll_outbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();

        // WebTransport sessions are symmetric: once a connection is established either peer may
        // open new bidirectional streams, regardless of who dialed. `open_bi` resolves in two
        // stages: first the local stream id is reserved, then the peer grants flow-control credit.
        let outgoing = this.outgoing.get_or_insert_with(|| {
            let connection = this.connection.clone();
            async move { Ok(connection.open_bi().await?.await?) }.boxed()
        });

        let (send, recv) = ready!(outgoing.poll_unpin(cx))?;
        this.outgoing.take();
        let stream = Stream::new(send, recv);
        Poll::Ready(Ok(stream))
    }

    fn poll(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
        // TODO: If connection migration is enabled (currently disabled) address
        // change on the connection needs to be handled.
        Poll::Pending
    }
}
