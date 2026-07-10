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
