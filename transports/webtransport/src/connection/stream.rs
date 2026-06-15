use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wtransport::{RecvStream, SendStream};

/// A single bidirectional stream on a connection.
///
/// A QUIC bidirectional stream has two **independent** halves: a send half ([`SendStream`]) and a
/// recv half ([`RecvStream`]). Reads delegate solely to the recv half — quinn reports a peer FIN as
/// `Ok(0)` and a peer reset as a propagated `io::Error` on the recv half itself, so the state of
/// the *send* half must never gate reads. Closing the send half (FIN/`STOP_SENDING`) has no bearing
/// on what is still readable from the recv half.
pub struct Stream {
    /// The send half of the stream.
    send: SendStream,
    /// The recv half of the stream. Reports FIN/reset on its own; the sole source of read EOF.
    recv: RecvStream,
    /// Cached result of shutting down the **send** half, used only to make [`Self::poll_close`]
    /// idempotent ("fuse"able). Never gates reads.
    send_close: Option<Result<(), io::ErrorKind>>,
}

impl Stream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            send_close: None,
        }
    }
}

impl futures::AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // Reads delegate straight to the recv half. The send half's close state is deliberately not
        // consulted: a closed send half does not imply the recv half is at EOF, and quinn already
        // signals recv FIN (`Ok(0)`) and reset (`Err`) correctly on the recv half.
        let mut read_buf = ReadBuf::new(buf);
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, &mut read_buf)
            .map_ok(|()| read_buf.filled().len())
    }
}

impl futures::AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Idempotent "fuse", scoped to the send half only: once the send half has been shut down,
        // repeated `poll_close` calls replay the cached result instead of re-driving the shutdown.
        // This does not affect reads (see `poll_read`).
        if let Some(send_close) = self.send_close {
            return Poll::Ready(send_close.map_err(Into::into));
        }
        let res = futures::ready!(AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx));
        self.send_close = Some(res.as_ref().map_err(|e| e.kind()).copied());
        Poll::Ready(res)
    }
}
