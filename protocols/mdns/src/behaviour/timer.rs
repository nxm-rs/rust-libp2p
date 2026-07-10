// Copyright 2018 Parity Technologies (UK) Ltd.
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

//! mDNS's periodic timer, an accepted native-only exception to the `libp2p-timer` sweep.
//!
//! Unlike the rest of the tree, this timer is a *periodic* [`futures::Stream`] built on
//! `tokio::time::interval_at`, not the oneshot `Delay` future that `libp2p-timer` exposes; the
//! `libp2p-timer` abstraction has no interval type to sweep it onto without reworking mDNS's
//! generic [`super::Provider`] seam (which is deliberately kept generic over the timer/socket
//! backend). Keeping it here is safe because:
//!   * it is pausable under `tokio::time::pause` / `#[tokio::test(start_paused = true)]`, so it
//!     does not regress the deterministic paused-time tests that motivate `libp2p-timer`, and
//!   * `libp2p-mdns` has no wasm target (it needs raw UDP sockets), so the "tokio timer panics on
//!     wasm" hazard that `libp2p-timer` guards against is unreachable here.
//!
//! `scripts/retimer.sh`'s completeness oracle allowlists this file for exactly these reasons; see
//! the allowlist note in `misc/timer/README.md`.

use std::time::{Duration, Instant};

/// Simple wrapper for the different type of timers
#[derive(Debug)]
#[cfg(feature = "tokio")]
pub struct Timer<T> {
    inner: T,
}

/// Builder interface to homogenize the different implementations
#[allow(unreachable_pub)] // Users should not depend on this.
pub trait Builder: Send + Unpin + 'static {
    /// Creates a timer that emits an event once at the given time instant.
    fn at(instant: Instant) -> Self;

    /// Creates a timer that emits events periodically.
    fn interval(duration: Duration) -> Self;

    /// Creates a timer that emits events periodically, starting at start.
    fn interval_at(start: Instant, duration: Duration) -> Self;
}

#[cfg(feature = "tokio")]
pub(crate) mod tokio {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use ::tokio::time::{self, Instant as TokioInstant, Interval, MissedTickBehavior};
    use futures::Stream;

    use super::*;

    /// Tokio wrapper
    pub(crate) type TokioTimer = Timer<Interval>;
    impl Builder for TokioTimer {
        fn at(instant: Instant) -> Self {
            // Taken from: https://docs.rs/async-io/1.7.0/src/async_io/lib.rs.html#91
            let mut inner = time::interval_at(
                TokioInstant::from_std(instant),
                Duration::new(u64::MAX, 1_000_000_000 - 1),
            );
            inner.set_missed_tick_behavior(MissedTickBehavior::Skip);
            Self { inner }
        }

        fn interval(duration: Duration) -> Self {
            let mut inner = time::interval_at(TokioInstant::now() + duration, duration);
            inner.set_missed_tick_behavior(MissedTickBehavior::Skip);
            Self { inner }
        }

        fn interval_at(start: Instant, duration: Duration) -> Self {
            let mut inner = time::interval_at(TokioInstant::from_std(start), duration);
            inner.set_missed_tick_behavior(MissedTickBehavior::Skip);
            Self { inner }
        }
    }

    impl Stream for TokioTimer {
        type Item = TokioInstant;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.inner.poll_tick(cx).map(Some)
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (usize::MAX, None)
        }
    }
}
