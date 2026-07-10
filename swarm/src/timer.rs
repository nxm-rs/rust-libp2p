//! Runtime-aware oneshot timer for the swarm's internal connection deadlines.
//!
//! Native targets ride tokio's clock so `tokio::time::pause` drives these deadlines under test
//! without burning wall-clock; wasm32 keeps the runtime-agnostic global timer, which is the only
//! option there because tokio's time driver does not exist in the browser.

#[cfg(any(target_os = "emscripten", target_os = "wasi", target_os = "unknown"))]
pub(crate) use futures_timer::Delay;
#[cfg(not(any(target_os = "emscripten", target_os = "wasi", target_os = "unknown")))]
pub(crate) use native::Delay;

#[cfg(not(any(target_os = "emscripten", target_os = "wasi", target_os = "unknown")))]
mod native {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    /// Oneshot timer backed by tokio's clock.
    ///
    /// The `tokio::time::Sleep` is created lazily on first poll: construction happens off-runtime
    /// in some tests, and deferring keeps `new` from panicking there while the deadline still
    /// starts ticking the moment the timer is first polled inside the swarm's runtime.
    #[derive(Debug)]
    pub(crate) struct Delay {
        duration: Duration,
        sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    }

    impl Delay {
        pub(crate) fn new(duration: Duration) -> Self {
            Self {
                duration,
                sleep: None,
            }
        }
    }

    impl Future for Delay {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            let duration = this.duration;
            let sleep = this
                .sleep
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(duration)));
            sleep.as_mut().poll(cx)
        }
    }
}
