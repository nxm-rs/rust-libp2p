//! One timer backend for the whole tree so paused time drives every wait.
//!
//! [`Delay`] and [`bounded_delay`] replace direct `futures-timer` and `futures_bounded::Delay`
//! construction across the workspace. Native picks its backend when the timer is armed
//! (construction or `reset`) via `Handle::try_current`: tokio's clock when a runtime is present
//! (pausable under `tokio::time::pause`, which is what makes deterministic time-controlled tests
//! possible) and `futures-timer` off-runtime (the fork's own suites arm production timers off any
//! runtime, where a tokio-only timer would panic for want of a time driver). Arming eagerly rather
//! than at first poll keeps the countdown running while a timer is unpolled, which periodic
//! schedulers such as kad's bootstrap depend on: they arm a periodic `Delay`, suppress it while a
//! request is in flight without polling it, then expect the interval to have already elapsed. On
//! wasm there is no tokio time driver, so both are plain `futures-timer`.
//!
//! This tokio-preference on native is a deliberate fork choice, not an upstream-neutral one: it
//! trades runtime-agnosticism for pausability under the fork's tokio-driven test suite.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use std::time::Duration;

#[cfg(any(target_os = "emscripten", target_os = "wasi", target_os = "unknown"))]
pub use futures_timer::Delay;

/// Bounded-collection deadline for `futures_bounded::{FuturesSet, StreamSet}` construction.
///
/// wasm always uses the `futures-timer` backend; a tokio-backed `futures_bounded::Delay` compiles
/// on wasm but panics at first poll in the browser, where there is no time driver.
#[cfg(any(target_os = "emscripten", target_os = "wasi", target_os = "unknown"))]
pub fn bounded_delay(duration: Duration) -> futures_bounded::Delay {
    futures_bounded::Delay::futures_timer(duration)
}

#[cfg(not(any(target_os = "emscripten", target_os = "wasi", target_os = "unknown")))]
pub use native::Delay;

/// Bounded-collection deadline for `futures_bounded::{FuturesSet, StreamSet}` construction.
///
/// Uses tokio's clock when a runtime is present (pausable under test) and `futures-timer`
/// off-runtime.
#[cfg(not(any(target_os = "emscripten", target_os = "wasi", target_os = "unknown")))]
pub fn bounded_delay(duration: Duration) -> futures_bounded::Delay {
    if tokio::runtime::Handle::try_current().is_ok() {
        futures_bounded::Delay::tokio(duration)
    } else {
        futures_bounded::Delay::futures_timer(duration)
    }
}

#[cfg(not(any(target_os = "emscripten", target_os = "wasi", target_os = "unknown")))]
mod native {
    use std::{
        fmt,
        future::Future,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    /// Oneshot timer that binds its backend **eagerly, when it is armed** (construction or
    /// `reset`) — not lazily at first poll.
    ///
    /// The backend is chosen once, at arm time, through [`tokio::runtime::Handle::try_current`]:
    /// tokio's clock (a `tokio::time::Sleep`, pausable under `tokio::time::pause`) when armed on a
    /// runtime, and `futures-timer` when armed off one. That choice is fixed for the timer's life,
    /// so the panic-safety invariant is a property of *where it is armed versus where it is
    /// polled*:
    ///
    ///   * Armed off any runtime → `futures-timer`; drivable by any executor. Always safe.
    ///   * Armed on a runtime and polled from within that same runtime context (the common case: a
    ///     `Delay` is constructed and driven by one swarm task, so construction-context ==
    ///     poll-context). Safe.
    ///   * Armed on a runtime but then polled *off* that runtime → the inner `tokio::time::Sleep`
    ///     can panic for want of an entered time driver, exactly like any hand-rolled tokio
    ///     `Sleep`. Callers must not move a runtime-armed `Delay` off its runtime to poll it.
    ///
    /// Arming eagerly rather than at first poll is deliberate: the countdown must run while the
    /// timer is unpolled, because periodic schedulers arm a `Delay`, suppress polling it while a
    /// request is running, and then expect the interval to have already elapsed.
    pub struct Delay(State);

    enum State {
        Tokio(Pin<Box<tokio::time::Sleep>>),
        Wall(futures_timer::Delay),
        /// Fired; polling again stays `Ready` regardless of backend stickiness.
        Ready,
    }

    fn arm(duration: Duration) -> State {
        if tokio::runtime::Handle::try_current().is_ok() {
            State::Tokio(Box::pin(tokio::time::sleep(duration)))
        } else {
            State::Wall(futures_timer::Delay::new(duration))
        }
    }

    impl Delay {
        pub fn new(duration: Duration) -> Self {
            Self(arm(duration))
        }

        pub fn reset(&mut self, duration: Duration) {
            match &mut self.0 {
                // Reset the live backend in place so a waker already parked on it stays valid
                // (callers reset outside a poll context).
                State::Tokio(sleep) => {
                    sleep.as_mut().reset(tokio::time::Instant::now() + duration);
                }
                State::Wall(delay) => delay.reset(duration),
                // Already fired: re-arm from now.
                State::Ready => self.0 = arm(duration),
            }
        }
    }

    impl Future for Delay {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            let this = self.get_mut();
            let poll = match &mut this.0 {
                State::Tokio(sleep) => sleep.as_mut().poll(cx),
                State::Wall(delay) => Pin::new(delay).poll(cx),
                State::Ready => return Poll::Ready(()),
            };
            if poll.is_ready() {
                this.0 = State::Ready;
            }
            poll
        }
    }

    impl fmt::Debug for Delay {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let backend = match &self.0 {
                State::Tokio(_) => "Tokio",
                State::Wall(_) => "Wall",
                State::Ready => "Ready",
            };
            f.debug_tuple("Delay").field(&backend).finish()
        }
    }
}

#[cfg(all(
    test,
    not(any(target_os = "emscripten", target_os = "wasi", target_os = "unknown"))
))]
mod tests {
    use std::{future::poll_fn, pin::Pin, task::Poll, time::Duration};

    use super::Delay;

    #[tokio::test(start_paused = true)]
    async fn fires_at_deadline() {
        let start = tokio::time::Instant::now();
        Delay::new(Duration::from_secs(5)).await;
        assert!(start.elapsed() >= Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn reset_rearms_after_completion() {
        let mut delay = Delay::new(Duration::from_secs(1));
        poll_fn(|cx| Pin::new(&mut delay).poll(cx)).await;

        let after_first = tokio::time::Instant::now();
        delay.reset(Duration::from_secs(3));
        delay.await;

        assert!(after_first.elapsed() >= Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn reset_before_first_poll() {
        let start = tokio::time::Instant::now();
        let mut delay = Delay::new(Duration::from_secs(1));
        delay.reset(Duration::from_secs(10));
        delay.await;

        assert!(start.elapsed() >= Duration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn unpolled_timer_counts_down() {
        // A periodic scheduler arms a `Delay`, then does not poll it while other work runs; the
        // interval must still elapse in the background so the timer is ready by the time it is
        // next polled. Lazy first-poll arming would restart the countdown here instead.
        let mut delay = Delay::new(Duration::from_secs(1));
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            poll_fn(|cx| Poll::Ready(Pin::new(&mut delay).poll(cx)))
                .await
                .is_ready()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ready_is_sticky() {
        let mut delay = Delay::new(Duration::from_secs(1));
        poll_fn(|cx| Pin::new(&mut delay).poll(cx)).await;

        // A completed timer must keep returning `Ready` rather than re-arming or stalling.
        let polled = poll_fn(|cx| Poll::Ready(Pin::new(&mut delay).poll(cx))).await;
        assert!(polled.is_ready());
    }

    #[test]
    fn fallback_fires_off_runtime() {
        // No tokio runtime: `Handle::try_current` errors, the `futures-timer` arm must drive the
        // timer to completion under a plain executor.
        futures::executor::block_on(Delay::new(Duration::from_millis(50)));
    }
}
