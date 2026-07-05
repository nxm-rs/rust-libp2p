## 0.1.0

- Initial release.

  Runtime-aware `Delay` and `bounded_delay` so paused time can drive every wait in the tree. Native
  picks tokio's clock on a runtime and `futures-timer` off-runtime; wasm re-exports `futures-timer`.
