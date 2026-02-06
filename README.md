# tlsn-wasm-notarize

WASM bindings for TLSNotary attestation — the missing `notarize()` + `Presentation` API for browser applications.

## Why?

TLSNotary alpha-14 removed `notarize()`, `Attestation`, and `Presentation` from their official WASM bindings (`tlsn-wasm`), which only exposes `reveal()` for live verifier interaction. The Rust-level attestation APIs are still maintained in `tlsn-attestation`.

This package fills that gap: a general-purpose WASM package that exposes the full notarization flow (MPC-TLS → attestation signing → portable proof generation) for browser-based applications.

## Usage

```typescript
import init, { initialize, Prover, Presentation } from 'tlsn-wasm-notarize';

// Initialize WASM + rayon thread pool
await init();
await initialize(null, navigator.hardwareConcurrency);

// Create prover
const prover = new Prover({
  serverDns: "api.example.com",
  maxSentData: 4096,
  maxRecvData: 16384,
  network: "Bandwidth",
});

// Connect to notary
await prover.setup("wss://notary.example.com/notarize?sessionId=xxx");

// Send HTTP request through MPC-TLS
const response = await prover.sendRequest("wss://proxy.example.com/proxy", {
  url: "https://api.example.com/data",
  method: "GET",
  headers: { "Host": "api.example.com" },
});

// Get transcript
const { sent, recv } = prover.transcript();

// Notarize — returns hex-encoded bincode
const { attestation, secrets } = await prover.notarize();

// Build presentation with selective disclosure
const presentation = new Presentation({
  attestationHex: attestation,
  secretsHex: secrets,
  reveal: {
    sent: [{ start: 0, end: 50 }],
    recv: [{ start: 0, end: recv.length }],
  },
});

const proofHex = presentation.serialize();
```

## Building

Requires nightly Rust with `wasm32-unknown-unknown` target and `wasm-pack` 0.14.0+.

```bash
rustup toolchain install nightly --component rust-src --target wasm32-unknown-unknown
cargo install wasm-pack

./build.sh
# Output: pkg/ directory with .wasm + .js + .d.ts
```

## Architecture

```
Prover State Machine:
  Initialized → setup() → CommitAccepted → sendRequest() → Committed → notarize() → Complete

Key difference from official crate:
  - Official: setup() → sendRequest() → reveal() (live verifier)
  - This:     setup() → sendRequest() → notarize() (offline attestation)

Socket reclamation:
  WASM spawn_local has no JoinHandle. We use a oneshot channel to reclaim
  the session socket after MPC completes, enabling attestation exchange.
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
