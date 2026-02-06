//! WASM bindings for TLSNotary attestation (notarize + presentation).
//!
//! This crate provides the missing attestation flow for browser-based TLSNotary
//! applications. While the official `tlsn-wasm` crate only exposes `reveal()`
//! for live verifier interaction, this crate adds:
//!
//! - `Prover::notarize()` — MPC-TLS + attestation signing + portable proof generation
//! - `Presentation` — selective disclosure from attestation + secrets
//!
//! The output is a hex-encoded bincode serialization that can be stored, transmitted,
//! and verified offline.

#![cfg(target_arch = "wasm32")]
#![deny(unreachable_pub, unused_must_use, clippy::all)]
#![allow(non_snake_case)]

pub(crate) mod io;
mod log;
pub mod presentation;
pub mod prover;
pub mod types;

pub use log::{LoggingConfig, LoggingLevel};

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// Initializes the module.
///
/// Sets up browser console logging and spawns a rayon thread pool using
/// web workers for parallelism.
#[wasm_bindgen]
pub async fn initialize(
    logging_config: Option<LoggingConfig>,
    thread_count: usize,
) -> Result<(), JsValue> {
    log::init_logging(logging_config);

    JsFuture::from(web_spawn::start_spawner()).await?;

    // Initialize rayon global thread pool.
    rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .spawn_handler(|thread| {
            // Drop join handle.
            let _ = web_spawn::spawn(move || thread.run());
            Ok(())
        })
        .build_global()
        .unwrap_throw();

    Ok(())
}
