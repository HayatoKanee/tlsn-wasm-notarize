use tlsn::attestation::{
    presentation::Presentation as TlsnPresentation, Attestation, CryptoProvider, Secrets,
};
use wasm_bindgen::{prelude::*, JsError};

use crate::types::PresentationConfig;

type Result<T> = std::result::Result<T, JsError>;

/// WASM wrapper for building a TLSNotary Presentation with selective disclosure.
///
/// Takes hex-encoded attestation + secrets, applies reveal ranges, and outputs
/// a hex-encoded serialized Presentation.
#[wasm_bindgen(js_name = Presentation)]
pub struct JsPresentation {
    config: PresentationConfig,
}

#[wasm_bindgen(js_class = Presentation)]
impl JsPresentation {
    #[wasm_bindgen(constructor)]
    pub fn new(config: PresentationConfig) -> Result<JsPresentation> {
        Ok(JsPresentation { config })
    }

    /// Build and serialize the presentation.
    ///
    /// Returns hex-encoded bincode of the Presentation.
    pub fn serialize(&self) -> Result<String> {
        // Deserialize attestation from hex bincode
        let attestation_bytes = hex::decode(&self.config.attestation_hex)
            .map_err(|e| JsError::new(&format!("invalid attestation hex: {e}")))?;
        let attestation: Attestation = bincode::deserialize(&attestation_bytes)
            .map_err(|e| JsError::new(&format!("failed to deserialize attestation: {e}")))?;

        // Deserialize secrets from hex bincode
        let secrets_bytes = hex::decode(&self.config.secrets_hex)
            .map_err(|e| JsError::new(&format!("invalid secrets hex: {e}")))?;
        let secrets: Secrets = bincode::deserialize(&secrets_bytes)
            .map_err(|e| JsError::new(&format!("failed to deserialize secrets: {e}")))?;

        // Build transcript proof with selective disclosure
        let mut builder = secrets.transcript_proof_builder();

        for range in &self.config.reveal.sent {
            builder
                .reveal_sent(range)
                .map_err(|e| JsError::new(&format!("failed to reveal sent range: {e}")))?;
        }

        for range in &self.config.reveal.recv {
            builder
                .reveal_recv(range)
                .map_err(|e| JsError::new(&format!("failed to reveal recv range: {e}")))?;
        }

        let transcript_proof = builder
            .build()
            .map_err(|e| JsError::new(&format!("failed to build transcript proof: {e}")))?;

        // Build presentation
        let provider = CryptoProvider::default();
        let mut builder = attestation.presentation_builder(&provider);

        builder
            .identity_proof(secrets.identity_proof())
            .transcript_proof(transcript_proof);

        let presentation: TlsnPresentation = builder
            .build()
            .map_err(|e| JsError::new(&format!("failed to build presentation: {e}")))?;

        // Serialize to hex bincode
        let presentation_bytes = bincode::serialize(&presentation)
            .map_err(|e| JsError::new(&format!("failed to serialize presentation: {e}")))?;

        Ok(hex::encode(presentation_bytes))
    }
}
