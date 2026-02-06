mod config;

pub use config::ProverConfig;

use async_io_stream::IoStream;
use enum_try_as_inner::EnumTryAsInner;
use futures::{io::AsyncReadExt as _, io::AsyncWriteExt as _, TryFutureExt};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use tlsn::{
    attestation::{
        request::{Request as AttestationRequest, RequestConfig},
        Attestation, CryptoProvider,
    },
    config::{
        prove::ProveConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, TlsCommitConfig},
    },
    connection::{HandshakeData, ServerName},
    prover::{state, Prover, ProverOutput, TlsConnection},
    transcript::TranscriptCommitConfig,
    webpki::{CertificateDer, PrivateKeyDer, RootCertStore},
    Session, SessionHandle,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tracing::info;
use wasm_bindgen::{prelude::*, JsError};
use wasm_bindgen_futures::spawn_local;
use ws_stream_wasm::{WsMeta, WsStreamIo};

use crate::{io::FuturesIo, types::*};

type Result<T> = std::result::Result<T, JsError>;

/// The IO type returned by the session driver when using WebSocket transport.
type WsIo = IoStream<WsStreamIo, Vec<u8>>;

#[wasm_bindgen(js_name = Prover)]
pub struct JsProver {
    config: ProverConfig,
    state: State,
}

#[derive(EnumTryAsInner)]
#[derive_err(Debug)]
enum State {
    Initialized,
    CommitAccepted {
        prover: Prover<state::CommitAccepted>,
        handle: SessionHandle,
        socket_rx: futures::channel::oneshot::Receiver<std::result::Result<WsIo, tlsn::Error>>,
    },
    Committed {
        prover: Prover<state::Committed>,
        handle: SessionHandle,
        socket_rx: futures::channel::oneshot::Receiver<std::result::Result<WsIo, tlsn::Error>>,
    },
    Complete,
    Error,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::Initialized => write!(f, "Initialized"),
            State::CommitAccepted { .. } => write!(f, "CommitAccepted"),
            State::Committed { .. } => write!(f, "Committed"),
            State::Complete => write!(f, "Complete"),
            State::Error => write!(f, "Error"),
        }
    }
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

#[wasm_bindgen(js_class = Prover)]
impl JsProver {
    #[wasm_bindgen(constructor)]
    pub fn new(config: ProverConfig) -> Result<JsProver> {
        Ok(JsProver {
            config,
            state: State::Initialized,
        })
    }

    /// Set up the prover.
    ///
    /// This performs all MPC setup prior to establishing the connection to the
    /// application server. Unlike the official WASM crate which discards the
    /// session driver, we use a oneshot channel to reclaim the socket after
    /// MPC completes — needed for attestation exchange with the notary.
    pub async fn setup(&mut self, verifier_url: &str) -> Result<()> {
        let State::Initialized = self.state.take() else {
            return Err(JsError::new("prover is not in initialized state"));
        };

        let tls_commit_config = TlsCommitConfig::builder()
            .protocol({
                let mut builder = MpcTlsConfig::builder()
                    .max_sent_data(self.config.max_sent_data)
                    .max_recv_data(self.config.max_recv_data);

                if let Some(value) = self.config.max_recv_data_online {
                    builder = builder.max_recv_data_online(value);
                }

                if let Some(value) = self.config.max_sent_records {
                    builder = builder.max_sent_records(value);
                }

                if let Some(value) = self.config.max_recv_records_online {
                    builder = builder.max_recv_records_online(value);
                }

                if let Some(value) = self.config.defer_decryption_from_start {
                    builder = builder.defer_decryption_from_start(value);
                }

                builder.network(self.config.network.into()).build()
            }?)
            .build()?;

        info!("connecting to verifier");

        let (_, verifier_conn) = WsMeta::connect(verifier_url, None).await?;

        info!("connected to verifier");

        let session = Session::new(verifier_conn.into_io());
        let (driver, mut handle) = session.split();

        // Use a oneshot channel to reclaim the socket after the session driver completes.
        // In WASM, spawn_local is fire-and-forget (no JoinHandle), so the oneshot
        // channel is the only way to get the socket back for attestation exchange.
        let (socket_tx, socket_rx) = futures::channel::oneshot::channel();
        spawn_local(async move {
            let result = driver.await;
            let _ = socket_tx.send(result);
        });

        let prover_config = tlsn::config::prover::ProverConfig::builder().build()?;
        let prover = handle.new_prover(prover_config)?;

        let prover = prover
            .commit(tls_commit_config)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        self.state = State::CommitAccepted {
            prover,
            handle,
            socket_rx,
        };

        Ok(())
    }

    /// Send the HTTP request to the server.
    pub async fn send_request(
        &mut self,
        ws_proxy_url: &str,
        request: HttpRequest,
    ) -> Result<HttpResponse> {
        let State::CommitAccepted {
            prover,
            handle,
            socket_rx,
        } = self.state.take()
        else {
            return Err(JsError::new("prover is not in commit accepted state"));
        };

        let mut builder = TlsClientConfig::builder()
            .server_name(ServerName::Dns(
                self.config
                    .server_name
                    .clone()
                    .try_into()
                    .map_err(|_| JsError::new("invalid server name"))?,
            ))
            .root_store(RootCertStore::mozilla());

        if let Some((certs, key)) = self.config.client_auth.clone() {
            let certs = certs
                .into_iter()
                .map(|cert| {
                    // Try to parse as PEM-encoded, otherwise assume DER.
                    if let Ok(cert) = CertificateDer::from_pem_slice(&cert) {
                        cert
                    } else {
                        CertificateDer(cert)
                    }
                })
                .collect();
            let key = PrivateKeyDer(key);
            builder = builder.client_auth((certs, key));
        }

        let tls_config = builder.build()?;

        info!("connecting to server");

        let (_, server_conn) = WsMeta::connect(ws_proxy_url, None).await?;

        info!("connected to server");

        let (tls_conn, prover_fut) = prover
            .connect(tls_config, server_conn.into_io())
            .map_err(|e| JsError::new(&e.to_string()))?;

        info!("sending request");

        let (response, prover) = futures::try_join!(
            send_request(tls_conn, request),
            prover_fut.map_err(|e| JsError::new(&e.to_string()))
        )?;

        info!("response received");

        self.state = State::Committed {
            prover,
            handle,
            socket_rx,
        };

        Ok(response)
    }

    /// Returns the transcript.
    pub fn transcript(&self) -> Result<Transcript> {
        let State::Committed { prover, .. } = &self.state else {
            return Err(JsError::new("prover is not in committed state"));
        };

        Ok(Transcript::from(prover.transcript()))
    }

    /// Notarize the transcript.
    ///
    /// Commits all transcript data, builds an AttestationRequest, sends it to
    /// the notary over the reclaimed session socket, and receives back a signed
    /// Attestation. Returns hex-encoded bincode of both the Attestation and Secrets.
    pub async fn notarize(&mut self) -> Result<NotarizeOutput> {
        let State::Committed {
            mut prover,
            handle,
            socket_rx,
        } = self.state.take()
        else {
            return Err(JsError::new("prover is not in committed state"));
        };

        info!("starting notarization");

        // Step 1: Parse HTTP transcript and build commit config
        let transcript = HttpTranscript::parse(prover.transcript())
            .map_err(|e| JsError::new(&format!("failed to parse HTTP transcript: {e}")))?;

        let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
        DefaultHttpCommitter::default()
            .commit_transcript(&mut commit_builder, &transcript)
            .map_err(|e| JsError::new(&format!("failed to commit transcript: {e}")))?;
        let transcript_commit = commit_builder
            .build()
            .map_err(|e| JsError::new(&format!("failed to build transcript commit: {e}")))?;

        // Step 2: Build request config
        let mut request_config_builder = RequestConfig::builder();
        request_config_builder.transcript_commit(transcript_commit);
        let request_config = request_config_builder
            .build()
            .map_err(|e| JsError::new(&format!("failed to build request config: {e}")))?;

        // Step 3: Build prove config
        let mut prove_builder = ProveConfig::builder(prover.transcript());
        if let Some(config) = request_config.transcript_commit() {
            prove_builder.transcript_commit(config.clone());
        }
        let prove_config = prove_builder
            .build()
            .map_err(|e| JsError::new(&format!("failed to build prove config: {e}")))?;

        // Step 4: Run the prove protocol
        let ProverOutput {
            transcript_commitments,
            transcript_secrets,
            ..
        } = prover
            .prove(&prove_config)
            .await
            .map_err(|e| JsError::new(&format!("prove failed: {e}")))?;

        // Step 5: Capture transcript data and TLS transcript
        let prover_transcript = prover.transcript().clone();
        let tls_transcript = prover.tls_transcript().clone();

        // Step 6: Close the prover (finalize MPC)
        prover
            .close()
            .await
            .map_err(|e| JsError::new(&format!("prover close failed: {e}")))?;

        info!("MPC finalized, building attestation request");

        // Step 7: Build AttestationRequest
        let server_name = ServerName::Dns(
            self.config
                .server_name
                .clone()
                .try_into()
                .map_err(|_| JsError::new("invalid server name"))?,
        );

        let mut att_builder = AttestationRequest::builder(&request_config);
        att_builder
            .server_name(server_name)
            .handshake_data(HandshakeData {
                certs: tls_transcript
                    .server_cert_chain()
                    .expect("server cert chain is present")
                    .to_vec(),
                sig: tls_transcript
                    .server_signature()
                    .expect("server signature is present")
                    .clone(),
                binding: tls_transcript.certificate_binding().clone(),
            })
            .transcript(prover_transcript)
            .transcript_commitments(transcript_secrets, transcript_commitments);

        let (request, secrets) = att_builder
            .build(&CryptoProvider::default())
            .map_err(|e| JsError::new(&format!("failed to build attestation request: {e}")))?;

        // Step 8: Close session handle and reclaim socket via oneshot channel
        handle.close();

        info!("reclaiming session socket");

        let mut socket = socket_rx
            .await
            .map_err(|_| JsError::new("session driver channel cancelled"))?
            .map_err(|e| JsError::new(&format!("session driver error: {e}")))?;

        // Step 9: Send attestation request to notary
        let request_bytes = bincode::serialize(&request)
            .map_err(|e| JsError::new(&format!("failed to serialize request: {e}")))?;

        info!("sending attestation request ({} bytes)", request_bytes.len());

        socket
            .write_all(&request_bytes)
            .await
            .map_err(|e| JsError::new(&format!("failed to send request: {e}")))?;
        socket
            .close()
            .await
            .map_err(|e| JsError::new(&format!("failed to close write end: {e}")))?;

        // Step 10: Receive attestation from notary
        let mut attestation_bytes = Vec::new();
        socket
            .read_to_end(&mut attestation_bytes)
            .await
            .map_err(|e| JsError::new(&format!("failed to read attestation: {e}")))?;

        let attestation: Attestation = bincode::deserialize(&attestation_bytes)
            .map_err(|e| JsError::new(&format!("failed to deserialize attestation: {e}")))?;

        info!("attestation received, validating");

        // Validate the attestation is consistent with our request
        let provider = CryptoProvider::default();
        request
            .validate(&attestation, &provider)
            .map_err(|e| JsError::new(&format!("attestation validation failed: {e}")))?;

        info!("notarization complete");

        // Serialize to hex-encoded bincode
        let attestation_hex = hex::encode(
            bincode::serialize(&attestation)
                .map_err(|e| JsError::new(&format!("failed to serialize attestation: {e}")))?,
        );
        let secrets_hex = hex::encode(
            bincode::serialize(&secrets)
                .map_err(|e| JsError::new(&format!("failed to serialize secrets: {e}")))?,
        );

        self.state = State::Complete;

        Ok(NotarizeOutput {
            attestation: attestation_hex,
            secrets: secrets_hex,
        })
    }
}

async fn send_request(conn: TlsConnection, request: HttpRequest) -> Result<HttpResponse> {
    let conn = FuturesIo::new(conn);
    let request = hyper::Request::<Full<Bytes>>::try_from(request)?;

    let (mut request_sender, conn) = hyper::client::conn::http1::handshake(conn).await?;

    spawn_local(async move { conn.await.expect("connection runs to completion") });

    let response = request_sender.send_request(request).await?;

    let (response, body) = response.into_parts();

    // Consume the body to ensure the full response is read into the transcript.
    let _body = body.collect().await?;

    let headers = response
        .headers
        .into_iter()
        .map(|(k, v)| {
            (
                k.map(|k| k.to_string()).unwrap_or_default(),
                v.as_bytes().to_vec(),
            )
        })
        .collect();

    Ok(HttpResponse {
        status: response.status.as_u16(),
        headers,
    })
}
