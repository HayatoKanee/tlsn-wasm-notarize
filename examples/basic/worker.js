import init, { initialize, Prover, Presentation, test_rayon } from '../../pkg/tlsn_wasm_notarize.js';

let initialized = false;

self.onmessage = async (e) => {
  const { type, data } = e.data;

  try {
    if (type === 'init') {
      if (initialized) {
        self.postMessage({ type: 'log', cls: 'warn', msg: 'Already initialized, skipping' });
        self.postMessage({ type: 'done', step: 'init' });
        return;
      }
      self.postMessage({ type: 'log', cls: 'info', msg: 'Initializing WASM...' });
      await init();
      self.postMessage({ type: 'log', cls: 'ok', msg: 'WASM loaded' });

      await initialize(null, data.threadCount);
      self.postMessage({ type: 'log', cls: 'ok', msg: 'Rayon thread pool initialized (' + data.threadCount + ' threads)' });
      // Verify rayon thread pool works
      const result = test_rayon();
      const expected = 499500;
      const pass = result.toString() === expected.toString();
      self.postMessage({ type: 'log', cls: pass ? 'ok' : 'err', msg: 'Rayon test: sum(0..1000) = ' + result + (pass ? '' : ' FAIL (expected ' + expected + ')') });

      initialized = true;
      self.postMessage({ type: 'done', step: 'init' });
    }

    if (type === 'run') {
      const { notaryUrl, targetUrl, targetHost, sessionId } = data;

      // Create Prover
      self.postMessage({ type: 'log', cls: 'info', msg: 'Creating Prover...' });
      const prover = new Prover({
        server_name: targetHost,
        max_sent_data: 4096,
        max_recv_data: 16384,
        network: 'Bandwidth',
      });
      self.postMessage({ type: 'log', cls: 'ok', msg: 'Prover created' });

      // Setup (MPC handshake)
      const wsUrl = notaryUrl.replace('http', 'ws');
      self.postMessage({ type: 'log', cls: 'info', msg: 'Connecting to notary at ' + wsUrl + '/notarize?sessionId=' + sessionId });
      const setupStart = performance.now();
      await prover.setup(wsUrl + '/notarize?sessionId=' + sessionId);
      self.postMessage({ type: 'log', cls: 'ok', msg: 'MPC setup complete in ' + ((performance.now() - setupStart) / 1000).toFixed(1) + 's' });

      // Send HTTP request through MPC-TLS
      self.postMessage({ type: 'log', cls: 'info', msg: 'Sending request to ' + targetUrl + '...' });
      const response = await prover.send_request(
        wsUrl + '/proxy?token=' + targetHost + ':443',
        {
          uri: targetUrl,
          method: 'GET',
          headers: {
            'Host': Array.from(new TextEncoder().encode(targetHost)),
            'Accept': Array.from(new TextEncoder().encode('*/*')),
            'Accept-Encoding': Array.from(new TextEncoder().encode('identity')),
            'Connection': Array.from(new TextEncoder().encode('close')),
            'User-Agent': Array.from(new TextEncoder().encode('tlsn-wasm-notarize/0.1.0')),
          },
          body: undefined,
        }
      );
      self.postMessage({ type: 'log', cls: 'ok', msg: 'Response: HTTP ' + response.status });

      // Get transcript
      const transcript = prover.transcript();
      self.postMessage({ type: 'log', cls: 'info', msg: 'Transcript: sent=' + transcript.sent.length + ' bytes, recv=' + transcript.recv.length + ' bytes' });

      const sentText = new TextDecoder().decode(new Uint8Array(transcript.sent));
      const recvText = new TextDecoder().decode(new Uint8Array(transcript.recv));
      self.postMessage({ type: 'log', cls: 'info', msg: '--- SENT ---\n' + sentText.slice(0, 500) });
      self.postMessage({ type: 'log', cls: 'info', msg: '--- RECV ---\n' + recvText.slice(0, 500) });

      // Notarize
      self.postMessage({ type: 'log', cls: 'warn', msg: 'Starting notarization...' });
      const startTime = performance.now();
      const { attestation, secrets } = await prover.notarize();
      const elapsed = ((performance.now() - startTime) / 1000).toFixed(1);
      self.postMessage({ type: 'log', cls: 'ok', msg: 'Notarization complete in ' + elapsed + 's' });
      self.postMessage({ type: 'log', cls: 'ok', msg: 'Attestation: ' + attestation.length + ' hex chars' });
      self.postMessage({ type: 'log', cls: 'ok', msg: 'Secrets: ' + secrets.length + ' hex chars' });

      // Build Presentation
      self.postMessage({ type: 'log', cls: 'info', msg: 'Building presentation (reveal all)...' });
      const presentation = new Presentation({
        attestation_hex: attestation,
        secrets_hex: secrets,
        reveal: {
          sent: [{ start: 0, end: transcript.sent.length }],
          recv: [{ start: 0, end: transcript.recv.length }],
        },
      });
      const proofHex = presentation.serialize();
      self.postMessage({ type: 'log', cls: 'ok', msg: 'Presentation: ' + proofHex.length + ' hex chars' });

      self.postMessage({ type: 'log', cls: 'ok', msg: '=== ALL TESTS PASSED ===' });
      self.postMessage({ type: 'done', step: 'run' });
    }
  } catch (err) {
    self.postMessage({ type: 'error', msg: err.message || String(err) });
  }
};
