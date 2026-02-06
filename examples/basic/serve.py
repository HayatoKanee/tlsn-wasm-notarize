#!/usr/bin/env python3
"""Simple HTTP server with COOP/COEP headers for SharedArrayBuffer support."""

import http.server
import os
import sys

PORT = 8080

class COOPHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Required for SharedArrayBuffer (needed by WASM threads)
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        super().end_headers()

    def guess_type(self, path):
        if path.endswith('.wasm'):
            return 'application/wasm'
        return super().guess_type(path)

if __name__ == '__main__':
    # Serve from repo root so pkg/ is accessible
    os.chdir(os.path.join(os.path.dirname(__file__), '..', '..'))
    print(f'Serving at http://localhost:{PORT}/examples/basic/')
    print(f'COOP/COEP headers enabled for SharedArrayBuffer')
    http.server.HTTPServer(('', PORT), COOPHandler).serve_forever()
