#!/usr/bin/env python3
"""Dev server with Cross-Origin Isolation headers for SharedArrayBuffer."""

import http.server
import sys


class COIHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        super().end_headers()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = http.server.HTTPServer(("0.0.0.0", port), COIHandler)
    print(f"Serving on http://localhost:{port} (cross-origin isolated)")
    server.serve_forever()
