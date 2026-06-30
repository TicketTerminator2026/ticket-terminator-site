#!/usr/bin/env python3
"""
Ticket Terminator local dev server.
- Serves dashboard.html, auth.html, dashboard.css from this folder at localhost:8888
- Proxies /.netlify/functions/* to the live Netlify site so real Airtable data flows through
"""

import http.server
import urllib.request
import urllib.error
import os
import sys

PORT = 8888
LIVE_SITE = "https://ticket-terminator-intake.netlify.app"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MIME = {
    ".html": "text/html; charset=utf-8",
    ".css":  "text/css; charset=utf-8",
    ".js":   "application/javascript; charset=utf-8",
    ".json": "application/json",
    ".png":  "image/png",
    ".ico":  "image/x-icon",
    ".svg":  "image/svg+xml",
}

class DevHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"  {self.command} {self.path}")

    def _proxy_to_netlify(self):
        url = LIVE_SITE + self.path
        headers = {}
        for h in ("Authorization", "Content-Type", "X-Staff-Token", "X-Staff-Role"):
            v = self.headers.get(h)
            if v:
                headers[h] = v

        body = None
        cl = self.headers.get("Content-Length")
        if cl:
            body = self.rfile.read(int(cl))

        req = urllib.request.Request(url, data=body, headers=headers, method=self.command)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                ct = resp.headers.get("Content-Type", "application/json")
                self.send_response(resp.status)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)

    def _serve_file(self, path):
        local = os.path.join(BASE_DIR, path.lstrip("/"))
        if not os.path.isfile(local):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")
            return
        ext = os.path.splitext(local)[1].lower()
        ct = MIME.get(ext, "application/octet-stream")
        with open(local, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Staff-Token, X-Staff-Role")
        self.end_headers()

    def do_GET(self):
        p = self.path.split("?")[0]
        if p.startswith("/.netlify/functions/"):
            self._proxy_to_netlify()
        elif p == "/" or p == "":
            self._serve_file("/dashboard.html")
        else:
            self._serve_file(p)

    def do_POST(self):
        self._proxy_to_netlify()

    def do_PATCH(self):
        self._proxy_to_netlify()

    def do_DELETE(self):
        self._proxy_to_netlify()

if __name__ == "__main__":
    os.chdir(BASE_DIR)
    server = http.server.HTTPServer(("", PORT), DevHandler)
    print(f"✅ Serving on port {PORT}  →  http://localhost:{PORT}")
    print("   Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
