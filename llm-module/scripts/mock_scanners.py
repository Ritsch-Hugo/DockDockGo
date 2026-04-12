#!/usr/bin/env python3
"""
Serveurs HTTP mock pour les scanners CVE et compliance.

Lance deux serveurs sur :
  - Port 3001 → mock scanner compliance (POST /v1/scan)
  - Port 3002 → mock scanner CVE/Trivy  (POST /v1/scan-upload)

Retournent des réponses JSON valides simulant une image propre.
Usage : python3 scripts/mock_scanners.py
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


# ── Réponses mock ─────────────────────────────────────────────────────────────

MOCK_STATIC_RESPONSE = {
    "SchemaVersion": 2,
    "ArtifactName": "mock-image",
    "ArtifactType": "container_image",
    "Metadata": {
        "OS": {"Family": "alpine", "Name": "3.18"},
        "ImageConfig": {"architecture": "amd64"}
    },
    "Results": [
        {
            "Target": "mock-image (alpine 3.18)",
            "Class": "os-pkgs",
            "Type": "alpine",
            "Vulnerabilities": []  # Aucune CVE → image propre
        }
    ]
}

MOCK_COMPLIANCE_RESPONSE = {
    "summary": {
        "pass": 8,
        "warn": 1,
        "fail": 0   # Aucun FAIL → image conforme
    },
    "findings": [
        {"rule": "no-root-user",    "status": "PASS", "detail": "Non-root user detected"},
        {"rule": "no-secrets-env",  "status": "PASS", "detail": "No secrets in env vars"},
        {"rule": "safe-entrypoint", "status": "PASS", "detail": "Entrypoint looks safe"},
        {"rule": "no-privileged",   "status": "PASS", "detail": "No privileged mode"},
        {"rule": "labels-present",  "status": "WARN", "detail": "Missing optional labels"},
        {"rule": "no-curl-wget",    "status": "PASS", "detail": "No curl/wget found"},
        {"rule": "no-ssh",          "status": "PASS", "detail": "No SSH server"},
        {"rule": "no-shell-history","status": "PASS", "detail": "No shell history files"},
        {"rule": "no-setuid",       "status": "PASS", "detail": "No setuid binaries found"},
    ]
}


# ── Handler commun ─────────────────────────────────────────────────────────────

class MockHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        # Consommer le corps de la requête (multipart ou JSON)
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            self.rfile.read(content_length)

        port = self.server.server_address[1]
        path = self.path

        print(f"[MOCK:{port}] POST {path} reçu")

        # Choisir la réponse selon le port
        if port == 3002:
            body = json.dumps(MOCK_STATIC_RESPONSE).encode()
            print(f"[MOCK:3002] → réponse Trivy mock (0 CVE)")
        elif port == 3001:
            body = json.dumps(MOCK_COMPLIANCE_RESPONSE).encode()
            print(f"[MOCK:3001] → réponse compliance mock (0 FAIL)")
        else:
            body = json.dumps({"status": "OK"}).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # Silence le log par défaut (trop verbeux pour les multipart)
        pass


# ── Lancement des deux serveurs ────────────────────────────────────────────────

def run_server(port):
    server = HTTPServer(("0.0.0.0", port), MockHandler)
    name = "CVE" if port == 3002 else "Compliance"
    print(f"[MOCK] Scanner {name} mock sur http://0.0.0.0:{port}")
    server.serve_forever()


if __name__ == "__main__":
    print("=" * 60)
    print("  Mock scanners — DocDockGo test")
    print("  Port 3001 : compliance scanner (stub)")
    print("  Port 3002 : CVE scanner / Trivy (stub)")
    print("  Ctrl+C pour arrêter")
    print("=" * 60)

    t1 = threading.Thread(target=run_server, args=(3001,), daemon=True)
    t2 = threading.Thread(target=run_server, args=(3002,), daemon=True)
    t1.start()
    t2.start()

    try:
        t1.join()
    except KeyboardInterrupt:
        print("\n[MOCK] Arrêt des serveurs mock")
