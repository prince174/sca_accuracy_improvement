"""Real HTTPS artifact download and smart-HTTP Git checkout, with local fixtures."""

import hashlib
import json
import os
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from sca_accuracy.remote import checkout, download_sbom


def test_real_https_artifact_and_exact_git_checkout(tmp_path, monkeypatch):
    openssl = shutil.which("openssl")
    if not openssl:
        bundled = Path("C:/Program Files/Git/usr/bin/openssl.exe")
        if bundled.is_file():
            openssl = str(bundled)
    assert openssl, "Install OpenSSL to run HTTPS integration tests"

    def run(*command, cwd=None):
        return (
            subprocess.run(command, cwd=cwd, check=True, capture_output=True)
            .stdout.decode()
            .strip()
        )

    certificate = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    run(
        openssl,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key),
        "-out",
        str(certificate),
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
    )
    origin = tmp_path / "origin"
    origin.mkdir()
    run("git", "init", "--quiet", cwd=origin)
    (origin / "package.json").write_text('{"name":"fixture","version":"1.0.0"}')
    run("git", "add", "package.json", cwd=origin)
    run(
        "git",
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-qm",
        "fixture",
        cwd=origin,
    )
    commit = run("git", "rev-parse", "HEAD", cwd=origin)
    run("git", "clone", "--bare", str(origin), str(tmp_path / "repo.git"))
    content = json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
    ).encode()
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.respond()

        def do_POST(self):
            self.respond()

        def respond(self):
            url = urlsplit(self.path)
            token = "Bearer artifact-test" if url.path == "/bom.json" else "Bearer git-test"
            if self.headers.get("Authorization") != token:
                self.send_error(401)
                return
            seen.append(url.path)
            if url.path == "/bom.json":
                self.send_response(200)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            environment = os.environ.copy()
            environment.update(
                {
                    "GIT_PROJECT_ROOT": str(tmp_path),
                    "GIT_HTTP_EXPORT_ALL": "1",
                    "PATH_INFO": url.path,
                    "QUERY_STRING": url.query,
                    "REQUEST_METHOD": self.command,
                    "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                    "CONTENT_LENGTH": self.headers.get("Content-Length", "0"),
                    "REMOTE_USER": "fixture",
                    "REMOTE_ADDR": "127.0.0.1",
                }
            )
            body = self.rfile.read(int(environment["CONTENT_LENGTH"]))
            response = subprocess.run(
                ["git", "http-backend"],
                input=body,
                env=environment,
                capture_output=True,
                check=True,
            ).stdout
            headers, _, payload = response.partition(b"\r\n\r\n")
            status = 200
            pairs = []
            for line in headers.decode().splitlines():
                name, value = line.split(":", 1)
                if name.lower() == "status":
                    status = int(value.strip().split()[0])
                else:
                    pairs.append((name, value.strip()))
            self.send_response(status)
            for name, value in pairs:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host = f"localhost:{server.server_port}"
    monkeypatch.setenv("SCA_CA_BUNDLE", str(certificate))
    monkeypatch.setenv("SCA_TEAMCITY_HOSTS", host)
    monkeypatch.setenv("SCA_BITBUCKET_HOSTS", host)
    monkeypatch.setenv("SCA_TEAMCITY_TOKEN", "artifact-test")
    monkeypatch.setenv("SCA_BITBUCKET_TOKEN", "git-test")
    monkeypatch.delenv("SCA_TEAMCITY_TOKEN_FILE", raising=False)
    monkeypatch.delenv("SCA_BITBUCKET_TOKEN_FILE", raising=False)
    try:
        checksum = download_sbom(f"https://{host}/bom.json", tmp_path / "download.json")
        assert checksum == hashlib.sha256(content).hexdigest()
        resolved = checkout(f"https://{host}/repo.git", commit, tmp_path / "checkout")
        assert resolved == commit
        assert (tmp_path / "checkout/package.json").read_bytes() == (
            origin / "package.json"
        ).read_bytes()
        monkeypatch.delenv("SCA_CA_BUNDLE")
        with pytest.raises(RuntimeError, match="TLS"):
            download_sbom(f"https://{host}/bom.json", tmp_path / "untrusted.json")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    assert "/bom.json" in seen
    assert "/repo.git/git-upload-pack" in seen
