import base64
import hashlib
import json
import os
import socket
import ssl
import time
from pathlib import Path

import pytest
import trustme
import urllib3
from pytest_httpserver import HTTPServer


@pytest.fixture(scope="session")
def cert_dir(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("certs")
    ca = trustme.CA()

    server_cert = ca.issue_cert("localhost")
    server_cert.private_key_and_cert_chain_pem.write_to_path(
        str(tmp_path / "server.pem")
    )

    wrong_server_cert = ca.issue_cert("localhost")
    wrong_server_cert.private_key_and_cert_chain_pem.write_to_path(
        str(tmp_path / "wrong_cert.pem")
    )

    yield str(tmp_path)


@pytest.fixture(scope="session")
def https_server(cert_dir):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(os.path.join(cert_dir, "server.pem"))
    server = HTTPServer(ssl_context=context)
    server.expect_request("/foobar").respond_with_json({"foo": "bar"})

    server.start()
    yield server
    server.stop()


def read_pem_file(file_obj) -> bytes:
    cert = b""
    for line in file_obj:
        if line.startswith(b"-----BEGIN CERTIFICATE-----"):
            break
    # scan until we find the first END CERTIFICATE marker
    for line in file_obj:
        if line.startswith(b"-----END CERTIFICATE-----"):
            break
        cert += line.strip()
    return base64.b64decode(cert)


def cert_fingerprint(server_cert):
    with open(server_cert, "rb") as f:
        cert_data = read_pem_file(f)
    digest = hashlib.sha256()
    digest.update(cert_data)
    return digest.hexdigest()


@pytest.mark.parametrize("cert_name", ["server.pem", "wrong_cert.pem"])
def test_ssl_cert_pinning(https_server, cert_dir, cert_name):
    server_cert = os.path.join(cert_dir, cert_name)
    http = urllib3.PoolManager(
        assert_fingerprint=cert_fingerprint(server_cert),
        assert_hostname=False,
        cert_reqs=ssl.CERT_NONE,
    )

    if cert_name == "server.pem":
        resp = http.request("GET", https_server.url_for("/foobar"))
        assert resp.status == 200
        assert json.loads(resp.data) == {"foo": "bar"}
    elif cert_name == "wrong_cert.pem":
        with pytest.raises(urllib3.exceptions.MaxRetryError):
            http.request("GET", https_server.url_for("/foobar"))
    else:
        raise ValueError(cert_name)
