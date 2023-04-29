import base64
import hashlib
import os
import socket
import ssl
import time
from pathlib import Path

import pytest
import trustme
import urllib3


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


def wait_for_open_port(port: int, host: str = "localhost", timeout: int = 30):
    start_time = time.time()
    while True:
        try:
            sock = socket.create_connection((host, port), timeout=0.1)
            sock.close()
            break
        except socket.error:
            time.sleep(0.01)
            if time.time() - start_time > timeout:
                raise TimeoutError()


@pytest.fixture
def httpsserver_custom(cert_dir):
    """The returned ``httpsserver`` (note the additional S!) provides a
    threaded HTTP server instance similar to funcarg ``httpserver`` but with
    SSL encryption.
    """
    from pytest_localserver import https

    key = os.path.join(cert_dir, "server.pem")

    server = https.SecureContentServer(key=key, cert=key)
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
def test_ssl_cert_pinning(httpsserver_custom, cert_dir, cert_name):
    wait_for_open_port(httpsserver_custom.server_address[1])
    httpsserver_custom.serve_content(
        code=202, content="", headers={"Location": "https://example.com/foo"}
    )
    server_cert = os.path.join(cert_dir, cert_name)
    http = urllib3.PoolManager(
        assert_fingerprint=cert_fingerprint(server_cert),
        assert_hostname=False,
        cert_reqs=ssl.CERT_NONE,
    )

    if cert_name == "server.pem":
        resp = http.request("GET", httpsserver_custom.url)
        assert resp.status == 202
    elif cert_name == "wrong_cert.pem":
        with pytest.raises(urllib3.exceptions.MaxRetryError):
            http.request("GET", httpsserver_custom.url)
    else:
        raise ValueError(cert_name)
