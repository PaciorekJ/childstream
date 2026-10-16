"""One-request ChildStream loopback TLS fixture. Uses a committed test-only certificate.

The private key is a public test fixture and must never be used by production code.
No certificate is installed into an OS trust store.
"""
import argparse
import hashlib
import pathlib
import socket
import ssl
import time

parser = argparse.ArgumentParser()
parser.add_argument("--metadata", required=True)
parser.add_argument("--code", type=int, required=True)
parser.add_argument("--response-file", required=True)
parser.add_argument("--delay", type=int, default=0)
args = parser.parse_args()

base = pathlib.Path(__file__).resolve().parent / "fixtures"
certificate = base / "tls-test-cert.pem"
key = base / "tls-test-key.pem"
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(str(certificate), str(key))
der = ssl.PEM_cert_to_DER_cert(certificate.read_text(encoding="ascii"))
fingerprint = hashlib.sha256(der).hexdigest().upper()
metadata = pathlib.Path(args.metadata)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    metadata.write_text(f"{listener.getsockname()[1]}|{fingerprint}", encoding="ascii")
    try:
        raw_client, _ = listener.accept()
        with raw_client:
            with context.wrap_socket(raw_client, server_side=True) as peer:
                peer.settimeout(5)
                header = bytearray()
                while len(header) < 8192 and not header.endswith(b"\r\n\r\n"):
                    data = peer.recv(1)
                    if not data:
                        break
                    header.extend(data)
                request = header.decode("ascii", errors="replace")
                length = 0
                for line in request.split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        length = int(line.split(":", 1)[1].strip())
                body = bytearray()
                while len(body) < min(length, 4096):
                    data = peer.recv(min(length, 4096) - len(body))
                    if not data:
                        break
                    body.extend(data)
                (metadata.parent / (metadata.name + ".request")).write_text(
                    request + "\nBODY:" + body.decode("utf-8", errors="replace"), encoding="utf-8")
                if args.delay:
                    time.sleep(args.delay / 1000)
                value = pathlib.Path(args.response_file).read_bytes()
                label = "OK" if args.code == 200 else "Found" if args.code == 302 else "Unauthorized"
                redirect = "Location: https://example.com/steal\r\n" if args.code == 302 else ""
                prefix = (f"HTTP/1.1 {args.code} {label}\r\nContent-Type: application/json\r\n"
                          f"{redirect}Content-Length: {len(value)}\r\nConnection: close\r\n\r\n").encode("ascii")
                peer.sendall(prefix + value)
    except Exception as error:
        (metadata.parent / (metadata.name + ".error")).write_text(repr(error), encoding="utf-8")
