import socket
from dataclasses import dataclass

@dataclass
class TLSServerInfo:
    """
    Stores info about a TLSServer
    """
    cert: dict
    tls_version: str


def get_tlsinfo(context, args) -> TLSServerInfo:
    """
    Connects to the server and gets the cert
    """
    # wrap socket with SSLContext as recommended: https://docs.python.org/3/library/ssl.html#certificate-chains
    with socket.create_connection((args.hostname, args.port)) as sock:
        with context.wrap_socket(sock, server_hostname=args.hostname) as tls_sock:
            return TLSServerInfo(cert=tls_sock.getpeercert(), tls_version=tls_sock.version())