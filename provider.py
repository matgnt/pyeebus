#!/usr/bin/env python

import asyncio
from genericpath import isfile
import os, sys
import wsproto
from datetime import datetime
import json
import pathlib
import socket
from OpenSSL import SSL
import logging

from pyeebus import x509_utils

logging.basicConfig(
    format="%(message)s",
    level=logging.DEBUG,
)

PROVIDER_PRIVATE_KEY_FN = os.getenv('PROVIDER_PRIVATE_KEY_FN', 'provider.key')
PROVIDER_PUBLIC_KEY_FN = os.getenv('PROVIDER_PUBLIC_KEY_FN', 'provider.pem')
PROVIDER_CERT_FN = os.getenv('PROVIDER_CERT_FN', 'provider.crt')

WEBSOCKET_HOST = os.getenv('WEBSOCKET_HOST', '127.0.0.1')
WEBSOCKET_PORT = int(os.getenv('WEBSOCKET_PORT', '8765'))


if not os.path.isfile(PROVIDER_PRIVATE_KEY_FN) and not os.path.isfile(PROVIDER_PUBLIC_KEY_FN) and not os.path.isfile(PROVIDER_CERT_FN):
    print(f"generating public and private keys and certificate...")
    x509_utils.generate_key(private_key_fn=PROVIDER_PRIVATE_KEY_FN, public_key_fn=PROVIDER_PUBLIC_KEY_FN)
    x509_utils.generate_x509_keys_by_fn(public_key_pem_fn=PROVIDER_PUBLIC_KEY_FN, private_key_pem_fn=PROVIDER_PRIVATE_KEY_FN, cert_fn=PROVIDER_CERT_FN)
else:
    print(f"One of the following files does exist already, thus, NOT creating any of those: {PROVIDER_PRIVATE_KEY_FN} {PROVIDER_PUBLIC_KEY_FN} {PROVIDER_CERT_FN}")

assert os.path.isfile(PROVIDER_PRIVATE_KEY_FN)
assert os.path.isfile(PROVIDER_PUBLIC_KEY_FN)
assert os.path.isfile(PROVIDER_CERT_FN)

connections = {}

def verify_cb(conn, cert, err, depth, ok):
    print(cert)

    return 1 # TODO: security: 1 means cert check ok!

ssl_context = SSL.Context(SSL.SSLv23_METHOD)
ssl_context.set_cipher_list(b"TLS_AES_128_GCM_SHA256:AES128-GCM-SHA256") # do we need this?
ssl_context.set_verify(SSL.VERIFY_PEER, callback=verify_cb)
ssl_context.use_certificate_file(certfile=PROVIDER_CERT_FN)
ssl_context.use_privatekey_file(keyfile=PROVIDER_PRIVATE_KEY_FN)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

conn = SSL.Connection(ssl_context, sock)
sock.bind(('', WEBSOCKET_PORT))
sock.listen(5)

while True:
    incoming_sock, fromaddr = sock.accept()
    incoming_ssl_conn = SSL.Connection(ssl_context, incoming_sock)
    incoming_ssl_conn.set_accept_state()
    incoming_ssl_conn.do_handshake()
    print(f"List of ciphers: {incoming_ssl_conn.get_cipher_list()}")
    req = incoming_ssl_conn.read(4096)
    print(req)
    incoming_ssl_conn.write(b"HTTP/1.1 200 OK\r\nServer: my-special\r\nContent-length: 10\r\n\r\nHello!\r\n\r\n")
    incoming_ssl_conn.set_shutdown(SSL.SENT_SHUTDOWN)
