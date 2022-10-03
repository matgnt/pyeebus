#!/usr/bin/env python

import asyncio
from genericpath import isfile
import os, sys
import websockets
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

CONSUMER_PRIVATE_KEY_FN = os.getenv('CONSUMER_PRIVATE_KEY_FN', 'consumer.key')
CONSUMER_PUBLIC_KEY_FN = os.getenv('CONSUMER_PUBLIC_KEY_FN', 'consumer.pem')
CONSUMER_CERT_FN = os.getenv('CONSUMER_CERT_FN', 'consumer.crt')

WEBSOCKET_URL = os.getenv('WEBSOCKET_URL', "wss://localhost:8765")


if not os.path.isfile(CONSUMER_PRIVATE_KEY_FN) and not os.path.isfile(CONSUMER_PUBLIC_KEY_FN) and not os.path.isfile(CONSUMER_CERT_FN):
    print(f"generating public and private keys and certificate...")
    x509_utils.generate_key(private_key_fn=CONSUMER_PRIVATE_KEY_FN, public_key_fn=CONSUMER_PUBLIC_KEY_FN)
    x509_utils.generate_x509_keys_by_fn(public_key_pem_fn=CONSUMER_PUBLIC_KEY_FN, private_key_pem_fn=CONSUMER_PRIVATE_KEY_FN, cert_fn=CONSUMER_CERT_FN)
else:
    print(f"One of the following files does exist already, thus, NOT creating any of those: {CONSUMER_PRIVATE_KEY_FN} {CONSUMER_PUBLIC_KEY_FN} {CONSUMER_CERT_FN}")

assert os.path.isfile(CONSUMER_PRIVATE_KEY_FN)
assert os.path.isfile(CONSUMER_PUBLIC_KEY_FN)
assert os.path.isfile(CONSUMER_CERT_FN)


def verify_cb(conn, cert, err, depth, ok):
    print(cert)

    return 1 # TODO: security: 1 means cert check ok!

ssl_context = SSL.Context(SSL.SSLv23_METHOD)
ssl_context.set_verify(SSL.VERIFY_PEER, callback=verify_cb)
ssl_context.use_certificate_file(certfile=CONSUMER_CERT_FN)
ssl_context.use_privatekey_file(keyfile=CONSUMER_PRIVATE_KEY_FN)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

conn = SSL.Connection(ssl_context, sock)
conn.connect(('localhost', 8765))
conn.do_handshake()
conn.send("""GET / HTTP/1.0""")

while True:
    msg = conn.recv(4096)
    print(msg)

