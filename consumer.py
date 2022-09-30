#!/usr/bin/env python

import asyncio
from genericpath import isfile
import os, sys
import websockets
from datetime import datetime
import json
import pathlib
import ssl

from pyeebus import x509_utils

CONSUMER_PRIVATE_KEY_FN = os.getenv('CONSUMER_PRIVATE_KEY_FN', 'consumer.key')
CONSUMER_PUBLIC_KEY_FN = os.getenv('CONSUMER_PUBLIC_KEY_FN', 'consumer.pem')
CONSUMER_CERT_FN = os.getenv('CONSUMER_CERT_FN', 'consumer.crt')

WEBSOCKET_URL = os.getenv('WEBSOCKET_URL', "ws://localhost:8765")


if not os.path.isfile(CONSUMER_PRIVATE_KEY_FN) and not os.path.isfile(CONSUMER_PUBLIC_KEY_FN) and not os.path.isfile(CONSUMER_CERT_FN):
    print(f"generating public and private keys and certificate...")
    x509_utils.generate_key(private_key_fn=CONSUMER_PRIVATE_KEY_FN, public_key_fn=CONSUMER_PUBLIC_KEY_FN)
    x509_utils.generate_x509_keys_by_fn(public_key_pem_fn=CONSUMER_PUBLIC_KEY_FN, private_key_pem_fn=CONSUMER_PRIVATE_KEY_FN, cert_fn=CONSUMER_CERT_FN)
else:
    print(f"One of the following files does exist already, thus, NOT creating any of those: {CONSUMER_PRIVATE_KEY_FN} {CONSUMER_PUBLIC_KEY_FN} {CONSUMER_CERT_FN}")

assert os.path.isfile(CONSUMER_PRIVATE_KEY_FN)
assert os.path.isfile(CONSUMER_PUBLIC_KEY_FN)
assert os.path.isfile(CONSUMER_CERT_FN)



ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
#ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE # just about any cert is accepted
ssl_context.load_verify_locations(CONSUMER_CERT_FN) # TODO: do we need this?

async def hello():
    uri = WEBSOCKET_URL
    #async with websockets.connect(uri, ssl=ssl_context) as websocket:
    async with websockets.connect(uri) as websocket:
        await websocket.send('hello')
        while True:
            msg = await websocket.recv()
            print(msg)

if __name__ == "__main__":
    asyncio.run(hello())
