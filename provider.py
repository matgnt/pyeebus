#!/usr/bin/env python

import asyncio
from genericpath import isfile
import os, sys
import websockets
from datetime import datetime
import json
import pathlib
import ssl
import logging

from pyeebus import x509_utils

logging.basicConfig(
    format="%(message)s",
    level=logging.DEBUG,
)

PROVIDER_PRIVATE_KEY_FN = os.getenv('PROVIDER_PRIVATE_KEY_FN', 'provider.key')
PROVIDER_PUBLIC_KEY_FN = os.getenv('PROVIDER_PUBLIC_KEY_FN', 'provider.pem')
PROVIDER_CERT_FN = os.getenv('PROVIDER_CERT_FN', 'provider.crt')

WEBSOCKET_HOST = os.getenv('WEBSOCKET_HOST', 'localhost')
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

#ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
#ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
#ssl_context.verify_mode = ssl.CERT_REQUIRED
#ssl_context.check_hostname = False
#ssl_context.load_cert_chain(certfile=PROVIDER_CERT_FN, keyfile=PROVIDER_PRIVATE_KEY_FN)
#ssl_context.load_verify_locations(PROVIDER_CERT_FN) # TODO: do we need this?

#ssl_context = ssl._create_unverified_context(purpose=ssl.Purpose.CLIENT_AUTH, certfile=PROVIDER_CERT_FN, keyfile=PROVIDER_PRIVATE_KEY_FN, cafile=PROVIDER_CERT_FN)
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
ssl_context.load_cert_chain
ssl_context.post_handshake_auth = True


async def send_data():
    while True:
        for id, ws in connections.items():
            data = {
                'id': id,
                'timestamp': datetime.now().isoformat(), 
            }
            await ws.send(json.dumps(data))
        await asyncio.sleep(5.0)

async def handler(websocket):
    # new connection
    global connections
    connections[str(websocket.id)] = websocket
    websocket.send('added to list')
    peercert = websocket.transport.get_extra_info('peercert')
    print(peercert)
    async for msg in websocket:
        print(msg)

async def connection_request(path, request_headers):
    """
    Ref: https://websockets.readthedocs.io/en/stable/reference/server.html#websockets.server.WebSocketServerProtocol.process_request
    """
    # try checking mTLS params here

    return None # None to continue with regular handshake

async def start_websocket():
    async with websockets.serve(handler, WEBSOCKET_HOST, WEBSOCKET_PORT, ssl=ssl_context, process_request=connection_request):
    #async with websockets.serve(handler, WEBSOCKET_HOST, WEBSOCKET_PORT, process_request=connection_request):
        await asyncio.Future()

async def main():
    await asyncio.gather(
        start_websocket(),
        send_data()
    )
    print('xxx')

if __name__ == "__main__":
    asyncio.run(main())
