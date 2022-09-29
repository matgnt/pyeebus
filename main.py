#!/usr/bin/env python

import asyncio
import os, sys
from wsgiref.headers import Headers
from websockets import connect, exceptions
from websockets.datastructures import Headers
from websockets.typing import Subprotocol
from datetime import datetime
import json


PASSWORD = os.getenv('PASSWORD', '')

if not PASSWORD:
    print(f"Please set ENV var PASSWORD to access the websocket. It is the admin / wpa2 password of the vitoconnect box.")
    sys.exit()

async def eebus(uri):
    headers= Headers()
    #headers['Sec-Websocket-Protocol'] = 'ship'
    headers['Sec-WebSocket-Version'] = 13
    async with connect(uri, subprotocols=[Subprotocol('ship')]) as websocket:
    #async with connect(uri) as websocket:
        now_unix = int(datetime.now().timestamp())
        data = {"command":"KeepAliveRequest","parameter":now_unix,"option":None}
        await websocket.send(json.dumps(data))
        while True:
            try:
                msg = await websocket.recv()
                print(msg)
            except exceptions.ConnectionClosedError as ex:
                print("Connection closed with error.")
                print(ex)
                break

asyncio.run(eebus(f"ws://admin:{PASSWORD}@vitoconnect/ws"))