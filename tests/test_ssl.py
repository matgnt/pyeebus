import pytest
import socket
from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.primitives._serialization import Encoding
import asyncio
import threading
import time
import queue
import sys
#from websockets import WebSocketCommonProtocol, WebSocketServerProtocol, WebsocketServer
from wsproto import WSConnection, ConnectionType
from wsproto.events import Request, AcceptConnection


HOSTNAME = 'localhost'
PORT = 7070

client_msg_queue = queue.Queue()

def get_reader_protocol():
    stream_reader = asyncio.StreamReader(loop=asyncio.get_event_loop())
    reader_protocol = asyncio.StreamReaderProtocol(stream_reader=stream_reader)
    return reader_protocol, stream_reader

def get_writer_protocol():
    stream_writer = asyncio.StreamWriter()
    writer_protocol = asyncio.SteamWriterProtocol()
    return writer_protocol

def handshake(connection: SSL.Connection, timeout_sec: int = 10):
    """
    Runs until handshake is ok or timout.

    addapted example from pyopenssl tests:
    https://github.com/pyca/pyopenssl/blob/main/tests/test_ssl.py#L238
    """
    looper = True
    while looper:
            time.sleep(1)
            try:
                connection.do_handshake()
            except SSL.WantReadError:
                pass
            else:
                # we know it is ok now
                looper = False

            if timeout_sec <= 0:
                #or stop the loop after the timeout
                looper = False

            timeout_sec = timeout_sec -1

def openssl_cert_to_ski(cert: crypto.X509):
    x509_cert: x509.Certificate = cert.to_cryptography()
    xx = x509_cert.public_bytes(encoding=Encoding.PEM)
    #print(xx)
    ski = x509_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    return ski.value.digest

def ski_bytes_to_human_readable(ski: bytes):
    return ski.hex(':').upper()

def verify_cb(conn, cert, err, depth, ok):
    print(cert)
    ski = openssl_cert_to_ski(cert)
    # don't trust this for self-signed certs without recalculating it from pub key!!!
    print(f"ski:{ski}")

    return 1 # TODO: security: 1 means cert check ok!

def ws_handler(connection):
    print(connection)

def ws_read_write_loop(ws: WSConnection, ssl_connection: SSL.Connection, conn_type: ''):
    while True:
        #print(ws.state)
        #print(conn_type)
        cert = ssl_connection.get_peer_certificate()
        ski = openssl_cert_to_ski(cert)
        ski_human = ski_bytes_to_human_readable(ski)
        print(f"{conn_type}, PEER Cert SKI: {ski_human}")
        #print(cert)
        # anything to read?
        #nr_bytes = ssl_connection.pending()
        if True:
            data = None
            try:
                data = ssl_connection.read(4096)
                print(f"read: {data}")
                ws.receive_data(data)
            except SSL.WantReadError as ex:
                pass

        # anything to send?
        for event in ws.events():
            print(event)
            data_to_send = None
            if isinstance(event, Request):
                print('Accepting connection request')
                data_to_send = ws.send(AcceptConnection())
            # TODO: other messages here

            if data_to_send:
                print(f"sending: {data_to_send}")
                ssl_connection.sendall(data_to_send)
        
        print('------')
        time.sleep(2)



def start_server():
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.use_certificate_file('./provider.crt')
    context.use_privatekey_file('./provider.key')
    context.set_verify(mode=SSL.VERIFY_PEER, callback=verify_cb)


    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOSTNAME, PORT))
        sock.listen(5)
        # TODO: loop
        conn, addr = sock.accept()
        conn.setblocking(False)
        conn.send(b'pure socket')

        ssl_connection = SSL.Connection(context=context, socket=conn)
        ssl_connection.set_accept_state() # server mode
        handshake(ssl_connection)

        ssl_connection.send(b'pyopenssl socket')

        # websocket relevant part
        ws = WSConnection(ConnectionType.SERVER)
        ws_read_write_loop(ws, ssl_connection, conn_type='server')


    return 'server result'

def start_client():
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.use_certificate_file('./consumer.crt')
    context.use_privatekey_file('./consumer.key')
    context.set_verify(mode=SSL.VERIFY_PEER, callback=verify_cb)

    with socket.create_connection((HOSTNAME, PORT)) as sock:
        data = sock.recv(4096)
        client_msg_queue.put(data)
        # now lets wrap it into ssl
        client_ssl_conn = SSL.Connection(context=context, socket=sock)
        client_ssl_conn.set_connect_state() # client mode
        handshake(client_ssl_conn)

        data = client_ssl_conn.recv(4096)
        client_msg_queue.put(data)

        # ws relevant part
        sock.setblocking(False)
        ws = WSConnection(ConnectionType.CLIENT)
        data = ws.send(Request(host=HOSTNAME, target='/'))
        client_ssl_conn.send(data)
        ws_read_write_loop(ws, client_ssl_conn, conn_type='client')


    return 'client result'



def test_ssl():
    server = threading.Thread(target=start_server)
    server.start()
    time.sleep(5) # give server time to start
    client = threading.Thread(target=start_client)
    client.start()

    while True:
        time.sleep(1)
        data = client_msg_queue.get()
        print(data)

if __name__ == '__main__':
    test_ssl()
