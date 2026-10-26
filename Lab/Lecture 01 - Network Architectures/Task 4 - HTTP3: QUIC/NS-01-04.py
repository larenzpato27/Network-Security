import socket
import ssl
import threading
import urllib.parse
import hashlib
import asyncio

from aioquic.asyncio import QuicConnectionProtocol, serve #type: ignore
from aioquic.quic.configuration import QuicConfiguration #type: ignore
from aioquic.h3.connection import H3Connection #type: ignore
from aioquic.h3.events import HeadersReceived, DataReceived #type: ignore

HOST = "0.0.0.0"
PORT = 4433

ctx_tcp = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx_tcp.load_cert_chain(certfile="server.crt", keyfile="server.key")

def handle_tcp_client(client_socket, client_address):
    print(f"Connection established with {client_address}")
    
    while True:
        try:
            data = client_socket.recv(4096)
        except (ConnectionResetError, ssl.SSLError):
            break

        if not data:
            break

        request = data.decode("utf-8", errors = "ignore")
        print(f"Received: {request}")

        parts = request.split("\r\n\r\n", 1)
        header_part = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = header_part.split("\r\n")
        request_line = lines[0]
        
        parts_req = request_line.split(" ")
        if len(parts_req) < 2:
            break
        method, path = parts_req[0], parts_req[1]

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()

        content_length = int(headers.get("content-length", 0))
        while len(body.encode("utf-8")) < content_length:
            more_data = client_socket.recv(4096)
            if not more_data:
                break
            body += more_data.decode("utf-8", errors="ignore")
        
        parsed_url = urllib.parse.urlparse(path)

        if method == "GET" and parsed_url.path == "/":
            response = (
                "HTTP/1.1 200 OK\r\n"
                'Alt-Svc: h3=":4433"\r\n'
                "Content-Length: 0\r\n\r\n"
            )

        elif method == "GET" and parsed_url.path == "/proto":
            resp_body = "HTTP/1.1"
            response = (
                "HTTP/1.1 200 OK\r\n"
                'Alt-Svc: h3=":4433"\r\n'
                "Content-Type: text/plain\r\n"
                f"Content-Length: {len(resp_body)}\r\n"
                "\r\n"
                f"{resp_body}"
            )

        elif method == "POST" and parsed_url.path == "/hash":
            hash_hex = hashlib.sha256(body.encode("utf-8")).hexdigest()
            response = (
                "HTTP/1.1 200 OK\r\n"
                'Alt-Svc: h3=":4333"\r\n'
                "Content-Type: text/plain\r\n"
                f"Content-Length: {len(hash_hex)}\r\n"
                "\r\n"
                f"{hash_hex}"
            )

        else:
            response = (
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Length: 0\r\n"
            )

        client_socket.sendall(response.encode("utf-8"))
        print(f"Sending: {response}")
    
    print(f"Client {client_address} disconnected.")
    client_socket.close()

def run_tcp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"TCP HTTPS server listening on port {PORT}...")

    while True:
        raw_socket, client_address = server.accept()
        try:
            tls_socket = ctx_tcp.wrap_socket(raw_socket, server_side = True)
            thread = threading.Thread(target=handle_tcp_client, args=(tls_socket, client_address), daemon=True)
            thread.start()
        except ssl.SSLError:
            raw_socket.close()

class Http3Server(QuicConnectionProtocol):
    def __init__(self,*args,**kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.headers = {}
        self.bodies = {}

    def quic_event_received(self, event):
        for h3_event in self.http.handle_event(event):
            stream_id = h3_event.stream_id

            if isinstance(h3_event, HeadersReceived):
                self.headers[stream_id] = dict(h3_event.headers)
                self.bodies[stream_id] = b""
                if h3_event.stream_ended:
                    self.handle_request(stream_id)

            elif isinstance(h3_event, DataReceived):
                self.bodies[stream_id] += h3_event.data
                if h3_event.stream_ended:
                    self.handle_request(stream_id)

    def handle_request(self, stream_id):
        headers = self.headers.get(stream_id, {})
        body = self.bodies.get(stream_id, b"")

        method = headers.get(b":method", b"").decode("utf-8", errors = "ignore")
        raw_path = headers.get(b":path", b"").decode("utf-8", errors = "ignore")

        path = urllib.parse.urlparse(raw_path).path

        if method == "GET" and path == "/":
            status = b"200"
            resp_headers = [(b":status", status)]
            resp_body = b""

        elif method == "GET" and path == "/proto":
            status = b"200"
            resp_body = b"HTTP/3"
            resp_headers = [
                (b":status", status),
                (b"content-type", b"text/plain"),
                (b"content-length", str(len(resp_body)).encode())
            ]

        elif method == "POST" and path == "/hash":
            digest_hex = hashlib.sha256(body).hexdigest().encode()
            status = b"200"
            resp_body = digest_hex
            resp_headers = [
                (b":status", status),
                (b"content-type", b"text/plain"),
                (b"content-length", str(len(resp_body)).encode())
            ]

        else:
            status = b"404"
            resp_body = b"Not Found"
            resp_headers = [
                (b":status", status),
                (b"content-type", b"text/plain"),
                (b"content-length", str(len(resp_body)).encode())
            ]
        
        self.http.send_headers(stream_id, headers=resp_headers, end_stream=(len(resp_body) == 0))
        if len(resp_body) > 0:
            self.http.send_data(stream_id, data=resp_body, end_stream=True)
        
        self.transmit()
        self.headers.pop(stream_id, None)
        self.bodies.pop(stream_id, None)

async def run_server():
    configuration = QuicConfiguration(is_client = False)
    configuration.alpn_protocols = ["h3"]
    configuration.load_cert_chain(certfile="server.crt", keyfile="server.key")

    print(f"HTTP/3 QUIC server listening on UDP {PORT}...")

    await serve(
        HOST, 
        PORT, 
        configuration=configuration,
        create_protocol=Http3Server
    )

    await asyncio.Future()

if __name__ == "__main__":
    tcp_thread = threading.Thread(target=run_tcp_server, daemon=True)
    tcp_thread.start()

    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        print("Shutting down server.")