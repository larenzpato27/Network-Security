import socket
import ssl
import threading
import json
import urllib.parse
import uuid

HOST = "0.0.0.0"
PORT = 8443
MTLS_PORT = 8444
sessions = {}

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")

mtls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
mtls_ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")
mtls_ctx.verify_mode = ssl.CERT_REQUIRED
mtls_ctx.load_verify_locations(cafile="ca.crt")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))
server.listen(5)

print(f"Listening on port {PORT}...")

def json_response(status, data):
    body = json.dumps(data)
    body_bytes = body.encode("utf-8")
    return (
        f"HTTP/1.1 {status}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        "\r\n"
        f"{body}"
    )

def empty_response(status):
    return f"HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n"

def handle_client(client_socket, client_address):
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
            response = empty_response("200 OK")

        elif method == "POST" and parsed_url.path == "/login":
            try:
                payload = json.loads(body)
            except Exception:
                payload = {}

            user = payload.get("user")
            password = payload.get("password")

            if password == "netsec" and user:
                session_id = str(uuid.uuid4())
                sessions[session_id] = user

                response = (
                    "HTTP/1.1 200 OK\r\n"
                    f"Set-Cookie: session={session_id}; Secure; HttpOnly; Path=/\r\n"
                    "Content-Length: 0\r\n"
                    "\r\n"
                )
            else:
                response = empty_response("401 Unauthorized")

        elif method == "GET" and parsed_url.path == "/me":
            cookie_header = headers.get("cookie", "")
            session_id = None
            
            for item in cookie_header.split(";"):
                if "=" in item:
                    k, v = item.strip().split("=", 1)
                    if k == "session":
                        session_id = v
                        
            if session_id and session_id in sessions:
                user = sessions[session_id]
                response = json_response("200 OK", {"user": user})
            else:
                response = empty_response("401 Unauthorized")

        else:
            response = empty_response("404 Not Found")

        client_socket.sendall(response.encode("utf-8"))
        print(f"Sending: {response}")
    
    print(f"Client {client_address} disconnected.")
    client_socket.close()

def handle_mtls_client(client_socket, client_address):
    cert = client_socket.getpeercert()
    cn = ""
    for rdn in cert.get("subject", ()):
        for key, val in rdn:
            if key == "commonName":
                cn = val

    while True:
        try: 
            data = client_socket.recv(4096)
        except (ConnectionResetError, ssl.SSLError):
            break

        if not data:
            break

        request = data.decode("utf-8", errors="ignore")
        print(f"Received: {request}")

        parts = request.split("\r\n\r\n", 1)
        lines = parts[0].split("\r\n")
        parts_req = lines[0].split(" ")
        if len(parts_req) < 2:
            break

        method, path = parts_req[0], parts_req[1]

        parsed_url = urllib.parse.urlparse(path)

        if method == "GET" and parsed_url.path == "/whoami":
            body_bytes = cn.encode("utf-8")
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                "\r\n"
                f"{cn}"
            )
        else:
            response = empty_response("404 Not Found")

        client_socket.sendall(response.encode("utf-8"))
        print(f"Sending: {response}")

    print(f"Client {client_address} disconnected.")
    client_socket.close()

def run_mtls_server():
    mtls_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mtls_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mtls_server.bind((HOST, MTLS_PORT))
    mtls_server.listen(5)

    print(f"Listening for MTLS connections on {MTLS_PORT}...")

    while True:
        raw_socket, client_address = mtls_server.accept()
        try:
            tls_socket = mtls_ctx.wrap_socket(raw_socket, server_side=True)
            thread = threading.Thread(target=handle_mtls_client, args=(tls_socket, client_address), daemon=True)
            thread.start()
        except ssl.SSLError:
            raw_socket.close()

threading.Thread(target=run_mtls_server, daemon=True).start()

while True:
    raw_socket, client_address = server.accept()
    try:
        tls_socket = ctx.wrap_socket(raw_socket, server_side=True)
        thread = threading.Thread(target=handle_client, args=(tls_socket, client_address), daemon=True)
        thread.start()
    except ssl.SSLError:
        raw_socket.close()