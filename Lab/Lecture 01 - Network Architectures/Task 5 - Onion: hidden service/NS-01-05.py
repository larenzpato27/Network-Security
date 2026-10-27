import socket
import threading
import urllib.parse

HOST = "0.0.0.0"
PORT = 8090

last_token = ""
token_lock = threading.Lock()

def handle_client(client_socket, client_address):
    print(f"Connection established with {client_address}")

    global last_token

    try:
        raw_data = b""
        while b"\r\n\r\n" not in raw_data:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            raw_data += chunk
        if not raw_data:
            return

        header_part, _, body_part = raw_data.partition(b"\r\n\r\n")
        lines = header_part.decode("iso-8859-1").split("\r\n")
        request_line = lines[0].split()

        if len(request_line) < 2:
            return

        method = request_line[0]
        raw_path = request_line[1]
        path = urllib.parse.urlparse(raw_path).path

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(": ", 1)
                headers[k.lower()] = v

        content_length = int(headers.get("content-length", 0))
        body = body_part

        while len(body) < content_length:
            chunk = client_socket.recv(min(4096, content_length - len(body)))
            if not chunk:
                break
            body += chunk
        
        if method == "GET" and path == "/":
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 0\r\n\r\n"
            )
        
        elif method == "POST" and path == "/claim":
            token_received = body.decode("utf-8", errors="ignore").strip()
            
            with token_lock:
                last_token = token_received
                print(f"Stored token from POST /claim: {token_received}")
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Length: 0\r\n\r\n"
                )

        elif method == "GET" and path == "/claim":
            with token_lock:
                current_token = last_token
                print(f"Serving token to GET /claim: {current_token}")
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    f"Content-Length: {len(current_token.encode())}\r\n"
                    "\r\n"
                    f"{current_token}"
                )

        else:
            response = (
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Length: 0\r\n\r\n"
            )
        
        client_socket.sendall(response.encode("utf-8"))
        print(f"Sending: {response}")

    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        print(f"Client {client_address} disconnected.")
        client_socket.close()

def run_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen(5)

    print(f"Listening on port {PORT}...")

    while True:
        client_socket, client_address = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True)
        thread.start()

if __name__ == "__main__":
    try:
        run_server()
    except KeyboardInterrupt:
        print("Shutting down server.")