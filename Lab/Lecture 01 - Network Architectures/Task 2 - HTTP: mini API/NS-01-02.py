import socket
import threading
import json
import urllib.parse

HOST = "0.0.0.0"
PORT = 8080
notes = {}
next_id = 1

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
    print(f"Connection established with {client_address}.")

    while True:
        try:
            data = client_socket.recv(4096)
        except ConnectionResetError:
            break

        if not data:
            break

        request = data.decode("utf-8")
        print(f"Received: {request}")

        parts = request.split("\r\n\r\n", 1)
        header_part = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = header_part.split("\r\n")
        request_line = lines[0]
        method, path, _ = request_line.split(" ")

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                name, val = line.split(":", 1)
                headers[name.strip().lower()] = val.strip()

        parsed_url = urllib.parse.urlparse(path)

        if method == "GET" and parsed_url.path == "/":
            response = empty_response("200 OK")

        elif method == "GET" and parsed_url.path == "/echo":
            query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
            text = query_params.get("msg", [""])[0]
            response = json_response("200 OK", {"msg": text})

        elif parsed_url.path == "/notes":
            if method != "POST":
                response = empty_response("405 Method Not Allowed")
            elif not headers.get("content-type", "").startswith("application/json"):
                response = empty_response("415 Unsupported Media Type")
            else:
                try:
                    payload = json.loads(body)
                    if not isinstance(payload, dict) or "text" not in payload or not isinstance(payload["text"], str):
                        response = empty_response("400 Bad Request")
                    else:
                        global next_id
                        note_id = next_id
                        next_id += 1
                        notes[note_id] = payload["text"]
                        response = json_response("201 Created", {"id": note_id})
                except Exception:
                    response = empty_response("400 Bad Request")

        elif parsed_url.path.startswith("/notes/"):
            id_str = parsed_url.path[len("/notes/"):]
            if not id_str.isdigit():
                response = empty_response("404 Not Found")
            else:
                note_id = int(id_str)
                if method == "GET":
                    if note_id in notes:
                        response = json_response("200 OK", {"id": note_id, "text": notes[note_id]})
                    else:
                        response = empty_response("404 Not Found")
                elif method == "DELETE":
                    if note_id in notes:
                        del notes[note_id]
                        response = empty_response("204 No Content")
                    else:
                        response = empty_response("404 Not Found")
                else:
                    response = empty_response("405 Method Not Allowed")

        else:
            response = empty_response("404 Not Found")

        client_socket.sendall(response.encode("utf-8"))
        print(f"Sending: {response}")

    print(f"Client {client_address} disconnected.")
    client_socket.close()

while True:
    client_socket, client_address = server.accept()
    thread = threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True)
    thread.start()