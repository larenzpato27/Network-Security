import socket
import threading

HOST = "0.0.0.0"
PORT = 9001
store = {}

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))
server.listen(5)

print(f"Listening on port {PORT}...")

def handle_client(client_socket, client_address):
    print(f"Connection established with {client_address}.")
    buffer = ""

    while True:
        try:
            data = client_socket.recv(1024)
        except ConnectionResetError:
            break

        if not data:
            break

        buffer += data.decode("utf-8")
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            message = line.rstrip("\r")
            print(f"Received: {message}")

            parts = message.split(" ", 1)

            response = "ERR\n"

            if parts[0] == "PING":
                if len(parts) == 1:
                    response = "PONG\n"

            elif parts[0] == "ECHO":
                if len(parts) > 1:
                    response = parts[1] + "\n"

            elif parts[0] == "SET":
                if len(parts) > 1 and " " in parts[1]:
                    key, val = parts[1].split(" ", 1)
                    if key != "":
                        store[key] = val
                        response = "OK\n"

            elif parts[0] == "GET":
                if len(parts) > 1 and " " not in parts[1] and parts[1] != "":
                    key = parts[1]
                    if key in store:
                        response = store[key] + "\n"
                    else:
                        response = "NOT_FOUND\n"

            client_socket.sendall(response.encode("utf-8"))
            print(f"Sending: {response}")

    print(f"Client {client_address} disconnected.")
    client_socket.close()


while True:
    client_socket, client_address = server.accept()
    thread = threading.Thread(target = handle_client, args = (client_socket, client_address))
    thread.start()