import socket
import threading
import paramiko

clients = {}  # username -> channel
HOST_KEY = paramiko.RSAKey.generate(2048)

class SSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


def client_handler(chan, addr):
    username = None
    try:
        # Receive username first (sent by client after session opens)
        username = chan.recv(1024).decode().strip()
        if not username:
            chan.close()
            return

        clients[username] = chan
        print(f"[+] {username} connected from {addr}")

        while True:
            data = chan.recv(1024)
            if not data:
                break

            message = data.decode().strip()

            # Expected format: target|message
            if "|" not in message:
                chan.send(b"System|Format should be target|message\n")
                continue

            target, msg = message.split("|", 1)

            if target in clients:
                # SEND IN CLIENT-EXPECTED FORMAT
                clients[target].send(f"{username}|{msg}\n".encode())
            else:
                chan.send(b"System|User not found\n")

    except Exception as e:
        print(f"[!] Error with {addr}: {e}")

    finally:
        if username in clients:
            clients.pop(username)
        chan.close()
        print(f"[-] {username} disconnected")


def main():
    host = input("Bind IP (e.g. 0.0.0.0 or 127.0.0.1): ").strip()
    port = int(input("Port (e.g. 2222): ").strip())

    sock = socket.socket()
    sock.bind((host, port))
    sock.listen(100)

    print(f"[+] SSH Messenger Server running on {host}:{port}")

    while True:
        client, addr = sock.accept()
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)

        server = SSHServer()
        transport.start_server(server=server)

        chan = transport.accept(20)
        if chan:
            threading.Thread(
                target=client_handler,
                args=(chan, addr),
                daemon=True
            ).start()


if __name__ == "__main__":
    main()
