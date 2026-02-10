import socket
import threading
import paramiko
import os

USERS_FILE = "users.txt"

def load_users():
    users = {}
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            f.write("admin:password\nuser1:1234\nuser2:1234\n")
    with open(USERS_FILE) as f:
        for line in f:
            if ":" in line:
                u, p = line.strip().split(":", 1)
                users[u] = p
    return users

if not os.path.exists("server.key"):
    paramiko.RSAKey.generate(2048).write_private_key_file("server.key")

HOST_KEY = paramiko.RSAKey(filename="server.key")

clients = {}
public_keys = {}
lock = threading.Lock()

class MessengerServer(paramiko.ServerInterface):
    def __init__(self):
        self.users = load_users()

    def check_auth_password(self, username, password):
        if username in self.users and self.users[username] == password:
            print(f"[AUTH] {username} logged in.")
            return paramiko.AUTH_SUCCESSFUL
        print(f"[AUTH] Denied login for: {username}")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

def handle_client(chan, addr):
    username = None
    try:
        data = chan.recv(8192).decode().strip()
        if "|" not in data:
            return

        username, pub_key = data.split("|", 1)

        with lock:
            clients[username] = chan
            public_keys[username] = pub_key

        print(f"[+] {username} connected from {addr}")

        with lock:
            for user, key in public_keys.items():
                chan.send(f"KEYSHARE|{user}:{key}\n".encode())
                if user != username:
                    clients[user].send(f"KEYSHARE|{username}:{pub_key}\n".encode())

        buffer = ""
        while True:
            data = chan.recv(8192)
            if not data:
                break
            buffer += data.decode()
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if line.startswith("MSG|"):
                    _, target, secret = line.split("|", 2)
                    with lock:
                        if target in clients:
                            clients[target].send(f"MSG|{username}|{secret}\n".encode())

    except Exception as e:
        print(f"[!] Error with {username}: {e}")
    finally:
        with lock:
            clients.pop(username, None)
            public_keys.pop(username, None)
        chan.close()
        print(f"[-] {username} disconnected.")

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", 2222))
    server_sock.listen(100)

    print("=== SECURE E2EE SERVER RUNNING ===")
    print("Listening on port 2222")
    print("==================================")

    while True:
        client_sock, addr = server_sock.accept()
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(HOST_KEY)
        transport.start_server(server=MessengerServer())
        chan = transport.accept(20)
        if chan:
            threading.Thread(
                target=handle_client,
                args=(chan, addr),
                daemon=True
            ).start()

if __name__ == "__main__":
    main()
