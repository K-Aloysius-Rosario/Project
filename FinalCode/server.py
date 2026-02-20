import socket
import threading
import paramiko
import os

# =============================
# USER AUTHENTICATION SYSTEM
# =============================
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

# =============================
# RSA HOST KEY SETUP
# =============================
if not os.path.exists("server.key"):
    paramiko.RSAKey.generate(2048).write_private_key_file("server.key")

HOST_KEY = paramiko.RSAKey(filename="server.key")

clients = {}
public_keys = {}
lock = threading.Lock()

# =============================
# SSH SERVER INTERFACE
# =============================
class MessengerServer(paramiko.ServerInterface):
    def __init__(self):
        self.users = load_users()

    def check_auth_password(self, username, password):
        if username in self.users and self.users[username] == password:
            print(f"[AUTH] User '{username}' successfully authenticated.")
            return paramiko.AUTH_SUCCESSFUL
        print(f"[AUTH] Failed login attempt for '{username}'.")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

# =============================
# CLIENT HANDLER & RELAY
# =============================
def handle_client(chan, addr):
    username = None
    buffer = b"" 

    try:
        # 1. Receive Initial Identification (Username|PublicKey)
        data = chan.recv(8192)
        if not data:
            return

        line_init = data.decode('utf-8').strip()
        if "|" not in line_init:
            return

        username, pub_key = line_init.split("|", 1)
        username = username.strip().lower()

        with lock:
            clients[username] = chan
            public_keys[username] = pub_key

        print(f"[+] Client connected: {username} [{addr[0]}]")

        # 2. KEY BROADCAST (Crucial for Alice/Bob visibility)
        with lock:
            for user, key in public_keys.items():
                # Send existing user keys to the new joiner
                chan.sendall(f"KEYSHARE|{user}:{key}\n".encode('utf-8'))
                # Send the new joiner's key to all online users
                if user != username:
                    try:
                        clients[user].sendall(f"KEYSHARE|{username}:{pub_key}\n".encode('utf-8'))
                    except:
                        pass

        # 3. MESSAGE RELAY LOOP
        while True:
            chunk = chan.recv(1048576) # 1MB chunks
            if not chunk:
                break

            buffer += chunk

            while b"\n" in buffer:
                line_bytes, buffer = buffer.split(b"\n", 1)
                if not line_bytes.strip():
                    continue

                try:
                    # Parse the header to find the target
                    header_check = line_bytes[:500].decode('utf-8')
                    parts = header_check.split("|", 2)
                    if len(parts) < 3:
                        continue
                    
                    target = parts[1].strip().lower()

                    with lock:
                        if target in clients:
                            # Re-wrap packet to include the sender's name
                            # Protocol: TYPE|SENDER|CONTENT
                            relay_packet = f"{parts[0]}|{username}|".encode('utf-8') + line_bytes.split(b'|', 2)[2] + b"\n"
                            clients[target].sendall(relay_packet)
                except Exception as e:
                    print(f"Relay logic error: {e}")
                    continue

    except Exception as e:
        print(f"Connection error with {username}: {e}")
    finally:
        with lock:
            if username in clients: del clients[username]
            if username in public_keys: del public_keys[username]
        chan.close()

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", 2222))
    server_sock.listen(100)
    print("---------------------------------------")
    print("  E2EE ENCRYPTED SERVER IS NOW ONLINE  ")
    print("  LISTENING ON PORT 2222               ")
    print("---------------------------------------")

    while True:
        client_sock, addr = server_sock.accept()
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(HOST_KEY)
        transport.start_server(server=MessengerServer())
        chan = transport.accept(20)
        if chan:
            threading.Thread(target=handle_client, args=(chan, addr), daemon=True).start()

if __name__ == "__main__":
    main()