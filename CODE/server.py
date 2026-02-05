import socket, threading, paramiko, os

# --- AUTH SYSTEM ---
USERS_FILE = "users.txt"

def load_users():
    """Loads users from users.txt. Creates default if missing."""
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

# --- SSH SETUP ---
if not os.path.exists("server.key"):
    paramiko.RSAKey.generate(2048).write_private_key_file("server.key")
HOST_KEY = paramiko.RSAKey(filename="server.key")

clients = {}      # username -> channel
public_keys = {}  # username -> pub_key string
lock = threading.Lock()

class MessengerServer(paramiko.ServerInterface):
    def __init__(self):
        self.users = load_users()

    def check_auth_password(self, username, password):
        # NOW CHECKS users.txt
        if username in self.users and self.users[username] == password:
            print(f"[AUTH] {username} logged in.")
            return paramiko.AUTH_SUCCESSFUL
        print(f"[AUTH] Denied login for: {username}")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED

def handle_client(chan, addr):
    username = None
    try:
        # 1. Get Identity (Username|PublicKey)
        # Note: We use a larger buffer to ensure the full key arrives
        data = chan.recv(8192).decode('utf-8').strip()
        if "|" not in data: return
        username, pub_key = data.split("|", 1)
        
        # Clean the key immediately to prevent relaying corrupt data
        pub_key = pub_key.replace('\n', '').replace('\r', '').strip()

        with lock:
            clients[username] = chan
            public_keys[username] = pub_key
        
        print(f"[+] {username} connected from {addr}")

        # 2. Sync Keys (Clean relay)
        with lock:
            for user, key in public_keys.items():
                # Send all existing keys to new user
                chan.send(f"KEYSHARE|{user}:{key}\n".encode('utf-8'))
                # Send new user's key to all online users
                if user != username:
                    clients[user].send(f"KEYSHARE|{username}:{pub_key}\n".encode('utf-8'))

        # 3. Secure Relay Loop
        buffer = ""
        while True:
            data = chan.recv(8192)
            if not data: break
            buffer += data.decode('utf-8')
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if "MSG|" in line:
                    parts = line.split("|")
                    if len(parts) >= 3:
                        _, target, secret = parts
                        with lock:
                            if target in clients:
                                # Relay the exact encrypted blob
                                clients[target].send(f"MSG|{username}|{secret}\n".encode('utf-8'))
    except Exception as e:
        print(f"[!] Error handling {username}: {e}")
    finally:
        with lock:
            clients.pop(username, None)
            public_keys.pop(username, None)
        chan.close()
        print(f"[-] {username} disconnected.")

def main():
    # Detect IP for local network binding
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(('8.8.8.8', 1)); host = s.getsockname()[0]
    except: host = '127.0.0.1'
    finally: s.close()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, 2222))
    server_sock.listen(100)
    print(f"--- SECURE E2EE SERVER ---")
    print(f"IP:   {host}")
    print(f"PORT: 2222")
    print(f"--------------------------")

    while True:
        try:
            client_sock, addr = server_sock.accept()
            t = paramiko.Transport(client_sock)
            t.add_server_key(HOST_KEY)
            t.start_server(server=MessengerServer())
            chan = t.accept(20)
            if chan:
                threading.Thread(target=handle_client, args=(chan, addr), daemon=True).start()
        except Exception as e:
            print(f"[!] Server Accept Error: {e}")

if __name__ == "__main__":
    main()