import paramiko
import threading
import getpass

def receive_messages(channel):
    while True:
        try:
            data = channel.recv(1024).decode()
            if data:
                print("\n" + data.strip())
        except:
            break

def start_client():
    host = input("Server IP: ").strip()
    port = input("Port (default 2222): ").strip()
    port = int(port) if port else 2222

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password
    )

    channel = client.invoke_shell()
    print(channel.recv(1024).decode())

    threading.Thread(target=receive_messages, args=(channel,), daemon=True).start()

    try:
        while True:
            msg = input()
            if msg.lower() in ["exit", "quit"]:
                break
            channel.send(msg + "\n")
    finally:
        client.close()
        print("Disconnected.")

if __name__ == "__main__":
    start_client()
    
    #goodbtye
# second bye test
