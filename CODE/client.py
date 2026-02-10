import paramiko
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox
import base64
import os
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers import algorithms as modern_algorithms
from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit_algorithms

# =============================
# SELECT SYMMETRIC ALGORITHM
# =============================

print("Select Encryption Algorithm:")
print("1. AES")
print("2. TripleDES")
print("3. RC4")
print("4. Blowfish")
print("5. ChaCha20")

choice = input("Enter number: ")

ALGO_MAP = {
    "1": "AES",
    "2": "TripleDES",
    "3": "RC4",
    "4": "Blowfish",
    "5": "ChaCha20"
}

ALGORITHM = ALGO_MAP.get(choice, "AES")
print(f"\n[CLIENT] Using Algorithm: {ALGORITHM}")
print("***** DEBUG MODE ENABLED *****\n")

# =============================
# UI STYLING (UNCHANGED)
# =============================

BG_MAIN, BG_LEFT, BG_RIGHT, FG_RIGHT = "#f5f5f7", "#e5e5ea", "#0a84ff", "white"
FONT_MAIN, FONT_CHAT = ("Segoe UI", 11), ("Segoe UI", 10)

# =============================
# RSA KEY GENERATION
# =============================

priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

pub_der = priv_key.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

pub_b64 = base64.b64encode(pub_der).decode()

other_public_keys = {}
messages = {}
current_contact = None

decrypt_times = []
encrypt_times = []
total_received_chars = 0
total_sent_chars = 0

# =============================
# SYMMETRIC CIPHER FACTORY
# =============================

def build_cipher(key, iv):
    if ALGORITHM == "AES":
        return Cipher(modern_algorithms.AES(key), modes.CFB(iv))

    elif ALGORITHM == "TripleDES":
        return Cipher(decrepit_algorithms.TripleDES(key), modes.CFB(iv))

    elif ALGORITHM == "Blowfish":
        return Cipher(decrepit_algorithms.Blowfish(key), modes.CFB(iv))

    elif ALGORITHM == "RC4":
        return Cipher(decrepit_algorithms.ARC4(key), mode=None)

    elif ALGORITHM == "ChaCha20":
        return Cipher(modern_algorithms.ChaCha20(key, iv), mode=None)

# =============================
# ENCRYPT
# =============================

def encrypt_message(target_pub_b64, text):
    global total_sent_chars

    total_sent_chars += len(text)

    target_der = base64.b64decode(target_pub_b64)
    target_pub_key = serialization.load_der_public_key(target_der)

    if ALGORITHM == "AES":
        sym_key = os.urandom(32)
        iv = os.urandom(16)

    elif ALGORITHM == "TripleDES":
        sym_key = os.urandom(24)
        iv = os.urandom(8)

    elif ALGORITHM == "Blowfish":
        sym_key = os.urandom(16)
        iv = os.urandom(8)

    elif ALGORITHM == "RC4":
        sym_key = os.urandom(16)
        iv = b''

    elif ALGORITHM == "ChaCha20":
        sym_key = os.urandom(32)   # 256-bit key
        iv = os.urandom(16)        # 128-bit nonce

    start = time.perf_counter()  # <<--- START TIMER

    cipher = build_cipher(sym_key, iv)
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()

    end = time.perf_counter()  # <<--- END TIMER
    encrypt_time_ms = (end - start) * 1000
    encrypt_times.append(encrypt_time_ms)

    enc_sym_key = target_pub_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f"[DEBUG] Characters Sent: {len(text)}")
    print(f"[DEBUG] Last Encrypt Time: {encrypt_time_ms:.4f} ms")
    print(f"[DEBUG] Average Encrypt Time: {sum(encrypt_times)/len(encrypt_times):.4f} ms")

    return f"{base64.b64encode(enc_sym_key).decode()}:{base64.b64encode(iv).decode()}:{base64.b64encode(encrypted_text).decode()}"

# =============================
# DECRYPT
# =============================

def decrypt_message(secret_blob):
    global total_received_chars

    try:
        start = time.perf_counter()

        e_sym, iv, ct = [base64.b64decode(x) for x in secret_blob.split(":")]

        sym_key = priv_key.decrypt(
            e_sym,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = build_cipher(sym_key, iv)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ct) + decryptor.finalize()

        end = time.perf_counter()

        decrypt_time_ms = (end - start) * 1000
        decrypt_times.append(decrypt_time_ms)

        text = plaintext.decode()
        total_received_chars += len(text)

        print("\n========== DEBUG INFO ==========")
        print(f"Characters Received (Total): {total_received_chars}")
        print(f"Last Decrypt Time: {decrypt_time_ms:.4f} ms")
        print(f"Average Decrypt Time: {sum(decrypt_times)/len(decrypt_times):.4f} ms")
        print(f"Total Messages Measured: {len(decrypt_times)}")
        print("================================\n")

        return text

    except Exception as e:
        print("Decrypt Error:", e)
        return "[Decryption Error]"

# =============================
# NETWORK RECEIVE LOOP
# =============================

def receive_loop():
    while True:
        try:
            data = chan.recv(8192).decode()
            if not data:
                break

            for line in data.strip().split("\n"):
                if "|" not in line:
                    continue

                header, content = line.split("|", 1)

                if header == "KEYSHARE":
                    user, key_b64 = content.split(":", 1)
                    if user != username:
                        other_public_keys[user] = key_b64
                        if user not in contacts_list.get(0, tk.END):
                            contacts_list.insert(tk.END, user)

                elif header == "MSG":
                    sender, secret = content.split("|", 1)
                    dec = decrypt_message(secret)
                    add_message(sender, "left", dec)

        except:
            break

# =============================
# SEND ACTION
# =============================

def send_action(event=None):
    if not current_contact:
        return

    text = msg_entry.get("1.0", tk.END).strip()
    if not text:
        return

    try:
        secret = encrypt_message(other_public_keys[current_contact], text)
        chan.send(f"MSG|{current_contact}|{secret}\n".encode())
        add_message(current_contact, "right", text)
        msg_entry.delete("1.0", tk.END)

    except:
        messagebox.showerror("Error", "User offline or key missing.")

# =============================
# UI LOGIC (UNCHANGED)
# =============================

def add_message(contact, side, text):
    messages.setdefault(contact, []).append((side, text))
    if current_contact == contact:
        display_messages(contact)

def display_messages(contact):
    chat_area.config(state="normal")
    chat_area.delete("1.0", tk.END)

    for side, text in messages.get(contact, []):
        tag = "right" if side == "right" else "left"
        chat_area.insert(tk.END, text + "\n\n", tag)

    chat_area.config(state="disabled")
    chat_area.yview(tk.END)

def select_contact(event):
    global current_contact
    sel = contacts_list.curselection()
    if not sel:
        return
    current_contact = contacts_list.get(sel[0])
    receiver_label.config(text=f"Secure: {current_contact}")
    display_messages(current_contact)

# =============================
# CONNECT TO SERVER
# =============================

root = tk.Tk()
root.title("E2EE Messenger")
root.geometry("800x550")
root.configure(bg=BG_MAIN)

server_ip = simpledialog.askstring("Connect", "Server IP:")
username = simpledialog.askstring("Login", "Username:")
password = simpledialog.askstring("Login", "Password:", show="*")

try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(server_ip, port=2222, username=username, password=password)
    chan = ssh.get_transport().open_session()
    chan.send(f"{username}|{pub_b64}\n".encode())

except Exception as e:
    messagebox.showerror("Failed", str(e))
    sys.exit()

# =============================
# UI LAYOUT (UNCHANGED)
# =============================

left = tk.Frame(root, width=200, bg="white")
left.pack(side="left", fill="y")

tk.Label(left, text="CONTACTS", bg="white", font=("Arial", 9, "bold")).pack(pady=10)

contacts_list = tk.Listbox(left, bd=0, font=FONT_MAIN)
contacts_list.pack(fill="both", expand=True, padx=10)
contacts_list.bind("<<ListboxSelect>>", select_contact)

right = tk.Frame(root, bg=BG_MAIN)
right.pack(side="right", fill="both", expand=True)

receiver_label = tk.Label(right, text="Select user", bg=BG_MAIN, font=FONT_MAIN)
receiver_label.pack(pady=10)

chat_area = tk.Text(right, state="disabled", bg=BG_MAIN, font=FONT_CHAT, padx=15, pady=10, bd=0)
chat_area.tag_configure("left", justify="left", background=BG_LEFT, lmargin1=10, rmargin=100, spacing3=10)
chat_area.tag_configure("right", justify="right", background=BG_RIGHT, foreground=FG_RIGHT, lmargin1=100, rmargin=10, spacing3=10)
chat_area.pack(fill="both", expand=True)

in_f = tk.Frame(right, bg="white")
in_f.pack(fill="x", side="bottom")

msg_entry = tk.Text(in_f, height=2, font=FONT_MAIN, bd=0, padx=10, pady=10)
msg_entry.pack(side="left", fill="x", expand=True)
msg_entry.bind("<Return>", lambda e: send_action() or "break")

tk.Button(in_f, text="SEND", command=send_action, bg=BG_RIGHT, fg="white", bd=0, padx=20).pack(side="right", fill="y")

threading.Thread(target=receive_loop, daemon=True).start()
root.mainloop()
