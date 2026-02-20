import paramiko
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
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
# UI STYLING
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
# NEW: FILE STORAGE
# =============================

incoming_files = {}
CHUNK_SIZE = 64 * 1024  # 64KB per chunk

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
        sym_key = os.urandom(32)
        iv = os.urandom(16)

    start = time.perf_counter()

    cipher = build_cipher(sym_key, iv)
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()

    end = time.perf_counter()
    encrypt_times.append((end - start) * 1000)

    enc_sym_key = target_pub_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return f"{base64.b64encode(enc_sym_key).decode()}:{base64.b64encode(iv).decode()}:{base64.b64encode(encrypted_text).decode()}"

# =============================
# DECRYPT
# =============================

def decrypt_message(secret_blob):
    global total_received_chars
    try:
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

        text = plaintext.decode()
        total_received_chars += len(text)
        return text

    except:
        return "[Decryption Error]"

# =============================
# SEND TEXT (UNCHANGED)
# =============================

def send_action(event=None):
    if not current_contact:
        return

    text = msg_entry.get("1.0", tk.END).strip()
    if not text:
        return

    secret = encrypt_message(other_public_keys[current_contact], text)
    chan.send(f"MSG|{current_contact}|{secret}\n".encode())
    add_message(current_contact, "right", text)
    msg_entry.delete("1.0", tk.END)

# =============================
# SEND FILE (UPGRADED ONLY)
# =============================

def send_file():
    if not current_contact:
        return

    file_path = filedialog.askopenfilename(title="Select File")
    if not file_path:
        return

    try:
        filename = os.path.basename(file_path)

        with open(file_path, "rb") as f:
            file_bytes = f.read()

        chunks = [
            file_bytes[i:i + CHUNK_SIZE]
            for i in range(0, len(file_bytes), CHUNK_SIZE)
        ]

        total_chunks = len(chunks)

        chan.send(f"FILESTART|{current_contact}|{filename}|{total_chunks}\n".encode())

        for i, chunk in enumerate(chunks):
            chunk_b64 = base64.b64encode(chunk).decode()
            secret = encrypt_message(other_public_keys[current_contact], chunk_b64)
            chan.send(f"FILECHUNK|{current_contact}|{i}|{secret}\n".encode())

        chan.send(f"FILEEND|{current_contact}|{filename}\n".encode())

        add_message(current_contact, "right", f"[File Sent: {filename}]")

    except Exception as e:
        messagebox.showerror("Error", str(e))

# =============================
# RECEIVE LOOP (ONLY FILE PART UPDATED)
# =============================

def receive_loop():
    buffer = ""

    while True:
        try:
            data = chan.recv(65536).decode()
            if not data:
                break

            buffer += data

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)

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

                elif header == "FILESTART":
                    sender, rest = content.split("|", 1)
                    filename, total = rest.split("|")
                    incoming_files[sender] = {
                        "filename": filename,
                        "total": int(total),
                        "chunks": {}
                    }

                elif header == "FILECHUNK":
                    sender, rest = content.split("|", 1)
                    index, secret = rest.split("|", 1)
                    index = int(index)
                    dec = decrypt_message(secret)
                    chunk_bytes = base64.b64decode(dec)
                    incoming_files[sender]["chunks"][index] = chunk_bytes

                elif header == "FILEEND":
                    sender, filename = content.split("|", 1)
                    file_data = incoming_files[sender]

                    ordered_chunks = [
                        file_data["chunks"][i]
                        for i in range(file_data["total"])
                    ]

                    full_file = b"".join(ordered_chunks)

                    save_path = f"received_{filename}"
                    with open(save_path, "wb") as f:
                        f.write(full_file)

                    add_message(sender, "left", f"[File Received: {filename}]")

                    del incoming_files[sender]

        except:
            break