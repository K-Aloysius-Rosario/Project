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
from cryptography.hazmat.primitives.ciphers import algorithms as decrepit_algorithms

# =============================
# ALGORITHM SELECTION
# =============================
print("---------------------------------------")
print("   SECURE MESSENGER: CRYPTO SETUP      ")
print("---------------------------------------")
print("Select Symmetrical Encryption Algorithm:")
print("1. AES (Advanced Encryption Standard)")
print("2. TripleDES (Legacy 3DES)")
print("3. RC4 (Stream Cipher)")
print("4. Blowfish")
print("5. ChaCha20 (Modern Stream Cipher)")

choice = input("Enter selection [1-5]: ")
ALGO_MAP = {
    "1": "AES",
    "2": "TripleDES",
    "3": "RC4",
    "4": "Blowfish",
    "5": "ChaCha20"
}
ALGORITHM = ALGO_MAP.get(choice, "AES")
print(f"[*] Symmetrical Algorithm Locked: {ALGORITHM}")
# =============================
# TECHNICAL PERFORMANCE MONITOR
# =============================
DEBUG_ENABLED = True  

def debug_log(mode, sender, payload_len, filename=None):
    if not DEBUG_ENABLED:
        return

    print(f"\n--- [DEBUG: {mode.upper()} MODE] ---")

    if mode.lower() == "sender":
        # Calculate Average Encrypt Time
        avg_enc = sum(encrypt_times) / len(encrypt_times) if encrypt_times else 0
        
        print(f"Character Sent        : {payload_len}")
        print(f"Last Encrypt Time     : {encrypt_times[-1]:.4f} ms")
        print(f"Average Encrypt Time  : {avg_enc:.4f} ms")
        if filename:
            print(f"FILE STATUS           : Successfully sent '{filename}'")

    elif mode.lower() == "receiver":
        # Calculate Average Decrypt Time
        avg_dec = sum(decrypt_times) / len(decrypt_times) if decrypt_times else 0
        
        print(f"Characters Received (Total) : {total_received_chars}")
        print(f"Last Decrypt Time           : {decrypt_times[-1]:.4f} ms")
        print(f"Average Decrypt Time        : {avg_dec:.4f} ms")
        # Time taken to receive is the network latency for the last chunk
        print(f"Time taken to receive       : {time.strftime('%H:%M:%S')}")
        if filename:
            print(f"FILE STATUS                 : Received and saved '{filename}'")

    print("-" * 35)
# =============================
# UI STYLING CONSTANTS
# =============================
BG_MAIN = "#f5f5f7"
BG_LEFT = "#e5e5ea"
BG_RIGHT = "#0a84ff"
FG_RIGHT = "white"
FONT_MAIN = ("Segoe UI", 11)
FONT_CHAT = ("Segoe UI", 10)

# =============================
# ASYMMETRIC KEY GENERATION
# =============================
print("[*] Generating 2048-bit RSA Key Pair...")
priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub_der = priv_key.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
pub_b64 = base64.b64encode(pub_der).decode()

# Global Communication Buffers
other_public_keys = {}
messages = {}
current_contact = None

# Statistics Variables (Restored)
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
# ENCRYPTION & DECRYPTION
# =============================
def encrypt_message(target_pub_b64, text):
    global total_sent_chars
    total_sent_chars += len(text)
    
    target_der = base64.b64decode(target_pub_b64)
    target_pub_key = serialization.load_der_public_key(target_der)

    # Determine required key/IV sizes for the chosen algorithm
    if ALGORITHM in ["AES", "ChaCha20"]:
        k_sz, iv_sz = 32, 16
    elif ALGORITHM == "TripleDES":
        k_sz, iv_sz = 24, 8
    elif ALGORITHM == "Blowfish":
        k_sz, iv_sz = 16, 8
    else: # RC4
        k_sz, iv_sz = 16, 0

    sym_key = os.urandom(k_sz)
    iv = os.urandom(iv_sz) if iv_sz > 0 else b''

    start_time = time.perf_counter()
    cipher = build_cipher(sym_key, iv)
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
    encrypt_times.append((time.perf_counter() - start_time) * 1000)

    # Wrap the symmetric key with RSA
    enc_sym_key = target_pub_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return f"{base64.b64encode(enc_sym_key).decode()}:{base64.b64encode(iv).decode()}:{base64.b64encode(encrypted_text).decode()}"

def decrypt_message(secret_blob):
    global total_received_chars
    try:
        e_sym, iv, ct = [base64.b64decode(x) for x in secret_blob.split(":")]
        
        # Unwrap the symmetric key
        sym_key = priv_key.decrypt(
            e_sym,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        start_time = time.perf_counter()
        cipher = build_cipher(sym_key, iv)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ct) + decryptor.finalize()
        decrypt_times.append((time.perf_counter() - start_time) * 1000)
        
        text = plaintext.decode()
        total_received_chars += len(text)
        return text
    except Exception as e:
        print(f"Decryption Failure: {e}")
        return "[Decryption Error]"

# =============================
# UI LOGIC & REFRESH
# =============================
def add_message(contact, side, text):
    contact = contact.strip().lower()
    if contact not in messages:
        messages[contact] = []
    messages[contact].append((side, text))
    
    # Force UI update on the main thread
    root.after(0, lambda: display_messages(contact))

def display_messages(contact):
    if current_contact != contact:
        return
    
    chat_area.config(state="normal")
    chat_area.delete("1.0", tk.END)
    
    # Configure tags for speech bubbles
    chat_area.tag_configure("left", justify="left", background=BG_LEFT, lmargin1=10, rmargin=100, spacing3=10)
    chat_area.tag_configure("right", justify="right", background=BG_RIGHT, foreground=FG_RIGHT, lmargin1=100, rmargin=10, spacing3=10)
    
    for side, text in messages.get(contact, []):
        chat_area.insert(tk.END, text + "\n\n", side)
    
    chat_area.config(state="disabled")
    chat_area.see(tk.END)

# =============================
# SENDING ACTIONS
# =============================
def send_action(event=None):
    if not current_contact:
        return
    
    if current_contact not in other_public_keys:
        messagebox.showwarning("System", f"Awaiting Public Key from {current_contact}...")
        return

    text = msg_entry.get("1.0", tk.END).strip()
    if not text:
        return

    try:
        secret_blob = encrypt_message(other_public_keys[current_contact], text)
        debug_log("sender", username, len(text))
        chan.sendall(f"MSG|{current_contact}|{secret_blob}\n".encode('utf-8'))
        add_message(current_contact, "right", text)
        msg_entry.delete("1.0", tk.END)
    except Exception as e:
        messagebox.showerror("Send Error", str(e))

def send_file():
    if not current_contact:
        return

    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()

        filename = os.path.basename(file_path)
        # We strip any potential newlines from the base64 string itself
        file_b64 = base64.b64encode(file_bytes).decode('utf-8').replace("\n", "").replace("\r", "")
        
        # Build the packet carefully
        payload = f"FILE|{current_contact}|{filename}##{file_b64}\n"
        
        # Send in one go
        chan.sendall(payload.encode('utf-8'))
        
        debug_log("sender", username, len(file_b64), filename=filename)
        add_message(current_contact, "right", f"[File Sent: {filename}]")
    except Exception as e:
        messagebox.showerror("File Error", str(e))

def select_contact(event):
    global current_contact
    selection = contacts_list.curselection()
    if selection:
        current_contact = contacts_list.get(selection[0]).strip().lower()
        receiver_label.config(text=f"Secure Connection: {current_contact}")
        display_messages(current_contact)

# =============================
# BACKGROUND RECEIVER LOOP
# =============================
def receive_loop():
    buffer = b""  # This acts as a 'waiting room' for incoming data
    while True:
        try:
            # We use a large 2MB buffer to catch big file chunks
            data = chan.recv(2097152) 
            if not data:
                break
            
            buffer += data
            
            # CRITICAL: Only process if a full line (\n) exists in the buffer
            while b"\n" in buffer:
                # Extract one full line, leave the rest in the buffer
                line_bytes, buffer = buffer.split(b"\n", 1)
                
                if not line_bytes.strip():
                    continue

                # Use maxsplit=2 to protect the file data from internal pipes
                # and check length to prevent "Index Out of Range"
                parts = line_bytes.split(b"|", 2)
                
                if len(parts) < 3:
                    # This was a partial or malformed line; skip it to prevent crash
                    continue

                header = parts[0].decode('utf-8', errors='ignore')
                sender = parts[1].decode('utf-8', errors='ignore').strip().lower()
                payload = parts[2] # This is the raw message or file data

                if header == "KEYSHARE":
                    u_info = payload.decode('utf-8', errors='ignore')
                    u_name, u_key = u_info.split(":", 1)
                    u_name = u_name.strip().lower()
                    if u_name != username:
                        other_public_keys[u_name] = u_key
                        if u_name not in contacts_list.get(0, tk.END):
                            root.after(0, lambda u=u_name: contacts_list.insert(tk.END, u))

                elif header == "MSG":
                    secret = payload.decode('utf-8', errors='ignore')
                    decrypted_text = decrypt_message(secret)
                    debug_log("receiver", sender, len(decrypted_text))
                    add_message(sender, "left", decrypted_text)

                elif header == "FILE":
                    # For files, we split filename and base64
                    try:
                        file_parts = payload.split(b"##", 1)
                        if len(file_parts) < 2:
                            continue
                        
                        fname = file_parts[0].decode('utf-8', errors='ignore')
                        fb64 = file_parts[1] # Keep as bytes for decoding
                        
                        file_data = base64.b64decode(fb64)
                        with open(f"received_{fname}", "wb") as f:
                            f.write(file_data)
                        
                        debug_log("receiver", sender, len(fb64), filename=fname)
                        add_message(sender, "left", f"[File Received: {fname}]")
                    except Exception as file_err:
                        print(f"File saving error: {file_err}")

        except Exception as e:
            print(f"Receive Loop Error: {e}")
            break

# =============================
# GUI ASSEMBLY
# =============================
root = tk.Tk()
root.title("E2EE Messenger - 2048-bit RSA")
root.geometry("850x600")
root.configure(bg=BG_MAIN)

# Startup Login Dialogs
server_ip = simpledialog.askstring("Server", "Enter Server IP:")
username = simpledialog.askstring("Login", "Username:").strip().lower()
password = simpledialog.askstring("Login", "Password:", show="*")

try:
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(server_ip, port=2222, username=username, password=password)
    chan = ssh_client.get_transport().open_session()
    chan.sendall(f"{username}|{pub_b64}\n".encode('utf-8'))
except Exception as e:
    messagebox.showerror("SSH Error", f"Connection Failed: {e}")
    sys.exit()

# UI - Left Sidebar (Contacts)
sidebar = tk.Frame(root, width=220, bg="white")
sidebar.pack(side="left", fill="y")

tk.Label(sidebar, text="ONLINE CONTACTS", bg="white", font=("Arial", 9, "bold")).pack(pady=15)
contacts_list = tk.Listbox(sidebar, bd=0, font=FONT_MAIN, selectbackground=BG_RIGHT, highlightthickness=0)
contacts_list.pack(fill="both", expand=True, padx=15)
contacts_list.bind("<<ListboxSelect>>", select_contact)

# UI - Right Main Chat
chat_pane = tk.Frame(root, bg=BG_MAIN)
chat_pane.pack(side="right", fill="both", expand=True)

receiver_label = tk.Label(chat_pane, text="Select a user to begin encryption", bg=BG_MAIN, font=FONT_MAIN)
receiver_label.pack(pady=10)

chat_area = tk.Text(chat_pane, state="disabled", bg=BG_MAIN, font=FONT_CHAT, padx=20, pady=20, bd=0)
chat_area.pack(fill="both", expand=True)

# UI - Input Footer
footer = tk.Frame(chat_pane, bg="white", height=80)
footer.pack(fill="x", side="bottom")

msg_entry = tk.Text(footer, height=3, font=FONT_MAIN, bd=0, padx=15, pady=10)
msg_entry.pack(side="left", fill="x", expand=True)
msg_entry.bind("<Return>", lambda e: send_action() or "break")

btn_frame = tk.Frame(footer, bg="white")
btn_frame.pack(side="right", fill="y")

send_btn = tk.Button(btn_frame, text="SEND", command=send_action, bg=BG_RIGHT, fg="white", bd=0, padx=25, font=("Arial", 10, "bold"))
send_btn.pack(side="top", fill="both", expand=True)

file_btn = tk.Button(btn_frame, text="FILE", command=send_file, bg="#34c759", fg="white", bd=0, padx=25, font=("Arial", 10, "bold"))
file_btn.pack(side="bottom", fill="both", expand=True)

# Start Listener Thread
threading.Thread(target=receive_loop, daemon=True).start()

root.mainloop()
