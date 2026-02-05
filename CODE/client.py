import paramiko
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox
import base64
import os
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- UI STYLING ---
BG_MAIN, BG_LEFT, BG_RIGHT, FG_RIGHT = "#f5f5f7", "#e5e5ea", "#0a84ff", "white"
FONT_MAIN, FONT_CHAT = ("Segoe UI", 11), ("Segoe UI", 10)

# --- CRYPTO CORE (DER ENCODING) ---
# Generate Keys
priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
# We export as DER (Binary) and then Base64 it to avoid ALL formatting issues
pub_der = priv_key.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
pub_b64 = base64.b64encode(pub_der).decode('utf-8')

other_public_keys = {} 
messages = {}          
current_contact = None

def encrypt_message(target_pub_b64, text):
    # 1. Decode the target's public key from Base64 DER
    target_der = base64.b64decode(target_pub_b64)
    target_pub_key = serialization.load_der_public_key(target_der)
    
    # 2. AES Setup
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
    
    # 3. RSA Encrypt AES Key
    enc_aes_key = target_pub_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    return f"{base64.b64encode(enc_aes_key).decode()}:{base64.b64encode(iv).decode()}:{base64.b64encode(encrypted_text).decode()}"

def decrypt_message(secret_blob):
    try:
        e_aes, iv, ct = [base64.b64decode(x) for x in secret_blob.split(":")]
        aes_key = priv_key.decrypt(
            e_aes,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        return (cipher.decryptor().update(ct) + cipher.decryptor().finalize()).decode()
    except:
        return "[Decryption Error]"

# --- NETWORKING ---
def receive_loop():
    while True:
        try:
            data = chan.recv(8192).decode('utf-8')
            if not data: break
            for line in data.strip().split("\n"):
                if "|" not in line: continue
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
        except: break

def send_action(event=None):
    if not current_contact: return
    text = msg_entry.get("1.0", tk.END).strip()
    if not text: return
    try:
        secret = encrypt_message(other_public_keys[current_contact], text)
        chan.send(f"MSG|{current_contact}|{secret}\n".encode())
        add_message(current_contact, "right", text)
        msg_entry.delete("1.0", tk.END)
    except Exception as e:
        messagebox.showerror("Error", "Check if the other user is still online.")

# --- UI LOGIC ---
def add_message(contact, side, text):
    messages.setdefault(contact, []).append((side, text))
    if current_contact == contact: display_messages(contact)

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
    if not sel: return
    current_contact = contacts_list.get(sel[0])
    receiver_label.config(text=f"Secure: {current_contact}")
    display_messages(current_contact)

# --- APP START ---
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
    # Send username and the Base64 DER key
    chan.send(f"{username}|{pub_b64}\n".encode())
except Exception as e:
    messagebox.showerror("Failed", str(e))
    sys.exit()

# UI Layout
left = tk.Frame(root, width=200, bg="white", highlightbackground=BG_LEFT, highlightthickness=1)
left.pack(side="left", fill="y")
tk.Label(left, text="CONTACTS", bg="white", font=("Arial", 9, "bold")).pack(pady=10)
contacts_list = tk.Listbox(left, bd=0, font=FONT_MAIN, highlightthickness=0)
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