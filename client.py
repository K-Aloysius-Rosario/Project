import paramiko
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox

messages = {}
current_contact = None  # will track chat history

def add_message(contact, side, text):
    if contact not in messages:
        messages[contact] = []
    messages[contact].append((side, text))
    display_messages(contact)

def display_messages(contact):
    chat_area.config(state='normal')
    chat_area.delete('1.0', tk.END)
    if contact in messages:
        for side, text in messages[contact]:
            if side == 'right':
                chat_area.insert(tk.END, f"You: {text}\n", 'right')
            else:
                chat_area.insert(tk.END, f"{text}\n", 'left')
    chat_area.config(state='disabled')
    chat_area.yview(tk.END)

def receive_messages(chan):
    while True:
        try:
            data = chan.recv(1024)
            if not data:
                break
            text = data.decode().strip()
            if "|" not in text:
                continue
            sender, msg = text.split("|", 1)
            add_message(sender, 'left', msg)
        except:
            break

def send_message():
    target = receiver_entry.get().strip()
    if not target:
        messagebox.showwarning("No Receiver", "Enter a username in the To: field!")
        return
    msg = message_entry.get().strip()
    if not msg:
        return
    full_msg = f"{target}|{msg}"
    try:
        chan.send(full_msg.encode())
        add_message(target, 'right', msg)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send message: {e}")
    message_entry.delete(0, tk.END)

# --- GUI Setup ---
root = tk.Tk()
root.title("SSH Messenger - WhatsApp Style")
root.geometry("700x500")
root.resizable(False, False)

# --- SSH Connection ---
server_ip = simpledialog.askstring("Server IP", "Enter server IP:")
port = simpledialog.askinteger("Port", "Enter server port:")
username = simpledialog.askstring("Username", "Enter your username:")
password = simpledialog.askstring("Password", "Enter your password:", show='*')

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    client.connect(server_ip, port=port, username=username, password=password)
except Exception as e:
    messagebox.showerror("Connection Error", f"Failed to connect: {e}")
    root.destroy()
    exit()

transport = client.get_transport()
chan = transport.open_session()
chan.send((username + "\n").encode())

# --- Layout ---
# Left panel: optional contacts list
left_panel = tk.Frame(root, width=200, bg="#f0f0f0")
left_panel.pack(side="left", fill="y")

tk.Label(left_panel, text="Contacts (optional)", bg="#f0f0f0", font=("Arial", 12, "bold")).pack(pady=5)
contacts_list = tk.Listbox(left_panel)
contacts_list.pack(fill="y", expand=True, padx=5, pady=5)

# Right panel: chat
right_panel = tk.Frame(root, bg="white")
right_panel.pack(side="right", fill="both", expand=True)

# Editable "To:" field
receiver_frame = tk.Frame(right_panel, bg="white")
receiver_frame.pack(fill="x", pady=5, padx=5)
tk.Label(receiver_frame, text="To:", bg="white", font=("Arial", 10)).pack(side="left")
receiver_entry = tk.Entry(receiver_frame, width=30)  # editable now
receiver_entry.pack(side="left", padx=5)

# Chat area
chat_area = tk.Text(right_panel, state='disabled', wrap='word', bg="white")
chat_area.tag_configure('right', justify='right', background="#dcf8c6", foreground="black", spacing3=5)
chat_area.tag_configure('left', justify='left', background="#f0f0f0", foreground="black", spacing3=5)
chat_area.pack(fill="both", expand=True, padx=5, pady=5)

# Input frame
input_frame = tk.Frame(right_panel, bg="#f0f0f0")
input_frame.pack(fill="x", pady=5)

message_entry = tk.Entry(input_frame, width=50)
message_entry.pack(side="left", padx=5, pady=5)
send_btn = tk.Button(input_frame, text="Send", command=send_message)
send_btn.pack(side="left", padx=5, pady=5)

# --- Receiving thread ---
threading.Thread(target=receive_messages, args=(chan,), daemon=True).start()

root.mainloop()
chan.close()
client.close()
