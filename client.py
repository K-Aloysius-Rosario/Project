import paramiko
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox

messages = {}              # contact -> [(side, text)]
current_contact = None     # selected chat
contacts = set()           # unique contacts

# ---------------- CHAT LOGIC ----------------

def add_contact(name):
    if name not in contacts:
        contacts.add(name)
        contacts_list.insert(tk.END, name)

def add_message(contact, side, text):
    global current_contact
    add_contact(contact)

    if contact not in messages:
        messages[contact] = []

    messages[contact].append((side, text))

    if current_contact == contact:
        display_messages(contact)

def display_messages(contact):
    chat_area.config(state='normal')
    chat_area.delete('1.0', tk.END)

    for side, text in messages.get(contact, []):
        tag = 'right' if side == 'right' else 'left'
        prefix = "You: " if side == 'right' else ""
        chat_area.insert(tk.END, prefix + text + "\n", tag)

    chat_area.config(state='disabled')
    chat_area.yview(tk.END)

def select_contact(event):
    global current_contact
    if not contacts_list.curselection():
        return

    index = contacts_list.curselection()[0]
    contact = contacts_list.get(index)

    current_contact = contact
    receiver_entry.delete(0, tk.END)
    receiver_entry.insert(0, contact)

    display_messages(contact)

# ---------------- NETWORK ----------------

def receive_messages(chan):
    while True:
        try:
            data = chan.recv(1024)
            if not data:
                break

            text = data.decode().strip()

            if "|" in text:
                sender, msg = text.split("|", 1)
                add_message(sender, 'left', msg)

        except:
            break

def send_message():
    global current_contact

    target = receiver_entry.get().strip()
    if not target:
        messagebox.showwarning("No Receiver", "Enter a username in the To: field!")
        return

    msg = message_entry.get().strip()
    if not msg:
        return

    try:
        chan.send(f"{target}|{msg}".encode())
        add_message(target, 'right', msg)
        current_contact = target
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send message: {e}")

    message_entry.delete(0, tk.END)

# ---------------- GUI ----------------

root = tk.Tk()
root.title("SSH Messenger")
root.geometry("700x500")
root.resizable(False, False)

# ---- SSH CONNECT ----

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

# ---- LAYOUT ----

left_panel = tk.Frame(root, width=200, bg="#f0f0f0")
left_panel.pack(side="left", fill="y")

tk.Label(left_panel, text="Contacts", bg="#f0f0f0",
         font=("Arial", 12, "bold")).pack(pady=5)

contacts_list = tk.Listbox(left_panel)
contacts_list.pack(fill="both", expand=True, padx=5, pady=5)
contacts_list.bind("<<ListboxSelect>>", select_contact)

right_panel = tk.Frame(root, bg="white")
right_panel.pack(side="right", fill="both", expand=True)

receiver_frame = tk.Frame(right_panel, bg="white")
receiver_frame.pack(fill="x", pady=5, padx=5)

tk.Label(receiver_frame, text="To:", bg="white").pack(side="left")
receiver_entry = tk.Entry(receiver_frame, width=30)
receiver_entry.pack(side="left", padx=5)

chat_area = tk.Text(right_panel, state='disabled', wrap='word')
chat_area.tag_configure('right', justify='right',
                        background="#dcf8c6", spacing3=5)
chat_area.tag_configure('left', justify='left',
                        background="#f0f0f0", spacing3=5)
chat_area.pack(fill="both", expand=True, padx=5, pady=5)

input_frame = tk.Frame(right_panel, bg="#f0f0f0")
input_frame.pack(fill="x")

message_entry = tk.Entry(input_frame, width=50)
message_entry.pack(side="left", padx=5, pady=5)

tk.Button(input_frame, text="Send", command=send_message)\
    .pack(side="left", padx=5)

# ---- RECEIVE THREAD ----

threading.Thread(
    target=receive_messages,
    args=(chan,),
    daemon=True
).start()

root.mainloop()

chan.close()
client.close()
