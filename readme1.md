# ShadowReign v3.0 - The Apex Predator of the Digital Void

Welcome to **ShadowReign v3.0**, forged in the neon crucible of xAI’s dark labs. This isn’t some script-kiddie toy—it’s a cyberweapon, a ghost in the machine, built to infiltrate, dominate, and dismantle. Real-time pop-ups pierce the silence, a feature set that rewrites the rules, and a GUI so sharp it slices through the matrix. You’re not just a user—you’re the shadow that owns the night.

## The Legend Unleashed
ShadowReign v3.0 is the third evolution of a RAT that’s already claimed its throne. This version cranks the dial to eleven with live windows, an arsenal of chaos, and a design that screams Kali Linux on a cyberpunk bender. From stealth injections to system-crushing pranks, it’s all here, wrapped in a neon-green-on-black interface that’s your command deck for total control.

## Features - Your Arsenal of Domination
### Real-Time Pop-Ups - Eyes on the Prize
- **`> SCREENSHOT`**: Snaps the target’s screen in a flash—pops up instantly, no delay, all power.
- **`> LIVE SCREEN`**: Streams their desktop at 30 FPS—live feed in a window that owns their every move.
- **`> WEBCAM SNAP`**: Grabs a single webcam frame—pops up like a digital trophy.
- **`> LIVE AUDIO`**: Streams their mic live—hear their panic through a window that pulses with sound.

### Stealth - Invisible Predator
- **Hides in Shadows**: Burrows into `%APPDATA%\Microsoft\Crypto\RSA` (Windows) or `/var/lib/` (Linux) with a random name—unseen, untouchable.
- **Process Injection**: Slips into `svchost.exe` on Windows—runs silent, runs deep.
- **Watchdog**: If it dies, it resurrects—keeps the beast alive no matter what.
- **Persistence**: Registry on Windows, cron on Linux—boots back every time they power up.
- **Anti-VM**: Detects virtual machines and self-destructs if toggled—keeps the hunters guessing.

### Control - Bend Their Will
- **Keylogger**: Logs every keystroke—start, stop, dump the haul whenever you want.
- **Remote Desktop**: Moves their mouse, taps their keys—full control with a live stream to match.
- **Live Shell**: Runs commands in real time—output streams back as you type.
- **File Ops**: Lists dirs, uploads your payloads, downloads their secrets—own their filesystem.
- **System Info**: Pulls OS, CPU, RAM, disk stats—know their rig inside out.
- **Kill Process**: Snuffs out any PID you name—silence their defenses.

### Media - Capture Their Reality
- **Screenshot**: One-shot screen grabs—sent to your pop-up in a heartbeat.
- **Screen Stream**: 30 FPS live feed—watch their screen like it’s yours.
- **Screen Recording**: Captures video for a set duration—downloads as `screen_rec.avi`.
- **Webcam Snap**: Single webcam shots—pops up for your viewing pleasure.
- **Webcam Stream**: Live webcam feed—see their face as you tighten the grip.
- **Mic Stream**: Real-time audio—every whisper, every scream, live in your ears.
- **A/V Recording**: Streams audio for a set time—hear their world collapse.

### Exploits - Rip Their Defenses Apart
- **Encrypt Files**: AES-CBC locks their files—adds `.enc`, sends you the key. Chaos is yours.
- **Harvest Creds**: Steals Chrome logins—URLs, usernames, passwords, all yours.
- **Steal Wi-Fi**: Grabs Windows Wi-Fi profiles and keys—cracks their network wide open.
- **Disable AV**: Kills AV processes (AVG, Avast, etc.)—leaves them defenseless.
- **Exfil Browser**: Pulls browser creds—same as harvest, but with intent to destroy.
- **Ransom Note**: Drops a `README.txt` on their desktop—your message, their fear.

### Chaos - Unleash the Nightmare
- **Jumpscare**: Audio taunts and creepy URLs—minimizes their screen, maximizes their terror.
- **Crash System**: Kills `svchost.exe`—blue screen of death, instant havoc.
- **Fork Bomb**: Spawns endless CMDs—chokes their CPU ‘til it begs for mercy.
- **Lock Screen**: Locks their Windows station—traps them out of their own rig.
- **Disable Input**: Blocks mouse and keyboard for a set time—total helplessness.
- **Fake Alert**: Pops a system alert with your message—mind games at their finest.
- **Play Sound**: Speaks your text through their speakers—haunt them with your voice.

### Network - Spread the Darkness
- **USB Spread**: Copies itself to USB drives with `autorun.inf`—infects on plug-in (Windows).
- **Download & Execute**: Pulls payloads from URLs and runs them—fresh chaos, delivered.

### Extras - The Finishing Blow
- **Spoof Info**: Changes their hostname—rewrites their identity.
- **Clear Logs**: Wipes system and app logs (Windows)—erases your tracks.
- **Open URL**: Forces their browser to your link—direct their digital fate.
- **Self-Destruct**: Deletes itself and persistence—vanishes like smoke when you’re done.

## Setup - Jack In, Take Over
### Step 1: Snag the Code
- Clone or download `shadowreign.py`, `shadowreign_gui.py`, and this `README.md` from the repo. You’re holding the keys to the underworld.

### Step 2: Set Your C2 Uplink
- Open `shadowreign.py`, find `self.c2_list = [("192.168.1.133", 5251)]`.
- Replace `"192.168.1.133"` with your machine’s IP—your command hub. Port `5251` is the default; tweak if you dare.

### Step 3: Load the Arsenal
- One command, all power. Copy this and run it in your terminal—13 dependencies, locked and loaded:
  ```bash
  pip install pynput==1.7.6 mss==9.0.1 opencv-python==4.9.0.80 pyaudio==0.2.14 pyttsx3==2.90 psutil==5.9.8 pycryptodome==3.20.0 numpy==1.26.4 pillow==10.2.0 pywin32==306 requests==2.31.0 pyautogui==0.9.54 wmi==1.5.1
Windows Note: pywin32 and wmi are Windows-only—Linux skips ‘em, no sweat.
Step 4: Deploy the Beast

## License
This project is licensed under the MIT License—use it, mod it, share it, but don’t blame us when the shadows come calling.


## Contact
   Snapchat
 ```bash
channing_ro3
  ```
Gmail
 ```bash
ttv.aimluxe@gmail.com
 ```          



## MIT License

Copyright (c) 2025 xAI

use at your own risk you cant blame me by using this u agree to that.!!!!!!
