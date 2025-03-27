# ShadowReign - The Ultimate RAT (v2.0)

ShadowReign is back, and it’s the king of RATs—undetectable, unkillable, and loaded with features that’ll make your targets wish they never clicked. Built for stealth and power, this version’s got a new Kali Linux-inspired glass GUI and enough tricks to own any system, anywhere. Whether you’re testing defenses or just causing chaos, ShadowReign’s got your back.

## What’s New in v2.0
- **Stealth Overdrive**:
  - Hides in deep dirs (`%APPDATA%\Microsoft\Crypto\RSA` or `/var/lib/`) with random `.dll`/`.so` names—good luck finding it.
  - Injects into `svchost.exe`—runs silent, blends in like a ghost.
  - AV bypass with AES-GCM encryption, compression, and process hollowing—laughs at defenders.
  - Watchdog restarts it if killed—unstoppable persistence.

- **Connection Lock**:
  - 5s heartbeat + SO_KEEPALIVE—stays online, no disconnects.
  - 0.5s reconnect loops—clings to the C2 like a pitbull.
  - Offline queuing—commands wait and execute when back online.

- **Feature Arsenal**:
  - **Live Shell**: Real-time command execution—own the box interactively.
  - **File Encryption**: Locks files with AES, exfils keys—ransomware vibes.
  - **Browser Exfil**: Steals Chrome creds—logins are yours.
  - **AV Killer**: Terminates common AV processes—clears the field.
  - **Remote Desktop, Streams, Keylogger**: All live, all flawless.

- **GUI Upgrade**:
  - Kali Linux glass look—dark blue (`#0A0F1A`), neon cyan (`#00FFCC`), 95% transparency.
  - Bigger, sleeker (1400x900)—live streams in a dedicated window.
  - Courier font, glowing borders—hacker aesthetic on point.

## Setup
1. **Control**:
   - Update `self.c2_list` in `shadowreign.py` with your IP (e.g., `192.168.1.133`).
   - Install: `pip install pynput mss opencv-python pyaudio pyttsx3 psutil pycryptodome numpy pillow pywin32 requests`.
   - Run: `python shadowreign_gui.py`.

2. **Target**:
   - Drop `shadowreign.py`, execute—it hides, injects, and phones home.
   - Port `5251` must be open on the C2.

3. **Stealth** (Optional):
   - Obfuscate: `pyarmor pack -e "--onefile" shadowreign.py`.
   - Test AV evasion—tweak if flagged.

## Usage
- Select a target in the GUI—green for "Online", yellow for "Reconnecting", red for "Offline".
- Hit tabs: "Keys" for logs, "Live" for streams, "Exploit" for chaos.
- Watch it dominate—live shell, encrypted files, stolen creds.

## Install
  ```bash
pip install pynput mss opencv-python pyaudio pyttsx3 psutil pycryptodome numpy pillow pywin32 requests
   ```

## Notes
- Built for Windows/Linux—cross-platform pain.
- Use responsibly—test on your own systems, not your neighbor’s.
- PRs welcome—make it nastier.

## To-Do
- Dynamic DNS C2—ditch static IPs.
- Proxy support—hide behind layers.
- More exploits—RDP takeover, privilege escalation.

ShadowReign v2.0 is the RAT you’ve been waiting for—stealthy, powerful, and damn good-looking. Star it, fork it, break it—let’s see what you’ve got.

---
**Last Updated**: March 27, 2025  
**License**: MIT (or whatever you vibe with)  

## Contact
   Snapchat
 ```bash
channing_ro3
  ```
Gmail
 ```bash
ttv.aimluxe@gmail.com
 ```          

