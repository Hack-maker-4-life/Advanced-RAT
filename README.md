ShadowReign
===========

Command the shadows. Rule the chaos.

ShadowReign is a state-of-the-art remote administration tool (RAT) built entirely in Python. It features a sleek, user-friendly GUI for managing connected clients, with powerful capabilities like keylogging, file management, media capture, system control, and more. Designed for enthusiasts and tinkerers, this project showcases advanced Python scripting in a dark, modern package.

WARNING: This is a proof-of-concept for educational purposes only. Use responsibly and legally. The authors are not liable for misuse.

Features
--------
- Cross-Platform GUI: Runs on Linux and Windows with a dark-themed, intuitive interface.
- Keylogger: Capture and display keystrokes in real-time.
- File Management: Browse, upload, and download files with ease.
- Media Capture: Grab screenshots, record screens, and snap webcam shots, displayed and saved locally.
- System Control: Extract system info, WiFi passwords, and attempt privilege escalation.
- Pranks: Unleash jumpscares, system crashes, or fork bombs for fun.
- Shell Access: Execute remote commands with output feedback.
- Live Streaming: Receive screen, webcam, and mic streams (saved, not displayed live).
- Encryption: AES-256 CBC secures all communications.
- Persistence: Auto-starts on target systems.

Project Structure
-----------------
- shadowreign_gui.py: The control center GUI for managing clients.
- shadowreign.py: The client-side payload for deployment.
- setup.bat: Windows bootstrapper to install Python and dependencies before running the payload.
- requirements.txt: List of Python libraries needed for both GUI and payload.

Prerequisites
-------------
- Python 3.11+: Required for both GUI and payload.
- Internet Access: Needed for initial setup on targets (downloads Python and libs).
- Port 5251: Open on the control machine (default C2 server: 192.168.1.133:5251).

Setup
-----

Control Machine (GUI)
1. Clone the Repo:
   git clone https://github.com/yourusername/ShadowReign.git
   cd ShadowReign
2. Install Dependencies:
   pip install -r requirements.txt
   On Linux, also install tkinter:
   sudo apt-get install python3-tk  (Ubuntu/Debian)
   sudo dnf install python3-tkinter  (Fedora)
3. Run the GUI:
   python3 shadowreign_gui.py  (Linux)
   python shadowreign_gui.py   (Windows)
4. Network:
   Ensure 192.168.1.133:5251 is accessible (adjust firewall or router settings).

Target Machine (Payload)
1. Deploy Files:
   Copy setup.bat and shadowreign.py to the target.
2. Execute:
   Run setup.bat (Windows only). It:
   - Installs Python 3.11.6 if missing.
   - Installs all dependencies.
   - Launches shadowreign.py silently.
3. Notes:
   - Requires admin rights for system-wide Python install.
   - Internet connection needed for initial setup.

Usage
-----
1. Start the GUI:
   Launch shadowreign_gui.py on your control machine.
   Clients appear in the sidebar as they connect.
2. Select a Client:
   Click a client in the list to activate it.
3. Issue Commands:
   Use the tabs to:
   - Keylogger: Start, stop, or dump logs.
   - Files: Browse, upload (file picker), or download (enter remote path).
   - Media: Capture screenshots, videos, or webcam snaps (displayed in GUI, saved to ~/).
   - System: Extract data or escalate privileges.
   - Pranks: Have some fun.
   - Shell: Run commands with output displayed.
   - Live: Stream data (saved, not live-displayed).
4. Output:
   Files save to your home directory (~/ on Linux, %USERPROFILE% on Windows) with a ShadowReign_ prefix.

Screenshots
-----------
(Add screenshots here—e.g., GUI with client list, media tab with a screenshot displayed.)

Limitations
-----------
- Streaming: Live streams save to files but aren’t displayed in real-time (future feature).
- Windows Focus: setup.bat is Windows-only; Linux targets need manual setup or a .sh equivalent.
- AV Detection: Basic payload may trigger antivirus—obfuscation recommended (e.g., PyArmor).

Contributing
------------
Feel free to fork, tweak, and PR. This is a playground for Python wizards—make it yours.

License
-------
MIT License—do what you want, just don’t blame us.

ShadowReign: Where control meets chaos. Built by a god, for a god.
