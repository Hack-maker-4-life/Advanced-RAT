ShadowReign
Command the shadows. Rule the chaos.

ShadowReign is an advanced remote administration tool (RAT) built with Python. With a sleek, dark-themed GUI, it allows you to manage connected clients with powerful features like keylogging, file management, media capture, system control, and more. Designed for tech enthusiasts and tinkerers, this project demonstrates the capabilities of Python scripting in a modern, efficient package.

WARNING: This tool is a proof-of-concept and intended for educational purposes only. The authors do not condone illegal use. Use responsibly and ensure compliance with all applicable laws.

Features
Cross-Platform GUI: Runs on both Linux and Windows with an intuitive, dark-themed interface.

Keylogger: Real-time keystroke capture and display.

File Management: Seamlessly browse, upload, and download files.

Media Capture: Capture screenshots, record screens, and snap webcam photos (saved locally).

System Control: Extract system information, Wi-Fi passwords, and attempt privilege escalation.

Pranks: Execute fun pranks like jumpscares, system crashes, or fork bombs.

Shell Access: Run remote shell commands with feedback.

Live Streaming: Receive saved streams from screen, webcam, and mic (not displayed live).

Encryption: AES-256 CBC encryption ensures secure communication.

Persistence: Automatically starts on target systems.

Project Structure
diff
Copy
Edit
- shadowreign_gui.py  : GUI for controlling and managing clients.
- shadowreign.py      : Client-side payload for deployment.
- setup.bat           : Windows bootstrapper to install Python and dependencies.
- requirements.txt    : Python libraries required for both GUI and payload.
Prerequisites
Python 3.11+: Required for both the GUI and payload.

Internet Access: Required for initial setup (downloads Python and dependencies).

Port 5251: Open on the control machine (default C2 server: 192.168.1.133:5251).

Setup
Control Machine (GUI)
Clone the Repo:

bash
Copy
Edit
git clone https://github.com/yourusername/ShadowReign.git
cd ShadowReign
Install Dependencies:

bash
Copy
Edit
pip install -r requirements.txt
On Linux, install tkinter:

For Ubuntu/Debian:

bash
Copy
Edit
sudo apt-get install python3-tk
For Fedora:

bash
Copy
Edit
sudo dnf install python3-tkinter
Run the GUI:

Linux:

bash
Copy
Edit
python3 shadowreign_gui.py
Windows:

bash
Copy
Edit
python shadowreign_gui.py
Network Configuration:

Ensure that 192.168.1.133:5251 is accessible. Adjust firewall or router settings as necessary.

Target Machine (Payload)
Deploy Files:

Copy setup.bat and shadowreign.py to the target machine.

Execute:

On Windows, run setup.bat. This will:

Install Python 3.11.6 if missing.

Install all dependencies.

Launch shadowreign.py silently.

Notes:

Requires admin rights for a system-wide Python installation.

An internet connection is required for the initial setup.

Usage
Start the GUI: Launch shadowreign_gui.py on your control machine. Clients will appear in the sidebar as they connect.

Select a Client: Click on a client from the list to interact with it.

Issue Commands: Use the tabs to manage tasks:

Keylogger: Start, stop, or dump logs.

Files: Browse, upload, or download files.

Media: Capture screenshots, videos, or webcam photos (saved locally).

System: Extract data or escalate privileges.

Pranks: Execute fun pranks on the client system.

Shell: Run commands with output displayed.

Live: Stream data (saved, not displayed live).

File Output: Files will be saved in your home directory (~/ on Linux, %USERPROFILE% on Windows), prefixed with ShadowReign_.

Screenshots
(Add relevant screenshots, e.g., GUI with client list, media tab, screenshots captured, etc.)

Limitations
Streaming: Live streams are saved but not displayed in real-time (future feature).

Windows Focus: setup.bat is Windows-only. Linux users must manually set up or create a .sh equivalent.

AV Detection: The payload may trigger antivirus software. Obfuscation (e.g., using PyArmor) is recommended.

Contributing
Feel free to fork, modify, and create pull requests. This is a playground for Python developers—make it your own!

License
MIT License—do what you want, just don’t blame us.

ShadowReign: Where control meets chaos. Built by a god, for a god.

