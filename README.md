# ShadowReign

**Command the shadows. Rule the chaos.**

ShadowReign is a state-of-the-art remote administration tool (RAT) built entirely in Python. It features a sleek, user-friendly GUI for managing connected clients, with powerful capabilities like keylogging, file management, media capture, system control, and more. Designed for enthusiasts and tinkerers, this project showcases advanced Python scripting in a dark, modern package.

⚠️ **Disclaimer**: This is a proof-of-concept for educational purposes only. Use responsibly and legally. The authors are not liable for misuse.

---

## Features

- **Cross-Platform GUI**: Runs on Linux and Windows with a dark-themed, intuitive interface.
- **Keylogger**: Capture and display keystrokes in real-time.
- **File Management**: Browse, upload, and download files with ease.
- **Media Capture**: Grab screenshots, record screens, and snap webcam shots, displayed and saved locally.
- **System Control**: Extract system info, WiFi passwords, and attempt privilege escalation.
- **Pranks**: Unleash jumpscares, system crashes, or fork bombs for fun.
- **Shell Access**: Execute remote commands with output feedback.
- **Live Streaming**: Receive screen, webcam, and mic streams (saved, not displayed live).
- **Encryption**: AES-256 CBC secures all communications.
- **Persistence**: Auto-starts on target systems.

---

## Project Structure

- `shadowreign_gui.py`: The control center GUI for managing clients.
- `shadowreign.py`: The client-side payload for deployment.
- `setup.bat`: Windows bootstrapper to install Python and dependencies before running the payload.
- `requirements.txt`: List of Python libraries needed for both GUI and payload.

---

## Prerequisites

- **Python 3.11+**: Required for both GUI and payload.
- **Internet Access**: Needed for initial setup on targets (downloads Python and libs).
- **Port 5251**: Open on the control machine (default C2 server: `192.168.1.133:5251`).

---

## Setup

### Control Machine (GUI)
1. **Clone the Repo**:
   ```bash
   git clone https://github.com/yourusername/ShadowReign.git
   cd ShadowReign
