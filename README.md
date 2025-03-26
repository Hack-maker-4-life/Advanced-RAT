# ShadowReign
**Command the shadows. Rule the chaos.**

ShadowReign is a state-of-the-art remote administration tool (RAT) built entirely in Python. It features a sleek, user-friendly GUI for managing connected clients, with powerful capabilities like keylogging, file management, media capture, system control, and more. Designed for enthusiasts and tinkerers, this project showcases advanced Python scripting in a dark, modern package.

⚠️ **Disclaimer**: This is a proof-of-concept for educational purposes only. Use responsibly and legally. The authors are not liable for misuse.

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

## Project Structure
- **shadowreign_gui.py**: The control center GUI for managing clients.
- **shadowreign.py**: The client-side payload for deployment.
- **setup.bat**: Windows bootstrapper to install Python and dependencies before running the payload.
- **requirements.txt**: List of Python libraries needed for both GUI and payload.

## Prerequisites
- **Python 3.11+**: Required for both GUI and payload.
- **Internet Access**: Needed for initial setup on targets (downloads Python and libs).
- **Port 5251**: Open on the control machine (default C2 server: 192.168.1.133:5251).

## Setup

### Control Machine (GUI)
1. **Clone the Repo**:
    ```bash
    git clone https://github.com/yourusername/ShadowReign.git
    cd ShadowReign
    ```
2. **Install Dependencies**: Make sure your environment has all the required libraries:
    ```bash
    pip install -r requirements.txt
    ```
3. **Install Additional Libraries for Linux**: If you're on Linux, you may need to install tkinter (for GUI support):
    - For Ubuntu/Debian:
        ```bash
        sudo apt-get install python3-tk
        ```
    - For Fedora:
        ```bash
        sudo dnf install python3-tkinter
        ```
4. **Run the GUI**:
    - On Linux:
        ```bash
        python3 shadowreign_gui.py
        ```
    - On Windows:
        ```bash
        python shadowreign_gui.py
        ```

5. **Open Port 5251**: Make sure port 5251 is open on your firewall/router to allow the C2 communication.

### Target Machine (Payload)
1. **Drop the Payload**: Transfer `setup.bat` and `shadowreign.py` to the target machine. You can use a USB drive, file sharing, or any other method.

2. **Run the Setup**: On the target machine, execute `setup.bat`:
    This will:
    - Install Python 3.11.6 (if not already installed).
    - Install the required dependencies.
    - Launch the payload in stealth mode.

    **Admin Privileges**: You will need administrator rights for Python installation and for running the setup script.

    **Internet Connection**: Ensure the target machine has internet access during setup to fetch the necessary Python libraries.

## Usage

### Launch the GUI
Start `shadowreign_gui.py` on your control machine. You should see a list of connected clients in the sidebar.

### Select a Target
Click on a client to start controlling it.

### Control Features:
- **Keylogger**: Start/stop logging, dump logs.
- **File Management**: Browse the target’s files, upload or download files.
- **Media Capture**: Take screenshots or videos, save them to your local system.
- **System Control**: Dump system information, extract WiFi passwords, escalate privileges.
- **Pranks**: Trigger fun pranks like system crashes, jumpscares, or fork bombs.
- **Shell Access**: Execute commands on the target system and view the output.
- **Live Streaming**: Capture streams from the target’s screen, webcam, and mic (saved locally).
- **Save Files**: Files you capture will be saved in your home directory with a `ShadowReign_` prefix.

## Limitations
- **Streaming**: Streams are captured but not displayed live at the moment.
- **Windows Bias**: `setup.bat` is Windows-only. Linux setup requires manual configuration.
- **AV Detection**: The payload might trigger antivirus software. You can attempt to obfuscate it using tools like PyArmor.

## Contribute
This is a Python playground. Fork it, modify it, and submit pull requests. Let’s make it stronger together. but include me

## License
This project is licensed under the MIT License. You can do whatever you like with it—just don’t blame us if things go sideways.

## Updates
If yall have any ideas to make this better or for me to add let me know and ill try to add it.

comming soon:AV BYPASS (ALREADY BYPASS MOST OF IT BUT NOT FULLY)

**ShadowReign: best of the best**
