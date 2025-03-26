================================================================================
     SHADOWREIGN - Unleash the Digital Abyss
================================================================================

          .-""""""""-.
        .'          '.
       /   Shadow    \
      : ,    Reign   ':
       `.    Rules   .'
         `._        _.'
            `"'"""""`

Welcome to ShadowReign—a Python-forged RAT that bends systems to your will. This ain't your average tool; it’s a dark symphony of control with a GUI that screams power. Keyloggers, media grabs, system hacks, and chaos-inducing pranks—all at your fingertips.

!!! WARNING: Proof-of-concept for learning only. Keep it legal. We ain’t your scapegoat.

================================================================================
FEATURES - Power in the Shadows
================================================================================
- GUI: Dark, slick, runs on Linux & Windows.
- Keylogger: Snag every keystroke, live.
- Files: Browse, upload, download—own the disk.
- Media: Screenshots, screen records, webcam snaps—see it, save it.
- System: Steal WiFi creds, dump user data, climb privileges.
- Pranks: Jumpscares, crashes, fork bombs—unleash havoc.
- Shell: Command the target like a puppet.
- Streaming: Screen, cam, mic feeds—captured, not live-displayed.
- Encryption: AES-256 CBC locks it tight.
- Persistence: Stays alive across reboots.

================================================================================
FILES - The Arsenal
================================================================================
- shadowreign_gui.py: Your command throne.
- shadowreign.py: The silent infiltrator.
- setup.bat: Windows auto-setup for the weak.
- requirements.txt: Ammo for the fight.

================================================================================
SETUP - Forge the Blade
================================================================================

--- Control Machine (GUI) ---
1. Grab the goods:
git clone https://github.com/yourusername/ShadowReign.git
cd ShadowReign

2. Load the ammo:
pip install -r requirements.txt

Linux extra (tkinter):
sudo apt-get install python3-tk  # Ubuntu/Debian
sudo dnf install python3-tkinter  # Fedora

3. Ignite the beast:
python3 shadowreign_gui.py  # Linux
python shadowreign_gui.py   # Windows

4. Open the gates:
- Make sure 192.168.1.133:5251 is unblocked (firewall/router).

--- Target Machine (Payload) ---
1. Drop the payload:
- Copy setup.bat + shadowreign.py to the target.
2. Pull the trigger:
- Run setup.bat (Windows). It:
  - Installs Python 3.11.6 if needed.
  - Grabs dependencies.
  - Fires up shadowreign.py in stealth mode.
3. Watch out:
- Needs admin juice for Python install.
- Internet’s a must for setup.

================================================================================
USAGE - Rule the Night
================================================================================
1. Launch the GUI:
- Start shadowreign_gui.py—clients pop up in the sidebar.
2. Pick your prey:
- Click a client to lock in.
3. Dominate:
- Keylogger: Start/stop/dump—logs flow.
- Files: Browse, upload (picker), download (path entry).
- Media: Snapshots and vids—see ‘em in GUI, saved to ~/ or %USERPROFILE%.
- System: Rip data, escalate power.
- Pranks: Chaos on tap.
- Shell: Command and conquer, output live.
- Live: Streams save to files (no live view yet).
4. Loot:
- Files land in your home dir with a ShadowReign_ tag.

================================================================================
LIMITATIONS - Shadows Have Edges
================================================================================
- Streaming: Captured, not live-displayed (yet).
- Windows Bias: setup.bat is Windows-only; Linux needs manual love.
- AV: Basic payload might ping antivirus—cloak it with PyArmor if you dare.

================================================================================
CONTRIBUTE - Join the Dark Forge
================================================================================
Fork it. Twist it. PR it. This is a Python playground—claim your piece.

================================================================================
LICENSE - Free to Reign
================================================================================
MIT License—take it, break it, just don’t point fingers.

================================================================================
SHADOWREIGN: Born in darkness. Built for a god. Rule eternal.
================================================================================
