#!/bin/bash
pip install -r requirements.txt --break-system-packages
chmod +x jwtdrive.py
sudo ln -sf "$(pwd)/jwtdrive.py" /usr/local/bin/jwtdrive
echo "[+] jwtdrive installed. Run: jwtdrive -h"
