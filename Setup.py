#!/usr/bin/env python3
import os
import subprocess
from pathlib import Path

# Get parent directory
base_dir = Path(__file__).parent.absolute()

# Run CVE_Looter OneTimeRun.py if exists
cve_script = base_dir / "CVE_Looter" / "OneTimeRun.py"
if cve_script.exists():
    subprocess.run(["python3", str(cve_script)])

# Run Telegram_CVE OneTimeRun.py if exists
telegram_script = base_dir / "Telegram_CVE" / "OneTimeRun.py"
if telegram_script.exists():
    subprocess.run(["python3", str(telegram_script)])

# Self-destruct
os.remove(__file__)
