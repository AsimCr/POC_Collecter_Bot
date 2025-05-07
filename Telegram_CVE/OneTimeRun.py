#!/usr/bin/env python3
import os
from pathlib import Path

BASE_PATH = Path(__file__).parent.absolute()
CRON_JOBS = f"""
#Telegram_CVE
28,58 * * * * {BASE_PATH}/Server_Runner.py
5 * * * * python {BASE_PATH}/check_cves.py
8 * * * * python {BASE_PATH}/NewsLetter.py
"""

os.system(f'(crontab -l 2>/dev/null; echo "{CRON_JOBS}") | crontab -')
os.remove(__file__)
