#!/usr/bin/env python3
import os
from pathlib import Path

# Get current script's directory as the base path
BASE_PATH = Path(__file__).parent.absolute()

# Cron entries to add (using relative paths)
CRON_JOBS = f"""
#CVE_Looter
0 * * * * python {BASE_PATH}/Looter.py
20 * * * * python {BASE_PATH}/Filter.py
52 * * * * python {BASE_PATH}/SubProject/github_collecter.py
"""

# Add to crontab
os.system(f'(crontab -l 2>/dev/null; echo "{CRON_JOBS}") | crontab -')

# Self-destruct
os.remove(__file__)
