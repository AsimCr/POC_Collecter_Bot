#!/bin/bash

pkill -f "python /home/kali/Projects/Telegram_CVE/server.py"
sleep 3
nohup python /home/kali/Projects/Telegram_CVE/server.py &