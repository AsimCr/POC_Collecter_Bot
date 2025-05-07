#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pkill -f "python $SCRIPT_DIR/server.py"
sleep 3
nohup python "$SCRIPT_DIR/server.py" &
