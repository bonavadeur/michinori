#!/usr/bin/env bash
echo "RUNNING DETECTION APP"
export LC_CTYPE=en_US.UTF-8
python3 yolo_detection.py
# Just a loop to keep the container running
while true; do :; done