#!/bin/bash
cd "$(dirname "$0")"
# Run the scanner with sudo for full ARP discovery
sudo ./venv/bin/python network_scanner.py scan --range 192.168.1.0/24 --quiet >> scan.log 2>&1
