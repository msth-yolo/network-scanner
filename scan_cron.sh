#!/bin/bash
# Wrapper script for the network scanner cron job
# Usage: ./scan_cron.sh [network_range]

# Get the script's directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
NETWORK_RANGE=${1:-"10.0.2.0/24"}

# Log timestamp
echo "--- Scan started at $(date) ---"

# Run the scanner
# Using sudo if needed, though often it's needed for ARP/MAC info
# On some systems, nmap needs root for the best info
# But here we assume the user has permissions or we run as root
python3 "$DIR/network_scanner.py" scan --range "$NETWORK_RANGE"

echo "--- Scan completed at $(date) ---"
echo ""
