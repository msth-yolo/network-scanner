#!/usr/bin/env python3
"""
Network Scanner Bot - Home Network Device Discovery and Tracking
Uses nmap to scan the local network and stores results in SQLite.
"""

import argparse
import os
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path
import nmap
from mac_vendor_lookup import MacLookup
import subprocess

TELEGRAM_TO = "8533701109" # Tom's personal Telegram ID
TELEGRAM_CHANNEL = "telegram" # Or a specific channel name if needed

def send_alert(message):
    """Sends an alert message using OpenClaw's message tool."""
    try:
        subprocess.run(
            ["openclaw", "message", "send", "--message", message, "--channel", TELEGRAM_CHANNEL, "--to", TELEGRAM_TO],
            check=True,
            capture_output=True,
            text=True
        )
        print(f"Alert sent: {message}")
    except subprocess.CalledProcessError as e:
        print(f"Error sending alert: {e}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
    except FileNotFoundError:
        print("Error: 'openclaw' command not found. Is OpenClaw CLI installed and in PATH?")

# Database and config paths
DB_PATH = Path(__file__).parent / "network_devices.db"
DEFAULT_SCAN_RANGE = "192.168.1.0/24"


def init_db():
    """Initialize the SQLite database with required tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Main devices table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT,
            ip_address TEXT,
            hostname TEXT,
            vendor TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            UNIQUE(mac_address)
        )
    """)
    
    # Device history table - tracks all appearances
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            ip_address TEXT,
            hostname TEXT,
            seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    """)
    
    # Scan history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_range TEXT,
            devices_found INTEGER,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    return conn

def get_vendor(mac_address):
    """Lookup vendor by MAC address."""
    if not mac_address:
        return None
    try:
        return MacLookup().lookup(mac_address)
    except Exception:
        return "Unknown"

def scan_network(network_range=DEFAULT_SCAN_RANGE):
    """Scan the network using nmap and return discovered devices."""
    nm = nmap.PortScanner()
    
    print(f"Scanning {network_range}...")
    
    # Scan for hosts with basic info (no port scan to be faster)
    # -sn: ping scan (no port scan)
    # -PR: ARP scan for local network
    # sudo is often needed for MAC addresses on some systems, but ARP scan usually works on local subnet
    try:
        nm.scan(hosts=network_range, arguments='-sn -PR')
    except Exception as e:
        print(f"Error running nmap: {e}")
        return []
    
    devices = []
    for host in nm.all_hosts():
        info = {'ip': host, 'mac': None, 'hostname': None, 'vendor': None}
        
        # Get MAC address
        if 'addresses' in nm[host] and 'mac' in nm[host]['addresses']:
            info['mac'] = nm[host]['addresses']['mac']
        
        # Fallback to vendor lookup if nmap didn't provide it or if we want to be sure
        if info['mac']:
             # Try our library first
            vendor = get_vendor(info['mac'])
            if vendor != "Unknown":
                 info['vendor'] = vendor
            else:
                # Fallback to nmap's vendor info
                info['vendor'] = nm[host].get('vendor', {}).get(info['mac'], 'Unknown')

        # Get hostname
        if 'hostnames' in nm[host] and nm[host]['hostnames']:
             info['hostname'] = nm[host]['hostnames'][0].get('name', '')
        
        devices.append(info)
    
    return devices


def update_devices(conn, devices):
    """
    Update the database with discovered devices.
    Returns:
        tuple: (new_devices_list, left_devices_list)
    """
    cursor = conn.cursor()
    
    # 1. Get snapshot of currently active devices (MAC -> IP or IP -> IP)
    # Try to match by MAC first, then by IP for devices without MAC
    cursor.execute("SELECT mac_address, ip_address, hostname, vendor FROM devices WHERE is_active = 1")
    prev_active = {}
    for row in cursor.fetchall():
        mac, ip, hostname, vendor = row
        if mac:
            prev_active[mac] = {'ip': ip, 'hostname': hostname, 'vendor': vendor}
        elif ip:
            # Also index by IP for devices without MAC
            prev_active[f"ip:{ip}"] = {'ip': ip, 'hostname': hostname, 'vendor': vendor, 'no_mac': True}
    
    # 2. Process current scan
    current_ids = set()  # Will hold MAC addresses or "ip:XXX" for no-MAC devices
    new_devices = []
    
    for device in devices:
        mac = device.get('mac')
        ip = device.get('ip')
        
        # Use a consistent identifier
        device_id = mac if mac else f"ip:{ip}"
        
        # Check if this is a NEW device
        if device_id not in prev_active:
            new_devices.append(device)
            
        current_ids.add(device_id)
        
        # Check if device exists in DB (try MAC first, then IP)
        if mac:
            cursor.execute("SELECT id FROM devices WHERE mac_address = ?", (mac,))
            result = cursor.fetchone()
        else:
            result = None
            # Try to find by IP if no MAC
            if ip:
                cursor.execute("SELECT id FROM devices WHERE ip_address = ?", (ip,))
                result = cursor.fetchone()
        
        if result:
            # Update existing
            device_id_db = result[0]
            cursor.execute("""
                UPDATE devices 
                SET ip_address = ?, hostname = ?, vendor = ?, 
                    last_seen = CURRENT_TIMESTAMP, is_active = 1
                WHERE id = ?
            """, (ip, device['hostname'], device['vendor'], device_id_db))
            
            # Add history
            cursor.execute("""
                INSERT INTO device_history (device_id, ip_address, hostname)
                VALUES (?, ?, ?)
            """, (device_id_db, ip, device['hostname']))
        else:
            # Insert new
            cursor.execute("""
                INSERT INTO devices (mac_address, ip_address, hostname, vendor, is_active)
                VALUES (?, ?, ?, ?, 1)
            """, (mac, ip, device['hostname'], device['vendor']))
            
            device_id_db = cursor.lastrowid
            
            # Add history
            cursor.execute("""
                INSERT INTO device_history (device_id, ip_address, hostname)
                VALUES (?, ?, ?)
            """, (device_id_db, ip, device['hostname']))
    
    # 3. Identify who left
    # Left = in prev_active BUT NOT in current_ids
    left_devices = []
    for prev_id, info in prev_active.items():
        if prev_id not in current_ids:
            left_devices.append({'mac': prev_id if ':' not in prev_id else None, **info})
            # Mark as inactive in DB
            if ':' in prev_id:
                # It's an IP-only device
                cursor.execute("UPDATE devices SET is_active = 0 WHERE ip_address = ?", (info['ip'],))
            else:
                cursor.execute("UPDATE devices SET is_active = 0 WHERE mac_address = ?", (prev_id,))
            
    conn.commit()
    return new_devices, left_devices


def log_scan(conn, network_range, devices_found):
    """Log the scan to history."""
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_history (scan_range, devices_found)
        VALUES (?, ?)
    """, (network_range, devices_found))
    conn.commit()


def list_devices(conn, show_inactive=False):
    """List all devices in the database."""
    cursor = conn.cursor()
    
    query = """
        SELECT mac_address, ip_address, hostname, vendor, 
               first_seen, last_seen, is_active
        FROM devices
    """
    
    if not show_inactive:
        query += " WHERE is_active = 1"
    
    query += " ORDER BY last_seen DESC"
    
    cursor.execute(query)
    devices = cursor.fetchall()
    
    if not devices:
        print("No devices found.")
        return
    
    print("\n{:20} {:15} {:25} {:20} {:20} {:10}".format(
        "MAC Address", "IP Address", "Hostname", "Vendor", "Last Seen", "Status"))
    print("-" * 115)
    
    for dev in devices:
        mac, ip, hostname, vendor, first_seen, last_seen, is_active = dev
        status = "Active" if is_active else "Inactive"
        hostname = hostname or "-"
        vendor = vendor or "-"
        
        # Format last seen time
        last_seen_str = datetime.fromisoformat(last_seen).strftime("%Y-%m-%d %H:%M")
        
        print("{:20} {:15} {:25} {:20} {:20} {:10}".format(
            mac[:20] if mac else "-",
            ip or "-",
            hostname[:25] if hostname else "-",
            vendor[:20] if vendor else "-",
            last_seen_str,
            status
        ))


def show_history(conn, mac_address=None, limit=20):
    """Show device history."""
    cursor = conn.cursor()
    
    if mac_address:
        cursor.execute("""
            SELECT d.mac_address, d.ip_address, h.hostname, h.seen_at
            FROM device_history h
            JOIN devices d ON h.device_id = d.id
            WHERE d.mac_address = ?
            ORDER BY h.seen_at DESC
            LIMIT ?
        """, (mac_address.upper(), limit))
    else:
        cursor.execute("""
            SELECT d.mac_address, d.ip_address, h.hostname, h.seen_at
            FROM device_history h
            JOIN devices d ON h.device_id = d.id
            ORDER BY h.seen_at DESC
            LIMIT ?
        """, (limit,))
    
    history = cursor.fetchall()
    
    if not history:
        print("No history found.")
        return
    
    print("\n{:20} {:15} {:25} {:20}".format(
        "MAC Address", "IP Address", "Hostname", "Last Seen"))
    print("-" * 85)
    
    for entry in history:
        mac, ip, hostname, seen_at = entry
        seen_str = datetime.fromisoformat(seen_at).strftime("%Y-%m-%d %H:%M:%S")
        
        print("{:20} {:15} {:25} {:20}".format(
            mac[:20] if mac else "-",
            ip or "-",
            hostname or "-",
            seen_str
        ))


def show_scan_history(conn, limit=10):
    """Show recent scan history."""
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, scan_range, devices_found, scanned_at
        FROM scan_history
        ORDER BY scanned_at DESC
        LIMIT ?
    """, (limit,))
    
    scans = cursor.fetchall()
    
    if not scans:
        print("No scan history found.")
        return
    
    print("\n{:5} {:20} {:12} {:20}".format(
        "ID", "Scan Range", "Found", "Scanned At"))
    print("-" * 60)
    
    for scan in scans:
        scan_id, range_str, count, scanned_at = scan
        scanned_str = datetime.fromisoformat(scanned_at).strftime("%Y-%m-%d %H:%M:%S")
        
        print("{:20} {:15} {:20}".format(
            range_str, count, scanned_str))



def show_scan_diff(conn, scan1_id=None, scan2_id=None, limit=10):
    """Compare two specific scans."""
    cursor = conn.cursor()
    
    # Get scans
    if scan1_id and scan2_id:
        cursor.execute("SELECT id, scanned_at FROM scan_history WHERE id IN (?, ?)", (scan1_id, scan2_id))
        scans = cursor.fetchall()
        if len(scans) < 2:
            print("Scan IDs not found")
            return
    else:
        cursor.execute("SELECT id, scanned_at FROM scan_history ORDER BY scanned_at DESC LIMIT 2")
        scans = cursor.fetchall()
        if len(scans) < 2:
            print("Need at least 2 scans")
            return
        scan1_id = scans[1][0]
        scan2_id = scans[0][0]
    
    scan1_time = next(s[1] for s in scans if s[0] == scan1_id)
    scan2_time = next(s[1] for s in scans if s[0] == scan2_id)
    
    # Get IPs that appeared after scan1_time (new)
    cursor.execute("SELECT ip_address, hostname FROM devices WHERE last_seen > ?", (scan1_time,))
    new = [(r[0], r[1]) for r in cursor.fetchall() if r[0]]
    
    # Get IPs that were last seen before scan1_time (gone from view)
    cursor.execute("SELECT ip_address, hostname FROM devices WHERE last_seen <= ?", (scan1_time,))
    gone = [(r[0], r[1]) for r in cursor.fetchall() if r[0]]
    
    print(f"Comparing last scan ({scan1_time}) vs current state:")
    print(f"\n+ New/Recently seen ({len(new)}):")
    for ip, host in sorted(new)[:limit]:
        print(f"  + {ip} {host or ''}")
    print(f"\n- Not seen since last scan ({len(gone)}):")
    for ip, host in sorted(gone)[:limit]:
        print(f"  - {ip} {host or ''}")


def main():
    parser = argparse.ArgumentParser(
        description="Home Network Scanner Bot - Discover and track network devices"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan the network for devices")
    scan_parser.add_argument(
        "--range", "-r", 
        default=DEFAULT_SCAN_RANGE,
        help=f"Network range to scan (default: {DEFAULT_SCAN_RANGE})"
    )
    scan_parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress output (useful for cron)"
    )
    
    # List command
    list_parser = subparsers.add_parser("list", help="List discovered devices")
    list_parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Show all devices including inactive ones"
    )
    
    # History command
    history_parser = subparsers.add_parser("history", help="Show device history")
    history_parser.add_argument(
        "--mac", "-m",
        help="Filter by MAC address"
    )
    history_parser.add_argument(
        "--limit", "-l",
        type=int,
        default=20,
        help="Number of entries to show (default: 20)"
    )
    
    # Scan history command
    subparsers.add_parser("scans", help="Show scan history")
    diff_parser = subparsers.add_parser("diff", help="Compare scans")
    diff_parser.add_argument("--scan1", type=int, help="First scan ID")
    diff_parser.add_argument("--scan2", type=int, help="Second scan ID")
    diff_parser.add_argument("--limit", "-l", type=int, default=10)
    
    args = parser.parse_args()
    
    # Initialize database
    conn = init_db()
    
    if args.command == "scan":
        devices = scan_network(args.range)
        if not args.quiet:
            print(f"Found {len(devices)} devices")
        
        new_devs, left_devs = update_devices(conn, devices)
        log_scan(conn, args.range, len(devices))
        
        # Alerts (disabled by default - enable manually when needed)
        # if new_devs:
        #     print("\n[ALERT] New devices detected:")
        #     for d in new_devs:
        #         alert_message = f"🚨 New Device: {d['mac']} {d['vendor']} ({d['hostname']}) at {d['ip']}"
        #         send_alert(alert_message)
        #         
        # if left_devs:
        #     print("\n[ALERT] Devices left the network:")
        #     for d in left_devs:
        #         alert_message = f"👋 Device Left: {d['mac']} {d['vendor']} ({d['hostname']}) at {d['ip']}"
        #         send_alert(alert_message)

        if not args.quiet:
            print(f"Devices added: {len(new_devs)}")
            print(f"Devices left: {len(left_devs)}")
        
    elif args.command == "list":
        list_devices(conn, args.all)
        
    elif args.command == "history":
        show_history(conn, args.mac, args.limit)
        
    elif args.command == "scans":
        show_scan_history(conn)

    elif args.command == "diff":
        show_scan_diff(conn, args.scan1, args.scan2, args.limit)

    else:
        # Default: show help and list devices
        parser.print_help()
        print("\n--- Current Devices ---")
        list_devices(conn)
    
    conn.close()


if __name__ == "__main__":
    main()
