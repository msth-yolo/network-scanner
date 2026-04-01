import os
from pathlib import Path

OUI_PATH = Path(__file__).parent / "oui.txt"

_oui_cache = {}

def load_oui():
    """Load the OUI database into memory."""
    global _oui_cache
    if _oui_cache:
        return _oui_cache
    
    if not OUI_PATH.exists():
        return {}
    
    with open(OUI_PATH, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if "(hex)" in line:
                # Format: 00-00-00   (hex)		XEROX CORPORATION
                parts = line.split("(hex)")
                if len(parts) == 2:
                    oui = parts[0].strip().replace("-", ":").upper()
                    vendor = parts[1].strip()
                    _oui_cache[oui] = vendor
    return _oui_cache

def lookup_vendor(mac):
    """Lookup vendor name for a given MAC address."""
    if not mac:
        return "Unknown"
    
    oui_db = load_oui()
    # Normalize MAC and get OUI (first 3 bytes / 8 characters)
    mac = mac.upper().replace("-", ":")
    oui = mac[:8]
    
    return oui_db.get(oui, "Unknown")
