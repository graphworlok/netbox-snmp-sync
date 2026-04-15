# ---------------------------------------------------------------------------
# NetBox SNMP Sync — configuration
# Replace placeholder values before use.
# ---------------------------------------------------------------------------

# --- NetBox ---
NETBOX_URL = "https://netbox.example.com"
NETBOX_TOKEN = "YOUR_NETBOX_API_TOKEN"

# --- SNMP credential profiles ---
# Tried in order for every device until one succeeds.
# Each entry is a dict with keys:
#   name        – human label (shown in output)
#   version     – 2 or 3
#   community   – (v2 only) community string
#   username    – (v3 only)
#   auth_protocol, auth_key, priv_protocol, priv_key  – (v3 only)
#
# auth_protocol choices : MD5 | SHA | SHA224 | SHA256 | SHA384 | SHA512
# priv_protocol choices : DES | AES | AES192 | AES256
SNMP_CREDENTIALS: list[dict] = [
    {
        "name": "v2-public",
        "version": 2,
        "community": "public",
    },
    {
        "name": "v2-private",
        "version": 2,
        "community": "private",
    },
    {
        "name": "v3-default",
        "version": 3,
        "username": "snmpuser",
        "auth_protocol": "SHA",
        "auth_key": "YOUR_AUTH_KEY",
        "priv_protocol": "AES",
        "priv_key": "YOUR_PRIV_KEY",
    },
]

# --- Per-device credential overrides ---
# Key: device IP.  Value: list of credential dicts (same format as above).
# These replace (not supplement) the global list for that device.
# Example:
#   "192.168.1.1": [{"name": "mgmt-v2", "version": 2, "community": "secret"}],
DEVICE_CREDENTIALS: dict[str, list[dict]] = {}

# --- SNMP transport settings ---
SNMP_PORT = 161
SNMP_TIMEOUT = 5     # seconds per attempt
SNMP_RETRIES = 2     # retries after timeout

# --- High-latency / distant host settings (activated with --slow) ---
# Use these when polling devices over slow WAN links or high-RTT paths.
SNMP_TIMEOUT_SLOW = 30   # seconds per attempt
SNMP_RETRIES_SLOW = 3    # retries after timeout

# --- CrowdStrike local asset cache ---
# Path to the JSON file that stores the full raw asset records from all CS APIs.
# The MAC index is rebuilt from this cache rather than re-fetching from the API
# on every run.  Set to "" or None to disable caching.
CS_CACHE_FILE = "cs_asset_cache.json"
# Maximum age in seconds before the cache is considered stale (default 24 h).
CS_CACHE_MAX_AGE = 86400

# --- Concurrency ---
# Number of devices to poll via SNMP simultaneously during discovery.
SNMP_WORKERS = 10
# Number of parallel NetBox API workers used during drift detection.
# Each worker uses its own HTTP session; set lower if NetBox rate-limits.
NETBOX_WORKERS = 5

# --- Auto-discovery ---
# When True, CDP/LLDP neighbors not in the seed list are probed automatically.
AUTO_DISCOVER_NEIGHBORS = True
# Maximum recursion depth for neighbour-driven discovery (0 = seed only).
DISCOVERY_MAX_DEPTH = 2

# --- Sync behaviour ---
# When True the sync engine creates missing NetBox objects.
DEFAULT_CREATE_MISSING = True

# Manufacturer slug used when creating new Cisco devices in NetBox.
CISCO_MANUFACTURER_SLUG = "cisco"

# --- NetBox defaults for new devices ---
# NetBox requires a site and device role when creating a device.
# Set these to the slug of an existing site/role, or leave as None to be
# prompted at runtime (the sync engine will raise clearly if unset).
DEFAULT_SITE_SLUG = "default"          # e.g. "london-dc1"
DEFAULT_DEVICE_ROLE_SLUG = "network"   # e.g. "router", "switch", "firewall"

# Device role slugs used when importing endpoints from CrowdStrike.
# The roles are created automatically if they do not already exist.
CS_WORKSTATION_ROLE_SLUG = "workstation"
CS_SERVER_ROLE_SLUG      = "server"

# ---------------------------------------------------------------------------
# Cisco Meraki (optional)
# ---------------------------------------------------------------------------
# Dashboard API key — generate in Meraki Dashboard under
# Organisation → Settings → Dashboard API access.
# Used by meraki_sync.py.  Leave blank if not using Meraki.
MERAKI_API_KEY = ""

# ---------------------------------------------------------------------------
# IEEE OUI vendor lookup (optional)
# ---------------------------------------------------------------------------
# Path to a local copy of the IEEE OUI assignment CSV.  Download from:
#   https://standards-oui.ieee.org/oui/oui.csv   (MA-L, ~37 k entries)
#   https://standards-oui.ieee.org/oui28/mam.csv  (MA-M)
#   https://standards-oui.ieee.org/oui36/oui36.csv (MA-S)
#
# A single path string or a list of paths (all files are merged).
# Leave blank to disable vendor resolution; the 'vendor' field will be empty.
OUI_FILE = ""   # e.g. "/opt/oui/oui.csv" or ["oui.csv", "mam.csv", "oui36.csv"]
