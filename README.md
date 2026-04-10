# netbox-snmp-sync

Query Cisco IOS, IOS-XE, IOS XR, NX-OS (Nexus), ASA, and Palo Alto PAN-OS devices via SNMP and keep NetBox aligned with the results.

## What it does

- **Discovers devices** — start with a seed list of IPs; CDP/LLDP neighbours are automatically probed up to a configurable depth
- **Collects per-device data** — hostname, platform, model, serial, OS version, interfaces, IP addresses
- **Detects drift** — compares collected data against NetBox and reports what is missing or out of date
- **Syncs to NetBox** — creates or updates devices, interfaces, IP addresses, cables, and MAC address tables
- **Creates cables** — uses CDP and LLDP neighbour data to create cable links between interfaces in NetBox
- **Stores MAC tables** — writes the bridge forwarding table for each interface as a JSON custom field (`mac_table`) on `dcim.interface`
- **Multi-credential fallback** — tries a list of SNMP credentials in order; caches the working one per device
- **Dry-run safe** — `--dry-run` shows exactly what would change without writing anything

---

## Supported platforms

| Platform | Detected from sysDescr | CDP | LLDP | MAC table |
|---|---|---|---|---|
| Cisco IOS / IOS-XE | `Cisco IOS Software` | yes | yes | per-VLAN via `community@vlan` |
| Cisco IOS XR | `Cisco IOS XR Software` | yes | yes | Q-BRIDGE walk |
| Cisco NX-OS (Nexus) | `Cisco NX-OS` | yes | yes | Q-BRIDGE walk |
| Cisco ASA | `Adaptive Security Appliance` | yes | yes | Q-BRIDGE walk |
| Palo Alto PAN-OS | `Palo Alto Networks` | no | yes | Q-BRIDGE walk |

---

## Requirements

- Python 3.10+
- A running NetBox instance (v3.3+) with an API token
- SNMP enabled on target devices

```
pip install -r requirements.txt
```

Dependencies: `pysnmp`, `pynetbox`, `click`, `rich`

---

## Configuration

All settings live in `config.py`. Copy and edit before first use.

### NetBox connection

```python
NETBOX_URL   = "https://netbox.example.com"
NETBOX_TOKEN = "YOUR_NETBOX_API_TOKEN"
```

Set `self.nb.http_session.verify = False` in `netbox_client.py` if your NetBox uses a self-signed certificate.

### NetBox defaults for new devices

NetBox requires a **site** and **device role** when creating a device. Set these to slugs that already exist in your NetBox, or the tool will attempt to create them.

```python
DEFAULT_SITE_SLUG        = "default"   # e.g. "london-dc1"
DEFAULT_DEVICE_ROLE_SLUG = "network"   # e.g. "router", "switch", "firewall"
```

### SNMP credential profiles

Credentials are tried in order for every device until one succeeds. The working credential is cached per device so subsequent OID walks do not retry failed profiles.

```python
SNMP_CREDENTIALS = [
    {
        "name":      "v2-prod",
        "version":   2,
        "community": "my-community",
    },
    {
        "name":          "v3-default",
        "version":       3,
        "username":      "snmpuser",
        "auth_protocol": "SHA",    # MD5 | SHA | SHA224 | SHA256 | SHA384 | SHA512
        "auth_key":      "secret",
        "priv_protocol": "AES",    # DES | AES | AES192 | AES256
        "priv_key":      "secret",
    },
]
```

#### Per-device credential overrides

Replace the global list for specific devices:

```python
DEVICE_CREDENTIALS = {
    "192.168.1.1": [{"name": "legacy", "version": 2, "community": "old-string"}],
}
```

### SNMP transport

```python
SNMP_PORT    = 161
SNMP_TIMEOUT = 5    # seconds per attempt
SNMP_RETRIES = 2    # retries after timeout
```

### Auto-discovery

```python
AUTO_DISCOVER_NEIGHBORS = True   # probe CDP/LLDP neighbours automatically
DISCOVERY_MAX_DEPTH     = 2      # max hops from seed (0 = seed list only)
```

---

## Usage

### `drift` — read-only comparison

Shows what is out of date or missing in NetBox. Writes nothing.

```
python main.py drift [OPTIONS] [IP...]
```

| Option | Description |
|---|---|
| `IP...` | One or more seed device IP addresses |
| `-f`, `--file FILE` | File containing one IP per line (lines starting with `#` are ignored) |
| `--depth N` | Max CDP/LLDP discovery hops from seed (default: value from `config.py`) |
| `--no-discover` | Disable automatic neighbour discovery; only query seed IPs |
| `-v`, `--verbose` | Enable debug logging (including pysnmp internals) |

**Examples**

```bash
# Check two devices
python main.py drift 192.168.1.1 10.0.0.254

# Check all devices in a file, discover neighbours up to 3 hops away
python main.py drift --file devices.txt --depth 3

# Check seed devices only, no discovery
python main.py drift --no-discover --file devices.txt
```

---

### `sync` — write changes to NetBox

Collects data, computes drift, and applies changes to NetBox. Runs in three ordered passes:

1. **Devices → interfaces → IP addresses**
2. **Cables** (requires both endpoints to exist — done after pass 1)
3. **MAC address tables** (written to `mac_table` JSON custom field on each interface)

```
python main.py sync [OPTIONS] [IP...]
```

| Option | Description |
|---|---|
| `IP...` | One or more seed device IP addresses |
| `-f`, `--file FILE` | File containing one IP per line |
| `--depth N` | Max CDP/LLDP discovery hops from seed |
| `--no-discover` | Disable automatic neighbour discovery |
| `--dry-run` | Compute all changes but write nothing to NetBox |
| `--no-create` | Only update existing objects; do not create new ones |
| `-v`, `--verbose` | Enable debug logging |

**Examples**

```bash
# Full sync, discover up to 2 hops (default)
python main.py sync 192.168.1.1

# See what would change without touching NetBox
python main.py sync --dry-run --file devices.txt

# Update existing records only — no new devices/interfaces/cables created
python main.py sync --no-create 192.168.1.1

# Full sync with debug output
python main.py sync -v --depth 3 --file devices.txt
```

---

## Device file format

Plain text, one IP per line. Comments and blank lines are ignored.

```
# Core switches
10.0.0.1
10.0.0.2

# Distribution
10.1.0.1
# 10.1.0.2  (decommissioned)
```

---

## What gets created in NetBox

### On first sync of a new device

| NetBox object | Source |
|---|---|
| Manufacturer | Derived from platform (Cisco / Palo Alto Networks) — created if absent |
| Device type | ENTITY-MIB model string — created if absent |
| Platform | Detected from sysDescr (`cisco-ios`, `cisco-nxos`, `cisco-asa`, `palo-alto-panos`, …) |
| Device role | `DEFAULT_DEVICE_ROLE_SLUG` from config — created if absent |
| Site | `DEFAULT_SITE_SLUG` from config — created if absent |
| Device | sysName as name, serial from ENTITY-MIB |
| Interfaces | IF-MIB + ifXTable (name, description, MAC, speed, admin/oper status) |
| IP addresses | IP-MIB ipAddrTable, assigned to their interface |

### Cables (second pass)

A cable is created between two interfaces when:
- Both devices and both interfaces already exist in NetBox
- A CDP or LLDP neighbour entry links them
- No cable already connects those two interfaces

Duplicate prevention: because device A reports B as a neighbour and B reports A, each pair is deduplicated using a `frozenset` of interface IDs.

### MAC address table (third pass)

A `mac_table` JSON custom field is auto-created on `dcim.interface` if it does not exist. Each interface's field is written as:

```json
[
  {"mac": "aa:bb:cc:dd:ee:ff", "vlan": 10,  "type": "learned"},
  {"mac": "11:22:33:44:55:66", "vlan": 100, "type": "learned"}
]
```

- Self, management, and invalid entries are filtered out — only `learned` and `other` entries are stored.
- On Cisco IOS/IOS-XE the bridge MIB is partitioned per VLAN; the tool reads the active VLAN list via VTP MIB and queries each VLAN instance using `community@vlan` community-string indexing (v2c only).
- On NX-OS and other platforms, the Q-BRIDGE MIB is walked once and covers all VLANs.

---

## Output

Both commands print colour-coded tables to the terminal using [Rich](https://rich.readthedocs.io/).

**Discovery summary** — every polled device with platform, model, serial, OS version, interface count, and neighbour count. Unreachable discovered neighbours are listed separately in red.

**Drift report** — every object that differs from NetBox, showing the current NetBox value and the SNMP value it would be changed to.

---

## Project structure

```
netbox-snmp-sync/
├── config.py           Credentials, NetBox URL, discovery settings
├── models.py           Dataclasses: DeviceInfo, Interface, Neighbor, MacTableEntry, …
├── snmp_collector.py   SNMP v2c/v3 walks: interfaces, IPs, CDP, LLDP, MAC table
├── discovery.py        BFS neighbour-driven device discovery engine
├── netbox_client.py    pynetbox wrapper: CRUD for devices, interfaces, IPs, cables, custom fields
├── sync.py             Drift detection + apply logic + cable/MAC sync passes
├── main.py             CLI (click): drift and sync commands
└── requirements.txt
```

---

## Notes

- NetBox 3.3+ is required for the cable termination format (`a_terminations` / `b_terminations` lists).
- The tool never deletes objects from NetBox.
- SNMP v3 does not support `community@vlan` indexing; per-VLAN MAC table walks use v2c credentials only. If only v3 credentials are configured, the Q-BRIDGE MIB walk is attempted instead.
