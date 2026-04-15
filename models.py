"""Dataclasses representing data collected from devices via SNMP."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Platform(str, Enum):
    """Detected OS/platform of a queried device."""
    IOS     = "ios"       # Cisco IOS / IOS-XE
    IOSXR   = "ios-xr"   # Cisco IOS XR
    NXOS    = "nxos"      # Cisco NX-OS (Nexus)
    ASA     = "asa"       # Cisco ASA
    PANOS   = "panos"     # Palo Alto PAN-OS
    OPENWRT = "openwrt"   # OpenWrt (Linux-based router/AP OS)
    LINUX   = "linux"     # Generic Linux (net-snmp)
    MERAKI  = "meraki"    # Cisco Meraki (Dashboard API)
    DELL_OS10  = "dell-os10"   # Dell EMC SmartFabric OS10 (Data Center)
    DELL_OS9   = "dell-os9"    # Dell EMC FTOS / OS9 (Force10, S/Z-series)
    DELL_PC    = "dell-pc"     # Dell PowerConnect / N-series (campus)
    UNKNOWN = "unknown"


class AdminStatus(str, Enum):
    UP = "up"
    DOWN = "down"
    TESTING = "testing"


class OperStatus(str, Enum):
    UP = "up"
    DOWN = "down"
    TESTING = "testing"
    UNKNOWN = "unknown"
    DORMANT = "dormant"
    NOT_PRESENT = "not-present"
    LOWER_LAYER_DOWN = "lower-layer-down"


@dataclass
class IPAddress:
    address: str        # e.g. "192.168.1.1"
    prefix_length: int  # e.g. 24
    if_index: int

    @property
    def cidr(self) -> str:
        return f"{self.address}/{self.prefix_length}"


@dataclass
class Interface:
    index: int
    name: str
    description: str = ""
    mac_address: str = ""           # colon-separated lowercase
    admin_status: AdminStatus = AdminStatus.DOWN
    oper_status: OperStatus = OperStatus.UNKNOWN
    speed_bps: int = 0              # bits per second; 0 = unknown
    ip_addresses: list[IPAddress] = field(default_factory=list)

    @property
    def speed_mbps(self) -> Optional[int]:
        return self.speed_bps // 1_000_000 if self.speed_bps else None


@dataclass
class Neighbor:
    """A single CDP or CDP/LLDP adjacency entry."""
    protocol: str           # "lldp" or "cdp"
    local_if_index: int
    local_if_name: str
    remote_device_id: str   # sysName or CDP device-id
    remote_port_id: str     # port description / id
    remote_platform: str = ""
    remote_ip: str = ""


class MacEntryType(str, Enum):
    LEARNED  = "learned"   # dot1dTpFdbStatus 3
    SELF     = "self"      # 4 — the device's own MAC
    MGMT     = "mgmt"      # 5 — management
    OTHER    = "other"     # 1
    INVALID  = "invalid"   # 2


@dataclass
class MacTableEntry:
    """A single row from the bridge forwarding table (dot1dTpFdbTable)."""
    mac_address: str       # colon-separated lowercase
    if_index: int
    if_name: str = ""      # resolved from interface list after collection
    vlan: int = 0          # 0 = unknown / not a VLAN-aware entry
    entry_type: MacEntryType = MacEntryType.LEARNED


@dataclass
class StackMember:
    """One physical member of a Cisco StackWise / Catalyst stacked chassis."""
    member_number: int      # 1-based stack position
    model: str
    serial_number: str
    os_version: str = ""


@dataclass
class DeviceInfo:
    """Top-level information about a queried device."""
    query_ip: str
    hostname: str = ""
    description: str = ""       # sysDescr
    model: str = ""             # from ENTITY-MIB
    serial_number: str = ""     # from ENTITY-MIB
    os_version: str = ""        # parsed from sysDescr
    platform: Platform = Platform.UNKNOWN
    interfaces: list[Interface] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    mac_table: list[MacTableEntry] = field(default_factory=list)
    site_id: Optional[int] = None  # override IPAM site resolution when set
    stack_members: list[StackMember] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        return self.hostname or self.query_ip


# ---------------------------------------------------------------------------
# Drift reporting
# ---------------------------------------------------------------------------

class ChangeKind(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"   # unused for now — we never delete from NetBox


@dataclass
class FieldDiff:
    field: str
    netbox_value: object
    snmp_value: object


@dataclass
class DriftItem:
    """A single discrepancy between SNMP truth and NetBox state."""
    kind: ChangeKind
    object_type: str    # "device", "interface", "ip_address", "cable"
    identifier: str     # human-readable key (hostname, interface name, …)
    diffs: list[FieldDiff] = field(default_factory=list)
    # Payload ready to send to NetBox (populated by sync engine)
    payload: dict = field(default_factory=dict)


@dataclass
class DriftReport:
    device_ip: str
    hostname: str
    items: list[DriftItem] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return bool(self.items)

    def summary(self) -> str:
        creates = sum(1 for i in self.items if i.kind == ChangeKind.CREATE)
        updates = sum(1 for i in self.items if i.kind == ChangeKind.UPDATE)
        return (
            f"{self.hostname or self.device_ip}: "
            f"{creates} to create, {updates} to update"
        )
