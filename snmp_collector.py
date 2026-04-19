"""
SNMP collection for network devices.

Supports:
  - SNMPv2c and SNMPv3 with automatic credential fallback
  - System info  (sysDescr, sysName, ENTITY-MIB model/serial)
  - Interfaces   (IF-MIB + ifXTable)
  - IPv4 addresses (IP-MIB)
  - LLDP neighbours (LLDP-MIB)
  - CDP neighbours  (CISCO-CDP-MIB) — Cisco/UNKNOWN platforms only
  - MAC address table (BRIDGE-MIB / Q-BRIDGE-MIB)

Supported platforms: Cisco IOS, IOS-XE, IOS XR, NX-OS, ASA,
                     Palo Alto PAN-OS, OpenWrt, generic Linux (net-snmp)
"""

from __future__ import annotations

import logging
import re
import socket
import time
from typing import Optional

from pysnmp.hlapi import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulkCmd,
    getCmd,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)

from models import (
    AdminStatus,
    BgpPeer,
    BgpPeerState,
    DeviceInfo,
    Interface,
    IPAddress,
    MacEntryType,
    MacTableEntry,
    Neighbor,
    OperStatus,
    Platform,
    RouteEntry,
    RouteProtocol,
    StackMember,
    _SNMP_BGP_STATE_MAP,
    _SNMP_PROTO_MAP,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OID constants
# ---------------------------------------------------------------------------

# System
OID_SYS_DESCR   = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME    = "1.3.6.1.2.1.1.5.0"

# ENTITY-MIB (physical table — index 1 is the chassis on most Cisco gear)
OID_ENT_PHYS_DESCR      = "1.3.6.1.2.1.47.1.1.1.1.2"
OID_ENT_PHYS_CLASS      = "1.3.6.1.2.1.47.1.1.1.1.5"   # 3=chassis
OID_ENT_PHYS_SERIAL     = "1.3.6.1.2.1.47.1.1.1.1.11"
OID_ENT_PHYS_MODEL      = "1.3.6.1.2.1.47.1.1.1.1.13"
OID_ENT_PHYS_SW_REV     = "1.3.6.1.2.1.47.1.1.1.1.10"

# IF-MIB
OID_IF_DESCR        = "1.3.6.1.2.1.2.2.1.2"
OID_IF_TYPE         = "1.3.6.1.2.1.2.2.1.3"
OID_IF_SPEED        = "1.3.6.1.2.1.2.2.1.5"
OID_IF_PHYS_ADDR    = "1.3.6.1.2.1.2.2.1.6"
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
OID_IF_OPER_STATUS  = "1.3.6.1.2.1.2.2.1.8"
# ifXTable
OID_IF_NAME         = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_ALIAS        = "1.3.6.1.2.1.31.1.1.1.18"
OID_IF_HIGH_SPEED   = "1.3.6.1.2.1.31.1.1.1.15"  # Mbps

# IP-MIB
OID_IP_AD_ENT_ADDR    = "1.3.6.1.2.1.4.20.1.1"
OID_IP_AD_ENT_IF_IDX  = "1.3.6.1.2.1.4.20.1.2"
OID_IP_AD_ENT_MASK    = "1.3.6.1.2.1.4.20.1.3"

# LLDP-MIB  (IEEE 802.1AB)
OID_LLDP_REM_SYS_NAME  = "1.0.8802.1.1.2.1.4.1.1.9"
OID_LLDP_REM_PORT_ID   = "1.0.8802.1.1.2.1.4.1.1.7"
OID_LLDP_REM_PORT_DESC = "1.0.8802.1.1.2.1.4.1.1.8"
OID_LLDP_REM_MAN_ADDR  = "1.0.8802.1.1.2.1.4.2.1.4"  # mgmt address TLV
OID_LLDP_LOC_PORT_ID   = "1.0.8802.1.1.2.1.3.7.1.3"

# BRIDGE-MIB (dot1dTpFdbTable) — MAC address table
# Index: <mac-address-as-6-octet-oid>
OID_FDB_ADDRESS = "1.3.6.1.2.1.17.4.3.1.1"   # MAC address
OID_FDB_PORT    = "1.3.6.1.2.1.17.4.3.1.2"   # bridge port number
OID_FDB_STATUS  = "1.3.6.1.2.1.17.4.3.1.3"   # 1=other 2=invalid 3=learned 4=self 5=mgmt
# BRIDGE-MIB dot1dBasePortTable — maps bridge port → ifIndex
OID_BP_IF_INDEX = "1.3.6.1.2.1.17.1.4.1.2"
# Q-BRIDGE-MIB dot1qTpFdbTable — per-VLAN MAC table (NX-OS / newer IOS)
# Index: <vlan>.<mac-as-6-octet-oid>
OID_QFDB_PORT   = "1.3.6.1.2.1.17.7.1.2.2.1.2"
OID_QFDB_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"

# CISCO-CDP-MIB
OID_CDP_CACHE_DEVICE_ID   = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
OID_CDP_CACHE_DEVICE_PORT = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
OID_CDP_CACHE_PLATFORM    = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"
OID_CDP_CACHE_ADDRESS     = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"

# IP-FORWARD-MIB — ipCidrRouteTable (RFC 2096, preferred)
# Index: <dest>.<mask>.<tos>.<nexthop>
OID_CIDR_ROUTE_DEST     = "1.3.6.1.2.1.4.24.4.1.1"  # destination network
OID_CIDR_ROUTE_MASK     = "1.3.6.1.2.1.4.24.4.1.2"  # subnet mask
OID_CIDR_ROUTE_NEXTHOP  = "1.3.6.1.2.1.4.24.4.1.4"  # next-hop IP
OID_CIDR_ROUTE_IFINDEX  = "1.3.6.1.2.1.4.24.4.1.5"  # ifIndex
OID_CIDR_ROUTE_TYPE     = "1.3.6.1.2.1.4.24.4.1.6"  # 1=other 3=local 4=remote
OID_CIDR_ROUTE_PROTO    = "1.3.6.1.2.1.4.24.4.1.9"  # protocol (bgp=13, ospf=9, …)
OID_CIDR_ROUTE_METRIC   = "1.3.6.1.2.1.4.24.4.1.12" # primary metric

# IP-MIB — ipRouteTable (RFC 1213, legacy fallback)
# Index: <dest>
OID_IP_ROUTE_DEST       = "1.3.6.1.2.1.4.21.1.1"
OID_IP_ROUTE_IFINDEX    = "1.3.6.1.2.1.4.21.1.2"
OID_IP_ROUTE_METRIC     = "1.3.6.1.2.1.4.21.1.3"
OID_IP_ROUTE_NEXTHOP    = "1.3.6.1.2.1.4.21.1.7"
OID_IP_ROUTE_TYPE       = "1.3.6.1.2.1.4.21.1.8"
OID_IP_ROUTE_PROTO      = "1.3.6.1.2.1.4.21.1.9"
OID_IP_ROUTE_MASK       = "1.3.6.1.2.1.4.21.1.11"

# BGP4-MIB (RFC 1657)
OID_BGP_LOCAL_AS        = "1.3.6.1.2.1.15.2.0"        # bgpLocalAs
OID_BGP_PEER_STATE      = "1.3.6.1.2.1.15.3.1.2"      # bgpPeerState
OID_BGP_PEER_LOCAL_ADDR = "1.3.6.1.2.1.15.3.1.5"      # bgpPeerLocalAddr
OID_BGP_PEER_REMOTE_AS  = "1.3.6.1.2.1.15.3.1.9"      # bgpPeerRemoteAs

# DELL-VENDOR-MIB (1.3.6.1.4.1.674) — fallback when ENTITY-MIB is sparse
# PowerConnect / N-series
OID_DELL_PC_MODEL      = "1.3.6.1.4.1.674.10895.3000.1.2.100.1.0"   # pcMfgName (product name)
OID_DELL_PC_SERIAL     = "1.3.6.1.4.1.674.10895.3000.1.2.100.3.0"   # pcSerialNum
OID_DELL_PC_VERSION    = "1.3.6.1.4.1.674.10895.3000.1.2.100.4.0"   # pcSwVersion
# Dell Networking OS9 (Force10 / S-series / Z-series)
OID_DELL_OS9_PRODUCT   = "1.3.6.1.4.1.6027.3.26.1.3.4.1.7.1"        # productName in F10-CHASSIS-MIB
OID_DELL_OS9_SERIAL    = "1.3.6.1.4.1.6027.3.26.1.3.4.1.11.1"       # serialNumber
# Dell OS10 / SmartFabric — uses standard ENTITY-MIB; these are fallbacks
OID_DELL_OS10_MODEL    = "1.3.6.1.4.1.674.11000.5000.100.4.1.1.3.1.8"   # os10SystemCardModelName
OID_DELL_OS10_SERIAL   = "1.3.6.1.4.1.674.11000.5000.100.4.1.1.3.1.4"   # os10SystemCardSerialNumber

# ---------------------------------------------------------------------------
# Protocol maps
# ---------------------------------------------------------------------------

_AUTH_PROTOCOLS = {
    "MD5":    usmHMACMD5AuthProtocol,
    "SHA":    usmHMACSHAAuthProtocol,
    "SHA224": usmHMAC128SHA224AuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol,
    "SHA384": usmHMAC256SHA384AuthProtocol,
    "SHA512": usmHMAC384SHA512AuthProtocol,
}

_PRIV_PROTOCOLS = {
    "DES":    usmDESPrivProtocol,
    "AES":    usmAesCfb128Protocol,
    "AES192": usmAesCfb192Protocol,
    "AES256": usmAesCfb256Protocol,
}

_FDB_STATUS = {
    1: MacEntryType.OTHER,
    2: MacEntryType.INVALID,
    3: MacEntryType.LEARNED,
    4: MacEntryType.SELF,
    5: MacEntryType.MGMT,
}

_ADMIN_STATUS = {1: AdminStatus.UP, 2: AdminStatus.DOWN, 3: AdminStatus.TESTING}
_OPER_STATUS  = {
    1: OperStatus.UP, 2: OperStatus.DOWN, 3: OperStatus.TESTING,
    4: OperStatus.UNKNOWN, 5: OperStatus.DORMANT,
    6: OperStatus.NOT_PRESENT, 7: OperStatus.LOWER_LAYER_DOWN,
}


# ---------------------------------------------------------------------------
# Credential helpers
# ---------------------------------------------------------------------------

def _make_auth(cred: dict):
    """Return a pysnmp CommunityData or UsmUserData object."""
    if cred["version"] == 2:
        return CommunityData(cred["community"], mpModel=1)
    # v3
    auth_proto = _AUTH_PROTOCOLS.get(cred.get("auth_protocol", "SHA").upper(),
                                     usmHMACSHAAuthProtocol)
    priv_proto = _PRIV_PROTOCOLS.get(cred.get("priv_protocol", "AES").upper(),
                                     usmAesCfb128Protocol)
    auth_key = cred.get("auth_key", "")
    priv_key = cred.get("priv_key", "")

    if not auth_key:
        return UsmUserData(cred["username"],
                           authProtocol=usmNoAuthProtocol,
                           privProtocol=usmNoPrivProtocol)
    if not priv_key:
        return UsmUserData(cred["username"], authKey=auth_key,
                           authProtocol=auth_proto,
                           privProtocol=usmNoPrivProtocol)
    return UsmUserData(cred["username"],
                       authKey=auth_key, privKey=priv_key,
                       authProtocol=auth_proto, privProtocol=priv_proto)


def _transport(host: str, port: int, timeout: int, retries: int):
    return UdpTransportTarget((host, port), timeout=timeout, retries=retries)


# ---------------------------------------------------------------------------
# SNMPCollector
# ---------------------------------------------------------------------------

class SNMPCollector:
    """
    Collects device data via SNMP.

    Parameters
    ----------
    host        Target IP or hostname.
    credentials List of credential dicts to try in order.
    port        UDP port (default 161).
    timeout     Seconds per attempt.
    retries     Retries after timeout.
    """

    def __init__(
        self,
        host: str,
        credentials: list[dict],
        port: int = 161,
        timeout: int = 5,
        retries: int = 2,
    ):
        self.host = host
        self.credentials = credentials
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self._engine = SnmpEngine()
        self._working_cred: Optional[dict] = None   # set after first success

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, oid: str) -> Optional[object]:
        """GET a single scalar OID, trying credentials in order."""
        for cred in self._cred_list():
            cred_name = cred.get("name", "?")
            auth = _make_auth(cred)
            transport = _transport(self.host, self.port,
                                   self.timeout, self.retries)
            log.debug("SNMP GET  %s  oid=%s  cred=%s  timeout=%ds  retries=%d",
                      self.host, oid, cred_name, self.timeout, self.retries)
            t0 = time.monotonic()
            error_indication, error_status, _, var_binds = next(
                getCmd(self._engine, auth, transport, ContextData(),
                       ObjectType(ObjectIdentity(oid)))
            )
            elapsed = time.monotonic() - t0
            if error_indication:
                log.debug("SNMP GET  %s  oid=%s  cred=%s  FAILED (%.2fs): %s",
                          self.host, oid, cred_name, elapsed, error_indication)
                continue
            if error_status:
                log.debug("SNMP GET  %s  oid=%s  cred=%s  ERROR (%.2fs): %s",
                          self.host, oid, cred_name, elapsed, error_status.prettyPrint())
                continue
            self._working_cred = cred
            val = var_binds[0][1]
            result = val.prettyPrint() if hasattr(val, "prettyPrint") else str(val)
            log.debug("SNMP GET  %s  oid=%s  cred=%s  OK (%.2fs): %r",
                      self.host, oid, cred_name, elapsed, result[:80] if result else result)
            return result
        log.debug("SNMP GET  %s  oid=%s  all credentials exhausted — unreachable", self.host, oid)
        return None

    def _walk(self, oid: str) -> dict[str, str]:
        """
        BULK walk a table OID.  Returns {last_oid_component: value_str}.
        Tries credentials in order; stops at first working credential.
        """
        results: dict[str, str] = {}
        for cred in self._cred_list():
            cred_name = cred.get("name", "?")
            auth = _make_auth(cred)
            transport = _transport(self.host, self.port,
                                   self.timeout, self.retries)
            log.debug("SNMP WALK %s  oid=%s  cred=%s  timeout=%ds  retries=%d",
                      self.host, oid, cred_name, self.timeout, self.retries)
            t0 = time.monotonic()
            success = False
            last_error: str = ""
            for (err_ind, err_status, _, var_binds) in bulkCmd(
                self._engine, auth, transport, ContextData(),
                0, 25,
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
            ):
                if err_ind:
                    last_error = str(err_ind)
                    break
                if err_status:
                    last_error = err_status.prettyPrint()
                    break
                success = True
                for obj_name, val in var_binds:
                    oid_str = str(obj_name)
                    suffix = oid_str[len(oid):].lstrip(".")
                    results[suffix] = (
                        val.prettyPrint()
                        if hasattr(val, "prettyPrint")
                        else str(val)
                    )
            elapsed = time.monotonic() - t0
            if success:
                self._working_cred = cred
                log.debug("SNMP WALK %s  oid=%s  cred=%s  OK (%.2fs): %d row(s)",
                          self.host, oid, cred_name, elapsed, len(results))
                return results
            else:
                log.debug("SNMP WALK %s  oid=%s  cred=%s  FAILED (%.2fs): %s",
                          self.host, oid, cred_name, elapsed, last_error or "no data")
        return results

    def _cred_list(self) -> list[dict]:
        """Put the last working credential first to avoid unnecessary retries."""
        if self._working_cred:
            others = [c for c in self.credentials if c is not self._working_cred]
            return [self._working_cred] + others
        return self.credentials

    # ------------------------------------------------------------------
    # Public probe
    # ------------------------------------------------------------------

    def probe(self) -> bool:
        """Return True if the device responds to at least one credential."""
        val = self._get(OID_SYS_NAME)
        return val is not None

    def working_credential_name(self) -> Optional[str]:
        if self._working_cred:
            return self._working_cred.get("name", "unknown")
        return None

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------

    def collect(self) -> Optional[DeviceInfo]:
        """
        Full collection pass.  Returns None if the device is unreachable.
        """
        sys_name = self._get(OID_SYS_NAME)
        if sys_name is None:
            log.warning("SNMP unreachable: %s", self.host)
            return None

        info = DeviceInfo(query_ip=self.host)
        info.hostname = sys_name.strip()
        info.description = (self._get(OID_SYS_DESCR) or "").strip()
        info.platform = _detect_platform(info.description)
        info.os_version = _parse_os_version(info.description, info.platform)

        self._collect_entity(info)

        interfaces = self._collect_interfaces()
        self._attach_ips(interfaces)
        info.interfaces = list(interfaces.values())

        info.neighbors = self._collect_lldp(interfaces)
        # CDP is Cisco-proprietary; only attempt on Cisco platforms and UNKNOWN
        # (Dell, OpenWrt, and Linux devices never implement CDP)
        if info.platform in (Platform.IOS, Platform.IOSXR,
                             Platform.NXOS, Platform.ASA,
                             Platform.UNKNOWN):
            info.neighbors += self._collect_cdp(interfaces)

        info.mac_table = self._collect_mac_table(interfaces)

        return info

    # ------------------------------------------------------------------
    # Entity MIB (model / serial)
    # ------------------------------------------------------------------

    def _collect_entity(self, info: DeviceInfo) -> None:
        classes  = self._walk(OID_ENT_PHYS_CLASS)
        serials  = self._walk(OID_ENT_PHYS_SERIAL)
        models   = self._walk(OID_ENT_PHYS_MODEL)
        sw_revs  = self._walk(OID_ENT_PHYS_SW_REV)
        descs    = self._walk(OID_ENT_PHYS_DESCR)

        # Find all chassis entries (entPhysicalClass == 3); fall back to index "1"
        chassis_indices = [idx for idx, cls in classes.items() if cls == "3"]
        if not chassis_indices:
            chassis_indices = ["1"]

        # Sort numerically for consistent member ordering (lower OID index = lower member)
        chassis_indices.sort(key=lambda x: int(x) if x.isdigit() else 0)

        if len(chassis_indices) == 1:
            # Single device — original behaviour
            idx = chassis_indices[0]
            info.model = models.get(idx, "").strip()
            info.serial_number = serials.get(idx, "").strip()
            if not info.os_version:
                info.os_version = sw_revs.get(idx, "").strip()

            # Dell vendor-specific fallback when ENTITY-MIB is sparse/empty
            if info.platform in (Platform.DELL_OS10, Platform.DELL_OS9, Platform.DELL_PC):
                self._collect_entity_dell(info)
            return

        # Multiple chassis entries — stack detected; populate stack_members
        for position, idx in enumerate(chassis_indices, start=1):
            model  = models.get(idx, "").strip()
            serial = serials.get(idx, "").strip()
            desc   = descs.get(idx, "").strip()
            os_ver = sw_revs.get(idx, "").strip()

            # Derive member number from entPhysicalDescr ("Switch 2") when present
            m = re.search(r'[Ss]witch\s+(\d+)', desc)
            member_num = int(m.group(1)) if m else position

            info.stack_members.append(StackMember(
                member_number=member_num,
                model=model,
                serial_number=serial,
                os_version=os_ver,
            ))

        # Populate top-level DeviceInfo fields from the primary member (1)
        # so the discovery summary table still shows meaningful data
        primary = next(
            (sm for sm in info.stack_members if sm.member_number == 1),
            info.stack_members[0],
        )
        info.model = primary.model
        info.serial_number = primary.serial_number
        if not info.os_version:
            info.os_version = primary.os_version

    def _collect_entity_dell(self, info: DeviceInfo) -> None:
        """
        Fill in model/serial/os_version from Dell vendor MIBs when ENTITY-MIB
        is absent or returns empty strings.  Tries each Dell product line in
        order and stops at the first successful retrieval.

        OID families used:
          PowerConnect / N-series : 1.3.6.1.4.1.674.10895.3000.*
          OS9 / FTOS (Force10)    : 1.3.6.1.4.1.6027.3.26.*
          OS10 / SmartFabric      : 1.3.6.1.4.1.674.11000.5000.*
        """
        def _fill(model_oid, serial_oid, version_oid=None) -> bool:
            model  = (self._get(model_oid)  or "").strip()
            serial = (self._get(serial_oid) or "").strip()
            if not model and not serial:
                return False
            if model  and not info.model:
                info.model = model
                log.debug("Dell entity: model from vendor MIB: %s", model)
            if serial and not info.serial_number:
                info.serial_number = serial
                log.debug("Dell entity: serial from vendor MIB: %s", serial)
            if version_oid and not info.os_version:
                ver = (self._get(version_oid) or "").strip()
                if ver:
                    info.os_version = ver
                    log.debug("Dell entity: os_version from vendor MIB: %s", ver)
            return True

        if info.platform == Platform.DELL_PC:
            if _fill(OID_DELL_PC_MODEL, OID_DELL_PC_SERIAL, OID_DELL_PC_VERSION):
                return

        if info.platform == Platform.DELL_OS9:
            if _fill(OID_DELL_OS9_PRODUCT, OID_DELL_OS9_SERIAL):
                return

        if info.platform == Platform.DELL_OS10:
            if _fill(OID_DELL_OS10_MODEL, OID_DELL_OS10_SERIAL):
                return

        # Last resort: walk the full ENTITY-MIB physical table and take the
        # first non-empty model/serial regardless of class
        if not info.model or not info.serial_number:
            serials = self._walk(OID_ENT_PHYS_SERIAL)
            models  = self._walk(OID_ENT_PHYS_MODEL)
            for idx in sorted(serials.keys() | models.keys(),
                              key=lambda x: int(x) if x.isdigit() else 9999):
                m = models.get(idx, "").strip()
                s = serials.get(idx, "").strip()
                if m or s:
                    if m and not info.model:
                        info.model = m
                    if s and not info.serial_number:
                        info.serial_number = s
                    log.debug("Dell entity: fallback ENTITY-MIB idx=%s model=%r serial=%r",
                              idx, info.model, info.serial_number)
                    break

    # ------------------------------------------------------------------
    # Interfaces
    # ------------------------------------------------------------------

    def _collect_interfaces(self) -> dict[int, Interface]:
        names        = self._walk(OID_IF_NAME)
        descs        = self._walk(OID_IF_DESCR)
        aliases      = self._walk(OID_IF_ALIAS)
        phys_addrs   = self._walk(OID_IF_PHYS_ADDR)
        admin_stats  = self._walk(OID_IF_ADMIN_STATUS)
        oper_stats   = self._walk(OID_IF_OPER_STATUS)
        high_speeds  = self._walk(OID_IF_HIGH_SPEED)
        speeds       = self._walk(OID_IF_SPEED)

        ifaces: dict[int, Interface] = {}
        all_indices = set(names) | set(descs)

        for idx_str in all_indices:
            try:
                idx = int(idx_str)
            except ValueError:
                continue

            name = names.get(idx_str) or descs.get(idx_str, f"if{idx_str}")
            alias = aliases.get(idx_str, "")
            mac_raw = phys_addrs.get(idx_str, "")
            mac = _format_mac(mac_raw)

            admin_raw = _safe_int(admin_stats.get(idx_str), default=2)
            oper_raw  = _safe_int(oper_stats.get(idx_str),  default=4)

            # Prefer high-speed (Mbps → bps); fall back to ifSpeed (bps)
            hs = high_speeds.get(idx_str)
            hs_int = _safe_int(hs)
            speed = hs_int * 1_000_000 if hs_int else _safe_int(speeds.get(idx_str), default=0)

            ifaces[idx] = Interface(
                index=idx,
                name=name.strip(),
                description=alias.strip(),
                mac_address=mac,
                admin_status=_ADMIN_STATUS.get(admin_raw, AdminStatus.DOWN),
                oper_status=_OPER_STATUS.get(oper_raw, OperStatus.UNKNOWN),
                speed_bps=speed,
            )

        return ifaces

    # ------------------------------------------------------------------
    # IP addresses
    # ------------------------------------------------------------------

    def _attach_ips(self, interfaces: dict[int, Interface]) -> None:
        addrs   = self._walk(OID_IP_AD_ENT_ADDR)
        if_idxs = self._walk(OID_IP_AD_ENT_IF_IDX)
        masks   = self._walk(OID_IP_AD_ENT_MASK)

        for ip_suffix, ip_addr in addrs.items():
            if_idx_str = if_idxs.get(ip_suffix)
            mask_str   = masks.get(ip_suffix, "255.255.255.255")
            if not if_idx_str:
                continue
            try:
                if_idx = int(if_idx_str)
                prefix_len = _mask_to_prefix(mask_str)
            except (ValueError, TypeError):
                continue

            ip_obj = IPAddress(
                address=ip_addr,
                prefix_length=prefix_len,
                if_index=if_idx,
            )
            if if_idx in interfaces:
                interfaces[if_idx].ip_addresses.append(ip_obj)

    # ------------------------------------------------------------------
    # MAC address table  (bridge forwarding table)
    # ------------------------------------------------------------------

    def _collect_mac_table(self, interfaces: dict[int, Interface]) -> list[MacTableEntry]:
        """
        Walk the BRIDGE-MIB dot1dTpFdbTable to get the MAC address table.

        On Cisco IOS/IOS-XE, MACs are partitioned per VLAN and only accessible
        by appending '@<vlan>' to the community string.  We query the active
        VLAN list from CISCO-VTP-MIB and issue one walk per VLAN.

        On NX-OS and most other platforms, the Q-BRIDGE-MIB dot1qTpFdbTable
        encodes the VLAN in the OID index directly, so a single walk covers all
        VLANs.

        Results from both sources are merged and deduplicated by (mac, ifIndex).
        """
        if_names = {idx: iface.name for idx, iface in interfaces.items()}

        # bridge port → ifIndex map (shared across all VLAN instances)
        bp_to_if = self._build_bp_if_map()

        entries: dict[tuple, MacTableEntry] = {}   # (mac, if_idx) → entry

        # --- Q-BRIDGE-MIB (single walk, VLAN in index) ---
        self._walk_qbridge(bp_to_if, if_names, entries)

        # --- Per-VLAN BRIDGE-MIB walks (Cisco IOS community@vlan) ---
        self._walk_per_vlan(bp_to_if, if_names, entries)

        # Filter out self/mgmt/invalid entries — keep learned + other
        return [
            e for e in entries.values()
            if e.entry_type not in (MacEntryType.SELF,
                                    MacEntryType.MGMT,
                                    MacEntryType.INVALID)
        ]

    def _build_bp_if_map(self) -> dict[int, int]:
        """Return {bridge_port_num: ifIndex}."""
        raw = self._walk(OID_BP_IF_INDEX)
        result: dict[int, int] = {}
        for key, val in raw.items():
            try:
                result[int(key)] = int(val)
            except ValueError:
                pass
        return result

    def _walk_qbridge(
        self,
        bp_to_if: dict[int, int],
        if_names: dict[int, str],
        out: dict[tuple, MacTableEntry],
    ) -> None:
        """Walk Q-BRIDGE-MIB dot1qTpFdbTable; index is <vlan>.<mac-6-octets>."""
        ports   = self._walk(OID_QFDB_PORT)
        statuses = self._walk(OID_QFDB_STATUS)

        for key, port_str in ports.items():
            parts = key.split(".")
            if len(parts) < 7:
                continue
            try:
                vlan    = int(parts[0])
                mac     = _mac_from_oid_parts(parts[1:7])
                bp_num  = int(port_str)
                if_idx  = bp_to_if.get(bp_num, 0)
                status  = _FDB_STATUS.get(int(statuses.get(key, 3)),
                                          MacEntryType.LEARNED)
            except (ValueError, IndexError):
                continue
            if not mac:
                continue
            out[(mac, if_idx)] = MacTableEntry(
                mac_address=mac,
                if_index=if_idx,
                if_name=if_names.get(if_idx, ""),
                vlan=vlan,
                entry_type=status,
            )

    def _walk_per_vlan(
        self,
        bp_to_if: dict[int, int],
        if_names: dict[int, str],
        out: dict[tuple, MacTableEntry],
    ) -> None:
        """
        Walk BRIDGE-MIB once per active VLAN using Cisco community@vlan indexing.
        Skips if no active VLAN list is available (non-Cisco / no VTP).
        """
        vlans = self._get_cisco_vlans()
        if not vlans:
            # Fall back to a plain (non-VLAN-indexed) walk of the base instance
            self._walk_fdb_instance(
                community_suffix="",
                vlan=0,
                bp_to_if=bp_to_if,
                if_names=if_names,
                out=out,
            )
            return

        for vlan in vlans:
            self._walk_fdb_instance(
                community_suffix=f"@{vlan}",
                vlan=vlan,
                bp_to_if=bp_to_if,
                if_names=if_names,
                out=out,
            )

    def _get_cisco_vlans(self) -> list[int]:
        """
        Return the list of active VLAN IDs from CISCO-VTP-MIB vtpVlanState.
        Returns [] if the OID is not supported (non-Cisco, or VTP not running).
        vtpVlanState 1.3.6.1.4.1.9.9.46.1.3.1.1.2.<vlan-mgmt-domain>.<vlan-id>
        State value 1 = operational
        """
        OID_VTP_VLAN_STATE = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"
        raw = self._walk(OID_VTP_VLAN_STATE)
        vlans: list[int] = []
        for key, state in raw.items():
            if state != "1":
                continue
            parts = key.split(".")
            # last component is the VLAN id
            try:
                vlans.append(int(parts[-1]))
            except (ValueError, IndexError):
                pass
        return sorted(vlans)

    def _walk_fdb_instance(
        self,
        community_suffix: str,
        vlan: int,
        bp_to_if: dict[int, int],
        if_names: dict[int, str],
        out: dict[tuple, MacTableEntry],
    ) -> None:
        """
        Walk dot1dTpFdbTable for one BRIDGE-MIB instance (possibly VLAN-specific).
        community_suffix is appended to the credential community string.
        """
        # Temporarily patch credentials so _walk uses the right community
        patched = self._patched_credentials(community_suffix)
        if patched is None:
            return   # no v2 cred available for this walk

        saved = self.credentials
        saved_working = self._working_cred
        self.credentials = patched
        self._working_cred = None

        ports   = self._walk(OID_FDB_PORT)
        statuses = self._walk(OID_FDB_STATUS)

        self.credentials = saved
        self._working_cred = saved_working

        for key, port_str in ports.items():
            parts = key.split(".")
            if len(parts) < 6:
                continue
            try:
                mac    = _mac_from_oid_parts(parts[:6])
                bp_num = int(port_str)
                if_idx = bp_to_if.get(bp_num, 0)
                status = _FDB_STATUS.get(int(statuses.get(key, 3)),
                                         MacEntryType.LEARNED)
            except (ValueError, IndexError):
                continue
            if not mac:
                continue
            out[(mac, if_idx)] = MacTableEntry(
                mac_address=mac,
                if_index=if_idx,
                if_name=if_names.get(if_idx, ""),
                vlan=vlan,
                entry_type=status,
            )

    def _patched_credentials(self, suffix: str) -> Optional[list[dict]]:
        """
        Return a copy of the credential list with community strings suffixed.
        Only v2c credentials support community@vlan indexing.
        Returns None if no v2c credential is available.
        """
        patched: list[dict] = []
        for cred in self.credentials:
            if cred.get("version") == 2:
                patched.append({**cred, "community": cred["community"] + suffix})
        return patched if patched else None

    # ------------------------------------------------------------------
    # Routing table + BGP
    # ------------------------------------------------------------------

    def collect_routing(self, info: DeviceInfo) -> None:
        """
        Populate *info* with routing table entries and BGP peer data.

        Attempts ipCidrRouteTable (IP-FORWARD-MIB, RFC 2096) first; falls back
        to the legacy ipRouteTable (IP-MIB, RFC 1213) if the modern table is
        empty.  BGP local AS and peer table are collected from BGP4-MIB
        regardless of which routing table source is used.
        """
        if_name_map = {iface.index: iface.name for iface in info.interfaces}

        routes = self._collect_cidr_routes(if_name_map)
        if not routes:
            log.debug("%s: ipCidrRouteTable empty, trying legacy ipRouteTable",
                      info.display_name)
            routes = self._collect_legacy_routes(if_name_map)

        info.routing_table = routes
        log.debug("%s: collected %d route(s)", info.display_name, len(routes))

        info.bgp_local_as, info.bgp_peers = self._collect_bgp()
        if info.bgp_local_as:
            log.debug("%s: BGP local AS %d, %d peer(s)",
                      info.display_name, info.bgp_local_as, len(info.bgp_peers))

    def _collect_cidr_routes(self, if_name_map: dict[int, str]) -> list[RouteEntry]:
        """Walk ipCidrRouteTable (IP-FORWARD-MIB)."""
        dests    = self._walk(OID_CIDR_ROUTE_DEST)
        if not dests:
            return []
        masks    = self._walk(OID_CIDR_ROUTE_MASK)
        nexthops = self._walk(OID_CIDR_ROUTE_NEXTHOP)
        if_idxs  = self._walk(OID_CIDR_ROUTE_IFINDEX)
        protos   = self._walk(OID_CIDR_ROUTE_PROTO)
        metrics  = self._walk(OID_CIDR_ROUTE_METRIC)

        routes: list[RouteEntry] = []
        for key, dest in dests.items():
            mask = masks.get(key, "0.0.0.0")
            try:
                prefix_len = _mask_to_prefix(mask)
            except Exception:
                continue
            nexthop  = nexthops.get(key, "0.0.0.0")
            if_idx   = _safe_int(if_idxs.get(key), default=0)
            proto_id = _safe_int(protos.get(key), default=0)
            metric   = _safe_int(metrics.get(key), default=0)
            protocol = _SNMP_PROTO_MAP.get(proto_id, RouteProtocol.UNKNOWN)
            routes.append(RouteEntry(
                destination=dest,
                prefix_length=prefix_len,
                next_hop=nexthop,
                protocol=protocol,
                if_index=if_idx,
                if_name=if_name_map.get(if_idx, ""),
                metric=metric,
            ))
        return routes

    def _collect_legacy_routes(self, if_name_map: dict[int, str]) -> list[RouteEntry]:
        """Walk legacy ipRouteTable (IP-MIB, RFC 1213)."""
        dests = self._walk(OID_IP_ROUTE_DEST)
        if not dests:
            return []
        masks    = self._walk(OID_IP_ROUTE_MASK)
        nexthops = self._walk(OID_IP_ROUTE_NEXTHOP)
        if_idxs  = self._walk(OID_IP_ROUTE_IFINDEX)
        protos   = self._walk(OID_IP_ROUTE_PROTO)
        metrics  = self._walk(OID_IP_ROUTE_METRIC)

        routes: list[RouteEntry] = []
        for key, dest in dests.items():
            mask = masks.get(key, "0.0.0.0")
            try:
                prefix_len = _mask_to_prefix(mask)
            except Exception:
                continue
            nexthop  = nexthops.get(key, "0.0.0.0")
            if_idx   = _safe_int(if_idxs.get(key), default=0)
            proto_id = _safe_int(protos.get(key), default=0)
            metric   = _safe_int(metrics.get(key), default=0)
            protocol = _SNMP_PROTO_MAP.get(proto_id, RouteProtocol.UNKNOWN)
            routes.append(RouteEntry(
                destination=dest,
                prefix_length=prefix_len,
                next_hop=nexthop,
                protocol=protocol,
                if_index=if_idx,
                if_name=if_name_map.get(if_idx, ""),
                metric=metric,
            ))
        return routes

    def _collect_bgp(self) -> tuple[Optional[int], list[BgpPeer]]:
        """Collect BGP local AS and peer table from BGP4-MIB."""
        local_as_str = self._get(OID_BGP_LOCAL_AS)
        if not local_as_str:
            return None, []

        try:
            local_as = int(local_as_str)
        except ValueError:
            return None, []

        if local_as == 0:
            return None, []

        states     = self._walk(OID_BGP_PEER_STATE)
        local_addr = self._walk(OID_BGP_PEER_LOCAL_ADDR)
        remote_as  = self._walk(OID_BGP_PEER_REMOTE_AS)

        peers: list[BgpPeer] = []
        for peer_ip, state_str in states.items():
            r_as = _safe_int(remote_as.get(peer_ip), default=0)
            state_int = _safe_int(state_str, default=0)
            peers.append(BgpPeer(
                peer_ip=peer_ip,
                remote_as=r_as,
                state=_SNMP_BGP_STATE_MAP.get(state_int, BgpPeerState.UNKNOWN),
                local_ip=local_addr.get(peer_ip, ""),
            ))
        return local_as, peers

    # ------------------------------------------------------------------
    # LLDP neighbours
    # ------------------------------------------------------------------

    def _collect_lldp(self, interfaces: dict[int, Interface]) -> list[Neighbor]:
        sys_names  = self._walk(OID_LLDP_REM_SYS_NAME)
        port_ids   = self._walk(OID_LLDP_REM_PORT_ID)
        port_descs = self._walk(OID_LLDP_REM_PORT_DESC)
        loc_ports  = self._walk(OID_LLDP_LOC_PORT_ID)

        neighbours: list[Neighbor] = []
        # LLDP remote table index: <timeMark>.<localPortNum>.<remoteIndex>
        for key, remote_name in sys_names.items():
            parts = key.split(".")
            if len(parts) < 3:
                continue
            local_port_num = int(parts[1])
            local_iface = _find_iface_by_lldp_port(local_port_num,
                                                    loc_ports, interfaces)
            neighbours.append(Neighbor(
                protocol="lldp",
                local_if_index=local_iface.index if local_iface else local_port_num,
                local_if_name=local_iface.name if local_iface else str(local_port_num),
                remote_device_id=remote_name.strip(),
                remote_port_id=(port_ids.get(key) or port_descs.get(key, "")).strip(),
            ))
        return neighbours

    # ------------------------------------------------------------------
    # CDP neighbours
    # ------------------------------------------------------------------

    def _collect_cdp(self, interfaces: dict[int, Interface]) -> list[Neighbor]:
        device_ids  = self._walk(OID_CDP_CACHE_DEVICE_ID)
        device_ports = self._walk(OID_CDP_CACHE_DEVICE_PORT)
        platforms   = self._walk(OID_CDP_CACHE_PLATFORM)
        addresses   = self._walk(OID_CDP_CACHE_ADDRESS)

        neighbours: list[Neighbor] = []
        # CDP table index: <ifIndex>.<neighborIndex>
        for key, dev_id in device_ids.items():
            parts = key.split(".")
            if not parts:
                continue
            try:
                if_idx = int(parts[0])
            except ValueError:
                continue
            iface = interfaces.get(if_idx)
            neighbours.append(Neighbor(
                protocol="cdp",
                local_if_index=if_idx,
                local_if_name=iface.name if iface else str(if_idx),
                remote_device_id=dev_id.strip(),
                remote_port_id=device_ports.get(key, "").strip(),
                remote_platform=platforms.get(key, "").strip(),
                remote_ip=_parse_cdp_address(addresses.get(key, "")),
            ))
        return neighbours


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _detect_platform(sys_descr: str) -> Platform:
    """
    Classify a device from its sysDescr string.

    Typical sysDescr examples
    -------------------------
    IOS/IOS-XE : "Cisco IOS Software [Fuji], Catalyst ... Version 16.9.4, ..."
    IOS XR     : "Cisco IOS XR Software, Version 6.5.3"
    NX-OS      : "Cisco NX-OS(tm) n9k, Software (n9k-dk9), Version 7.0(3)I7(9)"
    ASA        : "Cisco Adaptive Security Appliance Software Version 9.14(3)9"
    PAN-OS     : "Palo Alto Networks PA-3220 series firewall. SW Version: 10.1.3"
    Dell OS10  : "Dell EMC Networking OS10 Enterprise"
                 "OS10 Enterprise 10.5.2.4"
    Dell OS9   : "Dell Networking OS, Version 9.14.2.16"
                 "Force10 Networks Real Time Operating System Software"
    Dell PC    : "Dell PowerConnect 6224, 4.1.0.6, VxWorks 6.6"
                 "Dell Networking N3048, OS Version: 6.4.0.8"
    OpenWrt    : "Linux OpenWrt 5.15.137 #0 SMP ..."
                 "OpenWrt Chaos Calmer 15.05 / LuCI ..."
    Linux      : "Linux hostname 5.15.0-91-generic #101-Ubuntu SMP ..."
    """
    d = sys_descr.lower()
    if "palo alto" in d or "pan-os" in d:
        return Platform.PANOS
    if "adaptive security appliance" in d or "cisco asa" in d:
        return Platform.ASA
    if "nx-os" in d or "nxos" in d:
        return Platform.NXOS
    if "ios xr" in d:
        return Platform.IOSXR
    if "cisco ios" in d:
        return Platform.IOS
    # Dell OS10 (SmartFabric / Data Centre)
    if "os10" in d or "dell emc networking os10" in d or "dell networking os10" in d:
        return Platform.DELL_OS10
    # Dell OS9 / FTOS (Force10, S-series, Z-series)
    if "force10" in d or ("dell" in d and ("ftos" in d or "networking os" in d or "os version" in d)):
        return Platform.DELL_OS9
    # Dell PowerConnect / N-series (campus)
    if "powerconnect" in d or ("dell" in d and ("powerconnect" in d or "n-series" in d)):
        return Platform.DELL_PC
    # Broader Dell catch — if none of the above matched but sysDescr starts with "dell"
    if d.startswith("dell ") or "\ndell " in d:
        return Platform.DELL_PC
    # Check OpenWrt before generic Linux — OpenWrt sysDescr contains "linux"
    if "openwrt" in d:
        return Platform.OPENWRT
    if d.startswith("linux ") or "\nlinux " in d:
        return Platform.LINUX
    return Platform.UNKNOWN


def _parse_os_version(sys_descr: str, platform: Platform = Platform.UNKNOWN) -> str:
    """
    Extract the OS version string from sysDescr.

    Platform-specific patterns
    --------------------------
    IOS/IOS-XE/XR/ASA/NX-OS : "Version 15.2(4)M3" or "Version 9.14(3)9"
    PAN-OS                   : "SW Version: 10.1.3"  or "Version 10.1.3"
    OpenWrt                  : "Linux OpenWrt 5.15.137 ..." → "5.15.137"
                               "OpenWrt 23.05.2 / ..."     → "23.05.2"
    Linux                    : "Linux hostname 5.15.0-91-generic ..." → "5.15.0-91-generic"
    """
    if platform == Platform.PANOS:
        match = re.search(r"SW\s+[Vv]ersion[:\s]+([\d\.]+)", sys_descr)
        if match:
            return match.group(1)

    if platform == Platform.OPENWRT:
        # "OpenWrt 23.05.2 / LuCI ..." — standalone release string
        match = re.search(r"OpenWrt\s+([\d\.]+)", sys_descr, re.IGNORECASE)
        if match:
            return match.group(1)
        # "Linux OpenWrt 5.15.137 #0 ..." — kernel version in field 3
        match = re.search(r"Linux\s+\S+\s+([\d][\w\.\-]+)", sys_descr)
        if match:
            return match.group(1)

    if platform == Platform.LINUX:
        # "Linux <hostname> <kernel-version> ..."
        match = re.search(r"Linux\s+\S+\s+([\d][\w\.\-]+)", sys_descr)
        if match:
            return match.group(1)

    if platform == Platform.DELL_OS10:
        # "OS10 Enterprise 10.5.2.4" or "Dell EMC Networking OS10 Enterprise 10.5.2.4"
        match = re.search(r"OS10\s+\w+\s+([\d][\d\.]+)", sys_descr, re.IGNORECASE)
        if match:
            return match.group(1)

    if platform == Platform.DELL_OS9:
        # "Dell Networking OS, Version 9.14.2.16" or "FTOS Version 8.3.16.1"
        match = re.search(r"[Vv]ersion\s+([\d][\d\.]+)", sys_descr)
        if match:
            return match.group(1)

    if platform == Platform.DELL_PC:
        # "Dell PowerConnect 6224, 4.1.0.6, VxWorks 6.6" — version is 2nd CSV field
        # "Dell Networking N3048, OS Version: 6.4.0.8"
        match = re.search(r"OS\s+[Vv]ersion[:\s]+([\d][\d\.]+)", sys_descr)
        if match:
            return match.group(1)
        # Fallback: first dotted-number after comma
        match = re.search(r",\s*([\d]+\.[\d\.]+)", sys_descr)
        if match:
            return match.group(1)

    # Covers IOS, IOS-XR, NX-OS, ASA, and unknown gear
    match = re.search(r"[Vv]ersion\s+([\d\w\.\(\)]+)", sys_descr)
    return match.group(1) if match else ""


def _mac_from_oid_parts(parts: list[str]) -> str:
    """Convert 6 decimal OID octets to colon-separated MAC, e.g. ['0','12','34','0','1','2'] → '00:0c:22:00:01:02'."""
    try:
        octets = [int(p) for p in parts[:6]]
        if any(o < 0 or o > 255 for o in octets):
            return ""
        # Skip broadcast and multicast MACs
        if octets[0] & 0x01:
            return ""
        return ":".join(f"{o:02x}" for o in octets)
    except (ValueError, TypeError):
        return ""


def _format_mac(raw: str) -> str:
    """Convert pysnmp hex representation to XX:XX:XX:XX:XX:XX."""
    # pysnmp renders MAC as "0x001122334455" or "00:11:22:33:44:55"
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw.replace("0x", ""))
    if len(cleaned) == 12:
        return ":".join(cleaned[i:i+2] for i in range(0, 12, 2)).lower()
    return ""


def _safe_int(value: Optional[str], default: int = 0) -> int:
    """
    Convert an SNMP string value to int, returning *default* on failure.
    Guards against error message strings that pysnmp occasionally returns
    in place of numeric OID values (e.g. 'No more variables left in this
    MIB view').
    """
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _mask_to_prefix(mask: str) -> int:
    """Convert dotted-decimal mask to prefix length."""
    try:
        parts = [int(x) for x in mask.split(".")]
        bits = sum(bin(p).count("1") for p in parts)
        return bits
    except Exception:
        return 32


def _find_iface_by_lldp_port(
    local_port_num: int,
    loc_ports: dict[str, str],
    interfaces: dict[int, Interface],
) -> Optional[Interface]:
    """Map LLDP local port number to an Interface object."""
    port_id = loc_ports.get(str(local_port_num))
    if port_id:
        for iface in interfaces.values():
            if iface.name == port_id:
                return iface
    return interfaces.get(local_port_num)


def _parse_cdp_address(raw: str) -> str:
    """
    CDP address is encoded as a hex string by pysnmp.
    Attempt to decode IPv4 (last 4 bytes).
    """
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw.replace("0x", ""))
    if len(cleaned) >= 8:
        try:
            octets = [int(cleaned[i:i+2], 16) for i in range(-8, 0, 2)]
            return ".".join(str(o) for o in octets)
        except Exception:
            pass
    return ""


# ---------------------------------------------------------------------------
# Convenience factory used by the discovery engine
# ---------------------------------------------------------------------------

def make_collector(host: str, credentials: list[dict], **kwargs) -> SNMPCollector:
    return SNMPCollector(host, credentials, **kwargs)
