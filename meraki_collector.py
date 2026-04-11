"""
Cisco Meraki Dashboard API collector.

Queries a Meraki network and returns a list of DeviceInfo objects using the
same model as the SNMP collector, so the existing sync/drift/cable machinery
in sync.py works without modification.

Supported device families
-------------------------
MS  — switches  (ports, CDP/LLDP neighbours, client MAC table)
MX  — security appliances  (uplink + LAN ports, no MAC table)
MR  — wireless access points  (radios modelled as interfaces, no MAC table)
Other models — basic device record only

Rate limiting
-------------
The Meraki Dashboard API allows 10 requests/second per organisation.
A 0.12 s inter-request delay keeps us comfortably within that limit.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import requests

from models import (
    AdminStatus,
    DeviceInfo,
    Interface,
    IPAddress,
    MacEntryType,
    MacTableEntry,
    Neighbor,
    OperStatus,
    Platform,
)

log = logging.getLogger(__name__)

_BASE_URL  = "https://api.meraki.com/api/v1"
_API_DELAY = 0.12   # seconds between requests


# ---------------------------------------------------------------------------
# Meraki REST client
# ---------------------------------------------------------------------------

class MerakiClient:
    def __init__(self, api_key: str) -> None:
        self._session = requests.Session()
        self._session.headers.update({
            "X-Cisco-Meraki-API-Key": api_key,
            "Content-Type": "application/json",
        })

    def _get(self, path: str, **params) -> object:
        resp = self._session.get(f"{_BASE_URL}{path}", params=params, timeout=30)
        resp.raise_for_status()
        time.sleep(_API_DELAY)
        return resp.json()

    def _get_paginated(self, path: str, **params) -> list:
        """Follow Link: <url>; rel=next pagination automatically."""
        params.setdefault("perPage", 1000)
        results = []
        url: Optional[str] = f"{_BASE_URL}{path}"
        while url:
            resp = self._session.get(url, params=params, timeout=30)
            resp.raise_for_status()
            time.sleep(_API_DELAY)
            results.extend(resp.json())
            params = {}   # params are already encoded in the next URL
            link = resp.headers.get("Link", "")
            url = _parse_next_link(link)
        return results

    # Network-level endpoints
    def get_network_devices(self, network_id: str) -> list[dict]:
        return self._get(f"/networks/{network_id}/devices")

    def get_network_clients(self, network_id: str, timespan: int = 86400) -> list[dict]:
        return self._get_paginated(
            f"/networks/{network_id}/clients",
            timespan=timespan,
        )

    def get_network_topology(self, network_id: str) -> dict:
        try:
            return self._get(f"/networks/{network_id}/topology/linkLayer")
        except requests.HTTPError as exc:
            if exc.response.status_code == 404:
                return {}
            raise

    # Device-level endpoints
    def get_switch_ports(self, serial: str) -> list[dict]:
        try:
            return self._get(f"/devices/{serial}/switch/ports")
        except requests.HTTPError as exc:
            if exc.response.status_code in (404, 400):
                return []
            raise

    def get_switch_port_statuses(self, serial: str) -> list[dict]:
        try:
            return self._get(f"/devices/{serial}/switch/ports/statuses")
        except requests.HTTPError as exc:
            if exc.response.status_code in (404, 400):
                return []
            raise

    def get_appliance_ports(self, serial: str) -> list[dict]:
        try:
            return self._get(f"/devices/{serial}/appliance/ports")
        except requests.HTTPError as exc:
            if exc.response.status_code in (404, 400):
                return []
            raise


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def collect_network(
    client: MerakiClient,
    network_id: str,
    site_id: Optional[int] = None,
    client_timespan: int = 86400,
) -> list[DeviceInfo]:
    """
    Collect all devices in a Meraki network and return them as DeviceInfo objects.

    Parameters
    ----------
    client          : authenticated MerakiClient
    network_id      : Meraki network ID (e.g. "N_xxxxxxxxxxxx")
    site_id         : NetBox site ID to stamp on every DeviceInfo so
                      _resolve_site() skips IPAM lookup
    client_timespan : how far back (seconds) to look for clients when building
                      MAC tables (default 24 h)
    """
    log.info("Meraki: collecting network %s", network_id)

    devices  = client.get_network_devices(network_id)
    clients  = client.get_network_clients(network_id, timespan=client_timespan)
    topology = client.get_network_topology(network_id)

    # Index clients by (serial, switchport) for MAC table building
    clients_by_port: dict[tuple[str, str], list[dict]] = {}
    for c in clients:
        serial    = c.get("recentDeviceSerial", "")
        switchport = str(c.get("switchport") or "")
        if serial and switchport:
            clients_by_port.setdefault((serial, switchport), []).append(c)

    # Index topology neighbours by serial + local port
    nbr_index = _build_neighbour_index(topology)

    result: list[DeviceInfo] = []
    for dev in devices:
        try:
            info = _collect_device(
                dev, client, clients_by_port, nbr_index, site_id
            )
            result.append(info)
        except Exception as exc:
            log.warning("Failed to collect Meraki device %s: %s",
                        dev.get("serial", "?"), exc)

    log.info("Meraki: collected %d device(s) from network %s",
             len(result), network_id)
    return result


# ---------------------------------------------------------------------------
# Per-device collection
# ---------------------------------------------------------------------------

def _collect_device(
    dev: dict,
    client: MerakiClient,
    clients_by_port: dict[tuple[str, str], list[dict]],
    nbr_index: dict[tuple[str, str], list[dict]],
    site_id: Optional[int],
) -> DeviceInfo:
    serial  = dev.get("serial", "")
    model   = dev.get("model", "")
    name    = dev.get("name") or dev.get("serial", "")
    lan_ip  = dev.get("lanIp") or dev.get("wan1Ip") or ""
    fw      = dev.get("firmware", "")

    info = DeviceInfo(
        query_ip      = lan_ip or "0.0.0.0",
        hostname      = name,
        model         = model,
        serial_number = serial,
        os_version    = fw,
        platform      = Platform.MERAKI,
        site_id       = site_id,
    )

    family = _model_family(model)

    if family == "MS":
        _collect_switch(info, serial, client, clients_by_port, nbr_index)
    elif family == "MX":
        _collect_appliance(info, serial, client, lan_ip)
    elif family == "MR":
        _collect_ap(info, dev)

    # Management IP as an interface IP regardless of device type
    if lan_ip and info.interfaces:
        iface = info.interfaces[0]
        iface.ip_addresses.append(IPAddress(
            address=lan_ip, prefix_length=24, if_index=iface.index
        ))

    return info


def _collect_switch(
    info: DeviceInfo,
    serial: str,
    client: MerakiClient,
    clients_by_port: dict[tuple[str, str], list[dict]],
    nbr_index: dict[tuple[str, str], list[dict]],
) -> None:
    ports    = client.get_switch_ports(serial)
    statuses = {s["portId"]: s for s in client.get_switch_port_statuses(serial)}

    for idx, port in enumerate(ports):
        port_id  = str(port.get("portId", idx))
        status   = statuses.get(port_id, {})
        enabled  = port.get("enabled", True)
        connected = status.get("status", "") == "Connected"

        iface = Interface(
            index       = _port_index(port_id, idx),
            name        = port_id,
            description = port.get("name") or port.get("portId", ""),
            admin_status = AdminStatus.UP if enabled else AdminStatus.DOWN,
            oper_status  = OperStatus.UP if connected else OperStatus.DOWN,
            speed_bps    = _parse_speed(status.get("speed", "")),
        )
        info.interfaces.append(iface)

        # Neighbours from CDP / LLDP in port status
        for proto, key in (("cdp", "cdpInfo"), ("lldp", "lldpInfo")):
            nbr_data = status.get(key)
            if nbr_data:
                remote_id = (
                    nbr_data.get("systemName")
                    or nbr_data.get("sourcePort")
                    or ""
                )
                remote_port = (
                    nbr_data.get("portId")
                    or nbr_data.get("sourcePort")
                    or ""
                )
                remote_ip = nbr_data.get("address") or nbr_data.get("managementAddress") or ""
                if remote_id:
                    info.neighbors.append(Neighbor(
                        protocol       = proto,
                        local_if_index = iface.index,
                        local_if_name  = port_id,
                        remote_device_id = remote_id,
                        remote_port_id   = remote_port,
                        remote_ip        = remote_ip,
                    ))

        # MAC table from connected clients
        for entry in clients_by_port.get((serial, port_id), []):
            mac = _colon_mac(entry.get("mac", ""))
            if not mac:
                continue
            info.mac_table.append(MacTableEntry(
                mac_address = mac,
                if_index    = iface.index,
                if_name     = port_id,
                vlan        = entry.get("vlan") or 0,
                entry_type  = MacEntryType.LEARNED,
            ))

        # Topology-based neighbours (supplement port status CDP/LLDP)
        for nbr in nbr_index.get((serial, port_id), []):
            if not any(
                n.local_if_name == port_id and n.remote_device_id == nbr["remote_id"]
                for n in info.neighbors
            ):
                info.neighbors.append(Neighbor(
                    protocol         = "lldp",
                    local_if_index   = iface.index,
                    local_if_name    = port_id,
                    remote_device_id = nbr["remote_id"],
                    remote_port_id   = nbr["remote_port"],
                ))


def _collect_appliance(
    info: DeviceInfo,
    serial: str,
    client: MerakiClient,
    lan_ip: str,
) -> None:
    ports = client.get_appliance_ports(serial)
    for idx, port in enumerate(ports):
        port_id = str(port.get("number", idx))
        iface = Interface(
            index        = idx,
            name         = f"Port {port_id}",
            description  = port.get("type", ""),
            admin_status = AdminStatus.UP if port.get("enabled", True) else AdminStatus.DOWN,
            oper_status  = OperStatus.UNKNOWN,
        )
        if port.get("type") == "wan" and lan_ip:
            iface.ip_addresses.append(
                IPAddress(address=lan_ip, prefix_length=24, if_index=idx)
            )
        info.interfaces.append(iface)

    if not info.interfaces:
        info.interfaces.append(Interface(
            index=0, name="Management",
            admin_status=AdminStatus.UP, oper_status=OperStatus.UNKNOWN,
        ))


def _collect_ap(info: DeviceInfo, dev: dict) -> None:
    info.interfaces.append(Interface(
        index        = 0,
        name         = "Radio",
        description  = dev.get("model", ""),
        admin_status = AdminStatus.UP,
        oper_status  = OperStatus.UNKNOWN,
    ))


# ---------------------------------------------------------------------------
# Topology index
# ---------------------------------------------------------------------------

def _build_neighbour_index(topology: dict) -> dict[tuple[str, str], list[dict]]:
    """
    Parse the /topology/linkLayer response into a dict keyed by
    (local_serial, local_port) → [{remote_id, remote_port}, ...].
    """
    index: dict[tuple[str, str], list[dict]] = {}
    for link in (topology.get("links") or []):
        ends = link.get("ends") or []
        if len(ends) != 2:
            continue
        a, b = ends
        for local, remote in ((a, b), (b, a)):
            serial = (local.get("device") or {}).get("serial", "")
            port   = str((local.get("discovered") or {}).get("portId") or
                         (local.get("connected") or {}).get("portId") or "")
            r_serial = (remote.get("device") or {}).get("serial", "")
            r_port   = str((remote.get("discovered") or {}).get("portId") or
                           (remote.get("connected") or {}).get("portId") or "")
            if serial and port and r_serial:
                index.setdefault((serial, port), []).append({
                    "remote_id":   r_serial,
                    "remote_port": r_port,
                })
    return index


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _model_family(model: str) -> str:
    """Return the two-letter Meraki model family (MS, MX, MR, …)."""
    return model[:2].upper() if model else ""


def _port_index(port_id: str, fallback: int) -> int:
    try:
        return int(port_id)
    except (ValueError, TypeError):
        return fallback


def _parse_speed(speed_str: str) -> int:
    """Convert Meraki speed string to bits per second. Returns 0 if unknown."""
    if not speed_str:
        return 0
    s = speed_str.strip().lower()
    try:
        if "gbps" in s:
            return int(float(s.replace("gbps", "").strip()) * 1_000_000_000)
        if "mbps" in s:
            return int(float(s.replace("mbps", "").strip()) * 1_000_000)
    except ValueError:
        pass
    return 0


def _colon_mac(mac: str) -> str:
    digits = mac.lower().replace(":", "").replace("-", "").replace(".", "")
    if len(digits) != 12:
        return ""
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def _parse_next_link(link_header: str) -> Optional[str]:
    """Extract the URL from a 'Link: <url>; rel=next' header, or None."""
    for part in link_header.split(","):
        part = part.strip()
        if 'rel="next"' in part or "rel=next" in part:
            try:
                return part.split(";")[0].strip().strip("<>")
            except IndexError:
                pass
    return None
