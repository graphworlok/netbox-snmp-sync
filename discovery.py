"""
Neighbour-driven discovery engine.

Starting from a seed list of IPs, queries each device and then recursively
probes CDP/LLDP neighbours that have not yet been visited, up to
DISCOVERY_MAX_DEPTH hops away.

Returns a list of DeviceInfo objects (successfully collected) and a list of
unreachable neighbour IPs/hostnames (discovered but not reachable by SNMP).
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass, field
from typing import Optional

import config
from models import DeviceInfo, Neighbor
from snmp_collector import SNMPCollector, make_collector

log = logging.getLogger(__name__)


@dataclass
class DiscoveryResult:
    collected: list[DeviceInfo] = field(default_factory=list)
    # Neighbours that were discovered but could not be queried
    unreachable: list[str] = field(default_factory=list)


def _credentials_for(ip: str) -> list[dict]:
    return config.DEVICE_CREDENTIALS.get(ip, config.SNMP_CREDENTIALS)


def _resolve(name: str) -> Optional[str]:
    """Try to resolve a hostname to an IP; return None on failure."""
    try:
        return socket.gethostbyname(name)
    except socket.gaierror:
        return None


def _neighbour_ips(device: DeviceInfo) -> list[str]:
    """
    Return candidate IPs/hostnames for all discovered neighbours.
    Prefers the reported management IP; falls back to resolving the device-id.
    """
    candidates: list[str] = []
    for nbr in device.neighbors:
        if nbr.remote_ip:
            candidates.append(nbr.remote_ip)
        elif nbr.remote_device_id:
            resolved = _resolve(nbr.remote_device_id)
            if resolved:
                candidates.append(resolved)
    return candidates


def run(
    seed_ips: list[str],
    max_depth: Optional[int] = None,
) -> DiscoveryResult:
    """
    Parameters
    ----------
    seed_ips    Initial list of device IPs to query.
    max_depth   Override config.DISCOVERY_MAX_DEPTH (None = use config).
    """
    if max_depth is None:
        max_depth = config.DISCOVERY_MAX_DEPTH

    result = DiscoveryResult()
    visited: set[str] = set()   # IPs we have already attempted
    queue: list[tuple[str, int]] = [(ip, 0) for ip in seed_ips]

    while queue:
        ip, depth = queue.pop(0)
        if ip in visited:
            continue
        visited.add(ip)

        creds = _credentials_for(ip)
        collector = make_collector(
            ip, creds,
            port=config.SNMP_PORT,
            timeout=config.SNMP_TIMEOUT,
            retries=config.SNMP_RETRIES,
        )

        log.info("[depth=%d] Querying %s …", depth, ip)
        device = collector.collect()

        if device is None:
            log.warning("  Unreachable: %s", ip)
            result.unreachable.append(ip)
            continue

        cred_name = collector.working_credential_name() or "unknown"
        log.info("  OK  %-40s  platform=%-8s  cred=%s",
                 device.display_name, device.platform.value, cred_name)
        result.collected.append(device)

        # Auto-discover neighbours
        if config.AUTO_DISCOVER_NEIGHBORS and depth < max_depth:
            for nbr_ip in _neighbour_ips(device):
                if nbr_ip not in visited:
                    log.debug("  Enqueuing neighbour %s (depth %d)",
                              nbr_ip, depth + 1)
                    queue.append((nbr_ip, depth + 1))

    return result
