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
from concurrent.futures import ThreadPoolExecutor, as_completed
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


def _collect_one(ip: str, depth: int) -> tuple[str, int, object, Optional[str]]:
    """
    Collect a single device.  Returns (ip, depth, DeviceInfo|None, cred_name|None).
    Designed to be called from a thread pool.
    """
    creds = _credentials_for(ip)
    collector = make_collector(
        ip, creds,
        port=config.SNMP_PORT,
        timeout=config.SNMP_TIMEOUT,
        retries=config.SNMP_RETRIES,
    )
    device = collector.collect()
    cred_name = collector.working_credential_name()
    return ip, depth, device, cred_name


def run(
    seed_ips: list[str],
    max_depth: Optional[int] = None,
) -> DiscoveryResult:
    """
    Parameters
    ----------
    seed_ips    Initial list of device IPs to query.
    max_depth   Override config.DISCOVERY_MAX_DEPTH (None = use config).

    Devices at each BFS depth level are polled concurrently using up to
    config.SNMP_WORKERS threads.  Neighbour IPs discovered at depth N are
    collected as a batch at depth N+1, keeping discovery deterministic.
    """
    if max_depth is None:
        max_depth = config.DISCOVERY_MAX_DEPTH

    result = DiscoveryResult()
    visited: set[str] = set()

    # Seed the first batch
    current_batch: list[tuple[str, int]] = []
    for ip in seed_ips:
        if ip not in visited:
            visited.add(ip)
            current_batch.append((ip, 0))

    workers = max(1, config.SNMP_WORKERS)

    while current_batch:
        depth = current_batch[0][1]
        log.info("[depth=%d] Polling %d device(s) concurrently (workers=%d)…",
                 depth, len(current_batch), workers)

        next_batch: list[tuple[str, int]] = []

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(_collect_one, ip, d): ip
                for ip, d in current_batch
            }
            for future in as_completed(futures):
                try:
                    ip, d, device, cred_name = future.result()
                except Exception as exc:
                    ip = futures[future]
                    log.error("  Error collecting %s: %s", ip, exc)
                    result.unreachable.append(ip)
                    continue

                if device is None:
                    log.warning("  Unreachable: %s", ip)
                    result.unreachable.append(ip)
                    continue

                log.info("  OK  %-40s  platform=%-8s  cred=%s",
                         device.display_name, device.platform.value,
                         cred_name or "unknown")
                result.collected.append(device)

                if config.AUTO_DISCOVER_NEIGHBORS and d < max_depth:
                    for nbr_ip in _neighbour_ips(device):
                        if nbr_ip not in visited:
                            log.debug("  Enqueuing neighbour %s (depth %d)",
                                      nbr_ip, d + 1)
                            visited.add(nbr_ip)
                            next_batch.append((nbr_ip, d + 1))

        current_batch = next_batch

    return result
