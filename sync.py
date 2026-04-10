"""
Drift detection and NetBox synchronisation.

Public API
----------
drift_device(info, nb)          -> DriftReport   (read-only NetBox queries)
apply_report(report, nb, ...)   -> int            (writes devices/interfaces/IPs)
sync_cables(devices, nb, ...)   -> int            (second pass: cables only)
"""

from __future__ import annotations

import logging
from typing import Optional

import config
from enrichment import MacEnricher
from models import (
    ChangeKind,
    DeviceInfo,
    DriftItem,
    DriftReport,
    FieldDiff,
    Interface,
    IPAddress,
    Platform,
)
from netbox_client import NetBoxClient

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Manufacturer meta
# ---------------------------------------------------------------------------

_MANUFACTURER = {"slug": "cisco",               "name": "Cisco"}
_PALO_MFR     = {"slug": "palo-alto-networks",  "name": "Palo Alto Networks"}
_GENERIC_MFR  = {"slug": "generic",             "name": "Generic"}

_PLATFORM_MFR: dict[Platform, dict] = {
    Platform.PANOS:   _PALO_MFR,
    Platform.OPENWRT: _GENERIC_MFR,
    Platform.LINUX:   _GENERIC_MFR,
}


def _manufacturer_for(platform: Platform) -> dict:
    return _PLATFORM_MFR.get(platform, _MANUFACTURER)


# ---------------------------------------------------------------------------
# Drift detection  (read-only — no NetBox writes)
# ---------------------------------------------------------------------------

def drift_device(info: DeviceInfo, nb: NetBoxClient) -> DriftReport:
    """
    Compare SNMP-collected DeviceInfo against the current NetBox state.
    Returns a DriftReport; does NOT write anything to NetBox.
    Cables are handled separately via sync_cables() after all devices exist.
    """
    report = DriftReport(device_ip=info.query_ip, hostname=info.display_name)

    nb_device = (
        nb.get_device_by_name(info.hostname)
        or nb.get_device_by_ip(info.query_ip)
    )

    if nb_device is None:
        report.items.append(DriftItem(
            kind=ChangeKind.CREATE,
            object_type="device",
            identifier=info.display_name,
            payload=_device_payload(info, nb),
        ))
        for iface in info.interfaces:
            report.items.append(DriftItem(
                kind=ChangeKind.CREATE,
                object_type="interface",
                identifier=f"{info.display_name} / {iface.name}",
                payload=_interface_payload(iface, device_id=None),
            ))
            for ip in iface.ip_addresses:
                report.items.append(DriftItem(
                    kind=ChangeKind.CREATE,
                    object_type="ip_address",
                    identifier=ip.cidr,
                    payload=_ip_payload(ip, iface_id=None),
                ))
        return report

    # Device exists — check individual fields
    device_diffs: list[FieldDiff] = []
    _check(device_diffs, "serial",  getattr(nb_device, "serial", ""),   info.serial_number)
    _check(device_diffs, "comments", getattr(nb_device, "comments", ""), info.os_version,
           label="os_version")
    if device_diffs:
        report.items.append(DriftItem(
            kind=ChangeKind.UPDATE,
            object_type="device",
            identifier=info.display_name,
            diffs=device_diffs,
            payload={d.field: d.snmp_value for d in device_diffs},
        ))

    nb_ifaces = {i.name: i for i in nb.get_interfaces(nb_device.id)}

    for iface in info.interfaces:
        nb_iface = nb_ifaces.get(iface.name)
        if nb_iface is None:
            report.items.append(DriftItem(
                kind=ChangeKind.CREATE,
                object_type="interface",
                identifier=f"{info.display_name} / {iface.name}",
                payload=_interface_payload(iface, device_id=nb_device.id),
            ))
        else:
            iface_diffs: list[FieldDiff] = []
            _check(iface_diffs, "description",
                   getattr(nb_iface, "description", ""), iface.description)
            _check(iface_diffs, "mac_address",
                   getattr(nb_iface, "mac_address", ""), iface.mac_address)
            if iface_diffs:
                report.items.append(DriftItem(
                    kind=ChangeKind.UPDATE,
                    object_type="interface",
                    identifier=f"{info.display_name} / {iface.name}",
                    diffs=iface_diffs,
                    payload={d.field: d.snmp_value for d in iface_diffs},
                ))

        for ip in iface.ip_addresses:
            if not nb.get_ip_address(ip.cidr):
                report.items.append(DriftItem(
                    kind=ChangeKind.CREATE,
                    object_type="ip_address",
                    identifier=ip.cidr,
                    payload=_ip_payload(
                        ip, iface_id=nb_iface.id if nb_iface else None
                    ),
                ))

    return report


# ---------------------------------------------------------------------------
# Apply device / interface / IP changes
# ---------------------------------------------------------------------------

def apply_report(
    report: DriftReport,
    nb: NetBoxClient,
    create_missing: bool = True,
) -> int:
    """
    Push device, interface, and IP address changes from a DriftReport to NetBox.
    Returns the number of objects written.

    Cable creation is intentionally excluded here — call sync_cables() once
    all devices in a run have been processed.
    """
    applied = 0
    device_id: Optional[int] = None

    order = {"device": 0, "interface": 1, "ip_address": 2}
    items = sorted(
        [i for i in report.items if i.object_type != "cable"],
        key=lambda i: order.get(i.object_type, 9),
    )

    for item in items:
        if item.kind == ChangeKind.CREATE and not create_missing:
            continue
        try:
            if item.object_type == "device":
                if item.kind == ChangeKind.CREATE:
                    result = nb.create_device(item.payload)
                    device_id = result.id if result else None
                else:
                    _ensure_device_id(report, nb, lambda d: None)
                    dev = nb.get_device_by_name(report.hostname) or \
                          nb.get_device_by_ip(report.device_ip)
                    if dev:
                        nb.update_device(dev.id, item.payload)
                        device_id = dev.id

            elif item.object_type == "interface":
                if device_id is None:
                    dev = nb.get_device_by_name(report.hostname) or \
                          nb.get_device_by_ip(report.device_ip)
                    device_id = dev.id if dev else None

                if item.kind == ChangeKind.CREATE:
                    if device_id and item.payload.get("device") is None:
                        item.payload["device"] = device_id
                    created_iface = nb.create_interface(item.payload)
                    # Patch any IP payloads that were waiting on this iface ID
                    if created_iface:
                        iface_name = item.payload.get("name", "")
                        _backfill_iface_id(items, iface_name, created_iface.id,
                                           report.hostname)
                else:
                    iface_name = item.identifier.split(" / ", 1)[-1]
                    if device_id:
                        nb_iface = nb.get_interface(device_id, iface_name)
                        if nb_iface:
                            nb.update_interface(nb_iface.id, item.payload)

            elif item.object_type == "ip_address":
                if item.kind == ChangeKind.CREATE:
                    nb.create_ip_address(item.payload)
                else:
                    ip_obj = nb.get_ip_address(item.identifier)
                    if ip_obj:
                        nb.update_ip_address(ip_obj.id, item.payload)

            applied += 1
        except Exception as exc:
            log.error("Failed to apply %s %s: %s", item.kind, item.identifier, exc)

    return applied


def _backfill_iface_id(
    items: list[DriftItem],
    iface_name: str,
    iface_id: int,
    hostname: str,
) -> None:
    """After creating an interface, update any pending IP payloads that
    reference it by matching identifier prefix."""
    prefix = f"{hostname} / {iface_name} /"
    for item in items:
        if item.object_type == "ip_address" and item.kind == ChangeKind.CREATE:
            if item.identifier.startswith(prefix) or \
               item.payload.get("assigned_object_id") is None:
                # Only backfill if it looks like it belongs to this interface
                # (IP items store iface_id in payload; None means "not yet known")
                if item.payload.get("assigned_object_id") is None:
                    item.payload["assigned_object_type"] = "dcim.interface"
                    item.payload["assigned_object_id"] = iface_id


def _ensure_device_id(report, nb, _):
    pass  # placeholder kept for symmetry


# ---------------------------------------------------------------------------
# Cable sync  (second pass — after all devices/interfaces exist in NetBox)
# ---------------------------------------------------------------------------

def sync_mac_table(
    devices: list[DeviceInfo],
    nb: NetBoxClient,
    dry_run: bool = False,
) -> dict[str, int]:
    """
    Write per-interface MAC address tables into NetBox as a JSON custom field
    (mac_table) on dcim.interface.

    Groups all MacTableEntry records by interface, enriches each entry with
    external-tool links (Lansweeper, CrowdStrike, …) when configured, then
    calls upsert_mac_table for each interface that has at least one entry.

    The custom field is created automatically on first run if absent.

    Returns counts: {"updated": N, "unchanged": N, "skipped": N}.
    """
    nb.ensure_mac_table_custom_field()
    enricher = MacEnricher.from_config()

    counts: dict[str, int] = {"updated": 0, "unchanged": 0, "skipped": 0}

    for device in devices:
        if not device.mac_table:
            continue

        nb_device = (
            nb.get_device_by_name(device.hostname)
            or nb.get_device_by_ip(device.query_ip)
        )
        if nb_device is None:
            log.debug("MAC table sync: device %s not in NetBox yet",
                      device.display_name)
            counts["skipped"] += len(device.mac_table)
            continue

        # Group entries by interface name
        by_iface: dict[str, list[dict]] = {}
        for entry in device.mac_table:
            if not entry.if_name:
                continue
            by_iface.setdefault(entry.if_name, []).append({
                "mac":  entry.mac_address,
                "vlan": entry.vlan,
                "type": entry.entry_type.value,
            })

        log.info("MAC table sync: %s  %d interface(s)",
                 device.display_name, len(by_iface))

        for if_name, entries in by_iface.items():
            enricher.enrich(entries)   # adds *_url fields in place when configured
            if dry_run:
                log.info("  [dry-run] %s/%s  %d MAC(s)",
                         device.display_name, if_name, len(entries))
                counts["updated"] += 1
                continue
            try:
                action = nb.upsert_mac_table(nb_device.id, if_name, entries)
                counts[action] += 1
            except Exception as exc:
                log.error("MAC table upsert failed %s/%s: %s",
                          device.display_name, if_name, exc)
                counts["skipped"] += 1

    return counts


def sync_cables(
    devices: list[DeviceInfo],
    nb: NetBoxClient,
    create_missing: bool = True,
    dry_run: bool = False,
) -> int:
    """
    Walk every neighbour entry across all collected devices and create missing
    cables in NetBox.

    Must be called AFTER apply_report() has run for every device so that both
    endpoints exist in NetBox.

    Returns the number of cables created.
    """
    created = 0
    # Track pairs we've already processed to avoid A→B and B→A duplicates.
    # Key: frozenset of the two NetBox interface IDs.
    seen_pairs: set[frozenset] = set()

    for device in devices:
        nb_device = (
            nb.get_device_by_name(device.hostname)
            or nb.get_device_by_ip(device.query_ip)
        )
        if nb_device is None:
            log.debug("Cable sync: device %s not in NetBox, skipping",
                      device.display_name)
            continue

        nb_ifaces = {i.name: i for i in nb.get_interfaces(nb_device.id)}

        for nbr in device.neighbors:
            local_nb_iface = nb_ifaces.get(nbr.local_if_name)
            if local_nb_iface is None:
                log.debug("Cable sync: local iface %s/%s not in NetBox",
                          device.display_name, nbr.local_if_name)
                continue

            remote_device = (
                nb.get_device_by_name(nbr.remote_device_id)
                or (nb.get_device_by_ip(nbr.remote_ip) if nbr.remote_ip else None)
            )
            if remote_device is None:
                log.info(
                    "Cable sync: remote device %r not in NetBox "
                    "(was it discovered and synced?)",
                    nbr.remote_device_id,
                )
                continue

            remote_nb_iface = nb.get_interface(remote_device.id, nbr.remote_port_id)
            if remote_nb_iface is None:
                log.debug("Cable sync: remote iface %s/%s not in NetBox",
                          nbr.remote_device_id, nbr.remote_port_id)
                continue

            pair = frozenset({local_nb_iface.id, remote_nb_iface.id})
            if pair in seen_pairs:
                continue  # already handled from the other device's perspective
            seen_pairs.add(pair)

            # Check whether a cable already exists
            already_connected = nb.get_connected_interface_ids(local_nb_iface.id)
            if remote_nb_iface.id in already_connected:
                log.debug("Cable already exists: %s/%s <-> %s/%s",
                          device.display_name, nbr.local_if_name,
                          nbr.remote_device_id, nbr.remote_port_id)
                continue

            label = (
                f"{nbr.protocol.upper()}: "
                f"{device.display_name}/{nbr.local_if_name} "
                f"<-> "
                f"{nbr.remote_device_id}/{nbr.remote_port_id}"
            )
            log.info("Cable: %s", label)
            if not dry_run and create_missing:
                try:
                    nb.create_cable(local_nb_iface.id, remote_nb_iface.id, label)
                    created += 1
                except Exception as exc:
                    log.error("Failed to create cable %s: %s", label, exc)
            else:
                created += 1   # count as "would create" in dry-run

    return created


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def _device_payload(info: DeviceInfo, nb: NetBoxClient) -> dict:
    mfr_meta = _manufacturer_for(info.platform)
    device_type = nb.get_or_create_device_type(
        info.model, mfr_meta["slug"], mfr_meta["name"]
    )
    platform = nb.get_or_create_platform(info.platform.value)

    site = nb.get_or_create_site(config.DEFAULT_SITE_SLUG)
    role = nb.get_or_create_device_role(config.DEFAULT_DEVICE_ROLE_SLUG)

    if site is None:
        raise RuntimeError(
            f"Cannot create device: NetBox site {config.DEFAULT_SITE_SLUG!r} "
            "does not exist and could not be created. "
            "Set DEFAULT_SITE_SLUG in config.py to a valid site slug."
        )
    if role is None:
        raise RuntimeError(
            f"Cannot create device: NetBox device role "
            f"{config.DEFAULT_DEVICE_ROLE_SLUG!r} does not exist and could not "
            "be created. Set DEFAULT_DEVICE_ROLE_SLUG in config.py."
        )

    return {
        "name":        info.hostname or info.query_ip,
        "device_type": device_type.id if device_type else None,
        "role":        role.id,
        "site":        site.id,
        "platform":    platform.id if platform else None,
        "serial":      info.serial_number,
        "status":      "active",
        "comments":    info.os_version,
    }


def _interface_payload(iface: Interface, device_id: Optional[int]) -> dict:
    payload: dict = {
        "name":        iface.name,
        "type":        NetBoxClient.speed_to_type_slug(iface.speed_mbps),
        "enabled":     iface.admin_status.value == "up",
        "description": iface.description,
        "mac_address": iface.mac_address or None,
    }
    if device_id is not None:
        payload["device"] = device_id
    return payload


def _ip_payload(ip: IPAddress, iface_id: Optional[int]) -> dict:
    payload: dict = {
        "address": ip.cidr,
        "status":  "active",
    }
    if iface_id is not None:
        payload["assigned_object_type"] = "dcim.interface"
        payload["assigned_object_id"]   = iface_id
    return payload


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _check(
    diffs: list[FieldDiff],
    field: str,
    netbox_val: object,
    snmp_val: object,
    label: Optional[str] = None,
) -> None:
    nb_norm   = (str(netbox_val) or "").strip().lower()
    snmp_norm = (str(snmp_val)   or "").strip().lower()
    if nb_norm != snmp_norm and snmp_norm:
        diffs.append(FieldDiff(
            field=label or field,
            netbox_value=netbox_val,
            snmp_value=snmp_val,
        ))
