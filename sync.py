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
import re
from typing import Optional

import config
from oui import OuiLookup
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

    For stacked switches (info.stack_members populated), delegates to
    _build_stack_drift() which creates a virtual chassis and one device per
    member named <hostname>-<N>.

    Device lookup order: serial number → hostname → management IP.
    """
    report = DriftReport(device_ip=info.query_ip, hostname=info.display_name)

    short_hostname = _short_hostname(info.hostname)

    log.debug(
        "Lookup [%s]  serial=%r  hostname=%r  short=%r  ip=%s",
        info.display_name, info.serial_number or "(none)",
        info.hostname, short_hostname, info.query_ip,
    )

    # Stack: delegate to dedicated handler
    if info.stack_members:
        log.debug(
            "  → stack detected: %d member(s): %s",
            len(info.stack_members),
            ", ".join(
                f"member {sm.member_number} serial={sm.serial_number!r} model={sm.model!r}"
                for sm in info.stack_members
            ),
        )
        _build_stack_drift(info, nb, report)
        return report

    # Non-stack: serial → full hostname → short hostname → virtual chassis → IP
    nb_device = None
    if info.serial_number:
        nb_device = nb.get_device_by_serial(info.serial_number)
        if nb_device:
            log.debug("  → matched by serial %r → NetBox id=%s name=%r",
                      info.serial_number, nb_device.id, str(nb_device))
        else:
            log.debug("  → serial %r not found in NetBox", info.serial_number)
    else:
        log.debug("  → no serial number collected; skipping serial lookup")

    if nb_device is None and short_hostname and short_hostname != info.hostname:
        nb_device = nb.get_device_by_name(short_hostname)
        if nb_device:
            log.debug("  → matched by short hostname %r → NetBox id=%s",
                      short_hostname, nb_device.id)
        else:
            log.debug("  → short hostname %r not found in NetBox", short_hostname)

    if nb_device is None:
        nb_device = nb.get_device_by_name(info.hostname)
        if nb_device:
            log.debug("  → matched by hostname %r → NetBox id=%s", info.hostname, nb_device.id)
        else:
            log.debug("  → hostname %r not found in NetBox", info.hostname)

    if nb_device is None:
        nb_device = nb.get_device_by_vc_name(info.hostname)
        if nb_device is None and short_hostname != info.hostname:
            nb_device = nb.get_device_by_vc_name(short_hostname)
        if nb_device:
            log.debug("  → matched via virtual chassis name → NetBox id=%s name=%r",
                      nb_device.id, str(nb_device))
        else:
            log.debug("  → no virtual chassis found for %r", info.hostname)

    if nb_device is None:
        nb_device = nb.get_device_by_ip(info.query_ip)
        if nb_device:
            log.debug("  → matched by IP %s → NetBox id=%s name=%r",
                      info.query_ip, nb_device.id, str(nb_device))
        else:
            log.debug("  → IP %s not found in NetBox — device will be created", info.query_ip)

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


def _stack_member_from_iface_name(name: str) -> int:
    """
    Extract the stack member number from a Cisco interface name.

    On Catalyst stacked switches the member number is the first digit group
    in the interface name, e.g.:
        GigabitEthernet2/0/1  → 2
        TenGigabitEthernet3/1/1 → 3
        Te1/0/24              → 1

    Returns 0 for interfaces that don't follow this pattern (Vlan10,
    Loopback0, mgmt0, etc.) — callers should default those to member 1.
    """
    m = re.match(r'[A-Za-z]+(\d+)/', name)
    return int(m.group(1)) if m else 0


def _build_stack_drift(info: DeviceInfo, nb: NetBoxClient, report: DriftReport) -> None:
    """
    Populate *report* with drift items for a stacked (virtual chassis) device.

    Emits:
      - One ``virtual_chassis`` item (CREATE if absent, skipped if already exists).
      - One ``device`` item per stack member, named <hostname>-<N>.
        Member lookup is serial-first, then by name.
      - ``interface`` items distributed to the correct member device by parsing
        the first digit group from the interface name (Gi2/0/1 → member 2).
      - ``ip_address`` items for any IPs not yet in NetBox.
    """
    short = _short_hostname(info.hostname)

    # Check whether a virtual chassis already exists — short name first
    existing_vc = None
    if short != info.hostname:
        log.debug("  VC lookup: checking short name %r", short)
        existing_vc = nb.get_virtual_chassis(short)
        if existing_vc:
            log.debug("  → virtual chassis %r already exists in NetBox (id=%s)",
                      short, existing_vc.id)
        else:
            log.debug("  → virtual chassis %r not found in NetBox", short)

    if existing_vc is None:
        log.debug("  VC lookup: checking full hostname %r", info.hostname)
        existing_vc = nb.get_virtual_chassis(info.hostname)
        if existing_vc:
            log.debug("  → virtual chassis %r already exists in NetBox (id=%s)",
                      info.hostname, existing_vc.id)
        else:
            log.debug("  → virtual chassis %r not found in NetBox", info.hostname)

    if existing_vc is None:
        log.debug("  → virtual chassis will be created")
        report.items.append(DriftItem(
            kind=ChangeKind.CREATE,
            object_type="virtual_chassis",
            identifier=info.hostname,
            payload={"name": info.hostname},
        ))
    else:
        # VC exists — store its id in the report payload so apply_report can
        # backfill it into member device payloads without a second lookup
        report.items.append(DriftItem(
            kind=ChangeKind.UPDATE,
            object_type="virtual_chassis",
            identifier=info.hostname,
            payload={"id": existing_vc.id, "name": str(existing_vc)},
        ))

    # Distribute interfaces to members by name; unresolvable → member 1
    member_ifaces: dict[int, list] = {}
    for iface in info.interfaces:
        member_num = _stack_member_from_iface_name(iface.name)
        if member_num == 0:
            member_num = 1
        member_ifaces.setdefault(member_num, []).append(iface)

    for member in sorted(info.stack_members, key=lambda sm: sm.member_number):
        member_name = f"{info.hostname}-{member.member_number}"

        short_member_name = f"{_short_hostname(info.hostname)}-{member.member_number}"

        log.debug(
            "  Stack member %d  name=%r  short=%r  serial=%r  model=%r",
            member.member_number, member_name, short_member_name,
            member.serial_number or "(none)", member.model or "(none)",
        )

        # serial → full member name → short member name → VC member lookup
        nb_dev = None
        if member.serial_number:
            nb_dev = nb.get_device_by_serial(member.serial_number)
            if nb_dev:
                log.debug("    → matched by serial %r → NetBox id=%s name=%r",
                          member.serial_number, nb_dev.id, str(nb_dev))
            else:
                log.debug("    → serial %r not found in NetBox", member.serial_number)
        else:
            log.debug("    → no serial for member %d; skipping serial lookup",
                      member.member_number)

        if nb_dev is None and short_member_name != member_name:
            nb_dev = nb.get_device_by_name(short_member_name)
            if nb_dev:
                log.debug("    → matched by short name %r → NetBox id=%s",
                          short_member_name, nb_dev.id)
            else:
                log.debug("    → short name %r not found in NetBox", short_member_name)

        if nb_dev is None:
            nb_dev = nb.get_device_by_name(member_name)
            if nb_dev:
                log.debug("    → matched by name %r → NetBox id=%s", member_name, nb_dev.id)
            else:
                log.debug("    → name %r not found in NetBox — member will be created",
                          member_name)

        if nb_dev is None:
            member_info = DeviceInfo(
                query_ip=info.query_ip,
                hostname=member_name,
                model=member.model,
                serial_number=member.serial_number,
                os_version=member.os_version,
                platform=info.platform,
                site_id=info.site_id,
            )
            payload = _device_payload(member_info, nb)
            payload["vc_position"] = member.member_number
            # virtual_chassis id is backfilled by apply_report after VC creation
            report.items.append(DriftItem(
                kind=ChangeKind.CREATE,
                object_type="device",
                identifier=member_name,
                payload=payload,
            ))
        else:
            diffs: list[FieldDiff] = []
            _check(diffs, "serial", getattr(nb_dev, "serial", ""), member.serial_number)
            _check(diffs, "comments", getattr(nb_dev, "comments", ""), member.os_version,
                   label="os_version")
            if diffs:
                report.items.append(DriftItem(
                    kind=ChangeKind.UPDATE,
                    object_type="device",
                    identifier=member_name,
                    diffs=diffs,
                    payload={d.field: d.snmp_value for d in diffs},
                ))

        nb_ifaces = {i.name: i for i in nb.get_interfaces(nb_dev.id)} if nb_dev else {}

        for iface in member_ifaces.get(member.member_number, []):
            nb_iface = nb_ifaces.get(iface.name)
            if nb_iface is None:
                payload = _interface_payload(
                    iface, device_id=nb_dev.id if nb_dev else None
                )
                report.items.append(DriftItem(
                    kind=ChangeKind.CREATE,
                    object_type="interface",
                    identifier=f"{member_name} / {iface.name}",
                    payload=payload,
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
                        identifier=f"{member_name} / {iface.name}",
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

    For stacked devices the report will contain a ``virtual_chassis`` item
    followed by per-member ``device`` items.  The VC id is resolved first and
    backfilled into each member's payload before the device rows are processed.
    Interfaces are routed to the correct member device using the device name
    embedded in the item identifier (<device-name> / <iface-name>).

    Cable creation is intentionally excluded here — call sync_cables() once
    all devices in a run have been processed.
    """
    applied = 0
    device_id: Optional[int] = None
    # Stack member name → NetBox device id; populated during device processing
    member_device_ids: dict[str, int] = {}
    vc_id: Optional[int] = None

    order = {"virtual_chassis": 0, "device": 1, "interface": 2, "ip_address": 3}
    items = sorted(
        [i for i in report.items if i.object_type != "cable"],
        key=lambda i: order.get(i.object_type, 9),
    )

    for item in items:
        if item.kind == ChangeKind.CREATE and not create_missing:
            continue
        try:
            if item.object_type == "virtual_chassis":
                if item.kind == ChangeKind.UPDATE:
                    # VC already exists — id was stashed in payload by _build_stack_drift
                    vc_id = item.payload["id"]
                    log.debug("VC already exists (id=%s) — skipping create", vc_id)
                else:
                    vc = nb.get_or_create_virtual_chassis(item.payload["name"])
                    vc_id = vc.id if vc else None
                if vc_id:
                    # Backfill vc id into member device payloads queued after this item
                    for dev_item in items:
                        if (dev_item.object_type == "device"
                                and "vc_position" in dev_item.payload
                                and not dev_item.payload.get("virtual_chassis")):
                            dev_item.payload["virtual_chassis"] = vc_id

            elif item.object_type == "device":
                if item.kind == ChangeKind.CREATE:
                    result = nb.create_device(item.payload)
                    if result:
                        if "vc_position" in item.payload:
                            member_device_ids[item.identifier] = result.id
                        else:
                            device_id = result.id
                else:
                    dev = (
                        nb.get_device_by_name(_short_hostname(item.identifier))
                        or nb.get_device_by_name(item.identifier)
                        or nb.get_device_by_ip(report.device_ip)
                    )
                    if dev:
                        nb.update_device(dev.id, item.payload)
                        if item.identifier != report.hostname:
                            member_device_ids[item.identifier] = dev.id
                        else:
                            device_id = dev.id

            elif item.object_type == "interface":
                # Determine which device owns this interface from the identifier
                iface_device_name = item.identifier.split(" / ", 1)[0]

                if iface_device_name in member_device_ids:
                    target_device_id = member_device_ids[iface_device_name]
                elif member_device_ids or iface_device_name != report.hostname:
                    # Stack run — member device may already exist in NetBox
                    dev = (
                        nb.get_device_by_name(_short_hostname(iface_device_name))
                        or nb.get_device_by_name(iface_device_name)
                    )
                    target_device_id = dev.id if dev else None
                    if target_device_id:
                        member_device_ids[iface_device_name] = target_device_id
                else:
                    # Non-stack: resolve the single device id
                    if device_id is None:
                        dev = (
                            nb.get_device_by_name(_short_hostname(report.hostname))
                            or nb.get_device_by_name(report.hostname)
                            or nb.get_device_by_ip(report.device_ip)
                        )
                        device_id = dev.id if dev else None
                    target_device_id = device_id

                if item.kind == ChangeKind.CREATE:
                    if target_device_id and item.payload.get("device") is None:
                        item.payload["device"] = target_device_id
                    created_iface = nb.create_interface(item.payload)
                    if created_iface:
                        iface_name = item.payload.get("name", "")
                        _backfill_iface_id(items, iface_name, created_iface.id,
                                           iface_device_name)
                else:
                    iface_name = item.identifier.split(" / ", 1)[-1]
                    if target_device_id:
                        nb_iface = nb.get_interface(target_device_id, iface_name)
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


# ---------------------------------------------------------------------------
# Cable sync  (second pass — after all devices/interfaces exist in NetBox)
# ---------------------------------------------------------------------------

def sync_mac_table(
    devices: list[DeviceInfo],
    nb: NetBoxClient,
    dry_run: bool = False,
) -> dict[str, int]:
    """
    Sync per-interface MAC address tables to native NetBox dcim.mac_addresses objects.

    For stacked devices, interfaces are resolved against the individual member
    devices rather than a single parent device.

    Returns totals: {"created": N, "refreshed": N, "stale": N, "unchanged": N, "skipped": N}.
    """
    nb.ensure_mac_address_fields()
    oui = OuiLookup.from_config()

    totals: dict[str, int] = {
        "created": 0, "refreshed": 0, "stale": 0, "unchanged": 0, "skipped": 0,
    }

    for device in devices:
        if not device.mac_table:
            continue

        # Group MACs by interface name first
        by_iface: dict[str, set[str]] = {}
        vendor_map: dict[str, str] = {}
        for entry in device.mac_table:
            if not entry.if_name:
                continue
            by_iface.setdefault(entry.if_name, set()).add(entry.mac_address)
            if entry.mac_address not in vendor_map:
                vendor_map[entry.mac_address] = oui.lookup(entry.mac_address)

        # Build a map of interface name → NetBox device for this device/stack
        iface_device_map = _resolve_iface_devices(device, nb)
        if not iface_device_map:
            log.debug("MAC table sync: no NetBox devices found for %s", device.display_name)
            totals["skipped"] += len(device.mac_table)
            continue

        log.info("MAC table sync: %s  %d interface(s)", device.display_name, len(by_iface))

        for if_name, macs in by_iface.items():
            nb_dev = iface_device_map.get(if_name)
            if nb_dev is None:
                log.debug("MAC table sync: interface %s/%s — no member device resolved",
                          device.display_name, if_name)
                totals["skipped"] += len(macs)
                continue

            nb_iface = nb.get_interface(nb_dev.id, if_name)
            if nb_iface is None:
                log.debug("MAC table sync: interface %s/%s not in NetBox",
                          device.display_name, if_name)
                totals["skipped"] += len(macs)
                continue

            if dry_run:
                log.info("  [dry-run] %s/%s  %d MAC(s)",
                         device.display_name, if_name, len(macs))
                totals["created"] += len(macs)
                continue

            try:
                counts = nb.sync_interface_macs(nb_iface.id, if_name, macs, vendor_map)
                for k, v in counts.items():
                    totals[k] += v
            except Exception as exc:
                log.error("MAC sync failed %s/%s: %s", device.display_name, if_name, exc)
                totals["skipped"] += len(macs)

    return totals


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
        # Build interface name → NetBox device map (handles stacks correctly)
        iface_device_map = _resolve_iface_devices(device, nb)
        if not iface_device_map:
            log.debug("Cable sync: no NetBox devices found for %s, skipping",
                      device.display_name)
            continue

        for nbr in device.neighbors:
            local_nb_dev = iface_device_map.get(nbr.local_if_name)
            if local_nb_dev is None:
                log.debug("Cable sync: local iface %s/%s — no member device resolved",
                          device.display_name, nbr.local_if_name)
                continue

            local_nb_iface = nb.get_interface(local_nb_dev.id, nbr.local_if_name)
            if local_nb_iface is None:
                log.debug("Cable sync: local iface %s/%s not in NetBox",
                          device.display_name, nbr.local_if_name)
                continue

            # Remote device: try name, short name, VC member lookup, then IP
            remote_device = _resolve_remote_device(nbr, nb)
            if remote_device is None:
                log.info(
                    "Cable sync: remote device %r not in NetBox "
                    "(was it discovered and synced?)",
                    nbr.remote_device_id,
                )
                continue

            # Remote interface: the port may live on a stack member
            remote_nb_iface = _resolve_remote_iface(remote_device, nbr.remote_port_id, nb)
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
# Stack-aware interface / device resolution helpers
# ---------------------------------------------------------------------------

def _resolve_iface_devices(device: DeviceInfo, nb: NetBoxClient) -> dict[str, object]:
    """
    Return a mapping of {interface_name: nb_device} for every interface on
    *device*.

    For stacked devices each interface is routed to its member device (derived
    from the slot number in the interface name).  For a non-stack device every
    interface maps to the single NetBox device.

    Returns an empty dict if no NetBox device can be found.
    """
    if not device.stack_members:
        nb_dev = (
            nb.get_device_by_serial(device.serial_number)
            or nb.get_device_by_name(_short_hostname(device.hostname))
            or nb.get_device_by_name(device.hostname)
            or nb.get_device_by_ip(device.query_ip)
        )
        if nb_dev is None:
            return {}
        return {iface.name: nb_dev for iface in device.interfaces}

    short = _short_hostname(device.hostname)

    # Build member_number → nb_device cache
    member_nb_devs: dict[int, object] = {}
    for member in device.stack_members:
        nb_dev = None
        if member.serial_number:
            nb_dev = nb.get_device_by_serial(member.serial_number)
        if nb_dev is None:
            nb_dev = nb.get_device_by_name(f"{short}-{member.member_number}")
        if nb_dev is None:
            nb_dev = nb.get_device_by_name(f"{device.hostname}-{member.member_number}")
        if nb_dev:
            member_nb_devs[member.member_number] = nb_dev
        else:
            log.debug("_resolve_iface_devices: member %d of %s not found in NetBox",
                      member.member_number, device.display_name)

    if not member_nb_devs:
        return {}

    result: dict[str, object] = {}
    for iface in device.interfaces:
        member_num = _stack_member_from_iface_name(iface.name)
        if member_num == 0:
            member_num = 1
        nb_dev = member_nb_devs.get(member_num) or next(iter(member_nb_devs.values()))
        result[iface.name] = nb_dev
    return result


def _resolve_remote_device(nbr: object, nb: NetBoxClient) -> Optional[object]:
    """
    Resolve the remote device for a cable endpoint.

    Tries in order:
      1. Exact name match (CDP/LLDP device-id as reported)
      2. Short hostname match
      3. Virtual chassis master/member lookup (for stacks that advertise
         the VC name rather than a member name via CDP/LLDP)
      4. Management IP
    """
    remote_id: str = nbr.remote_device_id  # type: ignore[attr-defined]
    remote_ip: str = getattr(nbr, "remote_ip", "") or ""
    short = _short_hostname(remote_id)

    if short != remote_id:
        dev = nb.get_device_by_name(short)
        if dev:
            return dev

    dev = nb.get_device_by_name(remote_id)
    if dev:
        return dev

    # Could be a VC — look up the member that owns the remote port (short first)
    dev = _resolve_vc_member_by_port(short, nbr.remote_port_id, nb)  # type: ignore[attr-defined]
    if dev is None and short != remote_id:
        dev = _resolve_vc_member_by_port(remote_id, nbr.remote_port_id, nb)  # type: ignore[attr-defined]
    if dev:
        return dev

    if remote_ip:
        dev = nb.get_device_by_ip(remote_ip)
    return dev


def _resolve_vc_member_by_port(vc_name: str, port_name: str, nb: NetBoxClient) -> Optional[object]:
    """
    If *vc_name* matches a virtual chassis, return the member device that owns
    *port_name* by deriving the member number from the port name.
    """
    try:
        vc = nb.get_virtual_chassis(vc_name)
        if not vc:
            return None
        member_num = _stack_member_from_iface_name(port_name)
        if member_num == 0:
            member_num = 1
        # Try <vc_name>-<N> and short-<vc_name>-<N>
        short = _short_hostname(vc_name)
        for candidate in (f"{short}-{member_num}", f"{vc_name}-{member_num}"):
            dev = nb.get_device_by_name(candidate)
            if dev:
                return dev
        # Fall back to VC master
        return getattr(vc, "master", None)
    except Exception as exc:
        log.debug("VC member port resolution failed for %s/%s: %s", vc_name, port_name, exc)
        return None


def _resolve_remote_iface(remote_device: object, port_name: str, nb: NetBoxClient) -> Optional[object]:
    """
    Look up a remote interface.  If the direct lookup on *remote_device* misses
    (e.g. the interface actually belongs to a stack member), also try searching
    by VC membership.
    """
    iface = nb.get_interface(remote_device.id, port_name)  # type: ignore[attr-defined]
    if iface:
        return iface

    # remote_device might be the VC master; the port may be on a different member
    vc = getattr(remote_device, "virtual_chassis", None)
    if not vc:
        return None
    try:
        member_num = _stack_member_from_iface_name(port_name)
        if member_num == 0:
            return None
        members = list(nb.nb.dcim.devices.filter(virtual_chassis_id=vc.id))
        for member in members:
            if getattr(member, "vc_position", None) == member_num:
                return nb.get_interface(member.id, port_name)
    except Exception as exc:
        log.debug("Remote iface VC member search failed: %s", exc)
    return None


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def _device_payload(info: DeviceInfo, nb: NetBoxClient) -> dict:
    mfr_meta = _manufacturer_for(info.platform)
    device_type = nb.get_or_create_device_type(
        info.model, mfr_meta["slug"], mfr_meta["name"]
    )
    platform = nb.get_or_create_platform(info.platform.value)

    site = _resolve_site(info, nb)
    role = nb.get_or_create_device_role(config.DEFAULT_DEVICE_ROLE_SLUG)

    if role is None:
        raise RuntimeError(
            f"Cannot create device: NetBox device role "
            f"{config.DEFAULT_DEVICE_ROLE_SLUG!r} does not exist and could not "
            "be created. Set DEFAULT_DEVICE_ROLE_SLUG in config.py."
        )

    payload: dict = {
        "name":        info.hostname or info.query_ip,
        "device_type": device_type.id if device_type else None,
        "role":        role.id,
        "platform":    platform.id if platform else None,
        "serial":      info.serial_number,
        "status":      "active",
        "comments":    info.os_version,
    }
    if site is not None:
        payload["site"] = site.id
    return payload


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
# Site resolution
# ---------------------------------------------------------------------------

def _resolve_site(info: DeviceInfo, nb: NetBoxClient) -> Optional[object]:
    """
    Determine the NetBox site for a device by IPAM prefix lookup only.

    0. Use ``info.site_id`` directly when set (e.g. supplied by Meraki sync).
    1. Check every IP address collected from the device against NetBox IPAM
       prefixes.  The most-specific prefix whose site field is set wins.
       The device's own management IP (query_ip) is tried first, then each
       interface IP in order.

    Returns None if no site can be resolved — the caller will log a warning
    and omit the site field rather than falling back to a default.
    """
    if info.site_id is not None:
        site = nb.nb.dcim.sites.get(info.site_id)
        if site:
            log.info("Site %r assigned to %s via site_id override",
                     str(site), info.display_name)
            return site

    # Collect IPs to probe: query IP first, then all interface IPs
    candidate_ips: list[str] = [info.query_ip]
    for iface in info.interfaces:
        for ip_obj in iface.ip_addresses:
            if ip_obj.address not in candidate_ips:
                candidate_ips.append(ip_obj.address)

    for ip in candidate_ips:
        site = nb.site_for_ip(ip)
        if site:
            log.info("Site %r assigned to %s via IPAM (IP %s)",
                     str(site), info.display_name, ip)
            return site

    log.warning("No IPAM site match for %s (IPs tried: %s) — site will be unset",
                info.display_name, ", ".join(candidate_ips))
    return None


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _short_hostname(hostname: str) -> str:
    """Return the first DNS label of *hostname* (everything before the first dot)."""
    return hostname.split(".")[0] if hostname else hostname


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
