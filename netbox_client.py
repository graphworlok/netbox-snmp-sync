"""
Thin wrapper around pynetbox for the objects we need.

All writes are guarded by a dry_run flag — when True every mutating call
is logged but not sent to NetBox.
"""

from __future__ import annotations

import logging
from typing import Optional

import pynetbox

log = logging.getLogger(__name__)

# NetBox interface type slug inferred from ifType / speed
_SPEED_TO_TYPE = {
    1_000:        "1000base-t",
    10_000:       "10gbase-x-sfpp",
    25_000:       "25gbase-x-sfp28",
    40_000:       "40gbase-x-qsfpp",
    100_000:      "100gbase-x-qsfp28",
    400_000:      "400gbase-x-qsfpdd",
}

_PLATFORM_SLUGS = {
    "ios":     "cisco-ios",
    "ios-xr":  "cisco-ios-xr",
    "nxos":    "cisco-nxos",
    "asa":     "cisco-asa",
    "panos":   "palo-alto-panos",
    "openwrt": "openwrt",
    "linux":   "linux",
    "unknown": "unknown",
}


class NetBoxClient:
    def __init__(self, url: str, token: str, dry_run: bool = False):
        self.nb = pynetbox.api(url, token=token)
        self.nb.http_session.verify = True   # set False if using self-signed cert
        self.dry_run = dry_run
        self._manufacturer_cache: dict[str, object] = {}
        self._platform_cache: dict[str, object] = {}
        self._device_type_cache: dict[str, object] = {}

    # ------------------------------------------------------------------
    # Manufacturers / device types / platforms
    # ------------------------------------------------------------------

    def get_or_create_manufacturer(self, slug: str, name: str) -> object:
        if slug in self._manufacturer_cache:
            return self._manufacturer_cache[slug]
        mfr = self.nb.dcim.manufacturers.get(slug=slug)
        if not mfr:
            log.info("Creating manufacturer: %s", name)
            if not self.dry_run:
                mfr = self.nb.dcim.manufacturers.create({"name": name, "slug": slug})
        self._manufacturer_cache[slug] = mfr
        return mfr

    def get_or_create_device_type(
        self, model: str, manufacturer_slug: str, manufacturer_name: str
    ) -> Optional[object]:
        if not model:
            return None
        key = f"{manufacturer_slug}/{model}"
        if key in self._device_type_cache:
            return self._device_type_cache[key]
        dt = self.nb.dcim.device_types.get(model=model,
                                           manufacturer=manufacturer_slug)
        if not dt:
            mfr = self.get_or_create_manufacturer(manufacturer_slug,
                                                   manufacturer_name)
            slug = model.lower().replace(" ", "-").replace("/", "-")
            log.info("Creating device type: %s", model)
            if not self.dry_run:
                dt = self.nb.dcim.device_types.create({
                    "manufacturer": mfr.id if mfr else None,
                    "model": model,
                    "slug": slug,
                })
        self._device_type_cache[key] = dt
        return dt

    def get_or_create_platform(self, platform_value: str) -> Optional[object]:
        slug = _PLATFORM_SLUGS.get(platform_value, "unknown")
        if slug in self._platform_cache:
            return self._platform_cache[slug]
        plat = self.nb.dcim.platforms.get(slug=slug)
        if not plat:
            log.info("Creating platform: %s", slug)
            if not self.dry_run:
                plat = self.nb.dcim.platforms.create({
                    "name": slug.replace("-", " ").title(),
                    "slug": slug,
                })
        self._platform_cache[slug] = plat
        return plat

    def get_or_create_site(self, slug: str) -> Optional[object]:
        site = self.nb.dcim.sites.get(slug=slug)
        if not site:
            log.info("Creating site: %s", slug)
            if not self.dry_run:
                site = self.nb.dcim.sites.create({
                    "name": slug.replace("-", " ").title(),
                    "slug": slug,
                    "status": "active",
                })
        return site

    def site_for_ip(self, ip: str) -> Optional[object]:
        """
        Return the NetBox site associated with the most-specific IPAM prefix
        that contains *ip*, or None if no matching prefix has a site.

        Queries ``ipam.prefixes?contains=<ip>`` which returns all prefixes
        that contain the address.  NetBox orders these from least- to
        most-specific; we reverse the list to prefer the most-specific match.
        """
        try:
            prefixes = list(self.nb.ipam.prefixes.filter(contains=ip))
        except Exception as exc:
            log.debug("IPAM prefix lookup failed for %s: %s", ip, exc)
            return None

        # Most-specific prefix first (longest prefix length wins)
        prefixes.sort(key=lambda p: int(str(p.prefix).split("/")[1]), reverse=True)
        for prefix in prefixes:
            site = getattr(prefix, "site", None)
            if site:
                log.debug("Site %r found via IPAM prefix %s for IP %s",
                          site, prefix.prefix, ip)
                return site
        return None

    def get_or_create_device_role(self, slug: str) -> Optional[object]:
        role = self.nb.dcim.device_roles.get(slug=slug)
        if not role:
            log.info("Creating device role: %s", slug)
            if not self.dry_run:
                role = self.nb.dcim.device_roles.create({
                    "name": slug.replace("-", " ").title(),
                    "slug": slug,
                    "color": "9e9e9e",
                })
        return role

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------

    def get_device_by_name(self, name: str) -> Optional[object]:
        return self.nb.dcim.devices.get(name=name)

    def get_device_by_ip(self, ip: str) -> Optional[object]:
        # Try primary IP lookup via IP address object
        ip_obj = self.nb.ipam.ip_addresses.get(address=ip)
        if ip_obj and getattr(ip_obj, "assigned_object", None):
            ao = ip_obj.assigned_object
            # assigned_object for a device interface has .device
            if hasattr(ao, "device"):
                return ao.device
        return None

    def create_device(self, payload: dict) -> Optional[object]:
        log.info("CREATE device: %s", payload.get("name"))
        if self.dry_run:
            return None
        return self.nb.dcim.devices.create(payload)

    def update_device(self, device_id: int, payload: dict) -> None:
        log.info("UPDATE device id=%s: %s", device_id, payload)
        if self.dry_run:
            return
        dev = self.nb.dcim.devices.get(device_id)
        if dev:
            dev.update(payload)

    # ------------------------------------------------------------------
    # Interfaces
    # ------------------------------------------------------------------

    def get_interfaces(self, device_id: int) -> list[object]:
        return list(self.nb.dcim.interfaces.filter(device_id=device_id))

    def get_interface(self, device_id: int, name: str) -> Optional[object]:
        return self.nb.dcim.interfaces.get(device_id=device_id, name=name)

    def create_interface(self, payload: dict) -> Optional[object]:
        log.info("CREATE interface: %s on device %s",
                 payload.get("name"), payload.get("device"))
        if self.dry_run:
            return None
        return self.nb.dcim.interfaces.create(payload)

    def update_interface(self, iface_id: int, payload: dict) -> None:
        log.info("UPDATE interface id=%s: %s", iface_id, payload)
        if self.dry_run:
            return
        iface = self.nb.dcim.interfaces.get(iface_id)
        if iface:
            iface.update(payload)

    # ------------------------------------------------------------------
    # Custom fields
    # ------------------------------------------------------------------

    _MAC_TABLE_FIELD = {
        "name":         "mac_table",
        "label":        "MAC Address Table",
        "type":         "json",
        "object_types": ["dcim.interface"],
        "description":  (
            "Bridge forwarding table entries learned on this interface. "
            "Format: [{\"mac\": \"aa:bb:cc:dd:ee:ff\", \"vlan\": 10, \"type\": \"learned\"}, ...]"
        ),
    }

    def ensure_mac_table_custom_field(self) -> None:
        """Create the mac_table JSON custom field on dcim.interface if absent."""
        existing = self.nb.extras.custom_fields.get(name="mac_table")
        if existing:
            return
        log.info("Creating custom field: mac_table on dcim.interface")
        if not self.dry_run:
            try:
                self.nb.extras.custom_fields.create(self._MAC_TABLE_FIELD)
            except Exception as exc:
                log.error("Could not create mac_table custom field: %s", exc)

    # ------------------------------------------------------------------
    # IP addresses
    # ------------------------------------------------------------------

    def get_ip_address(self, cidr: str) -> Optional[object]:
        return self.nb.ipam.ip_addresses.get(address=cidr)

    def create_ip_address(self, payload: dict) -> Optional[object]:
        log.info("CREATE ip_address: %s", payload.get("address"))
        if self.dry_run:
            return None
        return self.nb.ipam.ip_addresses.create(payload)

    def update_ip_address(self, ip_id: int, payload: dict) -> None:
        log.info("UPDATE ip_address id=%s: %s", ip_id, payload)
        if self.dry_run:
            return
        ip_obj = self.nb.ipam.ip_addresses.get(ip_id)
        if ip_obj:
            ip_obj.update(payload)

    def upsert_mac_table(
        self,
        device_id: int,
        if_name: str,
        entries: list[dict],   # [{"mac": str, "vlan": int, "type": str}, ...]
    ) -> str:
        """
        Write the MAC table entry list to the mac_table JSON custom field on a
        NetBox interface.  Returns "updated", "unchanged", or "skipped".
        """
        nb_iface = self.nb.dcim.interfaces.get(device_id=device_id, name=if_name)
        if nb_iface is None:
            log.debug("upsert_mac_table: interface %s not in NetBox", if_name)
            return "skipped"

        existing = (getattr(nb_iface, "custom_fields", {}) or {}).get("mac_table")
        if existing == entries:
            return "unchanged"

        log.info("UPDATE mac_table: device_id=%s  if=%s  (%d entries)",
                 device_id, if_name, len(entries))
        if not self.dry_run:
            nb_iface.update({"custom_fields": {"mac_table": entries}})
        return "updated"

    # ------------------------------------------------------------------
    # Cables
    # ------------------------------------------------------------------

    def get_connected_interface_ids(self, iface_id: int) -> set[int]:
        """Return the set of interface IDs cabled to the given interface."""
        connected: set[int] = set()
        cables = list(self.nb.dcim.cables.filter(
            termination_a_type="dcim.interface",
            termination_a_id=iface_id,
        )) + list(self.nb.dcim.cables.filter(
            termination_b_type="dcim.interface",
            termination_b_id=iface_id,
        ))
        for cable in cables:
            # Support both old (termination_a/b) and new (a_terminations list) API
            for term in getattr(cable, "a_terminations", []):
                connected.add(term.get("object_id") or getattr(term, "id", None))
            for term in getattr(cable, "b_terminations", []):
                connected.add(term.get("object_id") or getattr(term, "id", None))
            # Fallback for older NetBox
            ta = getattr(cable, "termination_a", None)
            tb = getattr(cable, "termination_b", None)
            if ta:
                connected.add(getattr(ta, "id", None))
            if tb:
                connected.add(getattr(tb, "id", None))
        connected.discard(None)
        return connected

    def create_cable(self, a_iface_id: int, b_iface_id: int, label: str = "") -> Optional[object]:
        log.info("CREATE cable: interface %s <-> interface %s  [%s]",
                 a_iface_id, b_iface_id, label)
        if self.dry_run:
            return None
        # NetBox 3.3+ termination format
        payload = {
            "a_terminations": [{"object_type": "dcim.interface", "object_id": a_iface_id}],
            "b_terminations": [{"object_type": "dcim.interface", "object_id": b_iface_id}],
            "status": "connected",
        }
        if label:
            payload["label"] = label
        return self.nb.dcim.cables.create(payload)

    def delete_cable(self, cable_id: int) -> None:
        log.info("DELETE cable id=%s", cable_id)
        if self.dry_run:
            return
        cable = self.nb.dcim.cables.get(cable_id)
        if cable:
            cable.delete()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def speed_to_type_slug(speed_mbps: Optional[int]) -> str:
        if speed_mbps is None:
            return "other"
        for threshold, slug in sorted(_SPEED_TO_TYPE.items()):
            if speed_mbps <= threshold:
                return slug
        return "other"
