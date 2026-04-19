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
    "meraki":  "meraki",
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

    def get_device_by_serial(self, serial: str) -> Optional[object]:
        if not serial:
            return None
        try:
            results = list(self.nb.dcim.devices.filter(serial=serial))
            return results[0] if results else None
        except Exception as exc:
            log.debug("Serial lookup failed for %s: %s", serial, exc)
            return None

    def get_device_by_name(self, name: str) -> Optional[object]:
        if not name:
            return None
        return self.nb.dcim.devices.get(name=name)

    def get_device_by_vc_name(self, vc_name: str) -> Optional[object]:
        """
        Return the master (or first) member device of a virtual chassis whose
        name matches *vc_name*.  Returns None if no matching VC exists.
        """
        if not vc_name:
            return None
        try:
            vc = self.nb.dcim.virtual_chassis.get(name=vc_name)
            if not vc:
                return None
            master = getattr(vc, "master", None)
            if master:
                return master
            # Fallback: return the first member device found in the VC
            members = list(self.nb.dcim.devices.filter(virtual_chassis_id=vc.id))
            return members[0] if members else None
        except Exception as exc:
            log.debug("VC name lookup failed for %s: %s", vc_name, exc)
            return None

    def get_device_by_ip(self, ip: str) -> Optional[object]:
        # Try primary IP lookup via IP address object
        ip_obj = self.nb.ipam.ip_addresses.get(address=ip)
        if ip_obj and getattr(ip_obj, "assigned_object", None):
            ao = ip_obj.assigned_object
            # assigned_object for a device interface has .device
            if hasattr(ao, "device"):
                return ao.device
        return None

    # ------------------------------------------------------------------
    # Virtual chassis
    # ------------------------------------------------------------------

    def get_virtual_chassis(self, name: str) -> Optional[object]:
        return self.nb.dcim.virtual_chassis.get(name=name)

    def get_or_create_virtual_chassis(self, name: str) -> Optional[object]:
        vc = self.get_virtual_chassis(name)
        if not vc:
            log.info("Creating virtual chassis: %s", name)
            if not self.dry_run:
                vc = self.nb.dcim.virtual_chassis.create({"name": name})
        return vc

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

    def get_interface_any_name(self, device_id: int, name: str,
                               variants_fn) -> Optional[object]:
        """
        Try each name variant returned by *variants_fn(name)* in order.
        Returns the first match, or None.  The variants_fn is passed in to
        avoid a circular import between netbox_client and sync.
        """
        for candidate in variants_fn(name):
            iface = self.nb.dcim.interfaces.get(device_id=device_id, name=candidate)
            if iface:
                if candidate != name:
                    log.debug("Interface %r matched as %r on device id=%s",
                              name, candidate, device_id)
                return iface
        return None

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

    def set_interface_uncontrolled_tag(self, iface: object, add: bool) -> None:
        """
        Add or remove the 'unmanaged-multimac' tag on *iface*.
        No-ops if the tag is already in the desired state.
        """
        slug = self._UNCONTROLLED_TAG["slug"]
        current_slugs = [t.slug for t in (getattr(iface, "tags", None) or [])]
        has_tag = slug in current_slugs

        if add and not has_tag:
            log.info("TAG unmanaged-multimac: interface id=%s (%s)",
                     iface.id, getattr(iface, "name", ""))
            if not self.dry_run:
                try:
                    iface.update({"tags": [{"slug": s} for s in current_slugs] + [{"slug": slug}]})
                except Exception as exc:
                    log.error("Could not add unmanaged-multimac tag to interface %s: %s",
                              iface.id, exc)
        elif not add and has_tag:
            log.info("UNTAG unmanaged-multimac: interface id=%s (%s)",
                     iface.id, getattr(iface, "name", ""))
            if not self.dry_run:
                try:
                    iface.update({"tags": [{"slug": s} for s in current_slugs if s != slug]})
                except Exception as exc:
                    log.error("Could not remove unmanaged-multimac tag from interface %s: %s",
                              iface.id, exc)

    def set_device_tag(self, device: object, slug: str, add: bool) -> None:
        """Add or remove a tag (by slug) on a NetBox device object."""
        current_slugs = [t.slug for t in (getattr(device, "tags", None) or [])]
        has_tag = slug in current_slugs
        if add and not has_tag:
            log.info("TAG %s: device %s", slug, getattr(device, "name", device.id))
            if not self.dry_run:
                try:
                    device.update({"tags": [{"slug": s} for s in current_slugs] + [{"slug": slug}]})
                except Exception as exc:
                    log.error("Could not add tag %s to device %s: %s", slug, device.id, exc)
        elif not add and has_tag:
            log.info("UNTAG %s: device %s", slug, getattr(device, "name", device.id))
            if not self.dry_run:
                try:
                    device.update({"tags": [{"slug": s} for s in current_slugs if s != slug]})
                except Exception as exc:
                    log.error("Could not remove tag %s from device %s: %s", slug, device.id, exc)

    # ------------------------------------------------------------------
    # MAC addresses (native dcim.mac_addresses — NetBox 4.1+)
    # ------------------------------------------------------------------

    _STALE_TAG = {"name": "stale", "slug": "stale", "color": "9e9e9e"}
    _UNCONTROLLED_TAG = {"name": "unmanaged-multimac", "slug": "unmanaged-multimac", "color": "f44336"}

    _MAC_CUSTOM_FIELDS: list[dict] = [
        {
            "name":         "vendor",
            "label":        "Vendor",
            "type":         "text",
            "object_types": ["dcim.macaddress"],
            "description":  "IEEE OUI-derived organisation name for this MAC address.",
            "required":     False,
        },
        {
            "name":         "external_url",
            "label":        "External URL",
            "type":         "url",
            "object_types": ["dcim.macaddress"],
            "description":  "Link to this MAC address in an external asset management tool.",
            "required":     False,
        },
    ]

    _IFACE_MAC_TABLE_FIELD: dict = {
        "name":         "learned_macs",
        "label":        "Learned MACs",
        "type":         "json",
        "object_types": ["dcim.interface"],
        "description":  "Bridge forwarding table MACs learned on this interface. "
                        "Each entry: {mac, vendor, cs_aid, cs_url}. "
                        "Populated by netbox-snmp-sync.",
        "required":     False,
    }

    def ensure_mac_address_fields(self) -> None:
        """Create required tags and custom fields if absent."""
        for tag in (self._STALE_TAG, self._UNCONTROLLED_TAG):
            if not self.nb.extras.tags.get(slug=tag["slug"]):
                log.info("Creating tag: %s", tag["slug"])
                if not self.dry_run:
                    try:
                        self.nb.extras.tags.create(tag)
                    except Exception as exc:
                        log.error("Could not create tag %s: %s", tag["slug"], exc)

        for field in self._MAC_CUSTOM_FIELDS + [self._IFACE_MAC_TABLE_FIELD]:
            if not self.nb.extras.custom_fields.get(name=field["name"]):
                log.info("Creating custom field: %s", field["name"])
                if not self.dry_run:
                    try:
                        self.nb.extras.custom_fields.create(field)
                    except Exception as exc:
                        log.error("Could not create custom field %s: %s", field["name"], exc)

    def sync_interface_macs(
        self,
        iface_id: int,
        if_name: str,
        snmp_macs: set[str],
        vendor_map: Optional[dict[str, str]] = None,
    ) -> dict[str, int]:
        """
        Reconcile SNMP-learned MACs against NetBox dcim.mac_addresses for one interface.

        - Creates entries for MACs not yet in NetBox, populating the 'vendor'
          custom field from *vendor_map* when available.
        - Clears the 'stale' tag from MACs that are seen again.
        - Applies the 'stale' tag to MACs present in NetBox but absent from the
          current SNMP table.

        Returns {"created": N, "refreshed": N, "stale": N, "unchanged": N}.
        """
        counts: dict[str, int] = {"created": 0, "refreshed": 0, "stale": 0, "unchanged": 0}
        vendor_map = vendor_map or {}

        existing = list(self.nb.dcim.mac_addresses.filter(
            assigned_object_type="dcim.interface",
            assigned_object_id=iface_id,
        ))
        existing_by_mac: dict[str, object] = {
            str(obj.mac_address).lower(): obj for obj in existing
        }

        for mac in snmp_macs:
            if mac in existing_by_mac:
                obj = existing_by_mac[mac]
                tag_slugs = [t.slug for t in (getattr(obj, "tags", None) or [])]
                if "stale" in tag_slugs:
                    log.info("REFRESH mac_address: %s on %s", mac, if_name)
                    if not self.dry_run:
                        obj.update({"tags": [{"slug": s} for s in tag_slugs if s != "stale"]})
                    counts["refreshed"] += 1
                else:
                    counts["unchanged"] += 1
            else:
                vendor = vendor_map.get(mac, "")
                log.info("CREATE mac_address: %s (%s) on interface id=%s (%s)",
                         mac, vendor or "unknown vendor", iface_id, if_name)
                if not self.dry_run:
                    try:
                        self.nb.dcim.mac_addresses.create({
                            "mac_address":          mac,
                            "assigned_object_type": "dcim.interface",
                            "assigned_object_id":   iface_id,
                            "custom_fields":        {"vendor": vendor},
                        })
                    except Exception as exc:
                        log.error("Failed to create MAC %s on %s: %s", mac, if_name, exc)
                        continue
                counts["created"] += 1

        for mac, obj in existing_by_mac.items():
            if mac not in snmp_macs:
                tag_slugs = [t.slug for t in (getattr(obj, "tags", None) or [])]
                if "stale" not in tag_slugs:
                    log.info("STALE mac_address: %s on %s", mac, if_name)
                    if not self.dry_run:
                        obj.update({"tags": [{"slug": s} for s in tag_slugs] + [{"slug": "stale"}]})
                    counts["stale"] += 1

        return counts

    def sync_interface_mac_table(
        self,
        iface: object,
        if_name: str,
        snmp_macs: set[str],
        vendor_map: Optional[dict[str, str]] = None,
    ) -> dict[str, int]:
        """
        Store bridge forwarding table MACs in the 'learned_macs' JSON custom
        field on *iface* rather than as dcim.mac_addresses objects.

        Each entry in the JSON array:
          {
            "mac":    "aa:bb:cc:dd:ee:ff",
            "vendor": "Vendor Inc.",        (from OUI lookup, may be "")
          }

        CrowdStrike enrichment (cs_falcon_url etc.) is applied to Ephemeral
        Endpoint devices by cs_sync.py, not stored here.

        Returns {"updated": 0|1, "unchanged": 0|1}.
        """
        import json as _json

        vendor_map = vendor_map or {}

        entries = []
        for mac in sorted(snmp_macs):
            entries.append({
                "mac":    mac,
                "vendor": vendor_map.get(mac, ""),
            })

        new_json = _json.dumps(entries, separators=(",", ":"))

        existing_cf = getattr(iface, "custom_fields", {}) or {}
        old_raw     = existing_cf.get("learned_macs")
        old_json    = _json.dumps(old_raw, separators=(",", ":")) if old_raw is not None else "null"

        # Compare normalised to avoid spurious updates
        try:
            old_norm = _json.dumps(_json.loads(old_json),  separators=(",", ":"), sort_keys=True)
            new_norm = _json.dumps(_json.loads(new_json),  separators=(",", ":"), sort_keys=True)
        except Exception:
            old_norm, new_norm = old_json, new_json

        if old_norm == new_norm:
            return {"updated": 0, "unchanged": 1}

        log.info("UPDATE learned_macs: %s/%s  %d MAC(s)",
                 if_name, getattr(iface, "id", "?"), len(entries))

        if not self.dry_run:
            try:
                iface.update({"custom_fields": {"learned_macs": entries}})
            except Exception as exc:
                log.error("Could not update learned_macs on %s: %s", if_name, exc)
                return {"updated": 0, "unchanged": 0}

        return {"updated": 1, "unchanged": 0}

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

    # ------------------------------------------------------------------
    # IPAM — prefixes, ASNs, RIRs
    # ------------------------------------------------------------------

    _RIR_CACHE: dict[str, object] = {}

    def get_or_create_rir(self, slug: str, name: str) -> Optional[object]:
        if slug in self._RIR_CACHE:
            return self._RIR_CACHE[slug]
        rir = self.nb.ipam.rirs.get(slug=slug)
        if not rir:
            log.info("Creating RIR: %s", name)
            if not self.dry_run:
                rir = self.nb.ipam.rirs.create({"name": name, "slug": slug})
        self._RIR_CACHE[slug] = rir
        return rir

    def get_or_create_asn(self, asn: int, rir_slug: str = "unknown",
                          description: str = "") -> Optional[object]:
        """Return the NetBox ASN record for *asn*, creating it if absent."""
        try:
            existing = list(self.nb.ipam.asns.filter(asn=asn))
            if existing:
                return existing[0]
        except Exception as exc:
            log.debug("ASN lookup failed for AS%d: %s", asn, exc)
            return None
        rir = self.get_or_create_rir(rir_slug,
                                      rir_slug.replace("-", " ").title())
        log.info("Creating ASN: AS%d", asn)
        if self.dry_run:
            return None
        try:
            payload: dict = {"asn": asn}
            if rir:
                payload["rir"] = rir.id
            if description:
                payload["description"] = description
            return self.nb.ipam.asns.create(payload)
        except Exception as exc:
            log.error("Could not create ASN AS%d: %s", asn, exc)
            return None

    def get_prefix(self, prefix: str, vrf_id: Optional[int] = None) -> Optional[object]:
        params: dict = {"prefix": prefix}
        if vrf_id is not None:
            params["vrf_id"] = vrf_id
        try:
            results = list(self.nb.ipam.prefixes.filter(**params))
            return results[0] if results else None
        except Exception as exc:
            log.debug("Prefix lookup failed for %s: %s", prefix, exc)
            return None

    def create_or_update_prefix(
        self,
        prefix: str,
        status: str = "active",
        description: str = "",
        vrf_id: Optional[int] = None,
        site_id: Optional[int] = None,
        role_slug: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> tuple[Optional[object], bool]:
        """
        Ensure a prefix record exists for *prefix*.

        Returns (prefix_object, created) where *created* is True if the record
        was newly inserted.  On dry-run the object is None and *created* reports
        what would happen.
        """
        existing = self.get_prefix(prefix, vrf_id=vrf_id)
        if existing:
            updates: dict = {}
            if description and str(getattr(existing, "description", "")) != description:
                updates["description"] = description
            if updates:
                log.info("UPDATE prefix %s: %s", prefix, updates)
                if not self.dry_run:
                    existing.update(updates)
            return existing, False

        payload: dict = {"prefix": prefix, "status": status}
        if description:
            payload["description"] = description
        if vrf_id is not None:
            payload["vrf"] = vrf_id
        if site_id is not None:
            payload["site"] = site_id
        if role_slug:
            role = self.nb.ipam.roles.get(slug=role_slug)
            if role:
                payload["role"] = role.id
        if tags:
            payload["tags"] = [{"slug": s} for s in tags]

        log.info("CREATE prefix: %s (%s)", prefix, status)
        if self.dry_run:
            return None, True
        try:
            return self.nb.ipam.prefixes.create(payload), True
        except Exception as exc:
            log.error("Could not create prefix %s: %s", prefix, exc)
            return None, False

    # ------------------------------------------------------------------
    # Meraki
    # ------------------------------------------------------------------

    _MERAKI_NETWORK_FIELD = {
        "name":         "meraki_network_id",
        "label":        "Meraki Network ID",
        "type":         "text",
        "object_types": ["dcim.site"],
        "description":  "Cisco Meraki Dashboard network ID (e.g. N_xxxxxxxxxxxx). "
                        "Used by meraki_sync.py to associate a NetBox site with a "
                        "Meraki network.",
        "required":     False,
    }

    # ------------------------------------------------------------------
    # CrowdStrike
    # ------------------------------------------------------------------

    _CS_TAG = {"name": "crowdstrike", "slug": "crowdstrike", "color": "e5001c"}

    _CS_DEVICE_FIELDS: list[dict] = [
        {
            "name":         "crowdstrike_aid",
            "label":        "CrowdStrike AID",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "CrowdStrike Falcon agent ID (AID) for this device.",
            "required":     False,
        },
        {
            "name":         "last_public_ip",
            "label":        "Last Public IP",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Last external/egress IP address this device was seen from "
                            "(sourced from CrowdStrike external_ip).",
            "required":     False,
        },
        {
            "name":         "vulnerabilities",
            "label":        "Vulnerabilities",
            "type":         "json",
            "object_types": ["dcim.device"],
            "description":  "Vulnerability findings from CrowdStrike Spotlight. "
                            "Includes CVEs and non-CVE misconfigurations. "
                            'Format: {"updated": "...", "counts": {...}, "findings": [...]}',
            "required":     False,
        },
    ]

    # Extended fields populated only by cs_sync.py
    _CS_DEVICE_FIELDS_EXTENDED: list[dict] = [
        {
            "name":         "cs_falcon_url",
            "label":        "CS Falcon URL",
            "type":         "url",
            "object_types": ["dcim.device"],
            "description":  "Direct link to this device in the CrowdStrike Falcon console.",
            "required":     False,
        },
        {
            "name":         "cs_first_seen",
            "label":        "CS First Seen",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Timestamp when the CrowdStrike Falcon agent first enrolled "
                            "on this device (ISO 8601, sourced from Falcon first_seen).",
            "required":     False,
        },
        {
            "name":         "cs_last_seen",
            "label":        "CS Last Seen",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Timestamp of the last CrowdStrike Falcon agent check-in "
                            "(ISO 8601, sourced from Falcon last_seen).",
            "required":     False,
        },
        {
            "name":         "cs_sensor_version",
            "label":        "CS Sensor Version",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "CrowdStrike Falcon sensor (agent) version installed on this device.",
            "required":     False,
        },
        {
            "name":         "cs_os_version",
            "label":        "CS OS Version",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Detailed operating system version string from CrowdStrike Falcon.",
            "required":     False,
        },
        {
            "name":         "cs_containment_status",
            "label":        "CS Containment Status",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "CrowdStrike network containment state: normal, contained, "
                            "containment_pending, or lift_containment_pending.",
            "required":     False,
        },
        {
            "name":         "cs_reduced_functionality",
            "label":        "CS Reduced Functionality",
            "type":         "boolean",
            "object_types": ["dcim.device"],
            "description":  "True if the CrowdStrike sensor is running in Reduced "
                            "Functionality Mode (RFM) — sensor capability is degraded.",
            "required":     False,
        },
        {
            "name":         "cs_prevention_policy",
            "label":        "CS Prevention Policy",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Name of the CrowdStrike prevention policy applied to this device.",
            "required":     False,
        },
        {
            "name":         "cs_groups",
            "label":        "CS Host Groups",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Comma-separated list of CrowdStrike host group names "
                            "this device belongs to.",
            "required":     False,
        },
        {
            "name":         "cs_chassis_type",
            "label":        "CS Chassis Type",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "Chassis type reported by CrowdStrike "
                            "(e.g. Desktop, Laptop, Server, Virtual Machine).",
            "required":     False,
        },
        {
            "name":         "cs_zta_score",
            "label":        "CS ZTA Score",
            "type":         "integer",
            "object_types": ["dcim.device"],
            "description":  "CrowdStrike Zero Trust Assessment overall score (0–100). "
                            "Higher is better. Requires ZTA to be licensed.",
            "required":     False,
        },
        {
            "name":         "cs_active_detections",
            "label":        "CS Active Detections",
            "type":         "integer",
            "object_types": ["dcim.device"],
            "description":  "Count of open or in-progress CrowdStrike Falcon detections "
                            "for this device.",
            "required":     False,
        },
        {
            "name":         "cs_discover_id",
            "label":        "CS Discover Asset ID",
            "type":         "text",
            "object_types": ["dcim.device"],
            "description":  "CrowdStrike Discover asset ID for devices that do not run "
                            "the Falcon sensor (unmanaged workstations, network gear). "
                            "Mutually exclusive with crowdstrike_aid.",
            "required":     False,
        },
    ]

    def ensure_crowdstrike_device_fields(self) -> None:
        """Create the crowdstrike tag and base custom fields on dcim.device if absent."""
        if not self.nb.extras.tags.get(slug="crowdstrike"):
            log.info("Creating tag: crowdstrike")
            if not self.dry_run:
                try:
                    self.nb.extras.tags.create(self._CS_TAG)
                except Exception as exc:
                    log.error("Could not create crowdstrike tag: %s", exc)

        for field in self._CS_DEVICE_FIELDS:
            if not self.nb.extras.custom_fields.get(name=field["name"]):
                log.info("Creating custom field: %s on dcim.device", field["name"])
                if not self.dry_run:
                    try:
                        self.nb.extras.custom_fields.create(field)
                    except Exception as exc:
                        log.error("Could not create custom field %s: %s", field["name"], exc)

    def ensure_crowdstrike_all_fields(self) -> None:
        """Create all CrowdStrike custom fields (base + extended) and the tag."""
        self.ensure_crowdstrike_device_fields()
        self.ensure_mac_address_fields()
        for field in self._CS_DEVICE_FIELDS_EXTENDED:
            if not self.nb.extras.custom_fields.get(name=field["name"]):
                log.info("Creating custom field: %s on dcim.device", field["name"])
                if not self.dry_run:
                    try:
                        self.nb.extras.custom_fields.create(field)
                    except Exception as exc:
                        log.error("Could not create custom field %s: %s", field["name"], exc)

    # ------------------------------------------------------------------
    # Ephemeral Endpoint devices (bridge MAC table entries)
    # ------------------------------------------------------------------

    _EPHEMERAL_MFR          = {"slug": "generic",              "name": "Generic"}
    _EPHEMERAL_TYPE_MODEL   = "Ephemeral Endpoint"
    _UNMANAGED_SW_TYPE_MODEL = "Unmanaged Switch"
    _EPHEMERAL_TAG          = {"name": "ephemeral-endpoint",   "slug": "ephemeral-endpoint",
                               "color": "607d8b"}
    _UNMANAGED_SW_TAG       = {"name": "unmanaged-switch",     "slug": "unmanaged-switch",
                               "color": "ff9800"}

    def ensure_ephemeral_endpoint_type(self) -> None:
        """
        Create the 'Generic' manufacturer, 'Ephemeral Endpoint' and 'Unmanaged Switch'
        device types, the corresponding device roles, and the tags if absent.
        Also ensures the cs_falcon_url URL custom field exists on dcim.device.
        Idempotent.
        """
        import config as _cfg

        # Manufacturer (shared by both device types)
        self.get_or_create_manufacturer(
            self._EPHEMERAL_MFR["slug"], self._EPHEMERAL_MFR["name"]
        )

        # Device types
        self.get_or_create_device_type(
            self._EPHEMERAL_TYPE_MODEL,
            self._EPHEMERAL_MFR["slug"],
            self._EPHEMERAL_MFR["name"],
        )
        self.get_or_create_device_type(
            self._UNMANAGED_SW_TYPE_MODEL,
            self._EPHEMERAL_MFR["slug"],
            self._EPHEMERAL_MFR["name"],
        )

        # Device roles
        self.get_or_create_device_role(_cfg.EPHEMERAL_ENDPOINT_ROLE_SLUG)
        self.get_or_create_device_role(_cfg.UNMANAGED_SWITCH_ROLE_SLUG)

        # Tags
        for tag in (self._EPHEMERAL_TAG, self._UNMANAGED_SW_TAG):
            if not self.nb.extras.tags.get(slug=tag["slug"]):
                log.info("Creating tag: %s", tag["slug"])
                if not self.dry_run:
                    try:
                        self.nb.extras.tags.create(tag)
                    except Exception as exc:
                        log.error("Could not create tag %s: %s", tag["slug"], exc)

        # cs_falcon_url URL field on dcim.device (so links are clickable)
        for field in self._CS_DEVICE_FIELDS_EXTENDED:
            if not self.nb.extras.custom_fields.get(name=field["name"]):
                log.info("Creating custom field: %s on dcim.device", field["name"])
                if not self.dry_run:
                    try:
                        self.nb.extras.custom_fields.create(field)
                    except Exception as exc:
                        log.error("Could not create custom field %s: %s",
                                  field["name"], exc)

    def get_or_create_ephemeral_endpoint(
        self,
        mac: str,
        site_id: Optional[int],
        upstream_iface_id: Optional[int] = None,
    ) -> Optional[object]:
        """
        Ensure a device of type 'Ephemeral Endpoint' exists for *mac* and that
        its eth0 is cabled to *upstream_iface_id*.

        *mac*               — colon-separated lowercase (e.g. 'aa:bb:cc:dd:ee:ff')
        *site_id*           — NetBox site.id for device placement
        *upstream_iface_id* — NetBox interface.id to cable eth0 to; this is either the
                              switch access port (single-MAC case) or a port on an
                              intermediate Unmanaged Switch device (multi-MAC case).

        Device name is the MAC address.  An 'eth0' interface is created and the
        MAC is assigned to it as a dcim.mac_addresses entry.  CrowdStrike enrichment
        (cs_falcon_url, crowdstrike tag) is handled by cs_sync.py — not this tool.

        Returns the pynetbox device object, or None on failure.
        """
        import config as _cfg

        # Build a normalised colon-separated name
        mac_name = mac.lower()

        # Lookup existing
        try:
            existing = self.nb.dcim.devices.get(name=mac_name)
        except Exception as exc:
            log.error("Ephemeral endpoint lookup failed for %s: %s", mac_name, exc)
            return None

        if existing:
            # Ensure the cable to the upstream port still exists
            if upstream_iface_id is not None:
                self._ensure_ephemeral_cable(existing, mac_name, upstream_iface_id)
            return existing

        # --- Create new ephemeral endpoint device ---
        role = self.nb.dcim.device_roles.get(slug=_cfg.EPHEMERAL_ENDPOINT_ROLE_SLUG)
        dt   = self.nb.dcim.device_types.get(
            model=self._EPHEMERAL_TYPE_MODEL,
            manufacturer=self._EPHEMERAL_MFR["slug"],
        )
        if not role or not dt:
            log.error(
                "Cannot create ephemeral endpoint %s: role or device type not found "
                "(run ensure_ephemeral_endpoint_type first)",
                mac_name,
            )
            return None

        payload: dict = {
            "name":        mac_name,
            "device_type": dt.id,
            "role":        role.id,
            "status":      "active",
            "tags":        [{"slug": self._EPHEMERAL_TAG["slug"]}],
        }
        if site_id:
            payload["site"] = site_id

        log.info("CREATE ephemeral endpoint: %s", mac_name)
        if self.dry_run:
            return None
        try:
            device = self.nb.dcim.devices.create(payload)
        except Exception as exc:
            log.error("Could not create ephemeral endpoint %s: %s", mac_name, exc)
            return None

        # Create an 'eth0' interface and assign the MAC address to it
        ep_iface = None
        try:
            ep_iface = self.nb.dcim.interfaces.create({
                "device": device.id,
                "name":   "eth0",
                "type":   "other",
            })
            self.nb.dcim.mac_addresses.create({
                "mac_address":          mac_name,
                "assigned_object_type": "dcim.interface",
                "assigned_object_id":   ep_iface.id,
            })
        except Exception as exc:
            log.error("Could not create interface/MAC for ephemeral endpoint %s: %s",
                      mac_name, exc)

        # Cable eth0 to the upstream port (switch port or unmanaged switch port)
        if upstream_iface_id is not None and ep_iface is not None:
            try:
                self.create_cable(upstream_iface_id, ep_iface.id, label=mac_name)
            except Exception as exc:
                log.error("Could not cable ephemeral endpoint %s to upstream port %s: %s",
                          mac_name, upstream_iface_id, exc)

        return device

    def _ensure_ephemeral_cable(
        self,
        endpoint_device: object,
        mac_name: str,
        upstream_iface_id: int,
    ) -> None:
        """
        Verify that the ephemeral endpoint's eth0 is cabled to *upstream_iface_id*.
        Creates the cable if absent.  If eth0 is connected to a *different* port
        (device moved), removes the stale cable first.
        """
        # Find the endpoint's eth0
        try:
            ep_iface = self.nb.dcim.interfaces.get(
                device_id=endpoint_device.id, name="eth0"
            )
        except Exception as exc:
            log.error("Could not look up eth0 for ephemeral endpoint %s: %s",
                      mac_name, exc)
            return

        if ep_iface is None:
            log.warning("Ephemeral endpoint %s has no eth0 interface", mac_name)
            return

        # Check existing cables on the endpoint's eth0
        connected_ids = self.get_connected_interface_ids(ep_iface.id)
        if upstream_iface_id in connected_ids:
            return  # already cabled correctly

        if connected_ids:
            # The device appears to have moved — remove stale cable(s)
            stale_cables = list(self.nb.dcim.cables.filter(
                termination_a_type="dcim.interface", termination_a_id=ep_iface.id,
            )) + list(self.nb.dcim.cables.filter(
                termination_b_type="dcim.interface", termination_b_id=ep_iface.id,
            ))
            for cable in stale_cables:
                other_ids = {
                    t.get("object", {}).get("id")
                    for term_list in (
                        getattr(cable, "a_terminations", None) or [],
                        getattr(cable, "b_terminations", None) or [],
                    )
                    for t in (term_list if isinstance(term_list, list) else [term_list])
                }
                if other_ids - {ep_iface.id}:
                    log.info(
                        "DELETE stale cable for moved endpoint %s (was on iface %s)",
                        mac_name, other_ids - {ep_iface.id},
                    )
                    self.delete_cable(cable.id)

        # Create the new cable
        try:
            self.create_cable(upstream_iface_id, ep_iface.id, label=mac_name)
        except Exception as exc:
            log.error("Could not cable ephemeral endpoint %s to upstream port %s: %s",
                      mac_name, upstream_iface_id, exc)

    def get_or_create_unmanaged_switch(
        self,
        name: str,
        site_id: Optional[int],
        switch_iface_id: int,
        current_macs: set[str],
    ) -> dict[str, int]:
        """
        Ensure an 'Unmanaged Switch' device exists for a multi-MAC access port and
        return a mapping of mac → unmanaged-switch port interface ID.

        *name*             — deterministic device name, e.g. 'usw:SW1/Gi1/0/5'
        *site_id*          — NetBox site.id for device placement
        *switch_iface_id*  — the real switch access port to cable the uplink to
        *current_macs*     — set of colon-separated lowercase MACs currently seen

        Topology created:
          switch_access_port ←cable→ usw.uplink
          usw.port-<mac>     ←cable→ ephemeral_endpoint.eth0   (one per MAC)

        Stale ports (MACs that have disappeared) are removed; their cables are
        deleted automatically by NetBox cascade.

        Returns {mac: port_iface_id} for all MACs in *current_macs*.
        """
        import config as _cfg

        mac_port_ids: dict[str, int] = {}

        # --- Find or create the unmanaged switch device ---
        try:
            device = self.nb.dcim.devices.get(name=name)
        except Exception as exc:
            log.error("Unmanaged switch lookup failed for %s: %s", name, exc)
            return mac_port_ids

        if not device:
            role = self.nb.dcim.device_roles.get(slug=_cfg.UNMANAGED_SWITCH_ROLE_SLUG)
            dt   = self.nb.dcim.device_types.get(
                model=self._UNMANAGED_SW_TYPE_MODEL,
                manufacturer=self._EPHEMERAL_MFR["slug"],
            )
            if not role or not dt:
                log.error(
                    "Cannot create unmanaged switch %s: role or device type not found",
                    name,
                )
                return mac_port_ids

            payload: dict = {
                "name":        name,
                "device_type": dt.id,
                "role":        role.id,
                "status":      "active",
                "tags":        [{"slug": self._UNMANAGED_SW_TAG["slug"]}],
            }
            if site_id:
                payload["site"] = site_id

            log.info("CREATE unmanaged switch: %s", name)
            if self.dry_run:
                return mac_port_ids
            try:
                device = self.nb.dcim.devices.create(payload)
            except Exception as exc:
                log.error("Could not create unmanaged switch %s: %s", name, exc)
                return mac_port_ids

        # --- Ensure uplink interface and cable to switch port ---
        try:
            uplink = self.nb.dcim.interfaces.get(device_id=device.id, name="uplink")
        except Exception:
            uplink = None

        if not uplink and not self.dry_run:
            try:
                uplink = self.nb.dcim.interfaces.create({
                    "device": device.id,
                    "name":   "uplink",
                    "type":   "other",
                })
            except Exception as exc:
                log.error("Could not create uplink for unmanaged switch %s: %s", name, exc)

        if uplink:
            connected = self.get_connected_interface_ids(uplink.id)
            if switch_iface_id not in connected:
                # Remove any stale uplink cable (switch port changed)
                if connected:
                    stale = list(self.nb.dcim.cables.filter(
                        termination_a_type="dcim.interface", termination_a_id=uplink.id,
                    )) + list(self.nb.dcim.cables.filter(
                        termination_b_type="dcim.interface", termination_b_id=uplink.id,
                    ))
                    for cable in stale:
                        self.delete_cable(cable.id)
                try:
                    self.create_cable(switch_iface_id, uplink.id, label=f"{name}/uplink")
                except Exception as exc:
                    log.error("Could not cable uplink for %s: %s", name, exc)

        # --- Reconcile per-MAC ports ---
        # Fetch all existing interfaces on this device except 'uplink'
        try:
            existing_ifaces = {
                iface.name: iface
                for iface in self.nb.dcim.interfaces.filter(device_id=device.id)
                if iface.name != "uplink"
            }
        except Exception as exc:
            log.error("Could not list interfaces for unmanaged switch %s: %s", name, exc)
            existing_ifaces = {}

        current_port_names = {f"port-{mac.lower()}" for mac in current_macs}

        # Remove stale ports (MACs no longer seen) — cable deleted by cascade
        for port_name, iface in list(existing_ifaces.items()):
            if port_name not in current_port_names:
                log.info("DELETE stale port %s on unmanaged switch %s", port_name, name)
                if not self.dry_run:
                    try:
                        iface.delete()
                    except Exception as exc:
                        log.error("Could not delete stale port %s on %s: %s",
                                  port_name, name, exc)

        # Create or return existing ports for current MACs
        for mac in current_macs:
            port_name = f"port-{mac.lower()}"
            iface = existing_ifaces.get(port_name)
            if not iface and not self.dry_run:
                try:
                    iface = self.nb.dcim.interfaces.create({
                        "device": device.id,
                        "name":   port_name,
                        "type":   "other",
                    })
                    log.debug("CREATE port %s on unmanaged switch %s", port_name, name)
                except Exception as exc:
                    log.error("Could not create port %s on %s: %s", port_name, name, exc)
            if iface:
                mac_port_ids[mac.lower()] = iface.id

        return mac_port_ids

    def get_device_by_crowdstrike_aid(self, aid: str) -> Optional[object]:
        """Return the NetBox device whose crowdstrike_aid custom field matches *aid*."""
        try:
            results = list(self.nb.dcim.devices.filter(**{"cf_crowdstrike_aid": aid}))
            return results[0] if results else None
        except Exception as exc:
            log.debug("AID lookup failed for %s: %s", aid, exc)
            return None

    def get_device_by_mac(self, mac: str) -> Optional[object]:
        """
        Return the NetBox device that owns the given MAC address (colon-separated),
        by looking up dcim.mac_addresses and following the assigned interface back
        to its device.
        """
        try:
            mac_obj = self.nb.dcim.mac_addresses.get(mac_address=mac)
            if mac_obj:
                assigned = getattr(mac_obj, "assigned_object", None)
                if assigned and hasattr(assigned, "device"):
                    return assigned.device
        except Exception as exc:
            log.debug("MAC device lookup failed for %s: %s", mac, exc)
        return None

    def get_device_by_any_ip(self, ips: list[str]) -> Optional[object]:
        """
        Try each IP in *ips* in turn and return the first NetBox device found.
        Checks ipam.ip_addresses for each address (plain or CIDR); follows the
        assignment back to a device interface.
        """
        for ip in ips:
            if not ip:
                continue
            try:
                dev = self.get_device_by_ip(ip)
                if dev:
                    return dev
            except Exception as exc:
                log.debug("any-IP lookup failed for %s: %s", ip, exc)
        return None

    def get_device_by_fqdn(self, fqdn: str) -> Optional[object]:
        """
        Try to match a device by its fully-qualified domain name.
        Checks:
          1. Exact device-name match against the full FQDN
          2. Exact device-name match against the short hostname (first label)
        The short-hostname fallback handles cases where NetBox stores "web01"
        but CrowdStrike reports "web01.corp.example.com".
        """
        if not fqdn:
            return None
        try:
            dev = self.nb.dcim.devices.get(name=fqdn)
            if dev:
                return dev
            if "." in fqdn:
                short = fqdn.split(".")[0]
                dev = self.nb.dcim.devices.get(name=short)
                if dev:
                    return dev
        except Exception as exc:
            log.debug("FQDN device lookup failed for %s: %s", fqdn, exc)
        return None

    def get_device_by_discover_id(self, discover_id: str) -> Optional[object]:
        """Return the NetBox device whose cs_discover_id custom field matches *discover_id*."""
        try:
            results = list(self.nb.dcim.devices.filter(**{"cf_cs_discover_id": discover_id}))
            return results[0] if results else None
        except Exception as exc:
            log.debug("Discover ID lookup failed for %s: %s", discover_id, exc)
            return None

    def ensure_meraki_network_field(self) -> None:
        """Create the meraki_network_id custom field on dcim.site if absent."""
        if not self.nb.extras.custom_fields.get(name="meraki_network_id"):
            log.info("Creating custom field: meraki_network_id on dcim.site")
            if not self.dry_run:
                try:
                    self.nb.extras.custom_fields.create(self._MERAKI_NETWORK_FIELD)
                except Exception as exc:
                    log.error("Could not create meraki_network_id custom field: %s", exc)

    def get_sites_by_meraki_network(self) -> dict[str, object]:
        """
        Return a mapping of Meraki network ID → NetBox site object for every
        site that has the meraki_network_id custom field populated.
        """
        result: dict[str, object] = {}
        try:
            sites = list(self.nb.dcim.sites.filter(**{"cf_meraki_network_id__n": ""}))
        except Exception as exc:
            log.error("Failed to query sites with meraki_network_id: %s", exc)
            return result
        for site in sites:
            network_id = (getattr(site, "custom_fields", {}) or {}).get("meraki_network_id", "")
            if network_id:
                result[network_id] = site
        return result

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
            # a_terminations items are pynetbox Records, not dicts — use getattr
            for term in getattr(cable, "a_terminations", []):
                connected.add(getattr(term, "object_id", None) or getattr(term, "id", None))
            for term in getattr(cable, "b_terminations", []):
                connected.add(getattr(term, "object_id", None) or getattr(term, "id", None))
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
