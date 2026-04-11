#!/usr/bin/env python3
"""
Import / update NetBox devices from CrowdStrike Falcon.

Scrolls through all hosts in CrowdStrike Falcon and, for each one:
  - Finds the matching NetBox device (by AID → hostname → MAC → local IP)
  - Creates it if absent
  - Updates crowdstrike_aid and last_public_ip custom fields
  - Creates or updates a Management interface with the host's MAC address
  - Creates a dcim.mac_addresses object on that interface (vendor via OUI)

Credentials
-----------
NetBox      : config.py  (NETBOX_URL, NETBOX_TOKEN)
CrowdStrike : CS_FEM_TOKEN file  (JSON: client_id / client_secret)

Custom fields created automatically on first run
-------------------------------------------------
  dcim.device   : crowdstrike_aid, last_public_ip
  dcim.macaddress : vendor, external_url  (if not already present)

Usage
-----
  python cs_import.py                  # import/update all hosts
  python cs_import.py --dry-run        # show what would change
  python cs_import.py --filter "tags:'IT-managed'"   # FQL filter
  python cs_import.py --token-file /etc/cs/CS_FEM_TOKEN
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
from rich.table import Table

import config
from netbox_client import NetBoxClient
from oui import OuiLookup

console = Console()
log = logging.getLogger(__name__)

_DEFAULT_TOKEN_FILE = "CS_FEM_TOKEN"
_DEFAULT_BASE_URL   = "https://api.crowdstrike.com"
_DEFAULT_CONSOLE    = "https://falcon.crowdstrike.com"
_API_DELAY          = 0.05   # seconds between CrowdStrike calls
_DETAILS_BATCH      = 100    # max AIDs per GetDeviceDetails call
_AID_BATCH          = 100    # max AIDs per Spotlight QueryVulnerabilities call
_VULN_BATCH         = 400    # max vuln IDs per GetVulnerabilities call

# CrowdStrike platform_name → NetBox platform slug
_CS_PLATFORM_MAP = {
    "Windows": "windows",
    "Linux":   "linux",
    "Mac":     "macos",
}

# CrowdStrike product_type_desc → NetBox device role slug
_CS_ROLE_MAP = {
    "Workstation":          getattr(config, "CS_WORKSTATION_ROLE_SLUG", "workstation"),
    "Server":               getattr(config, "CS_SERVER_ROLE_SLUG",      "server"),
    "Domain Controller":    getattr(config, "CS_SERVER_ROLE_SLUG",      "server"),
}


# ---------------------------------------------------------------------------
# Falcon client
# ---------------------------------------------------------------------------

class FalconImporter:
    """
    Wraps falconpy Hosts to scroll all devices and fetch their details.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = _DEFAULT_BASE_URL,
        console_url: str = _DEFAULT_CONSOLE,
    ) -> None:
        self.console_url = console_url.rstrip("/")
        try:
            from falconpy import Hosts
            self._hosts = Hosts(
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
            )
        except ImportError:
            console.print(
                "[red]crowdstrike-falconpy is not installed.[/red]\n"
                "Install it with:  pip install crowdstrike-falconpy"
            )
            sys.exit(1)

    def scroll_all(self, fql_filter: str = "") -> list[dict]:
        """
        Return full device detail dicts for every host matching *fql_filter*
        (empty string = all hosts).  Uses scroll pagination + batched detail
        fetches to handle fleets of any size.
        """
        all_aids: list[str] = []
        after: Optional[str] = None

        while True:
            kwargs: dict = {"limit": 5_000}
            if fql_filter:
                kwargs["filter"] = fql_filter
            if after:
                kwargs["after"] = after

            resp = self._hosts.query_devices_by_filter_scroll(**kwargs)
            if resp.get("status_code") != 200:
                log.error(
                    "CrowdStrike scroll failed (HTTP %s): %s",
                    resp.get("status_code"),
                    (resp.get("body") or {}).get("errors"),
                )
                break

            body  = resp["body"]
            aids  = body.get("resources") or []
            after = (body.get("meta") or {}).get("pagination", {}).get("after")
            all_aids.extend(aids)

            if not aids or not after:
                break
            time.sleep(_API_DELAY)

        log.info("CrowdStrike: %d host(s) found", len(all_aids))
        return self._fetch_details(all_aids)

    def device_url(self, aid: str) -> str:
        return f"{self.console_url}/host-management/hosts/{aid}"

    def _fetch_details(self, aids: list[str]) -> list[dict]:
        details: list[dict] = []
        for i in range(0, len(aids), _DETAILS_BATCH):
            batch = aids[i : i + _DETAILS_BATCH]
            resp = self._hosts.get_device_details(ids=batch)
            if resp.get("status_code") == 200:
                details.extend(resp["body"].get("resources") or [])
            else:
                log.error(
                    "GetDeviceDetails failed for batch %d–%d (HTTP %s)",
                    i, i + len(batch),
                    resp.get("status_code"),
                )
            time.sleep(_API_DELAY)
        return details

    @classmethod
    def from_token_file(cls, path: str | Path | None = None) -> "FalconImporter":
        token_path = Path(path) if path else Path(os.getcwd()) / _DEFAULT_TOKEN_FILE
        if not token_path.exists():
            console.print(
                f"[red]CS_FEM_TOKEN not found at:[/red] {token_path}\n"
                "Create the file with your CrowdStrike API credentials."
            )
            sys.exit(1)
        try:
            creds = json.loads(token_path.read_text())
            client_id     = creds["client_id"]
            client_secret = creds["client_secret"]
        except (json.JSONDecodeError, KeyError) as exc:
            console.print(f"[red]CS_FEM_TOKEN is invalid:[/red] {exc}")
            sys.exit(1)
        return cls(
            client_id     = client_id,
            client_secret = client_secret,
            base_url      = creds.get("base_url",    _DEFAULT_BASE_URL),
            console_url   = creds.get("console_url", _DEFAULT_CONSOLE),
        )


# ---------------------------------------------------------------------------
# Spotlight (vulnerability) client
# ---------------------------------------------------------------------------

class SpotlightClient:
    """
    Fetches vulnerability and misconfiguration findings from CrowdStrike Spotlight
    for a list of AIDs and returns a per-AID summary dict ready to write into the
    NetBox 'vulnerabilities' custom field.

    Covers:
      - CVE-based vulnerabilities (cve.id present)
      - Non-CVE / misconfiguration findings (cve.id absent)

    Only open / in-progress / reopened findings are fetched; closed and expired
    findings are excluded to keep the field concise.
    """

    _OPEN_STATUSES = "status:!['closed','expired']"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = _DEFAULT_BASE_URL,
    ) -> None:
        try:
            from falconpy import SpotlightVulnerabilities
            self._spotlight = SpotlightVulnerabilities(
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
            )
        except ImportError:
            console.print(
                "[red]crowdstrike-falconpy is not installed.[/red]\n"
                "Install it with:  pip install crowdstrike-falconpy"
            )
            sys.exit(1)

    def fetch_summaries(self, aids: list[str]) -> dict[str, dict]:
        """
        Return {aid: vulnerability_summary} for every AID in *aids*.
        AIDs with no findings get an empty summary (counts all zero, findings []).
        """
        summaries: dict[str, dict] = {aid: _empty_vuln_summary() for aid in aids}

        for i in range(0, len(aids), _AID_BATCH):
            batch = aids[i : i + _AID_BATCH]
            aid_list = ",".join(f"'{a}'" for a in batch)
            fql = f"aid:[{aid_list}]+{self._OPEN_STATUSES}"

            vuln_ids = self._scroll_vuln_ids(fql)
            if not vuln_ids:
                continue

            for j in range(0, len(vuln_ids), _VULN_BATCH):
                id_batch = vuln_ids[j : j + _VULN_BATCH]
                resp = self._spotlight.get_vulnerabilities(ids=id_batch)
                if resp.get("status_code") != 200:
                    log.error(
                        "GetVulnerabilities failed (HTTP %s): %s",
                        resp.get("status_code"),
                        (resp.get("body") or {}).get("errors"),
                    )
                    continue
                for vuln in (resp["body"].get("resources") or []):
                    aid = vuln.get("aid", "")
                    if aid in summaries:
                        _add_finding(summaries[aid], vuln)
                time.sleep(_API_DELAY)

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for s in summaries.values():
            s["updated"] = now

        return summaries

    def _scroll_vuln_ids(self, fql: str) -> list[str]:
        """Page through QueryVulnerabilities and collect all matching IDs."""
        ids: list[str] = []
        after: Optional[str] = None
        while True:
            kwargs: dict = {"filter": fql, "limit": 400}
            if after:
                kwargs["after"] = after
            resp = self._spotlight.query_vulnerabilities(**kwargs)
            if resp.get("status_code") != 200:
                log.error(
                    "QueryVulnerabilities failed (HTTP %s): %s",
                    resp.get("status_code"),
                    (resp.get("body") or {}).get("errors"),
                )
                break
            body  = resp["body"]
            batch = body.get("resources") or []
            after = (body.get("meta") or {}).get("pagination", {}).get("after")
            ids.extend(batch)
            if not batch or not after:
                break
            time.sleep(_API_DELAY)
        return ids

    @classmethod
    def from_token_file(cls, path: str | Path | None = None) -> "SpotlightClient":
        token_path = Path(path) if path else Path(os.getcwd()) / _DEFAULT_TOKEN_FILE
        if not token_path.exists():
            console.print(f"[red]CS_FEM_TOKEN not found at:[/red] {token_path}")
            sys.exit(1)
        try:
            creds = json.loads(token_path.read_text())
        except (json.JSONDecodeError, KeyError) as exc:
            console.print(f"[red]CS_FEM_TOKEN is invalid:[/red] {exc}")
            sys.exit(1)
        return cls(
            client_id     = creds["client_id"],
            client_secret = creds["client_secret"],
            base_url      = creds.get("base_url", _DEFAULT_BASE_URL),
        )


def _empty_vuln_summary() -> dict:
    return {
        "updated":  "",
        "counts":   {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
        "findings": [],
    }


def _add_finding(summary: dict, vuln: dict) -> None:
    """Append one Spotlight vulnerability record to a summary dict in place."""
    cve_info = vuln.get("cve") or {}
    app_info = vuln.get("app") or {}

    severity = (vuln.get("severity") or "unknown").lower()
    counts   = summary["counts"]
    counts[severity] = counts.get(severity, 0) + 1

    finding: dict = {
        "status":   vuln.get("status", "open"),
        "severity": severity,
        "product":  (
            app_info.get("product_name_version")
            or app_info.get("product_name")
            or ""
        ),
    }

    cve_id = cve_info.get("id")
    if cve_id:
        finding["cve"]   = cve_id
        finding["score"] = cve_info.get("base_score")
    else:
        # Non-CVE finding — use the product name as the label
        finding["name"] = app_info.get("product_name") or vuln.get("id", "unknown")

    summary["findings"].append(finding)


# ---------------------------------------------------------------------------
# Import logic
# ---------------------------------------------------------------------------

def run_import(
    nb: NetBoxClient,
    falcon: FalconImporter,
    spotlight: SpotlightClient,
    oui: OuiLookup,
    fql_filter: str,
    dry_run: bool,
) -> dict[str, int]:
    counts = {"created": 0, "updated": 0, "unchanged": 0, "skipped": 0, "error": 0}
    results: list[dict] = []

    nb.ensure_crowdstrike_device_fields()
    nb.ensure_mac_address_fields()

    console.print("Fetching hosts from CrowdStrike…")
    hosts = falcon.scroll_all(fql_filter)
    if not hosts:
        console.print("[yellow]No hosts returned from CrowdStrike.[/yellow]")
        return counts

    aids = [h["device_id"] for h in hosts if h.get("device_id")]
    console.print(f"Fetching vulnerability data for {len(aids)} host(s) from Spotlight…")
    vuln_summaries = spotlight.fetch_summaries(aids)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Syncing to NetBox…", total=len(hosts))

        for host in hosts:
            progress.advance(task)
            aid = host.get("device_id", "")
            try:
                action = _sync_host(
                    host, nb, falcon, oui,
                    vuln_summary=vuln_summaries.get(aid),
                    dry_run=dry_run,
                )
                counts[action] += 1
                if action in ("created", "updated"):
                    summary = vuln_summaries.get(aid, {})
                    c = summary.get("counts", {})
                    results.append({
                        "hostname":    host.get("hostname", ""),
                        "aid":         aid,
                        "action":      action,
                        "local_ip":    host.get("local_ip", ""),
                        "external_ip": host.get("external_ip", ""),
                        "vulns":       f"C:{c.get('critical',0)} H:{c.get('high',0)} "
                                       f"M:{c.get('medium',0)} L:{c.get('low',0)}",
                    })
            except Exception as exc:
                log.error("Failed to sync host %s: %s", host.get("hostname", "?"), exc)
                counts["error"] += 1

    _print_results(results, dry_run)
    return counts


def _sync_host(
    host: dict,
    nb: NetBoxClient,
    falcon: FalconImporter,
    oui: OuiLookup,
    vuln_summary: Optional[dict],
    dry_run: bool,
) -> str:
    """
    Sync one CrowdStrike host to NetBox.
    Returns "created", "updated", "unchanged", or "skipped".
    """
    aid      = host.get("device_id", "")
    hostname = host.get("hostname", "").strip()
    mac_raw  = host.get("mac_address", "")
    local_ip = host.get("local_ip", "")

    if not hostname:
        log.debug("Skipping host with no hostname (AID %s)", aid)
        return "skipped"

    mac = _colon_mac(mac_raw) if mac_raw else ""

    # --- Find existing NetBox device ---
    nb_device = (
        (nb.get_device_by_crowdstrike_aid(aid) if aid else None)
        or nb.get_device_by_name(hostname)
        or (nb.get_device_by_mac(mac) if mac else None)
        or (nb.get_device_by_ip(local_ip) if local_ip else None)
    )

    cs_fields: dict = {
        "crowdstrike_aid": aid,
        "last_public_ip":  host.get("external_ip", ""),
    }
    if vuln_summary is not None:
        cs_fields["vulnerabilities"] = vuln_summary

    if nb_device is None:
        # --- Create ---
        payload = _build_device_payload(host, nb)
        if payload is None:
            return "skipped"
        payload["tags"] = [{"slug": "crowdstrike"}]
        log.info("CREATE device: %s (AID %s)", hostname, aid)
        if not dry_run:
            nb_device = nb.nb.dcim.devices.create(payload)
            if nb_device:
                nb_device.update({"custom_fields": cs_fields})
                _sync_management_interface(nb_device, mac, oui, nb, dry_run)
        return "created"

    # --- Update ---
    updates: dict = {}
    existing_cf   = getattr(nb_device, "custom_fields", {}) or {}
    existing_tags = [t.slug for t in (getattr(nb_device, "tags", None) or [])]

    if existing_cf.get("crowdstrike_aid") != aid:
        updates["crowdstrike_aid"] = aid
    if existing_cf.get("last_public_ip") != host.get("external_ip", ""):
        updates["last_public_ip"] = host.get("external_ip", "")
    if vuln_summary is not None:
        # Always refresh vulnerability data — findings change every run
        updates["vulnerabilities"] = vuln_summary

    tag_patch: dict = {}
    if "crowdstrike" not in existing_tags:
        tag_patch = {"tags": [{"slug": t} for t in existing_tags] + [{"slug": "crowdstrike"}]}

    if updates or tag_patch:
        log.info("UPDATE device: %s — %s", hostname,
                 list(updates.keys()) + (["tags"] if tag_patch else []))
        if not dry_run:
            if updates:
                nb_device.update({"custom_fields": updates})
            if tag_patch:
                nb_device.update(tag_patch)
        _sync_management_interface(nb_device, mac, oui, nb, dry_run)
        return "updated"

    # Even if device fields are unchanged, keep MAC fresh
    if mac:
        _sync_management_interface(nb_device, mac, oui, nb, dry_run)

    return "unchanged"


def _build_device_payload(host: dict, nb: NetBoxClient) -> Optional[dict]:
    """Build a NetBox device creation payload from a CrowdStrike host dict."""
    hostname    = host.get("hostname", "").strip()
    mfr_name    = (host.get("system_manufacturer") or "Generic").strip()
    model_name  = (host.get("system_product_name")  or "Unknown").strip()
    platform_cs = host.get("platform_name", "")
    role_cs     = host.get("product_type_desc", "")
    local_ip    = host.get("local_ip", "")
    serial      = host.get("serial_number", "") or ""

    mfr_slug  = mfr_name.lower().replace(" ", "-").replace(",", "").replace(".", "")[:50]
    role_slug = _CS_ROLE_MAP.get(role_cs, getattr(config, "DEFAULT_DEVICE_ROLE_SLUG", "network"))

    try:
        mfr         = nb.get_or_create_manufacturer(mfr_slug, mfr_name)
        device_type = nb.get_or_create_device_type(model_name, mfr_slug, mfr_name)
        role        = nb.get_or_create_device_role(role_slug)
        platform    = _get_or_create_cs_platform(nb, platform_cs)
        site        = nb.site_for_ip(local_ip) if local_ip else None
        if site is None:
            site = nb.get_or_create_site(getattr(config, "DEFAULT_SITE_SLUG", "default"))
    except Exception as exc:
        log.error("Failed to resolve NetBox objects for %s: %s", hostname, exc)
        return None

    if site is None or role is None:
        log.warning("Cannot create %s — site or role unavailable", hostname)
        return None

    return {
        "name":        hostname,
        "device_type": device_type.id if device_type else None,
        "role":        role.id,
        "site":        site.id,
        "platform":    platform.id if platform else None,
        "serial":      serial,
        "status":      "active",
    }


def _sync_management_interface(
    nb_device: object,
    mac: str,
    oui: OuiLookup,
    nb: NetBoxClient,
    dry_run: bool,
) -> None:
    """
    Ensure the device has a 'Management' interface and a dcim.mac_addresses
    object for *mac* linked to it.
    """
    if not mac:
        return

    device_id = nb_device.id

    # Get or create the Management interface
    iface = nb.get_interface(device_id, "Management")
    if iface is None:
        log.info("CREATE interface: Management on device id=%s", device_id)
        if not dry_run:
            iface = nb.nb.dcim.interfaces.create({
                "device": device_id,
                "name":   "Management",
                "type":   "virtual",
            })
        else:
            return   # can't create MAC without the interface

    # Sync the MAC address object
    vendor_map = {mac: oui.lookup(mac)}
    nb.sync_interface_macs(iface.id, "Management", {mac}, vendor_map)


# ---------------------------------------------------------------------------
# NetBox platform helpers for endpoint OS types
# ---------------------------------------------------------------------------

_CS_PLATFORM_CACHE: dict[str, object] = {}

def _get_or_create_cs_platform(nb: NetBoxClient, platform_name: str) -> Optional[object]:
    slug = _CS_PLATFORM_MAP.get(platform_name, "unknown")
    if slug in _CS_PLATFORM_CACHE:
        return _CS_PLATFORM_CACHE[slug]
    plat = nb.nb.dcim.platforms.get(slug=slug)
    if not plat and slug != "unknown":
        name = platform_name or slug.replace("-", " ").title()
        log.info("Creating platform: %s", slug)
        try:
            plat = nb.nb.dcim.platforms.create({"name": name, "slug": slug})
        except Exception as exc:
            log.warning("Could not create platform %s: %s", slug, exc)
    _CS_PLATFORM_CACHE[slug] = plat
    return plat


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _print_results(results: list[dict], dry_run: bool) -> None:
    if not results:
        return
    t = Table(
        title="CrowdStrike import results" + (" [dry-run]" if dry_run else ""),
        show_lines=True,
    )
    t.add_column("Hostname",    style="bold")
    t.add_column("Action")
    t.add_column("Local IP",    style="cyan")
    t.add_column("External IP", style="cyan")
    t.add_column("Vulns",       style="dim", justify="right")
    t.add_column("AID",         style="dim")
    for r in results:
        colour = "green" if r["action"] == "created" else "yellow"
        t.add_row(
            r["hostname"],
            f"[{colour}]{r['action']}[/{colour}]",
            r["local_ip"],
            r["external_ip"],
            r.get("vulns", ""),
            r["aid"],
        )
    console.print(t)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.command()
@click.option("--token-file", default=None, metavar="PATH",
              help=f"Path to CS_FEM_TOKEN credential file (default: ./{_DEFAULT_TOKEN_FILE})")
@click.option("--filter", "fql_filter", default="", metavar="FQL",
              help="CrowdStrike FQL filter to limit which hosts are imported "
                   "(e.g. \"tags:'IT-managed'\"). Default: all hosts.")
@click.option("--dry-run", is_flag=True,
              help="Query CrowdStrike and NetBox but write nothing.")
@click.option("--verbose", "-v", is_flag=True)
def cli(token_file, fql_filter, dry_run, verbose):
    """Import or update NetBox devices from CrowdStrike Falcon hosts."""
    logging.basicConfig(
        format="%(levelname)-8s %(name)s: %(message)s",
        level=logging.DEBUG if verbose else logging.INFO,
    )

    nb         = NetBoxClient(config.NETBOX_URL, config.NETBOX_TOKEN, dry_run=dry_run)
    falcon     = FalconImporter.from_token_file(token_file)
    spotlight  = SpotlightClient.from_token_file(token_file)
    oui        = OuiLookup.from_config()

    if dry_run:
        console.print("[yellow]Dry-run mode — no changes will be written to NetBox.[/yellow]")

    counts = run_import(nb, falcon, spotlight, oui, fql_filter=fql_filter, dry_run=dry_run)

    action_word = "would be" if dry_run else "were"
    console.print(
        f"\n[bold]Done.[/bold]  "
        f"[green]{counts['created']} created[/green]  "
        f"[yellow]{counts['updated']} updated[/yellow]  "
        f"[dim]{counts['unchanged']} unchanged  "
        f"{counts['skipped']} skipped[/dim]"
        + (f"  [red]{counts['error']} error(s)[/red]" if counts["error"] else "")
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _colon_mac(mac: str) -> str:
    """Normalise any MAC format to lowercase colon-separated."""
    digits = mac.lower().replace("-", "").replace(":", "").replace(".", "")
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


if __name__ == "__main__":
    cli()
