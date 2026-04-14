#!/usr/bin/env python3
"""
cs_sync.py — CrowdStrike Falcon → NetBox comprehensive sync

Integrates as much data as possible from CrowdStrike Falcon into NetBox:

  Hosts API       → device metadata: first/last seen, sensor version, OS version,
                     containment status, Reduced Functionality Mode (RFM),
                     prevention policy name, host group names, chassis type,
                     all network interfaces (NICs) with IP + MAC, Falcon console URL
  Spotlight       → vulnerability findings: CVEs with CVSS scores, non-CVE
                     misconfigurations, per-severity counts
  Zero Trust      → ZTA overall score (0-100) per device
  Detections      → count of open / in-progress detections per device

NetBox objects created / updated
---------------------------------
  dcim.device        created from Falcon host if not already present;
                     matched to existing by AID → hostname → MAC → local IP
  dcim.interface     one per NIC in network_interfaces[]; falls back to a
                     single "Management" interface if that field is absent
  dcim.mac_address   one per NIC MAC, linked to the interface; vendor via OUI;
                     external_url set to the Falcon device console page
  ipam.ip_address    (only with --sync-ips) created for each NIC IP if absent
  extras.tag         "crowdstrike" tag applied to every synced device

Custom fields auto-created on dcim.device
------------------------------------------
  crowdstrike_aid          CrowdStrike agent ID
  last_public_ip           Last egress IP seen by Falcon
  cs_falcon_url            Falcon console device page URL
  cs_first_seen            First Falcon agent enrollment timestamp (ISO 8601)
  cs_last_seen             Last Falcon agent check-in timestamp (ISO 8601)
  cs_sensor_version        Falcon sensor version installed
  cs_os_version            OS version string from Falcon
  cs_containment_status    Network containment state (normal / contained / …)
  cs_reduced_functionality True if sensor is in Reduced Functionality Mode
  cs_prevention_policy     Name of the applied Falcon prevention policy
  cs_groups                Comma-separated Falcon host group names
  cs_chassis_type          Chassis type: Desktop, Laptop, Server, Virtual Machine, …
  cs_zta_score             Zero Trust Assessment overall score (0–100)
  cs_active_detections     Count of open / in-progress Falcon detections
  vulnerabilities          Spotlight findings JSON (counts + per-CVE list)

Custom fields auto-created on dcim.macaddress
----------------------------------------------
  vendor                   IEEE OUI-derived vendor name
  external_url             Falcon host page URL (MAC-level cross-linking)

Credentials
-----------
  NetBox      : config.py  (NETBOX_URL, NETBOX_TOKEN)
  CrowdStrike : CS_FEM_TOKEN file  (JSON: client_id / client_secret,
                optionally base_url / console_url)

  {
      "client_id":     "...",
      "client_secret": "...",
      "base_url":      "https://api.crowdstrike.com",      (optional)
      "console_url":   "https://falcon.crowdstrike.com"    (optional)
  }

Usage examples
--------------
  python cs_sync.py                             # full sync, all data sources
  python cs_sync.py --dry-run                   # show what would change
  python cs_sync.py --filter "tags:'corp'"      # limit by Falcon FQL filter
  python cs_sync.py --no-vulns                  # skip Spotlight
  python cs_sync.py --no-zta                    # skip Zero Trust Assessment
  python cs_sync.py --no-detections             # skip detection counts
  python cs_sync.py --sync-ips                  # also create IPAM IP addresses
  python cs_sync.py --overwrite-macs            # refresh all MAC external_url fields
  python cs_sync.py --token-file /etc/cs/CS_FEM_TOKEN
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
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
)
from rich.table import Table

import config
from netbox_client import NetBoxClient
from oui import OuiLookup

console = Console()
log = logging.getLogger(__name__)

_DEFAULT_TOKEN_FILE    = "CS_FEM_TOKEN"
_DEFAULT_BASE_URL      = "https://api.crowdstrike.com"
_DEFAULT_CONSOLE       = "https://falcon.crowdstrike.com"
_API_DELAY             = 0.05    # seconds between CrowdStrike calls
_HOSTS_SCROLL_LIMIT    = 5_000   # max AIDs per scroll page
_DETAILS_BATCH         = 100     # AIDs per GetDeviceDetails call
_ZTA_BATCH             = 100     # AIDs per ZTA get_assessments call
_DETECT_QUERY_LIMIT    = 5_000   # detection IDs per query_detects page
_DETECT_SUMMARY_BATCH  = 1_000   # detection IDs per get_detect_summaries call
_VULN_AID_BATCH        = 100     # AIDs per Spotlight FQL clause
_VULN_ID_BATCH         = 400     # vuln IDs per GetVulnerabilities call
_DISCOVER_SCROLL_LIMIT = 5_000   # max asset IDs per Discover scroll page
_DISCOVER_DETAILS_BATCH = 100    # asset IDs per GetAssets call

# CrowdStrike platform_name → NetBox platform slug
_CS_PLATFORM_MAP: dict[str, str] = {
    "Windows": "windows",
    "Linux":   "linux",
    "Mac":     "macos",
}

# CrowdStrike product_type_desc → NetBox device role slug
_CS_ROLE_MAP: dict[str, str] = {
    "Workstation":       getattr(config, "CS_WORKSTATION_ROLE_SLUG", "workstation"),
    "Server":            getattr(config, "CS_SERVER_ROLE_SLUG",      "server"),
    "Domain Controller": getattr(config, "CS_SERVER_ROLE_SLUG",      "server"),
}


# ---------------------------------------------------------------------------
# Credential helper
# ---------------------------------------------------------------------------

def _load_token_file(path: Optional[str]) -> dict:
    """
    Load and validate the CS_FEM_TOKEN file.

    Format — two lines, no quotes:
        <client_secret>
        <client_id (CID)>
    """
    token_path = Path(path) if path else Path(os.getcwd()) / _DEFAULT_TOKEN_FILE
    if not token_path.exists():
        console.print(
            f"[red]CS_FEM_TOKEN not found at:[/red] {token_path}\n"
            "Create the file with your CrowdStrike credentials:\n"
            "  Line 1: client secret\n"
            "  Line 2: client ID (CID)"
        )
        sys.exit(1)
    try:
        lines = [l.strip() for l in token_path.read_text().splitlines() if l.strip()]
        if len(lines) < 2:
            raise ValueError("Expected 2 lines (secret, CID)")
        creds = {"client_secret": lines[0], "client_id": lines[1]}
    except Exception as exc:
        console.print(f"[red]CS_FEM_TOKEN is invalid:[/red] {exc}")
        sys.exit(1)
    return creds


def _require_falconpy() -> None:
    console.print(
        "[red]crowdstrike-falconpy is not installed.[/red]\n"
        "Install it with:  pip install crowdstrike-falconpy"
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Falcon Hosts client
# ---------------------------------------------------------------------------

class FalconHostsClient:
    """Scroll all Falcon hosts and fetch their full device details."""

    def __init__(self, creds: dict) -> None:
        self.console_url = creds.get("console_url", _DEFAULT_CONSOLE).rstrip("/")
        try:
            from falconpy import Hosts
            self._hosts = Hosts(
                client_id=creds["client_id"],
                client_secret=creds["client_secret"],
                base_url=creds.get("base_url", _DEFAULT_BASE_URL),
            )
        except ImportError:
            _require_falconpy()

    def scroll_all(self, fql_filter: str = "") -> list[dict]:
        """Return full detail dicts for all hosts matching *fql_filter*."""
        all_aids: list[str] = []
        after: Optional[str] = None

        while True:
            kwargs: dict = {"limit": _HOSTS_SCROLL_LIMIT}
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
                    "GetDeviceDetails failed for batch %d (HTTP %s): %s",
                    i // _DETAILS_BATCH,
                    resp.get("status_code"),
                    (resp.get("body") or {}).get("errors"),
                )
            time.sleep(_API_DELAY)
        return details


# ---------------------------------------------------------------------------
# Spotlight (vulnerability) client
# ---------------------------------------------------------------------------

class SpotlightClient:
    """Fetch open Spotlight vulnerability and misconfiguration findings per AID."""

    _OPEN_STATUSES = "status:!['closed','expired']"

    def __init__(self, creds: dict) -> None:
        try:
            from falconpy import SpotlightVulnerabilities
            self._sv = SpotlightVulnerabilities(
                client_id=creds["client_id"],
                client_secret=creds["client_secret"],
                base_url=creds.get("base_url", _DEFAULT_BASE_URL),
            )
        except ImportError:
            _require_falconpy()

    def fetch_summaries(self, aids: list[str]) -> dict[str, dict]:
        """Return {aid: vulnerability_summary_dict} for every AID in *aids*."""
        summaries: dict[str, dict] = {a: _empty_vuln_summary() for a in aids}

        for i in range(0, len(aids), _VULN_AID_BATCH):
            batch = aids[i : i + _VULN_AID_BATCH]
            aid_list = ",".join(f"'{a}'" for a in batch)
            fql = f"aid:[{aid_list}]+{self._OPEN_STATUSES}"

            vuln_ids = self._scroll_vuln_ids(fql)
            for j in range(0, len(vuln_ids), _VULN_ID_BATCH):
                resp = self._sv.get_vulnerabilities(ids=vuln_ids[j : j + _VULN_ID_BATCH])
                if resp.get("status_code") == 200:
                    for vuln in (resp["body"].get("resources") or []):
                        aid = vuln.get("aid", "")
                        if aid in summaries:
                            _add_finding(summaries[aid], vuln)
                else:
                    log.error(
                        "GetVulnerabilities failed (HTTP %s): %s",
                        resp.get("status_code"),
                        (resp.get("body") or {}).get("errors"),
                    )
                time.sleep(_API_DELAY)

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for s in summaries.values():
            s["updated"] = now
        return summaries

    def _scroll_vuln_ids(self, fql: str) -> list[str]:
        ids: list[str] = []
        after: Optional[str] = None
        while True:
            kwargs: dict = {"filter": fql, "limit": _VULN_ID_BATCH}
            if after:
                kwargs["after"] = after
            resp = self._sv.query_vulnerabilities(**kwargs)
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


# ---------------------------------------------------------------------------
# Zero Trust Assessment client
# ---------------------------------------------------------------------------

class ZTAClient:
    """Fetch Zero Trust Assessment overall scores per AID."""

    def __init__(self, creds: dict) -> None:
        try:
            from falconpy import ZeroTrustAssessment
            self._zta = ZeroTrustAssessment(
                client_id=creds["client_id"],
                client_secret=creds["client_secret"],
                base_url=creds.get("base_url", _DEFAULT_BASE_URL),
            )
        except ImportError:
            _require_falconpy()

    def fetch_scores(self, aids: list[str]) -> dict[str, Optional[int]]:
        """
        Return {aid: overall_score} for every AID in *aids*.
        Value is None if the score is unavailable.
        Returns an empty dict if ZTA is not licensed (HTTP 403).
        """
        scores: dict[str, Optional[int]] = {}

        for i in range(0, len(aids), _ZTA_BATCH):
            batch = aids[i : i + _ZTA_BATCH]
            try:
                resp = self._zta.get_assessments(ids=batch)
            except Exception as exc:
                log.warning("ZTA get_assessments error (batch %d): %s", i // _ZTA_BATCH, exc)
                for aid in batch:
                    scores[aid] = None
                continue

            status = resp.get("status_code")
            if status == 403:
                log.warning(
                    "ZTA: access denied (HTTP 403) — Zero Trust Assessment may not be "
                    "licensed for this CID. ZTA scores will be skipped entirely."
                )
                return {}
            if status != 200:
                log.warning(
                    "ZTA: unexpected HTTP %s for batch %d — skipping batch",
                    status, i // _ZTA_BATCH,
                )
                for aid in batch:
                    scores[aid] = None
                time.sleep(_API_DELAY)
                continue

            for rec in (resp["body"].get("resources") or []):
                aid     = rec.get("aid", "")
                overall = (rec.get("assessment") or {}).get("overall")
                scores[aid] = int(overall) if overall is not None else None
            time.sleep(_API_DELAY)

        return scores


# ---------------------------------------------------------------------------
# Detections client
# ---------------------------------------------------------------------------

class DetectionsClient:
    """Count open / in-progress Falcon detections per AID."""

    # Only unresolved statuses count against a device
    _OPEN_FILTER = "status:!['closed','false_positive','ignored']"

    def __init__(self, creds: dict) -> None:
        try:
            from falconpy import Detects
            self._detects = Detects(
                client_id=creds["client_id"],
                client_secret=creds["client_secret"],
                base_url=creds.get("base_url", _DEFAULT_BASE_URL),
            )
        except ImportError:
            _require_falconpy()

    def fetch_counts(self, aids: list[str]) -> dict[str, int]:
        """
        Return {aid: open_detection_count} for every AID in *aids*.
        Returns an empty dict if detections are not accessible (HTTP 403).
        """
        counts: dict[str, int] = {a: 0 for a in aids}
        aid_set = set(aids)

        # Collect all open detection IDs in one paginated pass
        all_ids: list[str] = []
        offset = 0
        while True:
            resp = self._detects.query_detects(
                filter=self._OPEN_FILTER,
                limit=_DETECT_QUERY_LIMIT,
                offset=offset,
            )
            status = resp.get("status_code")
            if status == 403:
                log.warning(
                    "Detections: access denied (HTTP 403) — detection data will be skipped."
                )
                return {}
            if status != 200:
                log.warning("Detections: query_detects returned HTTP %s", status)
                break
            body  = resp["body"]
            batch = body.get("resources") or []
            total = (body.get("meta") or {}).get("pagination", {}).get("total", 0)
            all_ids.extend(batch)
            offset += len(batch)
            if not batch or offset >= total:
                break
            time.sleep(_API_DELAY)

        if not all_ids:
            return counts

        # Fetch summaries in batches to map detection → AID
        for i in range(0, len(all_ids), _DETECT_SUMMARY_BATCH):
            batch = all_ids[i : i + _DETECT_SUMMARY_BATCH]
            resp = self._detects.get_detect_summaries(body={"ids": batch})
            if resp.get("status_code") != 200:
                log.warning(
                    "Detections: get_detect_summaries HTTP %s for batch %d",
                    resp.get("status_code"),
                    i // _DETECT_SUMMARY_BATCH,
                )
                continue
            for det in (resp["body"].get("resources") or []):
                aid = (det.get("device") or {}).get("device_id", "")
                if aid in aid_set:
                    counts[aid] = counts.get(aid, 0) + 1
            time.sleep(_API_DELAY)

        return counts


# ---------------------------------------------------------------------------
# CrowdStrike Discover client  (unmanaged / unsupported assets)
# ---------------------------------------------------------------------------

class DiscoverClient:
    """
    Fetch unmanaged and unsupported (network device) assets from CrowdStrike Discover.

    Asset types returned by the Discover API:
      "managed"     — host running the Falcon sensor (handled via Hosts API)
      "unmanaged"   — endpoint/server seen by neighbouring sensors but without its own agent
      "unsupported" — network device (switch, router, firewall) that cannot run the agent

    This client fetches only "unmanaged" and "unsupported" assets so we never
    duplicate the work already done by FalconHostsClient.
    """

    # Only pull assets that have no sensor — managed assets are handled by
    # the Hosts API and would create ambiguous duplicate matches.
    _TYPE_FILTER = "asset_type:['unmanaged','unsupported']"

    def __init__(self, creds: dict) -> None:
        self.console_url = creds.get("console_url", _DEFAULT_CONSOLE).rstrip("/")
        try:
            from falconpy import Discover
            self._discover = Discover(
                client_id=creds["client_id"],
                client_secret=creds["client_secret"],
                base_url=creds.get("base_url", _DEFAULT_BASE_URL),
            )
        except ImportError:
            _require_falconpy()

    def scroll_all(self) -> list[dict]:
        """
        Return full asset detail dicts for all unmanaged/unsupported Discover assets.
        Returns an empty list if the Discover module is not licensed (HTTP 403).
        """
        all_ids: list[str] = []
        offset = 0

        while True:
            resp = self._discover.query_assets(
                filter=self._TYPE_FILTER,
                limit=_DISCOVER_SCROLL_LIMIT,
                offset=offset,
            )
            status = resp.get("status_code")
            if status == 403:
                log.warning(
                    "Discover: access denied (HTTP 403) — Falcon Discover may not be "
                    "licensed for this CID. Discover sync will be skipped."
                )
                return []
            if status != 200:
                log.error(
                    "Discover query_assets failed (HTTP %s): %s",
                    status,
                    (resp.get("body") or {}).get("errors"),
                )
                break

            body  = resp["body"]
            batch = body.get("resources") or []
            total = (body.get("meta") or {}).get("pagination", {}).get("total", 0)
            all_ids.extend(batch)
            offset += len(batch)
            if not batch or offset >= total:
                break
            time.sleep(_API_DELAY)

        log.info("CrowdStrike Discover: %d unmanaged/unsupported asset(s) found", len(all_ids))
        return self._fetch_details(all_ids)

    def asset_url(self, asset_id: str) -> str:
        return f"{self.console_url}/discover/assets/{asset_id}"

    def _fetch_details(self, ids: list[str]) -> list[dict]:
        details: list[dict] = []
        for i in range(0, len(ids), _DISCOVER_DETAILS_BATCH):
            batch = ids[i : i + _DISCOVER_DETAILS_BATCH]
            resp = self._discover.get_assets(ids=batch)
            if resp.get("status_code") == 200:
                details.extend(resp["body"].get("resources") or [])
            else:
                log.error(
                    "Discover get_assets failed for batch %d (HTTP %s)",
                    i // _DISCOVER_DETAILS_BATCH,
                    resp.get("status_code"),
                )
            time.sleep(_API_DELAY)
        return details


# ---------------------------------------------------------------------------
# Spotlight data helpers
# ---------------------------------------------------------------------------

def _empty_vuln_summary() -> dict:
    return {
        "updated":  "",
        "counts":   {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
        "findings": [],
    }


def _add_finding(summary: dict, vuln: dict) -> None:
    """Append one Spotlight finding to a summary dict in place."""
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
        finding["name"] = app_info.get("product_name") or vuln.get("id", "unknown")

    summary["findings"].append(finding)


# ---------------------------------------------------------------------------
# Host field extraction helpers
# ---------------------------------------------------------------------------

def _extract_prevention_policy(host: dict) -> str:
    """Return the name of the applied Prevention policy, or empty string."""
    for policy in (host.get("policies") or []):
        if policy.get("policy_type") == "prevention":
            return policy.get("policy_name") or policy.get("policy_id") or ""
    return ""


def _extract_group_names(host: dict) -> str:
    """Return comma-separated Falcon host group names."""
    names = [g.get("name", "") for g in (host.get("groups") or []) if g.get("name")]
    return ", ".join(names)


def _extract_network_interfaces(host: dict) -> list[dict]:
    """
    Return a normalised list of NIC dicts from host detail.
    Each entry: {name, mac, ip, prefix}.

    Reads host["network_interfaces"] when present; falls back to the
    primary mac_address / local_ip fields on the host root.
    """
    nics   = host.get("network_interfaces") or []
    result = []
    seen_macs: set[str] = set()

    for nic in nics:
        mac_raw = nic.get("mac_address") or nic.get("mac") or ""
        if not mac_raw:
            continue
        mac = _colon_mac(mac_raw)
        if mac in seen_macs:
            continue
        seen_macs.add(mac)
        result.append({
            "name":   (
                nic.get("interface_alias")
                or nic.get("name")
                or f"nic-{mac}"
            ),
            "mac":    mac,
            "ip":     nic.get("local_ip") or nic.get("ipv4") or "",
            "prefix": str(nic.get("network_prefix") or ""),
        })

    # Fallback: use the top-level mac_address / local_ip
    if not result:
        mac_raw = host.get("mac_address", "")
        if mac_raw:
            result.append({
                "name":   "Management",
                "mac":    _colon_mac(mac_raw),
                "ip":     host.get("local_ip", ""),
                "prefix": "",
            })

    return result


# ---------------------------------------------------------------------------
# Core sync orchestration
# ---------------------------------------------------------------------------

def run_sync(
    nb:           NetBoxClient,
    hosts_client: FalconHostsClient,
    spotlight:    Optional[SpotlightClient],
    zta:          Optional[ZTAClient],
    detections:   Optional[DetectionsClient],
    discover:     Optional[DiscoverClient],
    oui:          OuiLookup,
    fql_filter:   str,
    dry_run:      bool,
    sync_ips:     bool,
    overwrite_macs: bool,
) -> dict[str, int]:

    counts  = {"created": 0, "updated": 0, "unchanged": 0, "skipped": 0, "error": 0}
    results: list[dict] = []

    nb.ensure_crowdstrike_all_fields()

    console.print("Fetching hosts from CrowdStrike…")
    hosts = hosts_client.scroll_all(fql_filter)
    if not hosts:
        console.print("[yellow]No hosts returned from CrowdStrike.[/yellow]")
        return counts

    aids = [h["device_id"] for h in hosts if h.get("device_id")]

    # ---- Spotlight ----
    vuln_summaries: dict[str, dict] = {}
    if spotlight:
        console.print(f"Fetching vulnerability data for {len(aids)} host(s) from Spotlight…")
        vuln_summaries = spotlight.fetch_summaries(aids)

    # ---- ZTA ----
    zta_scores: dict[str, Optional[int]] = {}
    if zta:
        console.print(f"Fetching ZTA scores for {len(aids)} host(s)…")
        zta_scores = zta.fetch_scores(aids)
        if not zta_scores:
            console.print("[yellow]ZTA scores unavailable — skipping.[/yellow]")

    # ---- Detections ----
    detect_counts: dict[str, int] = {}
    if detections:
        console.print(f"Fetching open detection counts for {len(aids)} host(s)…")
        detect_counts = detections.fetch_counts(aids)
        if not detect_counts:
            console.print("[yellow]Detection data unavailable — skipping.[/yellow]")

    # ---- Per-host sync ----
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
                    host=host,
                    nb=nb,
                    hosts_client=hosts_client,
                    oui=oui,
                    vuln_summary=vuln_summaries.get(aid),
                    zta_score=zta_scores.get(aid),
                    detect_count=detect_counts.get(aid),
                    dry_run=dry_run,
                    sync_ips=sync_ips,
                    overwrite_macs=overwrite_macs,
                )
                counts[action] += 1
                if action in ("created", "updated"):
                    c = vuln_summaries.get(aid, {}).get("counts", {})
                    zta_val     = zta_scores.get(aid)
                    detect_val  = detect_counts.get(aid)
                    results.append({
                        "hostname":    host.get("hostname", ""),
                        "aid":         aid,
                        "action":      action,
                        "local_ip":    host.get("local_ip", ""),
                        "external_ip": host.get("external_ip", ""),
                        "vulns": (
                            f"C:{c.get('critical',0)} H:{c.get('high',0)} "
                            f"M:{c.get('medium',0)} L:{c.get('low',0)}"
                        ),
                        "zta":      "" if zta_val is None else str(zta_val),
                        "detects":  "" if detect_val is None else str(detect_val),
                    })
            except Exception as exc:
                log.error("Failed to sync host %s: %s", host.get("hostname", "?"), exc)
                counts["error"] += 1

    _print_results(results, dry_run)

    # ---- Discover pass: match agentless / network-device assets ----
    if discover:
        console.print("\n[bold]Discover pass (unmanaged / network devices)…[/bold]")
        run_discover_sync(nb, discover, oui, dry_run)

    return counts


# ---------------------------------------------------------------------------
# Per-host sync
# ---------------------------------------------------------------------------

def _sync_host(
    host:          dict,
    nb:            NetBoxClient,
    hosts_client:  FalconHostsClient,
    oui:           OuiLookup,
    vuln_summary:  Optional[dict],
    zta_score:     Optional[int],
    detect_count:  Optional[int],
    dry_run:       bool,
    sync_ips:      bool,
    overwrite_macs: bool,
) -> str:
    """
    Sync one CrowdStrike host to NetBox.
    Returns "created", "updated", "unchanged", or "skipped".
    """
    aid      = host.get("device_id", "")
    hostname = host.get("hostname", "").strip()
    local_ip = host.get("local_ip", "")
    mac_raw  = host.get("mac_address", "")
    mac      = _colon_mac(mac_raw) if mac_raw else ""

    if not hostname:
        log.debug("Skipping host with no hostname (AID %s)", aid)
        return "skipped"

    cs_fields = _build_cs_fields(host, hosts_client, vuln_summary, zta_score, detect_count)

    # Find existing NetBox device using a cascading set of strategies:
    #
    #  1. crowdstrike_aid custom field  — fastest, unambiguous
    #  2. Exact hostname match          — covers most managed endpoints
    #  3. FQDN: hostname.machine_domain — covers DNS-named / domain-joined devices
    #  4. Primary MAC address           — covers devices seen via SNMP/ARP
    #  5. Primary local IP              — covers routable internal devices
    #  6. External/egress IP            — covers internet-facing services where the
    #                                     NetBox IP is the public address
    #  7. All NIC IPs from Falcon       — covers multi-homed hosts and cases where
    #                                     NetBox holds a secondary interface IP
    domain = host.get("machine_domain", "")
    fqdn   = f"{hostname}.{domain}" if domain else ""

    nic_ips = [
        n["ip"] for n in _extract_network_interfaces(host)
        if n.get("ip") and n["ip"] != local_ip
    ]
    external_ip = host.get("external_ip", "")

    nb_device = (
        (nb.get_device_by_crowdstrike_aid(aid) if aid else None)
        or nb.get_device_by_name(hostname)
        or (nb.get_device_by_fqdn(fqdn) if fqdn else None)
        or (nb.get_device_by_mac(mac) if mac else None)
        or (nb.get_device_by_ip(local_ip) if local_ip else None)
        or (nb.get_device_by_ip(external_ip) if external_ip else None)
        or (nb.get_device_by_any_ip(nic_ips) if nic_ips else None)
    )

    if nb_device is None:
        payload = _build_device_payload(host, nb)
        if payload is None:
            return "skipped"
        payload["tags"] = [{"slug": "crowdstrike"}]
        log.info("CREATE device: %s (AID %s)", hostname, aid)
        if not dry_run:
            nb_device = nb.nb.dcim.devices.create(payload)
            if nb_device:
                nb_device.update({"custom_fields": cs_fields})
                _sync_interfaces(nb_device, host, oui, nb, dry_run, sync_ips, overwrite_macs, hosts_client)
        return "created"

    # --- Update path ---
    updates   = _compute_cf_updates(nb_device, cs_fields)
    tag_patch = _compute_tag_patch(nb_device)

    if updates or tag_patch:
        log.info(
            "UPDATE device: %s — fields: %s%s",
            hostname,
            list(updates.keys()),
            " + tags" if tag_patch else "",
        )
        if not dry_run:
            if updates:
                nb_device.update({"custom_fields": updates})
            if tag_patch:
                nb_device.update(tag_patch)
        _sync_interfaces(nb_device, host, oui, nb, dry_run, sync_ips, overwrite_macs, hosts_client)
        return "updated"

    # Even if device fields are unchanged, keep interfaces + MACs fresh
    _sync_interfaces(nb_device, host, oui, nb, dry_run, sync_ips, overwrite_macs, hosts_client)
    return "unchanged"


def _build_cs_fields(
    host:         dict,
    hosts_client: FalconHostsClient,
    vuln_summary: Optional[dict],
    zta_score:    Optional[int],
    detect_count: Optional[int],
) -> dict:
    """Assemble the full custom-fields payload for a CrowdStrike host."""
    aid = host.get("device_id", "")
    rfm = host.get("reduced_functionality_mode", "")

    fields: dict = {
        "crowdstrike_aid":          aid,
        "last_public_ip":           host.get("external_ip", "") or "",
        "cs_falcon_url":            hosts_client.device_url(aid) if aid else "",
        "cs_first_seen":            host.get("first_seen", "") or "",
        "cs_last_seen":             host.get("last_seen", "") or "",
        "cs_sensor_version":        host.get("agent_version", "") or "",
        "cs_os_version":            host.get("os_version", "") or "",
        "cs_containment_status":    host.get("status", "") or "",
        "cs_reduced_functionality": rfm.lower() == "yes" if isinstance(rfm, str) else bool(rfm),
        "cs_prevention_policy":     _extract_prevention_policy(host),
        "cs_groups":                _extract_group_names(host),
        "cs_chassis_type":          host.get("chassis_type", "") or "",
    }

    # Only include optional scored/counted fields when data is available
    if zta_score is not None:
        fields["cs_zta_score"] = zta_score
    if detect_count is not None:
        fields["cs_active_detections"] = detect_count
    if vuln_summary is not None:
        fields["vulnerabilities"] = vuln_summary

    return fields


def _compute_cf_updates(nb_device: object, desired: dict) -> dict:
    """Return only fields that differ from the current NetBox custom_fields values."""
    existing = getattr(nb_device, "custom_fields", {}) or {}
    updates: dict = {}
    for key, new_val in desired.items():
        old_val = existing.get(key)
        # Treat None and "" as equivalent for text fields to avoid spurious updates
        if isinstance(new_val, str) and (old_val is None):
            old_val = ""
        # Vulnerability data changes every run; always refresh it
        if key == "vulnerabilities":
            updates[key] = new_val
            continue
        if old_val != new_val:
            updates[key] = new_val
    return updates


def _compute_tag_patch(nb_device: object) -> dict:
    existing_tags = [t.slug for t in (getattr(nb_device, "tags", None) or [])]
    if "crowdstrike" not in existing_tags:
        return {"tags": [{"slug": s} for s in existing_tags] + [{"slug": "crowdstrike"}]}
    return {}


# ---------------------------------------------------------------------------
# Interface + MAC + IP sync
# ---------------------------------------------------------------------------

def _sync_interfaces(
    nb_device:      object,
    host:           dict,
    oui:            OuiLookup,
    nb:             NetBoxClient,
    dry_run:        bool,
    sync_ips:       bool,
    overwrite_macs: bool,
    hosts_client:   FalconHostsClient,
) -> None:
    """Create/update interfaces, MACs, and (optionally) IP addresses from NIC data."""
    nics      = _extract_network_interfaces(host)
    device_id = nb_device.id
    aid       = host.get("device_id", "")
    falcon_url = hosts_client.device_url(aid) if aid else ""

    for nic in nics:
        # Get or create interface
        iface = nb.get_interface(device_id, nic["name"])
        if iface is None:
            log.info("CREATE interface: %s on device id=%s", nic["name"], device_id)
            if not dry_run:
                iface = nb.nb.dcim.interfaces.create({
                    "device": device_id,
                    "name":   nic["name"],
                    "type":   "virtual",
                })
        if iface is None:
            continue  # dry-run: interface doesn't exist yet, skip MAC/IP sync

        # MAC address
        if nic["mac"]:
            vendor_map = {nic["mac"]: oui.lookup(nic["mac"])}
            nb.sync_interface_macs(
                iface.id, nic["name"],
                {nic["mac"]},
                vendor_map,
            )
            # Set external_url on the MAC object
            if falcon_url and not dry_run:
                _set_mac_external_url(nb, nic["mac"], iface.id, falcon_url, overwrite_macs)

        # IP address (opt-in)
        if sync_ips and nic["ip"] and not dry_run:
            _sync_ip_address(nb, nic["ip"], nic["prefix"], iface.id)


def _set_mac_external_url(
    nb:        NetBoxClient,
    mac:       str,
    iface_id:  int,
    url:       str,
    overwrite: bool,
) -> None:
    """Write *url* into the external_url custom field of the MAC address object."""
    try:
        objs = list(nb.nb.dcim.mac_addresses.filter(
            assigned_object_type="dcim.interface",
            assigned_object_id=iface_id,
            mac_address=mac,
        ))
        if not objs:
            return
        obj      = objs[0]
        existing = (getattr(obj, "custom_fields", {}) or {}).get("external_url") or ""
        if overwrite or not existing:
            obj.update({"custom_fields": {"external_url": url}})
    except Exception as exc:
        log.debug("Could not set external_url on MAC %s: %s", mac, exc)


def _sync_ip_address(
    nb:      NetBoxClient,
    ip:      str,
    prefix:  str,
    iface_id: int,
) -> None:
    """Create an IPAM IP address linked to *iface_id* if it does not already exist."""
    cidr = f"{ip}/{prefix}" if prefix else ip
    try:
        if not nb.nb.ipam.ip_addresses.get(address=cidr):
            nb.nb.ipam.ip_addresses.create({
                "address":              cidr,
                "assigned_object_type": "dcim.interface",
                "assigned_object_id":   iface_id,
                "status":               "active",
            })
            log.info("CREATE ip_address: %s on interface id=%s", cidr, iface_id)
    except Exception as exc:
        log.debug("Could not sync IP %s: %s", cidr, exc)


# ---------------------------------------------------------------------------
# Device creation helpers
# ---------------------------------------------------------------------------

_CS_PLATFORM_CACHE: dict[str, object] = {}


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
        platform    = _get_or_create_platform(nb, platform_cs)
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


def _get_or_create_platform(nb: NetBoxClient, platform_name: str) -> Optional[object]:
    slug = _CS_PLATFORM_MAP.get(platform_name, "unknown")
    if slug in _CS_PLATFORM_CACHE:
        return _CS_PLATFORM_CACHE[slug]
    plat = nb.nb.dcim.platforms.get(slug=slug)
    if not plat and slug != "unknown":
        log.info("Creating platform: %s", slug)
        try:
            plat = nb.nb.dcim.platforms.create({"name": platform_name, "slug": slug})
        except Exception as exc:
            log.warning("Could not create platform %s: %s", slug, exc)
    _CS_PLATFORM_CACHE[slug] = plat
    return plat


# ---------------------------------------------------------------------------
# Discover sync  (unmanaged / unsupported / network-device assets)
# ---------------------------------------------------------------------------

def run_discover_sync(
    nb:       NetBoxClient,
    discover: DiscoverClient,
    oui:      OuiLookup,
    dry_run:  bool,
) -> dict[str, int]:
    """
    Match CrowdStrike Discover assets (unmanaged/unsupported) to existing
    NetBox devices and write what data is available.

    This pass NEVER creates new NetBox devices — Discover assets are matched
    only against devices that already exist.  Network gear (unsupported) and
    agentless workstations (unmanaged) are matched by:
      1. cs_discover_id custom field (idempotent on re-runs)
      2. Hostname
      3. Any local IP address
      4. Any MAC address

    Fields written on a match:
      cs_discover_id    — Discover asset ID (stable cross-run reference)
      cs_falcon_url     — link to the Discover asset page in the Falcon console
      cs_first_seen     — first observed timestamp
      cs_last_seen      — last observed timestamp
      cs_chassis_type   — asset_type label (Unmanaged / Unsupported / Network Device)
      crowdstrike tag   — applied even without a sensor AID
    """
    counts: dict[str, int] = {"matched": 0, "unmatched": 0, "unchanged": 0, "error": 0}

    console.print("Fetching Discover assets (unmanaged / network devices)…")
    assets = discover.scroll_all()
    if not assets:
        return counts

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Matching Discover assets to NetBox…", total=len(assets))

        for asset in assets:
            progress.advance(task)
            try:
                result = _sync_discover_asset(asset, nb, discover, oui, dry_run)
                counts[result] += 1
            except Exception as exc:
                log.error(
                    "Failed to process Discover asset %s: %s",
                    asset.get("id", "?"), exc,
                )
                counts["error"] += 1

    console.print(
        f"  Discover: [green]{counts['matched']} matched[/green]  "
        f"[dim]{counts['unchanged']} unchanged  "
        f"{counts['unmatched']} unmatched[/dim]"
        + (f"  [red]{counts['error']} error(s)[/red]" if counts["error"] else "")
    )
    return counts


def _sync_discover_asset(
    asset:    dict,
    nb:       NetBoxClient,
    discover: DiscoverClient,
    oui:      OuiLookup,
    dry_run:  bool,
) -> str:
    """
    Match one Discover asset to a NetBox device and update it.
    Returns "matched", "unchanged", or "unmatched".
    """
    asset_id   = asset.get("id", "")
    hostname   = (asset.get("hostname") or "").strip()
    asset_type = asset.get("asset_type", "")    # "unmanaged" | "unsupported"

    # Collect all IPs and MACs reported for this asset
    local_ips = asset.get("local_ip_addresses") or []
    # Newer API versions may nest IPs inside network_interfaces
    for nic in (asset.get("network_interfaces") or []):
        ip = nic.get("local_ip") or nic.get("ipv4") or ""
        if ip and ip not in local_ips:
            local_ips.append(ip)

    raw_macs = asset.get("mac_addresses") or []
    macs = [_colon_mac(m) for m in raw_macs if m]

    # ---- Match to existing NetBox device ----
    nb_device = (
        (nb.get_device_by_discover_id(asset_id) if asset_id else None)
        or (nb.get_device_by_name(hostname) if hostname else None)
        or nb.get_device_by_any_ip(local_ips)
        or next((nb.get_device_by_mac(m) for m in macs if nb.get_device_by_mac(m)), None)
    )

    if nb_device is None:
        log.debug(
            "Discover asset %s (%s) — no matching NetBox device found (type=%s)",
            asset_id, hostname or "<no hostname>", asset_type,
        )
        return "unmatched"

    # ---- Skip if this device already has a sensor AID — Hosts API owns it ----
    existing_cf = getattr(nb_device, "custom_fields", {}) or {}
    if existing_cf.get("crowdstrike_aid"):
        log.debug(
            "Discover asset %s matched device %s which already has AID — skipping",
            asset_id, nb_device,
        )
        return "unchanged"

    # ---- Build the update payload ----
    # Map asset_type to a human-readable chassis label
    chassis_label = {
        "unmanaged":   "Unmanaged Endpoint",
        "unsupported": "Network Device (No Agent)",
    }.get(asset_type, asset_type.replace("_", " ").title())

    desired: dict = {
        "cs_discover_id": asset_id,
        "cs_falcon_url":  discover.asset_url(asset_id),
        "cs_first_seen":  asset.get("first_seen_timestamp") or asset.get("first_seen") or "",
        "cs_last_seen":   asset.get("last_seen_timestamp")  or asset.get("last_seen")  or "",
        "cs_chassis_type": chassis_label,
    }
    # Normalise: treat None as "" for comparison
    updates = {
        k: v for k, v in desired.items()
        if (existing_cf.get(k) or "") != (v or "")
    }
    tag_patch = _compute_tag_patch(nb_device)

    if not updates and not tag_patch:
        return "unchanged"

    log.info(
        "UPDATE device %s from Discover asset %s — %s",
        getattr(nb_device, "name", nb_device),
        asset_id,
        list(updates.keys()) + (["tags"] if tag_patch else []),
    )
    if not dry_run:
        if updates:
            nb_device.update({"custom_fields": updates})
        if tag_patch:
            nb_device.update(tag_patch)

        # Sync any MACs we learned from Discover onto the device
        _sync_discover_macs(nb_device, macs, oui, nb)

    return "matched"


def _sync_discover_macs(
    nb_device: object,
    macs:      list[str],
    oui:       OuiLookup,
    nb:        NetBoxClient,
) -> None:
    """
    For each MAC reported by Discover that isn't already in NetBox,
    ensure the device has a "Management" interface and attach the MAC.
    """
    device_id = nb_device.id
    for mac in macs:
        if not mac:
            continue
        iface = nb.get_interface(device_id, "Management")
        if iface is None:
            try:
                iface = nb.nb.dcim.interfaces.create({
                    "device": device_id,
                    "name":   "Management",
                    "type":   "virtual",
                })
            except Exception as exc:
                log.debug("Could not create Management interface for %s: %s", nb_device, exc)
                continue
        nb.sync_interface_macs(iface.id, "Management", {mac}, {mac: oui.lookup(mac)})
        break   # Discover usually only has one reliable MAC; stop after the first


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _print_results(results: list[dict], dry_run: bool) -> None:
    if not results:
        return

    t = Table(
        title="CrowdStrike sync results" + (" [dry-run]" if dry_run else ""),
        show_lines=True,
    )
    t.add_column("Hostname",     style="bold")
    t.add_column("Action")
    t.add_column("Local IP",     style="cyan")
    t.add_column("External IP",  style="cyan")
    t.add_column("Vulns",        justify="right", style="dim")
    t.add_column("ZTA",          justify="right")
    t.add_column("Detections",   justify="right")
    t.add_column("AID",          style="dim")

    for r in results:
        action_colour = "green" if r["action"] == "created" else "yellow"

        zta_val = r.get("zta", "")
        if zta_val:
            score = int(zta_val)
            zta_colour = "green" if score >= 70 else ("yellow" if score >= 40 else "red")
            zta_cell = f"[{zta_colour}]{zta_val}[/{zta_colour}]"
        else:
            zta_cell = ""

        det_val = r.get("detects", "")
        if det_val:
            det_colour = "red" if int(det_val) > 0 else "green"
            det_cell = f"[{det_colour}]{det_val}[/{det_colour}]"
        else:
            det_cell = ""

        t.add_row(
            r["hostname"],
            f"[{action_colour}]{r['action']}[/{action_colour}]",
            r["local_ip"],
            r["external_ip"],
            r["vulns"],
            zta_cell,
            det_cell,
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
              help="CrowdStrike FQL filter (e.g. \"tags:'corp'\"). Default: all hosts.")
@click.option("--dry-run",        is_flag=True,
              help="Query all sources but write nothing to NetBox.")
@click.option("--no-vulns",       is_flag=True,
              help="Skip Spotlight vulnerability data.")
@click.option("--no-zta",         is_flag=True,
              help="Skip Zero Trust Assessment scores.")
@click.option("--no-detections",  is_flag=True,
              help="Skip active detection counts.")
@click.option("--no-discover",    is_flag=True,
              help="Skip the Falcon Discover pass for unmanaged / network-device assets.")
@click.option("--sync-ips",       is_flag=True,
              help="Create IPAM IP addresses from NIC data (skipped by default).")
@click.option("--overwrite-macs", is_flag=True,
              help="Overwrite existing MAC external_url fields even if already set.")
@click.option("--verbose", "-v",  is_flag=True)
def cli(
    token_file, fql_filter, dry_run,
    no_vulns, no_zta, no_detections, no_discover,
    sync_ips, overwrite_macs, verbose,
):
    """
    Comprehensive CrowdStrike Falcon → NetBox sync.

    Syncs host metadata, Spotlight vulnerabilities, ZTA scores, detection counts,
    and all network interfaces (with MACs and optionally IPs) into NetBox.
    """
    logging.basicConfig(
        format="%(levelname)-8s %(name)s: %(message)s",
        level=logging.DEBUG if verbose else logging.INFO,
    )

    creds = _load_token_file(token_file)
    nb    = NetBoxClient(config.NETBOX_URL, config.NETBOX_TOKEN, dry_run=dry_run)
    oui   = OuiLookup.from_config()

    hosts_client = FalconHostsClient(creds)
    spotlight    = None if no_vulns      else SpotlightClient(creds)
    zta          = None if no_zta        else ZTAClient(creds)
    detections   = None if no_detections else DetectionsClient(creds)
    discover     = None if no_discover   else DiscoverClient(creds)

    if dry_run:
        console.print("[yellow]Dry-run mode — no changes will be written to NetBox.[/yellow]")

    counts = run_sync(
        nb=nb,
        hosts_client=hosts_client,
        spotlight=spotlight,
        zta=zta,
        detections=detections,
        discover=discover,
        oui=oui,
        fql_filter=fql_filter,
        dry_run=dry_run,
        sync_ips=sync_ips,
        overwrite_macs=overwrite_macs,
    )

    console.print(
        f"\n[bold]Done.[/bold]  "
        f"[green]{counts['created']} created[/green]  "
        f"[yellow]{counts['updated']} updated[/yellow]  "
        f"[dim]{counts['unchanged']} unchanged  "
        f"{counts['skipped']} skipped[/dim]"
        + (f"  [red]{counts['error']} error(s)[/red]" if counts["error"] else "")
    )


# ---------------------------------------------------------------------------
# MAC format helpers
# ---------------------------------------------------------------------------

def _colon_mac(mac: str) -> str:
    """Normalise any MAC format to lowercase colon-separated."""
    digits = mac.lower().replace("-", "").replace(":", "").replace(".", "")
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


if __name__ == "__main__":
    cli()
