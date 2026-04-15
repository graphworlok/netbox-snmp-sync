#!/usr/bin/env python3
"""
netbox-snmp-sync — CLI entry point

Usage examples
--------------
# Drift report only (no changes written to NetBox)
python main.py drift 192.168.1.1 10.0.0.1

# Sync seed devices AND auto-discover neighbours up to 2 hops
python main.py sync --depth 2 192.168.1.1

# Dry-run sync (shows what would change, writes nothing)
python main.py sync --dry-run 192.168.1.1

# Load IPs from a file (one per line)
python main.py drift --file devices.txt

# Suppress neighbour discovery
python main.py drift --no-discover 192.168.1.1
"""

from __future__ import annotations

import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import json

import click
from rich.console import Console
from rich.table import Table
from rich import print as rprint

import config
import discovery
import sync as sync_mod
from models import ChangeKind, DriftReport
from netbox_client import NetBoxClient

console = Console()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(levelname)-8s %(name)s: %(message)s",
        level=level,
    )
    # Suppress noisy pysnmp internals unless verbose
    if not verbose:
        logging.getLogger("pysnmp").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Shared options
# ---------------------------------------------------------------------------

_common_options = [
    click.argument("ips", nargs=-1, metavar="IP..."),
    click.option("--file", "-f", "ip_file", type=click.Path(exists=True),
                 help="File with one device IP per line."),
    click.option("--depth", default=config.DISCOVERY_MAX_DEPTH,
                 show_default=True,
                 help="Max neighbour-discovery hops (0 = seed only)."),
    click.option("--no-discover", is_flag=True,
                 help="Disable CDP/LLDP-driven auto-discovery."),
    click.option("--slow", is_flag=True,
                 help=(
                     f"Use high-latency SNMP settings "
                     f"(timeout={config.SNMP_TIMEOUT_SLOW}s, "
                     f"retries={config.SNMP_RETRIES_SLOW}) "
                     f"for distant/WAN hosts."
                 )),
    click.option("--cs-refresh", is_flag=True,
                 help="Force a full re-fetch of CrowdStrike asset data, ignoring the local cache."),
    click.option("--verbose", "-v", is_flag=True),
]


def _add_options(options):
    def decorator(f):
        for opt in reversed(options):
            f = opt(f)
        return f
    return decorator


def _collect_seed_ips(ips: tuple[str, ...], ip_file: str | None) -> list[str]:
    result = list(ips)
    if ip_file:
        for line in Path(ip_file).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                result.append(line)
    if not result:
        console.print("[red]No device IPs provided.[/red]")
        sys.exit(1)
    return result


# ---------------------------------------------------------------------------
# Parallel drift detection
# ---------------------------------------------------------------------------

def _parallel_drift(
    devices: list,
    dry_run: bool = False,
) -> list[DriftReport]:
    """
    Run drift_device() for every device concurrently.

    Each worker gets its own NetBoxClient (requests Session is not
    thread-safe for concurrent use).  Results are returned in the same
    order as *devices*.
    """
    workers = max(1, config.NETBOX_WORKERS)
    reports: list[DriftReport] = [None] * len(devices)  # type: ignore[list-item]

    def _run(idx: int, device) -> tuple[int, DriftReport]:
        nb = NetBoxClient(config.NETBOX_URL, config.NETBOX_TOKEN, dry_run=dry_run)
        return idx, sync_mod.drift_device(device, nb)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_run, i, d): i for i, d in enumerate(devices)}
        for future in as_completed(futures):
            try:
                idx, report = future.result()
                reports[idx] = report
            except Exception as exc:
                i = futures[future]
                log.error("Drift detection failed for %s: %s",
                          devices[i].display_name, exc)

    return [r for r in reports if r is not None]


# ---------------------------------------------------------------------------
# Integration status
# ---------------------------------------------------------------------------

def _print_integration_status() -> None:
    """Print a status table showing which integrations are configured and available."""
    from pathlib import Path as _Path

    t = Table(title="Integration status", show_lines=True)
    t.add_column("Integration")
    t.add_column("Status")
    t.add_column("Detail")

    # --- NetBox ---
    nb_url   = getattr(config, "NETBOX_URL",   "")
    nb_token = getattr(config, "NETBOX_TOKEN", "")
    placeholder_url   = not nb_url   or nb_url   == "https://netbox.example.com"
    placeholder_token = not nb_token or nb_token == "YOUR_NETBOX_API_TOKEN"
    if placeholder_url or placeholder_token:
        t.add_row("NetBox", "[red]NOT CONFIGURED[/red]",
                  "Set NETBOX_URL and NETBOX_TOKEN in config.py")
    else:
        t.add_row("NetBox", "[green]configured[/green]", nb_url)

    # --- SNMP credentials ---
    creds = getattr(config, "SNMP_CREDENTIALS", [])
    real_creds = [
        c for c in creds
        if c.get("version") == 2 and c.get("community") not in ("public", "private")
        or c.get("version") == 3 and c.get("auth_key", "") not in ("", "YOUR_AUTH_KEY")
    ]
    v2 = sum(1 for c in creds if c.get("version") == 2)
    v3 = sum(1 for c in creds if c.get("version") == 3)
    if not creds:
        t.add_row("SNMP", "[red]NOT CONFIGURED[/red]", "No credentials in SNMP_CREDENTIALS")
    elif not real_creds and creds:
        t.add_row("SNMP", "[yellow]default only[/yellow]",
                  f"{v2} v2c (public/private), {v3} v3 placeholder — update config.py")
    else:
        t.add_row("SNMP", "[green]configured[/green]",
                  f"{v2} v2c credential(s), {v3} v3 credential(s)")

    # --- OUI database ---
    oui_file = getattr(config, "OUI_FILE", "")
    if isinstance(oui_file, (list, tuple)):
        oui_paths = [_Path(p) for p in oui_file if p]
    else:
        oui_paths = [_Path(oui_file)] if oui_file else []
    missing = [str(p) for p in oui_paths if not p.exists()]
    if not oui_paths:
        t.add_row("OUI lookup", "[yellow]disabled[/yellow]",
                  "Set OUI_FILE in config.py to enable vendor resolution")
    elif missing:
        t.add_row("OUI lookup", "[red]file(s) missing[/red]", ", ".join(missing))
    else:
        t.add_row("OUI lookup", "[green]configured[/green]",
                  ", ".join(str(p) for p in oui_paths))

    # --- CrowdStrike ---
    cs_token_path = _Path(getattr(config, "CS_FEM_TOKEN_FILE", "CS_FEM_TOKEN"))
    cs_pkg = False
    try:
        import falconpy  # noqa: F401
        cs_pkg = True
    except ImportError:
        pass
    if not cs_pkg and not cs_token_path.exists():
        t.add_row("CrowdStrike", "[dim]not configured[/dim]",
                  "Install crowdstrike-falconpy and create CS_FEM_TOKEN to enable")
    elif not cs_pkg:
        t.add_row("CrowdStrike", "[yellow]package missing[/yellow]",
                  "pip install crowdstrike-falconpy")
    elif not cs_token_path.exists():
        t.add_row("CrowdStrike", "[yellow]token missing[/yellow]",
                  f"{cs_token_path} not found")
    else:
        try:
            lines = [l.strip() for l in cs_token_path.read_text().splitlines() if l.strip()]
            if len(lines) >= 2:
                t.add_row("CrowdStrike", "[green]configured[/green]",
                          f"{cs_token_path}")
            else:
                t.add_row("CrowdStrike", "[red]invalid token file[/red]",
                          "Expected 2 lines: client_secret on line 1, client_id on line 2")
        except Exception as exc:
            t.add_row("CrowdStrike", "[red]token file error[/red]", str(exc))

    # --- Cisco Meraki ---
    meraki_key = getattr(config, "MERAKI_API_KEY", "")
    meraki_pkg = False
    try:
        import meraki  # noqa: F401
        meraki_pkg = True
    except ImportError:
        pass
    if not meraki_key and not meraki_pkg:
        t.add_row("Meraki", "[dim]not configured[/dim]",
                  "Set MERAKI_API_KEY in config.py and install meraki SDK to enable")
    elif not meraki_pkg:
        t.add_row("Meraki", "[yellow]package missing[/yellow]",
                  "pip install meraki")
    elif not meraki_key:
        t.add_row("Meraki", "[yellow]no API key[/yellow]",
                  "Set MERAKI_API_KEY in config.py")
    else:
        t.add_row("Meraki", "[green]configured[/green]", "API key set")

    console.print(t)
    console.print()


# ---------------------------------------------------------------------------
# CrowdStrike asset cache helpers
# ---------------------------------------------------------------------------

def _cs_creds() -> Optional[dict]:
    """Load and return CS credentials from token file, or None if unavailable."""
    from pathlib import Path as _Path
    token_path = _Path(getattr(config, "CS_FEM_TOKEN_FILE", "CS_FEM_TOKEN"))
    if not token_path.exists():
        log.debug("CS: token file not found at %s", token_path)
        return None
    try:
        lines = [l.strip() for l in token_path.read_text().splitlines() if l.strip()]
        if len(lines) < 2:
            raise ValueError(f"Expected 2 lines, got {len(lines)}")
        log.debug("CS: token file loaded from %s  client_id=%s…", token_path, lines[1][:8])
        return {"client_secret": lines[0], "client_id": lines[1]}
    except Exception as exc:
        log.warning("CS: could not read token file %s: %s", token_path, exc)
        return None


def _cs_cache_path() -> Optional["Path"]:
    from pathlib import Path as _Path
    p = getattr(config, "CS_CACHE_FILE", "cs_asset_cache.json")
    return _Path(p) if p else None


def _cs_cache_is_fresh() -> bool:
    """Return True if the cache file exists and is younger than CS_CACHE_MAX_AGE."""
    import time as _time
    path = _cs_cache_path()
    if not path or not path.exists():
        return False
    age = _time.time() - path.stat().st_mtime
    max_age = getattr(config, "CS_CACHE_MAX_AGE", 86400)
    if age < max_age:
        log.debug("CS cache: fresh (age %.0fs / max %ds) — %s", age, max_age, path)
        return True
    log.debug("CS cache: stale (age %.0fs / max %ds) — will refresh", age, max_age)
    return False


def _cs_cache_load() -> Optional[dict]:
    """Load and return the raw cache dict, or None on failure."""
    path = _cs_cache_path()
    if not path or not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        log.debug("CS cache: loaded %d Hosts + %d Discover records from %s",
                  len(data.get("hosts", [])),
                  len(data.get("discover_hosts", [])),
                  path)
        return data
    except Exception as exc:
        log.warning("CS cache: failed to load %s: %s", path, exc)
        return None


def _cs_cache_save(data: dict) -> None:
    """Write the raw asset data dict to the cache file."""
    import time as _time
    path = _cs_cache_path()
    if not path:
        return
    data["cached_at"] = _time.time()
    try:
        path.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
        total = sum(len(v) for k, v in data.items() if isinstance(v, list))
        log.info("CS cache: saved %d total records to %s", total, path)
    except Exception as exc:
        log.warning("CS cache: could not write %s: %s", path, exc)


def _cs_fetch_assets(creds: dict) -> dict:
    """
    Fetch all raw asset records from CrowdStrike APIs.

    Returns a dict:
      {
        "hosts":          [...],   # Hosts API (sensor-managed)
        "discover_hosts": [...],   # Discover query_hosts (unmanaged)
      }

    Pagination bug fix: stop when len(fetched_ids) >= declared total,
    not just when a page returns fewer than page_limit items (the API
    sometimes returns exactly page_limit on the final page).
    """
    console_url = "https://falcon.crowdstrike.com"
    result: dict[str, list] = {"hosts": [], "discover_hosts": []}

    try:
        from falconpy import Hosts, Discover
    except ImportError:
        log.debug("CS: falconpy not installed")
        return result

    def _scroll_ids(label: str, query_fn, page_limit: int = 100) -> list[str]:
        """Page through a query endpoint, return all IDs. Respects declared total."""
        if query_fn is None:
            log.debug("CS %s: query function not available", label)
            return []
        all_ids: list[str] = []
        offset = 0
        page   = 0
        total  = None   # populated from first response
        while True:
            resp   = query_fn(limit=page_limit, offset=offset)
            status = resp.get("status_code")
            if status == 403:
                log.info("CS %s: HTTP 403 — scope not available for this token", label)
                return all_ids
            if status != 200:
                log.warning("CS %s: query page %d HTTP %s: %s",
                            label, page, status,
                            (resp.get("body") or {}).get("errors"))
                return all_ids
            body    = resp["body"]
            ids     = body.get("resources") or []
            meta    = (body.get("meta") or {}).get("pagination") or {}
            if total is None:
                total = meta.get("total")
                log.debug("CS %s: %d total asset(s) declared by API", label, total or "?")
            all_ids.extend(ids)
            log.debug("CS %s: page %d — %d id(s) fetched (running %d / %s)",
                      label, page, len(ids), len(all_ids), total or "?")
            page   += 1
            offset += len(ids)
            # Stop when: no more IDs, short page, OR we've reached the declared total
            if not ids:
                break
            if total is not None and len(all_ids) >= total:
                log.debug("CS %s: reached declared total (%d) — stopping", label, total)
                break
            if len(ids) < page_limit:
                break
        log.info("CS %s: %d id(s) collected", label, len(all_ids))
        return all_ids

    def _fetch_details(label: str, get_fn, ids: list[str], batch_size: int = 100) -> list[dict]:
        """Fetch full detail records for a list of IDs in batches."""
        if not ids or get_fn is None:
            return []
        records: list[dict] = []
        for i in range(0, len(ids), batch_size):
            batch  = ids[i:i + batch_size]
            resp   = get_fn(ids=batch)
            status = resp.get("status_code")
            if status != 200:
                log.warning("CS %s: get_details batch %d HTTP %s: %s",
                            label, i // batch_size, status,
                            (resp.get("body") or {}).get("errors"))
                continue
            batch_records = (resp["body"].get("resources") or [])
            records.extend(batch_records)
            log.debug("CS %s: fetched detail batch %d — %d record(s) (running %d)",
                      label, i // batch_size, len(batch_records), len(records))
        log.info("CS %s: %d full record(s) fetched", label, len(records))
        return records

    # ---- 1. Hosts API (sensor-managed) ----
    log.debug("CS Hosts: starting scroll…")
    try:
        hosts_svc = Hosts(client_id=creds["client_id"], client_secret=creds["client_secret"])
        # Hosts uses cursor-based scroll, not offset
        all_aids: list[str] = []
        after = None
        page  = 0
        total = None
        while True:
            kwargs: dict = {"limit": 5000}
            if after:
                kwargs["after"] = after
            resp   = hosts_svc.query_devices_by_filter_scroll(**kwargs)
            status = resp.get("status_code")
            if status == 403:
                log.info("CS Hosts: HTTP 403 — Hosts:Read scope not available (FEM-only token)")
                break
            if status != 200:
                log.warning("CS Hosts: scroll page %d HTTP %s: %s",
                            page, status, (resp.get("body") or {}).get("errors"))
                break
            body  = resp["body"]
            aids  = body.get("resources") or []
            meta  = (body.get("meta") or {}).get("pagination") or {}
            after = meta.get("after")
            if total is None:
                total = meta.get("total")
                log.debug("CS Hosts: %d total AID(s) declared", total or "?")
            all_aids.extend(aids)
            log.debug("CS Hosts: scroll page %d — %d AID(s) (running %d / %s)",
                      page, len(aids), len(all_aids), total or "?")
            page += 1
            if not aids or not after:
                break
            if total is not None and len(all_aids) >= total:
                log.debug("CS Hosts: reached declared total (%d) — stopping", total)
                break
        result["hosts"] = _fetch_details(
            "Hosts", hosts_svc.get_device_details, all_aids
        )
    except Exception as exc:
        log.warning("CS Hosts API failed: %s", exc, exc_info=True)

    # ---- 2. Discover — unmanaged hosts (FEM scope) ----
    log.debug("CS Discover: starting scroll of unmanaged hosts…")
    try:
        discover_svc = Discover(client_id=creds["client_id"], client_secret=creds["client_secret"])
        query_fn = (getattr(discover_svc, "query_hosts", None)
                    or getattr(discover_svc, "QueryHosts", None))
        get_fn   = (getattr(discover_svc, "get_hosts", None)
                    or getattr(discover_svc, "GetHosts", None))
        if query_fn and get_fn:
            ids = _scroll_ids("Discover/unmanaged-hosts", query_fn, page_limit=100)
            result["discover_hosts"] = _fetch_details("Discover/unmanaged-hosts", get_fn, ids)
            if result["discover_hosts"]:
                log.debug("CS Discover: first record keys: %s",
                          sorted(result["discover_hosts"][0].keys()))
        else:
            log.debug("CS Discover: query_hosts/get_hosts not available on this falconpy build")
    except Exception as exc:
        log.warning("CS Discover API failed: %s", exc, exc_info=True)

    return result


def _build_cs_index_from_assets(asset_data: dict) -> dict[str, dict]:
    """
    Build a normalised MAC → {aid, url} index from raw cached asset records.
    Pure transform — no API calls.
    """
    console_url = "https://falcon.crowdstrike.com"
    index: dict[str, dict] = {}

    def _norm(raw: str) -> str:
        return raw.lower().replace("-", "").replace(":", "").replace(".", "").strip()

    def _add(macs_raw: list[str], asset_id: str, url: str) -> int:
        added = 0
        for raw in macs_raw:
            n = _norm(raw)
            if n and len(n) == 12 and n not in index:
                index[n] = {"aid": asset_id, "url": url}
                added += 1
        return added

    for host in (asset_data.get("hosts") or []):
        aid  = host.get("device_id", "")
        url  = f"{console_url}/host-management/hosts/{aid}"
        macs: list[str] = []
        for nic in (host.get("network_interfaces") or []):
            m = nic.get("mac_address") or nic.get("mac") or ""
            if m:
                macs.append(m)
        if host.get("mac_address"):
            macs.append(host["mac_address"])
        _add(macs, aid, url)

    for asset in (asset_data.get("discover_hosts") or []):
        asset_id = asset.get("id", "")
        url      = f"{console_url}/discover/hosts/{asset_id}"
        macs: list[str] = []
        for nic in (asset.get("network_interfaces") or []):
            m = nic.get("mac_address") or nic.get("mac") or ""
            if m:
                macs.append(m)
        for field in ("mac_address", "mac", "primary_mac"):
            v = asset.get(field) or ""
            if v:
                macs.append(v)
                break
        _add(macs, asset_id, url)

    log.info("CS index: %d unique MAC(s) from %d Hosts + %d Discover records",
             len(index),
             len(asset_data.get("hosts") or []),
             len(asset_data.get("discover_hosts") or []))
    return index


def _build_cs_index(force_rebuild: bool = False) -> dict[str, dict]:
    """
    Return a MAC → {aid, url} index, using the local asset cache when fresh.

    force_rebuild=True skips the cache check and re-fetches from the API,
    then saves the result to cache.
    """
    creds = _cs_creds()
    if creds is None:
        return {}

    try:
        import falconpy  # noqa: F401
    except ImportError:
        log.debug("CS: falconpy not installed — skipping enrichment")
        return {}

    # Use cache if fresh and not forced
    if not force_rebuild and _cs_cache_is_fresh():
        data = _cs_cache_load()
        if data:
            return _build_cs_index_from_assets(data)
        log.debug("CS cache: load failed — falling back to live fetch")

    # Fetch fresh data from the APIs
    console.print("[bold]Fetching CrowdStrike asset data from API…[/bold]")
    asset_data = _cs_fetch_assets(creds)
    _cs_cache_save(asset_data)
    return _build_cs_index_from_assets(asset_data)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group()
def cli():
    """Query Cisco IOS/ASA/NX-OS and Palo Alto devices via SNMP and sync with NetBox."""


@cli.command("drift")
@_add_options(_common_options)
def cmd_drift(ips, ip_file, depth, no_discover, slow, cs_refresh, verbose):
    """Show differences between SNMP data and NetBox (no changes written)."""
    _setup_logging(verbose)
    _print_integration_status()

    if no_discover:
        config.AUTO_DISCOVER_NEIGHBORS = False
    if slow:
        config.SNMP_TIMEOUT = config.SNMP_TIMEOUT_SLOW
        config.SNMP_RETRIES = config.SNMP_RETRIES_SLOW
        console.print(f"[yellow]--slow: SNMP timeout={config.SNMP_TIMEOUT}s  retries={config.SNMP_RETRIES}[/yellow]")

    seed = _collect_seed_ips(ips, ip_file)
    disc = discovery.run(seed, max_depth=depth)

    _print_discovery_summary(disc)

    reports: list[DriftReport] = _parallel_drift(disc.collected, dry_run=True)

    _print_drift_table(reports)

    nb = NetBoxClient(config.NETBOX_URL, config.NETBOX_TOKEN, dry_run=True)

    # Cable report — show what would be created (dry-run, so nothing written)
    cable_count = sync_mod.sync_cables(
        disc.collected, nb, create_missing=True, dry_run=True
    )
    if cable_count:
        console.print(f"\n[cyan]{cable_count} cable(s) would be created from CDP/LLDP data.[/cyan]")

    # MAC table report
    cs_index = _build_cs_index(force_rebuild=cs_refresh)
    mac_counts = sync_mod.sync_mac_table(disc.collected, nb, dry_run=True, cs_index=cs_index)
    if mac_counts.get("updated"):
        console.print(
            f"[cyan]{mac_counts['updated']} interface(s) would have their "
            f"MAC table updated.[/cyan]"
        )


@cli.command("sync")
@_add_options(_common_options)
@click.option("--dry-run", is_flag=True,
              help="Compute changes but do not write to NetBox.")
@click.option("--no-create", is_flag=True,
              help="Only update existing objects, do not create new ones.")
def cmd_sync(ips, ip_file, depth, no_discover, slow, cs_refresh, verbose, dry_run, no_create):
    """Sync SNMP data into NetBox (creates and updates)."""
    _setup_logging(verbose)
    _print_integration_status()

    if no_discover:
        config.AUTO_DISCOVER_NEIGHBORS = False
    if slow:
        config.SNMP_TIMEOUT = config.SNMP_TIMEOUT_SLOW
        config.SNMP_RETRIES = config.SNMP_RETRIES_SLOW
        console.print(f"[yellow]--slow: SNMP timeout={config.SNMP_TIMEOUT}s  retries={config.SNMP_RETRIES}[/yellow]")

    seed = _collect_seed_ips(ips, ip_file)
    disc = discovery.run(seed, max_depth=depth)

    _print_discovery_summary(disc)

    # Drift detection is read-only — run in parallel
    reports = _parallel_drift(disc.collected, dry_run=dry_run)

    # Apply is write-heavy with ordering constraints — keep sequential
    nb = NetBoxClient(config.NETBOX_URL, config.NETBOX_TOKEN, dry_run=dry_run)
    total_applied = 0
    for report in reports:
        if not dry_run and report.has_drift:
            applied = sync_mod.apply_report(
                report, nb,
                create_missing=not no_create,
            )
            total_applied += applied

    _print_drift_table(reports)

    # Second pass: cables (requires all devices/interfaces to exist first)
    console.print("\n[bold]Cable sync (CDP/LLDP)…[/bold]")
    cable_count = sync_mod.sync_cables(
        disc.collected, nb,
        create_missing=not no_create,
        dry_run=dry_run,
    )

    # MAC table sync — enrich with CrowdStrike data if available
    console.print("\n[bold]MAC table sync…[/bold]")
    cs_index = _build_cs_index(force_rebuild=cs_refresh)
    mac_counts = sync_mod.sync_mac_table(disc.collected, nb, dry_run=dry_run, cs_index=cs_index)

    if dry_run:
        console.print(
            f"[yellow]Dry-run mode — no changes written. "
            f"{cable_count} cable(s) would be created. "
            f"{mac_counts.get('updated', 0)} interface(s) would have MAC table updated.[/yellow]"
        )
    else:
        console.print(
            f"\n[green]Applied {total_applied} change(s) to NetBox. "
            f"{cable_count} cable(s) created from CDP/LLDP data. "
            f"MAC tables: {mac_counts['updated']} updated, "
            f"{mac_counts['unchanged']} unchanged, "
            f"{mac_counts['skipped']} skipped.[/green]"
        )


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _print_discovery_summary(disc: discovery.DiscoveryResult) -> None:
    console.print(
        f"\n[bold]Discovery complete:[/bold] "
        f"{len(disc.collected)} device(s) collected, "
        f"{len(disc.unreachable)} unreachable.\n"
    )

    if disc.collected:
        t = Table(title="Collected devices", show_lines=True)
        t.add_column("IP",       style="cyan")
        t.add_column("Hostname", style="bold")
        t.add_column("Platform")
        t.add_column("Model")
        t.add_column("Serial")
        t.add_column("OS Version")
        t.add_column("Interfaces", justify="right")
        t.add_column("Neighbours", justify="right")
        for d in disc.collected:
            t.add_row(
                d.query_ip,
                d.hostname,
                d.platform.value,
                d.model,
                d.serial_number,
                d.os_version,
                str(len(d.interfaces)),
                str(len(d.neighbors)),
            )
        console.print(t)

    if disc.unreachable:
        t = Table(title="[red]Unreachable (discovered but not polled)[/red]",
                  show_lines=True)
        t.add_column("IP / Hostname", style="red")
        for ip in disc.unreachable:
            t.add_row(ip)
        console.print(t)


def _print_drift_table(reports: list[DriftReport]) -> None:
    if not any(r.has_drift for r in reports):
        console.print("[green]No drift detected — NetBox is up to date.[/green]")
        return

    t = Table(title="Drift report", show_lines=True)
    t.add_column("Device")
    t.add_column("Object type")
    t.add_column("Action")
    t.add_column("Identifier")
    t.add_column("Field diffs")

    for report in reports:
        for item in report.items:
            kind_style = "green" if item.kind == ChangeKind.CREATE else "yellow"
            diffs_str = ""
            if item.diffs:
                diffs_str = "\n".join(
                    f"{d.field}: [red]{d.netbox_value!r}[/red] → "
                    f"[green]{d.snmp_value!r}[/green]"
                    for d in item.diffs
                )
            t.add_row(
                report.hostname or report.device_ip,
                item.object_type,
                f"[{kind_style}]{item.kind.value}[/{kind_style}]",
                item.identifier,
                diffs_str,
            )

    console.print(t)


# ---------------------------------------------------------------------------
# cs-lookup test command
# ---------------------------------------------------------------------------

def _cs_direct_mac_lookup(creds: dict, mac_norm: str, verbose: bool) -> Optional[dict]:
    """
    Query CrowdStrike directly for a single normalised MAC (12 hex chars, no separators).

    Tries Discover query_hosts with an FQL filter first (FEM-scoped token).
    Falls back to Hosts query_devices_by_filter if the token has that scope.

    Returns {"id": ..., "url": ..., "hostname": ..., "source": ...} or None.
    """
    console_url = "https://falcon.crowdstrike.com"

    # Format MAC as colon-separated for the FQL filter (CrowdStrike stores it that way)
    mac_colon = ":".join(mac_norm[i:i+2] for i in range(0, 12, 2))
    log.debug("CS direct lookup: normalised=%s  colon=%s", mac_norm, mac_colon)

    try:
        from falconpy import Discover
        discover_svc = Discover(
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
        )
        query_fn = getattr(discover_svc, "query_hosts", None) or getattr(discover_svc, "QueryHosts", None)
        get_fn   = getattr(discover_svc, "get_hosts",   None) or getattr(discover_svc, "GetHosts",   None)

        if query_fn and get_fn:
            # CrowdStrike Discover stores MACs in various formats depending on
            # the field — try every plausible FQL field + format combination.
            # Sample record shows CrowdStrike stores MACs as uppercase-dash: 'F4-DD-06-61-E9-B2'
            mac_upper_dash = "-".join(mac_norm[i:i+2] for i in range(0, 12, 2)).upper()
            mac_lower_dash = mac_upper_dash.lower()
            mac_upper_colon = mac_colon.upper()
            mac_plain  = mac_norm  # no separators

            fql_candidates = [
                f"network_interfaces.mac_address:'{mac_upper_dash}'",   # confirmed format
                f"network_interfaces.mac_address:'{mac_colon}'",
                f"network_interfaces.mac_address:'{mac_upper_colon}'",
                f"network_interfaces.mac_address:'{mac_lower_dash}'",
                f"network_interfaces.mac_address:'{mac_plain}'",
                f"mac_address:'{mac_upper_dash}'",
                f"mac_address:'{mac_colon}'",
            ]

            ids: list[str] = []
            matched_fql = ""
            for fql in fql_candidates:
                log.debug("CS Discover direct: trying FQL = %s", fql)
                resp = query_fn(filter=fql, limit=5)
                status = resp.get("status_code")
                found = (resp.get("body") or {}).get("resources") or []
                log.debug("CS Discover direct: HTTP %s  resources=%s", status, found)
                if status == 200 and found:
                    ids = found
                    matched_fql = fql
                    break
                elif status not in (200, 400):
                    log.debug("CS Discover direct: unexpected HTTP %s: %s",
                              status, (resp.get("body") or {}).get("errors"))

            if ids:
                log.debug("CS Discover direct: matched via FQL '%s'", matched_fql)
                resp2 = get_fn(ids=ids[:5])
                log.debug("CS Discover direct: get_hosts HTTP %s", resp2.get("status_code"))
                for asset in (resp2["body"].get("resources") or []):
                    asset_id = asset.get("id", "")
                    return {
                        "id":       asset_id,
                        "url":      f"{console_url}/discover/hosts/{asset_id}",
                        "hostname": asset.get("hostname") or asset.get("name") or "",
                        "source":   f"Discover/unmanaged-hosts [{matched_fql}]",
                        "asset":    asset,
                    }
            else:
                log.debug("CS Discover direct: no results for MAC %s (tried %d FQL variants)",
                          mac_norm, len(fql_candidates))

                # Fetch one sample record (no filter) to show actual MAC field structure
                log.debug("CS Discover direct: fetching 1 sample record to inspect MAC field names…")
                sample_resp = query_fn(limit=1)
                sample_ids  = (sample_resp.get("body") or {}).get("resources") or []
                if sample_ids:
                    sample_detail = get_fn(ids=sample_ids)
                    for rec in ((sample_detail.get("body") or {}).get("resources") or []):
                        # Log only MAC-related fields to avoid dumping PII
                        mac_fields = {
                            k: v for k, v in rec.items()
                            if "mac" in k.lower() or k == "network_interfaces"
                        }
                        log.debug(
                            "CS Discover sample record MAC fields: %s",
                            mac_fields,
                        )
                else:
                    log.debug("CS Discover direct: no records exist in Discover for this CID")
    except Exception as exc:
        log.debug("CS Discover direct lookup failed: %s", exc, exc_info=True)

    # Fallback: Hosts API (requires Hosts:Read scope, may 403 on FEM-only tokens)
    try:
        from falconpy import Hosts
        hosts_svc = Hosts(
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
        )
        fql = f"mac_address:'{mac_colon}'"
        log.debug("CS Hosts direct: FQL filter = %s", fql)
        resp = hosts_svc.query_devices_by_filter(filter=fql, limit=5)
        status = resp.get("status_code")
        log.debug("CS Hosts direct: query HTTP %s  resources=%s",
                  status, (resp.get("body") or {}).get("resources"))
        if status == 200:
            aids = (resp["body"].get("resources") or [])
            if aids:
                resp2 = hosts_svc.get_device_details(ids=aids[:5])
                for host in (resp2["body"].get("resources") or []):
                    aid = host.get("device_id", "")
                    return {
                        "id":       aid,
                        "url":      f"{console_url}/host-management/hosts/{aid}",
                        "hostname": host.get("hostname", ""),
                        "source":   "Hosts/managed",
                        "asset":    host,
                    }
        elif status == 403:
            log.debug("CS Hosts direct: HTTP 403 — Hosts:Read scope not available on this token")
    except Exception as exc:
        log.debug("CS Hosts direct lookup failed: %s", exc, exc_info=True)

    return None


@cli.command("cs-lookup")
@click.argument("macs", nargs=-1, metavar="MAC...")
@click.option("--verbose", "-v", is_flag=True,
              help="Show API debug output for each lookup.")
@click.option("--full-index", is_flag=True,
              help="Build the full local MAC index instead of querying per-MAC "
                   "(useful when checking many MACs from a bulk sync run).")
def cmd_cs_lookup(macs: tuple[str, ...], verbose: bool, full_index: bool) -> None:
    """Look up one or more MAC addresses directly in CrowdStrike.

    By default each MAC is queried individually via FQL filter — fast for
    spot-checks.  Use --full-index to build the complete local index first
    (better when checking many MACs at once).

    Always prints token/package diagnostics before querying.

    \b
    Examples:
      python main.py cs-lookup aa:bb:cc:dd:ee:ff
      python main.py cs-lookup -v 00-11-22-33-44-55 aabbccddeeff
      python main.py cs-lookup --full-index aa:bb:cc:dd:ee:ff
    """
    _setup_logging(verbose)

    if not macs:
        console.print("[red]Provide at least one MAC address.[/red]")
        return

    # ---- pre-flight diagnostics ----
    from pathlib import Path as _Path
    token_path = _Path(getattr(config, "CS_FEM_TOKEN_FILE", "CS_FEM_TOKEN"))
    console.print(f"Token file : [cyan]{token_path}[/cyan]  "
                  + ("[green]exists[/green]" if token_path.exists()
                     else "[red]NOT FOUND[/red]"))
    if not token_path.exists():
        return
    lines = [l.strip() for l in token_path.read_text().splitlines() if l.strip()]
    console.print(f"Token lines: {len(lines)}  "
                  + (f"client_id prefix=[cyan]{lines[1][:8]}…[/cyan]"
                     if len(lines) >= 2 else "[red]too few lines[/red]"))
    if len(lines) < 2:
        return
    creds = {"client_secret": lines[0], "client_id": lines[1]}

    try:
        import falconpy  # noqa: F401
        console.print("falconpy  : [green]installed[/green]")
    except ImportError:
        console.print("falconpy  : [red]NOT installed[/red]  (pip install crowdstrike-falconpy)")
        return
    console.print()

    t = Table(title="CrowdStrike MAC lookup results", show_lines=True)
    t.add_column("Input MAC",  style="cyan")
    t.add_column("Normalised", style="dim")
    t.add_column("Result",     justify="center")
    t.add_column("Source")
    t.add_column("Hostname")
    t.add_column("Asset / AID")
    t.add_column("Falcon URL")

    if full_index:
        console.print("[bold]Building full CrowdStrike MAC index…[/bold]")
        index = _build_cs_index(force_rebuild=True)
        console.print(f"[green]Index built: {len(index)} unique MAC(s).[/green]\n")
        for raw in macs:
            norm = raw.lower().replace(":", "").replace("-", "").replace(".", "").strip()
            hit  = index.get(norm)
            if hit:
                t.add_row(raw, norm, "[green]FOUND[/green]", "index",
                          "", hit.get("aid", ""), hit.get("url", ""))
            else:
                sample = ", ".join(list(index.keys())[:3]) + ("…" if len(index) > 3 else "")
                t.add_row(raw, norm, "[red]not found[/red]", "", "",
                          "", f"[dim]sample: {sample}[/dim]")
    else:
        for raw in macs:
            norm = raw.lower().replace(":", "").replace("-", "").replace(".", "").strip()
            if len(norm) != 12 or not all(c in "0123456789abcdef" for c in norm):
                t.add_row(raw, norm, "[red]invalid MAC[/red]", "", "", "", "")
                continue
            console.print(f"Querying CrowdStrike for [cyan]{raw}[/cyan]…")
            hit = _cs_direct_mac_lookup(creds, norm, verbose)
            if hit:
                t.add_row(raw, norm, "[green]FOUND[/green]",
                          hit.get("source", ""),
                          hit.get("hostname", ""),
                          hit.get("id", ""),
                          hit.get("url", ""))
            else:
                t.add_row(raw, norm, "[red]not found[/red]", "", "", "", "")

    console.print(t)


# ---------------------------------------------------------------------------
# cs-build-cache command
# ---------------------------------------------------------------------------

@cli.command("cs-build-cache")
@click.option("--verbose", "-v", is_flag=True)
@click.option("--force", is_flag=True,
              help="Rebuild even if the existing cache is still fresh.")
def cmd_cs_build_cache(verbose: bool, force: bool) -> None:
    """Pre-populate (or refresh) the local CrowdStrike asset cache.

    Fetches all asset records from the Hosts and Discover APIs and writes
    them to the cache file defined by CS_CACHE_FILE in config.py.
    Subsequent drift/sync runs will use this cache instead of hitting the
    API each time, until it becomes stale (CS_CACHE_MAX_AGE seconds, default 24 h).

    \b
    Examples:
      python main.py cs-build-cache
      python main.py cs-build-cache --force --verbose
    """
    _setup_logging(verbose)

    cache_path = _cs_cache_path()
    max_age    = getattr(config, "CS_CACHE_MAX_AGE", 86400)
    console.print(f"Cache file : [cyan]{cache_path}[/cyan]")
    console.print(f"Max age    : {max_age}s ({max_age // 3600}h)")

    if not force and _cs_cache_is_fresh():
        import time as _time
        age = _time.time() - (cache_path.stat().st_mtime if cache_path else 0)
        console.print(
            f"[green]Cache is fresh (age {age:.0f}s).[/green]  "
            f"Use [bold]--force[/bold] to rebuild anyway."
        )
        data = _cs_cache_load()
        if data:
            console.print(
                f"  Hosts records    : {len(data.get('hosts', []))}\n"
                f"  Discover records : {len(data.get('discover_hosts', []))}"
            )
        return

    creds = _cs_creds()
    if creds is None:
        console.print("[red]No CrowdStrike credentials available — check CS_FEM_TOKEN.[/red]")
        return
    try:
        import falconpy  # noqa: F401
    except ImportError:
        console.print("[red]falconpy not installed — pip install crowdstrike-falconpy[/red]")
        return

    console.print("[bold]Fetching CrowdStrike assets from API…[/bold]")
    asset_data = _cs_fetch_assets(creds)
    _cs_cache_save(asset_data)

    t = Table(title="Cache build summary", show_lines=True)
    t.add_column("Source")
    t.add_column("Records", justify="right")
    t.add_row("Hosts (sensor-managed)",    str(len(asset_data.get("hosts", []))))
    t.add_row("Discover (unmanaged hosts)", str(len(asset_data.get("discover_hosts", []))))
    console.print(t)

    idx = _build_cs_index_from_assets(asset_data)
    console.print(f"\n[green]MAC index: {len(idx)} unique MAC(s) ready.[/green]")
    if cache_path:
        console.print(f"Saved to: [cyan]{cache_path}[/cyan]")


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
