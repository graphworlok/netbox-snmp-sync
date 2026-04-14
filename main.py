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


def _build_cs_index() -> dict[str, dict]:
    """
    Build a MAC → {aid, url} index from CrowdStrike.

    Queries two APIs:
      1. Hosts API  — managed endpoints that have the Falcon sensor installed.
      2. Discover API (Falcon Exposure Management) — unmanaged endpoints and
         network devices visible to neighbouring sensors.

    Reads the CS_FEM_TOKEN credential file (two plain-text lines: secret, CID).
    Returns an empty dict silently if the token file is absent or falconpy is
    not installed, so MAC sync continues without CrowdStrike data.
    """
    token_path = getattr(config, "CS_FEM_TOKEN_FILE", "CS_FEM_TOKEN")
    from pathlib import Path as _Path

    if not _Path(token_path).exists():
        log.debug("CS: token file not found at %s — skipping CrowdStrike enrichment", token_path)
        return {}

    try:
        lines = [l.strip() for l in _Path(token_path).read_text().splitlines() if l.strip()]
        if len(lines) < 2:
            raise ValueError(f"Token file {token_path} must have 2 lines (secret, CID); got {len(lines)}")
        creds = {"client_secret": lines[0], "client_id": lines[1]}
        log.debug("CS: token file loaded from %s  client_id=%s…", token_path, lines[1][:8])
    except Exception as exc:
        log.warning("CS: could not read token file %s: %s", token_path, exc)
        return {}

    try:
        from falconpy import Hosts, Discover
    except ImportError:
        log.debug("CS: falconpy not installed — skipping CrowdStrike enrichment")
        return {}

    index: dict[str, dict] = {}
    console_url = "https://falcon.crowdstrike.com"

    def _norm_mac(raw: str) -> str:
        return raw.lower().replace("-", "").replace(":", "").replace(".", "").strip()

    def _add_macs(macs_raw: list[str], aid: str, url: str) -> int:
        added = 0
        for mac_raw in macs_raw:
            norm = _norm_mac(mac_raw)
            if norm and len(norm) == 12 and norm not in index:
                index[norm] = {"aid": aid, "url": url}
                added += 1
        return added

    # ------------------------------------------------------------------ #
    # 1. Hosts API — sensor-managed endpoints                             #
    #    403 means the credential only has FEM scope — that is fine,      #
    #    Discover will cover unmanaged assets.                             #
    # ------------------------------------------------------------------ #
    log.debug("CS Hosts: starting scroll of managed devices…")
    try:
        hosts_svc = Hosts(
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
        )
        after = None
        all_aids: list[str] = []
        page = 0
        while True:
            kwargs: dict = {"limit": 5000}
            if after:
                kwargs["after"] = after
            resp = hosts_svc.query_devices_by_filter_scroll(**kwargs)
            status = resp.get("status_code")
            if status == 403:
                log.info(
                    "CS Hosts: HTTP 403 — credential does not have Hosts:Read scope "
                    "(FEM-only token is fine; Discover will cover unmanaged assets)"
                )
                break
            if status != 200:
                log.warning("CS Hosts: scroll page %d returned HTTP %s: %s",
                            page, status,
                            (resp.get("body") or {}).get("errors"))
                break
            body  = resp["body"]
            aids  = body.get("resources") or []
            after = (body.get("meta") or {}).get("pagination", {}).get("after")
            all_aids.extend(aids)
            log.debug("CS Hosts: scroll page %d — %d AID(s) (running total %d)",
                      page, len(aids), len(all_aids))
            page += 1
            if not aids or not after:
                break

        log.debug("CS Hosts: %d AID(s) discovered; fetching device details in batches of 100…",
                  len(all_aids))
        hosts_macs = 0
        for i in range(0, len(all_aids), 100):
            batch = all_aids[i:i + 100]
            resp = hosts_svc.get_device_details(ids=batch)
            status = resp.get("status_code")
            if status != 200:
                log.warning("CS Hosts: get_device_details batch %d returned HTTP %s: %s",
                            i // 100, status,
                            (resp.get("body") or {}).get("errors"))
                continue
            for host in (resp["body"].get("resources") or []):
                aid  = host.get("device_id", "")
                url  = f"{console_url}/host-management/hosts/{aid}"
                macs_raw: list[str] = []
                for nic in (host.get("network_interfaces") or []):
                    m = nic.get("mac_address") or nic.get("mac") or ""
                    if m:
                        macs_raw.append(m)
                top = host.get("mac_address", "")
                if top:
                    macs_raw.append(top)
                added = _add_macs(macs_raw, aid, url)
                if added:
                    log.debug("CS Hosts: AID %s  hostname=%s  +%d MAC(s)",
                              aid[:16], host.get("hostname", "?"), added)
                hosts_macs += added

        log.info("CS Hosts: %d MAC(s) indexed from %d managed host(s)",
                 hosts_macs, len(all_aids))

    except Exception as exc:
        log.warning("CS Hosts API failed: %s", exc, exc_info=True)

    # ------------------------------------------------------------------ #
    # 2. Discover API — Falcon Exposure Management (FEM)                  #
    #                                                                      #
    # This version of falconpy exposes two asset classes separately:       #
    #   query_hosts / get_hosts       — unmanaged endpoints                #
    #   query_iot_hosts / get_iot_hosts — IoT / network devices            #
    # (older builds used query_assets/get_assets for both; newer builds   #
    #  split them — we try both styles and skip any that 403/fail)         #
    # ------------------------------------------------------------------ #
    log.debug("CS Discover (FEM): querying unmanaged hosts and IoT/network devices…")
    try:
        discover_svc = Discover(
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
        )

        def _scroll_and_fetch(
            label: str,
            query_fn,
            get_fn,
            url_path: str,
        ) -> int:
            """Generic scroll + details fetch for one Discover asset class."""
            if query_fn is None or get_fn is None:
                log.debug("CS Discover: %s — methods not available on this falconpy build", label)
                return 0

            all_ids: list[str] = []
            offset = 0
            page = 0
            while True:
                resp = query_fn(limit=5000, offset=offset)
                status = resp.get("status_code")
                if status == 403:
                    log.info(
                        "CS Discover %s: HTTP 403 — may not be licensed or scoped for this CID",
                        label,
                    )
                    return 0
                if status != 200:
                    log.warning("CS Discover %s: query page %d HTTP %s: %s",
                                label, page, status,
                                (resp.get("body") or {}).get("errors"))
                    return 0
                ids   = resp["body"].get("resources") or []
                total = (resp["body"].get("meta") or {}).get("pagination", {}).get("total", "?")
                all_ids.extend(ids)
                log.debug("CS Discover %s: page %d — %d id(s) (total %d / %s)",
                          label, page, len(ids), len(all_ids), total)
                page   += 1
                offset += len(ids)
                if not ids or len(ids) < 5000:
                    break

            log.debug("CS Discover %s: %d id(s); fetching details…", label, len(all_ids))
            macs_added = 0
            for i in range(0, len(all_ids), 100):
                batch = all_ids[i:i + 100]
                resp = get_fn(ids=batch)
                status = resp.get("status_code")
                if status != 200:
                    log.warning("CS Discover %s: get batch %d HTTP %s: %s",
                                label, i // 100, status,
                                (resp.get("body") or {}).get("errors"))
                    continue
                for asset in (resp["body"].get("resources") or []):
                    asset_id = asset.get("id", "")
                    url      = f"{console_url}/{url_path}/{asset_id}"
                    macs_raw: list[str] = []
                    for nic in (asset.get("network_interfaces") or []):
                        m = nic.get("mac_address") or ""
                        if m:
                            macs_raw.append(m)
                    top = asset.get("mac_address") or asset.get("mac") or ""
                    if top:
                        macs_raw.append(top)
                    added = _add_macs(macs_raw, asset_id, url)
                    if added:
                        log.debug(
                            "CS Discover %s: asset %s  hostname=%-30s  +%d MAC(s)",
                            label, asset_id[:16],
                            (asset.get("hostname") or asset.get("name") or "?")[:30],
                            added,
                        )
                    macs_added += added

            log.info("CS Discover %s: %d MAC(s) from %d asset(s)", label, macs_added, len(all_ids))
            return macs_added

        # --- unmanaged hosts (sensors on neighbours, no local agent) ---
        _scroll_and_fetch(
            "unmanaged-hosts",
            getattr(discover_svc, "query_hosts",     None) or getattr(discover_svc, "QueryHosts",    None),
            getattr(discover_svc, "get_hosts",        None) or getattr(discover_svc, "GetHosts",      None),
            "discover/hosts",
        )

        # --- IoT / network devices (switches, routers, cameras, etc.) ---
        _scroll_and_fetch(
            "iot-hosts",
            getattr(discover_svc, "query_iot_hosts",  None) or getattr(discover_svc, "QueryIoTHosts", None),
            getattr(discover_svc, "get_iot_hosts",    None) or getattr(discover_svc, "GetIoTHosts",   None),
            "discover/iot-assets",
        )

        # --- legacy combined assets endpoint (older falconpy / older CID) ---
        _scroll_and_fetch(
            "assets (legacy)",
            getattr(discover_svc, "query_assets",    None) or getattr(discover_svc, "QueryAssets",   None),
            getattr(discover_svc, "get_assets",      None) or getattr(discover_svc, "GetAssets",     None),
            "discover/assets",
        )

    except Exception as exc:
        log.warning("CS Discover (FEM) API failed: %s", exc, exc_info=True)

    log.info("CS MAC index total: %d unique MAC(s) across Hosts + Discover", len(index))
    return index


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group()
def cli():
    """Query Cisco IOS/ASA/NX-OS and Palo Alto devices via SNMP and sync with NetBox."""


@cli.command("drift")
@_add_options(_common_options)
def cmd_drift(ips, ip_file, depth, no_discover, verbose):
    """Show differences between SNMP data and NetBox (no changes written)."""
    _setup_logging(verbose)
    _print_integration_status()

    if no_discover:
        config.AUTO_DISCOVER_NEIGHBORS = False

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
    cs_index = _build_cs_index()
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
def cmd_sync(ips, ip_file, depth, no_discover, verbose, dry_run, no_create):
    """Sync SNMP data into NetBox (creates and updates)."""
    _setup_logging(verbose)
    _print_integration_status()

    if no_discover:
        config.AUTO_DISCOVER_NEIGHBORS = False

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
    cs_index = _build_cs_index()
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

@cli.command("cs-lookup")
@click.argument("macs", nargs=-1, metavar="MAC...")
@click.option("--verbose", "-v", is_flag=True,
              help="Show per-page API debug output while building the index.")
def cmd_cs_lookup(macs: tuple[str, ...], verbose: bool) -> None:
    """Look up one or more MAC addresses in the CrowdStrike index.

    Builds the full Hosts + Discover (FEM) MAC index then checks each
    supplied MAC.  Always prints a detailed diagnostic summary so you can
    see exactly what the API returned and why a MAC did or did not match.
    Use --verbose to also stream per-page API debug logs while building.

    \b
    Examples:
      python main.py cs-lookup aa:bb:cc:dd:ee:ff
      python main.py cs-lookup -v 00-11-22-33-44-55 aabbccddeeff
    """
    _setup_logging(verbose)

    if not macs:
        console.print("[red]Provide at least one MAC address.[/red]")
        return

    # ---- token / package pre-flight ----
    from pathlib import Path as _Path
    token_path = _Path(getattr(config, "CS_FEM_TOKEN_FILE", "CS_FEM_TOKEN"))
    console.print(f"Token file : [cyan]{token_path}[/cyan]  "
                  + ("[green]exists[/green]" if token_path.exists()
                     else "[red]NOT FOUND[/red]"))
    if token_path.exists():
        lines = [l.strip() for l in token_path.read_text().splitlines() if l.strip()]
        console.print(f"Token lines: {len(lines)}  "
                      + (f"client_id prefix=[cyan]{lines[1][:8]}…[/cyan]"
                         if len(lines) >= 2 else "[red]too few lines[/red]"))
    try:
        import falconpy  # noqa: F401
        console.print("falconpy  : [green]installed[/green]")
    except ImportError:
        console.print("falconpy  : [red]NOT installed[/red]  (pip install crowdstrike-falconpy)")
        return
    console.print()

    # ---- build index ----
    console.print("[bold]Building CrowdStrike MAC index (Hosts + Discover/FEM)…[/bold]")
    index = _build_cs_index()

    if not index:
        console.print("\n[yellow]Index is empty.[/yellow]  "
                      "Run with [bold]--verbose[/bold] to see API responses.")
        return

    console.print(f"\n[green]Index built: {len(index)} unique MAC(s).[/green]\n")

    # ---- lookup table ----
    t = Table(title="CrowdStrike MAC lookup results", show_lines=True)
    t.add_column("Input MAC",   style="cyan")
    t.add_column("Normalised",  style="dim")
    t.add_column("Result",      justify="center")
    t.add_column("Asset / AID")
    t.add_column("Falcon URL")

    for raw in macs:
        norm = raw.lower().replace(":", "").replace("-", "").replace(".", "").strip()
        hit  = index.get(norm)
        if hit:
            t.add_row(
                raw, norm,
                "[green]FOUND[/green]",
                hit.get("aid", ""),
                hit.get("url", ""),
            )
        else:
            # Show a few nearby keys to help diagnose formatting issues
            sample = ", ".join(list(index.keys())[:3]) + ("…" if len(index) > 3 else "")
            t.add_row(
                raw, norm,
                "[red]not found[/red]",
                "",
                f"[dim]index sample: {sample}[/dim]",
            )

    console.print(t)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
