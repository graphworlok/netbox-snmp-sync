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


def _build_cs_index() -> dict[str, dict]:
    """
    Build a MAC → {aid, url} index from CrowdStrike Hosts + Discover APIs.

    Reads the CS_FEM_TOKEN credential file.  Returns an empty dict
    (silently) if the token file is absent or falconpy is not installed,
    so the MAC sync still works without CrowdStrike configured.
    """
    token_path = getattr(config, "CS_FEM_TOKEN_FILE", "CS_FEM_TOKEN")
    from pathlib import Path as _Path
    if not _Path(token_path).exists():
        log.debug("CS_FEM_TOKEN not found — skipping CrowdStrike MAC enrichment")
        return {}

    try:
        creds = json.loads(_Path(token_path).read_text())
        from falconpy import Hosts
    except (ImportError, Exception) as exc:
        log.debug("CrowdStrike MAC index unavailable: %s", exc)
        return {}

    console_url = creds.get("console_url", "https://falcon.crowdstrike.com").rstrip("/")
    index: dict[str, dict] = {}

    try:
        hosts = Hosts(
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
            base_url=creds.get("base_url", "https://api.crowdstrike.com"),
        )
        after = None
        all_aids: list[str] = []
        while True:
            kwargs: dict = {"limit": 5000}
            if after:
                kwargs["after"] = after
            resp = hosts.query_devices_by_filter_scroll(**kwargs)
            if resp.get("status_code") != 200:
                break
            body  = resp["body"]
            aids  = body.get("resources") or []
            after = (body.get("meta") or {}).get("pagination", {}).get("after")
            all_aids.extend(aids)
            if not aids or not after:
                break

        for i in range(0, len(all_aids), 100):
            batch = all_aids[i:i + 100]
            resp = hosts.get_device_details(ids=batch)
            if resp.get("status_code") != 200:
                continue
            for host in (resp["body"].get("resources") or []):
                aid = host.get("device_id", "")
                url = f"{console_url}/host-management/hosts/{aid}"
                # Collect all MACs from network_interfaces + top-level mac_address
                macs: list[str] = []
                for nic in (host.get("network_interfaces") or []):
                    m = nic.get("mac_address") or nic.get("mac") or ""
                    if m:
                        macs.append(m)
                top_mac = host.get("mac_address", "")
                if top_mac:
                    macs.append(top_mac)
                for mac_raw in macs:
                    norm = mac_raw.lower().replace("-", "").replace(":", "").replace(".", "")
                    if norm and norm not in index:
                        index[norm] = {"aid": aid, "url": url}

        log.info("CrowdStrike MAC index: %d entries from %d host(s)",
                 len(index), len(all_aids))
    except Exception as exc:
        log.warning("CrowdStrike MAC index build failed: %s", exc)

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

if __name__ == "__main__":
    cli()
