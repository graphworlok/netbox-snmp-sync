#!/usr/bin/env python3
"""
Meraki → NetBox sync.

Reads every NetBox site that has the 'meraki_network_id' custom field populated,
collects device data from the corresponding Meraki network via the Dashboard API,
and syncs it into NetBox using the same drift/apply/cable/MAC machinery as the
SNMP tool.

Custom field created automatically on first run
-----------------------------------------------
  dcim.site : meraki_network_id  (text)

Credentials
-----------
NetBox : config.py  (NETBOX_URL, NETBOX_TOKEN)
Meraki : config.py  (MERAKI_API_KEY)

Usage
-----
  python meraki_sync.py drift                  # show drift across all mapped sites
  python meraki_sync.py sync                   # sync all mapped sites
  python meraki_sync.py sync --dry-run         # show what would change
  python meraki_sync.py sync --network N_xxxx  # limit to one network
"""

from __future__ import annotations

import logging
import sys

import click
from rich.console import Console
from rich.table import Table

import config
import sync as sync_mod
from meraki_collector import MerakiClient, collect_network
from models import ChangeKind, DriftReport
from netbox_client import NetBoxClient
from oui import OuiLookup

console = Console()


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        format="%(levelname)-8s %(name)s: %(message)s",
        level=logging.DEBUG if verbose else logging.INFO,
    )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _get_api_key() -> str:
    key = getattr(config, "MERAKI_API_KEY", "")
    if not key:
        console.print(
            "[red]MERAKI_API_KEY is not set in config.py.[/red]\n"
            "Add:  MERAKI_API_KEY = \"your-api-key\""
        )
        sys.exit(1)
    return key


def _load_network_map(
    nb: NetBoxClient,
    network_filter: str | None,
) -> dict[str, object]:
    """
    Return {network_id: nb_site} for all mapped sites.
    Optionally restricted to a single *network_filter* ID.
    """
    nb.ensure_meraki_network_field()
    mapping = nb.get_sites_by_meraki_network()
    if not mapping:
        console.print(
            "[yellow]No NetBox sites have 'meraki_network_id' set.[/yellow]\n"
            "Populate the custom field on dcim.site to map sites to Meraki networks."
        )
        sys.exit(0)
    if network_filter:
        if network_filter not in mapping:
            console.print(
                f"[red]Network {network_filter!r} not found in NetBox site mappings.[/red]"
            )
            sys.exit(1)
        return {network_filter: mapping[network_filter]}
    return mapping


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group()
def cli():
    """Sync Cisco Meraki network data into NetBox."""


@cli.command("drift")
@click.option("--network", default=None, metavar="NETWORK_ID",
              help="Limit to a single Meraki network ID.")
@click.option("--verbose", "-v", is_flag=True)
def cmd_drift(network, verbose):
    """Show differences between Meraki data and NetBox (no changes written)."""
    _setup_logging(verbose)

    nb      = NetBoxClient(config.NETBOX_URL, config.NETBOX_TOKEN, dry_run=True)
    meraki  = MerakiClient(_get_api_key())
    mapping = _load_network_map(nb, network)

    all_reports: list[DriftReport] = []

    for network_id, nb_site in mapping.items():
        site_name = str(nb_site)
        console.print(f"\n[bold]Network {network_id}[/bold] → site [cyan]{site_name}[/cyan]")

        devices = collect_network(meraki, network_id, site_id=nb_site.id)
        _print_collection_summary(devices)

        for device in devices:
            report = sync_mod.drift_device(device, nb)
            all_reports.append(report)

        cable_count = sync_mod.sync_cables(devices, nb, dry_run=True)
        mac_counts  = sync_mod.sync_mac_table(devices, nb, dry_run=True)

        if cable_count:
            console.print(f"  [cyan]{cable_count} cable(s) would be created.[/cyan]")
        if mac_counts.get("created"):
            console.print(
                f"  [cyan]{mac_counts['created']} MAC address(es) would be created.[/cyan]"
            )

    _print_drift_table(all_reports)


@cli.command("sync")
@click.option("--network", default=None, metavar="NETWORK_ID",
              help="Limit to a single Meraki network ID.")
@click.option("--dry-run", is_flag=True,
              help="Compute changes but do not write to NetBox.")
@click.option("--no-create", is_flag=True,
              help="Only update existing objects; do not create new ones.")
@click.option("--verbose", "-v", is_flag=True)
def cmd_sync(network, dry_run, no_create, verbose):
    """Sync Meraki network data into NetBox."""
    _setup_logging(verbose)

    nb      = NetBoxClient(config.NETBOX_URL, config.NETBOX_TOKEN, dry_run=dry_run)
    meraki  = MerakiClient(_get_api_key())
    oui     = OuiLookup.from_config()
    mapping = _load_network_map(nb, network)

    total_applied = 0
    total_cables  = 0
    total_macs: dict[str, int] = {"created": 0, "refreshed": 0, "stale": 0, "unchanged": 0, "skipped": 0}

    for network_id, nb_site in mapping.items():
        site_name = str(nb_site)
        console.print(f"\n[bold]Network {network_id}[/bold] → site [cyan]{site_name}[/cyan]")

        devices = collect_network(meraki, network_id, site_id=nb_site.id)
        _print_collection_summary(devices)

        # Pass 1: devices / interfaces / IPs
        for device in devices:
            report = sync_mod.drift_device(device, nb)
            if not dry_run and report.has_drift:
                applied = sync_mod.apply_report(report, nb, create_missing=not no_create)
                total_applied += applied

        # Pass 2: cables
        cables = sync_mod.sync_cables(
            devices, nb, create_missing=not no_create, dry_run=dry_run
        )
        total_cables += cables

        # Pass 3: MAC tables
        mac_counts = sync_mod.sync_mac_table(devices, nb, dry_run=dry_run)
        for k, v in mac_counts.items():
            total_macs[k] = total_macs.get(k, 0) + v

    if dry_run:
        console.print(
            f"\n[yellow]Dry-run — no changes written. "
            f"{total_cables} cable(s) and "
            f"{total_macs.get('created', 0)} MAC(s) would be created.[/yellow]"
        )
    else:
        console.print(
            f"\n[green]Done. "
            f"{total_applied} object(s) applied, "
            f"{total_cables} cable(s) created, "
            f"MACs: {total_macs.get('created',0)} created / "
            f"{total_macs.get('stale',0)} stale / "
            f"{total_macs.get('refreshed',0)} refreshed.[/green]"
        )


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _print_collection_summary(devices) -> None:
    if not devices:
        console.print("  [yellow]No devices returned.[/yellow]")
        return
    t = Table(show_lines=True, box=None, pad_edge=False)
    t.add_column("Serial",   style="dim")
    t.add_column("Name",     style="bold")
    t.add_column("Model")
    t.add_column("Firmware", style="dim")
    t.add_column("Ifaces",   justify="right")
    t.add_column("Nbrs",     justify="right")
    t.add_column("MACs",     justify="right")
    for d in devices:
        t.add_row(
            d.serial_number,
            d.hostname,
            d.model,
            d.os_version,
            str(len(d.interfaces)),
            str(len(d.neighbors)),
            str(len(d.mac_table)),
        )
    console.print(t)


def _print_drift_table(reports: list[DriftReport]) -> None:
    if not any(r.has_drift for r in reports):
        console.print("\n[green]No drift — NetBox is up to date.[/green]")
        return

    t = Table(title="Drift report", show_lines=True)
    t.add_column("Device")
    t.add_column("Object type")
    t.add_column("Action")
    t.add_column("Identifier")
    t.add_column("Field diffs")

    for report in reports:
        for item in report.items:
            colour = "green" if item.kind == ChangeKind.CREATE else "yellow"
            diffs_str = "\n".join(
                f"{d.field}: [red]{d.netbox_value!r}[/red] → [green]{d.snmp_value!r}[/green]"
                for d in item.diffs
            )
            t.add_row(
                report.hostname or report.device_ip,
                item.object_type,
                f"[{colour}]{item.kind.value}[/{colour}]",
                item.identifier,
                diffs_str,
            )

    console.print(t)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
