#!/usr/bin/env python3
"""
CrowdStrike Falcon enrichment for NetBox MAC addresses.

Iterates over all dcim.mac_addresses in NetBox and, for each MAC that matches
a host in CrowdStrike Falcon, writes the Falcon device page URL into the
'external_url' custom field.

Credentials
-----------
NetBox      : config.py  (NETBOX_URL, NETBOX_TOKEN)
CrowdStrike : CS_FEM_TOKEN file (JSON with at minimum client_id / client_secret)

  {
      "client_id": "...",
      "client_secret": "...",
      "base_url": "https://api.crowdstrike.com",      (optional)
      "console_url": "https://falcon.crowdstrike.com" (optional)
  }

Usage examples
--------------
# Enrich all MACs that do not yet have an external_url
python cs_enrich.py

# Re-check everything, overwriting existing URLs
python cs_enrich.py --overwrite

# Dry-run (show what would change, write nothing)
python cs_enrich.py --dry-run

# Use a token file in a non-default location
python cs_enrich.py --token-file /etc/crowdstrike/CS_FEM_TOKEN
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

import click
import pynetbox
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
from rich.table import Table

import config

console = Console()
log = logging.getLogger(__name__)

_DEFAULT_TOKEN_FILE = "CS_FEM_TOKEN"
_DEFAULT_BASE_URL   = "https://api.crowdstrike.com"
_DEFAULT_CONSOLE    = "https://falcon.crowdstrike.com"

# Seconds to wait between CrowdStrike API calls.  Keeps us well inside rate limits.
_API_DELAY = 0.1


# ---------------------------------------------------------------------------
# CrowdStrike client
# ---------------------------------------------------------------------------

class FalconClient:
    """
    Thin wrapper around falconpy's Hosts service collection.
    Looks up a single MAC address and returns the Falcon console URL for the
    matching host, or None if not found.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = _DEFAULT_BASE_URL,
        console_url: str = _DEFAULT_CONSOLE,
    ) -> None:
        self._console_url = console_url.rstrip("/")
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

    def lookup(self, mac: str) -> Optional[str]:
        """
        Return the Falcon console URL for the host with *mac*, or None.
        MAC may be in any common format; it is normalised to dash-separated
        before querying (the format Falcon stores internally).
        """
        mac_dash = _to_dash(mac)
        try:
            resp = self._hosts.query_devices_by_filter(
                filter=f"mac_address:'{mac_dash}'",
                limit=1,
            )
        except Exception as exc:
            log.debug("CrowdStrike API error for %s: %s", mac, exc)
            return None

        if resp.get("status_code") != 200:
            log.debug(
                "CrowdStrike returned HTTP %s for %s: %s",
                resp.get("status_code"), mac,
                (resp.get("body") or {}).get("errors"),
            )
            return None

        aids = (resp.get("body") or {}).get("resources", [])
        if aids:
            return f"{self._console_url}/host-management/hosts/{aids[0]}"
        return None

    @classmethod
    def from_token_file(cls, path: str | Path | None = None) -> "FalconClient":
        """
        Load credentials from the CS_FEM_TOKEN JSON file.
        Raises SystemExit with a clear message if the file is missing or invalid.
        """
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
# Enrichment logic
# ---------------------------------------------------------------------------

def run_enrichment(
    nb: pynetbox.api,
    falcon: FalconClient,
    overwrite: bool,
    dry_run: bool,
) -> dict[str, int]:
    """
    Page through all dcim.mac_addresses in NetBox and enrich with CrowdStrike URLs.

    Returns counts: {"matched": N, "skipped": N, "no_match": N, "error": N}.
    """
    counts = {"matched": 0, "skipped": 0, "no_match": 0, "error": 0}
    results: list[dict] = []   # collected for the summary table

    log.info("Fetching MAC addresses from NetBox…")
    try:
        all_macs = list(nb.dcim.mac_addresses.all())
    except Exception as exc:
        console.print(f"[red]Failed to fetch MAC addresses from NetBox:[/red] {exc}")
        sys.exit(1)

    if not all_macs:
        console.print("[yellow]No MAC addresses found in NetBox.[/yellow]")
        return counts

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Querying CrowdStrike…", total=len(all_macs))

        for mac_obj in all_macs:
            mac = str(mac_obj.mac_address)
            existing_url = (getattr(mac_obj, "custom_fields", {}) or {}).get("external_url") or ""

            progress.advance(task)

            if existing_url and not overwrite:
                log.debug("SKIP %s — already has external_url", mac)
                counts["skipped"] += 1
                continue

            try:
                url = falcon.lookup(mac)
            except Exception as exc:
                log.warning("Lookup failed for %s: %s", mac, exc)
                counts["error"] += 1
                results.append({"mac": mac, "status": "error", "url": ""})
                time.sleep(_API_DELAY)
                continue

            time.sleep(_API_DELAY)

            if url:
                if url == existing_url:
                    log.debug("UNCHANGED %s — URL already matches", mac)
                    counts["skipped"] += 1
                    continue

                log.info("%s %s → %s", "DRY-RUN" if dry_run else "MATCH", mac, url)
                if not dry_run:
                    try:
                        mac_obj.update({"custom_fields": {"external_url": url}})
                    except Exception as exc:
                        log.error("Failed to update NetBox for %s: %s", mac, exc)
                        counts["error"] += 1
                        results.append({"mac": mac, "status": "error", "url": url})
                        continue

                counts["matched"] += 1
                results.append({"mac": mac, "status": "matched", "url": url})
            else:
                log.debug("NO MATCH %s", mac)
                counts["no_match"] += 1

    _print_results(results, dry_run)
    return counts


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _print_results(results: list[dict], dry_run: bool) -> None:
    if not results:
        return

    t = Table(
        title="CrowdStrike enrichment results" + (" [dry-run]" if dry_run else ""),
        show_lines=True,
    )
    t.add_column("MAC address",   style="cyan")
    t.add_column("Status")
    t.add_column("Falcon URL")

    for r in results:
        status = r["status"]
        style  = "green" if status == "matched" else "red"
        t.add_row(r["mac"], f"[{style}]{status}[/{style}]", r["url"])

    console.print(t)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.command()
@click.option("--token-file", default=None, metavar="PATH",
              help=f"Path to CS_FEM_TOKEN credential file (default: ./{_DEFAULT_TOKEN_FILE})")
@click.option("--overwrite", is_flag=True,
              help="Re-check and overwrite MACs that already have an external_url.")
@click.option("--dry-run", is_flag=True,
              help="Query CrowdStrike but do not write anything to NetBox.")
@click.option("--verbose", "-v", is_flag=True)
def cli(token_file, overwrite, dry_run, verbose):
    """Match NetBox MAC addresses to CrowdStrike assets and store the device page URL."""
    logging.basicConfig(
        format="%(levelname)-8s %(name)s: %(message)s",
        level=logging.DEBUG if verbose else logging.INFO,
    )

    nb     = pynetbox.api(config.NETBOX_URL, token=config.NETBOX_TOKEN)
    falcon = FalconClient.from_token_file(token_file)

    if dry_run:
        console.print("[yellow]Dry-run mode — no changes will be written to NetBox.[/yellow]")

    counts = run_enrichment(nb, falcon, overwrite=overwrite, dry_run=dry_run)

    action = "would be updated" if dry_run else "updated"
    console.print(
        f"\n[bold]Done.[/bold]  "
        f"[green]{counts['matched']} matched ({action})[/green]  "
        f"[dim]{counts['skipped']} skipped[/dim]  "
        f"[dim]{counts['no_match']} no match[/dim]"
        + (f"  [red]{counts['error']} error(s)[/red]" if counts["error"] else "")
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_dash(mac: str) -> str:
    """Normalise a MAC to lowercase dash-separated (Falcon's internal format)."""
    digits = mac.lower().replace(":", "").replace("-", "").replace(".", "")
    return "-".join(digits[i:i + 2] for i in range(0, 12, 2))


if __name__ == "__main__":
    cli()
