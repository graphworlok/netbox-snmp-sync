"""
Django management command: python manage.py sync_snmp

Reads configuration from:
  - The SyncSchedule DB record (seed IPs, max_depth, max_workers)
  - SNMPCredential DB records (ordered by priority)
  - Django PLUGINS_CONFIG['netbox_snmp_sync'] (netbox_url, netbox_token, etc.)

Then runs the SNMP discovery + NetBox sync engine and writes a SyncLog record.
"""

import logging
import traceback
from datetime import datetime, timezone

from django.conf import settings
from django.core.management.base import BaseCommand

from netbox_snmp_sync.engine import config as engine_config
from netbox_snmp_sync.models import SyncLog, SyncSchedule, SNMPCredential
from netbox_snmp_sync.choices import SyncStatusChoices

log = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Run a manual SNMP discovery and NetBox sync."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            default=False,
            help="Perform discovery but do not write changes to NetBox.",
        )
        parser.add_argument(
            "--seed",
            nargs="+",
            metavar="IP",
            help="Override seed IPs (space-separated). Skips SyncSchedule seed_ips.",
        )
        parser.add_argument(
            "--depth",
            type=int,
            default=None,
            metavar="N",
            help="Override max CDP/LLDP discovery depth.",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]

        # ------------------------------------------------------------------ #
        # 1. Load plugin settings
        # ------------------------------------------------------------------ #
        plugin_cfg = getattr(settings, "PLUGINS_CONFIG", {}).get("netbox_snmp_sync", {})

        netbox_url   = plugin_cfg.get("netbox_url", "")
        netbox_token = plugin_cfg.get("netbox_token", "")

        if not netbox_url or not netbox_token:
            self.stderr.write(
                self.style.ERROR(
                    "netbox_url and netbox_token must be set in "
                    "PLUGINS_CONFIG['netbox_snmp_sync'] in configuration.py"
                )
            )
            return

        # ------------------------------------------------------------------ #
        # 2. Load schedule + credentials from DB
        # ------------------------------------------------------------------ #
        schedule, _ = SyncSchedule.objects.get_or_create(pk=1)

        seed_ips = options["seed"] or schedule.seed_ip_list()
        if not seed_ips:
            self.stderr.write(
                self.style.WARNING(
                    "No seed IPs configured. Add IPs in the Schedule page or pass --seed."
                )
            )
            return

        max_depth   = options["depth"] if options["depth"] is not None else schedule.max_depth
        max_workers = schedule.max_workers

        credentials = [
            c.to_config_dict()
            for c in SNMPCredential.objects.order_by("priority", "name")
        ]
        if not credentials:
            self.stderr.write(
                self.style.WARNING(
                    "No SNMP credentials configured. Add credentials in "
                    "Configuration → SNMP Credentials."
                )
            )
            return

        # ------------------------------------------------------------------ #
        # 3. Patch the engine config module
        # ------------------------------------------------------------------ #
        engine_config.NETBOX_URL          = netbox_url
        engine_config.NETBOX_TOKEN        = netbox_token
        engine_config.SNMP_CREDENTIALS    = credentials
        engine_config.DISCOVERY_MAX_DEPTH = max_depth
        engine_config.SNMP_WORKERS        = max_workers
        engine_config.AUTO_DISCOVER_NEIGHBORS = plugin_cfg.get(
            "auto_discover_neighbors", True
        )
        engine_config.DEFAULT_SITE_SLUG        = plugin_cfg.get(
            "default_site_slug", "default"
        )
        engine_config.DEFAULT_DEVICE_ROLE_SLUG = plugin_cfg.get(
            "default_device_role_slug", "network"
        )
        engine_config.OUI_FILE = plugin_cfg.get("oui_file", "")

        # ------------------------------------------------------------------ #
        # 4. Create a SyncLog record
        # ------------------------------------------------------------------ #
        sync_log = SyncLog.objects.create(status=SyncStatusChoices.RUNNING)

        self.stdout.write(
            f"Starting SNMP sync  |  seeds={len(seed_ips)}  depth={max_depth}  "
            f"workers={max_workers}  dry_run={dry_run}"
        )

        # ------------------------------------------------------------------ #
        # 5. Run the engine
        # ------------------------------------------------------------------ #
        try:
            from netbox_snmp_sync.engine.discovery import run as discover
            from netbox_snmp_sync.engine.sync import (
                drift_device,
                apply_report,
                sync_cables,
                sync_mac_table,
            )
            from netbox_snmp_sync.engine.netbox_client import NetBoxClient

            result  = discover(seed_ips)
            devices = result.collected
            self.stdout.write(f"Discovery complete: {len(devices)} device(s) collected.")

            nb = NetBoxClient(netbox_url, netbox_token, dry_run=dry_run)

            objects_written = 0
            errors = []

            for info in devices:
                try:
                    report = drift_device(info, nb)
                    objects_written += apply_report(report, nb)
                except Exception as exc:
                    msg = f"Error syncing {info.display_name}: {exc}"
                    log.error(msg)
                    self.stderr.write(f"  {msg}")
                    errors.append(msg)

            try:
                cable_count = sync_cables(devices, nb, dry_run=dry_run)
                self.stdout.write(f"Cables synced: {cable_count}")
            except Exception as exc:
                log.error("Cable sync failed: %s", exc)
                errors.append(f"Cable sync failed: {exc}")

            mac_counts: dict = {}
            try:
                mac_counts = sync_mac_table(devices, nb, dry_run=dry_run)
                macs_total = sum(mac_counts.values()) if isinstance(mac_counts, dict) else int(mac_counts)
                self.stdout.write(f"MACs synced: {macs_total}")
            except Exception as exc:
                log.error("MAC sync failed: %s", exc)
                errors.append(f"MAC sync failed: {exc}")
                macs_total = 0

            sync_log.status            = SyncStatusChoices.FAILED if errors else SyncStatusChoices.SUCCESS
            sync_log.devices_seen      = len(devices)
            sync_log.interfaces_synced = objects_written
            sync_log.macs_synced       = macs_total
            sync_log.completed_at      = datetime.now(tz=timezone.utc)
            if errors:
                sync_log.message = "\n".join(errors[:10])  # cap at 10 error lines
            sync_log.save()

            if errors:
                self.stdout.write(self.style.WARNING(f"Sync finished with {len(errors)} error(s)."))
            else:
                self.stdout.write(self.style.SUCCESS("Sync complete."))

        except Exception as exc:
            sync_log.status       = SyncStatusChoices.FAILED
            sync_log.completed_at = datetime.now(tz=timezone.utc)
            sync_log.message      = traceback.format_exc()
            sync_log.save()
            self.stderr.write(self.style.ERROR(f"Sync failed: {exc}"))
            raise

        # Update schedule last_run metadata
        schedule.last_run_at     = sync_log.completed_at
        schedule.last_run_status = sync_log.status
        schedule.save(update_fields=["last_run_at", "last_run_status"])
