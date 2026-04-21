from django.db import models
from django.urls import reverse
from utilities.queryset import RestrictedQuerySet


class SyncSchedule(models.Model):
    objects = RestrictedQuerySet.as_manager()

    """
    Singleton model storing the SNMP sync schedule and seed configuration.
    Only one row should exist (pk=1); views use get_or_create to enforce this.

    The actual execution is triggered externally (cron / systemd timer / etc.)
    using the management command:  python manage.py sync_snmp

    This model exposes the schedule configuration in the NetBox GUI so
    operators can review and adjust seed IPs without editing files.
    """
    enabled = models.BooleanField(
        default=False,
        help_text="Whether scheduled syncs are active (informational — external scheduler reads this).",
    )
    cron_expression = models.CharField(
        max_length=100,
        blank=True,
        default="0 2 * * *",
        help_text="Cron expression for the sync schedule, e.g. '0 2 * * *' for 2 AM daily.",
    )
    seed_ips = models.TextField(
        blank=True,
        help_text="One IP address per line. These are the starting points for SNMP discovery.",
    )
    max_depth = models.PositiveSmallIntegerField(
        default=2,
        help_text="Maximum CDP/LLDP neighbour hops to follow from seed IPs.",
    )
    max_workers = models.PositiveSmallIntegerField(
        default=8,
        help_text="Concurrent SNMP threads during a discovery run.",
    )
    last_run_at  = models.DateTimeField(null=True, blank=True)
    last_run_status = models.CharField(max_length=20, blank=True)

    class Meta:
        verbose_name = "Sync Schedule"
        verbose_name_plural = "Sync Schedule"

    def __str__(self) -> str:
        return "SNMP Sync Schedule"

    def get_absolute_url(self) -> str:
        return reverse("plugins:netbox_snmp_sync:schedule")

    def seed_ip_list(self) -> list[str]:
        return [ip.strip() for ip in self.seed_ips.splitlines() if ip.strip()]
