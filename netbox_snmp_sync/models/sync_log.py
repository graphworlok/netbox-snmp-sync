from django.db import models
from django.urls import reverse
from utilities.queryset import RestrictedQuerySet

from ..choices import SyncStatusChoices


class SyncLog(models.Model):
    objects = RestrictedQuerySet.as_manager()

    started_at   = models.DateTimeField(auto_now_add=True, db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=SyncStatusChoices,
        default=SyncStatusChoices.PENDING,
        db_index=True,
    )
    message = models.TextField(blank=True)

    devices_seen      = models.PositiveIntegerField(default=0)
    devices_created   = models.PositiveIntegerField(default=0)
    devices_updated   = models.PositiveIntegerField(default=0)
    interfaces_synced = models.PositiveIntegerField(default=0)
    macs_synced       = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-started_at"]
        verbose_name = "Sync Log"
        verbose_name_plural = "Sync Logs"

    def __str__(self) -> str:
        return f"SNMP Sync @ {self.started_at:%Y-%m-%d %H:%M}"

    def get_absolute_url(self) -> str:
        return reverse("plugins:netbox_snmp_sync:synclog", args=[self.pk])

    @property
    def duration(self):
        if self.completed_at and self.started_at:
            return self.completed_at - self.started_at
        return None

    def get_status_color(self) -> str:
        return SyncStatusChoices.colors.get(self.status, "secondary")
