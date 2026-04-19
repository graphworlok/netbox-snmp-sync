from django.db import models
from django.urls import reverse
from django.utils import timezone

from ..choices import LearnedMACStatusChoices, MACEntryTypeChoices


class LearnedMAC(models.Model):
    """
    A MAC address learned from a device's SNMP bridge forwarding table.
    Records accumulate across sync runs; status reflects the most recent run.
    """
    mac_address = models.CharField(max_length=17, db_index=True)
    vendor      = models.CharField(max_length=200, blank=True)

    # Where it was seen
    source_device_ip   = models.GenericIPAddressField(db_index=True)
    source_device_name = models.CharField(max_length=200, blank=True)
    source_interface   = models.CharField(max_length=100, blank=True)
    vlan               = models.PositiveSmallIntegerField(default=0)

    entry_type = models.CharField(
        max_length=10,
        choices=MACEntryTypeChoices,
        default=MACEntryTypeChoices.LEARNED,
        db_index=True,
    )
    status = models.CharField(
        max_length=10,
        choices=LearnedMACStatusChoices,
        default=LearnedMACStatusChoices.NEW,
        db_index=True,
    )

    first_seen = models.DateTimeField(auto_now_add=True, db_index=True)
    last_seen  = models.DateTimeField(default=timezone.now, db_index=True)

    # Set when promoted to a NetBox device
    promoted_to_device_id = models.PositiveIntegerField(null=True, blank=True)
    promoted_at           = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-last_seen"]
        # A MAC can appear on multiple devices (e.g. on uplink ports of two switches)
        unique_together = [("mac_address", "source_device_ip")]
        verbose_name = "Learned MAC"
        verbose_name_plural = "Learned MACs"

    def __str__(self) -> str:
        return self.mac_address

    def get_absolute_url(self) -> str:
        return reverse("plugins:netbox_snmp_sync:learned_mac", args=[self.pk])

    def get_status_color(self) -> str:
        return LearnedMACStatusChoices.colors.get(self.status, "secondary")

    def get_entry_type_color(self) -> str:
        return MACEntryTypeChoices.colors.get(self.entry_type, "secondary")

    @property
    def is_promotable(self) -> bool:
        return self.status != LearnedMACStatusChoices.PROMOTED
