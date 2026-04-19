import os

from django.db import models
from django.urls import reverse

from ..choices import OUIRegistryChoices


class OUIDatabase(models.Model):
    """
    One row per IEEE OUI registry (MA-L, MA-M, MA-S).
    Tracks where the file is stored, when it was last downloaded, and how many
    entries it contains.  The download path is written into the plugin's
    configured oui_storage_path directory.
    """
    registry = models.CharField(
        max_length=10,
        choices=OUIRegistryChoices,
        unique=True,
        db_index=True,
    )
    local_path       = models.CharField(max_length=500, blank=True)
    last_downloaded  = models.DateTimeField(null=True, blank=True)
    entry_count      = models.PositiveIntegerField(default=0)
    last_error       = models.TextField(blank=True)

    class Meta:
        ordering = ["registry"]
        verbose_name = "OUI Database"
        verbose_name_plural = "OUI Databases"

    def __str__(self) -> str:
        return f"IEEE {self.registry}"

    def get_absolute_url(self) -> str:
        return reverse("plugins:netbox_snmp_sync:oui_list")

    @property
    def download_url(self) -> str:
        return OUIRegistryChoices.DOWNLOAD_URLS.get(self.registry, "")

    @property
    def file_exists(self) -> bool:
        return bool(self.local_path) and os.path.isfile(self.local_path)

    @property
    def file_size_kb(self) -> int | None:
        if self.file_exists:
            return os.path.getsize(self.local_path) // 1024
        return None

    def get_registry_color(self) -> str:
        return OUIRegistryChoices.colors.get(self.registry, "secondary")
