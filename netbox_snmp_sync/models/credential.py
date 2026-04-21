from django.db import models
from django.urls import reverse
from utilities.queryset import RestrictedQuerySet

from ..choices import SNMPVersionChoices, SNMPAuthProtocolChoices, SNMPPrivProtocolChoices


class SNMPCredential(models.Model):
    objects = RestrictedQuerySet.as_manager()

    """
    An SNMP credential profile tried in priority order during device polling.
    Credentials are tried lowest priority value first (0 = highest priority).
    """
    name     = models.CharField(max_length=100, unique=True)
    priority = models.PositiveSmallIntegerField(
        default=10,
        help_text="Lower values are tried first.",
    )
    version = models.CharField(
        max_length=2,
        choices=SNMPVersionChoices,
        default=SNMPVersionChoices.V2,
    )
    # SNMPv2c
    community = models.CharField(
        max_length=200,
        blank=True,
        help_text="Community string (SNMPv2c only).",
    )
    # SNMPv3
    username = models.CharField(
        max_length=200,
        blank=True,
        help_text="Username (SNMPv3 only).",
    )
    auth_protocol = models.CharField(
        max_length=10,
        choices=SNMPAuthProtocolChoices,
        blank=True,
        help_text="Authentication protocol (SNMPv3 only).",
    )
    auth_key = models.CharField(
        max_length=200,
        blank=True,
        help_text="Authentication key (SNMPv3 only). Stored in plaintext.",
    )
    priv_protocol = models.CharField(
        max_length=10,
        choices=SNMPPrivProtocolChoices,
        blank=True,
        help_text="Privacy protocol (SNMPv3 only).",
    )
    priv_key = models.CharField(
        max_length=200,
        blank=True,
        help_text="Privacy key (SNMPv3 only). Stored in plaintext.",
    )

    class Meta:
        ordering = ["priority", "name"]
        verbose_name = "SNMP Credential"
        verbose_name_plural = "SNMP Credentials"

    def __str__(self) -> str:
        return f"{self.name} (v{self.version})"

    def get_absolute_url(self) -> str:
        return reverse("plugins:netbox_snmp_sync:credential", args=[self.pk])

    def get_version_color(self) -> str:
        return SNMPVersionChoices.colors.get(self.version, "secondary")

    def to_config_dict(self) -> dict:
        d: dict = {"name": self.name, "version": int(self.version)}
        if self.version == SNMPVersionChoices.V2:
            d["community"] = self.community
        else:
            d["username"] = self.username
            if self.auth_protocol:
                d["auth_protocol"] = self.auth_protocol
                d["auth_key"]      = self.auth_key
            if self.priv_protocol:
                d["priv_protocol"] = self.priv_protocol
                d["priv_key"]      = self.priv_key
        return d
