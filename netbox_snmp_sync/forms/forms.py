from django import forms

from ..choices import (
    SyncStatusChoices, SNMPVersionChoices, SNMPAuthProtocolChoices, SNMPPrivProtocolChoices,
    LearnedMACStatusChoices, MACEntryTypeChoices, OUIRegistryChoices,
)
from ..models import SNMPCredential, SyncSchedule


class SyncLogFilterForm(forms.Form):
    q = forms.CharField(
        required=False,
        label="Search",
        widget=forms.TextInput(attrs={"placeholder": "Search message…"}),
    )
    status = forms.ChoiceField(
        required=False,
        choices=[("", "Any status")] + list(SyncStatusChoices),
        label="Status",
    )


class SNMPCredentialFilterForm(forms.Form):
    q = forms.CharField(
        required=False,
        label="Search",
        widget=forms.TextInput(attrs={"placeholder": "Credential name…"}),
    )
    version = forms.ChoiceField(
        required=False,
        choices=[("", "Any version")] + list(SNMPVersionChoices),
        label="Version",
    )


class SNMPCredentialForm(forms.ModelForm):
    class Meta:
        model  = SNMPCredential
        fields = [
            "name", "priority", "version",
            "community",
            "username", "auth_protocol", "auth_key", "priv_protocol", "priv_key",
        ]
        widgets = {
            "auth_key": forms.PasswordInput(render_value=True),
            "priv_key": forms.PasswordInput(render_value=True),
        }

    def clean(self):
        cleaned = super().clean()
        version = cleaned.get("version")
        if version == "2" and not cleaned.get("community"):
            self.add_error("community", "Community string is required for SNMPv2c.")
        if version == "3" and not cleaned.get("username"):
            self.add_error("username", "Username is required for SNMPv3.")
        return cleaned


# ---------------------------------------------------------------------------
# Learned MAC forms
# ---------------------------------------------------------------------------

class LearnedMACFilterForm(forms.Form):
    q = forms.CharField(
        required=False,
        label="Search",
        widget=forms.TextInput(attrs={"placeholder": "MAC, vendor, or device…"}),
    )
    status = forms.ChoiceField(
        required=False,
        choices=[("", "Any status")] + list(LearnedMACStatusChoices),
        label="Status",
    )
    entry_type = forms.ChoiceField(
        required=False,
        choices=[("", "Any type")] + list(MACEntryTypeChoices),
        label="Entry Type",
    )
    vlan = forms.IntegerField(
        required=False,
        min_value=0,
        max_value=4094,
        label="VLAN",
        widget=forms.NumberInput(attrs={"placeholder": "VLAN ID"}),
    )


class PromoteToDeviceForm(forms.Form):
    """Form for promoting a learned MAC address to a new NetBox device."""

    hostname = forms.CharField(
        max_length=200,
        label="Device Name",
        help_text="Name for the new NetBox device.",
    )
    site = forms.ModelChoiceField(
        queryset=None,  # set in __init__
        label="Site",
        help_text="Site where the device will be placed.",
    )
    device_role = forms.ModelChoiceField(
        queryset=None,
        label="Device Role",
    )
    device_type = forms.ModelChoiceField(
        queryset=None,
        label="Device Type",
        help_text="Must already exist in NetBox.",
    )
    status = forms.ChoiceField(
        choices=[
            ("active",  "Active"),
            ("staged",  "Staged"),
            ("planned", "Planned"),
        ],
        initial="active",
    )
    comments = forms.CharField(
        required=False,
        label="Comments",
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text="Optional notes about this device.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Import NetBox models here to avoid circular imports at module load time
        from dcim.models import Site, DeviceRole, DeviceType
        self.fields["site"].queryset        = Site.objects.all().order_by("name")
        self.fields["device_role"].queryset = DeviceRole.objects.all().order_by("name")
        self.fields["device_type"].queryset = DeviceType.objects.all().order_by("model")


# ---------------------------------------------------------------------------
# OUI / Schedule forms
# ---------------------------------------------------------------------------

class OUIDownloadForm(forms.Form):
    registry = forms.ChoiceField(
        choices=OUIRegistryChoices,
        label="Registry",
        help_text="Which IEEE OUI registry to download.",
    )
    storage_path = forms.CharField(
        max_length=500,
        label="Storage Directory",
        help_text="Absolute path to the directory where the CSV file will be saved.",
        widget=forms.TextInput(attrs={"placeholder": "/opt/netbox/oui"}),
    )


class SyncScheduleForm(forms.ModelForm):
    class Meta:
        model  = SyncSchedule
        fields = ["enabled", "cron_expression", "seed_ips", "max_depth", "max_workers"]
        widgets = {
            "seed_ips": forms.Textarea(attrs={
                "rows": 8,
                "placeholder": "10.0.0.1\n10.0.0.2\n192.168.1.1",
                "style": "font-family: monospace;",
            }),
        }
        help_texts = {
            "cron_expression": "Standard 5-field cron expression. Use a tool like crontab.guru to build one.",
            "seed_ips":        "One IP address per line. Discovery fans out from these via CDP/LLDP.",
            "max_depth":       "0 = seed IPs only; 1 = seed + immediate neighbours; etc.",
        }
