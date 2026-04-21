import django_tables2 as tables
from netbox.tables import NetBoxTable, columns

from ..models import SyncLog, SNMPCredential, LearnedMAC


class SyncLogTable(NetBoxTable):
    started_at        = tables.DateTimeColumn(verbose_name="Started")
    completed_at      = tables.DateTimeColumn(verbose_name="Completed", orderable=True)
    status            = columns.ChoiceFieldColumn(verbose_name="Status")
    devices_seen      = tables.Column(verbose_name="Seen")
    devices_created   = tables.Column(verbose_name="Created")
    devices_updated   = tables.Column(verbose_name="Updated")
    interfaces_synced = tables.Column(verbose_name="Interfaces")
    macs_synced       = tables.Column(verbose_name="MACs")
    actions           = columns.ActionsColumn(actions=())

    class Meta(NetBoxTable.Meta):
        model = SyncLog
        fields = (
            "pk", "status", "started_at", "completed_at",
            "devices_seen", "devices_created", "devices_updated",
            "interfaces_synced", "macs_synced",
        )
        default_columns = (
            "status", "started_at", "devices_seen", "devices_created", "devices_updated",
        )


class SNMPCredentialTable(NetBoxTable):
    name     = tables.Column(linkify=True)
    priority = tables.Column()
    version  = columns.ChoiceFieldColumn()
    community = tables.Column()
    username  = tables.Column()
    actions   = columns.ActionsColumn(actions=("edit", "delete"))

    class Meta(NetBoxTable.Meta):
        model = SNMPCredential
        fields = ("pk", "name", "priority", "version", "community", "username", "actions")
        default_columns = ("name", "priority", "version", "community", "username", "actions")


class LearnedMACTable(NetBoxTable):
    mac_address        = tables.Column(linkify=True, verbose_name="MAC Address")
    vendor             = tables.Column(verbose_name="Vendor")
    source_device_name = tables.Column(verbose_name="Source Device")
    source_interface   = tables.Column(verbose_name="Interface")
    vlan               = tables.Column(verbose_name="VLAN")
    entry_type         = columns.ChoiceFieldColumn(verbose_name="Type")
    status             = columns.ChoiceFieldColumn(verbose_name="Status")
    last_seen          = tables.DateTimeColumn(verbose_name="Last Seen")
    first_seen         = tables.DateTimeColumn(verbose_name="First Seen")
    promote            = tables.TemplateColumn(
        template_code=(
            "{% if record.is_promotable %}"
            "<a href=\"{% url 'plugins:netbox_snmp_sync:learned_mac_promote' record.pk %}\" "
            "class=\"btn btn-xs btn-success\" title=\"Promote to Device\">"
            "<i class=\"mdi mdi-arrow-up-circle\"></i></a>"
            "{% endif %}"
        ),
        verbose_name="",
        orderable=False,
    )

    actions = columns.ActionsColumn(actions=())

    class Meta(NetBoxTable.Meta):
        model = LearnedMAC
        fields = (
            "pk", "mac_address", "vendor", "source_device_name", "source_interface",
            "vlan", "entry_type", "status", "last_seen", "first_seen", "promote",
        )
        default_columns = (
            "mac_address", "vendor", "source_device_name", "source_interface",
            "vlan", "status", "last_seen", "promote",
        )
