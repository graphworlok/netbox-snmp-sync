import django_filters

from .choices import SyncStatusChoices, SNMPVersionChoices, LearnedMACStatusChoices, MACEntryTypeChoices
from .models import SyncLog, SNMPCredential, LearnedMAC


class SyncLogFilterSet(django_filters.FilterSet):
    q      = django_filters.CharFilter(method="search", label="Search")
    status = django_filters.ChoiceFilter(choices=SyncStatusChoices)

    class Meta:
        model  = SyncLog
        fields = ["status"]

    def search(self, queryset, name, value):
        return queryset.filter(message__icontains=value)


class SNMPCredentialFilterSet(django_filters.FilterSet):
    q       = django_filters.CharFilter(method="search", label="Search")
    version = django_filters.ChoiceFilter(choices=SNMPVersionChoices)

    class Meta:
        model  = SNMPCredential
        fields = ["version"]

    def search(self, queryset, name, value):
        return queryset.filter(name__icontains=value)


class LearnedMACFilterSet(django_filters.FilterSet):
    q          = django_filters.CharFilter(method="search", label="Search")
    status     = django_filters.ChoiceFilter(choices=LearnedMACStatusChoices)
    entry_type = django_filters.ChoiceFilter(choices=MACEntryTypeChoices)
    vlan       = django_filters.NumberFilter()

    class Meta:
        model  = LearnedMAC
        fields = ["status", "entry_type", "vlan"]

    def search(self, queryset, name, value):
        return (
            queryset.filter(mac_address__icontains=value)
            | queryset.filter(vendor__icontains=value)
            | queryset.filter(source_device_name__icontains=value)
            | queryset.filter(source_interface__icontains=value)
        )
