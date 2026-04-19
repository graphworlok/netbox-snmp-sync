from netbox.views import generic

from ..filtersets import SNMPCredentialFilterSet
from ..forms import SNMPCredentialForm, SNMPCredentialFilterForm
from ..models import SNMPCredential
from ..tables import SNMPCredentialTable


class SNMPCredentialListView(generic.ObjectListView):
    queryset       = SNMPCredential.objects.all()
    table          = SNMPCredentialTable
    filterset      = SNMPCredentialFilterSet
    filterset_form = SNMPCredentialFilterForm
    template_name  = "netbox_snmp_sync/credential_list.html"


class SNMPCredentialView(generic.ObjectView):
    queryset      = SNMPCredential.objects.all()
    template_name = "netbox_snmp_sync/credential.html"


class SNMPCredentialEditView(generic.ObjectEditView):
    queryset      = SNMPCredential.objects.all()
    form_class    = SNMPCredentialForm
    template_name = "netbox_snmp_sync/credential_edit.html"


class SNMPCredentialDeleteView(generic.ObjectDeleteView):
    queryset = SNMPCredential.objects.all()
