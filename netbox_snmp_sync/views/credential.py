from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
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


class SNMPCredentialEditView(View):
    """
    Add / edit an SNMPCredential using a plain Django view.

    generic.ObjectEditView expects a NetBoxModel (for snapshot/change-logging).
    SNMPCredential is a plain Django model, so we handle the form ourselves.
    """
    template_name = "netbox_snmp_sync/credential_edit.html"

    def _get_object(self, pk=None):
        if pk:
            return get_object_or_404(SNMPCredential, pk=pk)
        return SNMPCredential()

    def get(self, request, pk=None):
        obj  = self._get_object(pk)
        form = SNMPCredentialForm(instance=obj)
        return render(request, self.template_name, {"object": obj, "form": form})

    def post(self, request, pk=None):
        obj  = self._get_object(pk)
        form = SNMPCredentialForm(request.POST, instance=obj)
        if form.is_valid():
            credential = form.save()
            messages.success(request, f"SNMP credential '{credential.name}' saved.")
            return redirect(credential.get_absolute_url())
        return render(request, self.template_name, {"object": obj, "form": form})


class SNMPCredentialDeleteView(View):
    template_name = "generic/object_delete.html"

    def get(self, request, pk):
        obj = get_object_or_404(SNMPCredential, pk=pk)
        return render(request, self.template_name, {
            "object": obj,
            "object_type": SNMPCredential._meta.verbose_name,
            "return_url": obj.get_absolute_url(),
        })

    def post(self, request, pk):
        obj = get_object_or_404(SNMPCredential, pk=pk)
        name = obj.name
        obj.delete()
        messages.success(request, f"SNMP credential '{name}' deleted.")
        return redirect("plugins:netbox_snmp_sync:credential_list")
