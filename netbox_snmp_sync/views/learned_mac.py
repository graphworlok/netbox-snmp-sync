from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views import View
from netbox.views import generic

from ..choices import LearnedMACStatusChoices
from ..filtersets import LearnedMACFilterSet
from ..forms import LearnedMACFilterForm, PromoteToDeviceForm
from ..models import LearnedMAC
from ..tables import LearnedMACTable


class LearnedMACListView(generic.ObjectListView):
    queryset       = LearnedMAC.objects.all()
    table          = LearnedMACTable
    filterset      = LearnedMACFilterSet
    filterset_form = LearnedMACFilterForm
    template_name  = "netbox_snmp_sync/learned_mac_list.html"


class LearnedMACView(generic.ObjectView):
    queryset      = LearnedMAC.objects.all()
    template_name = "netbox_snmp_sync/learned_mac.html"


class LearnedMACPromoteView(View):
    template_name = "netbox_snmp_sync/learned_mac_promote.html"

    def get(self, request, pk):
        mac  = get_object_or_404(LearnedMAC, pk=pk)
        if not mac.is_promotable:
            messages.warning(request, f"{mac.mac_address} has already been promoted to a device.")
            return redirect(mac.get_absolute_url())
        form = PromoteToDeviceForm(initial={
            "hostname": mac.source_device_name or "",
            "status":   "active",
        })
        return render(request, self.template_name, {"mac": mac, "form": form})

    def post(self, request, pk):
        from dcim.models import Device
        mac  = get_object_or_404(LearnedMAC, pk=pk)
        form = PromoteToDeviceForm(request.POST)
        if form.is_valid():
            cd = form.cleaned_data
            device = Device.objects.create(
                name        = cd["hostname"],
                site        = cd["site"],
                role        = cd["device_role"],
                device_type = cd["device_type"],
                status      = cd["status"],
                comments    = cd.get("comments", ""),
            )
            mac.status                 = LearnedMACStatusChoices.PROMOTED
            mac.promoted_to_device_id  = device.pk
            mac.promoted_at            = timezone.now()
            mac.save(update_fields=["status", "promoted_to_device_id", "promoted_at"])
            messages.success(request, f"Device '{device.name}' created from MAC {mac.mac_address}.")
            return redirect(device.get_absolute_url())
        return render(request, self.template_name, {"mac": mac, "form": form})


class LearnedMACMarkStaleView(View):
    """Mark all MACs not seen since a given sync run as stale."""

    def post(self, request):
        cutoff = request.POST.get("cutoff_hours", 48)
        try:
            cutoff = int(cutoff)
        except (TypeError, ValueError):
            cutoff = 48
        threshold = timezone.now() - timezone.timedelta(hours=cutoff)
        count = LearnedMAC.objects.filter(
            last_seen__lt=threshold,
            status=LearnedMACStatusChoices.ACTIVE,
        ).update(status=LearnedMACStatusChoices.STALE)
        messages.success(request, f"Marked {count} MAC address(es) as stale (not seen in {cutoff}h).")
        return redirect("plugins:netbox_snmp_sync:learned_mac_list")
