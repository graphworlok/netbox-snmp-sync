from django.contrib import messages
from django.shortcuts import redirect, render
from django.views import View

from ..forms import SyncScheduleForm
from ..models import SyncSchedule


def _get_schedule() -> SyncSchedule:
    obj, _ = SyncSchedule.objects.get_or_create(pk=1)
    return obj


class SyncScheduleView(View):
    template_name = "netbox_snmp_sync/schedule.html"

    def get(self, request):
        schedule = _get_schedule()
        return render(request, self.template_name, {"schedule": schedule})


class SyncScheduleEditView(View):
    template_name = "netbox_snmp_sync/schedule_edit.html"

    def get(self, request):
        schedule = _get_schedule()
        form     = SyncScheduleForm(instance=schedule)
        return render(request, self.template_name, {"form": form, "schedule": schedule})

    def post(self, request):
        schedule = _get_schedule()
        form     = SyncScheduleForm(request.POST, instance=schedule)
        if form.is_valid():
            form.save()
            messages.success(request, "Sync schedule saved.")
            return redirect("plugins:netbox_snmp_sync:schedule")
        return render(request, self.template_name, {"form": form, "schedule": schedule})
