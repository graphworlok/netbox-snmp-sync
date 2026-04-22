import csv
import logging
import os
import urllib.error
import urllib.request

from django.contrib import messages
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views import View

from ..choices import OUIRegistryChoices
from ..forms import OUIDownloadForm
from ..models import OUIDatabase

log = logging.getLogger(__name__)

_DOWNLOAD_TIMEOUT = 60  # seconds — OUI files are ~5 MB


class OUIDatabaseListView(View):
    template_name = "netbox_snmp_sync/oui_list.html"

    def get(self, request):
        # Ensure one row exists per registry
        for registry in (OUIRegistryChoices.MAL, OUIRegistryChoices.MAM, OUIRegistryChoices.MAS):
            OUIDatabase.objects.get_or_create(registry=registry)
        databases = OUIDatabase.objects.all()
        form = OUIDownloadForm()
        return render(request, self.template_name, {"databases": databases, "form": form})


class OUIDownloadView(View):
    """POST-only view — trigger download of a single OUI registry CSV."""

    def post(self, request):
        form = OUIDownloadForm(request.POST)
        if not form.is_valid():
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
            return redirect("plugins:netbox_snmp_sync:oui_list")

        registry     = form.cleaned_data["registry"]
        storage_path = form.cleaned_data["storage_path"]
        url          = OUIRegistryChoices.DOWNLOAD_URLS.get(registry, "")
        filename     = OUIRegistryChoices.DEFAULT_FILENAMES.get(registry, "oui.csv")

        db_row, _ = OUIDatabase.objects.get_or_create(registry=registry)

        # Ensure the directory exists
        try:
            os.makedirs(storage_path, exist_ok=True)
        except OSError as exc:
            messages.error(request, f"Cannot create directory {storage_path}: {exc}")
            return redirect("plugins:netbox_snmp_sync:oui_list")

        dest = os.path.join(storage_path, filename)

        # Download
        try:
            log.info("Downloading OUI %s from %s → %s", registry, url, dest)
            urllib.request.urlretrieve(url, dest)
        except urllib.error.HTTPError as exc:
            error_msg = (
                f"HTTP {exc.code} {exc.msg} — server refused the request.\n"
                f"URL: {url}\n"
                f"Try manually:  wget -O {dest} \"{url}\""
            )
            db_row.last_error = error_msg
            db_row.save(update_fields=["last_error"])
            messages.error(request, f"Download failed: HTTP {exc.code} {exc.msg} — see error details below.")
            return redirect("plugins:netbox_snmp_sync:oui_list")
        except urllib.error.URLError as exc:
            reason = exc.reason if hasattr(exc, "reason") else str(exc)
            error_msg = (
                f"Connection error: {reason}\n"
                f"URL: {url}\n"
                f"Try manually:  wget -O {dest} \"{url}\""
            )
            db_row.last_error = error_msg
            db_row.save(update_fields=["last_error"])
            messages.error(request, f"Download failed: {reason} — see error details below.")
            return redirect("plugins:netbox_snmp_sync:oui_list")
        except OSError as exc:
            error_msg = (
                f"File system error: {exc}\n"
                f"Destination: {dest}\n"
                f"Try manually:  wget -O {dest} \"{url}\""
            )
            db_row.last_error = error_msg
            db_row.save(update_fields=["last_error"])
            messages.error(request, f"Download failed: {exc} — see error details below.")
            return redirect("plugins:netbox_snmp_sync:oui_list")

        # Count entries
        entry_count = _count_entries(dest)

        db_row.local_path      = dest
        db_row.last_downloaded = timezone.now()
        db_row.entry_count     = entry_count
        db_row.last_error      = ""
        db_row.save()

        messages.success(
            request,
            f"Downloaded IEEE {registry} ({entry_count:,} entries) to {dest}.",
        )
        return redirect("plugins:netbox_snmp_sync:oui_list")


def _count_entries(path: str) -> int:
    count = 0
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if len(row) < 3:
                    continue
                assignment = row[1].strip().lower()
                if assignment in ("", "assignment"):
                    continue
                try:
                    int(assignment, 16)
                    count += 1
                except ValueError:
                    continue
    except OSError:
        pass
    return count
