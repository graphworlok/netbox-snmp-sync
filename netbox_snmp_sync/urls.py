from django.urls import path

from . import views

app_name = "netbox_snmp_sync"

urlpatterns = [
    # Sync logs
    path("sync-logs/",               views.SyncLogListView.as_view(),          name="synclog_list"),
    path("sync-logs/<int:pk>/",      views.SyncLogView.as_view(),              name="synclog"),

    # SNMP credentials
    path("credentials/",             views.SNMPCredentialListView.as_view(),   name="credential_list"),
    path("credentials/add/",         views.SNMPCredentialEditView.as_view(),   name="credential_add"),
    path("credentials/<int:pk>/",    views.SNMPCredentialView.as_view(),       name="credential"),
    path("credentials/<int:pk>/edit/",   views.SNMPCredentialEditView.as_view(),   name="credential_edit"),
    path("credentials/<int:pk>/delete/", views.SNMPCredentialDeleteView.as_view(), name="credential_delete"),

    # Learned MACs
    path("learned-macs/",                  views.LearnedMACListView.as_view(),   name="learned_mac_list"),
    path("learned-macs/mark-stale/",       views.LearnedMACMarkStaleView.as_view(), name="learned_mac_mark_stale"),
    path("learned-macs/<int:pk>/",         views.LearnedMACView.as_view(),       name="learned_mac"),
    path("learned-macs/<int:pk>/promote/", views.LearnedMACPromoteView.as_view(), name="learned_mac_promote"),

    # OUI databases
    path("oui/",          views.OUIDatabaseListView.as_view(), name="oui_list"),
    path("oui/download/", views.OUIDownloadView.as_view(),     name="oui_download"),

    # Sync schedule
    path("schedule/",      views.SyncScheduleView.as_view(),     name="schedule"),
    path("schedule/edit/", views.SyncScheduleEditView.as_view(), name="schedule_edit"),
]
