from netbox.plugins import PluginConfig


class SNMPSyncConfig(PluginConfig):
    name = "netbox_snmp_sync"
    verbose_name = "SNMP Sync"
    description = "Discover and synchronise devices into NetBox via SNMP"
    version = "0.1.0"
    author = "graphworlok"
    base_url = "snmp"
    min_version = "4.0.0"

    default_settings = {
        # SNMP transport settings
        "snmp_port": 161,
        "snmp_timeout": 5,
        "snmp_retries": 2,
        # Settings used when --slow mode is active
        "snmp_timeout_slow": 30,
        "snmp_retries_slow": 3,
        # Path to a local CrowdStrike asset cache JSON file (optional enrichment)
        "cs_asset_cache": "",
        # Path(s) to IEEE OUI CSV files for vendor lookup. Empty = disabled.
        "oui_file": "",
        # Directory where OUI CSV files are downloaded to via the GUI.
        # Defaults to a 'oui' subdirectory inside Django's MEDIA_ROOT.
        "oui_storage_path": "",
    }


config = SNMPSyncConfig
