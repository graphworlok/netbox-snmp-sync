# ---------------------------------------------------------------------------
# Engine configuration — defaults that are patched at runtime by the
# sync_snmp management command before any engine code runs.
# ---------------------------------------------------------------------------

NETBOX_URL   = ""
NETBOX_TOKEN = ""

SNMP_CREDENTIALS: list[dict] = []
DEVICE_CREDENTIALS: dict[str, list[dict]] = {}

SNMP_PORT    = 161
SNMP_TIMEOUT = 5
SNMP_RETRIES = 2

SNMP_TIMEOUT_SLOW = 30
SNMP_RETRIES_SLOW = 3

SNMP_WORKERS    = 10
NETBOX_WORKERS  = 5

AUTO_DISCOVER_NEIGHBORS = True
DISCOVERY_MAX_DEPTH     = 2

DEFAULT_CREATE_MISSING = True

CISCO_MANUFACTURER_SLUG = "cisco"

DEFAULT_SITE_SLUG        = "default"
DEFAULT_DEVICE_ROLE_SLUG = "network"

CS_WORKSTATION_ROLE_SLUG      = "workstation"
CS_SERVER_ROLE_SLUG           = "server"
EPHEMERAL_ENDPOINT_ROLE_SLUG  = "ephemeral-endpoint"
UNMANAGED_SWITCH_ROLE_SLUG    = "unmanaged-switch"

MERAKI_API_KEY = ""

OUI_FILE = ""

CS_CACHE_FILE    = ""
CS_CACHE_MAX_AGE = 86400
