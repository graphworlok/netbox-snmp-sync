"""
MAC address enrichment — attach external-tool links to bridge forwarding table
entries before they are written to the NetBox mac_table custom field.

Architecture
------------
Any external tool is represented by a *provider* — a small object that:
  - has a ``name`` attribute (str)  used as the JSON key: ``{name}_url``
  - implements ``lookup_mac(mac: str) -> Optional[str]``

Providers are registered with :class:`MacEnricher`, which calls each one for
every MAC in the table and injects the returned URL into the entry dict.
URL keys are only added when a match is found — absent means no record in that
tool, not an error.

Adding a new tool
-----------------
1. Implement the :class:`MacLookupProvider` protocol (or subclass
   :class:`BaseMacProvider` for free caching + MAC normalisation).
2. Instantiate it in ``MacEnricher.from_config()`` when the relevant
   config keys are present.
3. Add the config keys to ``config.py``.

No changes to ``sync.py`` are required.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

log = logging.getLogger(__name__)

# Name of the CrowdStrike credential file loaded from the user's CWD
_CS_TOKEN_FILENAME = "CS_FEM_TOKEN"


# ---------------------------------------------------------------------------
# Provider protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class MacLookupProvider(Protocol):
    """
    Minimal interface every enrichment provider must satisfy.

    ``name`` is used to derive the JSON key written into the mac_table entry::

        entry[f"{provider.name}_url"] = url
    """
    name: str

    def lookup_mac(self, mac: str) -> Optional[str]:
        """Return a URL to the record for *mac* in this tool, or None."""
        ...


# ---------------------------------------------------------------------------
# Convenience base class  (optional — providers need not inherit from it)
# ---------------------------------------------------------------------------

class BaseMacProvider:
    """
    Shared helpers: MAC normalisation and an in-memory result cache.

    Subclasses must set ``self.name`` and implement ``_fetch(mac_norm)``.
    The normalised MAC passed to ``_fetch`` is always lowercase
    colon-separated (``aa:bb:cc:dd:ee:ff``).
    """
    name: str = "unknown"

    def __init__(self) -> None:
        self._cache: dict[str, Optional[str]] = {}

    def lookup_mac(self, mac: str) -> Optional[str]:
        mac_norm = _normalise_mac(mac)
        if mac_norm not in self._cache:
            self._cache[mac_norm] = self._fetch(mac_norm)
        return self._cache[mac_norm]

    def _fetch(self, mac_norm: str) -> Optional[str]:  # pragma: no cover
        raise NotImplementedError


# ---------------------------------------------------------------------------
# CrowdStrike Falcon provider  (falconpy)
# ---------------------------------------------------------------------------

class CrowdStrikeProvider(BaseMacProvider):
    """
    Look up hosts in CrowdStrike Falcon by MAC address using falconpy.

    Credentials are loaded from a JSON file named ``CS_FEM_TOKEN`` in the
    user's current working directory.  The file must contain at minimum:

        {
            "client_id":     "YOUR_CLIENT_ID",
            "client_secret": "YOUR_CLIENT_SECRET"
        }

    Optional keys:
        "base_url"    — API base URL (default: "https://api.crowdstrike.com")
        "console_url" — Falcon console base URL
                        (default: "https://falcon.crowdstrike.com")

    A link is generated only when the MAC matches a device record in Falcon.
    Devices with no sensor record (printers, cameras, unmanaged gear) will
    simply not match and receive no link.

    The ``status`` field on each device is the *containment* status
    (normal / contained / etc.).  If you also want to filter on sensor
    freshness, use ``last_seen`` from the helper script ``cs_lookup.py``.
    """
    name = "crowdstrike"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url:    str = "https://api.crowdstrike.com",
        console_url: str = "https://falcon.crowdstrike.com",
    ) -> None:
        super().__init__()
        self._console_url = console_url.rstrip("/")
        try:
            from falconpy import Hosts
            self._falcon = Hosts(
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
            )
        except ImportError:
            raise ImportError(
                "crowdstrike-falconpy is required for CrowdStrike enrichment. "
                "Install it with: pip install crowdstrike-falconpy"
            )

    def _fetch(self, mac_norm: str) -> Optional[str]:
        # Falcon stores MACs as dash-separated; colons are not matched
        mac_dash = mac_norm.replace(":", "-")
        try:
            response = self._falcon.query_devices_by_filter(
                filter=f"mac_address:'{mac_dash}'",
                limit=1,
            )
            if response["status_code"] != 200:
                log.debug(
                    "CrowdStrike query returned HTTP %s for %s: %s",
                    response["status_code"], mac_norm,
                    response["body"].get("errors"),
                )
                return None
            aids = response["body"].get("resources", [])
            if aids:
                return f"{self._console_url}/host-management/hosts/{aids[0]}"
        except Exception as exc:
            log.debug("CrowdStrike lookup failed for %s: %s", mac_norm, exc)
        return None

    @classmethod
    def from_token_file(
        cls,
        path: str | Path | None = None,
    ) -> Optional["CrowdStrikeProvider"]:
        """
        Load credentials from the CS_FEM_TOKEN file and return a provider.
        Returns None (with a logged warning) if the file is missing or invalid.

        If *path* is not given, the file is looked for in the current working
        directory (``os.getcwd()``).
        """
        token_path = Path(path) if path else Path(os.getcwd()) / _CS_TOKEN_FILENAME
        if not token_path.exists():
            log.debug("CS_FEM_TOKEN not found at %s — CrowdStrike enrichment disabled", token_path)
            return None
        try:
            creds = json.loads(token_path.read_text())
            client_id     = creds["client_id"]
            client_secret = creds["client_secret"]
        except (json.JSONDecodeError, KeyError) as exc:
            log.warning("CS_FEM_TOKEN at %s is invalid: %s — CrowdStrike enrichment disabled", token_path, exc)
            return None

        log.debug("CrowdStrike enrichment enabled (credentials from %s)", token_path)
        return cls(
            client_id     = client_id,
            client_secret = client_secret,
            base_url      = creds.get("base_url",    "https://api.crowdstrike.com"),
            console_url   = creds.get("console_url", "https://falcon.crowdstrike.com"),
        )


# ---------------------------------------------------------------------------
# Static MAC → URL lookup table provider
# ---------------------------------------------------------------------------

class StaticMacProvider(BaseMacProvider):
    """
    Simple lookup table: maps known MAC addresses to fixed URLs.

    Useful for linking unmanaged or special-purpose devices (printers, OOB
    ports, access points) to their management pages or asset records in any
    external system, without needing an API.

    The table is a plain dict in ``config.py``::

        MAC_URL_TABLE: dict[str, str] = {
            "aa:bb:cc:dd:ee:ff": "https://printer-mgmt.example.com/device/42",
            "11:22:33:44:55:66": "https://wiki.example.com/assets/ap-lobby",
        }

    Keys are normalised on load so any common MAC format is accepted.
    The JSON key written into mac_table entries is ``"static_url"``.
    """
    name = "static"

    def __init__(self, table: dict[str, str]) -> None:
        super().__init__()
        # Normalise all keys at init time so lookups are always fast
        self._table: dict[str, str] = {
            _normalise_mac(k): v for k, v in table.items()
        }

    def _fetch(self, mac_norm: str) -> Optional[str]:
        return self._table.get(mac_norm)


# ---------------------------------------------------------------------------
# Lansweeper provider
# ---------------------------------------------------------------------------

class LansweeperProvider(BaseMacProvider):
    """
    Look up assets in Lansweeper by MAC address (GraphQL API).

    Cloud:
        api_url     = "https://api.lansweeper.com/api/integrations/graphql"
        site_id     = "<site-GUID from Settings → API>"
        console_url = "https://app.lansweeper.com/<site-name>"

    On-premises:
        api_url     = "https://<server>/api"
        site_id     = ""   (omit)
        console_url = "https://<server>"
    """
    name = "lansweeper"

    _QUERY = """
    query LookupByMac($siteId: String, $mac: String!) {
      site(id: $siteId) {
        assetResources(
          filters: [{ operator: EQUAL, path: "assetCustom.mac", value: $mac }]
          pagination: { limit: 1, page: 0 }
        ) {
          items { assetId key assetBasicInfo { name } }
        }
      }
    }
    """

    def __init__(
        self,
        api_url: str,
        token: str,
        site_id: str = "",
        console_url: str = "",
    ) -> None:
        super().__init__()
        self._api_url     = api_url
        self._site_id     = site_id or None   # GraphQL null when blank
        self._console_url = console_url.rstrip("/")
        try:
            import requests
            self._session = requests.Session()
            self._session.headers.update({
                "Authorization": f"Token {token}",
                "Content-Type":  "application/json",
            })
        except ImportError:
            raise ImportError(
                "requests is required for Lansweeper enrichment. "
                "Install it with: pip install requests"
            )

    def _fetch(self, mac_norm: str) -> Optional[str]:
        try:
            resp = self._session.post(
                self._api_url,
                json={
                    "query":     self._QUERY,
                    "variables": {"siteId": self._site_id, "mac": mac_norm},
                },
                timeout=10,
            )
            resp.raise_for_status()
            items = (
                resp.json()
                    .get("data", {})
                    .get("site", {})
                    .get("assetResources", {})
                    .get("items", [])
            )
            if items:
                asset_id = items[0].get("assetId") or items[0].get("key")
                if asset_id and self._console_url:
                    return f"{self._console_url}/asset/{asset_id}"
        except Exception as exc:
            log.debug("Lansweeper lookup failed for %s: %s", mac_norm, exc)
        return None


# ---------------------------------------------------------------------------
# Enricher
# ---------------------------------------------------------------------------

class MacEnricher:
    """
    Apply a list of :class:`MacLookupProvider` instances to MAC table entries.

    ``enrich(entries)`` mutates each entry dict in place, adding
    ``{provider.name}_url`` for every provider that returns a URL for that MAC.
    """

    def __init__(self, providers: list[MacLookupProvider] | None = None) -> None:
        self._providers: list[MacLookupProvider] = providers or []

    @property
    def enabled(self) -> bool:
        return bool(self._providers)

    def enrich(self, entries: list[dict]) -> list[dict]:
        """Add external-link URL fields to *entries* in place."""
        if not self.enabled:
            return entries
        for entry in entries:
            mac = entry.get("mac")
            if not mac:
                continue
            for provider in self._providers:
                url = provider.lookup_mac(mac)
                if url:
                    entry[f"{provider.name}_url"] = url
        return entries

    @classmethod
    def from_config(cls) -> "MacEnricher":
        """
        Instantiate providers from ``config.py`` and the CS_FEM_TOKEN file.

        Each integration is silently skipped when its required config keys are
        absent or blank, or when its credential file is not present.
        """
        import config  # local import avoids circular dependency

        providers: list[MacLookupProvider] = []

        # CrowdStrike — credentials from CS_FEM_TOKEN file in CWD
        cs = CrowdStrikeProvider.from_token_file()
        if cs:
            providers.append(cs)

        # Static MAC → URL table from config
        mac_table = getattr(config, "MAC_URL_TABLE", {})
        if mac_table:
            providers.append(StaticMacProvider(mac_table))
            log.debug("Static MAC table enrichment enabled (%d entries)", len(mac_table))

        # Lansweeper
        ls_url   = getattr(config, "LANSWEEPER_API_URL", "")
        ls_token = getattr(config, "LANSWEEPER_TOKEN",   "")
        if ls_url and ls_token:
            providers.append(LansweeperProvider(
                api_url     = ls_url,
                token       = ls_token,
                site_id     = getattr(config, "LANSWEEPER_SITE_ID",    ""),
                console_url = getattr(config, "LANSWEEPER_CONSOLE_URL", ""),
            ))
            log.debug("Lansweeper enrichment enabled (%s)", ls_url)

        # Arbitrary custom providers from config.ENRICHMENT_PROVIDERS
        # config.py may set:
        #   ENRICHMENT_PROVIDERS: list[MacLookupProvider] = [MyCustomProvider()]
        for extra in getattr(config, "ENRICHMENT_PROVIDERS", []):
            if isinstance(extra, MacLookupProvider):
                providers.append(extra)
                log.debug("Custom enrichment provider loaded: %s", extra.name)

        return cls(providers)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_mac(mac: str) -> str:
    """Return a lowercase colon-separated MAC from any common format."""
    digits = mac.lower().replace(":", "").replace("-", "").replace(".", "")
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def load_cs_token_file(path: str | Path | None = None) -> dict:
    """
    Load and return the raw contents of the CS_FEM_TOKEN credential file.
    Raises FileNotFoundError or ValueError on missing / malformed file.
    """
    token_path = Path(path) if path else Path(os.getcwd()) / _CS_TOKEN_FILENAME
    if not token_path.exists():
        raise FileNotFoundError(f"CS_FEM_TOKEN not found at: {token_path}")
    try:
        return json.loads(token_path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"CS_FEM_TOKEN is not valid JSON: {exc}") from exc
