"""
IEEE OUI lookup — resolves the first three octets of a MAC address to a
vendor / organisation name using the IEEE MA-L/MA-M/MA-S assignment CSV.

The CSV is published by the IEEE and can be downloaded from:
  https://standards-oui.ieee.org/oui/oui.csv   (MA-L, ~37 k entries)
  https://standards-oui.ieee.org/oui28/mam.csv  (MA-M)
  https://standards-oui.ieee.org/oui36/oui36.csv (MA-S)

Point OUI_FILE in config.py at a local copy of whichever file(s) you want.
Multiple files can be supplied as a list; all are merged at load time.

Expected CSV columns (header row present):
  Registry,Assignment,Organization Name,Organization Address

The "Assignment" column contains the hex prefix with NO separators:
  MA-L  →  6 hex chars   (aa:bb:cc prefix)
  MA-M  →  7 hex chars   (aa:bb:cc:d prefix)
  MA-S  →  9 hex chars   (aa:bb:cc:dd:ee:f prefix)
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path

log = logging.getLogger(__name__)


class OuiLookup:
    """
    Resolve a MAC address to an IEEE-registered organisation name.

    Lookup is longest-prefix-match so that MA-M / MA-S entries take
    precedence over the broader MA-L entry for the same prefix.

    Usage::

        oui = OuiLookup.from_config()
        vendor = oui.lookup("aa:bb:cc:dd:ee:ff")   # "Some Vendor Inc." or ""
    """

    def __init__(self, table: dict[str, str]) -> None:
        # table: normalised-hex-prefix (no separators, lowercase) -> org name
        self._table = table

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def lookup(self, mac: str) -> str:
        """
        Return the organisation name for *mac*, or an empty string if unknown.

        Tries MA-S (9-char), MA-M (7-char), then MA-L (6-char) prefixes so
        that finer-grained assignments win.
        """
        digits = _strip(mac)
        if len(digits) < 6:
            return ""
        for length in (9, 7, 6):
            vendor = self._table.get(digits[:length], "")
            if vendor:
                return vendor
        return ""

    @classmethod
    def from_config(cls) -> "OuiLookup":
        """
        Load OUI data from the path(s) specified in config.OUI_FILE.

        OUI_FILE may be:
          - a single path string
          - a list of path strings (all files are merged)
          - empty string / None / [] to disable OUI lookup (returns empty vendor)
        """
        try:
            import config
            paths = getattr(config, "OUI_FILE", "")
        except ImportError:
            paths = ""

        if isinstance(paths, (str, Path)):
            paths = [paths] if paths else []

        table: dict[str, str] = {}
        for path in paths:
            p = Path(path)
            if not p.exists():
                log.warning("OUI file not found: %s — vendor lookup disabled for this file", p)
                continue
            loaded = _load_csv(p)
            table.update(loaded)
            log.debug("Loaded %d OUI entries from %s", len(loaded), p)

        if not table:
            log.debug("No OUI data loaded — vendor field will be empty")

        return cls(table)

    @property
    def loaded(self) -> bool:
        return bool(self._table)


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _load_csv(path: Path) -> dict[str, str]:
    """
    Parse one IEEE OUI CSV file.  Tolerates the header row and ignores
    lines where the Assignment column is empty or non-hex.

    Returns a dict of lowercase-hex-prefix -> org name.
    """
    table: dict[str, str] = {}
    try:
        with path.open(newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if len(row) < 3:
                    continue
                assignment = row[1].strip()
                org_name   = row[2].strip()
                if not assignment or not org_name:
                    continue
                # Skip header row
                if assignment.lower() == "assignment":
                    continue
                try:
                    int(assignment, 16)  # validates it is hex
                except ValueError:
                    continue
                table[assignment.lower()] = org_name
    except OSError as exc:
        log.error("Could not read OUI file %s: %s", path, exc)
    return table


def _strip(mac: str) -> str:
    """Return lowercase hex digits only from any MAC format."""
    return mac.lower().replace(":", "").replace("-", "").replace(".", "")
