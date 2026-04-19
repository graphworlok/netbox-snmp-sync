from utilities.choices import ChoiceSet


class LearnedMACStatusChoices(ChoiceSet):
    NEW      = "new"
    ACTIVE   = "active"
    STALE    = "stale"
    PROMOTED = "promoted"

    CHOICES = [
        (NEW,      "New",      "blue"),
        (ACTIVE,   "Active",   "success"),
        (STALE,    "Stale",    "secondary"),
        (PROMOTED, "Promoted", "purple"),
    ]


class MACEntryTypeChoices(ChoiceSet):
    LEARNED = "learned"
    SELF    = "self"
    MGMT    = "mgmt"
    OTHER   = "other"

    CHOICES = [
        (LEARNED, "Learned", "success"),
        (SELF,    "Self",    "blue"),
        (MGMT,    "Mgmt",    "cyan"),
        (OTHER,   "Other",   "secondary"),
    ]


class OUIRegistryChoices(ChoiceSet):
    MAL = "MA-L"
    MAM = "MA-M"
    MAS = "MA-S"

    CHOICES = [
        (MAL, "MA-L (24-bit, ~37k entries)", "blue"),
        (MAM, "MA-M (28-bit)",               "green"),
        (MAS, "MA-S (36-bit)",               "cyan"),
    ]

    DOWNLOAD_URLS = {
        MAL: "https://standards-oui.ieee.org/oui/oui.csv",
        MAM: "https://standards-oui.ieee.org/oui28/mam.csv",
        MAS: "https://standards-oui.ieee.org/oui36/oui36.csv",
    }

    DEFAULT_FILENAMES = {
        MAL: "oui.csv",
        MAM: "mam.csv",
        MAS: "oui36.csv",
    }


class SyncStatusChoices(ChoiceSet):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED  = "failed"

    CHOICES = [
        (PENDING, "Pending",  "secondary"),
        (RUNNING, "Running",  "warning"),
        (SUCCESS, "Success",  "success"),
        (FAILED,  "Failed",   "danger"),
    ]


class SNMPVersionChoices(ChoiceSet):
    V2 = "2"
    V3 = "3"

    CHOICES = [
        (V2, "SNMPv2c", "blue"),
        (V3, "SNMPv3",  "green"),
    ]


class SNMPAuthProtocolChoices(ChoiceSet):
    MD5    = "MD5"
    SHA    = "SHA"
    SHA224 = "SHA224"
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"

    CHOICES = [
        (MD5,    "MD5",    "secondary"),
        (SHA,    "SHA",    "blue"),
        (SHA224, "SHA-224","blue"),
        (SHA256, "SHA-256","blue"),
        (SHA384, "SHA-384","blue"),
        (SHA512, "SHA-512","blue"),
    ]


class SNMPPrivProtocolChoices(ChoiceSet):
    DES    = "DES"
    AES    = "AES"
    AES192 = "AES192"
    AES256 = "AES256"

    CHOICES = [
        (DES,    "DES",     "secondary"),
        (AES,    "AES-128", "green"),
        (AES192, "AES-192", "green"),
        (AES256, "AES-256", "green"),
    ]
