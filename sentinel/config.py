"""Was Sentinel ueberwacht. Pfade sind relativ zum Root ('/' im echten System, Temp-Ordner in Tests)."""

# (Verzeichnis, Muster). Muster gilt fuer den Dateinamen; '*' = alles. Rekursiv.
TARGETS = [
    ("usr/bin", "*"),
    ("usr/sbin", "*"),
    ("usr/local/bin", "*"),
    ("usr/local/sbin", "*"),
    ("usr/lib", "*.so*"),       # Bibliotheken
    ("usr/lib", "*.ko*"),       # Kernel-Module
    ("etc", "*"),
    ("boot", "*"),
]

# Dateien, die sich im Normalbetrieb legitim aendern
EXCLUDE = {
    "etc/ld.so.cache",
    "etc/adjtime",
}

# Aenderung hier = kritisch (sonst ist eine /etc-Aenderung nur eine Warnung)
CRITICAL_ETC = {"etc/passwd", "etc/shadow", "etc/group", "etc/gshadow", "etc/sudoers"}
CRITICAL_ETC_PREFIXES = ("etc/sudoers.d/", "etc/ssh/", "etc/systemd/system/")

# Bei der SUID-Suche ueber das ganze Root ausgelassen (Pseudo-Dateisysteme)
SUID_SKIP = {"proc", "sys", "dev", "run"}

DEFAULT_DB = "/var/lib/sentinel/sentinel.db"

