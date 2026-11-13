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
    ("home/agent/sentinel/sentinel", "*.py"),   # Sentinel selbst (Dev-Installation): manipulierter Waechter faellt auf
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

# --- M2: Live-Checks ---
# Pflicht-Dienste (nicht aktiv = Warnung)
REQUIRED_UNITS = ("sshd.service", "systemd-networkd.service", "systemd-resolved.service", "systemd-journald.service")
DNS_NAME = "linuxfromscratch.org"
HTTPS_URL = None              # Owner-Entscheidung offen: z.B. "https://www.linuxfromscratch.org/" (braucht Internet)
DISK_PATHS = ("/",)
DISK_WARN_PCT = 90
MEM_MIN_AVAIL_PCT = 10
LOAD_PER_CPU = 2.0
BOOT_MAX_S = 60
