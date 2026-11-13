# Sicherheit

Sentinel ist ein Lern- und Demo-Projekt für ein selbst gebautes Linux (LFS) und kein geprüftes Sicherheitsprodukt.

- **`sentinel-fault` und `sentinel-selftest` verändern das System absichtlich** (Binaries, `/etc/passwd`, Dienste, DNS, Platte).
  Sie gehören nur in eine Wegwerf-VM (`lfs-vm --snapshot` bzw. `sentinel-e2e`), nie auf ein echtes System.
- Grenzen des Vertrauensmodells: siehe README, Abschnitt „Vertrauensmodell“. Ein root-Angreifer in der VM wird nur
  zusammen mit dem Host-Abgleich (`sentinel-host verify/offline`) erkannt.

Schwachstellen bitte **nicht** als öffentliches Issue melden, sondern über „Report a vulnerability“
(Private Vulnerability Reporting) im Security-Tab dieses Repositories.
