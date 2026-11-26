# WIZIX — Windows Security Center (desktop rebuild)

## Start
1. Extract the ZIP to a normal local folder (not inside the ZIP preview).
2. Install Python 3.10+ for Windows if it is not already installed.
3. Run `START_WIZIX.bat` and keep the black launcher window open while using WIZIX.
4. WIZIX opens in your browser at a local address. It binds to `127.0.0.1` only and tries ports 8765–8794 if the default port is busy.

## What's connected to real Windows data
- Installed applications: Windows uninstall registry entries from machine and current-user hives.
- Running processes: Windows process inventory including PID, executable path and command line when Windows permits access.
- Startup entries: Windows startup command inventory.
- Network: established/listening TCP connections and owning process IDs.
- Defender: Microsoft Defender status and available detection records.
- Firewall: Windows Firewall profile status.
- Browser extensions: Chrome and Edge extension manifests found in the current Windows user profile.
- File explorer: read-only listing of a folder selected by the user; available drive roots can be listed first. Each folder shows up to 500 entries. Access-denied folders are reported instead of crashing the app.
- Malware scanning: quick/full file malware scans are requested from Microsoft Defender. WIZIX does not claim that inventory listing is itself a malware scan.

## Important accuracy notes
- WIZIX does not label an unknown program or ordinary connection as malware by name alone.
- Defender detections are displayed as Defender records; review Windows Security > Protection History for current status and remediation.
- Heuristic indicators remain review items, not confirmed threats.
- WIZIX does not automatically delete, quarantine, disable or modify files, applications, processes, or security settings.
- File explorer is a directory browser, not a recursive whole-disk content scanner. For actual malware scanning, use Microsoft Defender Quick Scan or Full Scan.
- Some process paths, command lines, Defender fields, and protected folders may be unavailable without appropriate Windows permissions. WIZIX reports unavailable data instead of inventing it.

## Troubleshooting
- If the page says the local engine is offline, rerun `START_WIZIX.bat` and leave its console window open.
- If the default port is occupied, WIZIX selects another local port in the 8765–8794 range.
- If Windows blocks a protected inventory item, run the launcher as administrator only if you trust this local copy and need the additional read permissions. Do not disable Windows security controls.
- Python 3 and Windows 10/11 are required. WIZIX is a Python-backed local desktop web interface. Download either the source (needs Python) or `WIZIX.exe` from the Releases page (no Python needed; it is unsigned, so Windows SmartScreen may show a warning).

## Privacy
The local service listens only on loopback (`127.0.0.1`). File and system inventory stays on the computer except for any separate web feature the user explicitly invokes.
