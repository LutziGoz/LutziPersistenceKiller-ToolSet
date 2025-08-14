# LutziGoz-APK (Advanced Persistence Killer) -Free Bundle
Copyright (c) 2025 LutziGoz lutzigoz@lutzigoz.com
# LutziLyzer 2025
**COM & SID static persistence detection — one repo, two tools (free).**  
Windows-focused, offline-friendly, strict static checks first. Optional VT/AI only **when you choose**.

<img width="1024" height="1024" alt="ChatGPT Image Aug 9, 2025, 03_07_15 PM" src="https://github.com/user-attachments/assets/045d8919-b725-4767-8d03-ea1021ab2115" />


## Tools Included

- **LutziCOMLyzer - Advanced Persistence Detector** (`LutziCheckSuspiciousCOM.py`)  
  Deep forensic scanner for COM, WinRT, and indirect persistence vectors.  
  • Performs multi-layer validation: existence, signature, trusted path, ownership, dispatch test, hash matching.  
  • Detects orphaned/broken CLSIDs, Active Setup/Winsock persistence, and stealth COM-based persistence.  
  • Optional integration with VirusTotal and AI reasoning for high-confidence threat classification.  

- **LutziSIDHunter - Advanced Terminator THreats** (`tt7.ps1`)  
  Advanced registry/SID/ACL forensic utility.  
  • Scans live or offline hives for anomalous or malicious SIDs.  
  • Repairs ACLs, removes persistence keys, and backs up/restores registry hives.  
  • Supports writing cleaned hives back to the system and verifying post-install clean state.  
  • Includes optional download/burn of clean Windows ISOs for secure rebuilds.
---
## ✨ What it does
- **Static first:** file existence, Authenticode signature, trusted-path / allowlist checks.
- **Focused scope:** COM CLSIDs & common indirect persistence surfaces; SID/ACL anomalies.
- **Offline/Safe Mode friendly:** designed to run without “tickling” persistence.
- **Operator-controlled escalation:** *only if an entry remains suspicious* you can opt-in to:
  - **VirusTotal** lookup (requires your API key)
  - **AI reasoning** summary (requires your API key)
- **Runtime:** a full deep scan can take **~4 hours** on big systems — be patient.
- **Output:** CSV/JSON **only when you ask for export** (no endless auto-logging).

---
## 🔧 Requirements
> • **LutziCOMLyzer**  (Python)

  - **Windows 7/8/10/11

  - **Python 3.8.6+

  - **PowerShell available in PATH (for signature checks on Windows)

  - **(Optional) VirusTotal / AI keys if you choose those paths

> • **TT7** (PowerShell)

  - **Windows 10/11, Admin recommended

  - **PowerShell 5.1+ (or 7+), Set-ExecutionPolicy Bypass -Scope Process -Force when running locally

  - **VSS optional if you want to snapshot locked hives
---
## 🗂 Outputs (on demand)

- **  LutziCOMLyzer: com_scan.csv (CLSID, path, exists, signed, trusted, hash, notes).
- **  Optional: reasoning snippets when you used AI, VT verdict when you used VT.

- **  TT7: services.csv/json, tasks.csv/json, com_hotspots.csv/json, ifeo.csv/json, appcontainer.csv/json, acl_report.csv/json (names may vary by your flags).

- **  By design, there is no continuous auto-logging. You decide when to export.
---
##⚙️ Allow/deny lists

  - ** The tool uses trusted paths and signer allowlists (built-in + yours).

  - ** You can extend with your own whitelist / blacklist concepts (e.g., based on LOKI or your org’s intel).
this is actually for first, should update loki db and more relevant, then continue to scan and detection steps.
  - ** Anything whitelisted is never sent to VT/AI.

##🛡 Safety & ethics

  - **For defensive use on systems you own or are authorized to analyze.

  - **No destructive actions are included by default.

  - **Do not send samples or “live malware” to me. This repo is not a dropbox or a lab service.

##❓Support & feedback

- **Found a bug? Have a feature request?
- **Open an Issue on the repo with steps to reproduce and sanitized logs if possible.

- **For collaboration ideas: use GitHub Issues/Discussions.
---
## 🧭 When to use it
- Suspect a **stubborn persistence** returning after cleanup.
- Need a **static, explainable** triage (no secret black magic).
- Preparing for **firmware-level checks** (Intel ME / SPI flash) if software-level is clean but persistence returns.

> **Heads up (future docs):** if persistence keeps coming back, check Intel ME and consider SPI flash reprogramming with a clean BIOS image. A simple Video guide + SPI walk-through look at folloing Videos.

- **connect to chip directly.
[![Watch the video](t.jpg)](https://github.com/user-attachments/assets/62a99e55-c11a-47af-b2db-6aa85aa3bc58)

- **erase > program > verify (2 video parts).

- (V1).

[![Watch the video](t.jpg)](https://github.com/user-attachments/assets/a1a953d7-b018-4f13-913c-49edb0068d02)

- (v2).
[![Watch the video](t.jpg)](https://github.com/user-attachments/assets/7690376e-c7f8-43a7-9e95-e08942df8e90)


---

## Quick Start
### 1) LutziCOMLyzer
# from an elevated cmd/powershell in the repo folder
python LutziCheckSuspiciousCOM.py ^
  --mode strict ^
  --export out\com_scan.csv


 ## Notes

  - ** mode strict = escalate only if static checks still point suspicious.

 - ** On a big machine, expect ~4 hours for a deep pass.

 - ** If something survives the static filters, the tool will ask you whether to run VT and/or AI.
 - ** Nothing is sent anywhere unless you choose it and provide keys.

### 2) TT7
# from an elevated PowerShell in the repo folder
- ** Set-ExecutionPolicy Bypass -Scope Process -Force
- ** .\tt7.ps1 -OutDir "C:\Temp\TT7_Out" -ReadOnly


  -ReadOnly is the default mindset: enumerate, don’t modify.

- **  Add -UseVSS if you want to snapshot and copy locked hives safely.

- ** Output CSV/JSON/XML only if you request it via flags inside the script.
> ### Heads-up: Deep Scan Runtime
> `tt7` performs a **full persistence sweep** across services, drivers, COM, WMI, scheduled tasks, LSASS hooks, userland autoruns, and more.  
> On large systems or multi-disk environments this can take **many hours (up to ~24h)**, especially when:
> - scanning network-mounted volumes or very large profile stores,
> - collecting extended metadata / hashes from cold storage,
> - running with maximum verbosity and artifact preservation.
>
> **Tips to speed it up**
> - Prefer **local disks** (avoid remote mounts during the scan).
> - Run as admin with **PowerShell 7+**.
> - Use targeted scopes first (e.g., `-Scope Autoruns,COM,Tasks`) then expand.
> - Exclude known-good bulk paths with `-ExcludePath`.
>
> **OPS rule:** Let the long scan finish once started—partial runs can miss chained persistence.

---
## 📜 License

###LutziGoz Free-Use License (2025)

Copyright (c) 2025 LutziGoz lutzigoz@lutzigoz.com

https://lutzigoz.com

![lUTZIgOZGIF](https://github.com/user-attachments/assets/b6b40d47-02bb-4d4c-b8ce-ab9f3e08a6f0)


This software is released into the public domain for free use, modification, distribution, and incorporation into any project — personal, commercial, or otherwise — anywhere in the world.

###You may:

  Use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies

  Incorporate this work into proprietary or open-source software

  Use it for any purpose, including research, education, security testing, or commercial deployment

###You are not required to:

  Keep this notice or credit me (though attribution is appreciated)

  Pay any fees or royalties

###You may not:

  Claim authorship of the original work without meaningful modification

  Use my name or branding to imply endorsement without permission

Disclaimer:
This software is provided “AS IS,” without warranty of any kind, express or implied. The author is not liable for any damages, misuse, or consequences arising from use.

---
If you find an issue, need a fix, or want to collaborate:
📧 lutzigoz@lutzigoz.com  
We can work on projects together, test new ideas, or you can send me malware samples to analyze.  
---
