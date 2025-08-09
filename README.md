# LutziPersistenceKiller-ToolSet

# LutziLyzer 2025
**COM & SID static persistence detection — one repo, two tools (free).**  
Windows-focused, offline-friendly, strict static checks first. Optional VT/AI only **when you choose**.

> Tools included  
> • **LutziCOMLyzer** (`LutziCheckSuspiciousCOM.py`) – COM/WinRT & indirect-persistence triage (Python, Windows).  
> • **TT7** (`tt7.ps1`) – registry/SID/ACL triage and context (PowerShell, Windows).

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

## 🧭 When to use it
- Suspect a **stubborn persistence** returning after cleanup.
- Need a **static, explainable** triage (no secret black magic).
- Preparing for **firmware-level checks** (Intel ME / SPI flash) if software-level is clean but persistence returns.

> **Heads up (future docs):** if persistence keeps coming back, check Intel ME and consider SPI flash reprogramming with a clean BIOS image. A simple ME guide + SPI walk-through will be added later.



---
## 🧩 Workflow (high level)

flowchart TD
    A[Start scan] --> B[Enumerate COM & hotspots]
    B --> C[Static checks: exists, signed, trusted path, allowlist]
    C -->|Clean| D[Report clean / optional CSV]
    C -->|Suspicious| E{Ask operator: VT/AI?}
    E -->|Yes| F[VT/AI on suspicious only]
    E -->|No| G[Mark suspicious (local)]
    F --> H[Summarize reasoning]
    G --> H
    H --> I[Write CSV/JSON if requested]



If you find an issue, need a fix, or want to collaborate:
📧 lutzigoz@lutzigoz.com  
We can work on projects together, test new ideas, or you can send me malware samples to analyze.  




## Notes

 - ** mode strict = escalate only if static checks still point suspicious.

- **  On a big machine, expect ~4 hours for a deep pass.

- **  If something survives the static filters, the tool will ask you whether to run VT and/or AI.
- **  Nothing is sent anywhere unless you choose it and provide keys.


## Quick Start
###1) LutziCOMLyzer
# from an elevated cmd/powershell in the repo folder
python LutziCheckSuspiciousCOM.py ^
  --mode strict ^
  --export out\com_scan.csv


 ## Notes

  - ** mode strict = escalate only if static checks still point suspicious.

 - ** On a big machine, expect ~4 hours for a deep pass.

 - ** If something survives the static filters, the tool will ask you whether to run VT and/or AI.
 - ** Nothing is sent anywhere unless you choose it and provide keys.

###2) TT7
# from an elevated PowerShell in the repo folder
- ** Set-ExecutionPolicy Bypass -Scope Process -Force
- ** .\tt7.ps1 -OutDir "C:\Temp\TT7_Out" -ReadOnly

Notes

  -ReadOnly is the default mindset: enumerate, don’t modify.

-->  Add -UseVSS if you want to snapshot and copy locked hives safely.

--> Output CSV/JSON/XML only if you request it via flags inside the script.

## Layout
.
├─ LutziCheckSuspiciousCOM.py   # Python COM & indirect persistence triage.
├─ tt7.ps1                      # PowerShell SID/ACL triage.
├─ README.md.
├─ LICENSE.
└─ .gitignore.

