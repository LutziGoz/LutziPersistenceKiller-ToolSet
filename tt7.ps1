# LutziSIDHunter_PowerScan.ps1
# Full Registry Dump, Offline Restoration, SID Cleanup, and Safe Reinjection to System
$removedCount = 0
$failedCount = 0
$ErrorActionPreference = 'SilentlyContinue'
# ANSI color shortcuts
$Cyan    = [ConsoleColor]::Cyan
$Green   = [ConsoleColor]::Green
$Yellow  = [ConsoleColor]::Yellow
$Red     = [ConsoleColor]::Red
$DarkGray = [ConsoleColor]::DarkGray

$allSIDs = @{}
$legitSIDs = @(
    "S-1-5-18", "S-1-5-32-544", "S-1-5-19", "S-1-5-20", "S-1-5-21-*", "S-1-5-80-*", "NT SERVICE\\*", "NT AUTHORITY\\*"
)
$exportTime = Get-Date -Format 'yyyyMMdd_HHmmss'
$userSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

function Categorize-SID {
    param($sid)

    # Current user
    if ($sid -eq $userSID) { return "UserSID" }

    # AppContainer
    if ($sid -like "S-1-15-3-*") { return "AppContainer" }

    # Guest
    if ($sid -like "S-1-5-21-*-501") { return "GuestSID" }

    # Active Directory machine/user accounts
    if ($sid -match "^S-1-5-21-(\d+-){3}\d+$") { return "AD_SID" }

    # Legitimate Windows principals (do NOT delete)
    $legitPatterns = @(
        "S-1-5-18",                  # Local System
        "S-1-5-19",                  # Local Service
        "S-1-5-20",                  # Network Service
        "S-1-5-32-544",              # Builtin\Administrators
        "NT AUTHORITY\*",            # All AUTHORITY principals
        "NT SERVICE\*"               # All service accounts
    )
    foreach ($pat in $legitPatterns) {
        if ($sid -like $pat) { return "Legit" }
    }

    return "Unknown"
}

if ($mode -eq '1') {
    $logPath = "$currentDir\\Lutzi_SID_Map_Removal_LIVE_$exportTime.log"
    "[$(Get-Date)] SID Scan Started." | Out-File -Encoding UTF8 -FilePath $logPath
    "SID Cleanup (Generated $(Get-Date))`n" | Out-File -Encoding UTF8 -FilePath $logPath
}


$grouped = @{AppContainer=@{}; Unknown=@{}; UserSID=@{}; GuestSID=@{}; Legit=@{}}


$ErrorActionPreference = 'SilentlyContinue'
$writeInterim = $false  
# ANSI color shortcuts
$Cyan    = [ConsoleColor]::Cyan
$Green   = [ConsoleColor]::Green
$Yellow  = [ConsoleColor]::Yellow
$Red     = [ConsoleColor]::Red
$DarkGray = [ConsoleColor]::DarkGray
$global:confirmAll = $null
function Perform-RegistryScan {
    param (
        [array]$hivesToScan,
        [string]$logPath,
        [string]$currentDir
    )

    $grouped = @{AppContainer=@{}; Unknown=@{}; UserSID=@{}; GuestSID=@{}; Legit=@{}}
    $ownerMap = @{}
    $sidHiveMap = @{}
    $i = 0

    foreach ($hive in $hivesToScan) {
        Write-Host "`nScanning: $hive" -ForegroundColor Cyan
        $keys = Get-ChildItem -Recurse -Force -Path $hive
        $total = $keys.Count
        foreach ($key in $keys) {
            $i++
            Write-Progress -Activity "Scanning $hive" -Status "$i of $total" -PercentComplete (($i / $total) * 100)
            if (!(Test-Path $key.PSPath)) { continue }
            try {
                $acl = Get-Acl $key.PSPath
            } catch {
                Add-Content -Path $logPath -Value "ERROR (Get-Acl) [$($key.PSPath)]: $_"
                continue
            }
            $owner = $acl.Owner
            if (-not $ownerMap.ContainsKey($owner)) { $ownerMap[$owner] = @() }
            $ownerMap[$owner] += $key.PSPath
            $hiveRoot = ($key.PSPath -split ':')[0]

            foreach ($ace in $acl.Access) {
	        try {
		   if ($null -eq $ace.IdentityReference) { continue }
		    $sid = $ace.IdentityReference.Value
		    $cat = Categorize-SID $sid

		    if (-not $grouped.ContainsKey($cat)) { $grouped[$cat] = @{} }
		    if (-not $grouped[$cat].ContainsKey($sid)) { 
		        $grouped[$cat][$sid] = @()
		        if ($cat -in @("Unknown", "AppContainer", "GuestSID", "AD_SID")) {
		            Write-Host "[DETECTED SUSPICIOUS SID]: $sid → Category: $cat" -ForegroundColor Red
		        }
		    }
		    $grouped[$cat][$sid] += $key.PSPath
		    if ($cat -in @("Unknown", "AppContainer", "GuestSID", "AD_SID")) {
		        Add-Content -Path $logPath -Value "[$(Get-Date)] $cat → $sid at $($key.PSPath)"
		    }

		    if (-not $sidHiveMap.ContainsKey($sid)) { $sidHiveMap[$sid] = @{} }
		    $hiveRoot = ($key.PSPath -split ':')[0]
		    $sidHiveMap[$sid][$hiveRoot] = $true

	        } catch {
		    Add-Content -Path $logPath -Value "ERROR (Access loop) [$($key.PSPath)]: $_"
		    continue
	        }
	    }


            # Periodically export grouped results during scanning
            if ($writeInterim -and ($i % 500 -eq 0)) {
	        $filteredGrouped = @{}
	        foreach ($c in @("Unknown", "AppContainer", "GuestSID", "UserSID", "AD_SID")) {
		    if ($grouped.ContainsKey($c) -and $grouped[$c].Count -gt 0) {
		        $filteredGrouped[$c] = $grouped[$c]
		    }
	        }
	        if ($filteredGrouped.Count -gt 0) {
		    $progressPath = "$currentDir\\Lutzi_Grouped_Interim_$exportTime.xml"
		    Export-Clixml -Path $progressPath -InputObject $filteredGrouped
		    Write-Host "[INTERIM XML] Exported to $progressPath" -ForegroundColor Cyan
	        }
	    }

        }
        Write-Progress -Activity "Scanning complete" -Completed
    }

    return @{
        SidToHive = $sidToHive
        Grouped = $grouped
        OwnerMap = $ownerMap
        HiveMap = $sidHiveMap
    }
}
function Dump-And-Load-Hives {
    $currentPath = (Get-Location).Path
    $backupTarget = "$currentPath\DUMP"
    New-Item -ItemType Directory -Force -Path $backupTarget | Out-Null

    # Save hives consistently
    reg save HKLM\SOFTWARE "$backupTarget\SOFTWARE_HIVE" /y | Out-Null
    reg save HKLM\SYSTEM "$backupTarget\SYSTEM_HIVE" /y | Out-Null
    reg save HKLM\SECURITY "$backupTarget\SECURITY_HIVE" /y | Out-Null
    reg save HKLM\SAM "$backupTarget\SAM_HIVE" /y | Out-Null
    reg save HKU\.DEFAULT "$backupTarget\DEFAULT_HIVE" /y | Out-Null

    Copy-NTUSER-WithVSS

    # Load hives consistently for offline analysis
    reg load HKLM\LutziSOFTWARE "$backupTarget\SOFTWARE_HIVE" | Out-Null
    reg load HKLM\LutziSYSTEM "$backupTarget\SYSTEM_HIVE" | Out-Null
    reg load HKLM\LutziSECURITY "$backupTarget\SECURITY_HIVE" | Out-Null
    reg load HKLM\LutziSAM "$backupTarget\SAM_HIVE" | Out-Null
    reg load HKU\OfflineDEFAULT "$backupTarget\DEFAULT_HIVE" | Out-Null

    $ntusers = Get-ChildItem -Path $backupTarget -Filter "NTUSER_*.DAT"
    foreach ($nt in $ntusers) {
        $profileName = $nt.BaseName.Replace("NTUSER_", "")
        reg load "HKU\Offline_$profileName" "$($nt.FullName)" | Out-Null
    }

    Write-Host "`nOffline hives restored and mounted for analysis."
    return @("HKLM:\OfflineDEFAULT", "HKLM:\LutziSYSTEM", "HKLM:\LutziSECURITY", "HKLM:\LutziSAM", "HKU:\LutziSOFTWARE")
}


function Unload-Hives {
    reg unload HKLM\LutziSOFTWARE | Out-Null
    reg unload HKLM\LutziSYSTEM | Out-Null
}


function Show-RestoreOrBackupMenu {

    Write-Host "`nRegistry Hive Restore/Backup Menu"
    Write-Host "1 - Restore Hives to temporary offline view"
    Write-Host "2 - Backup (dump) all relevant Hives (SOFTWARE, SYSTEM, SECURITY, SAM, DEFAULT, NTUSER)"
    $currentPath = (Get-Location).Path
    $backupTarget = "$currentPath\DUMP"
    $subOption = Read-Host "Enter your choice (1/2)"
    if ($subOption -eq '1' -and -not (Test-Path "$backupTarget\SYSTEM_HIVE")) {
        Write-Host "SYSTEM_HIVE missing! Cannot restore." -ForegroundColor $Red
        exit
    }


    if ($subOption -eq '2') {
        New-Item -ItemType Directory -Force -Path $backupTarget | Out-Null

        # Save main system hives
        reg save HKLM\SOFTWARE "$backupTarget\SOFTWARE_HIVE" /y | Out-Null
        reg save HKLM\SYSTEM "$backupTarget\SYSTEM_HIVE" /y | Out-Null
        reg save HKLM\SECURITY "$backupTarget\SECURITY_HIVE" /y | Out-Null
        reg save HKLM\SAM "$backupTarget\SAM_HIVE" /y | Out-Null
        reg save HKU\.DEFAULT "$backupTarget\DEFAULT_HIVE" /y | Out-Null

        # Use VSS to safely copy NTUSER.DAT
        Copy-NTUSER-WithVSS

        # Compress all files into a backup archive
        Compress-Archive -Path "$backupTarget\*" -DestinationPath "$backupTarget\Lutzi_Backup_$(Get-Date -Format yyyyMMdd_HHmmss).zip" -Force

        Write-Host "`nAll registry hives and NTUSER profiles dumped successfully to: $backupTarget"

        $continue = Read-Host "Do you want to proceed to offline scan and cleanup now using this dump? (y/n)"
        if ($continue -eq 'y') {
            reg load HKLM\LutziSOFTWARE "$backupTarget\SOFTWARE_HIVE" | Out-Null
            reg load HKLM\LutziSYSTEM "$backupTarget\SYSTEM_HIVE" | Out-Null
            reg load HKLM\LutziSECURITY "$backupTarget\SECURITY_HIVE" | Out-Null
            reg load HKLM\LutziSAM "$backupTarget\SAM_HIVE" | Out-Null
            reg load HKU\OfflineDEFAULT "$backupTarget\DEFAULT_HIVE" | Out-Null

            $ntusers = Get-ChildItem -Path $backupTarget -Filter "NTUSER_*.DAT"
            foreach ($nt in $ntusers) {
                $profileName = $nt.BaseName.Replace("NTUSER_", "")
                reg load "HKU\Offline_$profileName" "$($nt.FullName)" | Out-Null
            }
            Write-Host "`nOffline hives restored and mounted for analysis."
            return @("HKLM:\LutziSYSTEM", "HKLM:\LutziSOFTWARE", "HKLM:\LutziSECURITY", "HKLM:\LutziSAM", "HKU:\OfflineDEFAULT")
        } else {
            Write-Host "`nDump complete. You can now reboot and analyze manually from WinPE or Hiren's BootCD ETC." -ForegroundColor Yellow
            exit
        }

    } elseif ($subOption -eq '1') {
        # RESTORE OPTION FIXED
        if (!(Test-Path "$backupTarget\SYSTEM_HIVE")) { Write-Host "SYSTEM_HIVE missing!"; exit }
        if (!(Test-Path "$backupTarget\SOFTWARE_HIVE")) { Write-Host "SOFTWARE_HIVE missing!"; exit }
        if (!(Test-Path "$backupTarget\SECURITY_HIVE")) { Write-Host "SECURITY_HIVE missing!"; exit }
        if (!(Test-Path "$backupTarget\SAM_HIVE")) { Write-Host "SAM_HIVE missing!"; exit }
        if (!(Test-Path "$backupTarget\DEFAULT_HIVE")) { Write-Host "DEFAULT_HIVE missing!"; exit }

        reg load HKLM\LutziSOFTWARE "$backupTarget\SOFTWARE_HIVE" | Out-Null
        reg load HKLM\LutziSYSTEM "$backupTarget\SYSTEM_HIVE" | Out-Null
        reg load HKLM\LutziSECURITY "$backupTarget\SECURITY_HIVE" | Out-Null
        reg load HKLM\LutziSAM "$backupTarget\SAM_HIVE" | Out-Null
        reg load HKU\OfflineDEFAULT "$backupTarget\DEFAULT_HIVE" | Out-Null

        $ntusers = Get-ChildItem -Path $backupTarget -Filter "NTUSER_*.DAT"
        foreach ($nt in $ntusers) {
            $profileName = $nt.BaseName.Replace("NTUSER_", "")
            reg load "HKU\Offline_$profileName" "$($nt.FullName)" | Out-Null
        }

        Write-Host "`nOffline hives restored and mounted for analysis."
        $grouped = @{}
        return @("HKLM:\LutziSYSTEM", "HKLM:\LutziSOFTWARE", "HKLM:\LutziSECURITY", "HKLM:\LutziSAM", "HKU:\OfflineDEFAULT")

    } else {
        Write-Host "Invalid selection. Exiting."
        exit
    }
}

function Show-Help {
    Write-Host "`nLutziSIDHunter - Help"
    Write-Host "--------------------------------------"
    Write-Host "This tool scans the Windows registry for suspicious SID entries in ACLs (permissions)."
    Write-Host ""
    Write-Host "Modes:"
    Write-Host "1 - Scan & Clean LIVE registry (Administrator only)."
    Write-Host ""
    Write-Host "2 - Dump & Analyze:"
    Write-Host "    - Saves SOFTWARE, SYSTEM, SECURITY, SAM, DEFAULT, and NTUSER profiles into a DUMP folder."
    Write-Host "    - You can then choose to proceed directly to offline scan,"
    Write-Host "      or stop and later analyze manually (e.g. after booting into a Live USB OS)."
    Write-Host ""
    Write-Host "3 - Restore or Backup:"
    Write-Host "    - Restore: Loads existing DUMPed hives and performs full OFFLINE scan and cleanup."
    Write-Host "      (Best used after booting into external Live OS like WinPE or Hiren's BootCD)."
    Write-Host "    - Backup: Saves all critical registry hives and user NTUSER profiles into a compressed archive."
    Write-Host "      (Useful for later manual analysis or forensic backup)."
    Write-Host ""
    Write-Host "4 - Write Cleaned Hives Back to System:"
    Write-Host "    - After offline cleanup, writes the cleaned hives back into live Windows locations."
    Write-Host "    - Requires reboot after applying the cleaned hives."
    Write-Host ""
    Write-Host "5 - Manual SID Removal Utility:"
    Write-Host "    - Allows you to input a specific SID for direct targeted cleanup in all registry ACLs."
    Write-Host "    - Supports SYSTEM, SOFTWARE, NTUSER hives and offers ACL reset options."
    Write-Host ""
    Write-Host "6 - Download Clean Windows 11 ISO & Burn to USB:"
    Write-Host "    - Downloads a known-clean Windows 11 Business Edition ISO (22H2, Nov 2022) from Archive.org."
    Write-Host "    - Prompts you to select a USB drive from detected devices and burns the ISO automatically."
    Write-Host "    - Ensures a clean, telemetry-free install base with minimal AppX bloat."
    Write-Host ""
    Write-Host "7 - Post-Install CleanBoot State Verification:"
    Write-Host "    - Performs SID scan immediately after OS install to verify it is clean from injected SIDs or containers."
    Write-Host "    - Validates that no UNKNOWN, orphaned, or AppContainer SIDs exist on a fresh install."
    Write-Host ""
    Write-Host "H - Display this help menu."
    Write-Host "0 - Exit the tool."
    Write-Host "--------------------------------------`n"
}



# MAIN MENU (Updated simplified version)
Write-Host "Select mode:"
Write-Host "1 - Scan & Clean LIVE registry (Administrator only)"
Write-Host "2 - Dump registry for OFFLINE analysis (optionally scan now)"
Write-Host "3 - Restore DUMP for Offline Scan or Backup Hives"
Write-Host "4 - Write cleaned hives back to Windows system"
Write-Host "5 - Load Last Scan Result and Perform Cleanup"
Write-Host "6 - Download Windows 11 ISO + Burn to USB"
Write-Host "7 - CleanBoot Check for Suspicious SIDs"
Write-Host "H - Help"
Write-Host "0 - Exit"
function Print-GroupedSIDs {
    param ([hashtable]$grouped)
    $sidOptions = @()
    $i = 1
    foreach ($cat in @("Unknown", "AppContainer", "UserSID", "GuestSID")) {
        if ($grouped.ContainsKey($cat)) {
            foreach ($sid in $grouped[$cat].Keys) {
                $name = try {
                    (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
                } catch {
                    "<unknown>"
                }
                Write-Host "$i. [$cat] $sid ($name)"
                $sidOptions += @{ Index = $i; SID = $sid; Category = $cat; Name = $name }
                $i++
            }
        }
    }
    return $sidOptions
}
$global:confirmAll = $null
function Confirm-Removal($sid) {
    if ($null -eq $global:confirmAll) {
        $confirm = Read-Host "Do you want to proceed with removing all selected SIDs? (y/n)"
        $global:confirmAll = $confirm -eq 'y'
    }
    return $global:confirmAll
}

$mode = Read-Host "Enter your choice (1/2/3/H/0)"
$currentDir = (Get-Location).Path
$grouped = $null

$driveMap = @{}

switch ($mode) {
    'H' {
        Show-Help
        exit
    }
    '0' {
        Write-Host "Exiting..."
        exit
    }
    '1' {
    
        $hives = @("HKLM:\SOFTWARE", "HKCU:\SOFTWARE", "HKCR:\CLSID")
        $currentDir = (Get-Location).Path
	$logPath = "$currentDir\Lutzi_SID_Map_Removal_LIVE_$exportTime.log"
	"[$(Get-Date)] SID Scan Started." | Out-File -Encoding UTF8 -FilePath $logPath
	$scanResult = Perform-RegistryScan -hivesToScan $hives -logPath $logPath -currentDir $currentDir
	$grouped = $scanResult.Grouped
	$ownerMap = $scanResult.OwnerMap
	$sidHiveMap = $scanResult.HiveMap
	if ($grouped -and $grouped.Count -gt 0) {
	    $filteredGrouped = @{}
	    foreach ($cat in @("Unknown", "AppContainer", "GuestSID", "UserSID", "AD_SID")) {
		if ($grouped.ContainsKey($cat) -and $grouped[$cat].Count -gt 0) {
		    $filteredGrouped[$cat] = $grouped[$cat]
		}
	    }

	    if ($filteredGrouped.Count -gt 0) {
		$groupedExportPath = "$currentDir\\Lutzi_Grouped_SUSPICIOUS_$exportTime.xml"
		Export-Clixml -Path $groupedExportPath -InputObject $filteredGrouped
		Write-Host "`nSaved suspicious grouped SIDs to: $groupedExportPath" -ForegroundColor Cyan
	    } else {
		Write-Host "`nNo suspicious entries found to export." -ForegroundColor Yellow
	    }

	    $enriched = @{ suspicious_owners = $ownerMap; cross_hive_sids = $sidHiveMap }
	    $enrichedJsonPath = "$currentDir\\Lutzi_SID_Enriched_$(Get-Date -Format yyyyMMdd_HHmmss).json"
	    $enriched | ConvertTo-Json -Depth 6 | Out-File -FilePath $enrichedJsonPath -Encoding UTF8
	    Write-Host "Saved enriched report to: $enrichedJsonPath" -ForegroundColor Cyan
	}


    }

    '2' {
        $hives = Dump-And-Load-Hives
        $logPath = "$currentDir\Lutzi_SID_Map_Removal_OFFLINE_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
	"[$(Get-Date)] SID Scan Started." | Out-File -Encoding UTF8 -FilePath $logPath
        $scanResult = Perform-RegistryScan -hivesToScan $hives -logPath $logPath -currentDir $currentDir
        $grouped = $scanResult.Grouped
        $ownerMap = $scanResult.OwnerMap
        $sidHiveMap = $scanResult.HiveMap

        Write-Host "`nOffline scan complete. Results are saved to: $logPath" -ForegroundColor Green
        Write-Host "`nSuspicious SIDs found:" -ForegroundColor Yellow
        $sidOptions = Print-GroupedSIDs -grouped $grouped

        # Diagnostic block to sample group stats
        Write-Host "`nSample from grouped results:"
        foreach ($cat in $grouped.Keys) {
            foreach ($sid in $grouped[$cat].Keys) {
                Write-Host "[$cat] $sid → $($grouped[$cat][$sid].Count) registry keys"
            }
        }

        do {
            $proceedCleanup = Read-Host "`nWould you like to proceed with cleaning these entries now? (y/n)"
            if ($proceedCleanup -ne 'y' -and $proceedCleanup -ne 'n') {
                Write-Host "Invalid input. Please enter 'y' or 'n'." -ForegroundColor Red
            }
        } until ($proceedCleanup -eq 'y' -or $proceedCleanup -eq 'n')

	if ($grouped -and $grouped.Count -gt 0) {
	    $filteredGrouped = @{}
	    foreach ($cat in @("Unknown", "AppContainer", "GuestSID", "UserSID", "AD_SID")) {
		if ($grouped.ContainsKey($cat) -and $grouped[$cat].Count -gt 0) {
		    $filteredGrouped[$cat] = $grouped[$cat]
		}
	    }

	    if ($filteredGrouped.Count -gt 0) {
		$groupedExportPath = "$currentDir\\Lutzi_Grouped_SUSPICIOUS_$exportTime.xml"
		Export-Clixml -Path $groupedExportPath -InputObject $filteredGrouped
		Write-Host "`nSaved suspicious grouped SIDs to: $groupedExportPath" -ForegroundColor Cyan
	    } else {
		Write-Host "`nNo suspicious entries found to export." -ForegroundColor Yellow
	    }

	    $enriched = @{ suspicious_owners = $ownerMap; cross_hive_sids = $sidHiveMap }
	    $enrichedJsonPath = "$currentDir\\Lutzi_SID_Enriched_$(Get-Date -Format yyyyMMdd_HHmmss).json"
	    $enriched | ConvertTo-Json -Depth 6 | Out-File -FilePath $enrichedJsonPath -Encoding UTF8
	    Write-Host "Saved enriched report to: $enrichedJsonPath" -ForegroundColor Cyan
	}

        if ($proceedCleanup -ne 'y') {
            Write-Host "Cleanup postponed. Use mode 5 to clean using the saved logs later." -ForegroundColor Yellow
            exit
        }
    }

    '3' {
        $hives = Show-RestoreOrBackupMenu
        $logPath = "$currentDir\Lutzi_SID_Map_Restore_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        "[$(Get-Date)] SID Scan Started." | Out-File -Encoding UTF8 -FilePath $logPath
        $scanResult = Perform-RegistryScan -hivesToScan $hives -logPath $logPath -currentDir $currentDir
        $grouped = $scanResult.Grouped
        $ownerMap = $scanResult.OwnerMap
        $sidHiveMap = $scanResult.HiveMap

        Write-Host "`nOffline restore complete. Results are saved to: $logPath" -ForegroundColor Green
        Write-Host "`nSuspicious SIDs found:" -ForegroundColor Yellow
        $sidOptions = Print-GroupedSIDs -grouped $grouped

        # Diagnostic block to sample group stats
        Write-Host "`nSample from grouped results:"
        foreach ($cat in $grouped.Keys) {
            foreach ($sid in $grouped[$cat].Keys) {
                Write-Host "[$cat] $sid → $($grouped[$cat][$sid].Count) registry keys"
            }
        }

        do {
            $proceedCleanup = Read-Host "`nWould you like to proceed with cleaning these entries now? (y/n)"
            if ($proceedCleanup -ne 'y' -and $proceedCleanup -ne 'n') {
                Write-Host "Invalid input. Please enter 'y' or 'n'." -ForegroundColor Red
            }
        } until ($proceedCleanup -eq 'y' -or $proceedCleanup -eq 'n')

	if ($grouped -and $grouped.Count -gt 0) {
	    $filteredGrouped = @{}
	    foreach ($cat in @("Unknown", "AppContainer", "GuestSID", "UserSID", "AD_SID")) {
		if ($grouped.ContainsKey($cat) -and $grouped[$cat].Count -gt 0) {
		    $filteredGrouped[$cat] = $grouped[$cat]
		}
	    }

	    if ($filteredGrouped.Count -gt 0) {
		$groupedExportPath = "$currentDir\\Lutzi_Grouped_SUSPICIOUS_$exportTime.xml"
		Export-Clixml -Path $groupedExportPath -InputObject $filteredGrouped
		Write-Host "`nSaved suspicious grouped SIDs to: $groupedExportPath" -ForegroundColor Cyan
	    } else {
		Write-Host "`nNo suspicious entries found to export." -ForegroundColor Yellow
	    }

	    $enriched = @{ suspicious_owners = $ownerMap; cross_hive_sids = $sidHiveMap }
	    $enrichedJsonPath = "$currentDir\\Lutzi_SID_Enriched_$(Get-Date -Format yyyyMMdd_HHmmss).json"
	    $enriched | ConvertTo-Json -Depth 6 | Out-File -FilePath $enrichedJsonPath -Encoding UTF8
	    Write-Host "Saved enriched report to: $enrichedJsonPath" -ForegroundColor Cyan
	}


        if ($proceedCleanup -ne 'y') {
            Write-Host "Cleanup postponed. Use mode 5 to clean using the saved logs later." -ForegroundColor Yellow
            exit
        }
    }



    '4' {
        Write-Host "`n[Restoring cleaned hives and user NTUSER.DAT profiles]..." -ForegroundColor Cyan

        $workingDrive = (Get-Location).Path.Substring(0,2)
        $dumpPath = "$workingDrive\DUMP"
        $configPath = "$workingDrive\Windows\System32\config"
        $excludeListPath = "$dumpPath\NTUSER_ExcludeList.txt"

        # Load exclusions if exist
        $excludedUsers = @()
        if (Test-Path $excludeListPath) {
            $excludedUsers = Get-Content $excludeListPath | Where-Object { $_ -match '\S' }
            Write-Host "Loaded exclude list from: $excludeListPath" -ForegroundColor DarkGray
        }

        $hiveMap = @{
            "SYSTEM_HIVE"   = "SYSTEM"
            "SOFTWARE_HIVE" = "SOFTWARE"
            "SECURITY_HIVE" = "SECURITY"
            "SAM_HIVE"      = "SAM"
            "DEFAULT_HIVE"  = "DEFAULT"
        }

        foreach ($hiveFile in $hiveMap.Keys) {
            $source = "$dumpPath\$hiveFile"
            $dest = "$configPath\$($hiveMap[$hiveFile])"
            if (Test-Path $source) {
                Write-Host "Restoring hive $hiveFile to $dest" -ForegroundColor Yellow
                reg restore "HKLM\$($hiveMap[$hiveFile])" "$source"
            } else {
                Write-Host "Hive file $source not found" -ForegroundColor Red
            }
        }

        $ntuserFiles = Get-ChildItem "$dumpPath" -Filter "NTUSER_*.DAT"
        foreach ($file in $ntuserFiles) {
            $userProfile = $file.BaseName -replace "^NTUSER_", ""

            if ($excludedUsers -contains $userProfile) {
                Write-Host "Skipping excluded user profile: $userProfile" -ForegroundColor DarkYellow
                continue
            }
            $targetPath = "$workingDrive\Users\$userProfile\NTUSER.DAT"
            try {
                Copy-Item -Path $file.FullName -Destination $targetPath -Force
                Write-Host "Restored NTUSER for $userProfile to $targetPath" -ForegroundColor Green
            } catch {
                Write-Host "Failed to restore $targetPath $_" -ForegroundColor Red
                
            }
        }

        Write-Host "`nDone! Reboot into Windows." -ForegroundColor Green
        exit
    }

    '5' {
        # User Selection for Cleanup Mode
        Write-Host "Choose Cleanup Mode:" -ForegroundColor Cyan
        Write-Host "1 - Conservative (Recommended)"
        Write-Host "2 - Aggressive (Remove ALL suspicious SIDs - may break Windows)"
        $cleanupChoice = Read-Host "Enter your choice (1/2)"

        if ($cleanupChoice -ne '1' -and $cleanupChoice -ne '2') {
	    Write-Host "Invalid selection. Defaulting to Conservative Mode." -ForegroundColor Yellow
	    $cleanupChoice = '1'
        }

        # Global LEGIT SID definition based on user choice
        if ($cleanupChoice -eq '1') {
	    $global:legitSIDs = @(
	        "S-1-5-18", "S-1-5-19", "S-1-5-20",
	        "S-1-5-32-544", "NT SERVICE\*", "NT AUTHORITY\*"
	    )
        } else {
	    # Aggressive mode - empty legit list means EVERYTHING suspicious will be removed
	    $global:legitSIDs = @()
	    Write-Host "Aggressive Mode selected. Proceed with caution!" -ForegroundColor Red
        }

        # Categorize-SID function
        function Categorize-SID {
	    param($sid)

	    if ($sid -eq $userSID) { return "UserSID" }
	    if ($sid -like "S-1-15-3-*") { return "AppContainer" }
	    if ($sid -like "S-1-5-21-*-501") { return "GuestSID" }
	    if ($sid -match "^S-1-5-21-(\d+-){3}\d+$") { return "AD_SID" }

	    # Check against legit SIDs based on mode
	    foreach ($pattern in $global:legitSIDs) {
	        if ($sid -like $pattern) { return "Legit" }
	    }

	    return "Unknown"
        }


        $scanResult = Perform-RegistryScan -hivesToScan $hives -logPath $logPath -currentDir $currentDir
	$grouped    = $scanResult.Grouped
	$sidToHive  = $scanResult.SidToHive
        $currentDir = (Get-Location).Path
        Write-Host "`n[Reload Previous Scan Result]" -ForegroundColor Cyan
        $groupedFiles = Get-ChildItem "$currentDir" -Filter "Lutzi_Grouped_*.xml" | Sort-Object LastWriteTime -Descending
        # ——— Start detailed cleanup log ———
        $cleanupLog = "$currentDir\Lutzi_Cleanup_Details_$(Get-Date -Format yyyyMMdd_HHmmss).log"
        "[{0}] MODE 5 cleanup started." -f (Get-Date) | Out-File -FilePath $cleanupLog -Encoding UTF8



        if ($groupedFiles.Count -eq 0) {
            Write-Host "No saved grouped result files found on currentdir." -ForegroundColor Red
            exit
        }

        $i = 1
        foreach ($file in $groupedFiles) {
            Write-Host "$i. $($file.Name) [$($file.LastWriteTime)]"
            $i++
        }

        $choice = Read-Host "Choose grouped file to load (1-$($groupedFiles.Count))"
        if ($choice -match '^\d+$' -and $choice -ge 1 -and $choice -le $groupedFiles.Count) {
	    $selectedPath = $groupedFiles[$choice - 1].FullName

	    if (-not $selectedPath -or !(Test-Path $selectedPath)) {
	        Write-Host "Grouped file path is invalid or file was deleted. Exiting." -ForegroundColor Red
	        exit
	    }


            # —— Import under its own try/catch ——
            try {
                $grouped = Import-Clixml -Path $selectedPath
                if (-not $grouped -or $grouped.Count -eq 0) {
                    Write-Host "Grouped file is empty or invalid!" -ForegroundColor Red
                    exit
                }
            } catch {
                Write-Host "Failed to load grouped scan: $_" -ForegroundColor Red
                exit
            }

           $sidOptions = Print-GroupedSIDs -grouped $grouped
           if ($mode -eq '1') {
	       $logPath = "$currentDir\\Lutzi_SID_Map_Removal_LIVE_$exportTime.log"
	       "[$(Get-Date)] SID Scan Started." | Out-File -Encoding UTF8 -FilePath $logPath
	   }

           Write-Host "Loaded: $selectedPath" -ForegroundColor Green

            $sidOptions = @()
            $i = 1
            foreach ($cat in @("Unknown", "AppContainer", "UserSID", "GuestSID")) {
                if ($grouped.ContainsKey($cat)) {
                    foreach ($sid in $grouped[$cat].Keys) {
                        $name = try {
                            (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
                        } catch {
                            '<unknown>'
                        }
                        Write-Host "$i. [$cat] $sid ($name)"
                        $sidOptions += @{Index=$i; SID=$sid; Category=$cat}
                        $i++
                    }
                }
            }

            if ($sidOptions.Count -eq 0) {
                Write-Host "`nNo suspicious SIDs found. Exiting." -ForegroundColor Red
                exit
            }

            Write-Host "`nDo you want to remove SIDs from list above?"
            Write-Host "1 - Remove only UNKNOWN"
            Write-Host "2 - Remove only AppContainer"
            Write-Host "3 - Remove specific UserSID"
            Write-Host "4 - Remove Entire Unknown + AppContainer + GuestSID"
            Write-Host "5 - Remove GuestSID"

            $choice = Read-Host "Enter your choice (1/2/3/4/5)"

            $selectedSIDs = @()
            switch ($choice) {
                "1" { $selectedSIDs = $sidOptions | Where-Object { $_.Category -eq "Unknown" } }
                "2" { $selectedSIDs = $sidOptions | Where-Object { $_.Category -eq "AppContainer" } }
                "3" { $selectedSIDs = $sidOptions | Where-Object { $_.Category -eq "UserSID" } }
                "4" { $selectedSIDs = $sidOptions | Where-Object { $_.Category -in @("Unknown", "AppContainer", "GuestSID") } }
                "5" { $selectedSIDs = $sidOptions | Where-Object { $_.Category -eq "GuestSID" } }
                default {
                    Write-Host "Invalid choice. Exiting." -ForegroundColor Red
                    exit
                }
            }

            $total = $selectedSIDs.Count
            $index = 0
            $excludedProfiles = @()

            foreach ($entry in $selectedSIDs) {
                # — Log which SID we’re processing —
		"{0} → Processing SID: {1}   Category: {2}" -f (Get-Date), $entry.SID, $entry.Category |
		Add-Content -Path $cleanupLog

                $index++
                $sidStatusMap = @{}
                Write-Progress -Activity "Removing SIDs" `
                               -Status "$index of $total - $($entry.SID)" `
                               -PercentComplete (($index / $total) * 100)

                $targetSID = $entry.SID
                Write-Host "[+] Attempting cleanup for SID: $targetSID (Category: $($entry.Category))" -ForegroundColor Cyan
                if (-not (Confirm-Removal $targetSID)) { continue }

                Write-Host "`nRemoving: $targetSID" -ForegroundColor Green

		$keys = @()
		if ($grouped.ContainsKey($entry.Category) -and $grouped[$entry.Category].ContainsKey($targetSID)) {
		    $keys = $grouped[$entry.Category][$targetSID]
		}

		if ($keys.Count -eq 0) {
		    # Fallback: attempt to clean inherited ACLs even without key association
		    $fallbackKey = $sidToHive[$targetSID]
		    if (-not (Test-Path $fallbackKey)) {
			foreach ($cand in $hives) {
			    if (Test-Path $cand) { $fallbackKey = $cand; break }
			}
		    }
		    if ([string]::IsNullOrEmpty($fallbackKey)) {
			Add-Content -Path $logPath -Value "ERROR: fallbackKey is NULL for SID $targetSID"
			continue
		    }

		    # Perform the actual fallback ACL cleanup
	            Add-Content -Path $cleanupLog -Value ("{0} → No keys for SID {1}; using fallback hive: {2}" `
			-f (Get-Date), $targetSID, $fallbackKey)
		    try {
			$acl = Get-Acl $fallbackKey
			$acl.SetAccessRuleProtection($true, $false)  # Disable inheritance
			$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
			Set-Acl -Path $fallbackKey -AclObject $acl
			$sidStatusMap[$targetSID] = "Fallback cleanup at $fallbackKey"
		    } catch {
			Add-Content -Path $cleanupLog -Value ("{0} → ERROR applying fallback on {1}: {2}" `
			    -f (Get-Date), $fallbackKey, $_)
			$sidStatusMap[$targetSID] = "Fallback error"
		    }
		    continue
		}
		    $sidStatusMap[$targetSID] = "Fallback cleanup applied (no keys)"
		    continue
		}
		foreach ($key in $keys) {
	            # — Log each key we’re attempting —
		    "{0} → Attempting key: {1}" -f (Get-Date), $key |
	                Add-Content -Path $cleanupLog
		    if ($targetSID -eq 'S-1-1-0' -and $key -notmatch '(LutziSYSTEM|LutziSOFTWARE|LutziSECURITY|LutziSAM)') {
			Write-Host "Skipping Everyone on non-critical key: $key" -ForegroundColor Yellow
			continue
		    }

		    if (!(Test-Path $key)) {
			try {
			    $parentKey = Split-Path -Path $key -Parent

			    try {
				$acl = Get-Acl $parentKey
				$acl.SetAccessRuleProtection($true, $false)
				$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
				Set-Acl -Path $parentKey -AclObject $acl
				Add-Content -Path $logPath -Value "Removed orphan SID $targetSID from parent key $parentKey"
			    } catch {
				Add-Content -Path $logPath -Value "ERROR (Orphan SID removal) [$parentKey]: $_"
			    }

			} catch {
			    Add-Content -Path $logPath -Value "ERROR (Parent key resolution) [$key]: $_"
			}

			continue
		    }


		    try {
			$acl = Get-Acl $key
			$acl.SetOwner([System.Security.Principal.NTAccount]"Administrators")
			$rule = New-Object System.Security.AccessControl.RegistryAccessRule (
			    "Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
			)
			$acl.ResetAccessRule($rule)
			$acl.SetAccessRuleProtection($true, $false)
			$newAccess = $acl.Access | Where-Object { $_.IdentityReference -notlike "*$targetSID*" }
			$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
			foreach ($entryACL in $newAccess) {
			    $acl.AddAccessRule($entryACL)
			}
			Set-Acl -Path $key -AclObject $acl
			Add-Content -Path $logPath -Value "Removed SID $targetSID from $key"
			$sidStatusMap[$targetSID] = "Removed from registry key"

		    } catch {
			Add-Content -Path $logPath -Value "ERROR (Set-Acl) [$key]: $_"
			$sidStatusMap[$targetSID] = "Error during cleanup"
		    }
		}
                # Get profile folder name from SID
                if ($entry.Category -in @("UserSID", "GuestSID")) {
                    try {
                        $profile = Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $targetSID }
                        if ($profile -and $profile.LocalPath) {
                            $folderName = Split-Path $profile.LocalPath -Leaf
                            $excludedProfiles += $folderName
                        } else {
                            $excludedProfiles += $targetSID
                        }
                    } catch {
                        $excludedProfiles += $targetSID
                    }
                }
                
            # ——— Final cleanup summary ———
	    "" | Add-Content -Path $cleanupLog
	    "===== Cleanup Summary =====" | Add-Content -Path $cleanupLog
	    foreach ($sid in $sidStatusMap.Keys) {
		"{0} → {1}" -f $sid, $sidStatusMap[$sid] |
		    Add-Content -Path $cleanupLog
	    }
	    "===========================" | Add-Content -Path $cleanupLog
	    # ————————————————————————
            Write-Progress -Activity "Removing SIDs" -Completed
            # After SID removal loop completes
	    if ($cleanupChoice -eq '1') {
	        $remainingSuspiciousSIDs = @()
	        foreach ($entry in $selectedSIDs) {
		    $cat = Categorize-SID $entry.SID
		    if ($cat -eq "Legit") {
		        $remainingSuspiciousSIDs += $entry.SID
		    }
	        }

	        if ($remainingSuspiciousSIDs.Count -gt 0) {
		    Write-Host "`n[!] Warning: Some critical SIDs remain suspicious but were not removed due to Conservative Mode:" -ForegroundColor Yellow
		    $remainingSuspiciousSIDs | ForEach-Object { Write-Host "- $_" -ForegroundColor Red }
		    Write-Host "You may consider running the cleanup again in Aggressive Mode." -ForegroundColor Cyan
	        } else {
		    Write-Host "`nNo suspicious critical SIDs remain. System cleaned successfully!" -ForegroundColor Green
	        }
	    }


            # Save exclusion file for NTUSER restore to skip these
            if ($excludedProfiles.Count -gt 0) {
                $dumpPath = "$((Get-Location).Path.Substring(0,2))\DUMP"
                $excludeFilePath = "$dumpPath\NTUSER_ExcludeList.txt"
                $excludedProfiles | Sort-Object -Unique | Out-File -Encoding UTF8 -FilePath $excludeFilePath
                Write-Host "`nSaved NTUSER exclusion list to: $excludeFilePath" -ForegroundColor Yellow
            }

            Write-Host "`nCleanup complete. Log saved to: $logPath" -ForegroundColor Green
            Write-Host "`n===== SID Removal Summary =====" -ForegroundColor Cyan
	    foreach ($kvp in $sidStatusMap.GetEnumerator()) {
	        Write-Host "$($kvp.Key): $($kvp.Value)"
	    }
	    return
	    }

	    else {
	        Write-Host "Invalid selection." -ForegroundColor Red
	        return
	    }}
    '6' {
        Write-Host "`n[+] Starting ISO download and USB burn process..." -ForegroundColor Cyan

        $isoUrl = "https://archive.org/download/en-us_windows_11_business_editions_version_22h2_updated_nov_2022_x64_dvd_7ed4b518/en-us_windows_11_business_editions_version_22h2_updated_nov_2022_x64_dvd_7ed4b518.iso"
        $isoPath = "$env:TEMP\Win11_LutziClean.iso"

       Write-Host "`n[~] Downloading ISO..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $isoUrl -OutFile $isoPath -UseBasicParsing
        Write-Host "[finished] ISO saved to: $isoPath" -ForegroundColor Green

        $usbList = Get-WmiObject Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' }
        if (-not $usbList) {
            Write-Host "[!] No USB drives detected." -ForegroundColor Red
            break
        }

        $i = 0
        foreach ($usb in $usbList) {
            $model = $usb.Model
            $size = [math]::Round($usb.Size / 1GB, 1)
            Write-Host "[$i] $model - $size GB"
            $driveMap[$i] = $usb.DeviceID
            $i++
        }

        $choice = Read-Host "Select USB index to burn ISO"
        if (-not $driveMap.ContainsKey([int]$choice)) {
            Write-Host "[!] Invalid choice." -ForegroundColor Red
            break
        }

        $deviceID = $driveMap[[int]$choice]
        Write-Host "[~] Selected device: $deviceID"

        if (Test-Path "C:\Program Files\Rufus\rufus.exe") {
            & "C:\Program Files\Rufus\rufus.exe" /ISO:$isoPath /Drive:$deviceID /Format:NTFS /Silent
        } else {
            Write-Host "[!] Rufus not found. Please burn manually with Rufus." -ForegroundColor Red
        }
    }

	    }
	    
# === Updated Registry Scan Loop with OWNER + Cross-Hive Detection ===
  
$ownerMap = @{}
$sidHiveMap = @{}
  
foreach ($hive in $hives) {
    Write-Host "`nScanning: $hive" -ForegroundColor $Cyan
    $keys = Get-ChildItem -Recurse -Force -Path $hive
    $total = $keys.Count; $i = 0
    foreach ($key in $keys) {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $i++
        Write-Progress -Activity "Scanning $hive" `
                       -Status "$i of $total" `
                       -PercentComplete (($i / $total) * 100)
  
        if (!(Test-Path $key.PSPath)) {
            continue
        }
  
        try {
            $acl = Get-Acl $key.PSPath
        } catch {
            Add-Content -Path $logPath -Value "ERROR (Get-Acl) [$($key.PSPath)]: $_"
            continue
        }
  
        # Track OWNER
        $owner = $acl.Owner
        if (-not $ownerMap.ContainsKey($owner)) { $ownerMap[$owner] = @() }
        $ownerMap[$owner] += $key.PSPath
  
        # Track HIVE ORIGIN per SID
        $hiveRoot = ($key.PSPath -split ':')[0]
  
        foreach ($ace in $acl.Access) {
	    try {
		if ($null -eq $ace.IdentityReference) { continue }
		$sid = $ace.IdentityReference.Value
		$cat = Categorize-SID $sid

		if (-not $grouped.ContainsKey($cat)) { $grouped[$cat] = @{} }
		if (-not $grouped[$cat].ContainsKey($sid)) { 
		    $grouped[$cat][$sid] = @()
		    if ($cat -in @("Unknown", "AppContainer", "GuestSID", "AD_SID")) {
		        Write-Host "[DETECTED SUSPICIOUS SID]: $sid → Category: $cat" -ForegroundColor Red
		    }
		}
		$grouped[$cat][$sid] += $key.PSPath


		if ($cat -in @("Unknown", "AppContainer", "GuestSID", "AD_SID")) {
		    Add-Content -Path $logPath -Value "[$(Get-Date)] $cat → $sid at $($key.PSPath)"
		}

		if (-not $sidHiveMap.ContainsKey($sid)) { $sidHiveMap[$sid] = @{} }
		$hiveRoot = ($key.PSPath -split ':')[0]
		$sidHiveMap[$sid][$hiveRoot] = $true

	    } catch {
		Add-Content -Path $logPath -Value "ERROR (Access loop) [$($key.PSPath)]: $_"
		continue
	    }
	}


    Write-Progress -Activity "Scanning complete" -Completed
    }
}
  
Write-Host "`nSID Listing Finished." -ForegroundColor $Green







$i = 1
$sidOptions = @()
foreach ($cat in @("Unknown", "AppContainer", "UserSID", "GuestSID")) {
    foreach ($sid in $grouped[$cat].Keys) {
        try {
            $name = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $name = '<unknown>'
        }
        Write-Host "$i. [$cat] $sid ($name)"
        $sidOptions += @{Index=$i; SID=$sid; Category=$cat}
        $i++
    }
}


if ($sidOptions.Count -eq 0) {
    Write-Host "`nNo suspicious SIDs found. Exiting." -ForegroundColor Red
    if ($mode -ne '1') { Unload-Hives }
    exit
}

# Clearly ask user if they want to proceed with cleanup or save for later
$proceedCleanup = Read-Host "`nDo you want to proceed to cleanup now? (y/n)"

if ($proceedCleanup -ne 'y' -and $proceedCleanup -ne 'n') {
    # Save results for later use
    if ($grouped -and $grouped.Count -gt 0) {
        $filteredGrouped = @{}
        foreach ($cat in @("Unknown", "AppContainer", "GuestSID", "UserSID", "AD_SID")) {
            if ($grouped.ContainsKey($cat) -and $grouped[$cat].Count -gt 0) {
                $filteredGrouped[$cat] = $grouped[$cat]
            }
        }

        if ($filteredGrouped.Count -gt 0) {
            $groupedExportPath = "$currentDir\\Lutzi_Grouped_SUSPICIOUS_$exportTime.xml"
            Export-Clixml -Path $groupedExportPath -InputObject $filteredGrouped
            Write-Host "`nSaved suspicious grouped SIDs to: $groupedExportPath" -ForegroundColor Cyan
         } else {
            Write-Host "`nNo suspicious entries found to export." -ForegroundColor Yellow
        }

        $enriched = @{ suspicious_owners = $ownerMap; cross_hive_sids = $sidHiveMap }
        $enrichedJsonPath = "$currentDir\\Lutzi_SID_Enriched_$(Get-Date -Format yyyyMMdd_HHmmss).json"
        $enriched | ConvertTo-Json -Depth 6 | Out-File -FilePath $enrichedJsonPath -Encoding UTF8
        Write-Host "Saved enriched report to: $enrichedJsonPath" -ForegroundColor Cyan
    }
    Write-Host "`nCleanup postponed. You can use mode 5 later." -ForegroundColor Yellow
    if ($mode -ne '1') { Unload-Hives }
    exit
}

# Only now ask which cleanup option if the user agreed
Write-Host "`nChoose SID cleanup option:"
Write-Host "1 - Remove only UNKNOWN"
Write-Host "2 - Remove only AppContainer"
Write-Host "3 - Remove specific UserSID"
Write-Host "4 - Remove Entire Unknown + AppContainer + GuestSID"
Write-Host "5 - Remove GuestSID"

$choice = Read-Host "Enter your choice (1/2/3/4/5)"



$selectedSIDs = @()

switch ($choice) {
    "1" { $selectedSIDs = $sidOptions | Where-Object { $_.Category -eq "Unknown" } }
    "2" { $selectedSIDs = $sidOptions | Where-Object { $_.Category -eq "AppContainer" } }
    "3" { $selectedSIDs = $sidOptions | Where-Object { $_.Category -eq "UserSID" } }
    "4" { $selectedSIDs = $sidOptions | Where-Object { $_.Category -in @("Unknown", "AppContainer", "GuestSID") } }
    "5" { $selectedSIDs = $sidOptions | Where-Object { $_.Category -eq "GuestSID" } }
    default {
        Write-Host "Invalid choice. Exiting."
        if ($mode -ne '1') { Unload-Hives }
        exit
    }
}



foreach ($entry in $selectedSIDs) {
    $targetSID = $entry.SID
    if (-not (Confirm-Removal $targetSID)) {
        continue
    }
    Write-Host "`nRemoving: $targetSID" -ForegroundColor $Green
    foreach ($key in $grouped[$entry.Category][$targetSID]) {
        if ($targetSID -eq 'S-1-1-0' -and $key -notmatch '(LutziSYSTEM|LutziSOFTWARE|LutziSECURITY|LutziSAM)') {
            Write-Host "Skipping Everyone on non-critical key: $key" -ForegroundColor $Yellow
            continue
        }

        if (!(Test-Path $key)) {
            $parentKey = Split-Path -Path $key -Parent
            try {
                $acl = Get-Acl $parentKey
                $acl.Access | Where-Object { $_.IdentityReference -like "*$targetSID*" } | ForEach-Object {
                    $acl.RemoveAccessRule($_)
                }
                Set-Acl -Path $parentKey -AclObject $acl
                Add-Content -Path $logPath -Value "Removed orphan SID $targetSID from parent key $parentKey"
                $removedCount++
            } catch {
                Add-Content -Path $logPath -Value "ERROR (Orphan SID removal) [$parentKey]: $_"
                $failedCount++
            }
            continue
        }

        try {
            $acl = Get-Acl $key
            $acl.SetOwner([System.Security.Principal.NTAccount]"Administrators")
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule (
                "Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
            )
            $acl.ResetAccessRule($rule)
            $acl.SetAccessRuleProtection($true, $false)
            $newAccess = $acl.Access | Where-Object { $_.IdentityReference -notlike "*$targetSID*" }
            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
            foreach ($entryACL in $newAccess) {
                $acl.AddAccessRule($entryACL)
            }
            Set-Acl -Path $key -AclObject $acl
            Add-Content -Path $logPath -Value "Removed SID $targetSID from $key"
            $removedCount++
        } catch {
            Add-Content -Path $logPath -Value "ERROR (Set-Acl) [$key]: $_"
            $failedCount++
        }
    }
}



Write-Host "\nDone. Log saved to: $logPath" -ForegroundColor $Green
if ($mode -ne '1') {
    Write-Host "`nUnloading registry hives..." -ForegroundColor DarkGray
    reg unload HKLM\LutziSOFTWARE | Out-Null
    reg unload HKLM\LutziSYSTEM | Out-Null
    reg unload HKLM\LutziSECURITY | Out-Null
    reg unload HKLM\LutziSAM | Out-Null
    reg unload HKU\OfflineDEFAULT | Out-Null

    # Unload all NTUSER hive loads
    $offlineUsers = Get-ChildItem -Path HKU: | Where-Object { $_.Name -like "Offline_*" }
    foreach ($u in $offlineUsers) {
        reg unload "HKU\$($u.PSChildName)" | Out-Null
    }

    Write-Host "Offline hives successfully unloaded." -ForegroundColor Green
}


# === Post-scan Analysis ===

# Identify suspicious OWNERs
$suspiciousOwners = @{}
foreach ($ownerSID in $ownerMap.Keys) {
    if ($ownerSID -notmatch "^(S-1-5-|NT AUTHORITY\\|NT SERVICE\\|BUILTIN\\|SYSTEM$)") {
        $suspiciousOwners[$ownerSID] = $ownerMap[$ownerSID]
    }
}

# Identify cross-hive persistence
$crossHiveSIDs = @{}
foreach ($sid in $sidHiveMap.Keys) {
    if ($sidHiveMap[$sid].Count -gt 1) {
        $crossHiveSIDs[$sid] = $sidHiveMap[$sid].Keys
    }
}

# Save JSON output
if ($grouped) {
    $currentDir = (Get-Location).Path
    $enriched = @{ suspicious_owners = $suspiciousOwners; cross_hive_sids = $crossHiveSIDs }
    $enrichedJsonPath = "$currentDir\Lutzi_SID_Enriched_$(Get-Date -Format yyyyMMdd_HHmmss).json"
    $enriched | ConvertTo-Json -Depth 6 | Out-File -FilePath $enrichedJsonPath -Encoding UTF8
    Write-Host "`nSaved enriched detection report to: $enrichedJsonPath" -ForegroundColor Yellow
}


if ($global:stopwatch -is [System.Diagnostics.Stopwatch]) {
    $global:stopwatch.Stop()
    $duration = $global:stopwatch.Elapsed

    Add-Content -Path $logPath -Value "`nSummary:"
    Add-Content -Path $logPath -Value "Duration: $($duration.ToString())"
    Add-Content -Path $logPath -Value "SIDs Successfully Removed: $removedCount"
    Add-Content -Path $logPath -Value "SIDs Failed to Remove: $failedCount"

    Write-Host "`nDone." -ForegroundColor Green

if ($grouped -and $grouped.Count -gt 0) {
    $filteredGrouped = @{}
    foreach ($cat in @("Unknown", "AppContainer", "GuestSID", "UserSID", "AD_SID")) {
        if ($grouped.ContainsKey($cat) -and $grouped[$cat].Count -gt 0) {
            $filteredGrouped[$cat] = $grouped[$cat]
        }
    }

    if ($filteredGrouped.Count -gt 0) {
        $groupedExportPath = "$currentDir\\Lutzi_Grouped_SUSPICIOUS_$exportTime.xml"
        Export-Clixml -Path $groupedExportPath -InputObject $filteredGrouped
        Write-Host "`nSaved suspicious grouped SIDs to: $groupedExportPath" -ForegroundColor Cyan
    } else {
        Write-Host "`nNo suspicious entries found to export." -ForegroundColor Yellow
    }

    $enriched = @{ suspicious_owners = $ownerMap; cross_hive_sids = $sidHiveMap }
    $enrichedJsonPath = "$currentDir\\Lutzi_SID_Enriched_$(Get-Date -Format yyyyMMdd_HHmmss).json"
    $enriched | ConvertTo-Json -Depth 6 | Out-File -FilePath $enrichedJsonPath -Encoding UTF8
    Write-Host "Saved enriched report to: $enrichedJsonPath" -ForegroundColor Cyan
}


    Write-Host "Removed Entries: $removedCount" -ForegroundColor Green
    Write-Host "Failed Removals: $failedCount" -ForegroundColor Red
    Write-Host "Duration: $($duration.ToString())" -ForegroundColor Yellow
}
