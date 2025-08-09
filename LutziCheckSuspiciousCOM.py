import os
import re
import json
import ctypes
import sys
import subprocess
import tempfile
import hashlib
import tkinter as tk
from tkinter import filedialog
import configparser
import webbrowser
import winreg
from colorama import init, Fore
from tqdm import tqdm
import openai
from win32com.client import Dispatch
import csv
import time
import datetime
from datetime import datetime
from win32security import GetNamedSecurityInfo, OWNER_SECURITY_INFORMATION, SE_REGISTRY_KEY
import win32con
import requests
from datetime import timedelta
from collections import defaultdict
now = datetime.now()
LOKI_HASH_URL = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/hash-iocs.txt"
init(autoreset=True)
CONFIG_FILE = "configAI.ini"
COM_EXPORT_FILE = "com_registry_snapshot.json"
AI_OUTPUT = "ai_com_suspicious_output.json"
CHECKSUMS_DB = "known_good_checksums.json"
UNKNOWN_CHECKSUMS_DB = "unknown_hashes.json"
COM_EXPORT_EXTENDED_FILE = "com_registry_extended_snapshot.json"
TRUSTED_PATHS = [
    r"C:\\Windows\\System32",
    r"C:\\Windows\\SysWOW64",
    r"C:\\Windows\\System32\\drivers",
    r"C:\\Windows\\WinSxS",
]

TRUSTED_PATHS2 = [
    r"C:\\Program Files",
    r"C:\\Program Files (x86)",
    r"C:\\Windows\\Fonts",
]

BOOT_FOLDERS = [
    r"C:\\Windows\\System32\\catroot2",
    r"C:\\Windows\\System32\\catroot",
    r"C:\\Windows\\SysWOW64\\catroot2",
    r"C:\\Windows\\SysWOW64\\catroot",
]
TRUSTED_OWNERS = ["TrustedInstaller", "NT SERVICE\\TrustedInstaller"]
UNKNOWN_SID_PREFIXES = ["S-1-15-3-", "S-1-12-", "S-1-5-21-"]
VT_USER_AUTO_MODE = None  # 'all' or 'ask'
REASONS = {
    "combo": "Failed dispatch, unsigned, untrusted path, and file missing.",
    "static": "Flagged by static analysis.",
    "ai": "Flagged by AI heuristics.",
    "junk": "Potential junk file and unsigned.",
    "unsigned": "File is not signed.",
    "missing": "File does not exist on disk.",
    "untrusted": "File is not located in a trusted path.",
    "nodispatch": "CLSID failed dispatch test."
}

SYSTEM_SIDS = ["SYSTEM", "Administrators", "LOCAL SERVICE", "S-1-5-18"]

# To be loaded externally
full_installation_index = {}  # path -> metadata dict (IsSigned, SHA256, etc)

def is_signed_file(filepath):
    return filepath.endswith(".dll") or filepath.endswith(".exe")

def is_in_critical_boot_folder(path):
    for boot_folder in BOOT_FOLDERS:
        if path.lower().startswith(boot_folder.lower()):
            return True
    return False

def find_other_versions(filename):
    matches = []
    for base in TRUSTED_PATHS + TRUSTED_PATHS2:
        for root, dirs, files in os.walk(base):
            if filename.lower() in [f.lower() for f in files]:
                matches.append(os.path.join(root, filename))
    return matches

def full_installation_index():
    index = {}
    for base in TRUSTED_PATHS + TRUSTED_PATHS2:
        for root, dirs, files in os.walk(base):
            for file in files:
                full_path = os.path.join(root, file)
                try:
                    sha256 = hashlib.sha256(open(full_path, 'rb').read()).hexdigest()
                    index[file.lower()] = {
                        "path": full_path,
                        "hash": sha256
                    }
                except:
                    continue
    return index

def get_clsid_owners(clsid):
    try:
        cmd = f'powershell -Command "(Get-Acl \"Registry::HKCR\\CLSID\\{clsid}\").Access | Format-List"'
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, universal_newlines=True)
        return output.strip()
    except Exception:
        return ""

def query_registry_paths(clsid):
    import subprocess
    paths = [
        f"HKCU\\Software\\Classes\\CLSID\\{clsid}",
        f"HKLM\\Software\\Classes\\CLSID\\{clsid}",
        f"HKCR\\CLSID\\{clsid}\\AppID",
        f"HKCR\\CLSID\\{clsid}\\TypeLib"
    ]
    found_paths = []
    for path in paths:
        cmd = f'reg query "{path}"'
        try:
            subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
            found_paths.append(path)
        except subprocess.CalledProcessError:
            continue
    return found_paths

def get_fltmc_instances():
    import subprocess
    altitudes = []
    try:
        cmd = "fltmc instances"
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, universal_newlines=True)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) > 2:
                try:
                    altitude = float(parts[2].replace('.', ''))
                    if altitude >= 300000:
                        altitudes.append({"filter": parts[0], "altitude": parts[2]})
                except:
                    continue
    except Exception:
        pass
    return altitudes
def analyze_critical_processes():
    import psutil
    from psutil import virtual_memory
    ram_size = virtual_memory().total
    target_processes = {
        "tiworker.exe": "Windows Modules Installer - updates and system-level file changes",
        "MoUsoCoreWorker.exe": "Aims to manage and orchestrate the installation of Windows Updates to keep The System up-tp-date with latest Security pathEs and features",
        "winlogon.exe": "Handles user login - potential session-0 persistence",
        "lsass.exe": "Security subsystem - token and credential manipulation",
        "services.exe": "Core service controller - high value for service hijacks",
        "svchost.exe": "Generic host for services - easy to hide injected DLLs",
        "smss.exe": "Session manager - responsible for initializing system sessions",
        "csrss.exe": "Client Server Runtime - controls low-level Win32 functions",
        "MsMpEng.exe": "Microsoft Defender engine - potential evasion target",
        "MpDefenderCoreService.exe": "Secondary Defender service - rarely analyzed",
        "System": "PID 4 kernel handler - reflective injection detection",
        "taskhostw.exe": "Host for Windows Tasks - often injected for persistence",
        "consent.exe": "UAC handler - high-privilege elevation abuse target",
        "dwm.exe": "Desktop Window Manager - visual injection/hook point",
        "explorer.exe": "Desktop shell - abused via COM/registry hijack",
        "spoolsv.exe": "Print spooler - abused for RPC persistence",
        "dllhost.exe": "COM Surrogate - direct abuse target for COM instantiation",
        "rundll32.exe": "Generic DLL launcher - abused for execution",
        "sihost.exe": "Shell infrastructure - may hide persistence",
        "fontdrvhost.exe": "Font host (AppContainer) - suspicious DLL loads",
        "WmiPrvSE.exe": "WMI provider host - WMI persistence",
        "searchhost.exe": "Search UX - user-mode DLL hijack point",
        "compattelrunner.exe": "Telemetry runner - stealthy execution hijack",
        "audiodg.exe": "Audio Graph - often untouched, but high-privilege",
        "shellexperiencehost.exe": "Shell UI handler - abused via COM or injection",
        "ctfmon.exe": "CTF loader - potential for input method injection",
        "shellhost.exe": "Shell host process - can reflect persistence",
        "vmnetdhcp.exe": "VMware DHCP service - stealthy if compromised",
        "vmware-authd.exe": "VMware Auth service - potential for backdoor",
        "vmware-usbdistributor64.exe": "USB virtualization - sensitive if altered",
        "usbpid": "USB device-level service - custom payload risk",
        "securityhealthservice.exe": "Windows Security Health - injection or masking",
        "protonvpn.wireguardservice.exe": "VPN service - persistence via service hijack",
        "protonvpnservice.exe": "VPN backend - can mask tunnels or persistence",
        "vmnat.exe": "VMware NAT service - less commonly audited",
        "lsalso.exe": "LSA-like spoofed process - red flag",
        "secure system.exe": "Fake or hijacked secure system instance"
    }
    results = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid', 'username', 'memory_info']):
        try:
            name = proc.info['name'].lower()
            if name in target_processes:
                vms = getattr(proc.info['memory_info'], 'vms', 0)
                exe = proc.info['exe']
                user = proc.info['username']
                score = 0
                reasons = []

                if not exe or not os.path.exists(exe):
                    score -= 50
                    reasons.append("❌ Executable path missing or invalid")
                elif not is_signed_file(exe):
                    score -= 50
                    reasons.append("⚠️ Unsigned binary")
                if vms > ram_size * 10:
                    score -= 50
                    reasons.append(f"🚩 VMS exceeds 10x RAM ({vms} > {ram_size * 10})")

                results.append({
                    "name": name,
                    "description": target_processes[name],
                    "pid": proc.info['pid'],
                    "ppid": proc.info['ppid'],
                    "user": user,
                    "exe": exe,
                    "vms": vms,
                    "score": score,
                    "reasons": reasons
                })
        except Exception:
            continue
    return results

def run_deep_clsid_correlation_analysis(clsid_data):
    import datetime
    from psutil import virtual_memory
    ram_size = virtual_memory().total
    now = datetime.datetime.now()
    print("\n🧠 Launching deep analysis on filtered suspicious CLSIDs...")
    summary = []
    installation_index = full_installation_index()
    flt_instances = get_fltmc_instances()
    tiworker_suspicious = analyze_critical_processes()

    for entry in tqdm(clsid_data, desc="Deep Correlation", unit="clsid"):
        file_path = entry.get("file_path", "")
        sid = entry.get("sid", "")
        clsid = entry.get("clsid", "")

        print(f"\n🔎 Checking CLSID: {clsid}")

        score = 0
        reason_flags = []
        signed = is_signed_file(file_path)

        if is_in_critical_boot_folder(file_path):
            score -= 100
            reason_flags.append("Located in critical boot folder")
            entry["boot_folder"] = True
        else:
            entry["boot_folder"] = False

        for path in TRUSTED_PATHS2:
            if file_path.startswith(path):
                if not signed:
                    score -= 40
                    reason_flags.append("File in user path but not signed")
                else:
                    score += 20
                    reason_flags.append("Signed file in user path")
                break

        if not os.path.exists(file_path):
            score -= 50
            reason_flags.append("File does not exist on disk")
            entry["file_missing"] = True
        else:
            entry["file_missing"] = False

        entry["shared_sid_control"] = any(
            e.get("sid") == sid and e.get("clsid") != clsid for e in clsid_data if "sid" in e
        )
        if entry["shared_sid_control"]:
            score -= 30
            reason_flags.append("Shared SID controls multiple CLSIDs")

        acl_output = get_clsid_owners(clsid)
        entry["sid_acl_raw"] = acl_output

        if any(prefix in acl_output for prefix in UNKNOWN_SID_PREFIXES):
            entry["unknown_sid_owners"] = True
            score -= 40
            reason_flags.append("ACL contains unknown AppContainer or SID")
        else:
            entry["unknown_sid_owners"] = False

        registry_refs = query_registry_paths(clsid)
        entry["registry_refs"] = registry_refs

        if any("AppID" in ref for ref in registry_refs):
            score += 10
            reason_flags.append("Linked AppID found")

        if any("TypeLib" in ref for ref in registry_refs):
            score += 10
            reason_flags.append("Linked TypeLib found")

        entry["fltmc_instances"] = flt_instances
        entry["signed"] = signed
        entry["score"] = score
        entry["suggest_deletion"] = score < -60
        entry["reason_flags"] = reason_flags
        filename = os.path.basename(file_path)
        entry["other_versions"] = find_other_versions(filename)

        # Display all known relevant metadata
        print(f"📁 File Path: {file_path}")
        print(f"🔒 Signed: {'Yes' if signed else 'No'}")
        print(f"🧾 Registry References: {registry_refs}")
        print(f"🧠 ACL Output: {acl_output.strip()[:100]}...")
        print(f"📦 Boot Folder: {entry['boot_folder']}")
        print(f"📌 Other Versions Found: {entry['other_versions']}")

        summary.append(entry)

        if entry["suggest_deletion"]:
            print(f"⚠️ Suspicious: CLSID: {clsid} | Score: {score} | File: {file_path}\nReasons: {', '.join(reason_flags)}")
        else:
            print(f"✅ Clean or low-risk: CLSID: {clsid} | Score: {score}")

    print("[+] Deep CLSID Correlation Completed.")
    if tiworker_suspicious:
        print(f"\n⚠️ Suspicious system-level processes detected:")
        for proc in tiworker_suspicious:
            print(f" - {proc['name']} (PID: {proc['pid']}) | Score: {proc['score']} | Flags: {', '.join(proc['reasons'])}")
    return summary


def vt_check_hashes(entries):
    api_key = get_virustotal_api_key()
    if not api_key:
        print(Fore.RED + "No VirusTotal API key found. Skipping VT checks.")
        return
    for entry in entries:
        sha256 = entry.get("SHA256")
        if not sha256:
            continue
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": api_key}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                total = sum(stats.values())
                positives = stats.get("malicious", 0)
                entry["VT_Result"] = f"{positives}/{total}"
                if 'VirusTotal' not in keys:
                    keys = list(keys) + ['VirusTotal']

            elif response.status_code == 404:
                entry["VT_Result"] = "Not found"
            else:
                entry["VT_Result"] = f"Error: {response.status_code}"
        except Exception as e:
            entry["VT_Result"] = f"Error: {str(e)}"
def COM_Based_Indirect_Persistence():
    """
    Scans registry locations and additional files for COM-based persistence.
    Categories scanned:
    - CLSID under Wow6432Node (32-bit COM on 64-bit system)
    - Image File Execution Options (IFEO) – Debugger/VerifierDlls
    - Winsock Catalog (LSP) – Protocol Providers
    - Winsock Namespace Providers – NameSpace Providers
    - Active Setup – StubPath Values
    - ShellServiceObjectDelayLoad – Autoloaded Shell Extensions
    - ShellExecuteHooks – ShellExecute Hooks
    """
    results = []
    # 1. CLSIDs via Wow6432Node (Systems 64-bit)
    try:
        root_hklm = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        clsid_key_path = r"SOFTWARE\\WOW6432Node\\Classes\\CLSID"
        clsid_key = winreg.OpenKey(root_hklm, clsid_key_path)
        total = winreg.QueryInfoKey(clsid_key)[0]
        print(Fore.CYAN + "🔍 Scanning 32-bit COM CLSIDs...")
        for i in tqdm(range(total), desc="CLSID (Wow6432)", unit="key"):
            try:
                subkey_name = winreg.EnumKey(clsid_key, i)
            except OSError:
                continue
            inproc_path = f"{clsid_key_path}\\{subkey_name}\\InprocServer32"
            try:
                with winreg.OpenKey(root_hklm, inproc_path) as inproc:
                    value, _ = winreg.QueryValueEx(inproc, None)
                    dll_path = os.path.expandvars(value)
                    file_exists = os.path.isfile(dll_path)
                    file_found_elsewhere = False
                    if not file_exists and os.path.exists("full_installation_index.json"):
                        file_found_elsewhere = verify_dll_exists_elsewhere(dll_path)
                    autorun_hit, svc_hit = check_autoruns_and_services(dll_path)
                    sha256 = compute_file_hash(dll_path) if file_exists else None
                    hash_status = check_hash_status(sha256) if sha256 else "N/A"
                    entry = {
                        'Category': 'CLSID_Wow6432',
                        'CLSID': subkey_name,
                        'DLL': dll_path,
                        'DispatchTest': test_dispatch(subkey_name),
                        'FileExists': file_exists,
                        'IsTrustedPath': any(dll_path.startswith(p) for p in TRUSTED_PATHS),
                        'IsSigned': verify_signature(dll_path) if file_exists else False,
                        'IsServiceLinked': is_linked_to_service(dll_path),
                        'IsScheduledTaskLinked': is_linked_to_scheduled_task(dll_path),
                        'Autorun': autorun_hit,
                        'Service': svc_hit,
                        'FoundElsewhere': file_found_elsewhere,
                        'SHA256': sha256,
                        'HashStatus': hash_status
                    }
                    results.append(entry)
            except FileNotFoundError:
                continue
    except Exception as e:
        print(Fore.RED + f"⚠ Error scanning Wow6432Node CLSIDs: {e}")
    finally:
        try:
            winreg.CloseKey(clsid_key)
        except:
            pass
    # 2. Image File Execution Options (IFEO) - Debugger and VerifierDlls
    try:
        ifeo_base_path = r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
        ifeo_key = winreg.OpenKey(root_hklm, ifeo_base_path)
        total = winreg.QueryInfoKey(ifeo_key)[0]
        print(Fore.CYAN + "🔍 Running COM-Based Indirect Persistence Scan...")
        for j in range(total):
            try:
                subkey_name = winreg.EnumKey(ifeo_key, j)
            except OSError:
                continue
            sub_path = f"{ifeo_base_path}\\{subkey_name}"
            try:
                with winreg.OpenKey(root_hklm, sub_path) as subkey:
                    debugger_value = None
                    verifier_value = None
                    try:
                        debugger_value, _ = winreg.QueryValueEx(subkey, "Debugger")
                    except Exception:
                        pass
                    try:
                        verifier_value, _ = winreg.QueryValueEx(subkey, "VerifierDlls")
                    except Exception:
                        pass
                    # IFEO Debugger
                    if debugger_value:
                        dbg = str(debugger_value)
                        dbg_path = dbg.strip().strip('"')
                        if " " in dbg_path:
                            if dbg_path.startswith('"') and '"' in dbg_path[1:]:
                                dbg_path = dbg_path[1:dbg_path.find('"', 1)]
                            else:
                                dbg_path = dbg_path.split(" ")[0]
                        dbg_path = os.path.expandvars(dbg_path)
                        file_exists = os.path.isfile(dbg_path)
                        file_found_elsewhere = False
                        if not file_exists and os.path.exists("full_installation_index.json"):
                            file_found_elsewhere = verify_dll_exists_elsewhere(dbg_path)
                        autorun_hit, svc_hit = check_autoruns_and_services(dbg_path)
                        sha256 = compute_file_hash(dbg_path) if file_exists else None
                        hash_status = check_hash_status(sha256) if sha256 else "N/A"
                        entry = {
                            'Category': 'IFEO_Debugger',
                            'TargetImage': subkey_name,
                            'Debugger': dbg,
                            'DLL': dbg_path,
                            'DispatchTest': False,
                            'FileExists': file_exists,
                            'IsTrustedPath': any(dbg_path.startswith(p) for p in TRUSTED_PATHS),
                            'IsSigned': verify_signature(dbg_path) if file_exists else False,
                            'IsServiceLinked': is_linked_to_service(dbg_path),
                            'IsScheduledTaskLinked': is_linked_to_scheduled_task(dbg_path),
                            'Autorun': autorun_hit,
                            'Service': svc_hit,
                            'FoundElsewhere': file_found_elsewhere,
                            'SHA256': sha256,
                            'HashStatus': hash_status
                        }
                        results.append(entry)
                    # IFEO VerifierDlls
                    if verifier_value:
                        ver = str(verifier_value)
                        for dll in ver.split(';'):
                            dll = dll.strip().strip('"')
                            if not dll:
                                continue
                            dll_path = os.path.expandvars(dll)
                            file_exists = os.path.isfile(dll_path)
                            file_found_elsewhere = False
                            if not file_exists and os.path.exists("full_installation_index.json"):
                                file_found_elsewhere = verify_dll_exists_elsewhere(dll_path)
                            autorun_hit, svc_hit = check_autoruns_and_services(dll_path)
                            sha256 = compute_file_hash(dll_path) if file_exists else None
                            hash_status = check_hash_status(sha256) if sha256 else "N/A"
                            entry = {
                                'Category': 'IFEO_VerifierDLL',
                                'TargetImage': subkey_name,
                                'DLL': dll_path,
                                'DispatchTest': False,
                                'FileExists': file_exists,
                                'IsTrustedPath': any(dll_path.startswith(p) for p in TRUSTED_PATHS),
                                'IsSigned': verify_signature(dll_path) if file_exists else False,
                                'IsServiceLinked': is_linked_to_service(dll_path),
                                'IsScheduledTaskLinked': is_linked_to_scheduled_task(dll_path),
                                'Autorun': autorun_hit,
                                'Service': svc_hit,
                                'FoundElsewhere': file_found_elsewhere,
                                'SHA256': sha256,
                                'HashStatus': hash_status
                            }
                            results.append(entry)
            except FileNotFoundError:
                continue
    except Exception as e:
        print(Fore.RED + f"⚠ Error scanning IFEO: {e}")
    finally:
        try:
            winreg.CloseKey(ifeo_key)
        except:
            pass
    # 3. Winsock Protocol Catalog (LSP)
    try:
        winsock_base = r"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9"
        for cat in ["Catalog_Entries64", "Catalog_Entries"]:
            try:
                cat_path = f"{winsock_base}\\{cat}"
                cat_key = winreg.OpenKey(root_hklm, cat_path)
            except FileNotFoundError:
                continue
            total_entries = winreg.QueryInfoKey(cat_key)[0]
            print(Fore.CYAN + f"🔍 Scanning Winsock {cat}...")
            for k in range(total_entries):
                try:
                    entry_name = winreg.EnumKey(cat_key, k)
                except OSError:
                    continue
                entry_path = f"{cat_path}\\{entry_name}"
                try:
                    with winreg.OpenKey(root_hklm, entry_path) as entry_key:
                        lib_value = None
                        try:
                            lib_value, _ = winreg.QueryValueEx(entry_key, "LibraryPath")
                        except Exception:
                            pass
                        if not lib_value:
                            continue
                        dll_path = os.path.expandvars(str(lib_value))
                        file_exists = os.path.isfile(dll_path)
                        file_found_elsewhere = False
                        if not file_exists and os.path.exists("full_installation_index.json"):
                            file_found_elsewhere = verify_dll_exists_elsewhere(dll_path)
                        autorun_hit, svc_hit = check_autoruns_and_services(dll_path)
                        sha256 = compute_file_hash(dll_path) if file_exists else None
                        hash_status = check_hash_status(sha256) if sha256 else "N/A"
                        entry = {
                            'Category': 'WinsockLSP',
                            'Entry': entry_name,
                            'DLL': dll_path,
                            'DispatchTest': False,
                            'FileExists': file_exists,
                            'IsTrustedPath': any(dll_path.startswith(p) for p in TRUSTED_PATHS),
                            'IsSigned': verify_signature(dll_path) if file_exists else False,
                            'IsServiceLinked': is_linked_to_service(dll_path),
                            'IsScheduledTaskLinked': is_linked_to_scheduled_task(dll_path),
                            'Autorun': autorun_hit,
                            'Service': svc_hit,
                            'FoundElsewhere': file_found_elsewhere,
                            'SHA256': sha256,
                            'HashStatus': hash_status
                        }
                        results.append(entry)
                except FileNotFoundError:
                    continue
            winreg.CloseKey(cat_key)
    except Exception as e:
        print(Fore.RED + f"⚠ Error scanning Winsock Catalog: {e}")
    # 4. Winsock Namespace Providers (NSP)
    try:
        nsp_base = r"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5"
        for cat in ["Catalog_Entries64", "Catalog_Entries"]:
            try:
                cat_path = f"{nsp_base}\\{cat}"
                cat_key = winreg.OpenKey(root_hklm, cat_path)
            except FileNotFoundError:
                continue
            total_entries = winreg.QueryInfoKey(cat_key)[0]
            print(Fore.CYAN + f"🔍 Scanning Winsock NameSpace {cat}...")
            for k in range(total_entries):
                try:
                    entry_name = winreg.EnumKey(cat_key, k)
                except OSError:
                    continue
                entry_path = f"{cat_path}\\{entry_name}"
                try:
                    with winreg.OpenKey(root_hklm, entry_path) as entry_key:
                        lib_value = None
                        try:
                            lib_value, _ = winreg.QueryValueEx(entry_key, "LibraryPath")
                        except Exception:
                            pass
                        if not lib_value:
                            continue
                        dll_path = os.path.expandvars(str(lib_value))
                        file_exists = os.path.isfile(dll_path)
                        file_found_elsewhere = False
                        if not file_exists and os.path.exists("full_installation_index.json"):
                            file_found_elsewhere = verify_dll_exists_elsewhere(dll_path)
                        autorun_hit, svc_hit = check_autoruns_and_services(dll_path)
                        sha256 = compute_file_hash(dll_path) if file_exists else None
                        hash_status = check_hash_status(sha256) if sha256 else "N/A"
                        entry = {
                            'Category': 'WinsockNSP',
                            'Entry': entry_name,
                            'DLL': dll_path,
                            'DispatchTest': False,
                            'FileExists': file_exists,
                            'IsTrustedPath': any(dll_path.startswith(p) for p in TRUSTED_PATHS),
                            'IsSigned': verify_signature(dll_path) if file_exists else False,
                            'IsServiceLinked': is_linked_to_service(dll_path),
                            'IsScheduledTaskLinked': is_linked_to_scheduled_task(dll_path),
                            'Autorun': autorun_hit,
                            'Service': svc_hit,
                            'FoundElsewhere': file_found_elsewhere,
                            'SHA256': sha256,
                            'HashStatus': hash_status
                        }
                        results.append(entry)
                except FileNotFoundError:
                    continue
            winreg.CloseKey(cat_key)
    except Exception as e:
        print(Fore.RED + f"⚠ Error scanning Winsock NSP: {e}")
    # 5. Active Setup
    try:
        active_setup_path = r"SOFTWARE\\Microsoft\\Active Setup\\Installed Components"
        as_root = winreg.OpenKey(root_hklm, active_setup_path)
        total = winreg.QueryInfoKey(as_root)[0]
        print(Fore.CYAN + "🔍 Scanning Active Setup StubPaths...")
        for m in range(total):
            try:
                comp_key_name = winreg.EnumKey(as_root, m)
            except OSError:
                continue
            comp_path = f"{active_setup_path}\\{comp_key_name}"
            try:
                with winreg.OpenKey(root_hklm, comp_path) as comp_key:
                    stub_value = None
                    try:
                        stub_value, _ = winreg.QueryValueEx(comp_key, "StubPath")
                    except Exception:
                        pass
                    if stub_value:
                        stub_cmd = str(stub_value)
                        main_path = stub_cmd.strip().strip('"')
                        if " " in main_path:
                            if main_path.startswith('"') and '"' in main_path[1:]:
                                main_path = main_path[1:main_path.find('"', 1)]
                            else:
                                main_path = main_path.split(" ")[0]
                        main_path = os.path.expandvars(main_path)
                        file_exists = os.path.isfile(main_path)
                        file_found_elsewhere = False
                        if not file_exists and os.path.exists("full_installation_index.json"):
                            file_found_elsewhere = verify_dll_exists_elsewhere(main_path)
                        autorun_hit, svc_hit = check_autoruns_and_services(main_path)
                        sha256 = compute_file_hash(main_path) if file_exists else None
                        hash_status = check_hash_status(sha256) if sha256 else "N/A"
                        entry = {
                            'Category': 'ActiveSetup',
                            'Component': comp_key_name,
                            'Command': stub_cmd,
                            'DLL': main_path,
                            'DispatchTest': False,
                            'FileExists': file_exists,
                            'IsTrustedPath': any(main_path.startswith(p) for p in TRUSTED_PATHS),
                            'IsSigned': verify_signature(main_path) if file_exists else False,
                            'IsServiceLinked': is_linked_to_service(main_path),
                            'IsScheduledTaskLinked': is_linked_to_scheduled_task(main_path),
                            'Autorun': autorun_hit,
                            'Service': svc_hit,
                            'FoundElsewhere': file_found_elsewhere,
                            'SHA256': sha256,
                            'HashStatus': hash_status
                        }
                        results.append(entry)
            except FileNotFoundError:
                continue
    except Exception as e:
        print(Fore.RED + f"⚠ Error scanning Active Setup: {e}")
    finally:
        try:
            winreg.CloseKey(as_root)
        except:
            pass
    # 6. ShellServiceObjectDelayLoad (SSODL)
    try:
        ssodl_path = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad"
        ssodl_key = winreg.OpenKey(root_hklm, ssodl_path)
        num_values = winreg.QueryInfoKey(ssodl_key)[1]
        print(Fore.CYAN + "🔍 Scanning ShellServiceObjectDelayLoad...")
        for idx in range(num_values):
            try:
                value_name, clsid_str, val_type = winreg.EnumValue(ssodl_key, idx)
            except OSError:
                continue
            name = value_name if value_name else "(Default)"
            clsid = str(clsid_str).strip()
            if not clsid or len(clsid) < 5:
                continue
            clsid = clsid.strip('{').strip('}')
            dll_path = None
            try:
                clsid_inproc = winreg.OpenKey(root_hklm, f"SOFTWARE\\Classes\\CLSID\\{{{clsid}}}\\InprocServer32")
                dll_path, _ = winreg.QueryValueEx(clsid_inproc, None)
                dll_path = os.path.expandvars(str(dll_path))
            except Exception:
                dll_path = None
            if dll_path:
                file_exists = os.path.isfile(dll_path)
                file_found_elsewhere = False
                if not file_exists and os.path.exists("full_installation_index.json"):
                    file_found_elsewhere = verify_dll_exists_elsewhere(dll_path)
                autorun_hit, svc_hit = check_autoruns_and_services(dll_path)
                sha256 = compute_file_hash(dll_path) if file_exists else None
                hash_status = check_hash_status(sha256) if sha256 else "N/A"
                entry = {
                    'Category': 'ShellServiceObjectDelayLoad',
                    'EntryName': name,
                    'CLSID': clsid,
                    'DLL': dll_path,
                    'DispatchTest': test_dispatch(clsid),
                    'FileExists': file_exists,
                    'IsTrustedPath': any(dll_path.startswith(p) for p in TRUSTED_PATHS),
                    'IsSigned': verify_signature(dll_path) if file_exists else False,
                    'IsServiceLinked': is_linked_to_service(dll_path),
                    'IsScheduledTaskLinked': is_linked_to_scheduled_task(dll_path),
                    'Autorun': autorun_hit,
                    'Service': svc_hit,
                    'FoundElsewhere': file_found_elsewhere,
                    'SHA256': sha256,
                    'HashStatus': hash_status
                }
                results.append(entry)
        winreg.CloseKey(ssodl_key)
    except Exception as e:
        print(Fore.RED + f"⚠ Error scanning SSODL: {e}")
    # 7. ShellExecuteHooks – Hooks and-ShellExecute
    try:
        hooks_path = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks"
        hooks_key = winreg.OpenKey(root_hklm, hooks_path)
        num_values = winreg.QueryInfoKey(hooks_key)[1]
        print(Fore.CYAN + "🔍 Scanning ShellExecuteHooks...")
        for idx in range(num_values):
            try:
                value_name, clsid_str, val_type = winreg.EnumValue(hooks_key, idx)
            except OSError:
                continue
            name = value_name if value_name else "(Default)"
            clsid = str(clsid_str).strip()
            if not clsid:
                continue
            clsid = clsid.strip('{').strip('}')
            dll_path = None
            try:
                clsid_inproc = winreg.OpenKey(root_hklm, f"SOFTWARE\\Classes\\CLSID\\{{{clsid}}}\\InprocServer32")
                dll_path, _ = winreg.QueryValueEx(clsid_inproc, None)
                dll_path = os.path.expandvars(str(dll_path))
            except Exception:
                dll_path = None
            if dll_path:
                file_exists = os.path.isfile(dll_path)
                file_found_elsewhere = False
                if not file_exists and os.path.exists("full_installation_index.json"):
                    file_found_elsewhere = verify_dll_exists_elsewhere(dll_path)
                autorun_hit, svc_hit = check_autoruns_and_services(dll_path)
                sha256 = compute_file_hash(dll_path) if file_exists else None
                hash_status = check_hash_status(sha256) if sha256 else "N/A"
                entry = {
                    'Category': 'ShellExecuteHooks',
                    'EntryName': name,
                    'CLSID': clsid,
                    'DLL': dll_path,
                    'DispatchTest': test_dispatch(clsid),
                    'FileExists': file_exists,
                    'IsTrustedPath': any(dll_path.startswith(p) for p in TRUSTED_PATHS),
                    'IsSigned': verify_signature(dll_path) if file_exists else False,
                    'IsServiceLinked': is_linked_to_service(dll_path),
                    'IsScheduledTaskLinked': is_linked_to_scheduled_task(dll_path),
                    'Autorun': autorun_hit,
                    'Service': svc_hit,
                    'FoundElsewhere': file_found_elsewhere,
                    'SHA256': sha256,
                    'HashStatus': hash_status
                }
                results.append(entry)
        winreg.CloseKey(hooks_key)
    except Exception as e:
        print(Fore.RED + f"⚠ Error scanning ShellExecuteHooks: {e}")
    with open(COM_EXPORT_EXTENDED_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    return results
def update_hash_lists():
    from datetime import timedelta
    print(Fore.CYAN + "🔄 Updating known_bad_checksums.json...")
    try:
        response = requests.get(LOKI_HASH_URL, timeout=20)
        response.raise_for_status()
        hashes = response.text.splitlines()
        bad_hashes = [h.strip().lower() for h in hashes if h.strip() and not h.startswith('#')]
        with open('known_bad_checksums.json', 'w') as f:
            json.dump(bad_hashes, f, indent=2)
        print(Fore.GREEN + "✅ known_bad_checksums.json updated successfully.")
    except Exception as e:
        print(Fore.RED + f"❌ Failed to update known_bad_checksums.json: {e}")
    print(Fore.CYAN + "🔄 Updating known_good_checksums.json...")
    good_hashes = []
    unknown_hashes = []
    system_paths = [r"C:\\Windows\\System32", r"C:\\Windows\\SysWOW64"]
    total_files = sum([len(files) for sp in system_paths for _, _, files in os.walk(sp)])
    processed = 0
    start_time = time.time()
    for system_path in system_paths:
        for root, dirs, files in os.walk(system_path):
            for file in files:
                full_path = os.path.join(root, file)
                try:
                    file_hash = compute_file_hash(full_path)
                    if not file_hash:
                        continue
                    if verify_signature(full_path):
                        good_hashes.append(file_hash.lower())
                    else:
                        unknown_hashes.append(file_hash.lower())
                except Exception:
                    continue
                processed += 1
                if processed % 500 == 0:
                    elapsed = timedelta(seconds=int(time.time() - start_time))
                    percent = (processed / total_files) * 100
                    print(Fore.LIGHTCYAN_EX + f"⏳ Progress: {processed}/{total_files} files ({percent:.2f}%) - Elapsed: {elapsed}")
    with open('known_good_checksums.json', 'w') as f:
        json.dump(good_hashes, f, indent=2)
    with open('unknown_hashes.json', 'w') as f:
        json.dump(unknown_hashes, f, indent=2)
    print(Fore.GREEN + "✅ known_good_checksums.json and unknown_hashes.json updated successfully.")
def run_with_admin_privileges():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return True
    vbs_script = os.path.join(tempfile.gettempdir(), 'run_with_admin.vbs')
    with open(vbs_script, 'w') as file:
        file.write('Set UAC = CreateObject("Shell.Application")\n')
        file.write(f'UAC.ShellExecute "{sys.executable}", "{__file__}", "", "runas", 1')
    subprocess.Popen(['cscript', vbs_script], shell=True)
    sys.exit()
def compute_file_hash(path):
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None
def get_key_owner(key_path):
    try:
        full_key = r"HKEY_CLASSES_ROOT\\" + key_path
        sd = GetNamedSecurityInfo(full_key, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION)
        owner_sid = sd.GetSecurityDescriptorOwner()
        return win32security.LookupAccountSid(None, owner_sid)[0]
    except Exception as e:
        return f"Error: {e}"
def verify_dll_exists_elsewhere(dll_path):
    try:
        with open("full_installation_index.json", "r") as f:
            all_files = json.load(f)
        dll_name = os.path.basename(dll_path).lower()
        for path in all_files:
            if dll_name == os.path.basename(path).lower():
                return True
        return False
    except Exception as e:
        print(Fore.RED + f"⚠ Failed to verify DLL in scanned drives: {e}")
        return False
def scan_installed_files():
    all_files = []
    drives = [f"{d}:/" for d in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if os.path.exists(f"{d}:/")]
    total_files = 0
    print(Fore.CYAN + "🔍 Counting files across all drives (pre-scan)...")
    for drive in drives:
        drive_file_count = 0
        for _, _, files in os.walk(drive):
            drive_file_count += len(files)
        total_files += drive_file_count
        print(Fore.LIGHTYELLOW_EX + f"• {drive} → {drive_file_count} files")
    print(Fore.YELLOW + f"📦 Estimated total files to scan: {total_files}")
    start_time = time.time()
    scanned = 0
    with tqdm(total=total_files, desc="📂 Scanning all drives", unit="file") as pbar:
        for drive in drives:
            for root, _, files in os.walk(drive):
                for file in files:
                    full = os.path.join(root, file)
                    all_files.append(full)
                    scanned += 1
                    pbar.update(1)
                    if scanned % 500 == 0:
                        elapsed = timedelta(seconds=int(time.time() - start_time))
                        pbar.set_postfix(Elapsed=str(elapsed))
    with open("full_installation_index.json", "w") as f:
        json.dump(all_files, f, indent=2)
    duration = timedelta(seconds=round(time.time() - start_time))
    print(Fore.GREEN + f"\n✅ Full disk scan completed in {duration}.")
def is_linked_to_service(dll_path):
    try:
        result = subprocess.run(['sc', 'query', 'type=', 'service', 'state=', 'all'], capture_output=True, text=True)
        return dll_path.lower() in result.stdout.lower()
    except Exception:
        return False
def is_linked_to_scheduled_task(dll_path):
    try:
        task_dir = r"C:\Windows\System32\Tasks"
        for root, dirs, files in os.walk(task_dir):
            for file in files:
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read().lower()
                        if dll_path.lower() in content:
                            return True
                except Exception:
                    continue
        return False
    except Exception:
        return False
def verify_signature(path):
    if not os.path.exists(path):
        return False
    command = f"Get-AuthenticodeSignature '{path}' | Select-Object -ExpandProperty Status"
    process = subprocess.Popen(["powershell", "-Command", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    status = process.stdout.read().strip()
    return status == 'Valid'
def check_autoruns_and_services(dll_path):
    dll_path = dll_path.lower()
    autorun_hits = []
    svc_hits = []
    run_keys = [
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    ]
    for key in run_keys:
        try:
            output = subprocess.check_output(["reg", "query", key], stderr=subprocess.DEVNULL, universal_newlines=True)
            if dll_path in output.lower():
                autorun_hits.append(key)
        except subprocess.CalledProcessError:
            continue
    try:
        output = subprocess.check_output("sc query type= service state= all", shell=True, universal_newlines=True)
        if dll_path in output.lower():
            svc_hits.append("ServiceList")
    except Exception:
        pass
    return bool(autorun_hits), bool(svc_hits)
def save_suspicious_to_csv(suspicious_list, filename="suspicious_COM.csv"):
    if not suspicious_list:
        print(Fore.GREEN + "No suspicious COM entries to save.")
        return
    keys = suspicious_list[0].keys()
    if 'VirusTotal' not in keys:
        keys = list(keys) + ['VirusTotal']
    for entry in suspicious_list:
        if "VT_Result" in entry:
            entry["VirusTotal"] = entry["VT_Result"]
        else:
            entry["VirusTotal"] = "N/A"
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for item in suspicious_list:
            writer.writerow(item)
    print(Fore.YELLOW + f"\nSuspicious COM entries saved to {filename}")
VT_CACHE = {}
def check_hash_status(sha256):
    if not sha256:
        return "Unknown"
    sha256 = sha256.lower()
    try:
        with open("known_good_checksums.json") as f:
            good = json.load(f)
        with open("known_bad_checksums.json") as f:
            bad = json.load(f)
        if sha256 in good:
            return "Whitelisted"
        elif sha256 in bad:
            return "Blacklisted"
        else:
            return "Unknown"
    except:
        return "Unknown"
def check_virustotal_hash(sha256):
    if not sha256:
        return "Unknown"
    if sha256 in VT_CACHE:
        return VT_CACHE[sha256]
    config = configparser.ConfigParser()
    config.read('configVT.ini')
    api_key = config.get('vt', 'api_key', fallback=None)
    if not api_key:
        print(Fore.RED + "❌ No VirusTotal API key found. Skipping VT check.")
        return "Unknown"
    url = f"https://www.virustotal.com/vtapi/v2/file/report?apikey={api_key}&resource={sha256}"
    for attempt in range(5):
        try:
            response = requests.get(url)
            if response.status_code == 204:
                print(Fore.YELLOW + "🕒 Rate limit reached. Waiting 61 seconds...")
                time.sleep(61)
                continue
            if response.status_code == 200:
                data = response.json()
                if data.get("response_code") == 1:
                    positives = data.get("positives", 0)
                    VT_CACHE[sha256] = f"Detected by {positives} engines"
                    return VT_CACHE[sha256]
                else:
                    VT_CACHE[sha256] = "Not Found"
                    return "Not Found"
            else:
                print(Fore.RED + f"Error from VT API: {response.status_code}")
                time.sleep(10)
        except requests.RequestException as e:
            print(Fore.RED + f"VT request error: {e}")
            time.sleep(10)
    return "Unknown"
def load_or_request_api():
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    def test_api_key(key):
        try:
            openai.api_key = key
            openai.Model.list()
            return True
        except openai.error.AuthenticationError:
            print(Fore.RED + "❌ Invalid OpenAI API key. Please try again.")
            return False
        except Exception as e:
            print(Fore.RED + f"⚠ Unexpected error while testing API key: {e}")
            return False
    if 'openai' in config and 'api_key' in config['openai']:
        key = config['openai']['api_key']
        if test_api_key(key):
            return
        else:
            print(Fore.YELLOW + "🧪 Stored key is invalid or expired. Enter new one.")
    while True:
        key = input(Fore.CYAN + "\n🔑 Enter your OpenAI API key: ")
        if test_api_key(key):
            config['openai'] = {'api_key': key}
            with open(CONFIG_FILE, 'w') as configfile:
                config.write(configfile)
            print(Fore.GREEN + "✅ API key saved and verified successfully.\n")
            break
def test_dispatch(clsid):
    try:
        Dispatch(f"{{{clsid}}}")
        return True
    except:
        return False
def estimate_ai_cost(clsid_count):
    avg_tokens_per_clsid = 100
    estimated_total_tokens = clsid_count * avg_tokens_per_clsid
    pricing = {
        "gpt-3.5-turbo": 0.0005,
        "gpt-4": 0.01
    }
    print(Fore.CYAN + "\n📊 Estimated AI Analysis Cost Breakdown:")
    print(Fore.YELLOW + f"• Number of CLSIDs to analyze: {clsid_count}")
    print(Fore.YELLOW + f"• Estimated tokens per CLSID: {avg_tokens_per_clsid}")
    print(Fore.YELLOW + f"• Total estimated tokens: {estimated_total_tokens}")
    print(Fore.MAGENTA + "\n💡 Choose your AI model:")
    print(Fore.CYAN + "1. GPT-3.5 Turbo (Fast & Cheap)")
    print(Fore.CYAN + "2. GPT-4 (Slower & Precise)")
    model_choice = input(Fore.YELLOW + "Enter choice (1 or 2): ")
    if model_choice.strip() == "1":
        model = "gpt-3.5-turbo"
    elif model_choice.strip() == "2":
        model = "gpt-4"
    else:
        print(Fore.RED + "Invalid choice. Exiting.")
        sys.exit()
    price_per_1k = pricing[model]
    total_price = (estimated_total_tokens / 1000) * price_per_1k
    print(Fore.GREEN + f"\n💰 Estimated Cost with {model}: ~${total_price:.4f}\n")
    proceed = input(Fore.CYAN + "👉 Do you want to proceed with AI analysis using this model? (y/n): ")
    if proceed.strip().lower() != 'y':
        print(Fore.RED + "\n⛔ Operation cancelled by user.")
        sys.exit()
    return model
def should_send_to_virustotal(entry):
    if entry.get("ManualWhitelist", False):
        return False, "Whitelisted manually."
    if entry.get("IsSigned", False) and entry.get("IsTrustedPath", False):
        return False, "Signed and located in a trusted path."
    # Match the exact detection logic used for AIAnalysisRequired
    if (
        not entry.get("DispatchTest", True)
        and not entry.get("IsTrustedPath", True)
        and not entry.get("FileExists", True)
        and not entry.get("IsSigned", True)
    ):
        return True, REASONS["combo"]
    if entry.get("StaticAnalysisSuspect", False):
        return True, REASONS["static"]
    if entry.get("AIAnalysisRequired", False):
        return True, REASONS["ai"]
    if entry.get("IsPotentiallyJunk", False) and not entry.get("IsSigned", False):
        return True, REASONS["junk"]
    return False, "Did not meet suspicious criteria."
def scan_com_entries():
    global VT_USER_AUTO_MODE
    root = winreg.ConnectRegistry(None, winreg.HKEY_CLASSES_ROOT)
    base = r"CLSID"
    result = []
    print("\nDo you want to send suspicious files to VirusTotal? (y/n): ", end="")
    vt_decision = input().strip().lower()
    if vt_decision not in ["y", "n"]:
        print("❌ Invalid input. Please choose 'y' or 'n'.")
        scan_com_entries()
    if vt_decision == 'y':
        print("\nSend automatically all files detected as suspicious or ask for each one? (all/ask): ", end="")
        VT_USER_AUTO_MODE = input().strip().lower()

    try:
        clsid = winreg.OpenKey(root, base)
        total_keys = winreg.QueryInfoKey(clsid)[0]
        for i in tqdm(range(total_keys), desc="Scanning CLSIDs", unit="key"):
            try:
                subkey_name = winreg.EnumKey(clsid, i)
                path = f"{base}\\{subkey_name}\\InprocServer32"
                try:
                    with winreg.OpenKey(root, path) as subkey:
                        value, _ = winreg.QueryValueEx(subkey, None)
                        dll_path = os.path.expandvars(value)
                        file_exists = os.path.isfile(dll_path)
                        entry = {
                            'CLSID': subkey_name,
                            'DLL': dll_path,
                            'FileExists': file_exists,
                            'IsTrustedPath': any(dll_path.startswith(p) for p in TRUSTED_PATHS),
                            'IsSigned': False,
                            'ManualWhitelist': False,
                            'IsPotentiallyJunk': False,
                            'StaticAnalysisSuspect': False,
                            'AIAnalysisRequired': False,
                            'DispatchTest': False,
                            'SHA256': compute_file_hash(dll_path) if file_exists else None
                        }
                        entry['IsSigned'] = verify_signature(dll_path) if file_exists else False
                        entry['DispatchTest'] = test_dispatch(subkey_name)
                        should_send, reason = should_send_to_virustotal(entry)
                        entry['ShouldSendToVT'] = should_send
                        entry['SuspicionReason'] = reason
                        if should_send:
                            print(f"\n🔍 Suspicious entry detected: CLSID: {entry['CLSID']} | {entry['DLL']}\nReason: {reason}")
                            entry['AIAnalysisRequired'] = True
                            if VT_USER_AUTO_MODE:
                                if not entry.get('SHA256'):
                                    print(Fore.LIGHTBLACK_EX + f"⚠️ Skipping VT: {entry['DLL']} (No SHA256 - file missing or unreadable)")
                                else:
                                    if VT_USER_AUTO_MODE == 'all':
                                        vt_check_hashes([entry])
                                        vt_result = entry.get('VT_Result', 'N/A')
                                        if vt_result != 'N/A':
                                            if "/" in vt_result:
                                                detections = vt_result.split("/")[0]
                                                if detections != "0":
                                                    print(Fore.RED + f"⚠️ VT: {entry['DLL']} flagged as malicious! {vt_result}")
                                                else:
                                                    print(Fore.GREEN + f"✅ VT: {entry['DLL']} appears clean. {vt_result}")
                                            else:
                                                print(Fore.YELLOW + f"❓ VT: {entry['DLL']} status unclear. {vt_result}")
                                        else:
                                            print(Fore.YELLOW + f"❓ VT: {entry['DLL']} status unclear. Result: N/A")
                                    elif VT_USER_AUTO_MODE == 'ask':
                                        print(f"\n🌐 Submit to VirusTotal? CLSID: {entry['CLSID']} | {entry['DLL']}\nReason: {reason}\n(y/n): ", end="")
                                        user_ans = input().strip().lower()
                                        if user_ans == 'y':
                                            vt_check_hashes([entry])
                                            vt_result = entry.get('VT_Result', 'N/A')
                                            if vt_result != 'N/A':
                                                if "/" in vt_result:
                                                    detections = vt_result.split("/")[0]
                                                    if detections != "0":
                                                        print(Fore.RED + f"⚠️ VT: {entry['DLL']} flagged as malicious! {vt_result}")
                                                    else:
                                                        print(Fore.GREEN + f"✅ VT: {entry['DLL']} appears clean. {vt_result}")
                                                else:
                                                    print(Fore.YELLOW + f"❓ VT: {entry['DLL']} status unclear. {vt_result}")
                                            else:
                                                print(Fore.YELLOW + f"❓ VT: {entry['DLL']} status unclear. Result: N/A")
                        result.append(entry)
                except FileNotFoundError:
                    continue
            except OSError:
                continue
    finally:
        winreg.CloseKey(clsid)
    with open(COM_EXPORT_FILE, 'w') as f:
        json.dump(result, f, indent=2)
    print("\n✅ COM scan completed. Results saved to", COM_EXPORT_FILE)

def query_ai(filtered_clsid_entries, mode="standard"):
    if not filtered_clsid_entries:
        print(Fore.YELLOW + "⚠ No suspicious entries passed to AI. Skipping AI analysis.")
        return []
    filtered_clsid_entries = [e for e in filtered_clsid_entries if e.get("AIAnalysisRequired")]
    if not filtered_clsid_entries:
        print(Fore.YELLOW + "⚠ No entries marked for AI analysis. Skipping.")
        return []
    print(Fore.CYAN + f"\n📊 {len(filtered_clsid_entries)} entries will be sent to AI for analysis...")
    model = estimate_ai_cost(len(filtered_clsid_entries))
    for entry in filtered_clsid_entries:
        dll_path = entry.get('DLL')
        if not dll_path:
            reason = "Unavailable - No path specified"
            entry['SHA256'] = entry['MD5'] = entry['SHA1'] = reason
            continue
        if not os.path.isfile(dll_path):
            reason = "Unavailable - File not found"
            entry['SHA256'] = entry['MD5'] = entry['SHA1'] = reason
            continue
        try:
            with open(dll_path, "rb") as f:
                data = f.read()
                entry['SHA256'] = hashlib.sha256(data).hexdigest()
                entry['MD5'] = hashlib.md5(data).hexdigest()
                entry['SHA1'] = hashlib.sha1(data).hexdigest()
        except PermissionError:
            reason = "Unavailable - Access denied"
            entry['SHA256'] = entry['MD5'] = entry['SHA1'] = reason
        except Exception as e:
            reason = f"Unavailable - Error: {str(e)}"
            entry['SHA256'] = entry['MD5'] = entry['SHA1'] = reason
    prompt_data = json.dumps(filtered_clsid_entries, indent=2)
    if mode == "extended":
        prompt = f"""
You are a highly skilled malware forensic analyst specializing in Windows persistence vectors and COM-related hijacks.

You're given registry and file-based metadata extracted from multiple persistence locations beyond standard HKCR\\CLSID entries, including:

🗂 Categories Scanned:
- WOW6432Node CLSIDs (32-bit COM hijacks)
- IFEO Debugger/VerifierDlls (Image Hijacking / DLL Injection)
- Winsock LSP / NSP (Low-level network hook DLLs)
- Active Setup StubPaths (user-level persistence)
- ShellServiceObjectDelayLoad & ShellExecuteHooks (legacy COM autoload)

📋 Indicators Provided per Entry:
- Category: Source of the persistence (e.g., IFEO_Debugger, WinsockLSP)
- DLL: Targeted DLL path
- FileExists, IsSigned, IsTrustedPath, FoundElsewhere
- SHA256, MD5, SHA1: Cryptographic hash values (if available)
- HashStatus, RegistryOwner, SuspiciousOwner

🎯 Goal:
Evaluate each entry’s risk level and provide short reasoning.

📤 Output Format:
[
  {{
    "Category": "<Type of Entry>",
    "DLL": "<DLL Path>",
    "SHA1": "<SHA1>",
    "SHA256": "<SHA256>",
    "MD5": "<MD5>",
    "Reason": "Why this entry is suspicious",
    "Confidence": "High | Medium | Low"
  }},
  ...
]

If no suspicious entries are detected, return an empty array `[]`.

🔎 Data for analysis:
{prompt_data}
"""
    else:
        prompt = f"""
You are a highly skilled malware forensic analyst specializing in COM-based malware detection and reverse engineering.

You're given detailed data on CLSID-based COM registry entries, each enriched with extensive metadata for accurate assessment.

📋 Indicators Provided for Analysis:
- FileExists, IsSigned, IsTrustedPath, DispatchTest
- IsServiceLinked / IsScheduledTaskLinked, FoundElsewhere
- SystemProtected, SuspiciousOwner
- SHA256, MD5, SHA1
- VirusTotal results (optional)

🎯 Analysis Logic & Guidelines:
Same strict filtering applies.

📤 Output Format:
[
  {{
    "CLSID": "<CLSID>",
    "DLL": "<DLL Path>",
    "SHA1": "<SHA1>",
    "SHA256": "<SHA256>",
    "MD5": "<MD5>",
    "Reason": "Concise explanation",
    "Confidence": "High | Medium | Low"
  }},
  ...
]

If no suspicious entries detected, return an empty array `[]`.

🔎 Data for analysis:
{prompt_data}
"""
    print(Fore.CYAN + "\n🔎 Sending the following entries to AI for analysis:\n")
    print(prompt_data)
    response = openai.ChatCompletion.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a malware forensic AI assistant."},
            {"role": "user", "content": prompt}
        ]
    )
    analysis = response.choices[0].message.content.strip()
    print(Fore.LIGHTBLACK_EX + f"\nAI raw response:\n{analysis[:300]}...\n")
    if not analysis:
        print(Fore.RED + "❌ Empty response from AI. Analysis failed.")
        return []
    if analysis.strip() == "[]":
        print(Fore.YELLOW + "🤖 AI indicates no suspicious entries found.")
        return []
    try:
        match = re.search(r"\[\s*{.*?}\s*]", analysis, re.DOTALL)
        json_text = match.group(0) if match else analysis
        parsed = json.loads(json_text)
    except json.JSONDecodeError as e:
        print(Fore.RED + f"❌ Invalid JSON returned by AI: {e}")
        with open(AI_OUTPUT, 'w', encoding='utf-8') as out:
            out.write(analysis)
        print(Fore.YELLOW + "⚠ Attempting fallback logic: continuing with unparsed response.")
        parsed = []
    with open(AI_OUTPUT, 'w', encoding='utf-8') as out:
        out.write(json.dumps(parsed, indent=2))
    return parsed
def restore_registry_backup():
    default_backup = "registry_backup.reg"
    if not os.path.exists(default_backup):
        print(Fore.YELLOW + f"\n⚠ Backup file '{default_backup}' not found in script directory.")
        choice = input(f"❓ Do you want to create a new empty backup file or choose an existing one?\n\nEnter '1' to Create Empty backup registry file at {(os.getcwd())}\nEnter '2' to Select it manually\nEnter '3' to return to The Main Menu\n\nEnter your Choice: ").strip().lower()
        if choice == '1':
            with open(default_backup, 'w') as f:
                f.write("Windows Registry Editor Version 5.00\n\n")
            print(Fore.GREEN + f"✅ Created new empty backup file at: {default_backup}")
            return
        elif choice == '2':
            tk.Tk().withdraw()
            selected_file = filedialog.askopenfilename(title="Select Registry Backup File", filetypes=[("Registry Files", "*.reg")])
            if not selected_file:
                print(Fore.CYAN + "No file selected. Restore cancelled.")
                return
            backup_file = selected_file
        else:
            print(Fore.CYAN + "Restore cancelled.")
            LutzimAIN()
    else:
        backup_file = default_backup
        print(Fore.CYAN + f"\n🗂 Found backup file: {backup_file} (Last Modified: {time.ctime(os.path.getmtime(backup_file))})")
    confirm = input(Fore.YELLOW + f"\n❓ Are you sure you want to restore the registry from '{backup_file}'? (y/n): ")
    if confirm.strip().lower() == 'y':
        try:
            abs_path = os.path.abspath(backup_file)
            subprocess.run(["reg", "import", abs_path], check=True)
            print(Fore.GREEN + f"\n✅ Registry successfully restored from {backup_file}.")
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"\n❌ Failed to restore registry: {e}")
    else:
        print(Fore.CYAN + "\nRestore cancelled by user.")
def backup_registry():
    print(Fore.YELLOW + "\nSelect a destination folder to save registry backup.")
    root = tk.Tk()
    root.withdraw()
    folder = filedialog.askdirectory()
    if not folder:
        print(Fore.RED + "No folder selected. Backup cancelled.")
        return None
    output_path = os.path.join(folder, "registry_backup.reg")
    subprocess.run(["reg", "export", "HKCR\\CLSID", output_path, "/y"], shell=True)
    print(Fore.GREEN + f"Registry backed up to {output_path}")
    return output_path
def get_key_owner(key_path):
    try:
        full_key = r"HKEY_CLASSES_ROOT\\" + key_path
        sd = GetNamedSecurityInfo(full_key, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION)
        owner_sid = sd.GetSecurityDescriptorOwner()
        return win32security.LookupAccountSid(None, owner_sid)[0]
    except Exception as e:
        return f"Error: {e}"
def get_key_owner_sid(key_path):
    try:
        full_key = r"HKEY_CLASSES_ROOT\\" + key_path
        sd = GetNamedSecurityInfo(full_key, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION)
        return sd.GetSecurityDescriptorOwner()
    except Exception:
        return None
def get_key_owner_name(key_path):
    try:
        sid = get_key_owner_sid(key_path)
        if sid:
            return win32security.LookupAccountSid(None, sid)[0]
        else:
            return "Unknown"
    except Exception:
        return "Unknown"
def is_unknown_sid(sid):
    sid_str = str(sid)
    return any(sid_str.startswith(prefix) for prefix in UNKNOWN_SID_PREFIXES)
def suggest_take_ownership(clsid):
    print(Fore.YELLOW + f"\n🔐 To delete CLSID {clsid}, you may need to take ownership:")
    print(Fore.CYAN + f"  > Run the following command as Administrator in CMD:")
    print(Fore.WHITE + f"    takeown /f \"HKCR\\CLSID\\{clsid}\" /a /r")
    print(Fore.WHITE + f"    icacls \"HKCR\\CLSID\\{clsid}\" /grant administrators:F /t")
    print(Fore.LIGHTBLACK_EX + "If that still fails, try Safe Mode or offline registry editing.")
def take_ownership_and_retry(clsid):
    try:
        subprocess.run(["takeown", "/f", f"HKCR\\CLSID\\{clsid}", "/a", "/r"], shell=True)
        subprocess.run(["icacls", f"HKCR\\CLSID\\{clsid}", "/grant", "administrators:F", "/t"], shell=True)
        return True
    except Exception as e:
        print(Fore.RED + f"⚠ Failed to take ownership: {e}")
        return False
def offer_deletion(suspicious_list):
    junk = []
    potential_rootkits = []
    for entry in suspicious_list:
        if 'CLSID' not in entry:
            print(Fore.YELLOW + f"\n⚠ Entry without CLSID skipped (category: {entry.get('Category', 'N/A')})")
            continue
        file_exists = entry.get('FileExists')
        is_signed = entry.get('IsSigned')
        is_trusted = entry.get('IsTrustedPath')
        dispatch = entry.get('DispatchTest')
        service = entry.get('IsServiceLinked')
        task = entry.get('IsScheduledTaskLinked')
        found_elsewhere = entry.get('FoundElsewhere')
        clsid_path = f"CLSID\\{entry['CLSID']}"
        sid = get_key_owner_sid(clsid_path)
        owner_name = get_key_owner_name(clsid_path)
        entry['RegistryOwner'] = owner_name
        if owner_name in TRUSTED_OWNERS:
            entry['SystemProtected'] = True
        elif sid and is_unknown_sid(sid):
            entry['SuspiciousOwner'] = True
        print(Fore.RED + f"\nSuspicious CLSID: {entry['CLSID']}")
        print(Fore.YELLOW + f"DLL: {entry['DLL']}")
        print(Fore.MAGENTA + f"FileExists: {'✅' if file_exists else '❌ No'}")
        print(Fore.BLUE + f"Signed: {'✅' if is_signed else '❌ No'}")
        print(Fore.CYAN + f"TrustedPath: {'✅' if is_trusted else '❌ No'}")
        print(Fore.WHITE + f"Dispatch: {'✅' if dispatch else '❌ No'}")
        print(Fore.LIGHTRED_EX + f"Linked to Service: {'✅' if service else '❌ No'}")
        print(Fore.LIGHTYELLOW_EX + f"Linked to Task: {'✅' if task else '❌ No'}")
        print(Fore.LIGHTBLACK_EX + f"FoundElsewhere: {'✅' if found_elsewhere else '❌ No'}")
        print(Fore.LIGHTMAGENTA_EX + f"Registry Owner: {owner_name}")
        print(Fore.LIGHTGREEN_EX + f"SHA256: {entry.get('SHA256', 'N/A')}")
        print(Fore.LIGHTYELLOW_EX + f"MD5: {entry.get('MD5', 'N/A')}")
        print(Fore.LIGHTCYAN_EX + f"SHA1: {entry.get('SHA1', 'N/A')}")
        print(Fore.LIGHTBLUE_EX + f"Hash Status: {entry.get('HashStatus', 'Unknown')}")
        print(Fore.LIGHTMAGENTA_EX + f"VirusTotal: {entry.get('VT_Result', 'N/A')}")
        if not file_exists and not is_signed and not is_trusted and not dispatch:
            if found_elsewhere or entry.get('SuspiciousOwner') or entry.get('SystemProtected'):
                potential_rootkits.append(entry)
            elif not service and not task:
                entry['SafeToDelete'] = True
                junk.append(entry)
            else:
                potential_rootkits.append(entry)
        else:
            potential_rootkits.append(entry)
    print(Fore.CYAN + f"\n📦 Junk/suspicious CLSIDs (crucial to implement deep scanning for them as well): {len(junk)}")
    print(Fore.MAGENTA + f"🛑 Potential Rootkits: {len(potential_rootkits)} (require review!)")
    time.sleep(0.33)
    print(Fore.LIGHTCYAN_EX + "\n🧠 Launching deep analysis on filtered suspicious CLSIDs...\n")
    time.sleep(0.33)
    run_deep_clsid_correlation_analysis(junk + potential_rootkits)
    if not junk:
        print(Fore.YELLOW + "No CLSID entries marked as safe junk to delete.")
        return
    choice = input(Fore.YELLOW + "\n❓ Delete only junk entries (safe)? (y/n): ")
    if choice.lower() != 'y':
        print(Fore.RED + "Aborted by user.")
        return
    backup_registry()
    for entry in junk:
        clsid = entry['CLSID']
        key_path = f"CLSID\\{clsid}"
        try:
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, f"{key_path}\\InprocServer32")
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, key_path)
            print(Fore.GREEN + f"✅ Deleted CLSID {clsid}")
        except PermissionError:
            print(Fore.RED + f"❌ Failed to delete {clsid} due to permission error.")
            choice = input(Fore.CYAN + f"Try to take ownership of {clsid} and retry? (y/n): ")
            if choice.strip().lower() == 'y':
                if take_ownership_and_retry(clsid):
                    try:
                        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, f"{key_path}\\InprocServer32")
                        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, key_path)
                        print(Fore.GREEN + f"✅ Deleted CLSID {clsid} after taking ownership")
                    except Exception as e:
                        print(Fore.RED + f"❌ Still failed after takeown: {e}")
                else:
                    print(Fore.RED + f"❌ Could not take ownership of {clsid}")
            else:
                print(Fore.YELLOW + f"➡ Skipped {clsid}")
        except Exception as e:
            print(Fore.RED + f"❌ Failed to delete {clsid}: {e}")
def show_help():
    print(Fore.CYAN + """
**📘 LutziLyzer - Centralized Post-Execution Threat Artifact Analyzer - Full Help (v1.0)**

---

### 🔍 Purpose:
Analyze Windows COM registry entries and persistence vectors to identify:
  • Broken or orphaned COM references
  • Suspicious or potentially malicious CLSID entries
  • Junk or abandoned registrations
  • Rootkit or stealth persistence via Winsock, Active Setup, and legacy COM paths

---

### 🎯 Detection Logic (Multi-Layer):
• Checks if referenced DLL exists, is signed, and resides in a trusted path
• Computes SHA256, MD5, and SHA1 hashes for each DLL
• Verifies hashes against:
    - ✅ Known Good (digitally signed, Microsoft path, clean hash)
    - ❌ Known Bad (Loki IoCs or user blacklists)
    - ❓ Unknown (collected for AI/VirusTotal analysis)
• Detects suspicious registry key ownership (TrustedInstaller or unknown SIDs)
• Validates links to autorun methods (services, scheduled tasks, Active Setup)
• Optionally cross-checks results with VirusTotal

---

### 🛡 Capabilities & Checks Performed:
• COM registry scans (HKCR\\CLSID\\...\\InProcServer32)
• **COM-Based Indirect Persistence Scan** (Option 3):
    - Winsock Providers (Protocol_Catalog9, Catalog_Entries64)
    - Active Setup components
    - COM persistence under AppID, TypeLib, Wow6432Node, Software\\Classes overlays
• File existence and path validation
• Digital signature and certificate trust evaluation
• COM object dispatch test (instantiation)
• Ownership analysis based on SID classification
• SHA256, MD5, SHA1 hash extraction and verification
• FoundElsewhere detection (file relocated or re-registered in different path)
• Optional cloud intelligence via VirusTotal
• Strict filtering to reduce false positives

✅ Entry is marked safe for deletion only if:
• DLL file does not exist
• Not signed and not located in a trusted system directory
• Not dispatchable (COM test fails)
• Not linked to services, scheduled tasks, or known autoruns
• Not owned by TrustedInstaller or an unknown SID
• Not matched to any known-good hashes
• Not found elsewhere on the system
• Confirmed safe to delete by AI or user logic

---

### 🧠 Analysis Modes Explained:

**1️⃣ Static Analysis ('1'):**
• Runs thorough local checks without internet access.
• Fast, efficient, suitable for offline environments.
• Applies strict AND-based filtering for high accuracy.

**🤖 AI-Assisted Analysis ('2'):**
• Combines initial static filtering with GPT-based AI reasoning.
• Provides detailed, context-aware analysis with confidence scores (High, Medium, Low).
• Cost estimation provided clearly before sending data to AI:
  - GPT-3.5: ~$0.0005 per 1K tokens
  - GPT-4: ~$0.01 per 1K tokens

**📡 Optional Full Disk Scan:**
• Deep-scan of all system drives, indexing all file paths.
• Identifies DLLs relocated or hidden in unusual locations.
• Prevents false deletions by marking legitimately moved files (FoundElsewhere=True).

---

### 🚩 Rootkit & Advanced Threat Indicators:
• FoundElsewhere=True → DLL moved or hidden, potential rootkit/evasion technique.
• SystemProtected=True → Registry key owned by TrustedInstaller, indicating system-critical or possible compromise.
• SuspiciousOwner=True → Ownership anomalies identified by specific SID patterns:
  - S-1-15-3-* → Typically AppContainer or Windows Store apps.
  - S-1-12-* → Usually virtual or dynamically assigned accounts.
  - S-1-5-21-* → User-specific accounts or legacy profiles.

### 🔎 SID Anomaly Implications:
• Missing DLL combined with SID anomalies (SuspiciousOwner=True) indicates strong suspicion of malware activity, unauthorized privilege escalation, or registry hijack.

### 🔐 Automated Ownership Handling:
• Prompts to automatically acquire registry permissions if deletion fails due to insufficient rights.
• Uses secure methods (takeown, icacls) to rectify permission issues safely.

---

### ♻️ Registry Backup & Restore:
• Automatic backups of registry prior to deletion actions.
• Facilitates easy restoration from backup .reg files.
• Auto-detects the latest registry backup or allows manual selection.

---

### 🎯 Hash Database Updates ('u'):
• Updates known-good and known-bad hashes from official IoC sources (Neo23x0/Loki).
• Strongly recommended to perform this update before every analysis run.

### 📎 Hash Matching:
• Downloads bad hashes from LOKI (Neo23x0)
• Computes SHA256, MD5, SHA1 for all DLLs
• If hash matches bad list → HashStatus=Malicious
• If hash is in system32 and signed → HashStatus=Trusted
• If hash is unknown → added to unknown_hashes.json

### 📎 Hash Matching - Reason Functionalities:
• Cross-checks DLL SHA256/MD5/SHA1 hashes with known malware (LOKI hash lists)
• Verified signed files in system32/syswow64 automatically marked trusted
• Unrecognized hashes logged separately in unknown_hashes.json for future review

---

### 🔗 VirusTotal Integration:
• Optional online check against VirusTotal’s extensive threat databases.
• Enables real-time malware detection and community intelligence integration.

---

### 🎛 Main Menu Options:
• 'u' – Update hash databases (highly recommended before scanning).
• '1' – Perform COM registry analysis (choose static/AI, optional disk scan).
• '2' – Restore Registry from a backup.
• '3' – COM-Based Indirect Persistence Scan (deep scan beyond standard CLSID entries).
• 'h' – Display this help information.

---

### 📂 Tip:
Always run the hash updater (option 'u') before scanning for best results.
It strengthens static detection by correlating with threat intel.

🌐 Learn more and follow updates:
https://lutzigoz.com
""")
def get_virustotal_api_key():
    config = configparser.ConfigParser()
    config.read('configVT.ini')
    try:
        api_key = config.get('vt', 'api_key')
    except (configparser.NoSectionError, configparser.NoOptionError):
        api_key = input(Fore.LIGHTCYAN_EX + "Enter your VirusTotal API Key (get from https://www.virustotal.com/gui/user/LutziGoz/apikey):\n")
        config['vt'] = {'api_key': api_key}
        with open('configVT.ini', 'w') as configfile:
            config.write(configfile)
    return api_key
def query_virustotal(sha256):
    api_key = get_virustotal_api_key()
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        vt_data = response.json()
        malicious = vt_data['data']['attributes']['last_analysis_stats']['malicious']
        undetected = vt_data['data']['attributes']['last_analysis_stats']['undetected']
        return f"Malicious: {malicious}, Undetected: {undetected}"
    elif response.status_code == 404:
        return "No VT data available"
    elif response.status_code == 401:
        print(Fore.RED + "VirusTotal API key is invalid. Please update your API key.")
        os.remove('configVT.ini')
        return "Invalid API Key"
    else:
        return f"Error {response.status_code}"
def open_virustotal_checker(sha256):
    webbrowser.open_new_tab(f"https://www.virustotal.com/gui/file/{sha256}/detection")
def merge_ai_results(filtered, ai_result):
    merged = []
    for ai_entry in ai_result:
        clsid = ai_entry.get("CLSID")
        dll = ai_entry.get("DLL")
        # חפש את הרשומה המלאה מתוך filtered
        for full_entry in filtered:
            if clsid and full_entry.get("CLSID") == clsid:
                full_entry.update(ai_entry)
                merged.append(full_entry)
                break
            elif dll and full_entry.get("DLL") == dll:
                full_entry.update(ai_entry)
                merged.append(full_entry)
                break
    return merged

def LutzimAIN():
    from LutziCheckSuspiciousCOM import (
        run_with_admin_privileges, scan_com_entries, save_suspicious_to_csv, offer_deletion,
        load_or_request_api, query_ai, scan_installed_files, COM_EXPORT_FILE,
        vt_check_hashes, show_help, update_hash_lists,
        restore_registry_backup, COM_Based_Indirect_Persistence, COM_EXPORT_EXTENDED_FILE
    )
    run_with_admin_privileges()
    while True:
        print(Fore.CYAN + "\n🛠 Main Menu")
        Lutzi_mainquestion = input(
            "Enter 'h' to get help\n"
            "Enter 'u' to update known_good and known_bad checksums (Recommended before each scan)\n"
            "Enter '1' to Scan COM Suspicious/Malicious\n"
            "Enter '2' to Restore Reg file\n"
            "Enter '3' to run COM-Based Indirect Persistence Scan\n> ").strip().lower()
        if Lutzi_mainquestion == 'h':
            show_help()
        elif Lutzi_mainquestion == 'u':
            update_hash_lists()
        elif Lutzi_mainquestion == '1':
            def LastLutziMission():
                print(Fore.CYAN + "\nChoose scan mode:")
                print("1 - Static analysis only (strict AND filter)")
                print("2 - AI analysis with static filter (cost efficient)")
                while True:
                    choice = input("Enter 1 / 2 > ").strip()
                    if choice in ['1', '2']:
                        break
                    print("❌ Invalid input. Please enter 1 or 2.\n")
                scan_com_entries()
                with open(COM_EXPORT_FILE) as f:
                    entries = json.load(f)
                suspicious_for_vt = [e for e in entries if e.get('ShouldSendToVT')]
                if suspicious_for_vt:
                    print(Fore.CYAN + f"\n🌐 Submitting {len(suspicious_for_vt)} suspicious entries to VirusTotal...")
                    vt_check_hashes(suspicious_for_vt)
                    print(Fore.GREEN + "✅ VirusTotal analysis completed for flagged entries.\n")
                filtered = [e for e in entries if not e['DispatchTest'] and not e['IsTrustedPath']
                            and not e['FileExists'] and not e['IsSigned']]
                if choice == '1':
                    save_suspicious_to_csv(filtered)
                    offer_deletion(filtered)
                else:
                    load_or_request_api()
                    ai_result = query_ai(filtered)
                    merged_ai = merge_ai_results(filtered, ai_result)
                    save_suspicious_to_csv(merged_ai)
                    offer_deletion(merged_ai)
                print(Fore.CYAN + "\n✅ Done.\n")
            while True:
                scan_disks = input("❓ Scan all drives to relocated COM DLLs?\nThis step is Very important\nReferences deep scanning to discover persistence ACL, Remote Callbacks-Kernel and COM types."
                                   "\nanswer by (y/n):\nEnter:  ").lower().strip()
                if scan_disks == "y":
                    scan_installed_files()
                    LastLutziMission()
                    break
                elif scan_disks == "n":
                    LastLutziMission()
                    break
                else:
                    print("❌ Invalid input. Please enter 'y' or 'n'.\n")
        elif Lutzi_mainquestion == '2':
            restore_registry_backup()
        elif Lutzi_mainquestion == '3':
            print(Fore.CYAN + "\n🛠 COM-Based Indirect Persistence Scan starting...")
            def ExtendedMission():
                print(Fore.CYAN + "\nChoose scan mode:")
                print("1 - Static analysis only (strict AND filter)")
                print("2 - AI analysis with static filter (cost efficient)")
                while True:
                    choice_ext = input("Enter 1 / 2 > ").strip()
                    if choice_ext in ['1', '2']:
                        break
                    print("❌ Invalid input. Please enter 1 or 2.\n")
                COM_Based_Indirect_Persistence()
                with open(COM_EXPORT_EXTENDED_FILE) as f:
                    entries_ext = json.load(f)
                filtered_ext = [e for e in entries_ext if not e['DispatchTest'] and not e['IsTrustedPath']
                                and not e['FileExists'] and not e['IsSigned']]
                vt_ask_ext = input(Fore.LIGHTCYAN_EX + "\n🌐 Check COM-Based entries on VirusTotal? (y/n): ").lower().strip()
                if vt_ask_ext == 'y':
                    vt_check_hashes(filtered_ext)
                if choice_ext == '1':
                    save_suspicious_to_csv(filtered_ext, filename="suspicious_COM_extended.csv")
                    print(Fore.YELLOW + "\n⚠ No auto-deletion for indirect entries. Please review manually.")
                else:
                    load_or_request_api()
                    ai_result_ext = query_ai(filtered_ext, mode="COM-Based Indirect Persistence")
                    vt_ask_ext2 = input(Fore.LIGHTCYAN_EX + "Do you want to send VirusTotal results to AI for deeper reasoning?").lower().strip()
                    if vt_ask_ext2 == 'y':
                        vt_check_hashes(ai_result_ext)
                    save_suspicious_to_csv(ai_result_ext, filename="suspicious_COM_extended.csv")
                    print(Fore.YELLOW + "\n⚠ No auto-deletion for indirect entries. Please review manually.")
                print(Fore.CYAN + "\n✅ COM-Based Indirect Persistence scan completed.\n")
            while True:
                scan_disks_ext = input("Scan full drives? (y/n): ").lower().strip()
                if scan_disks_ext == 'y':
                    scan_installed_files()
                    ExtendedMission()
                    break
                elif scan_disks_ext == 'n':
                    ExtendedMission()
                    break
                else:
                    print("❌ Invalid input. Please enter 'y' or 'n'.\n")
        else:
            print("❌ Invalid input. Please enter one of: 1, 2, 3, h, or u.\n")
LutzimAIN()
