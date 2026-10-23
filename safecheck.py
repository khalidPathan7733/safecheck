#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SafeCheck Desktop - read-only malware & remote-access ("bridge") checker for Windows.

What it checks
  * Files in Downloads, Desktop and WhatsApp Desktop folders (or any folder/file you pick):
    script files (.vbs/.js/.hta...), double extensions (photo.jpg.exe), hidden RTL characters,
    fake documents that are really programs, ZIPs hiding shortcuts/scripts, password-protected
    archives, APK files with scam names, unsigned programs.
  * Startup entries (Run keys, Startup folders, Winlogon), scheduled tasks, services.
  * Running processes (script hosts, fake system processes, programs running from Temp/Downloads).
  * "Bridges": remote-access tools (AnyDesk, UltraViewer, TeamViewer, RustDesk, VNC, RATs...),
    live internet connections per program, past incoming remote sessions, Remote Desktop,
    proxy settings and hosts-file redirects.
  * Windows protection: Defender real-time status, signature age, past detections, firewall.

What it NEVER does
  * It never deletes, moves, quarantines, renames or edits any file, registry value, task,
    service or setting. It only reads and explains, and shows manual removal steps.
  * It never uploads anything. "Look up hash online" only opens your browser with the file's
    fingerprint (SHA-256) when YOU click it.

Usage
  GUI :  SafeCheckDesktop.exe            (or: python safecheck.py)
  CLI :  python safecheck.py --cli [--folder PATH] [--file PATH]
"""
from __future__ import annotations

import hashlib
import html
import io
import ipaddress
import json
import os
import platform
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime

import struct

IS_WIN = os.name == "nt"
IS_WOW64 = IS_WIN and struct.calcsize("P") == 4 and bool(os.environ.get("PROCESSOR_ARCHITEW6432"))
try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None
if IS_WIN:
    import ctypes
    import winreg  # type: ignore

APP_NAME = "SafeCheck Desktop"
APP_VERSION = "1.1.0"
CREATE_NO_WINDOW = 0x08000000
MAX_HASH_SIZE = 300 * 1024 * 1024
MAX_FILES_PER_ROOT = 60000
MAX_DEPTH = 8
MAX_SIG_CHECKS = 800
SKIP_DIRS = {"node_modules", ".git", "__pycache__", "venv", ".venv", "site-packages",
             "vendor", ".gradle", ".idea", ".vs", ".cache"}

# "Check" = a manual check the user should do (not counted as a risk).
SEVERITIES = ["High", "Medium", "Low", "Check", "Info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

CAT_FILES = "Files"
CAT_STARTUP = "Startup"
CAT_TASKS = "Scheduled Tasks"
CAT_SERVICES = "Services"
CAT_PROCESSES = "Running Programs"
CAT_BRIDGE = "Remote Access (Bridge)"
CAT_NETWORK = "Network"
CAT_PROTECTION = "Windows Protection"
CAT_WHATSAPP = "WhatsApp"

NO_CHANGE_NOTE = "SafeCheck did not delete or change anything. All steps below are done by you, manually."


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    location: str = ""
    why: str = ""
    remove: list = field(default_factory=list)
    details: dict = field(default_factory=dict)
    path: str = ""
    sha256: str = ""


# --------------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------------
def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def pjoin(base: str, *parts: str) -> str:
    return os.path.join(base, *parts) if base else ""


def norm(p) -> str:
    if isinstance(p, dict):
        p = p.get("value") or p.get("Value") or ""
    if not isinstance(p, (str, bytes)) or not p:
        return ""
    return os.path.normcase(os.path.normpath(p))


def visible(text: str) -> str:
    """Show hidden direction-control characters instead of letting them reverse the text."""
    return "".join("[hidden-RTL]" if c in BIDI_CHARS else c for c in (text or ""))


def max_sev(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a if SEV_RANK[a] <= SEV_RANK[b] else b


def bump(sev):
    return {"Low": "Medium", "Medium": "High", "High": "High", None: "Medium"}.get(sev, sev)


def run_cmd(cmd, timeout=90):
    kw = dict(capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
    if IS_WIN:
        kw["creationflags"] = CREATE_NO_WINDOW
    try:
        r = subprocess.run(cmd, **kw)
        return (r.returncode,
                r.stdout.decode("utf-8", errors="replace"),
                r.stderr.decode("utf-8", errors="replace"))
    except Exception as e:  # noqa: BLE001
        return -1, "", str(e)


PS_PREFIX = ("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
             "$ErrorActionPreference='SilentlyContinue'; $ProgressPreference='SilentlyContinue'; ")


def ps_json(script: str, timeout=120) -> list:
    """Run a read-only PowerShell query and return a list of dicts."""
    if not IS_WIN:
        return []
    full = PS_PREFIX + "@(" + script + ") | ConvertTo-Json -Depth 4 -Compress"
    code, out, _ = run_cmd(["powershell.exe", "-NoProfile", "-NonInteractive",
                            "-ExecutionPolicy", "Bypass", "-Command", full], timeout)
    out = out.strip().lstrip("\ufeff")
    if not out:
        return []
    try:
        data = json.loads(out)
    except Exception:  # noqa: BLE001
        return []
    if isinstance(data, dict):
        return [data]
    return data if isinstance(data, list) else []


def is_admin() -> bool:
    if IS_WIN:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def sha256_file(path: str) -> str:
    try:
        if os.path.getsize(path) > MAX_HASH_SIZE:
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def read_head(path: str, n: int = 8) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def read_tail_lines(path: str, max_bytes=65536, lines=15) -> list:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read()
    except OSError:
        return []
    text = data.decode("utf-8", errors="replace")
    if "\x00" in text:
        text = data.decode("utf-16-le", errors="replace")
    rows = [r.strip() for r in text.splitlines() if r.strip()]
    return rows[-lines:]


def read_motw(path: str) -> dict:
    """Read the 'Mark of the Web' (where a file was downloaded from). Windows/NTFS only."""
    if not IS_WIN:
        return {}
    try:
        with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as f:
            txt = f.read()
    except OSError:
        return {}
    out = {}
    for line in txt.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
        if getattr(a, "ipv4_mapped", None):
            a = a.ipv4_mapped
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
                    or a.is_unspecified or a.is_reserved)
    except ValueError:
        return False


# ---------------------------- registry (read-only) ----------------------------
def _hkey(name):
    return {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}[name]


def _ropen(root, path):
    flags = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
    return winreg.OpenKey(_hkey(root), path, 0, flags)


def reg_get(root, path, name):
    if not IS_WIN:
        return None
    try:
        with _ropen(root, path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def reg_values(root, path):
    out = []
    if not IS_WIN:
        return out
    try:
        with _ropen(root, path) as k:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                out.append((name, data))
                i += 1
    except OSError:
        pass
    return out


def reg_subkeys(root, path):
    out = []
    if not IS_WIN:
        return out
    try:
        with _ropen(root, path) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


# ---------------------------- digital signatures ----------------------------
_sig_cache: dict = {}


def check_signatures(paths) -> dict:
    """Return {path: (status, signer_subject)} using Get-AuthenticodeSignature (read-only)."""
    paths = [p for p in dict.fromkeys(paths) if p]
    todo = [p for p in paths if norm(p) not in _sig_cache and os.path.isfile(p)]
    if IS_WIN and todo:
        for i in range(0, len(todo), 150):
            chunk = todo[i:i + 150]
            fd, tmp = tempfile.mkstemp(prefix="safecheck_", suffix=".txt")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write("\n".join(chunk))
                script = (
                    "Get-Content -LiteralPath '%s' -Encoding UTF8 | Where-Object { $_ } | ForEach-Object { "
                    "$s = Get-AuthenticodeSignature -LiteralPath $_; "
                    "[pscustomobject]@{P=[string]$_; S=[string]$s.Status; "
                    "N=$(if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' })} }"
                ) % tmp.replace("'", "''")
                for r in ps_json(script, timeout=300):
                    pv = r.get("P", "")
                    if isinstance(pv, dict):
                        pv = pv.get("value") or pv.get("Value") or ""
                    _sig_cache[norm(str(pv))] = (r.get("S", "") or "Unknown", r.get("N", "") or "")
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    return {p: _sig_cache.get(norm(p), ("Unknown", "")) for p in paths}


def signer_name(subject: str) -> str:
    m = re.search(r'CN="?([^,"]+)', subject or "")
    return m.group(1).strip() if m else (subject or "")


# --------------------------------------------------------------------------------------------
# Known folders
# --------------------------------------------------------------------------------------------
def _known_folder(value_name: str, fallback: str) -> str:
    v = reg_get("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", value_name)
    if v:
        v = os.path.expandvars(v)
        if os.path.isdir(v):
            return v
    return fallback


def downloads_dir() -> str:
    return _known_folder("{374DE290-123F-4565-9164-39C4925E467B}",
                         os.path.join(os.path.expanduser("~"), "Downloads"))


def desktop_dir() -> str:
    return _known_folder("Desktop", os.path.join(os.path.expanduser("~"), "Desktop"))


def whatsapp_dirs() -> list:
    out = []
    base = pjoin(_env("LOCALAPPDATA"), "Packages")
    if base and os.path.isdir(base):
        try:
            for d in os.listdir(base):
                if "whatsapp" in d.lower():
                    t = os.path.join(base, d, "LocalState", "shared", "transfers")
                    s = os.path.join(base, d, "LocalState", "shared")
                    if os.path.isdir(t):
                        out.append(t)
                    elif os.path.isdir(s):
                        out.append(s)
        except OSError:
            pass
    return out


def startup_dirs() -> list:
    return [d for d in (
        pjoin(_env("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        pjoin(_env("PROGRAMDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "StartUp"),
    ) if d and os.path.isdir(d)]


STRONG_LOC_MARKERS = [os.sep + "appdata" + os.sep + "local" + os.sep + "temp",
                      os.sep + "windows" + os.sep + "temp",
                      os.sep + "users" + os.sep + "public",
                      os.sep + "$recycle.bin",
                      os.sep + "downloads"]


def loc_risk(path: str) -> str:
    p = norm(path).lower()
    if not p:
        return ""
    if any(m in p for m in STRONG_LOC_MARKERS):
        return "strong"
    if os.sep + "appdata" + os.sep in p:
        return "weak"
    return ""


# --------------------------------------------------------------------------------------------
# File-name rules
# --------------------------------------------------------------------------------------------
WHY_SCRIPT = ("Script files run commands on your PC the moment they are double-clicked. Real documents, "
              "photos, bills and invitations are never sent as script files. CERT-In has warned about .vbs "
              "files spreading through WhatsApp Web/Desktop.")
WHY_MACRO = ("Office files with macros can run hidden code when you click 'Enable content'. "
             "Normal documents do not need macros.")
WHY_IMAGE = ("Disk-image files (.iso/.img/.vhd) are used to sneak programs past Windows security warnings. "
             "A real document or photo never needs to be 'mounted'.")
WHY_APK = ("This is an Android app installer. Scammers send fake 'RTO e-Challan', 'Wedding Invitation', "
           "'PM-Kisan', 'KYC update' or bank APKs on WhatsApp; once installed on a phone they read OTP SMS, "
           "take over WhatsApp and empty bank accounts.")

EXT_RULES = {
    ".vbs": ("High", "VBScript file", WHY_SCRIPT),
    ".vbe": ("High", "Encoded VBScript file", WHY_SCRIPT),
    ".js": ("High", "JScript file", WHY_SCRIPT + " (If you are a developer and this is source code you "
                                                 "downloaded on purpose, it is fine.)"),
    ".jse": ("High", "Encoded JScript file", WHY_SCRIPT),
    ".wsf": ("High", "Windows Script File", WHY_SCRIPT),
    ".wsh": ("High", "Windows Script Host file", WHY_SCRIPT),
    ".hta": ("High", "HTML Application", WHY_SCRIPT),
    ".scr": ("High", "Screensaver program", "'.scr' files are full programs disguised as screensavers. "
                                            "They are a classic malware trick."),
    ".pif": ("High", "Legacy program shortcut", "'.pif' files can run programs and are almost only used by malware today."),
    ".cpl": ("High", "Control Panel program", "'.cpl' files are programs. Nobody sends them legitimately by chat."),
    ".xll": ("High", "Excel add-in program", "'.xll' Excel add-ins run code as soon as Excel opens them."),
    ".com": ("High", "DOS program", "'.com' files are programs, and are rarely used legitimately today."),
    ".bat": ("Medium", "Batch script", WHY_SCRIPT),
    ".cmd": ("Medium", "Command script", WHY_SCRIPT),
    ".ps1": ("Medium", "PowerShell script", WHY_SCRIPT),
    ".psm1": ("Medium", "PowerShell module", WHY_SCRIPT),
    ".reg": ("Medium", "Registry file", "Opening a .reg file changes Windows settings; malware uses it to "
                                        "disable security or add itself to startup."),
    ".msc": ("Medium", "Management console file", "Specially crafted .msc files have been used to run hidden commands."),
    ".scf": ("Medium", "Shell command file", "'.scf' files can leak your Windows login hash to an attacker."),
    ".chm": ("Medium", "Compiled help file", "'.chm' help files can contain scripts that run when opened."),
    ".jar": ("Medium", "Java program", "'.jar' files are programs, often used to deliver remote-access trojans."),
    ".iso": ("Medium", "Disk image", WHY_IMAGE),
    ".img": ("Medium", "Disk image", WHY_IMAGE),
    ".vhd": ("Medium", "Virtual disk", WHY_IMAGE),
    ".vhdx": ("Medium", "Virtual disk", WHY_IMAGE),
    ".docm": ("Medium", "Word file with macros", WHY_MACRO),
    ".dotm": ("Medium", "Word template with macros", WHY_MACRO),
    ".xlsm": ("Medium", "Excel file with macros", WHY_MACRO),
    ".xltm": ("Medium", "Excel template with macros", WHY_MACRO),
    ".xlam": ("Medium", "Excel add-in with macros", WHY_MACRO),
    ".pptm": ("Medium", "PowerPoint with macros", WHY_MACRO),
    ".ppam": ("Medium", "PowerPoint add-in with macros", WHY_MACRO),
    ".apk": ("Medium", "Android app (APK)", WHY_APK),
    ".lnk": ("Medium", "Shortcut file", "A shortcut in your downloads is unusual. Malware hides inside ZIPs as a "
                                        "shortcut that looks like a PDF or photo but actually starts PowerShell or a script."),
    ".url": ("Low", "Internet shortcut", "Internet shortcuts can open phishing pages or remote files."),
    ".exe": ("Low", "Program", "Programs can do anything on your PC."),
    ".msi": ("Low", "Installer", "Installers can do anything on your PC."),
}

PROGRAM_EXT = {".exe", ".msi"}
DOC_LIKE_EXT = {".pdf", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".doc", ".docx", ".xls",
                ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv", ".mp4", ".mp3", ".wav", ".heic"}

_DOC = r"(pdf|jpe?g|png|gif|webp|bmp|docx?|xlsx?|pptx?|txt|rtf|csv|mp4|mp3|wav|heic)"
_EXE = r"(exe|scr|pif|com|bat|cmd|vbs|vbe|js|jse|wsf|hta|lnk|ps1|apk|msi|jar|cpl|url|iso|img)"
RE_DOUBLE = re.compile(r"\." + _DOC + r"[\s_.\-]*\." + _EXE + r"$", re.I)
RE_SPACES = re.compile(r"\s{5,}\.\w{2,4}$")
BIDI_CHARS = {"\u202e", "\u202d", "\u202b", "\u202a", "\u2066", "\u2067", "\u2068"}

LURE_WORDS = ["challan", "e-challan", "echallan", "rto", "parivahan", "traffic", "kyc", "aadhaar",
              "aadhar", "pancard", "pan card", "pm kisan", "pmkisan", "kisan", "yojana", "subsidy",
              "wedding", "invitation", "invite", "shaadi", "marriage", "card", "bank", "sbi", "yono",
              "hdfc", "icici", "axis", "kotak", "refund", "payment", "invoice", "receipt", "bill",
              "electricity", "bijli", "courier", "parcel", "customs", "job", "salary", "offer",
              "lottery", "prize", "reward", "update", "whatsapp", "photo", "video", "document"]


def classify_name(name: str):
    """Rules based only on a file name. Returns (severity|None, label, [reasons])."""
    base = os.path.basename(name.replace("\\", "/"))
    low = base.lower()
    ext = os.path.splitext(low)[1]
    sev, label, reasons = None, "", []
    if any(c in base for c in BIDI_CHARS):
        sev = "High"
        reasons.append("The file name contains a hidden 'right-to-left' character. This trick makes a program "
                       "look like a document (for example 'invoice\u202efdp.exe' shows as 'invoiceexe.pdf').")
    if RE_DOUBLE.search(low.strip()):
        sev = "High"
        reasons.append("The name has two extensions (for example 'photo.jpg.exe'). Windows often hides the last "
                       "one, so a program or script pretends to be a photo or document.")
    if RE_SPACES.search(base):
        sev = "High"
        reasons.append("There are many spaces before the extension, a trick to push the real file type out of view.")
    rule = EXT_RULES.get(ext)
    if rule:
        s, label, why = rule
        sev = max_sev(sev, s)
        reasons.append(why)
    lures = [w for w in LURE_WORDS if w in low]
    if lures and rule and ext not in (".url", ".exe", ".msi"):
        sev = bump(sev)
        reasons.append("The name uses a common scam bait word (%s)." % ", ".join(lures[:3]))
    return sev, label, reasons


LNK_PATTERNS = ["powershell", "pwsh", "cmd.exe", "mshta", "wscript", "cscript", "rundll32",
                "regsvr32", "bitsadmin", "certutil", "curl.exe", "-encodedcommand", "frombase64"]


def lnk_suspicious(path) -> list:
    try:
        with open(path, "rb") as f:
            data = f.read(262144)
    except OSError:
        return []
    text = " ".join([data.decode("latin-1"),
                     data.decode("utf-16-le", errors="ignore"),
                     data[1:].decode("utf-16-le", errors="ignore")]).lower()
    return [p for p in LNK_PATTERNS if p in text]


def inspect_zip(src, depth=0):
    """Look at file NAMES inside a ZIP (nothing is extracted to disk). Returns (sev, reasons, flagged)."""
    sev, reasons, flagged = None, [], []
    try:
        with zipfile.ZipFile(src) as z:
            infos = [i for i in z.infolist() if not i.is_dir()]
            encrypted = any(i.flag_bits & 0x1 for i in infos)
            total = 0
            for i in infos[:20000]:
                total += i.file_size
                s, label, _ = classify_name(i.filename)
                ext = os.path.splitext(i.filename.lower())[1]
                if ext in (".exe", ".msi", ".dll"):
                    s = max_sev(s, "Medium")
                    label = label or "Program"
                if ext == ".lnk":
                    s, label = "High", "Shortcut"
                if s:
                    s = max_sev(s, "Medium")
                    sev = max_sev(sev, s)
                    flagged.append("%s  (%s)" % (i.filename, label or ext))
                if depth == 0 and ext == ".zip" and not (i.flag_bits & 0x1) and i.file_size <= 50 * 1024 * 1024:
                    try:
                        s2, _r2, f2 = inspect_zip(io.BytesIO(z.read(i)), depth + 1)
                        if s2:
                            sev = max_sev(sev, s2)
                            flagged += ["%s > %s" % (i.filename, x) for x in f2]
                    except Exception:  # noqa: BLE001
                        pass
            if flagged:
                reasons.append("This archive contains risky files: " + "; ".join(flagged[:8])
                               + (" ..." if len(flagged) > 8 else ""))
                if len(infos) <= 2:
                    reasons.append("A ZIP holding just one or two scripts/programs/shortcuts is a classic malware "
                                   "delivery trick (seen in the SORVEPOTEL WhatsApp worm).")
            if encrypted:
                sev = max_sev(sev, "Medium")
                reasons.append("The archive is password-protected. Attackers do this so antivirus cannot look inside; "
                               "the password is usually written in the chat message.")
            if isinstance(src, str):
                try:
                    if total > 2 * 1024 ** 3 and os.path.getsize(src) < total / 100:
                        sev = max_sev(sev, "Medium")
                        reasons.append("The archive expands to a huge size (possible 'zip bomb').")
                except OSError:
                    pass
    except zipfile.BadZipFile:
        return "Low", ["This file is named .zip but could not be opened as a ZIP. It may be damaged or disguised."], []
    except Exception:  # noqa: BLE001
        return None, [], []
    return sev, reasons, flagged


# --------------------------------------------------------------------------------------------
# Command / process rules
# --------------------------------------------------------------------------------------------
SCRIPT_HOSTS = {"wscript.exe", "cscript.exe", "mshta.exe"}
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe"}
SYSTEM_NAMES = {"svchost.exe", "csrss.exe", "lsass.exe", "winlogon.exe", "services.exe", "smss.exe",
                "wininit.exe", "explorer.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe",
                "rundll32.exe", "conhost.exe", "ctfmon.exe", "sihost.exe", "lsm.exe", "dwm.exe"}
LOOKALIKES = {"scvhost.exe", "svch0st.exe", "svchosts.exe", "svhost.exe", "svchost32.exe", "lsas.exe",
              "lsasss.exe", "isass.exe", "csrs.exe", "crss.exe", "cssrs.exe", "expl0rer.exe",
              "explorer32.exe", "explore.exe", "winlogin.exe", "smsss.exe", "taskhost32.exe",
              "rundl32.exe", "spoolsvc.exe", "dllhst.exe"}
SUSP_CMD = re.compile(
    r"(-enc(odedcommand)?\s|\s-e\s+[a-z0-9+/=]{20,}|-w(indowstyle)?\s+h(idden)?\b|frombase64string|"
    r"downloadstring|downloadfile|invoke-expression|\biex\b|invoke-webrequest|\biwr\s|start-bitstransfer|"
    r"net\.webclient|bitsadmin\s|certutil.*-urlcache|mshta\s+(https?|vbscript|javascript)|"
    r"regsvr32.*/i:https?|rundll32.*javascript)", re.I)
RE_SCRIPT_HIGH = re.compile(r"\.(vbs|vbe|js|jse|wsf|hta)\b", re.I)
RE_SCRIPT_MED = re.compile(r"\.(ps1|bat|cmd)\b", re.I)

REMOTE_TOOLS = [
    ("anydesk", "AnyDesk"), ("teamviewer", "TeamViewer"), ("ultraviewer", "UltraViewer"),
    ("rustdesk", "RustDesk"), ("anyviewer", "AnyViewer"), ("screenconnect", "ScreenConnect"),
    ("splashtop", "Splashtop"), ("srservice", "Splashtop"), ("remotepc", "RemotePC"),
    ("remoting_host", "Chrome Remote Desktop"), ("ammyy", "Ammyy Admin"), ("aa_v3", "Ammyy Admin"),
    ("rserver3", "Radmin Server"), ("winvnc", "VNC Server"), ("tvnserver", "TightVNC Server"),
    ("vncserver", "VNC Server"), ("uvnc_service", "UltraVNC"), ("supremo", "Supremo"),
    ("aeroadmin", "AeroAdmin"), ("dwagent", "DWService"), ("meshagent", "MeshCentral Agent"),
    ("quickassist", "Microsoft Quick Assist"), ("rdpclip", "Remote Desktop (active session)"),
    ("airdroid", "AirDroid"), ("client32.exe", "NetSupport Manager"),
]
RAT_NAMES = [("remcos", "Remcos RAT"), ("asyncrat", "AsyncRAT"), ("quasar", "Quasar RAT"),
             ("njrat", "njRAT"), ("darkcomet", "DarkComet RAT"), ("nanocore", "NanoCore RAT")]
INSTALLED_REMOTE_WORDS = ["anydesk", "teamviewer", "ultraviewer", "rustdesk", "anyviewer", "screenconnect",
                          "connectwise control", "splashtop", "remotepc", "chrome remote desktop", "ammyy",
                          "radmin", "vnc", "supremo", "aeroadmin", "dwagent", "dwservice", "meshcentral",
                          "netsupport", "airdroid", "zoho assist"]


def remote_tool_for(name: str):
    n = (name or "").lower()
    for key, disp in RAT_NAMES:
        if key in n:
            return disp, True
    for key, disp in REMOTE_TOOLS:
        if (n == key) if key.endswith(".exe") else (key in n):
            return disp, False
    return None, False


def real_path(p: str) -> str:
    """32-bit build on 64-bit Windows: System32 is redirected to SysWOW64, so use Sysnative."""
    if IS_WOW64 and p:
        sys32 = os.path.join(_env("SystemRoot", r"C:\Windows"), "System32")
        if norm(p).startswith(norm(sys32) + os.sep):
            return os.path.join(_env("SystemRoot", r"C:\Windows"), "Sysnative", p[len(sys32) + 1:])
    return p


def extract_exe(cmd: str) -> str:
    return real_path(_extract_exe(cmd))


def _extract_exe(cmd: str) -> str:
    cmd = os.path.expandvars((cmd or "").strip())
    if not cmd:
        return ""
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 0 else cmd[1:]
    m = re.match(r"(.+?\.(exe|bat|cmd|vbs|vbe|js|jse|com|scr|ps1|hta|lnk|msi|dll))(\s|,|$)", cmd, re.I)
    return m.group(1) if m else cmd.split(" ")[0]


def evaluate_command(cmd: str) -> dict:
    reasons, sev = [], None
    exe = extract_exe(cmd)
    exe_name = os.path.basename(exe).lower()
    if SUSP_CMD.search(cmd or ""):
        sev = "High"
        reasons.append("The command uses tricks typical of malware: a hidden window, encoded commands, or code "
                       "downloaded from the internet.")
    if exe_name in SCRIPT_HOSTS:
        sev = "High"
        reasons.append("It starts a script through Windows Script Host / mshta. Ordinary apps almost never do this.")
    if RE_SCRIPT_HIGH.search(cmd or ""):
        sev = "High"
        reasons.append("It runs a script file (.vbs/.js/.hta) automatically.")
    elif RE_SCRIPT_MED.search(cmd or ""):
        sev = max_sev(sev, "Medium")
        reasons.append("It runs a script file (.ps1/.bat/.cmd) automatically.")
    loc = loc_risk(exe)
    if loc == "strong":
        sev = max_sev(sev, "Medium")
        reasons.append("It runs a program from a Temp, Downloads or Public folder, where real software is not installed.")
    tool, is_rat = remote_tool_for(exe_name)
    if tool:
        sev = max_sev(sev, "High" if is_rat else "Medium")
        reasons.append("%s is a remote-access program and it is set to start automatically. Anyone with its "
                       "access code/password can see and control this PC." % tool)
    in_windir = norm(exe).startswith(norm(_env("SystemRoot", r"C:\Windows")) + os.sep)
    if exe and os.path.isabs(exe) and not os.path.exists(exe) and sev is None and not in_windir:
        sev = "Low"
        reasons.append("It points to a file that no longer exists (probably a left-over entry).")
    return {"sev": sev, "reasons": reasons, "exe": exe, "loc": loc, "remote": tool}


# --------------------------------------------------------------------------------------------
# Removal-step templates (manual steps only)
# --------------------------------------------------------------------------------------------
def steps_file(kind="file"):
    s = ["Do NOT open, run or double-click this file.",
         'Click "Open File Location" below to see it in File Explorer.',
         "If you did not expect this file or do not fully trust where it came from: right-click it and choose "
         "Delete, then empty the Recycle Bin (or select it and press Shift+Delete to delete it permanently).",
         "If it came on WhatsApp from someone you know, CALL them on the phone. Their account may be hacked and "
         "sending this to all their contacts. Warn your contacts not to open it.",
         'Optional second opinion: "Scan File with Microsoft Defender" (no action is taken) or '
         '"Look Up Hash Online" (only the fingerprint is shared, not the file).',
         'If you ALREADY opened or ran it, follow "If you already opened a suspicious file" in the Removal Guide tab.']
    if kind == "apk":
        s.insert(1, "Never copy this file to a phone. Banks, the government (RTO/e-Challan, PM-Kisan) and wedding "
                    "invitations never come as APK files. If someone already installed it on a phone, see "
                    "'If an APK was installed on a phone' in the Removal Guide tab.")
    if kind == "zip":
        s.insert(1, "Do not extract (unzip) it. Delete the whole archive file.")
    return s


def steps_program(name, exe, pid=None):
    pid_txt = " (PID %s)" % pid if pid else ""
    return ["If you think this is malware, first disconnect from the internet (turn off Wi-Fi or unplug the cable).",
            "Press Ctrl+Shift+Esc to open Task Manager > 'Details' tab > find '%s'%s > right-click > "
            "'Open file location' (keep that window open) > then right-click > 'End task'." % (name, pid_txt),
            "Look in this tool's Startup, Scheduled Tasks and Services results for the same file and disable those "
            "entries too, otherwise it will start again after restart.",
            "If it belongs to an app you installed: Settings > Apps > Installed apps > Uninstall. Otherwise delete "
            "the file manually: %s" % (exe or "(see location)"),
            "Run a Microsoft Defender Offline scan: Windows Security > Virus & threat protection > Scan options > "
            "'Microsoft Defender Offline scan' > Scan now (the PC restarts; it takes about 15 minutes).",
            "From another device, change passwords for email, net-banking and UPI."]


def steps_run_key(reg_path, value_name, exe):
    return ["Press Ctrl+Shift+Esc > 'Startup apps' (or 'Startup' tab) > find '%s' > right-click > Disable." % value_name,
            "Restart the PC.",
            "If you do not recognise the program: Settings > Apps > Installed apps > find it > Uninstall.",
            "Then delete the file it starts (if it is still there): %s" % (exe or "(unknown)"),
            "Advanced, only if the entry is still there: press Win+R, type regedit, Enter. Go to %s, right-click the "
            "value '%s' > Export (backup), then right-click it again > Delete. WARNING: delete only this exact "
            "value. Changing other registry values can break Windows." % (reg_path, value_name)]


def steps_startup_folder(path):
    return ["Click 'Open File Location' to open the Startup folder.",
            "Move the file '%s' to your Desktop (cut + paste) so it no longer starts with Windows, then restart. "
            "If everything works and you don't need it, delete it." % os.path.basename(path),
            "If it is a script (.vbs/.js/.bat) or a shortcut that starts PowerShell, treat the PC as infected: "
            "follow 'If you already opened a suspicious file' in the Removal Guide tab."]


def steps_task(task_path, task_name):
    full = (task_path or "\\") + task_name
    return ["Press Win+R, type taskschd.msc, press Enter (Task Scheduler opens).",
            "In 'Task Scheduler Library' open the folder '%s' and select '%s'." % (task_path or "\\", task_name),
            "Check the 'Actions' tab to see which file it runs, then right-click the task > Disable.",
            "If you are sure it is malicious: right-click > Delete, then delete the file it runs.",
            'Advanced (Command Prompt as Administrator): schtasks /Change /TN "%s" /Disable' % full,
            "WARNING: do not disable tasks inside the \\Microsoft\\ folder unless SafeCheck marked them High. "
            "Windows needs many of them."]


def steps_service(name, display, exe):
    return ["Press Win+R, type services.msc, press Enter.",
            "Find '%s' > right-click > Properties > Stop. Set 'Startup type' to Disabled > OK." % (display or name),
            "Uninstall the program that owns it (Settings > Apps > Installed apps), then delete its file if it "
            "remains: %s" % (exe or "(see location)"),
            'Advanced (Command Prompt as Administrator): sc stop "%s"   then   sc config "%s" start= disabled' % (name, name),
            "WARNING: change only this exact service. Disabling Windows services can stop Windows from working."]


def steps_remote(tool):
    return ["If you did NOT start a support session yourself: turn off Wi-Fi or unplug the network cable NOW. "
            "This cuts any live connection.",
            "Close %s from the system tray (the icons near the clock) and end it in Task Manager (Ctrl+Shift+Esc)." % tool,
            "If you don't use it: Settings > Apps > Installed apps > %s > Uninstall." % tool,
            "From another device, change passwords for email, net-banking and UPI. Call your bank if any banking "
            "app or website was open while it was running.",
            "Remember: banks, 'customer care', courier, KYC or electricity-bill agents NEVER need AnyDesk, "
            "UltraViewer, TeamViewer, RustDesk or similar apps. Never share the access code.",
            "Lost money? Call 1930 immediately and report at cybercrime.gov.in."]


STEPS_RDP = ["If you don't use Remote Desktop: Settings > System > Remote Desktop > turn it Off.",
             "If an unknown session is active right now, disconnect the internet first.",
             "Make sure your Windows account has a strong password."]
STEPS_PROXY = ["If your office/college did NOT set a proxy: Settings > Network & internet > Proxy.",
               "Turn off 'Use a proxy server' and remove any 'Setup script' address (Use setup script > Off).",
               "Restart your browser. If the setting comes back by itself, malware is re-adding it: run a "
               "Microsoft Defender Offline scan."]
STEPS_HOSTS = ["Click Start, type Notepad, right-click it > 'Run as administrator'.",
               r"File > Open > C:\Windows\System32\drivers\etc\hosts (choose 'All files' to see it).",
               "Delete only the suspicious line(s) shown above, then Save.",
               "Open Command Prompt and run: ipconfig /flushdns",
               "WARNING: do not delete other lines unless you know what they do."]
STEPS_DEFENDER_OFF = ["Open Windows Security > Virus & threat protection > Manage settings.",
                      "Turn ON 'Real-time protection' and 'Tamper Protection'.",
                      "Go back and click 'Protection updates' > Check for updates.",
                      "If it turns itself off again (and you have no other antivirus), the PC may be infected: run "
                      "'Microsoft Defender Offline scan'."]
STEPS_FIREWALL = ["Open Windows Security > Firewall & network protection.",
                  "Turn ON the firewall for Domain, Private and Public networks."]
STEPS_THREAT = ["Open Windows Security > Virus & threat protection > Protection history.",
                "Open the item and choose Actions > Remove (or Quarantine). Do not choose 'Allow'.",
                "Then run 'Microsoft Defender Offline scan' (Scan options).",
                "If the threat had executed: change passwords from another device and watch your bank account."]
STEPS_WHATSAPP = ["On your PHONE: WhatsApp > Settings (or the three dots) > Linked devices. Log out every device "
                  "you don't recognise.",
                  "WhatsApp > Settings > Account > Two-step verification > Turn on and set a 6-digit PIN.",
                  "Never share WhatsApp's 6-digit SMS code or a pairing code with anyone, and never type your phone "
                  "number into a website opened from a WhatsApp link.",
                  "On this PC: if you use WhatsApp Web/Desktop, keep WhatsApp Desktop updated (Microsoft Store > "
                  "Library > Get updates) and log out when you leave the PC.",
                  "Treat any unexpected APK, ZIP, .vbs, .lnk or .exe as dangerous, even from family. Call the "
                  "sender to confirm."]


# --------------------------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------------------------
class Scanner:
    def __init__(self, progress=None, cancel: threading.Event | None = None):
        self.findings: list[Finding] = []
        self.progress = progress or (lambda m: None)
        self.cancel = cancel or threading.Event()
        self.errors: list[str] = []
        self.scanned_files = 0
        self._procs = None
        self.started = time.time()

    # -- plumbing --
    def add(self, f: Finding):
        self.findings.append(f)

    def step(self, msg):
        self.progress(msg)

    def finish(self):
        if self.errors and not any(f.title == "Some checks could not finish" for f in self.findings):
            self.add(Finding("Check", "Scanner", "Some checks could not finish", "SafeCheck",
                             "These parts of the scan did not complete, so results may be incomplete. Try "
                             "'Run as Administrator'. If it repeats, send this text to the developer.",
                             ["Restart SafeCheck as Administrator and run the check again."],
                             {"Details": "\n" + "\n".join(self.errors[:10])}))
        seen, out = set(), []
        for f in self.findings:
            key = (f.category, f.title, f.location)
            if key not in seen:
                seen.add(key)
                out.append(f)
        out.sort(key=lambda f: (SEV_RANK.get(f.severity, 9), f.category, f.title.lower()))
        self.findings = out

    def default_folders(self):
        roots = [(downloads_dir(), "downloads"), (desktop_dir(), "desktop")]
        roots += [(d, "downloads") for d in whatsapp_dirs()]
        return roots

    def run_full(self, extra_folders=()):
        steps = [
            ("Checking Windows protection status", self.check_protection),
            ("Checking Downloads, Desktop and WhatsApp files", lambda: self.scan_folders(self.default_folders())),
            ("Checking startup programs", self.check_startup),
            ("Checking scheduled tasks", self.check_tasks),
            ("Checking services", self.check_services),
            ("Checking running programs", self.check_processes),
            ("Checking remote access and live connections (bridges)", self.check_bridges),
            ("Checking network settings (proxy, hosts file)", self.check_network_settings),
            ("Adding WhatsApp safety checklist", self.add_whatsapp_checklist),
        ]
        for msg, fn in steps:
            if self.cancel.is_set():
                break
            self.step(msg + "...")
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                self.errors.append("%s: %s" % (msg, e))
        if extra_folders and not self.cancel.is_set():
            self.scan_folders([(p, "custom") for p in extra_folders])
        self.finish()

    # ---------------------------------------------------------------- files
    def _walk(self, root):
        count = 0
        root_depth = root.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            if self.cancel.is_set():
                return
            depth = dirpath.count(os.sep) - root_depth
            dirnames[:] = ([d for d in dirnames if d.lower() not in SKIP_DIRS and not d.startswith("$")]
                           if depth < MAX_DEPTH else [])
            for fn in filenames:
                yield os.path.join(dirpath, fn)
                count += 1
                if count >= MAX_FILES_PER_ROOT:
                    return

    def scan_folders(self, roots):
        programs = []
        for root, ctx in roots:
            if not root or not os.path.isdir(root):
                continue
            self.step("Scanning %s ..." % root)
            n = 0
            for p in self._walk(root):
                n += 1
                if n % 500 == 0:
                    self.step("Scanning %s ... %d files" % (root, n))
                try:
                    r = self.evaluate_file(p, ctx)
                except Exception:  # noqa: BLE001
                    continue
                if r == "PROGRAM":
                    programs.append((p, ctx))
                elif r:
                    self.add(r)
            self.scanned_files += n
        self._eval_programs(programs)

    def scan_single_file(self, path):
        self.step("Checking %s ..." % path)
        r = self.evaluate_file(path, "custom", single=True)
        if r == "PROGRAM":
            self._eval_programs([(path, "custom")], single=True)
        elif r:
            self.add(r)
        self.scanned_files = 1

    def _file_finding(self, path, sev, label, reasons, kind="file"):
        motw = read_motw(path)
        details = {"File type": label or os.path.splitext(path)[1] or "unknown"}
        try:
            st = os.stat(path)
            details["Size"] = "%.1f KB" % (st.st_size / 1024)
            details["Modified"] = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
        except OSError:
            pass
        src = motw.get("HostUrl") or motw.get("ReferrerUrl") or ""
        if src:
            details["Downloaded from"] = src
            if "whatsapp" in src.lower():
                reasons = reasons + ["This file was downloaded through WhatsApp Web/Desktop."]
        title = "%s: %s" % (label or "Suspicious file", visible(os.path.basename(path)))
        return Finding(sev, CAT_FILES, title, visible(path), " ".join(dict.fromkeys(reasons)), steps_file(kind),
                       details, path, sha256_file(path))

    def evaluate_file(self, path, ctx, single=False):
        name = os.path.basename(path)
        low = name.lower()
        if low in ("desktop.ini", "thumbs.db"):
            return None
        ext = os.path.splitext(low)[1]
        sev, label, reasons = classify_name(name)
        kind = "file"

        head = read_head(path, 8)
        if head[:2] == b"MZ" and ext in DOC_LIKE_EXT:
            sev = "High"
            label = "Program disguised as a document"
            reasons.append("Its name says it is a document/photo/media file, but its contents are actually a "
                           "Windows program.")
        elif head[:2] == b"PK" and ext in DOC_LIKE_EXT - {".docx", ".xlsx", ".pptx"}:
            sev = max_sev(sev, "Medium")
            reasons.append("Its contents are actually an archive or app package, not what the name says.")

        if ext == ".lnk":
            hits = lnk_suspicious(path)
            if hits:
                sev = "High"
                label = "Shortcut that runs a hidden command"
                reasons.append("This shortcut launches %s. Normal shortcuts open an app; malicious ones start "
                               "command tools to download and run malware." % ", ".join(hits[:4]))
            elif ctx in ("desktop", "startup") or (ctx == "custom" and not single):
                if not RE_DOUBLE.search(low) and not any(c in name for c in BIDI_CHARS):
                    sev = None  # ordinary shortcut
        if ext == ".url" and ctx != "downloads" and sev == "Low":
            sev = None
        if ext == ".js" and ctx == "custom" and not single and sev == "High" and len(reasons) == 1:
            sev = "Low"  # developer folders contain lots of .js
        if ext == ".apk":
            kind = "apk"
        if ext == ".zip":
            zs, zr, _ = inspect_zip(path)
            if zs:
                sev = max_sev(sev, zs)
                label = label or "Risky archive"
                reasons += zr
                kind = "zip"
        elif ext in (".rar", ".7z") and ctx == "downloads":
            sev = max_sev(sev, "Low")
            label = label or "Archive"
            reasons.append("SafeCheck cannot look inside this archive type. Open it only if you expected it, and "
                           "never run scripts, shortcuts or programs found inside.")
            kind = "zip"

        if ext in PROGRAM_EXT and sev in (None, "Low") and len(reasons) <= 2:
            return "PROGRAM" if (ctx in ("downloads", "desktop", "custom")) else None
        if sev is None or (sev == "Low" and ext in PROGRAM_EXT):
            if single:
                return Finding("Info", CAT_FILES, "No known red flags: %s" % name, path,
                               "SafeCheck found no suspicious signs in this file's name, type or contents. This is "
                               "NOT a guarantee that it is safe. Use 'Scan File with Microsoft Defender' or "
                               "'Look Up Hash Online' for a second opinion.",
                               ["Open it only if you expected it from someone you trust."],
                               {"Downloaded from": read_motw(path).get("HostUrl", "")} if IS_WIN else {},
                               path, sha256_file(path))
            return None
        return self._file_finding(path, sev, label, reasons, kind)

    def _eval_programs(self, programs, single=False):
        if not programs:
            return
        if len(programs) > MAX_SIG_CHECKS:
            self.errors.append("Only the first %d program files were signature-checked." % MAX_SIG_CHECKS)
            programs = programs[:MAX_SIG_CHECKS]
        self.step("Checking digital signatures of %d program files..." % len(programs))
        sigs = check_signatures([p for p, _ in programs])
        for p, ctx in programs:
            st, subj = sigs.get(p, ("Unknown", ""))
            name = os.path.basename(p)
            lures = [w for w in LURE_WORDS if w in name.lower()]
            reasons, sev = [], None
            if st == "Valid":
                if single:
                    self.add(Finding("Info", CAT_FILES, "Signed program: %s" % name, p,
                                     "This program has a valid digital signature from '%s'. A signature shows who "
                                     "published it; it does not prove the publisher is trustworthy." % signer_name(subj),
                                     ["Run it only if you trust this publisher and expected the file."],
                                     {"Signature": "Valid", "Signed by": signer_name(subj)}, p, sha256_file(p)))
                continue
            if st == "HashMismatch":
                sev = "High"
                reasons.append("Its digital signature is BROKEN: the file was modified after it was signed.")
            elif st in ("NotSigned", "UnknownError", "NotTrusted", "Incompatible", "NotSupportedFileFormat"):
                sev = "Medium" if ctx == "downloads" else "Low"
                reasons.append("This program has no valid digital signature (status: %s), so its publisher "
                               "cannot be verified." % st)
            else:
                if ctx != "downloads" and not single:
                    continue
                sev = "Low"
                reasons.append("SafeCheck could not verify this program's digital signature.")
            if lures:
                sev = bump(sev)
                reasons.append("The name uses a common scam bait word (%s)." % ", ".join(lures[:3]))
            f = self._file_finding(p, sev, "Unsigned program" if st == "NotSigned" else "Program", reasons)
            f.details["Signature"] = st
            self.add(f)

    # ---------------------------------------------------------------- startup
    def _resolve(self, pending):
        exes = [p["exe"] for p in pending if p["exe"] and p["loc"] and os.path.isfile(p["exe"])]
        sigs = check_signatures(exes) if exes else {}
        for p in pending:
            st, subj = sigs.get(p["exe"], ("", ""))
            sev, reasons = p["sev"], list(p["reasons"])
            if st and st != "Valid" and p["loc"]:
                if p["loc"] == "strong":
                    sev = "High"
                    reasons.append("The program is not validly signed (%s)." % st)
                else:
                    sev = max_sev(sev, "Medium")
                    reasons.append("The program is not validly signed (%s) and lives in your AppData folder, "
                                   "a place malware often hides in." % st)
            if sev is None and not p["info_ok"]:
                continue
            f = p["build"](sev or "Info", reasons)
            if f:
                if st:
                    f.details["Signature"] = st + (" (%s)" % signer_name(subj) if subj else "")
                self.add(f)

    def check_startup(self):
        if not IS_WIN:
            return
        pending = []
        run_keys = [
            ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
            ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        ]
        for root, path in run_keys:
            for name, data in reg_values(root, path):
                cmd = str(data)
                ev = evaluate_command(cmd)
                reg_path = "%s\\%s" % ("HKEY_CURRENT_USER" if root == "HKCU" else "HKEY_LOCAL_MACHINE", path)

                def build(sev, reasons, name=name, cmd=cmd, ev=ev, reg_path=reg_path):
                    cat = CAT_BRIDGE if ev["remote"] else CAT_STARTUP
                    why = " ".join(reasons) or "This program starts automatically when you sign in. Review it if you don't recognise it."
                    return Finding(sev, cat, "Startup entry: %s" % (name or "(default)"), reg_path + " > " + name, why,
                                   steps_run_key(reg_path, name, ev["exe"]), {"Command": cmd}, ev["exe"] if os.path.isfile(ev["exe"]) else "")
                pending.append(dict(ev, build=build, info_ok=True))

        # Winlogon hijack
        wl = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        shell = str(reg_get("HKLM", wl, "Shell") or "explorer.exe")
        if shell.strip().lower() not in ("explorer.exe", "explorer.exe,"):
            self.add(Finding("High", CAT_STARTUP, "Windows logon 'Shell' was changed", "HKEY_LOCAL_MACHINE\\" + wl,
                             "Windows should start only 'explorer.exe' here. Malware adds itself so it runs at every "
                             "logon.", ["Press Win+R, type regedit. Go to HKEY_LOCAL_MACHINE\\" + wl + ".",
                                        "Right-click 'Shell' > Export (backup), then Modify and set it to exactly: explorer.exe",
                                        "Delete the extra program it pointed to, then run a Microsoft Defender Offline scan.",
                                        "WARNING: a typo here can stop you from logging in. If unsure, ask a technician."],
                             {"Current value": shell}))
        uinit = str(reg_get("HKLM", wl, "Userinit") or "")
        parts = [x.strip() for x in uinit.split(",") if x.strip()]
        if parts and (len(parts) > 1 or not parts[0].lower().endswith("userinit.exe")):
            self.add(Finding("High", CAT_STARTUP, "Windows logon 'Userinit' was changed", "HKEY_LOCAL_MACHINE\\" + wl,
                             "This value should contain only userinit.exe. Extra programs here run at every logon.",
                             ["Press Win+R, type regedit. Go to HKEY_LOCAL_MACHINE\\" + wl + ".",
                              r"Right-click 'Userinit' > Export (backup), then Modify and set it to exactly: C:\Windows\system32\userinit.exe,",
                              "Delete the extra program it pointed to, then run a Microsoft Defender Offline scan.",
                              "WARNING: a mistake here can stop you from logging in. If unsure, ask a technician."],
                             {"Current value": uinit}))

        # Startup folders
        for d in startup_dirs():
            try:
                entries = os.listdir(d)
            except OSError:
                continue
            for fn in entries:
                p = os.path.join(d, fn)
                if fn.lower() == "desktop.ini" or not os.path.isfile(p):
                    continue
                ext = os.path.splitext(fn.lower())[1]
                sev, reasons = None, []
                if ext == ".lnk":
                    hits = lnk_suspicious(p)
                    if hits:
                        sev = "High"
                        reasons.append("This startup shortcut runs %s at every sign-in." % ", ".join(hits[:4]))
                elif ext in (".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".scr"):
                    sev = "High"
                    reasons.append("A script in the Startup folder runs automatically at every sign-in. This is a "
                                   "very common malware trick.")
                else:
                    sev = "Medium"
                    reasons.append("A program or file placed directly in the Startup folder runs at every sign-in.")
                self.add(Finding(sev or "Info", CAT_STARTUP, "Startup folder item: %s" % fn, p,
                                 " ".join(reasons) or "This shortcut starts an app when you sign in.",
                                 steps_startup_folder(p), {}, p, sha256_file(p) if ext != ".lnk" else ""))
        self._resolve(pending)

    def check_tasks(self):
        if not IS_WIN:
            return
        rows = ps_json("Get-ScheduledTask | Select-Object TaskName,TaskPath,"
                       "@{n='State';e={[string]$_.State}},Author,"
                       "@{n='Act';e={($_.Actions | ForEach-Object { (([string]$_.Execute) + ' ' + "
                       "([string]$_.Arguments)).Trim() }) -join ' | '}}", timeout=180)
        pending = []
        for r in rows:
            act = (r.get("Act") or "").strip()
            if not act:
                continue
            tpath, tname = r.get("TaskPath") or "\\", r.get("TaskName") or ""
            is_ms = tpath.lower().startswith("\\microsoft\\")
            ev = evaluate_command(act)
            if is_ms and ev["sev"] != "High":
                continue  # built-in Windows tasks: only clear red flags are worth showing
            if r.get("State") == "Disabled" and ev["sev"] == "High":
                ev["reasons"].append("(The task is currently disabled.)")

            def build(sev, reasons, tpath=tpath, tname=tname, act=act, r=r, ev=ev):
                cat = CAT_BRIDGE if ev["remote"] else CAT_TASKS
                why = " ".join(reasons) or "A scheduled task created by an app. Review it if you don't recognise the name."
                return Finding(sev, cat, "Scheduled task: %s" % tname, tpath + tname, why, steps_task(tpath, tname),
                               {"Runs": act, "State": r.get("State", ""), "Author": r.get("Author") or ""},
                               ev["exe"] if os.path.isfile(ev["exe"]) else "")
            pending.append(dict(ev, build=build, info_ok=not is_ms))
        self._resolve(pending)

    def check_services(self):
        if not IS_WIN:
            return
        rows = ps_json("Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName",
                       timeout=120)
        pending = []
        for r in rows:
            cmd = r.get("PathName") or ""
            if not cmd:
                continue
            ev = evaluate_command(cmd)
            if ev["remote"] and not ev["sev"] == "High":
                continue  # remote tools are reported in the Bridge section
            if ev["sev"] == "Low":
                continue

            def build(sev, reasons, r=r, cmd=cmd, ev=ev):
                return Finding(sev, CAT_SERVICES, "Service: %s" % (r.get("DisplayName") or r.get("Name")),
                               r.get("Name", ""), " ".join(reasons), steps_service(r.get("Name", ""), r.get("DisplayName", ""), ev["exe"]),
                               {"Runs": cmd, "State": r.get("State", ""), "Start mode": r.get("StartMode", "")},
                               ev["exe"] if os.path.isfile(ev["exe"]) else "")
            pending.append(dict(ev, build=build, info_ok=False))
        self._resolve(pending)

    # ---------------------------------------------------------------- processes
    def _proc_list(self):
        if self._procs is not None:
            return self._procs
        out = []
        if psutil:
            for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
                try:
                    i = p.info
                except Exception:  # noqa: BLE001
                    continue
                out.append({"pid": i.get("pid"), "name": (i.get("name") or ""), "exe": i.get("exe") or "",
                            "cmd": " ".join(i.get("cmdline") or []), "user": i.get("username") or ""})
        self._procs = out
        return out

    def check_processes(self):
        if not psutil:
            self.errors.append("psutil not available: running-program checks skipped.")
            return
        windir = norm(_env("SystemRoot", r"C:\Windows"))
        cands = {}
        for p in self._proc_list():
            name, exe, cmd = p["name"].lower(), p["exe"], p["cmd"]
            sev, reasons = None, []
            if name in LOOKALIKES:
                sev = "High"
                reasons.append("Its name imitates a core Windows process ('%s'). Malware uses look-alike names to hide." % p["name"])
            if IS_WIN and name in SYSTEM_NAMES and exe and not norm(exe).startswith(windir):
                sev = "High"
                reasons.append("It is named like a core Windows process but runs from the wrong folder.")
            if name in SCRIPT_HOSTS:
                sev = "High"
                reasons.append("A script is running right now through %s. Ordinary apps rarely do this." % p["name"])
            if name in SHELLS and SUSP_CMD.search(cmd or ""):
                sev = "High"
                reasons.append("A command window is running hidden/encoded/downloaded code.")
            tool, is_rat = remote_tool_for(name)
            if is_rat:
                sev = "High"
                reasons.append("Its name matches the known remote-access trojan '%s'." % tool)
            loc = loc_risk(exe)
            if sev:
                self.add(Finding(sev, CAT_PROCESSES, "Running: %s" % p["name"], exe or p["name"], " ".join(reasons),
                                 steps_program(p["name"], exe, p["pid"]),
                                 {"PID": p["pid"], "Command line": cmd[:600], "User": p["user"]}, exe,
                                 sha256_file(exe) if exe else ""))
            elif loc and exe and norm(exe) not in cands:
                cands[norm(exe)] = (p, loc)
        if cands:
            sigs = check_signatures([v[0]["exe"] for v in cands.values()])
            for p, loc in cands.values():
                st, subj = sigs.get(p["exe"], ("Unknown", ""))
                if st == "Valid" or (st == "Unknown" and IS_WIN):
                    continue
                if not IS_WIN and loc != "strong":
                    continue
                sev = "Medium" if loc == "strong" else "Low"
                if st == "HashMismatch":
                    sev = "High"
                why = ("This program is running from %s and is not validly signed (%s). Real software normally "
                       "runs from 'Program Files' and is signed." % (
                           "a Temp/Downloads/Public folder" if loc == "strong" else "your AppData folder", st))
                self.add(Finding(sev, CAT_PROCESSES, "Running: %s" % p["name"], p["exe"], why,
                                 steps_program(p["name"], p["exe"], p["pid"]),
                                 {"PID": p["pid"], "Signature": st, "Command line": p["cmd"][:600]}, p["exe"],
                                 sha256_file(p["exe"])))

    # ---------------------------------------------------------------- bridges
    def check_bridges(self):
        procs = {p["pid"]: p for p in self._proc_list()}
        ext_by_pid, listen_by_pid, rdp_live = {}, {}, []
        if psutil:
            try:
                conns = psutil.net_connections(kind="inet")
            except Exception as e:  # noqa: BLE001
                conns = []
                self.errors.append("Could not read network connections (%s). Run as Administrator." % e)
            for c in conns:
                if c.status == psutil.CONN_ESTABLISHED and c.raddr and is_public_ip(c.raddr.ip):
                    ext_by_pid.setdefault(c.pid, set()).add("%s:%s" % (c.raddr.ip, c.raddr.port))
                    if c.laddr and c.laddr.port == 3389:
                        rdp_live.append(c.raddr.ip)
                elif c.status == psutil.CONN_LISTEN and c.laddr and c.laddr.ip in ("0.0.0.0", "::"):
                    listen_by_pid.setdefault(c.pid, set()).add(c.laddr.port)

        # 1) remote-access tools / RATs running
        running_tools = {}
        for pid, p in procs.items():
            tool, is_rat = remote_tool_for(p["name"])
            if tool:
                t = running_tools.setdefault(tool, {"pids": [], "exe": p["exe"], "rat": is_rat, "ext": set(), "name": p["name"]})
                t["pids"].append(pid)
                t["ext"] |= ext_by_pid.get(pid, set())
        for tool, t in running_tools.items():
            if t["rat"]:
                sev, why = "High", ("A program matching the remote-access trojan '%s' is running. It can give a "
                                    "criminal full control of this PC." % tool)
            elif t["ext"]:
                sev, why = "High", ("%s is running AND connected to the internet right now. If you did not start a "
                                    "support session yourself, someone may be watching or controlling this PC." % tool)
            else:
                sev, why = "Medium", ("%s is running in the background, ready to accept remote connections. Scammers "
                                      "ask victims to install it to take control of the PC and bank accounts." % tool)
            self.add(Finding(sev, CAT_BRIDGE, "Remote access running: %s" % tool, t["exe"] or t["name"], why,
                             steps_remote(tool),
                             {"PIDs": ", ".join(map(str, t["pids"])),
                              "Live internet connections": ", ".join(sorted(t["ext"])[:10]) or "none right now"},
                             t["exe"]))

        # 2) installed remote tools (not running)
        if IS_WIN:
            seen = set()
            for root, path in (("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                               ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                               ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Uninstall")):
                for sk in reg_subkeys(root, path):
                    disp = str(reg_get(root, path + "\\" + sk, "DisplayName") or "")
                    dl = disp.lower()
                    if not disp or dl in seen or not any(w in dl for w in INSTALLED_REMOTE_WORDS):
                        continue
                    seen.add(dl)
                    if any(w.lower() in dl for w in running_tools):
                        continue
                    idate = str(reg_get(root, path + "\\" + sk, "InstallDate") or "")
                    recent = False
                    try:
                        recent = (datetime.now() - datetime.strptime(idate, "%Y%m%d")).days <= 14
                    except ValueError:
                        pass
                    self.add(Finding("Medium" if recent else "Low", CAT_BRIDGE, "Remote access installed: %s" % disp,
                                     "Installed apps", ("This remote-access app is installed%s. It is not running now, "
                                                        "but anyone with its access code could connect when it runs. "
                                                        "Remove it if you don't use it." % (
                                                            " recently (%s)" % idate if recent else "")),
                                     steps_remote(disp), {"Install date": idate or "unknown",
                                                          "Publisher": str(reg_get(root, path + "\\" + sk, "Publisher") or "")}))

        # 3) past incoming sessions (connection logs)
        logs = [("AnyDesk", pjoin(_env("APPDATA"), "AnyDesk", "connection_trace.txt")),
                ("AnyDesk", pjoin(_env("PROGRAMDATA"), "AnyDesk", "connection_trace.txt")),
                ("TeamViewer", pjoin(_env("ProgramFiles"), "TeamViewer", "Connections_incoming.txt")),
                ("TeamViewer", pjoin(_env("ProgramFiles(x86)"), "TeamViewer", "Connections_incoming.txt"))]
        for tool, lp in logs:
            if lp and os.path.isfile(lp):
                rows = read_tail_lines(lp)
                if rows:
                    self.add(Finding("Medium", CAT_BRIDGE, "Past incoming %s sessions found" % tool, lp,
                                     "This log lists computers that connected INTO this PC using %s. If you don't "
                                     "recognise these dates/IDs, someone may have controlled your PC." % tool,
                                     steps_remote(tool), {"Most recent entries": "\n" + "\n".join(rows)}, lp))

        # 4) Remote Desktop (RDP)
        if IS_WIN:
            deny = reg_get("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
            if rdp_live:
                self.add(Finding("High", CAT_BRIDGE, "Active Remote Desktop connection from the internet", "Port 3389",
                                 "Someone is connected to this PC through Remote Desktop right now.",
                                 STEPS_RDP, {"Connected from": ", ".join(sorted(set(rdp_live)))}))
            elif deny == 0:
                self.add(Finding("Medium", CAT_BRIDGE, "Remote Desktop is turned ON", "Settings > System > Remote Desktop",
                                 "Remote Desktop lets other computers sign in to this PC. Home users rarely need it, "
                                 "and attackers scan the internet for it.", STEPS_RDP))

        # 5) unknown programs talking to the internet / listening
        flagged_paths = {norm(f.path) for f in self.findings if f.path}
        for pid, addrs in ext_by_pid.items():
            p = procs.get(pid)
            if not p or remote_tool_for(p["name"])[0]:
                continue
            loc = loc_risk(p["exe"])
            if norm(p["exe"]) in flagged_paths or p["name"].lower() in SCRIPT_HOSTS or loc == "strong":
                self.add(Finding("High", CAT_NETWORK, "Suspicious program is connected to the internet: %s" % p["name"],
                                 p["exe"] or p["name"],
                                 "A program that already looks suspicious (or runs from Temp/Downloads) has live "
                                 "internet connections. It may be sending your data out or receiving commands.",
                                 steps_program(p["name"], p["exe"], pid),
                                 {"PID": pid, "Connected to": ", ".join(sorted(addrs)[:10])}, p["exe"]))
            else:
                self.add(Finding("Info", CAT_NETWORK, "Program connected to the internet: %s" % p["name"],
                                 p["exe"] or p["name"],
                                 "For your review. Browsers, WhatsApp, Windows Update and cloud apps connect to the "
                                 "internet normally. Look for programs you don't recognise.",
                                 ["If you don't recognise it, search its name and folder, or follow the "
                                  "'Running Programs' removal steps."],
                                 {"PID": pid, "Connections": len(addrs), "Examples": ", ".join(sorted(addrs)[:5])},
                                 p["exe"]))
        for pid, ports in listen_by_pid.items():
            p = procs.get(pid)
            if p and loc_risk(p["exe"]) == "strong":
                self.add(Finding("High", CAT_NETWORK, "Program from Temp/Downloads is accepting connections: %s" % p["name"],
                                 p["exe"], "This program opened a door (listening port) that other computers can "
                                           "connect to. Backdoors behave like this.",
                                 steps_program(p["name"], p["exe"], pid), {"Ports": ", ".join(map(str, sorted(ports)))},
                                 p["exe"]))

    # ---------------------------------------------------------------- network settings
    def check_network_settings(self):
        if IS_WIN:
            ie = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            en = reg_get("HKCU", ie, "ProxyEnable")
            srv = reg_get("HKCU", ie, "ProxyServer")
            pac = reg_get("HKCU", ie, "AutoConfigURL")
            if en == 1 and srv:
                self.add(Finding("Medium", CAT_NETWORK, "A proxy server is set for your internet traffic",
                                 "Settings > Network & internet > Proxy",
                                 "All browser traffic goes through '%s'. Banking malware sets a proxy to spy on or "
                                 "change what you see. If your office or college set it, this is fine." % srv,
                                 STEPS_PROXY, {"Proxy": str(srv)}))
            if pac:
                self.add(Finding("Medium", CAT_NETWORK, "An automatic proxy script is set",
                                 "Settings > Network & internet > Proxy",
                                 "A setup script (%s) decides where your traffic goes. Malware uses this to redirect "
                                 "banking sites. If your office set it, this is fine." % pac,
                                 STEPS_PROXY, {"Script URL": str(pac)}))
        hosts = (os.path.join(_env("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
                 if IS_WIN else "/etc/hosts")
        sensitive = ["bank", "sbi", "hdfc", "icici", "axis", "kotak", "paytm", "phonepe", "gpay", "google",
                     "microsoft", "windowsupdate", "whatsapp", "facebook", "instagram", "gov.in", "npci", "upi",
                     "amazon", "flipkart", "apple", "defender", "avast", "kaspersky", "quickheal", "mcafee",
                     "norton", "eset", "malwarebytes", "virustotal", "k7computing", "escan"]
        try:
            with open(hosts, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            lines = []
        bad, other = [], []
        for line in lines:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ip, names = parts[0], parts[1:]
            names_l = [n.lower() for n in names]
            if all(n in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
                         "broadcasthost") or n.startswith("ip6-") for n in names_l):
                continue
            if any(any(s in n for s in sensitive) for n in names_l):
                bad.append(line)
            elif not (IS_WIN is False and ip.startswith("127.")):
                other.append(line)
        if bad:
            self.add(Finding("High", CAT_NETWORK, "Hosts file redirects or blocks important websites", hosts,
                             "Your hosts file changes where bank, Google, WhatsApp or antivirus websites go. Malware "
                             "does this to show fake bank pages or to stop security updates.",
                             STEPS_HOSTS, {"Suspicious lines": "\n" + "\n".join(bad[:15])}, hosts))
        if other:
            self.add(Finding("Info", CAT_NETWORK, "Hosts file has custom entries", hosts,
                             "Custom hosts entries are usually added by developers or ad-blockers. Review them if you "
                             "didn't add them.", STEPS_HOSTS, {"Entries": "\n" + "\n".join(other[:15])}, hosts))

    # ---------------------------------------------------------------- protection
    def check_protection(self):
        if not IS_WIN:
            self.add(Finding("Info", CAT_PROTECTION, "Windows-only checks skipped", platform.system(),
                             "Startup, services, Defender and registry checks run only on Windows."))
            return
        av = ps_json("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
                     "Select-Object displayName,productState")
        enabled_av = []
        for a in av:
            try:
                on = ((int(a.get("productState") or 0) >> 12) & 0xF) == 1
            except (TypeError, ValueError):
                on = False
            if on:
                enabled_av.append(a.get("displayName", ""))
            self.add(Finding("Info", CAT_PROTECTION, "Antivirus: %s (%s)" % (a.get("displayName", "?"), "On" if on else "Off"),
                             "Windows Security Center", "Antivirus product registered with Windows."))
        third_party_on = any("defender" not in (n or "").lower() for n in enabled_av)
        st = ps_json("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
                     "IsTamperProtected,AMRunningMode,AntivirusSignatureAge,QuickScanAge,FullScanAge")
        if st:
            s = st[0]
            if not s.get("RealTimeProtectionEnabled") and not third_party_on:
                self.add(Finding("High", CAT_PROTECTION, "Microsoft Defender real-time protection is OFF",
                                 "Windows Security", "Without real-time protection, malicious files can run without "
                                 "any warning. Malware often switches it off.", STEPS_DEFENDER_OFF,
                                 {"Running mode": s.get("AMRunningMode", "")}))
            age = s.get("AntivirusSignatureAge")
            if isinstance(age, int) and 7 < age < 100000 and not third_party_on:
                self.add(Finding("Medium", CAT_PROTECTION, "Defender virus definitions are %d days old" % age,
                                 "Windows Security", "Old definitions cannot recognise new malware.",
                                 ["Windows Security > Virus & threat protection > Protection updates > Check for updates."]))
            if s.get("IsTamperProtected") is False and not third_party_on:
                self.add(Finding("Low", CAT_PROTECTION, "Tamper Protection is off", "Windows Security",
                                 "Tamper Protection stops malware from switching Defender off.", STEPS_DEFENDER_OFF))
        elif not enabled_av:
            self.add(Finding("Medium", CAT_PROTECTION, "Could not confirm any active antivirus", "Windows Security",
                             "SafeCheck could not read the antivirus status. Open Windows Security and check that "
                             "virus protection is on.", STEPS_DEFENDER_OFF))
        if av and not enabled_av:
            self.add(Finding("High", CAT_PROTECTION, "No active antivirus", "Windows Security",
                             "All registered antivirus products are turned off.", STEPS_DEFENDER_OFF))
        for r in ps_json("Get-NetFirewallProfile | Select-Object Name,@{n='On';e={[string]$_.Enabled}}"):
            if str(r.get("On", "")).lower() in ("false", "0"):
                self.add(Finding("Medium", CAT_PROTECTION, "Firewall is OFF for %s networks" % r.get("Name", "?"),
                                 "Windows Security", "The firewall blocks unwanted incoming connections.", STEPS_FIREWALL))
        threats = ps_json("Get-MpThreat | Select-Object ThreatName,IsActive,DidThreatExecute,"
                          "@{n='Res';e={($_.Resources -join '; ')}}")
        for t in threats[:20]:
            active, ran = bool(t.get("IsActive")), bool(t.get("DidThreatExecute"))
            sev = "High" if (active or ran) else "Low"
            self.add(Finding(sev, CAT_PROTECTION, "Defender detection: %s" % t.get("ThreatName", "?"),
                             (t.get("Res") or "")[:300],
                             ("Microsoft Defender detected this threat. " +
                              ("It is still ACTIVE. " if active else "It is no longer active. ") +
                              ("It had already RUN on this PC." if ran else "")),
                             STEPS_THREAT, {"Active": active, "Had executed": ran, "Files": t.get("Res", "")}))

    def add_whatsapp_checklist(self):
        self.add(Finding("Check", CAT_WHATSAPP, "Check WhatsApp Linked Devices and Two-step verification",
                         "On your phone",
                         "WhatsApp 'Linked devices' is also a bridge: a linked computer can read and send your "
                         "messages. Scams like 'GhostPairing' trick people into linking the attacker's device. "
                         "SafeCheck cannot see this from the PC, so please check it on your phone.", STEPS_WHATSAPP))


# --------------------------------------------------------------------------------------------
# Microsoft Defender on-demand scan (NO remediation)
# --------------------------------------------------------------------------------------------
def mpcmdrun_path() -> str:
    plat = os.path.join(_env("ProgramData", r"C:\ProgramData"), "Microsoft", "Windows Defender", "Platform")
    try:
        vers = [d for d in os.listdir(plat) if os.path.isfile(os.path.join(plat, d, "MpCmdRun.exe"))]
        vers.sort(key=lambda v: [int(x) for x in re.findall(r"\d+", v)], reverse=True)
        if vers:
            return os.path.join(plat, vers[0], "MpCmdRun.exe")
    except OSError:
        pass
    p = os.path.join(_env("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe")
    return p if os.path.isfile(p) else ""


def defender_scan_file(path: str) -> str:
    exe = mpcmdrun_path() if IS_WIN else ""
    if not exe:
        return "Microsoft Defender's command-line scanner was not found (another antivirus may be active)."
    code, out, err = run_cmd([exe, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"], timeout=900)
    threats = [t.strip() for t in re.findall(r"Threat\s*:\s*(.+)", out)]
    if code == 0:
        return "Microsoft Defender found NO threats in this file.\n\n(This is not a 100% guarantee.)"
    if code == 2 or threats:
        return ("Microsoft Defender DETECTED a threat:\n  " + "\n  ".join(threats or ["(name not shown)"]) +
                "\n\nSafeCheck asked Defender NOT to take any action. Follow the removal steps shown in SafeCheck.")
    return "Defender returned code %s.\n%s" % (code, (out or err)[-800:])


# --------------------------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------------------------
def counts(findings):
    c = {s: 0 for s in SEVERITIES}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c


def report_html(findings, meta) -> str:
    c = counts(findings)
    colors = {"High": "#b91c1c", "Medium": "#b45309", "Low": "#1d4ed8", "Check": "#047857", "Info": "#475569"}
    rows = []
    for f in findings:
        det = "".join("<div><b>%s:</b> %s</div>" % (html.escape(str(k)), html.escape(str(v)).replace("\n", "<br>"))
                      for k, v in f.details.items() if v not in ("", None))
        steps = "".join("<li>%s</li>" % html.escape(s) for s in f.remove)
        rows.append(
            "<section><h3><span class='sev' style='background:%s'>%s</span> %s</h3>"
            "<div class='cat'>%s</div><div class='loc'>%s</div>%s%s<p>%s</p>%s</section>" % (
                colors.get(f.severity, "#475569"), f.severity, html.escape(f.title), html.escape(f.category),
                html.escape(f.location), det,
                ("<div><b>SHA-256:</b> <code>%s</code></div>" % f.sha256) if f.sha256 else "",
                html.escape(f.why), ("<h4>How to remove it (manual steps)</h4><ol>%s</ol>" % steps) if steps else ""))
    return """<!doctype html><html><head><meta charset="utf-8"><title>SafeCheck report</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;max-width:960px;margin:24px auto;padding:0 16px;color:#111}
section{border:1px solid #ddd;border-radius:8px;padding:12px 16px;margin:12px 0}
.sev{color:#fff;border-radius:4px;padding:2px 8px;font-size:13px}.cat{color:#555;font-size:13px}
.loc{font-family:Consolas,monospace;font-size:12px;color:#333;word-break:break-all}code{word-break:break-all}</style>
</head><body><h1>%s report</h1><p>%s</p><p><b>High:</b> %d &nbsp; <b>Medium:</b> %d &nbsp; <b>Low:</b> %d
&nbsp; <b>Manual checks:</b> %d &nbsp; <b>Info:</b> %d</p><p><i>%s</i></p>%s</body></html>""" % (
        APP_NAME, html.escape(" | ".join("%s: %s" % kv for kv in meta.items())),
        c["High"], c["Medium"], c["Low"], c["Check"], c["Info"],
        "SafeCheck is read-only: it did not delete or change anything. No scanner can guarantee a PC is clean.",
        "".join(rows))


def meta_info(scanner: Scanner) -> dict:
    return {"Computer": platform.node(), "OS": "%s %s" % (platform.system(), platform.release()),
            "Scanned": datetime.now().strftime("%Y-%m-%d %H:%M"), "Administrator": "Yes" if is_admin() else "No",
            "Files checked": scanner.scanned_files, "Version": APP_VERSION}


# --------------------------------------------------------------------------------------------
# Guide text (English UI)
# --------------------------------------------------------------------------------------------
GUIDE = [
    ("h1", "Removal Guide\n"),
    ("p", "SafeCheck never deletes anything for you. This guide explains what to do yourself, step by step.\n"),
    ("h2", "\nIf you already opened a suspicious file on this PC\n"),
    ("ol", ["Disconnect from the internet (turn off Wi-Fi or unplug the cable). This stops data theft and remote control.",
            "From ANOTHER device (your phone), call your bank or 1930 if any money moved or OTPs arrived. Block net-banking/UPI if needed.",
            "Run SafeCheck as Administrator and look at High items in Startup, Scheduled Tasks, Running Programs and Remote Access.",
            "Disable/remove those items using the steps shown for each one.",
            "Run Microsoft Defender Offline scan: Windows Security > Virus & threat protection > Scan options > Microsoft Defender Offline scan > Scan now.",
            "From another device, change passwords: email first, then net-banking, UPI, social media. Turn on two-factor login.",
            "On your phone: WhatsApp > Linked devices > log out all unknown devices; turn on Two-step verification.",
            "Report it: cybercrime.gov.in or call 1930. Report fraud messages on Sanchar Saathi (Chakshu).",
            "If problems continue, back up your photos/documents (not programs) and reinstall Windows (Settings > System > Recovery > Reset this PC > Remove everything)."]),
    ("h2", "\nIf an APK was installed on a phone\n"),
    ("ol", ["Turn on Airplane mode immediately.",
            "Settings > Accessibility: turn off any unknown app's service.",
            "Settings > Security > Device admin apps: remove admin rights from the unknown app.",
            "Settings > Notifications > Notification access (and Default apps > SMS app): remove the unknown app.",
            "Uninstall the app. If its icon is hidden or Uninstall is greyed out, restart in Safe Mode (long-press Power, then long-press 'Power off') and uninstall from Settings > Apps.",
            "Open Play Store > profile icon > Play Protect > Scan.",
            "Change banking/email passwords from a clean device and call your bank. Lost money? Call 1930 at once."]),
    ("h2", "\nWhat a 'bridge' means here\n"),
    ("p", "A bridge is any path that lets someone else reach this PC or your accounts: remote-access apps "
          "(AnyDesk, UltraViewer, TeamViewer, RustDesk, VNC), remote-access trojans, Remote Desktop, a changed proxy or "
          "hosts file, a program secretly talking to the internet, or an unknown device linked to your WhatsApp.\n"),
    ("h2", "\nStay safe\n"),
    ("ol", ["Government offices, banks and wedding invitations never send APK, ZIP, .vbs, .lnk or .exe files.",
            "If a known contact sends an unexpected file, call them before opening it. Their account may be hacked.",
            "Keep Windows, your browser and WhatsApp Desktop updated.",
            "Never install AnyDesk/UltraViewer/TeamViewer for a 'customer care' caller.",
            "Never share OTPs, WhatsApp codes or pairing codes."]),
]

ABOUT = ("%s %s\n\n"
         "A free, read-only security checker.\n\n"
         "\u2022 It NEVER deletes, moves, quarantines or changes files, registry, tasks, services or settings.\n"
         "\u2022 It NEVER uploads files. 'Look Up Hash Online' only opens your browser with the file's SHA-256 "
         "fingerprint, and only when you click it.\n"
         "\u2022 'Scan File with Microsoft Defender' asks Defender to scan with remediation DISABLED.\n"
         "\u2022 Note: Microsoft Defender's own real-time protection may still quarantine a dangerous file when any "
         "program reads it. That is Defender's action, not SafeCheck's.\n\n"
         "No scanner can guarantee a computer is clean. 'No known red flags' does not mean 'safe'.\n\n"
         "Run as Administrator for complete results (services, all processes, all network connections).\n\n"
         "Emergency (India): call 1930 or report at cybercrime.gov.in" % (APP_NAME, APP_VERSION))


# --------------------------------------------------------------------------------------------
# Demo results (fake, for showing what detections look like - nothing on this PC is touched)
# --------------------------------------------------------------------------------------------
DEMO_TAG = "[DEMO] "


def demo_findings() -> list:
    u = r"C:\Users\Demo"
    wa = u + r"\Downloads"
    D = DEMO_TAG
    f = [
        Finding("High", CAT_BRIDGE, D + "Remote access running: AnyDesk", r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe",
                "AnyDesk is running AND connected to the internet right now. If you did not start a support session "
                "yourself, someone may be watching or controlling this PC.", steps_remote("AnyDesk"),
                {"PIDs": "7420, 7436", "Live internet connections": "185.229.191.44:443, 195.181.174.17:80"}),
        Finding("Medium", CAT_BRIDGE, D + "Past incoming AnyDesk sessions found", u + r"\AppData\Roaming\AnyDesk\connection_trace.txt",
                "This log lists computers that connected INTO this PC using AnyDesk. If you don't recognise these "
                "dates/IDs, someone may have controlled your PC.", steps_remote("AnyDesk"),
                {"Most recent entries": "\nIncoming    2026-10-21, 11:42    User    482 917 305    482 917 305"
                                        "\nIncoming    2026-10-21, 11:58    Passwd  482 917 305    482 917 305"}),
        Finding("High", CAT_BRIDGE, D + "Active Remote Desktop connection from the internet", "Port 3389",
                "Someone is connected to this PC through Remote Desktop right now.", STEPS_RDP,
                {"Connected from": "103.214.6.29"}),
        Finding("Medium", CAT_BRIDGE, D + "Remote access installed: UltraViewer", "Installed apps",
                "This remote-access app is installed recently (20261020). It is not running now, but anyone with its "
                "access code could connect when it runs. Remove it if you don't use it.", steps_remote("UltraViewer"),
                {"Install date": "20261020"}),
        Finding("High", CAT_FILES, D + "VBScript file: Bill_Payment.pdf.vbs", wa + r"\Bill_Payment.pdf.vbs",
                "The name has two extensions (for example 'photo.jpg.exe'). Windows often hides the last one, so a "
                "program or script pretends to be a photo or document. " + WHY_SCRIPT +
                " This file was downloaded through WhatsApp Web/Desktop.", steps_file(),
                {"File type": "VBScript file", "Size": "3.2 KB", "Downloaded from": "https://web.whatsapp.com/"},
                "", "9f2c" + "0" * 60),
        Finding("High", CAT_FILES, D + "Risky archive: Wedding_Invitation.zip", wa + r"\Wedding_Invitation.zip",
                "This archive contains risky files: Wedding_Card.pdf.lnk  (Shortcut). A ZIP holding just one or two "
                "scripts/programs/shortcuts is a classic malware delivery trick (seen in the SORVEPOTEL WhatsApp worm).",
                steps_file("zip"), {"File type": "Risky archive", "Downloaded from": "https://web.whatsapp.com/"}),
        Finding("High", CAT_FILES, D + "Android app (APK): RTO_E-Challan.apk", wa + r"\RTO_E-Challan.apk",
                WHY_APK + " The name uses a common scam bait word (challan, rto).", steps_file("apk"),
                {"File type": "Android app (APK)"}),
        Finding("High", CAT_PROCESSES, D + "Running: svchost.exe", u + r"\AppData\Roaming\Microsoft\svchost.exe",
                "It is named like a core Windows process but runs from the wrong folder.",
                steps_program("svchost.exe", u + r"\AppData\Roaming\Microsoft\svchost.exe", 9132),
                {"PID": 9132, "Signature": "NotSigned"}),
        Finding("High", CAT_NETWORK, D + "Suspicious program is connected to the internet: svchost.exe",
                u + r"\AppData\Roaming\Microsoft\svchost.exe",
                "A program that already looks suspicious (or runs from Temp/Downloads) has live internet connections. "
                "It may be sending your data out or receiving commands.",
                steps_program("svchost.exe", u + r"\AppData\Roaming\Microsoft\svchost.exe", 9132),
                {"PID": 9132, "Connected to": "91.92.240.18:4782"}),
        Finding("High", CAT_STARTUP, D + "Startup folder item: update.vbs",
                u + r"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.vbs",
                "A script in the Startup folder runs automatically at every sign-in. This is a very common malware trick.",
                steps_startup_folder("update.vbs")),
        Finding("High", CAT_TASKS, D + "Scheduled task: ChromeUpdaterSvc", "\\ChromeUpdaterSvc",
                "The command uses tricks typical of malware: a hidden window, encoded commands, or code downloaded "
                "from the internet.", steps_task("\\", "ChromeUpdaterSvc"),
                {"Runs": "powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi...", "State": "Ready"}),
        Finding("High", CAT_NETWORK, D + "Hosts file redirects or blocks important websites",
                r"C:\Windows\System32\drivers\etc\hosts",
                "Your hosts file changes where bank, Google, WhatsApp or antivirus websites go. Malware does this to "
                "show fake bank pages or to stop security updates.", STEPS_HOSTS,
                {"Suspicious lines": "\n45.88.12.9  onlinesbi.sbi\n127.0.0.1  www.quickheal.co.in"}),
        Finding("High", CAT_PROTECTION, D + "Microsoft Defender real-time protection is OFF", "Windows Security",
                "Without real-time protection, malicious files can run without any warning. Malware often switches it off.",
                STEPS_DEFENDER_OFF),
        Finding("Check", CAT_WHATSAPP, D + "Check WhatsApp Linked Devices and Two-step verification", "On your phone",
                "WhatsApp 'Linked devices' is also a bridge: a linked computer can read and send your messages.",
                STEPS_WHATSAPP),
    ]
    f.sort(key=lambda x: (SEV_RANK.get(x.severity, 9), x.category))
    return f


def live_bridges(findings) -> list:
    return [f for f in findings if f.severity == "High" and (
        f.category == CAT_BRIDGE or (f.category == CAT_NETWORK and ("connected" in f.title or "accepting" in f.title)))]


# --------------------------------------------------------------------------------------------
# GUI (tkinter)
# --------------------------------------------------------------------------------------------
def run_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    if IS_WIN:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:  # noqa: BLE001
            pass

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("%s %s" % (APP_NAME, APP_VERSION))
            self.geometry("1200x780")
            self.minsize(940, 620)
            self.q: queue.Queue = queue.Queue()
            self.findings: list[Finding] = []
            self.scanner: Scanner | None = None
            self.cancel = threading.Event()
            self.worker = None
            self.item_map = {}
            self.current: Finding | None = None
            self.show_info = tk.BooleanVar(value=False)
            self._build()
            self.after(120, self._poll)

        # ---------- layout ----------
        def _build(self):
            style = ttk.Style(self)
            for th in ("vista", "winnative", "clam"):
                if th in style.theme_names():
                    style.theme_use(th)
                    break
            style.configure("Treeview", rowheight=26)
            style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
            style.configure("Sub.TLabel", foreground="#555")
            style.configure("Sum.TLabel", font=("Segoe UI", 10, "bold"))

            top = ttk.Frame(self, padding=(14, 10, 14, 4))
            top.pack(fill="x")
            ttk.Label(top, text=APP_NAME, style="Title.TLabel").pack(side="left")
            ttk.Label(top, text="   Read-only: it never deletes or changes anything. Nothing is uploaded.",
                      style="Sub.TLabel").pack(side="left")
            admin = is_admin()
            ttk.Label(top, text=("Administrator: Yes" if admin else "Administrator: No (some checks limited)"),
                      foreground=("#047857" if admin else "#b45309")).pack(side="right")
            if IS_WIN and not admin:
                ttk.Button(top, text="Restart as Administrator", command=self.restart_admin).pack(side="right", padx=8)

            bar = ttk.Frame(self, padding=(14, 4))
            bar.pack(fill="x")
            self.btn_full = ttk.Button(bar, text="Run Full Check", command=lambda: self.start("full"))
            self.btn_full.pack(side="left")
            ttk.Button(bar, text="Scan a Folder...", command=self.pick_folder).pack(side="left", padx=6)
            ttk.Button(bar, text="Check a File...", command=self.pick_file).pack(side="left")
            ttk.Button(bar, text="Show Demo Results", command=self.show_demo).pack(side="left", padx=6)
            self.btn_stop = ttk.Button(bar, text="Stop", command=self.cancel.set, state="disabled")
            self.btn_stop.pack(side="left", padx=6)
            ttk.Button(bar, text="Export Report...", command=self.export).pack(side="right")
            ttk.Checkbutton(bar, text="Show informational items", variable=self.show_info,
                            command=self.refresh_tree).pack(side="right", padx=10)

            st = ttk.Frame(self, padding=(14, 2))
            st.pack(fill="x")
            self.pb = ttk.Progressbar(st, mode="indeterminate", length=180)
            self.pb.pack(side="left")
            self.status = ttk.Label(st, text="Ready. Click 'Run Full Check' to start.")
            self.status.pack(side="left", padx=10)
            self.summary = ttk.Label(self, text="", style="Sum.TLabel", padding=(14, 4))
            self.summary.pack(fill="x")
            self.banner = tk.Label(self, text="", anchor="w", justify="left", padx=14, pady=8,
                                   font=("Segoe UI", 11, "bold"), fg="white", bg="#b91c1c", wraplength=1100)
            self.banner_shown = False

            nb = ttk.Notebook(self)
            nb.pack(fill="both", expand=True, padx=10, pady=(0, 10))
            self.nb = nb

            res = ttk.Frame(nb)
            nb.add(res, text="  Scan Results  ")
            pw = ttk.PanedWindow(res, orient="vertical")
            pw.pack(fill="both", expand=True)

            tf = ttk.Frame(pw)
            cols = ("sev", "cat", "title", "loc")
            self.tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
            for c, t, w in (("sev", "Severity", 80), ("cat", "Category", 170), ("title", "Finding", 430),
                            ("loc", "Location", 420)):
                self.tree.heading(c, text=t)
                self.tree.column(c, width=w, stretch=(c in ("title", "loc")))
            for s, bg in (("High", "#fde2e1"), ("Medium", "#fff1d6"), ("Low", "#e8f0ff"),
                          ("Check", "#e3f6ec"), ("Info", "#ffffff")):
                self.tree.tag_configure(s, background=bg)
            ys = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
            self.tree.configure(yscrollcommand=ys.set)
            self.tree.pack(side="left", fill="both", expand=True)
            ys.pack(side="right", fill="y")
            self.tree.bind("<<TreeviewSelect>>", self.on_select)
            pw.add(tf, weight=3)

            df = ttk.Frame(pw)
            btns = ttk.Frame(df, padding=(0, 6))
            btns.pack(fill="x")
            self.b_open = ttk.Button(btns, text="Open File Location", command=self.open_location, state="disabled")
            self.b_hash = ttk.Button(btns, text="Copy SHA-256", command=self.copy_hash, state="disabled")
            self.b_look = ttk.Button(btns, text="Look Up Hash Online", command=self.lookup, state="disabled")
            self.b_def = ttk.Button(btns, text="Scan File with Microsoft Defender", command=self.defender, state="disabled")
            self.b_copy = ttk.Button(btns, text="Copy Details", command=self.copy_details, state="disabled")
            for b in (self.b_open, self.b_hash, self.b_look, self.b_def, self.b_copy):
                b.pack(side="left", padx=(0, 6))
            self.detail = tk.Text(df, wrap="word", height=14, padx=12, pady=10, relief="flat",
                                  font=("Segoe UI", 10), background="#fafafa")
            dys = ttk.Scrollbar(df, orient="vertical", command=self.detail.yview)
            self.detail.configure(yscrollcommand=dys.set)
            self.detail.pack(side="left", fill="both", expand=True)
            dys.pack(side="right", fill="y")
            self._text_tags(self.detail)
            self._set_text(self.detail, [("muted", "Select a finding to see why it matters and how to remove it.")])
            pw.add(df, weight=2)

            gf = ttk.Frame(nb)
            nb.add(gf, text="  Removal Guide  ")
            g = tk.Text(gf, wrap="word", padx=16, pady=12, relief="flat", font=("Segoe UI", 10))
            gys = ttk.Scrollbar(gf, orient="vertical", command=g.yview)
            g.configure(yscrollcommand=gys.set)
            g.pack(side="left", fill="both", expand=True)
            gys.pack(side="right", fill="y")
            self._text_tags(g)
            parts = []
            for kind, val in GUIDE:
                if kind == "ol":
                    for i, s in enumerate(val, 1):
                        parts.append(("step", "%d. %s\n" % (i, s)))
                else:
                    parts.append((kind, val))
            self._set_text(g, parts)

            af = ttk.Frame(nb)
            nb.add(af, text="  About  ")
            a = tk.Text(af, wrap="word", padx=16, pady=12, relief="flat", font=("Segoe UI", 10))
            a.pack(fill="both", expand=True)
            self._text_tags(a)
            self._set_text(a, [("p", ABOUT)])

        def _text_tags(self, t):
            t.tag_configure("h1", font=("Segoe UI", 14, "bold"), spacing3=6)
            t.tag_configure("h2", font=("Segoe UI", 11, "bold"), spacing1=6, spacing3=3)
            t.tag_configure("b", font=("Segoe UI", 10, "bold"))
            t.tag_configure("p", spacing3=4)
            t.tag_configure("step", lmargin1=14, lmargin2=34, spacing3=3)
            t.tag_configure("muted", foreground="#666")
            t.tag_configure("mono", font=("Consolas", 9))
            for s, col in (("High", "#b91c1c"), ("Medium", "#b45309"), ("Low", "#1d4ed8"),
                           ("Check", "#047857"), ("Info", "#475569")):
                t.tag_configure("sev_" + s, foreground=col, font=("Segoe UI", 10, "bold"))

        @staticmethod
        def _set_text(t, parts):
            t.configure(state="normal")
            t.delete("1.0", "end")
            for tag, txt in parts:
                t.insert("end", txt, tag)
            t.configure(state="disabled")

        # ---------- actions ----------
        def restart_admin(self):
            if getattr(sys, "frozen", False):
                exe, params = sys.executable, ""
            else:
                exe, params = sys.executable, '"%s"' % os.path.abspath(sys.argv[0])
            r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
            if r > 32:
                self.destroy()

        def pick_folder(self):
            d = filedialog.askdirectory(title="Choose a folder to scan")
            if d:
                self.start("folder", d)

        def pick_file(self):
            f = filedialog.askopenfilename(title="Choose a file to check")
            if f:
                self.start("file", f)

        def start(self, mode, target=None):
            if self.worker and self.worker.is_alive():
                return
            self.cancel.clear()
            self.findings = []
            self.refresh_tree()
            self.pb.start(12)
            self.btn_stop.configure(state="normal")
            self.btn_full.configure(state="disabled")
            if mode == "file":
                self.show_info.set(True)

            def work():
                sc = Scanner(progress=lambda m: self.q.put(("status", m)), cancel=self.cancel)
                try:
                    if mode == "full":
                        sc.run_full()
                    elif mode == "folder":
                        sc.scan_folders([(target, "custom")])
                        sc.finish()
                    else:
                        sc.scan_single_file(target)
                        sc.finish()
                except Exception as e:  # noqa: BLE001
                    sc.errors.append(str(e))
                self.q.put(("done", sc))
            self.worker = threading.Thread(target=work, daemon=True)
            self.worker.start()

        def _poll(self):
            try:
                while True:
                    kind, val = self.q.get_nowait()
                    if kind == "status":
                        self.status.configure(text=val[:160])
                    elif kind == "done":
                        self.scanner = val
                        self.findings = val.findings
                        self.pb.stop()
                        self.btn_stop.configure(state="disabled")
                        self.btn_full.configure(state="normal")
                        secs = time.time() - val.started
                        msg = "Finished in %.0f s. %d files checked." % (secs, val.scanned_files)
                        if self.cancel.is_set():
                            msg = "Stopped. Results so far are shown."
                        if val.errors:
                            msg += "  Notes: " + "; ".join(val.errors[:2])
                        self.status.configure(text=msg[:220])
                        self.refresh_tree()
                        self.alert_popup()
                    elif kind == "defender":
                        messagebox.showinfo("Microsoft Defender result", val)
                        self.b_def.configure(state="normal")
            except queue.Empty:
                pass
            self.after(150, self._poll)

        def show_demo(self):
            if self.worker and self.worker.is_alive():
                return
            self.scanner = Scanner()
            self.findings = demo_findings()
            self.status.configure(text="DEMO MODE: these are sample results to show how detections look. "
                                       "Nothing on this PC was scanned or changed.")
            self.refresh_tree()
            self.alert_popup()

        def alert_popup(self):
            live = live_bridges(self.findings)
            high = [f for f in self.findings if f.severity == "High"]
            demo = any(f.title.startswith(DEMO_TAG) for f in self.findings)
            if live:
                names = "\n".join("  \u2022 " + f.title.replace(DEMO_TAG, "") for f in live[:5])
                messagebox.showwarning(
                    ("DEMO - " if demo else "") + "Possible live connection to this PC",
                    "SafeCheck found a possible bridge into this PC:\n\n%s\n\n"
                    "If you did NOT start a support session yourself:\n"
                    "1. Turn off Wi-Fi or unplug the network cable NOW.\n"
                    "2. Then click each red row to see how to remove it.\n"
                    "3. From another phone, call your bank / 1930 if money or OTPs are involved.\n\n"
                    "SafeCheck has not changed anything." % names)
            elif high:
                messagebox.showwarning(
                    ("DEMO - " if demo else "") + "High-risk items found",
                    "SafeCheck found %d high-risk item(s).\n\nDo not open the flagged files. Click each red row "
                    "to see why it is risky and how to remove it.\n\nSafeCheck has not changed anything." % len(high))

        def _update_banner(self):
            live = live_bridges(self.findings)
            high = [f for f in self.findings if f.severity == "High"]
            demo = any(f.title.startswith(DEMO_TAG) for f in self.findings)
            pre = "DEMO \u2014 " if demo else ""
            if live:
                txt = (pre + "\u26a0  ALERT: possible live connection into this PC (%s). If you did not start it, "
                       "turn off Wi-Fi NOW, then follow the steps for each red item." %
                       ", ".join(sorted({f.title.replace(DEMO_TAG, "").split(": ", 1)[-1] for f in live})[:3]))
                bg = "#b91c1c"
            elif high:
                txt = pre + "\u26a0  %d HIGH-risk item(s) found. Do not open flagged files. Click each red row for removal steps." % len(high)
                bg = "#c2410c"
            else:
                txt, bg = "", None
            if txt:
                self.banner.configure(text=txt, bg=bg)
                if not self.banner_shown:
                    self.banner.pack(fill="x", padx=10, pady=(0, 6), after=self.summary)
                    self.banner_shown = True
            elif self.banner_shown:
                self.banner.pack_forget()
                self.banner_shown = False

        def refresh_tree(self):
            self._update_banner()
            self.tree.delete(*self.tree.get_children())
            self.item_map.clear()
            for f in self.findings:
                if f.severity == "Info" and not self.show_info.get():
                    continue
                iid = self.tree.insert("", "end", values=(f.severity, f.category, f.title, f.location),
                                       tags=(f.severity,))
                self.item_map[iid] = f
            c = counts(self.findings)
            if not self.findings:
                self.summary.configure(text="")
                return
            txt = "High: %d    Medium: %d    Low: %d    Manual checks: %d    Info: %d" % (
                c["High"], c["Medium"], c["Low"], c["Check"], c["Info"])
            if c["High"] == 0 and c["Medium"] == 0:
                txt += "     No high or medium risks found (this is not a guarantee)."
            elif c["High"]:
                txt += "     Review the HIGH items first."
            self.summary.configure(text=txt, foreground="#b91c1c" if c["High"] else "#111")

        def on_select(self, _e=None):
            sel = self.tree.selection()
            if not sel:
                return
            f = self.item_map.get(sel[0])
            self.current = f
            if not f:
                return
            parts = [("h1", f.title + "\n"), ("sev_" + f.severity, f.severity), ("muted", "   \u2022   %s\n" % f.category)]
            if f.location:
                parts += [("b", "Location: "), ("mono", f.location + "\n")]
            if f.sha256:
                parts += [("b", "SHA-256: "), ("mono", f.sha256 + "\n")]
            for k, v in f.details.items():
                if v in ("", None):
                    continue
                parts += [("b", "%s: " % k), ("p", "%s\n" % v)]
            if f.why:
                parts += [("h2", "\nWhy this matters\n"), ("p", f.why + "\n")]
            if f.remove:
                parts.append(("h2", "\nHow to remove it (manual steps)\n"))
                parts += [("step", "%d. %s\n" % (i, s)) for i, s in enumerate(f.remove, 1)]
            parts.append(("muted", "\n" + NO_CHANGE_NOTE + "\n"))
            self._set_text(self.detail, parts)
            exists = bool(f.path) and os.path.exists(f.path)
            self.b_open.configure(state="normal" if exists else "disabled")
            self.b_hash.configure(state="normal" if f.sha256 else "disabled")
            self.b_look.configure(state="normal" if f.sha256 else "disabled")
            self.b_def.configure(state="normal" if (exists and os.path.isfile(f.path) and IS_WIN) else "disabled")
            self.b_copy.configure(state="normal")

        def open_location(self):
            f = self.current
            if not f or not f.path:
                return
            p = os.path.normpath(f.path)
            if IS_WIN:
                subprocess.Popen('explorer /select,"%s"' % p)
            else:
                webbrowser.open("file://" + os.path.dirname(p))

        def copy_hash(self):
            if self.current and self.current.sha256:
                self.clipboard_clear()
                self.clipboard_append(self.current.sha256)
                self.status.configure(text="SHA-256 copied to clipboard.")

        def lookup(self):
            f = self.current
            if not f or not f.sha256:
                return
            if messagebox.askyesno("Look up hash online",
                                   "This opens VirusTotal in your browser with the file's SHA-256 fingerprint only.\n"
                                   "The file itself is NOT uploaded.\n\nContinue?"):
                webbrowser.open("https://www.virustotal.com/gui/file/" + f.sha256)

        def defender(self):
            f = self.current
            if not f or not f.path:
                return
            self.b_def.configure(state="disabled")
            self.status.configure(text="Microsoft Defender is scanning the file (no action will be taken)...")
            threading.Thread(target=lambda: self.q.put(("defender", defender_scan_file(f.path))), daemon=True).start()

        def copy_details(self):
            f = self.current
            if not f:
                return
            lines = [f.title, "Severity: %s | Category: %s" % (f.severity, f.category), "Location: " + f.location]
            if f.sha256:
                lines.append("SHA-256: " + f.sha256)
            lines += ["%s: %s" % kv for kv in f.details.items() if kv[1] not in ("", None)]
            lines += ["", "Why: " + f.why, "", "How to remove:"] + ["%d. %s" % (i, s) for i, s in enumerate(f.remove, 1)]
            self.clipboard_clear()
            self.clipboard_append("\n".join(lines))
            self.status.configure(text="Details copied to clipboard.")

        def export(self):
            if not self.findings or not self.scanner:
                messagebox.showinfo(APP_NAME, "Run a check first.")
                return
            p = filedialog.asksaveasfilename(defaultextension=".html", initialfile="SafeCheck-report.html",
                                             filetypes=[("HTML report", "*.html"), ("JSON", "*.json")])
            if not p:
                return
            try:
                with open(p, "w", encoding="utf-8") as fh:
                    if p.lower().endswith(".json"):
                        json.dump({"meta": meta_info(self.scanner), "findings": [asdict(f) for f in self.findings]},
                                  fh, indent=2, default=str)
                    else:
                        fh.write(report_html(self.findings, meta_info(self.scanner)))
                self.status.configure(text="Report saved: " + p)
            except OSError as e:
                messagebox.showerror(APP_NAME, "Could not save the report: %s" % e)

    App().mainloop()


# --------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------
def run_cli(argv):
    import argparse
    ap = argparse.ArgumentParser(description="%s (read-only)" % APP_NAME)
    ap.add_argument("--cli", action="store_true")
    ap.add_argument("--folder", help="scan only this folder")
    ap.add_argument("--file", help="check only this file")
    ap.add_argument("--html", help="also write an HTML report to this path")
    ap.add_argument("--demo", action="store_true", help="print sample (fake) results")
    a = ap.parse_args(argv)
    sc = Scanner(progress=lambda m: print("..", m, file=sys.stderr))
    if a.demo:
        sc.findings = demo_findings()
    elif a.file:
        sc.scan_single_file(a.file)
        sc.finish()
    elif a.folder:
        sc.scan_folders([(a.folder, "custom")])
        sc.finish()
    else:
        sc.run_full()
    out = {"meta": meta_info(sc), "counts": counts(sc.findings), "errors": sc.errors,
           "findings": [asdict(f) for f in sc.findings]}
    print(json.dumps(out, indent=2, default=str))
    if a.html:
        with open(a.html, "w", encoding="utf-8") as fh:
            fh.write(report_html(sc.findings, meta_info(sc)))


def main():
    if "--version" in sys.argv:
        print(APP_NAME, APP_VERSION)
        return
    if "--cli" in sys.argv:
        run_cli([x for x in sys.argv[1:]])
        return
    run_gui()


if __name__ == "__main__":
    main()
