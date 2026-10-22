#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SUTRA-Trace  ·  Sector E  ·  Interactive Forensic Cyber Cockpit & Prototype Runtime
====================================================================================

SUTRAM 2026 (IGDTUW · MeitY ISEA Phase-III · NFSU Gandhinagar), PS-01.

Sector E runs the real Sector A -> B -> C -> D pipeline from the sibling files in this
folder and shows what it produced in one offline, single-page cockpit:

    Sector A  sector_a_vault.py    evidence vault: SHA-256, BLAKE2b, RFC 6962 Merkle, s.105 BNSS
                                   seizure recording + 50 Hz ENF continuity, s.106 BNSS seal chain
    Sector B  sector_b_triage.py   LOLBins, rPPG pulse-transit deepfake screen, WebRTC srflx,
                                   UPI fan-out smurfing, mirror-hawala note serials, s.45 checklist
    Sector C  sector_c_graph.py    32-byte CSR temporal provenance graph, anti-timestomping,
                                   prize-collecting Steiner storyline with byte anchors
    Sector D  sector_d_legal.py    s.63 BSA certificate PDF, FIU-IND STR XML, s.106/107 BNSS
                                   freeze notice, verification QR

Two exhibits of FIR-042/2026-CYBER are processed on every run:

    HANDSET  Sector B's synthetic seized-handset bundle, vaulted by A (with a s.105 BNSS seizure
             recording and s.106 seals), triaged by B, graphed by C and certified by D.
    PC       Sector C's synthetic victim-PC evidence set (WhatsApp Desktop log, Sysmon export,
             NTFS image with a timestomped dropper, packet capture, bank statement, NPCI switch
             log); the disk image is vaulted by A and the six sources are graphed by C.

Nothing shown is typed into this file: every number, hash, offset and verdict on the page is
read from the outputs of Sectors A-D for the current run, and every byte anchor is re-read and
re-hashed from the evidence (with an RFC 6962 inclusion proof when the file is the vaulted image).

Modes
-----
    python sector_e_dashboard.py                    headless self-test (39 checks), exit 0 on pass
    python sector_e_dashboard.py --serve            cockpit on http://127.0.0.1:5000 (opens browser)
    python sector_e_dashboard.py --port 8080        same, other port (implies --serve)
    options: --host, --no-browser, --workdir DIR, --backend auto|flask|stdlib, --keep

Dependencies: Python 3.10+ standard library. Flask is used when installed (--backend auto);
otherwise the same routes are served by http.server. The page loads nothing from the network.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import hashlib
import importlib.util
import io
import json
import os
import re
import secrets
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import traceback
import webbrowser
import xml.etree.ElementTree as ET
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlsplit

try:  # Windows consoles default to a legacy code page; never crash on a "·" or "₹".
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    pass

try:  # optional web framework
    import flask as _flask  # type: ignore
except Exception:  # pragma: no cover - Flask is optional
    _flask = None


# --------------------------------------------------------------------------- #
# Sibling sectors (loaded by path from this folder, never an older copy)      #
# --------------------------------------------------------------------------- #

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_sibling(module_name: str, filename: str):
    """Import prototype/<filename> from this folder, not an older copy elsewhere on sys.path."""
    path = os.path.join(HERE, filename)
    mod = sys.modules.get(module_name)
    if mod is not None and os.path.abspath(getattr(mod, "__file__", "") or "") == path:
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
    except Exception:  # pragma: no cover - sibling broken
        traceback.print_exc()
        return None


# Order matters: B, C and D each load A (and C/D load B, C) by the same rule.
_sector_a = _load_sibling("sector_a_vault", "sector_a_vault.py")
_sector_b = _load_sibling("sector_b_triage", "sector_b_triage.py")
_sector_c = _load_sibling("sector_c_graph", "sector_c_graph.py")
_sector_d = _load_sibling("sector_d_legal", "sector_d_legal.py")

SECTOR_FILES = (("A", "sector_a_vault.py", _sector_a), ("B", "sector_b_triage.py", _sector_b),
                ("C", "sector_c_graph.py", _sector_c), ("D", "sector_d_legal.py", _sector_d))


# --------------------------------------------------------------------------- #
# Constants                                                                   #
# --------------------------------------------------------------------------- #

COCKPIT_VERSION = "SUTRA-COCKPIT-2026.3-SUPREME"
COCKPIT_REVISION = "r5"
CASE_ID = "FIR-042/2026-CYBER"
CASE_TITLE = "Operation Maya"
EXAMINER_ID = "EX-79A-NFSU"
DEFAULT_PORT = 5000
PIPELINE_BUDGET_S = 5.0            # manual item 1
DEMO_TARGET_S = 2.0                # the "golden benchmark" the cockpit reports against
ENTROPY_THRESHOLD = getattr(getattr(_sector_b, "LogTriageEngine", None), "ENTROPY_THRESHOLD", 4.8)
PTT_WINDOW_MS = (12.0, 45.0)        # physiological carotid-to-supraorbital transit window
LBA_BYTES = 512                     # legacy disk sector, as the inspector reports it
A_SECTOR_BYTES = getattr(getattr(_sector_a, "SutraEvidenceVault", None), "SECTOR_SIZE", 4096)
A_SUB_BLOCK = getattr(getattr(_sector_a, "SutraEvidenceVault", None), "SUB_CHUNK_SIZE", 1024)
MAX_ANCHOR_READ = 1 << 20           # never read more than 1 MiB into memory for one anchor (hashing streams)
# Every 1 KB sub-block of an anchor up to MAX_ANCHOR_READ is proved (an unaligned 1 MiB range touches 1025).
# Larger anchors are re-hashed in full, but only the first and last sub-block of each 4 MB chunk is proved,
# and the result is labelled INCLUSION_SAMPLED, never INCLUSION_VERIFIED.
MAX_PROOFS_PER_ANCHOR = MAX_ANCHOR_READ // A_SUB_BLOCK + 1
ANCHOR_HEAD_BYTES = 256             # bytes kept for the hexdump / text preview of an anchor
MAX_BODY_BYTES = 64 * 1024          # request bodies above this are refused (413) on both web engines
HANDLER_TIMEOUT_S = 15              # stdlib server: socket timeout per connection (slow-client guard)
MAX_HANDLER_THREADS = 32            # stdlib server: connections served at once; extra ones are closed
EXPECTED_CHECKS = 40
LEGAL_BLOBS = ("certificate_pdf", "str_xml", "freeze_notice_json", "qr_png")
KEEP_RUNS = 2

EXHIBITS = {
    "PC": {"title": "Victim PC, network and bank records",
           "short": "Victim PC",
           "sources": "WhatsApp Desktop log · Sysmon export · NTFS image ($MFT, $UsnJrnl) · PCAP · "
                      "bank statement · NPCI switch log"},
    "HANDSET": {"title": "Seized Android handset bundle",
                "short": "Seized handset",
                "sources": "Sector B case bundle (Sysmon JSONL, WhatsApp log, rPPG trace, registry, AnyDesk, "
                           "UPI CSV, chain CSV, chat, bugreport, APK) imaged as one file"},
}

STATUTES = {
    "s63": "Section 63 BSA 2023",
    "s45": "Section 45 BSA 2023",
    "s105": "Section 105 BNSS",
    "s106": "Section 106 BNSS",
    "s94": "Section 94 BNSS",
}

HEX = re.compile(r"^[0-9a-f]+$")


class CockpitError(RuntimeError):
    """A sector is missing or its output failed validation."""


# --------------------------------------------------------------------------- #
# Small helpers                                                               #
# --------------------------------------------------------------------------- #

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _ns_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z"


def _is_hex(v: Any, n: Optional[int] = None) -> bool:
    return isinstance(v, str) and bool(HEX.match(v)) and (n is None or len(v) == n)


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, indent=1, sort_keys=False, allow_nan=False).encode("utf-8")


def _forbidden_patterns() -> List["re.Pattern[str]"]:
    """The repealed provision and its statute, built from fragments so this file never spells them out."""
    fn = getattr(_sector_d, "_forbidden_patterns", None)
    if callable(fn):
        return fn()
    sec = "6" + "5"
    return [re.compile(r"(?<![0-9a-fA-F])" + sec + r"\s*-?\s*B(?![0-9a-zA-Z])"),
            re.compile("Indian" + r"\s+" + "Evidence" + r"\s+" + "Act", re.IGNORECASE),
            re.compile(r"\bI\.?\s?E\.?\s?A\.?\s*,?\s*18" + "72")]


def _hexdump(data: bytes, base: int, width: int = 16) -> List[str]:
    rows = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"{base + i:08x}  {hx:<{width * 3 - 1}}  {asc}")
    return rows


def _text_preview(data: Optional[bytes], limit: int = 240) -> Optional[str]:
    """The record as text when it is text (WhatsApp lines, CSV rows, JSON events); None for binary records."""
    if not data:
        return None
    head = data[:limit]
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13) or b >= 0x80)
    if printable < 0.9 * len(head):
        return None
    return head.decode("utf-8", "replace")


def _read_range(path: str, offset: int, length: int) -> Optional[bytes]:
    if not path or not os.path.isfile(path) or offset < 0 or length < 0 or length > MAX_ANCHOR_READ:
        return None
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read(length)
    return data if len(data) == length else None


def _hash_range(path: Optional[str], offset: int, length: int) -> Optional[Tuple[str, bytes]]:
    """SHA-256 of [offset, offset+length) streamed from disk, plus the first bytes for display; None if unreadable."""
    if not path or not os.path.isfile(path) or offset < 0 or length < 0:
        return None
    try:
        if offset + length > os.path.getsize(path):
            return None
        h, head, left = hashlib.sha256(), b"", length
        with open(path, "rb") as f:
            f.seek(offset)
            while left:
                blk = f.read(min(1 << 20, left))
                if not blk:
                    return None
                if len(head) < ANCHOR_HEAD_BYTES:
                    head += blk[:ANCHOR_HEAD_BYTES - len(head)]
                h.update(blk)
                left -= len(blk)
        return h.hexdigest(), head
    except OSError:
        return None


def _encoded_token(cmdline: str) -> Optional[str]:
    """The Base64 argument of a PowerShell -enc/-EncodedCommand switch, using Sector B's own pattern."""
    rx = getattr(_sector_b, "_ENC_ARG", None)
    m = rx.search(cmdline) if rx is not None else None
    return m.group(1) if m else None


def _entropy(s: str) -> float:
    fn = getattr(_sector_b, "shannon_entropy", None)
    if callable(fn):
        return float(fn(s))
    import math
    from collections import Counter
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values()) if n else 0.0


def _modules_report() -> List[Dict[str, Any]]:
    rows = []
    for sec, fname, mod in SECTOR_FILES:
        path = os.path.join(HERE, fname)
        version = None
        if mod is not None:
            version = " ".join(str(x) for x in (
                getattr(mod, "VAULT_VERSION", None) or getattr(mod, "TRIAGE_VERSION", None)
                or getattr(mod, "GRAPH_VERSION", None) or getattr(mod, "LEGAL_VERSION", None),
                getattr(mod, "TRIAGE_REVISION", None) or getattr(mod, "GRAPH_REVISION", None)
                or getattr(mod, "LEGAL_REVISION", None)) if x)
        rows.append({"sector": sec, "file": f"prototype/{fname}", "loaded": mod is not None, "version": version,
                     "bytes": os.path.getsize(path) if os.path.isfile(path) else None,
                     "sha256": _file_sha256(path) if os.path.isfile(path) else None})
    return rows


# --------------------------------------------------------------------------- #
# Physical Offset Inspector                                                   #
# --------------------------------------------------------------------------- #

class AnchorInspector:
    """
    Re-reads every byte anchor (file, Omega, length) from the evidence, re-hashes it, and, when the
    file is the image Sector A vaulted, proves each 1 KB sub-block it touches against the Sector A
    RFC 6962 Merkle root the way Sector A's own prove_sub_block() does (with Sector A's Merkle helpers and
    verifier, reading each 4 MB chunk once per anchor).

    Two modes:
      inspect(prov)       run snapshot, taken once when the pipeline finishes; memoised, and served in
                          /api/triage and /api/graph with mode "RUN_SNAPSHOT" and the time it was taken.
      inspect_live(id)    re-reads the bytes and rebuilds every Merkle proof from the file on disk now,
                          with no memoisation; served by /api/verify_anchor with mode "LIVE".
    Live checks accept only anchors this run recorded (by anchor_id), so the recorded digest they compare
    against always comes from Sectors B/C, never from the browser.
    """

    def __init__(self, exhibit: str, roots: Dict[str, str], vaults: Dict[str, Tuple[Any, Dict[str, Any], str]]):
        self.exhibit = exhibit
        self.roots = dict(roots)          # displayed file name -> path on disk
        self.vaults = dict(vaults)        # displayed file name -> (vault, manifest, path)
        self._proofs: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self._seen: Dict[Tuple[str, int, int, str], Dict[str, Any]] = {}
        self._index: Dict[str, Dict[str, Any]] = {}     # anchor_id -> provenance as recorded by Sector B/C
        self._live_lock = threading.Lock()              # one live re-verification at a time per exhibit

    @staticmethod
    def anchor_id(fname: str, off: int, ln: int, rec: Any) -> str:
        return _sha256_hex(f"{fname}|{off}|{ln}|{rec}".encode("utf-8"))[:24]

    @staticmethod
    def _parse(prov: Any) -> Tuple[Optional[Tuple[str, int, int, Any]], Optional[Dict[str, Any]]]:
        if not isinstance(prov, dict):
            return None, {"status": "NO_ANCHOR"}
        fname = str(prov.get("source_file") or prov.get("file_path") or "")
        try:
            off, ln = int(prov.get("byte_offset")), int(prov.get("length"))
        except (TypeError, ValueError):
            return None, {"status": "NO_ANCHOR", "source_file": fname}
        return (fname, off, ln, prov.get("sha256")), None

    def _proof(self, fname: str, idx: int, cache: bool = True) -> Dict[str, Any]:
        key = (fname, idx)
        if cache and key in self._proofs:
            return self._proofs[key]
        vault, manifest, path = self.vaults[fname]
        try:
            p = vault.prove_sub_block(path, manifest, idx)
        except Exception as e:  # a proof that cannot be built is a failed proof
            p = {"sub_block_index": idx, "verified": False, "error": f"{type(e).__name__}: {e}"}
        if not isinstance(p, dict):
            p = {"sub_block_index": idx, "verified": False, "error": "prove_sub_block returned no proof"}
        if cache:
            self._proofs[key] = p
        return p

    def _proofs_for(self, fname: str, idxs: Sequence[int], cache: bool = True) -> List[Dict[str, Any]]:
        """
        prove_sub_block() for many sub-blocks at once: each 4 MB chunk is read through Sector A's write
        blocker and hashed once, then every needed audit path is taken from that one tree (overnight audit
        E-02: one chunk read per sub-block made a 1 MiB anchor cost ~1024 chunk reads). The proofs are the
        ones Sector A's prove_sub_block() builds, from Sector A's own Merkle helpers and verifier; when any
        helper is missing this falls back to prove_sub_block() per sub-block.
        """
        out: Dict[int, Dict[str, Any]] = {}
        todo = []
        for i in idxs:
            if cache and (fname, i) in self._proofs:
                out[i] = self._proofs[(fname, i)]
            else:
                todo.append(i)
        vault, manifest, path = self.vaults[fname]
        sa = _sector_a
        helpers = [getattr(sa, n, None) for n in ("_merkle_levels", "_proof_from_levels", "verify_merkle_proof",
                                                  "_get_fd_size")]
        batch = (len(todo) > 1 and all(helpers) and all(hasattr(vault, n) for n in (
            "_read_chunk", "_sub_block_leaves", "write_blocker", "CHUNK_SIZE", "SUB_CHUNK_SIZE")))
        if not batch:
            for i in todo:
                out[i] = self._proof(fname, i, cache=cache)
            return [out[i] for i in idxs]
        levels_of, proof_from, verify, fd_size = helpers
        per_chunk = vault.CHUNK_SIZE // vault.SUB_CHUNK_SIZE
        by_chunk: Dict[int, List[int]] = {}
        for i in todo:
            by_chunk.setdefault(i // per_chunk, []).append(i)
        for ci, members in by_chunk.items():
            try:
                bad = set(manifest["bad_sector_manifest"]["bad_sectors"])
                fd = vault.write_blocker.open_read_only(path)
                try:
                    data, _, _ = vault._read_chunk(fd, ci, bad, fd_size(fd))
                finally:
                    os.close(fd)
                leaves = vault._sub_block_leaves(data)
                root = manifest["cryptographic_hashes"]["sha256_merkle_root_4mb"]
                top = proof_from(levels_of([bytes.fromhex(h) for h in manifest["merkle_tree"]["chunk_roots"]]), ci)
                local_levels = levels_of(leaves)
            except Exception as e:  # a chunk that cannot be read or hashed fails every proof in it
                for i in members:
                    out[i] = {"sub_block_index": i, "verified": False, "error": f"{type(e).__name__}: {e}"}
                continue
            for i in members:
                local = i - ci * per_chunk
                if local >= len(leaves):
                    p: Dict[str, Any] = {"sub_block_index": i, "verified": False,
                                         "error": "IndexError: sub-block index beyond end of evidence"}
                else:
                    proof = proof_from(local_levels, local) + top
                    leaf_hash = leaves[local].hex()
                    p = {"sub_block_index": i, "byte_offset": i * vault.SUB_CHUNK_SIZE, "chunk_index": ci,
                         "leaf_hash": leaf_hash, "proof": proof, "root": root,
                         "verified": verify(leaf_hash, proof, root)}
                out[i] = p
        if cache:
            for i in todo:
                self._proofs[(fname, i)] = out[i]
        return [out[i] for i in idxs]

    def inspect(self, prov: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Run snapshot (memoised). Registers the anchor so it can be re-verified live later."""
        parsed, none = self._parse(prov)
        if parsed is None:
            return none  # type: ignore[return-value]
        fname, off, ln, rec = parsed
        key = (fname, off, ln, str(rec))
        if key in self._seen:
            return self._seen[key]
        out = self._evaluate(prov, fname, off, ln, rec, live=False)  # type: ignore[arg-type]
        self._index[out["anchor_id"]] = dict(prov)  # type: ignore[arg-type]
        self._seen[key] = out
        return out

    def inspect_live(self, aid: str) -> Optional[Dict[str, Any]]:
        """Re-read and re-prove a recorded anchor from the disk now; None when the id is not in this run."""
        prov = self._index.get(aid)
        if prov is None:
            return None
        parsed, _ = self._parse(prov)
        fname, off, ln, rec = parsed  # type: ignore[misc]
        with self._live_lock:
            # Sector A's write blocker logs every read-only open; a live re-check must not grow that log
            # for as long as the cockpit runs (overnight audit E-03), so it is put back as it was.
            vault = self.vaults.get(fname, (None,))[0]
            log = getattr(getattr(vault, "write_blocker", None), "log", None)
            n = len(log) if isinstance(log, list) else None
            try:
                return self._evaluate(prov, fname, off, ln, rec, live=True)
            finally:
                if n is not None:
                    del log[n:]  # type: ignore[index]

    def _evaluate(self, prov: Dict[str, Any], fname: str, off: int, ln: int, rec: Any, live: bool) -> Dict[str, Any]:
        path = self.roots.get(fname)
        got = _hash_range(path, off, ln) if path else None
        now, head = got if got is not None else (None, None)
        out: Dict[str, Any] = {
            "exhibit": self.exhibit, "anchor_id": self.anchor_id(fname, off, ln, rec),
            "mode": "LIVE" if live else "RUN_SNAPSHOT", "verified_at_utc": _utc_now(),
            "source_file": fname, "source_type": prov.get("source_type"),
            "offset_basis": prov.get("offset_basis", "ABSOLUTE_IN_FILE"),
            "byte_offset": off, "byte_offset_hex": f"0x{off:X}", "length": ln,
            "end_offset_hex": f"0x{off + max(ln, 1) - 1:X}",
            "sector_512": off // LBA_BYTES, "sector_512_last": (off + max(ln, 1) - 1) // LBA_BYTES,
            "sector_4096": off // A_SECTOR_BYTES, "sub_block_1k": off // A_SUB_BLOCK,
            "sha256_recorded": rec, "sha256_now": now,
            "rehash": "MATCH" if now is not None and now == rec else ("MISMATCH" if now else "UNREADABLE"),
            "reverified_by_sector_c": prov.get("anchor_reverified"),
            "hexdump": _hexdump(head[:64], off) if head else [],
            "text_preview": _text_preview(head),
        }
        if fname in self.vaults and now is not None:
            out["merkle"] = self._merkle(fname, off, ln, cache=not live)
        elif fname in self.vaults:   # the vaulted image itself is missing, unreadable or shorter than the anchor
            manifest = self.vaults[fname][1]
            first, last = off // A_SUB_BLOCK, (off + max(ln, 1) - 1) // A_SUB_BLOCK
            out["merkle"] = {"status": "NOT_EVALUATED",
                             "note": "The image Sector A vaulted for this exhibit could not be read over this "
                                     "anchor (missing, unreadable or shorter than the anchor), so no inclusion "
                                     "proof was attempted.",
                             "root": (manifest.get("cryptographic_hashes") or {}).get("sha256_merkle_root_4mb"),
                             "evidence_id": manifest.get("evidence_id"), "sub_blocks": [first, last],
                             "needed": last - first + 1, "checked": 0, "proved": 0, "sampled": False,
                             "chunks_spanned": [], "failed_sub_blocks": []}
        else:
            out["merkle"] = {"status": "NOT_IN_VAULTED_IMAGE",
                             "note": "This source file is not the image Sector A vaulted for this exhibit; the "
                                     "record digest above is re-hashed from the file itself."}
        ms = out["merkle"]["status"]
        if out["rehash"] != "MATCH" or ms == "PROOF_FAILED":
            out["status"] = "FAILED"
        elif ms == "INCLUSION_SAMPLED":
            out["status"] = "VERIFIED_MERKLE_SAMPLED"
        else:
            out["status"] = "VERIFIED"
        return out

    def _merkle(self, fname: str, off: int, ln: int, cache: bool) -> Dict[str, Any]:
        _, manifest, _ = self.vaults[fname]
        first, last = off // A_SUB_BLOCK, (off + max(ln, 1) - 1) // A_SUB_BLOCK
        needed = last - first + 1
        sampled = needed > MAX_PROOFS_PER_ANCHOR
        if not sampled:
            idxs = list(range(first, last + 1))
        else:  # first and last sub-block of every 4 MB chunk the anchor spans
            chunk = int((manifest.get("merkle_tree") or {}).get("chunk_size_bytes") or (4 << 20))
            per = max(1, chunk // A_SUB_BLOCK)
            pick = {first, last}
            for c in range(first // per, last // per + 1):
                pick.add(max(first, c * per))
                pick.add(min(last, (c + 1) * per - 1))
            idxs = sorted(pick)
        proofs = list(zip(idxs, self._proofs_for(fname, idxs, cache=cache)))
        proved = sum(1 for _, p in proofs if p.get("verified"))
        all_ok = proved == len(proofs)
        groups: Dict[Any, List[Tuple[int, Dict[str, Any]]]] = {}
        for i, p in proofs:
            groups.setdefault(p.get("chunk_index"), []).append((i, p))
        chunks = []
        for c, items in groups.items():
            (i0, p0), (i1, p1) = items[0], items[-1]
            chunks.append({"chunk_index": c, "first_sub_block": i0, "last_sub_block": i1,
                           "proved": sum(1 for _, p in items if p.get("verified")), "checked": len(items),
                           "first_leaf_hash": p0.get("leaf_hash"), "first_audit_path": p0.get("proof", []),
                           "last_leaf_hash": p1.get("leaf_hash"), "last_audit_path": p1.get("proof", [])})
        p0 = proofs[0][1]
        return {
            "status": "PROOF_FAILED" if not all_ok else ("INCLUSION_SAMPLED" if sampled else "INCLUSION_VERIFIED"),
            "root": manifest["cryptographic_hashes"]["sha256_merkle_root_4mb"],
            "evidence_id": manifest.get("evidence_id"),
            "sub_blocks": [first, last], "needed": needed, "checked": len(proofs), "proved": proved,
            "sampled": sampled, "chunks_spanned": chunks,
            "failed_sub_blocks": [i for i, p in proofs if not p.get("verified")][:16],
            "first_leaf_hash": p0.get("leaf_hash"), "first_chunk_index": p0.get("chunk_index"),
            "first_audit_path": p0.get("proof", []),
        }


# --------------------------------------------------------------------------- #
# Pipeline: Sectors A -> B -> C -> D on both exhibits                         #
# --------------------------------------------------------------------------- #

_BUNDLE_KINDS = {"events": ("process_events_jsonl", "SYSMON_EVENT_LOG_JSONL"),
                 "whatsapp": ("whatsapp_log", "ANDROID_WHATSAPP_LOG"),
                 "rppg": ("rppg_trace", "VIDEO_CALL_ROI_TRACE"),
                 "registry": ("registry_export", "WINDOWS_REGISTRY_EXPORT"),
                 "anydesk": ("anydesk_trace", "ANYDESK_CONNECTION_TRACE"),
                 "upi": ("upi_csv", "UPI_TRANSACTION_EXPORT"),
                 "chain": ("chain_csv", "BLOCKCHAIN_TRANSFER_EXPORT"),
                 "chat": ("chat_transcript", "CHAT_TRANSCRIPT_TEXT"),
                 "bugreport": ("bugreport", "ANDROID_BUGREPORT"),
                 "apk": ("apk", "ANDROID_APK_FILE"),
                 "frame": ("image_pgm", "VIDEO_FRAME_PGM")}


def _require_sectors() -> None:
    missing = [f for s, f, m in SECTOR_FILES if m is None]
    if missing:
        raise CockpitError("missing or broken sibling module(s) in " + HERE + ": " + ", ".join(missing))


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_pipeline(base_dir: str, run_no: int) -> Dict[str, Any]:
    """Execute the full pipeline into base_dir/run_NNNN and return the run record (views included)."""
    _require_sectors()
    sa, sb, sc, sd = _sector_a, _sector_b, _sector_c, _sector_d
    wd = os.path.join(base_dir, f"run_{run_no:04d}")
    shutil.rmtree(wd, ignore_errors=True)
    os.makedirs(wd)
    timings: Dict[str, float] = {}
    started = _utc_now()
    t_all = time.perf_counter()

    def lap(name: str, t: float) -> float:
        now = time.perf_counter()
        timings[name] = round((now - t) * 1000.0, 1)
        return now

    # ---- Exhibit HANDSET: A -> B -> C -> D -------------------------------- #
    hd = os.path.join(wd, "handset")
    os.makedirs(hd)
    t = time.perf_counter()
    bundle = sb._build_case_bundle()
    layout, blob = {}, bytearray()
    for name, data in bundle.items():
        pos = (len(blob) + 4095) // 4096 * 4096
        blob.extend(bytes(pos - len(blob)))
        layout[name] = (pos, len(data))
        blob.extend(data)
    blob.extend(bytes((-len(blob)) % 4096))
    image = os.path.join(hd, "case_bundle.img")
    with open(image, "wb") as f:
        f.write(blob)
    video = os.path.join(hd, "seizure_recording_sec105.mp4")
    sa._write_synthetic_mp4(video)
    vault_h = sa.SutraEvidenceVault(
        case_id=CASE_ID, examiner_id=EXAMINER_ID, output_dir=os.path.join(hd, "sector_a"),
        hardware_telemetry={"make_model": "Android handset (Sector B synthetic case bundle)",
                            "serial_number": "R58N91XXXXX", "firmware_rev": "UP1A.231005"})
    vault_h.set_custody_seals("OPT-PUF-7Q2X-91A0", -112, "MK-CY-2026/089", "2026-10-18T09:30:00.000Z",
                              "OPT-PUF-7Q2X-91A0")
    vault_h.ingest_evidence(image, seizure_video_path=video)
    a_path = os.path.join(hd, "sector_a", sa.MANIFEST_FILENAME)
    a_doc = _load_json(a_path)
    t = lap("A_vault_handset", t)

    orch = sb.SutraNeuralTriageOrchestrator(CASE_ID, output_dir=hd, device_owner="rahul")
    orch.bind_sector_a_manifest(a_path)
    for name, (kind, stype) in _BUNDLE_KINDS.items():
        if name in layout:
            off, ln = layout[name]
            orch.add_artifact(name, kind, stype, path=image, base_offset=off, length=ln, extent=True,
                              display_path="case_bundle.img")
    orch.run(triage_time_utc=_utc_now())
    b_path = os.path.join(hd, sb.MANIFEST_FILENAME)
    b_doc = _load_json(b_path)
    t = lap("B_triage_handset", t)

    g = sc.TemporalProvenanceGraph(case_id=CASE_ID, capacity=200_000, output_dir=os.path.join(hd, "sector_c"),
                                   evidence_root=hd, verify_anchors=True)
    try:
        g.ingest_evidence_manifest(a_path)
        g.ingest_triage_manifest(b_doc)
        g.check_causality()
        c_utc = _ns_utc()
        graph_h = g.export_attack_graph(c_utc)
        story_h = g.export_storyline(c_utc)
    finally:
        g.close()
    t = lap("C_graph_handset", t)

    legal_dir = os.path.join(wd, "legal")
    gen = sd.BSACertificateGenerator(
        evidence_manifest=a_doc, triage_manifest=b_doc, storyline=story_h,
        scenario=sd.ScenarioType.SUSPECT_HOSTILE, evidence_path=image, seizure_video_path=video, evidence_root=hd,
        custodian=dict(sd._DEMO_PARTIES[sd.ScenarioType.SUSPECT_HOSTILE.value]), expert=dict(sd._DEMO_EXPERT),
        case_particulars=dict(sd._DEMO_CASE), generated_utc=_utc_now())
    legal_paths = gen.export_legal_bundle(legal_dir)
    verification = gen.verify()
    # Downloads are served from these in-memory copies, so pruning old run folders can never race a
    # download, and no file is re-read or re-hashed per request.
    blobs: Dict[str, Tuple[bytes, str]] = {}
    for key in LEGAL_BLOBS:
        body = _read_bytes(legal_paths[key])
        blobs[key] = (body, _sha256_hex(body))
    t = lap("D_legal_handset", t)

    # ---- Exhibit PC: A (disk image) + C (six sources) ---------------------- #
    pd = os.path.join(wd, "pc")
    expected = sc._write_digital_arrest_case(pd)
    disk = os.path.join(pd, "victim_disk.img")
    vault_p = sa.SutraEvidenceVault(
        case_id=CASE_ID, examiner_id=EXAMINER_ID, output_dir=os.path.join(pd, "sector_a"),
        hardware_telemetry={"make_model": "Windows workstation VICTIM-PC system disk (Sector C synthetic case)",
                            "serial_number": "WD-SN-DEMO-0042", "firmware_rev": "NTFS 3.1"})
    vault_p.ingest_evidence(disk)
    pa_path = os.path.join(pd, "sector_a", sa.MANIFEST_FILENAME)
    pa_doc = _load_json(pa_path)
    t = lap("A_vault_pc", t)

    pg = sc.TemporalProvenanceGraph(case_id=CASE_ID, capacity=200_000, output_dir=os.path.join(pd, "sector_c"),
                                    evidence_root=pd, verify_anchors=True)
    try:
        pg.ingest_evidence_manifest(pa_path)
        sc._ingest_digital_arrest(pg, pd, expected)
        pg.check_causality()
        c_utc = _ns_utc()
        graph_p = pg.export_attack_graph(c_utc)
        story_p = pg.export_storyline(c_utc)
    finally:
        pg.close()
    t = lap("C_graph_pc", t)
    pipeline_ms = round((time.perf_counter() - t_all) * 1000.0, 1)

    run: Dict[str, Any] = {
        "run_id": run_no, "workdir": wd, "started_utc": started,
        "handset": {"dir": hd, "image": image, "video": video, "a": a_doc, "a_path": a_path, "b": b_doc,
                    "b_path": b_path, "graph": graph_h, "story": story_h, "vault": vault_h, "layout": layout},
        "pc": {"dir": pd, "image": disk, "a": pa_doc, "a_path": pa_path, "graph": graph_p, "story": story_p,
               "vault": vault_p, "expected": {k: v for k, v in expected.items() if isinstance(v, tuple)}},
        "legal": {"gen": gen, "paths": legal_paths, "verification": verification, "blobs": blobs},
    }
    # Schema gates from the sectors themselves, before anything is shown.
    run["schema"] = {
        "sector_b_triage_manifest": list(sb.validate_manifest(b_doc)) if hasattr(sb, "validate_manifest") else [],
        "sector_c_attack_graph_handset": list(sc.validate_attack_graph(graph_h)),
        "sector_c_storyline_handset": list(sc.validate_storyline(story_h)),
        "sector_c_attack_graph_pc": list(sc.validate_attack_graph(graph_p)),
        "sector_c_storyline_pc": list(sc.validate_storyline(story_p)),
        "sector_d_str_xml": list(sd.validate_str_xml(_read_text(legal_paths["str_xml"]))),
    }
    t = time.perf_counter()
    run["inspectors"] = {
        "HANDSET": AnchorInspector("HANDSET", {"case_bundle.img": image, os.path.basename(video): video},
                                   {"case_bundle.img": (vault_h, a_doc, image)}),
        "PC": AnchorInspector("PC", {n: os.path.join(pd, n) for n in os.listdir(pd) if os.path.isfile(os.path.join(pd, n))},
                              {"victim_disk.img": (vault_p, pa_doc, disk)}),
    }
    run["views"] = build_views(run)
    lap("E_views_and_proofs", t)
    timings["pipeline_total"] = pipeline_ms
    timings["total_with_views"] = round((time.perf_counter() - t_all) * 1000.0, 1)
    run["timings_ms"] = timings
    run["finished_utc"] = _utc_now()
    run["views"]["status"].update(_status_timing(run))
    return run


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# --------------------------------------------------------------------------- #
# Views (what the API routes serve)                                           #
# --------------------------------------------------------------------------- #

def build_views(run: Dict[str, Any]) -> Dict[str, Any]:
    return {"status": status_view(run), "vault": vault_view(run), "triage": triage_view(run),
            "graph": graph_view(run), "exculpatory": exculpatory_view(run)}


def _status_timing(run: Dict[str, Any]) -> Dict[str, Any]:
    tm = run["timings_ms"]
    s = tm["pipeline_total"] / 1000.0
    return {"run_started_utc": run["started_utc"], "run_finished_utc": run["finished_utc"], "timings_ms": tm,
            "pipeline_seconds": round(s, 3), "pipeline_budget_seconds": PIPELINE_BUDGET_S,
            "within_budget": s < PIPELINE_BUDGET_S, "demo_target_seconds": DEMO_TARGET_S,
            "within_demo_target": s <= DEMO_TARGET_S}


def status_view(run: Dict[str, Any]) -> Dict[str, Any]:
    a = run["handset"]["a"]
    gen = run["legal"]["gen"]
    ver = run["legal"]["verification"]
    paths = run["legal"]["paths"]
    bundle = _load_json(paths["bundle_manifest"])
    notice = _load_json(paths["freeze_notice_json"])
    return {
        "product": "SUTRA-Trace", "cockpit": f"{COCKPIT_VERSION} {COCKPIT_REVISION}",
        "case_reference": a.get("case_reference"), "case_title": CASE_TITLE,
        "examiner_id": a.get("examiner_id"), "workstation": a.get("ingestion_workstation"),
        "run_id": run["run_id"], "health": "OK" if not any(run["schema"].values()) else "SCHEMA_ERRORS",
        "schema_validation": run["schema"],
        "readiness": ver["status"], "readiness_blocking": ver["blocking"], "readiness_notes": ver["notes"],
        "sector_a_admissibility": {"HANDSET": a["admissibility"]["status"],
                                   "PC": run["pc"]["a"]["admissibility"]["status"]},
        "exhibits": {k: dict(v, evidence_id=run[k.lower()]["a"]["evidence_id"],
                             filename=run[k.lower()]["a"]["evidence_media"]["filename"],
                             storyline_steps=len(run[k.lower()]["story"]["steps"]),
                             graph_edges=run[k.lower()]["graph"]["statistics"]["edges_exported"])
                     for k, v in EXHIBITS.items()},
        "legal": {
            "certificate_sha256": gen.certificate_digest(), "qr_payload": gen.generate_qr_payload(),
            "pdf_engine": bundle.get("pdf_engine"), "qr_engine": bundle.get("qr_engine"),
            "track": bundle.get("track"), "scenario": bundle.get("scenario"),
            "files": bundle.get("files"), "bundle_sha256": bundle.get("bundle_sha256"),
            "anchors": {k: ver["anchors"][k] for k in ("total", "verified", "mismatched", "unresolved")},
            "freeze_notice": {"notice_id": notice.get("notice_id"), "title": notice.get("title"),
                              "statute": notice.get("statute"), "aggregate_lien_inr": notice.get("aggregate_lien_inr"),
                              "principal_loss_cap_inr": notice.get("principal_loss_cap_inr"),
                              "addressees": notice.get("addressees"), "targets": len(notice.get("targets") or [])},
            "str_validation_errors": run["schema"]["sector_d_str_xml"],
        },
        "statutes": ["Section 63 BSA 2023 (certificate)", "Section 45 BSA 2023 (grounds of opinion)",
                     "Section 105 BNSS (audio-video recording of seizure)", "Section 106 BNSS (seizure)",
                     "Section 107 BNSS (attachment)", "Section 94 BNSS (summons to produce)",
                     "Section 12 PMLA 2002 (STR)", "Section 79A IT Act 2000 (examiner)"],
        "modules": _modules_report(), "python": sys.version.split()[0],
        "web_backend": None,
    }


_DIGEST_ROWS = (
    ("sha256_linear_primary", "Linear SHA-256 primary digest", "SHA-256", "sha256"),
    ("blake2b_secondary", "BLAKE2b secondary digest", "BLAKE2b-512", "blake2b"),
    ("sha256_merkle_root_4mb", "RFC 6962 binary Merkle root (4 MB chunks / 1 KB sub-blocks)", "SHA-256", "merkle_root"),
    ("bnss_105_seizure_video_sha256", "Section 105 BNSS audio-video seizure recording", "SHA-256", "video_sha"),
    ("final_bound_evidence_root", "Final bound master evidence root", "SHA-256", "bound_root"),
    ("master_case_root_v3", "Master case root v3 (FIR, seals and clock bound)", None, "master_root"),
)


def vault_view(run: Dict[str, Any]) -> Dict[str, Any]:
    a = run["handset"]["a"]
    hashes = a["cryptographic_hashes"]
    ver = run["legal"]["verification"]
    drows = {r["key"]: r for r in ver["hash_rows"]}
    digests = []
    for key, label, alg, dkey in _DIGEST_ROWS:
        digests.append({"id": key, "label": label,
                        "algorithm": alg or a.get("hash_algorithms", {}).get(key, "").upper() or None,
                        "value": hashes.get(key), "sector_d_check": drows.get(dkey, {}).get("status")})
    bnss = a["bnss_verification"]
    vid = bnss["sec_105_video_continuity"]
    enf = dict(vid.get("indian_enf_power_hum_50hz") or {})
    seal = bnss["sec_106_malkhana_seal_ledger"]
    sigs = seal.get("signatures") or {}

    def sig_status(m: str) -> Optional[str]:
        sig = sigs.get(m)
        return (str(sig.get("status") or "UNVERIFIED") if isinstance(sig, dict) else "ATTACHED") if sig else None

    def signed(m: str) -> bool:   # only a signature Sector A verified counts as signed (overnight audit E-SIG01)
        return sig_status(m) == "VALID"

    chain = [
        {"point": 1, "title": "Crime-scene Faraday bag seal", "statute": "Section 106 BNSS",
         "detail": f"barcode digest {seal.get('field_seal_barcode_sha256', '')[:16]}…; "
                   f"RSSI {seal.get('field_seal_rssi_dbm')} dBm (threshold ≤ -110 dBm); "
                   f"RF isolated: {seal.get('field_seal_rf_isolated')}",
         "rssi_dbm": seal.get("field_seal_rssi_dbm"), "ok": bool(seal.get("field_seal_rf_isolated")),
         "hash": seal.get("h_seal_field"), "signed": signed("field"), "signature_status": sig_status("field")},
        {"point": 2, "title": "Malkhana register deposit", "statute": "Section 106 BNSS",
         "detail": f"receipt {seal.get('malkhana_register_receipt')} deposited {seal.get('malkhana_deposit_utc')}",
         "receipt": seal.get("malkhana_register_receipt"), "ok": bool(seal.get("malkhana_register_receipt")),
         "hash": seal.get("h_malkhana"), "signed": signed("malkhana"),
         "signature_status": sig_status("malkhana")},
        {"point": 3, "title": "Laboratory unsealing camera verification", "statute": "Section 106 BNSS",
         "detail": f"seal barcode re-read at unsealing matches the field seal: {seal.get('lab_unseal_verified')}",
         "ok": bool(seal.get("lab_unseal_verified")), "hash": seal.get("h_lab"), "signed": signed("lab"),
         "signature_status": sig_status("lab")},
    ]
    size = a["evidence_media"]["size_bytes"]
    p = run["pc"]["a"]
    ph = p["cryptographic_hashes"]
    return {
        "exhibit": "HANDSET", "evidence_id": a["evidence_id"], "case_reference": a["case_reference"],
        "examiner_id": a["examiner_id"], "workstation": a.get("ingestion_workstation"),
        "ingestion_timestamp_utc": a["ingestion_timestamp_utc"], "filename": a["evidence_media"]["filename"],
        "size_bytes": size, "telemetry": {k: a["evidence_media"]["hardware_telemetry"].get(k)
                                          for k in ("make_model", "serial_number", "firmware_rev")},
        "digests": digests, "hash_algorithms": a.get("hash_algorithms"),
        "merkle": {"chunk_size_bytes": a["merkle_tree"]["chunk_size_bytes"],
                   "sub_block_bytes": a["merkle_tree"]["sub_block_bytes"],
                   "leaves": -(-size // a["merkle_tree"]["sub_block_bytes"]),
                   "chunk_roots": a["merkle_tree"]["chunk_roots"]},
        "bad_sectors": a["bad_sector_manifest"]["bad_sectors"],
        "sec105_recording": {"verified": vid.get("verified"), "audio_decoder": vid.get("audio_decoder"),
                             "vfr_max_vs_median_ratio": vid.get("vfr_max_vs_median_ratio"),
                             "edit_list_issues": vid.get("edit_list_issues"), "findings": vid.get("findings")},
        "enf": dict(enf, nominal_hz=50.0,
                    phase_ok=isinstance(enf.get("max_phase_jump_rad"), (int, float))
                    and isinstance(enf.get("threshold_rad"), (int, float))
                    and enf["max_phase_jump_rad"] < enf["threshold_rad"]),
        "seal_chain": chain, "seal_chain_head": seal.get("h_sec106_seal_chain"),
        "seal_signatures": (", ".join(f"{m} {sig_status(m) or 'none'}" for m in ("field", "malkhana", "lab"))
                            if sigs else "none attached (officer signatures pending)"),
        "rfc3161": (a.get("rfc3161_time_anchor") or {}).get("status"),
        "navic": (a.get("navic_stratum1_sync") or {}).get("clock_discipline_status"),
        "admissibility": a["admissibility"],
        "sector_d_reverification": {"status": ver["status"], "rows": ver["hash_rows"],
                                    "anchors_verified": ver["anchors"]["verified"],
                                    "anchors_total": ver["anchors"]["total"]},
        "statutory_compliance": a.get("statutory_compliance"),
        "pc_exhibit": {"evidence_id": p["evidence_id"], "filename": p["evidence_media"]["filename"],
                       "size_bytes": p["evidence_media"]["size_bytes"],
                       "sha256_linear_primary": ph.get("sha256_linear_primary"),
                       "blake2b_secondary": ph.get("blake2b_secondary"),
                       "sha256_merkle_root_4mb": ph.get("sha256_merkle_root_4mb"),
                       "final_bound_evidence_root": ph.get("final_bound_evidence_root"),
                       "admissibility": p["admissibility"]["status"],
                       "admissibility_warnings": list(p["admissibility"].get("warnings") or []),
                       "note": "No seizure recording was presented for this exhibit, so its bound root binds the "
                               "Merkle root to 32 zero bytes and Sector A marks it accordingly."},
    }


def _leads(b: Dict[str, Any], *cats: str) -> List[Dict[str, Any]]:
    return [l for l in b.get("symbolic_anchors", []) if l.get("threat_category") in cats]


def _dt_s(a: Optional[str], b: Optional[str]) -> Optional[float]:
    try:
        pa = datetime.datetime.fromisoformat(str(a).replace("Z", "+00:00"))
        pb = datetime.datetime.fromisoformat(str(b).replace("Z", "+00:00"))
        return round((pb - pa).total_seconds(), 3)
    except Exception:
        return None


def triage_view(run: Dict[str, Any]) -> Dict[str, Any]:
    b = run["handset"]["b"]
    insp: AnchorInspector = run["inspectors"]["HANDSET"]

    lolbins = []
    for l in _leads(b, "LOLBINS_COMMAND"):
        d = l["lead_details"]
        layers = d.get("deobfuscation_layers") or []
        raw = layers[0]["text"] if layers else ""
        token = _encoded_token(raw)
        own = None
        if token:
            try:
                own = base64.b64decode(token, validate=True).decode("utf-16-le")
            except (binascii.Error, UnicodeDecodeError):
                own = None
        decoded = [x for x in layers[1:]]
        cand = token or max(raw.split(), key=len, default="")
        h = _entropy(cand) if cand else 0.0
        lolbins.append({
            "lead_id": l["lead_id"], "image": d.get("image"), "parent_image": d.get("parent_image"),
            "user": d.get("user"), "logon_type": d.get("logon_type"), "timestamp_utc": d.get("timestamp_utc"),
            "threat_score": l["threat_score"], "severity": l["severity"],
            "mitre_primary": d.get("primary_mitre"), "mitre_techniques": d.get("mitre_techniques"),
            "indicators": [i.get("indicator") for i in d.get("indicators", [])],
            "command_line": raw, "decoded_layers": decoded,
            "encoded_token": token, "independent_utf16le_decode": own,
            "independent_decode_matches": bool(own) and any(x.get("text") == own for x in decoded),
            "entropy_input": "encoded token" if token else "longest token", "entropy_bits_per_char": round(h, 4),
            "entropy_threshold": ENTROPY_THRESHOLD, "entropy_at_or_above_threshold": h >= ENTROPY_THRESHOLD,
            "sector_b_high_entropy_tokens": d.get("high_entropy_tokens"),
            "anchor": insp.inspect(l.get("symbolic_anchor")),
        })

    df = _leads(b, "DIGITAL_ARREST_DEEPFAKE")
    deep = None
    if df:
        l = df[0]
        d = l["lead_details"]
        ptt = d.get("ptt_delay_ms")
        deep = {"lead_id": l["lead_id"], "threat_score": l["threat_score"], "verdict": d.get("verdict"),
                "ptt_delay_ms": ptt, "physiological_window_ms": list(PTT_WINDOW_MS),
                "ptt_in_physiological_window": d.get("ptt_in_physiological_window"),
                "phase_delta_rad": d.get("ptt_phase_delta_rad"), "heart_rate_bpm": d.get("heart_rate_bpm"),
                "pulse_snr": d.get("pulse_snr"), "subwindow_phase_jitter_rad": d.get("subwindow_phase_jitter_rad"),
                "dicrotic_in_range": d.get("dicrotic_in_range"), "chroma_in_range": d.get("chroma_in_range"),
                "neural_prefilter_score": d.get("neural_prefilter_score"),
                "statutory_actions": l.get("statutory_actions"), "anchor": insp.inspect(l.get("symbolic_anchor"))}
    spec = _leads(b, "SYNTHETIC_IMAGE_SPECTRUM")
    dct: Dict[str, Any]
    if spec:
        d = spec[0]["lead_details"]
        dct = {"status": "RUN", "lead_id": spec[0]["lead_id"], "verdict": d.get("verdict"),
               "spectral_alpha": d.get("spectral_alpha"), "hf_energy_excess_ratio": d.get("hf_energy_excess_ratio"),
               "hf_threshold_applied": d.get("hf_threshold_applied"),
               "nyquist_peak_excess_ratio": d.get("nyquist_peak_excess_ratio"),
               "nyquist_peak_threshold_applied": d.get("nyquist_peak_threshold_applied"),
               "qp_estimate": d.get("qp_estimate"), "qp_relaxation_factor": d.get("qp_relaxation_factor"),
               "anchor": insp.inspect(spec[0].get("symbolic_anchor"))}
    else:
        dct = {"status": "NOT_RUN",
               "reason": "This case bundle holds no still or decoded video frame, so Sector B's 2D-DCT spectral "
                         "decay test (QP-gated) had nothing to analyse. Add an image_pgm artifact to run it."}
    vcam = [{"lead_id": l["lead_id"], "threat_score": l["threat_score"],
             "friendly_name": l["lead_details"].get("friendly_name"),
             "registry_key": l["lead_details"].get("registry_key"),
             "anchor": insp.inspect(l.get("symbolic_anchor"))} for l in _leads(b, "VIRTUAL_CAMERA_INJECTOR")]

    webrtc = []
    for l in _leads(b, "WEBRTC_PEER_ENDPOINT"):
        d = l["lead_details"]
        c = d.get("candidate") or {}
        sa = l.get("statutory_actions") or {}
        webrtc.append({"lead_id": l["lead_id"], "threat_score": l["threat_score"],
                       "candidate_type": c.get("type"), "endpoint": f"{c.get('ip')}:{c.get('port')}",
                       "ip": c.get("ip"), "port": c.get("port"), "transport": c.get("transport"),
                       "public": c.get("public"), "call_id": c.get("call_id"), "timestamp_utc": c.get("timestamp_utc"),
                       "related_address": f"{c.get('related_address')}:{c.get('related_port')}",
                       "stun_turn_servers": d.get("stun_turn_servers"),
                       "sec94_requisition": sa.get("requisition"),
                       "sec94_ready": sa.get("bnss_sec_94_requisition_ready"),
                       "anchor": insp.inspect(l.get("symbolic_anchor"))})

    smurf = []
    for l in _leads(b, "RAPID_UPI_SMURFING"):
        d = l["lead_details"]
        inflow = d.get("inflow") or {}
        outs = []
        anchors = {r.get("txn_id"): r for r in d.get("row_anchors", [])}
        for o in d.get("outflows", []):
            outs.append(dict(o, seconds_after_inflow=_dt_s(inflow.get("timestamp_utc"), o.get("timestamp_utc")),
                             anchor=insp.inspect(anchors.get(o.get("txn_id")))))
        smurf.append({"lead_id": l["lead_id"], "threat_score": l["threat_score"], "alert": d.get("alert"),
                      "hub_vpa": d.get("hub_vpa"), "inflow": dict(inflow, anchor=insp.inspect(
                          anchors.get(inflow.get("txn_id")))),
                      "outflows": outs, "mules": d.get("flagged_mules"),
                      "dispersal_span_s": d.get("dispersal_span_s"), "dispersion_ratio": d.get("dispersion_ratio"),
                      "statutory_actions": {k: v for k, v in (l.get("statutory_actions") or {}).items()
                                            if k != "fiu_ind_str_xml"},
                      "anchor": insp.inspect(l.get("symbolic_anchor"))})
    hawala = [{"lead_id": l["lead_id"], "threat_score": l["threat_score"], "serial": l["lead_details"].get("serial"),
               "normalized": l["lead_details"].get("normalized"), "context": l["lead_details"].get("context"),
               "anchor": insp.inspect(l.get("symbolic_anchor"))} for l in _leads(b, "MIRROR_HAWALA_TOKEN")]
    bridge = []
    # The window Sector B matched bridges in: -CLOCK_SKEW_S <= dt <= TAU_ESCROW_S (overnight audit E-06).
    det = getattr(_sector_b, "FinancialMuleDetector", None)
    esc_lo, esc_hi = -float(getattr(det, "CLOCK_SKEW_S", 30.0)), float(getattr(det, "TAU_ESCROW_S", 300.0))
    for l in _leads(b, "CROSS_CHAIN_BRIDGE"):
        d = l["lead_details"]
        bridge.append({"lead_id": l["lead_id"], "threat_score": l["threat_score"], "upi": d.get("upi"),
                       "chain": d.get("chain"), "delta_t_s": d.get("delta_t_s"), "escrow_window_s": esc_hi,
                       "escrow_window_bounds_s": [esc_lo, esc_hi],
                       "within_escrow_window": isinstance(d.get("delta_t_s"), (int, float))
                       and esc_lo <= d["delta_t_s"] <= esc_hi,
                       "implied_inr_per_usdt": d.get("implied_inr_per_usdt"), "p2p_premium": d.get("p2p_premium"),
                       "rate_window_ok": d.get("rate_window_ok"), "affinity": d.get("affinity"),
                       "upi_anchor": insp.inspect(l.get("symbolic_anchor")),
                       "chain_anchor": insp.inspect(d.get("chain_anchor"))})
    bad_rrn = [{"lead_id": l["lead_id"], "rrn": l["lead_details"]["rrn_validation"].get("rrn"),
                "reasons": l["lead_details"]["rrn_validation"].get("reasons"),
                "transaction": l["lead_details"].get("transaction"), "anchor": insp.inspect(l.get("symbolic_anchor"))}
               for l in _leads(b, "INVALID_NPCI_RRN")]
    every = [{"lead_id": l["lead_id"], "category": l["threat_category"], "threat_score": l["threat_score"],
              "severity": l.get("severity"), "mitre": l.get("mitre_technique"),
              "anchor": insp.inspect(l.get("symbolic_anchor"))} for l in b.get("symbolic_anchors", [])]
    return {
        "exhibit": "HANDSET", "engine": f"{b.get('version')} {b.get('engine_runtime', {}).get('revision', '')}".strip(),
        "manifest_sha256": b.get("manifest_sha256"), "triage_timestamp_utc": b.get("triage_timestamp_utc"),
        "summary_metrics": b.get("summary_metrics"), "admissibility_doctrine": b.get("admissibility_doctrine"),
        "artifact_errors": b.get("artifact_errors"),
        "lolbins": lolbins, "deepfake": deep, "dct_spectrum": dct, "virtual_camera": vcam, "webrtc": webrtc,
        "upi_smurfing": smurf, "mirror_hawala": hawala, "cross_chain_bridge": bridge, "invalid_rrn": bad_rrn,
        "all_leads": every,
    }


def _timestomp_status(step: Dict[str, Any]) -> str:
    fl = set(step.get("flags") or [])
    basis = step.get("timestamp_basis")
    if "TIMESTOMP_INVERTED" in fl and "TIME_REPAIRED" in fl:
        return f"Backdated stamp caught; time repaired to a lower bound ({basis})"
    if "TIMESTOMP_INVERTED" in fl:
        return "Backdated $SI stamp caught; kernel journal time used"
    if "TIME_UNKNOWN" in fl or basis == "UNKNOWN":
        return "No trustworthy time in the record; ordered last"
    return "As recorded; no inversion"


def _graph_exhibit(key: str, run: Dict[str, Any]) -> Dict[str, Any]:
    ex = run[key.lower()]
    story, graph = ex["story"], ex["graph"]
    insp: AnchorInspector = run["inspectors"][key]
    prize = {(n["kind"], n["label"]): n.get("prize") for n in graph.get("nodes", [])}
    nodes: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def node(kind: str, label: str, step: Optional[int]) -> str:
        k = (kind, label)
        if k not in nodes:
            nodes[k] = {"id": f"n{len(nodes) + 1}", "label": label, "kind": kind, "prize": prize.get(k),
                        "first_step": step}
        return nodes[k]["id"]

    edges, rows = [], []
    for s in story["steps"]:
        src = node(s["actor_kind"], s["actor"], s["step"])
        dst = node(s["target_kind"], s["target"], s["step"])
        sec = [{"name": n, "anchor": insp.inspect(p)} for n, p in (s.get("secondary_anchors") or {}).items()]
        e = {"id": s["edge_uid"], "kind": "step", "step": s["step"], "source": src, "target": dst,
             "relation": s["relation"], "action": s["action"], "narrative": s.get("narrative"),
             "mitre": s.get("mitre"), "timestamp_utc": s.get("timestamp_utc"),
             "timestamp_basis": s.get("timestamp_basis"), "timestamp_source": s.get("timestamp_source"),
             "flags": s.get("flags"), "anomaly_score": s.get("anomaly_score"), "stage": s.get("stage"),
             "stage_name": s.get("stage_name"), "lead_id": s.get("lead_id"),
             "anti_timestomp": _timestomp_status(s),
             "timestamp_repair": s.get("timestamp_repair"),
             "anchor": insp.inspect(s.get("provenance")), "secondary_anchors": sec}
        edges.append(e)
        rows.append({"step": s["step"], "timestamp_utc": s.get("timestamp_utc"), "actor": s["actor"],
                     "action": s["action"], "target": s["target"], "relation": s["relation"],
                     "mitre": s.get("mitre"), "stage_name": s.get("stage_name"),
                     "anchor": f"{e['anchor'].get('source_file')} @ Ω={e['anchor'].get('byte_offset')} "
                               f"({e['anchor'].get('byte_offset_hex')})",
                     "anchor_status": e["anchor"].get("status"), "anti_timestomp": e["anti_timestomp"],
                     "edge_id": e["id"]})
    for bnd in story.get("identity_bindings", []):
        src = node(bnd["actor_kind"], bnd["actor"], None)
        dst = node(bnd["target_kind"], bnd["target"], None)
        edges.append({"id": bnd["edge_uid"], "kind": "binding", "step": None, "source": src, "target": dst,
                      "relation": bnd.get("relation"), "action": bnd.get("action"), "narrative": bnd.get("narrative"),
                      "mitre": bnd.get("mitre"), "timestamp_utc": bnd.get("timestamp_utc"),
                      "timestamp_basis": bnd.get("timestamp_basis"), "flags": bnd.get("flags"),
                      "binding_basis": bnd.get("binding_basis"), "anti_timestomp": _timestomp_status(bnd),
                      "anchor": insp.inspect(bnd.get("provenance")), "secondary_anchors": []})
    all_edges = graph.get("edges", [])
    anchored = sum(1 for e in all_edges if isinstance((e.get("provenance") or {}).get("byte_offset"), int)
                   and _is_hex((e.get("provenance") or {}).get("sha256"), 64)
                   and (e.get("provenance") or {}).get("source_file"))
    ts = graph.get("timestomp_analysis") or {}
    return {
        "exhibit": key, "title": EXHIBITS[key]["title"], "sources": EXHIBITS[key]["sources"],
        "nodes": list(nodes.values()), "edges": edges, "storyline": rows,
        "stages": story.get("stages"), "solver": story.get("solver"), "storyline_sha256": story.get("storyline_sha256"),
        "section63_summary": story.get("section63_summary"),
        "defense_challenge_matrix": story.get("defense_challenge_matrix"),
        "unconnected_clusters": story.get("unconnected_clusters"), "warnings": story.get("warnings"),
        "anti_timestomp": {"findings": [{k: f.get(k) for k in ("invariant", "rule", "grade", "path", "source_file",
                                                                "byte_offset", "si_created_utc",
                                                                "journal_create_utc")}
                                        for f in (ts.get("findings") or story.get("timestomp_findings") or [])],
                           "journal_append_only_ok": ts.get("journal_append_only_ok"),
                           "causality": graph.get("causality"),
                           "audit_ledger_count": graph.get("audit_ledger_count"),
                           "audit_ledger_head_sha256": graph.get("audit_ledger_head_sha256")},
        "t_pkg": {"schema": graph.get("schema"), "graph_sha256": graph.get("graph_sha256"),
                  "statistics": graph.get("statistics"), "edges_total": len(all_edges), "edges_anchored": anchored,
                  "edge_record_bytes": (graph.get("statistics") or {}).get("edge_record_bytes"),
                  "broker_epochs": graph.get("broker_epochs")},
    }


def graph_view(run: Dict[str, Any]) -> Dict[str, Any]:
    ex = {k: _graph_exhibit(k, run) for k in ("PC", "HANDSET")}
    primary = ex["PC"]
    return {"primary": "PC", "exhibits": ex, "nodes": primary["nodes"], "edges": primary["edges"],
            "storyline": primary["storyline"],
            "relation_names": sorted(set(getattr(_sector_c, "RELATION_NAMES", {}).values()))}


def exculpatory_view(run: Dict[str, Any]) -> Dict[str, Any]:
    b = run["handset"]["b"]
    s = b.get("section45_exculpatory_checklist") or {}
    gen = run["legal"]["gen"]
    d45 = gen.section45_summary()
    return {
        "statute": s.get("statute"), "sector_d_label": d45.get("label"),
        "evaluated_for_lead_offset": s.get("evaluated_for_lead_offset"),
        "target_timestamp_utc": s.get("target_timestamp_utc"), "session_class": s.get("session_class"),
        "logon_type": s.get("logon_type"), "lineage_complete": s.get("lineage_complete"),
        "process_lineage": s.get("process_lineage"), "remote_ancestor": s.get("remote_ancestor"),
        "checks": s.get("checks", []), "checks_evaluated": s.get("checks_evaluated"),
        "checks_determined": s.get("checks_determined"), "supports_attribution": s.get("supports_attribution"),
        "supports_intrusion_hypothesis": s.get("supports_intrusion_hypothesis"),
        "trojan_defense_probability": s.get("trojan_defense_probability"),
        "exculpatory_indicator_ratio_strict": d45.get("exculpatory_indicator_ratio_strict"),
        "exculpatory_indicator_ratio_upper_bound": d45.get("exculpatory_indicator_ratio_upper_bound"),
        "ratio_display": d45.get("display"), "ratio_consistent": d45.get("ratio_consistent"),
        "groups": d45.get("groups"), "method_note": d45.get("method_note"),
        "sector_b_method_note": s.get("method_note"),
        "examiner_reconciliation": d45.get("examiner_reconciliation"),
        "needs_reconciliation": d45.get("needs_reconciliation"),
        "defense_challenge_matrix": {k: run[k.lower()]["story"].get("defense_challenge_matrix")
                                     for k in ("PC", "HANDSET")},
        "judicial_note": (
            "Section 45 BSA 2023 makes the grounds on which an expert's opinion rests relevant. The 'Trojan "
            "defence' says malware or a remote intruder, not the accused, ran the incriminating commands. Each "
            "of the 14 indicators below is answered only from byte-anchored records (session logon type, remote "
            "tools and logons, parent-process lineage, tampering traces). The ratio is an unweighted count of "
            "indicators, not a probability; indicators that point towards intrusion or remain undetermined must "
            "be reconciled by the examiner in testimony."),
    }


# --------------------------------------------------------------------------- #
# Cockpit page (single file, offline: no CDN, no fonts, no external requests)  #
# --------------------------------------------------------------------------- #

COCKPIT_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SUTRA-TRACE Cyber Cockpit</title>
<style nonce="__NONCE__">
:root{--bg:#000;--bg2:#060909;--line:rgba(62,230,234,.14);--line2:rgba(62,230,234,.34);
--ink:#e4eef0;--mute:#8d999c;--dim:#58646a;--cyan:#3ee6ea;--teal:#22c7cf;--steel:#a9c3cf;
--green:#34d399;--red:#f87171;--amber:#fbbf24;--violet:#a78bfa;--pink:#f472b6;--blue:#60a5fa;
--mono:"Cascadia Code","Cascadia Mono","JetBrains Mono",Consolas,"SFMono-Regular",ui-monospace,"Liberation Mono",monospace;
--sans:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,-apple-system,Roboto,Arial,sans-serif;
--panel:radial-gradient(420px 220px at 0% 0%,rgba(255,255,255,.055),transparent 60%),linear-gradient(165deg,rgba(18,24,26,.94),rgba(3,5,6,.97));--r:6px}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
html,body{margin:0;color:var(--ink);font:300 14.5px/1.6 var(--sans);background:var(--bg)}
body{min-height:100vh;background:#000}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
 background:radial-gradient(1200px 420px at 50% 112%,rgba(34,199,207,.10),transparent 70%),radial-gradient(700px 500px at 100% 0%,rgba(34,199,207,.05),transparent 70%)}
b,strong{font-weight:600}
a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline}
::selection{background:rgba(62,230,234,.3)}
/* ---------- navigation ---------- */
nav.top{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:18px;padding:14px max(18px,calc((100vw - 1240px)/2));background:rgba(0,0,0,.72);
 backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-bottom:1px solid rgba(255,255,255,.04)}
.logo{display:flex;align-items:center;gap:9px;color:var(--ink);white-space:nowrap;font:700 15px var(--mono);letter-spacing:.06em}
.logo:hover{text-decoration:none}.logo b{color:var(--cyan);text-shadow:0 0 18px rgba(62,230,234,.45)}
.navlinks{display:flex;gap:2px;overflow-x:auto;scrollbar-width:none;flex:1;min-width:0;justify-content:flex-end}.navlinks::-webkit-scrollbar{display:none}
.navlinks a{color:var(--mute);padding:6px 11px;font:400 13px var(--sans);white-space:nowrap;position:relative;transition:color .2s}
.navlinks a:hover{color:var(--ink);text-decoration:none}
.navlinks a.on{color:var(--cyan)}.navlinks a.on::after{content:"";position:absolute;left:11px;right:11px;bottom:0;height:1px;background:var(--cyan);box-shadow:0 0 8px var(--cyan)}
.runchip{display:flex;align-items:center;gap:7px;font:12px var(--mono);color:var(--mute);white-space:nowrap}
.dot{width:8px;height:8px;border-radius:50%;background:var(--dim)}
.dot.ok{background:var(--cyan);animation:pulse 2.4s infinite}.dot.busy{background:var(--amber);animation:pulse 1s infinite}.dot.bad{background:var(--red)}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(62,230,234,.55)}70%{box-shadow:0 0 0 9px rgba(62,230,234,0)}100%{box-shadow:0 0 0 0 rgba(62,230,234,0)}}
@media (max-width:860px){nav.top{flex-wrap:wrap;padding:10px 14px;gap:8px 14px}.navlinks{order:3;flex-basis:100%;justify-content:flex-start}.runchip .lbl{display:none}}
/* ---------- pages ---------- */
main{position:relative;z-index:1;max-width:1240px;margin:0 auto;padding:30px 18px 60px;overflow-x:clip}
.page{display:none}.page.on{display:block;animation:rise .6s cubic-bezier(.2,.7,.2,1)}
@keyframes rise{from{opacity:0;transform:translateY(16px);filter:blur(4px)}to{opacity:1;transform:none;filter:none}}
.ph{position:relative;display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:10px 20px;margin:10px 0 26px;padding-top:18px}
.ph::before{content:attr(data-ghost);position:absolute;right:-6px;top:-14px;font:900 clamp(56px,10vw,140px)/1 var(--sans);letter-spacing:.01em;color:rgba(255,255,255,.045);
 pointer-events:none;white-space:nowrap;max-width:100%;overflow:hidden}
.ph>*{position:relative}
.ph h1,.mono-h{margin:4px 0 0;font:700 clamp(24px,3.2vw,36px)/1.2 var(--mono);letter-spacing:.02em;color:var(--ink)}
.eyebrow{font:700 12px var(--mono);letter-spacing:.42em;text-transform:uppercase;color:var(--cyan);margin-bottom:6px}
.lead{color:var(--mute);max-width:760px;margin:10px 0 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:18px 20px;min-width:0;box-shadow:inset 0 1px 0 rgba(255,255,255,.04)}
.card h2{margin:0 0 12px;font:700 14.5px var(--mono);letter-spacing:.02em;display:flex;align-items:center;gap:8px;flex-wrap:wrap;color:var(--ink)}
.card h3{margin:14px 0 6px;font:600 13px var(--mono);color:var(--steel)}
.sub{font:12px var(--sans);color:var(--mute);font-weight:300}
.grid{display:grid;gap:14px}.g2{grid-template-columns:repeat(2,minmax(0,1fr))}.g3{grid-template-columns:repeat(3,minmax(0,1fr))}.g4{grid-template-columns:repeat(4,minmax(0,1fr))}.g5{grid-template-columns:repeat(5,minmax(0,1fr))}
.g73{grid-template-columns:minmax(0,7fr) minmax(0,5fr)}
.grid>.card,.stack>.card{animation:rise .6s both}.grid>.card:nth-child(2){animation-delay:.06s}.grid>.card:nth-child(3){animation-delay:.12s}.grid>.card:nth-child(4){animation-delay:.18s}.grid>.card:nth-child(5){animation-delay:.24s}
@media (max-width:1050px){.g4,.g5{grid-template-columns:repeat(2,minmax(0,1fr))}.g3,.g73{grid-template-columns:minmax(0,1fr)}}
@media (max-width:640px){.g2,.g4,.g5{grid-template-columns:minmax(0,1fr)}}
.mt{margin-top:14px}.mt0{margin-top:0}.center{text-align:center}.center .lead{margin-left:auto;margin-right:auto}
/* ---------- buttons ---------- */
.btn{appearance:none;border:1px solid var(--line2);background:rgba(0,0,0,.55);color:var(--ink);padding:10px 18px;border-radius:4px;font:600 13px var(--sans);
 cursor:pointer;display:inline-flex;gap:10px;align-items:center;transition:background .2s,box-shadow .25s,border-color .2s,transform .15s;text-decoration:none}
.btn::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--teal);box-shadow:0 0 8px var(--cyan);flex:none}
.btn:hover{background:rgba(62,230,234,.10);border-color:var(--cyan);text-decoration:none;box-shadow:0 0 22px rgba(62,230,234,.18)}
.btn.primary{border-color:var(--cyan);background:rgba(4,34,38,.7);box-shadow:0 0 0 1px rgba(62,230,234,.2),0 0 26px rgba(62,230,234,.16)}
.btn.primary:hover{box-shadow:0 0 0 1px rgba(62,230,234,.45),0 0 34px rgba(62,230,234,.32)}
.btn.plain::before{display:none}
.btn:disabled{opacity:.6;cursor:wait}
.cta{display:flex;flex-wrap:wrap;gap:12px;margin-top:24px}.cta.jc{justify-content:center}
/* ---------- home ---------- */
.hero{position:relative;display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,.95fr);gap:20px;align-items:center;min-height:calc(100vh - 120px)}
@media (max-width:900px){.hero{grid-template-columns:minmax(0,1fr);min-height:0}}
.htitle{font:800 clamp(28px,3.7vw,54px)/1.15 var(--mono);letter-spacing:.03em;margin:12px 0 18px;text-transform:uppercase}
.gt{background:linear-gradient(92deg,#2fd2d9 0%,#68dbe2 35%,#b8ccd6 75%,#2fd2d9 100%);background-size:220% 100%;-webkit-background-clip:text;background-clip:text;color:transparent;animation:sheen 9s ease-in-out infinite}
@keyframes sheen{0%,100%{background-position:0% 50%}50%{background-position:100% 50%}}
.hero .tag{font:400 17px var(--sans);color:var(--ink);margin:0 0 8px}.hero .tag b{font-family:var(--mono);color:var(--cyan)}
.hero p{color:var(--mute);max-width:560px;margin:0}
.badges{display:flex;flex-wrap:wrap;gap:8px;margin:26px 0 0}
.badge{border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.02);border-radius:4px;padding:4px 10px;font:11.5px var(--mono);color:var(--mute);max-width:100%;overflow-wrap:anywhere}
.scene{position:relative;height:460px;min-width:0}
@media (max-width:900px){.scene{height:340px}}
.ridge{position:absolute;left:-12%;width:124%;bottom:30px;height:170px;opacity:.95}
.mist{position:absolute;left:5%;right:5%;bottom:70px;height:90px;border-radius:50%;background:radial-gradient(ellipse at center,rgba(62,230,234,.16),transparent 70%);filter:blur(14px)}
.sun{position:absolute;left:34%;bottom:150px;width:120px;height:120px;border-radius:50%;
 background:radial-gradient(circle at 38% 30%,#e6ffff 0%,#76f4f6 18%,#25d3dc 52%,#0a8f9b 82%,#05616b 100%);
 box-shadow:0 0 50px rgba(62,230,234,.55),0 0 130px rgba(62,230,234,.28);animation:bob 7s ease-in-out infinite}
@media (max-width:900px){.sun{width:90px;height:90px;bottom:120px}}
@keyframes bob{0%,100%{transform:translateY(0)}50%{transform:translateY(-12px)}}
.bot{position:absolute;width:120px;height:120px;border-radius:50%;
 background:radial-gradient(circle at 30% 24%,rgba(255,255,255,.75) 0,rgba(255,255,255,.18) 9%,rgba(40,48,52,.55) 26%,#07090a 55%,#000 75%);
 border:1px solid rgba(255,255,255,.22);box-shadow:inset -10px -14px 26px rgba(0,0,0,.9),inset 8px 8px 18px rgba(255,255,255,.10),0 12px 40px rgba(0,0,0,.8),0 0 0 1px rgba(62,230,234,.08);
 animation:float 6s ease-in-out infinite;transition:box-shadow .3s}
.bot::after{content:"";position:absolute;left:18%;top:62%;width:64%;height:30%;border-radius:50%;background:radial-gradient(ellipse at 50% 100%,rgba(62,230,234,.22),transparent 70%)}
#heroBot{left:52%;top:30px;cursor:pointer}
@media (max-width:900px){#heroBot{left:auto;right:6%;top:20px;width:96px;height:96px}}
@keyframes float{0%,100%{transform:translateY(0) rotate(-2deg)}50%{transform:translateY(-10px) rotate(2deg)}}
.eyes{position:absolute;left:50%;top:46%;display:flex;gap:14%;width:44%;justify-content:center;transform:translate(-50%,-50%);transition:transform .12s linear;z-index:1}
.eye{display:block;width:10px;height:26px;border-radius:6px;background:#8ff9f9;box-shadow:0 0 8px #3ee6ea,0 0 20px rgba(62,230,234,.7);animation:blink 5.5s infinite;transform-origin:50% 60%}
.eye+.eye{animation-delay:.04s}
@keyframes blink{0%,91%,97%,100%{transform:scaleY(1)}94%{transform:scaleY(.08)}}
.bot.think .eye{height:10px;width:10px;border-radius:50%;animation:think 1s ease-in-out infinite}
@keyframes think{0%,100%{transform:translateY(-3px)}50%{transform:translateY(3px)}}
.bot.happy .eye{height:12px;width:14px;border-radius:14px 14px 3px 3px;animation:none}
.bot.alert .eye{background:#ffb4b4;box-shadow:0 0 8px #f87171,0 0 20px rgba(248,113,113,.7)}
.bot.alert{box-shadow:inset -10px -14px 26px rgba(0,0,0,.9),0 0 30px rgba(248,113,113,.35)}
.bubble{position:absolute;max-width:280px;padding:10px 14px;border:1px solid rgba(62,230,234,.6);border-radius:8px;background:rgba(1,14,16,.82);
 font:12.5px/1.55 var(--mono);color:#dffcfd;box-shadow:0 0 26px rgba(62,230,234,.14);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);transition:opacity .35s,transform .35s}
.bubble.hide{opacity:0;transform:translateY(6px);pointer-events:none}
#heroBubble{left:20%;top:150px;z-index:2}
@media (max-width:900px){#heroBubble{left:2%;top:40px;max-width:60%}}
.caret{display:inline-block;width:7px;height:14px;margin-left:2px;vertical-align:-2px;background:var(--cyan);animation:caret 1s steps(1) infinite}
@keyframes caret{50%{opacity:0}}
.scrollcue{text-align:center;font:11px var(--mono);letter-spacing:.4em;color:var(--dim);text-transform:uppercase;margin:-30px 0 40px}
.scrollcue::after{content:"";display:block;width:1px;height:38px;margin:10px auto 0;background:linear-gradient(var(--cyan),transparent);animation:cue 2s ease-in-out infinite}
@keyframes cue{0%{transform:scaleY(0);transform-origin:top}50%{transform:scaleY(1);transform-origin:top}51%{transform-origin:bottom}100%{transform:scaleY(0);transform-origin:bottom}}
.band{margin:90px 0}
.rv{opacity:0;transform:translateY(28px);filter:blur(6px);transition:opacity .9s ease,transform .9s cubic-bezier(.2,.7,.2,1),filter .9s ease}
.rv.in{opacity:1;transform:none;filter:none}
.statgrid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-top:34px}
@media (max-width:900px){.statgrid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:520px){.statgrid{grid-template-columns:minmax(0,1fr)}}
.stat{position:relative;overflow:hidden;min-height:170px}
.stat .lab{font:600 10.5px var(--mono);letter-spacing:.2em;text-transform:uppercase;color:var(--mute)}
.stat .big{font:300 46px/1.1 var(--mono);color:var(--ink);margin-top:8px}.stat .big small{font-size:16px;color:var(--mute)}
.stat .cap{font-size:12.5px;color:var(--mute)}
.stat svg{display:block;width:100%;margin-top:6px}
.flow{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px}
@media (max-width:1050px){.flow{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:560px){.flow{grid-template-columns:minmax(0,1fr)}}
.feat{position:relative;overflow:hidden;cursor:pointer;min-height:220px;transition:transform .25s,border-color .25s,box-shadow .25s}
.feat:hover,.feat:focus-visible{transform:translateY(-4px);border-color:var(--line2);box-shadow:0 0 0 1px rgba(62,230,234,.18),0 20px 50px rgba(34,199,207,.12);outline:none}
.feat .ic{width:44px;height:44px;border-radius:6px;display:grid;place-items:center;border:1px solid currentColor;margin-bottom:22px;background:rgba(255,255,255,.02)}
.feat .ic svg{width:24px;height:24px}
.feat .k{font:600 10.5px var(--mono);letter-spacing:.22em;color:var(--dim);text-transform:uppercase}
.feat h3{margin:2px 0 8px;font:700 17px var(--mono);color:var(--ink)}.feat p{margin:0;color:var(--mute);font-size:13px}
.feat .go{position:absolute;right:16px;top:16px;color:var(--dim);transition:color .2s,transform .2s;font-family:var(--mono)}.feat:hover .go{color:var(--cyan);transform:translateX(3px)}
#hub svg{display:block;width:100%;max-width:820px;margin:20px auto 0}
.hubline{stroke-dasharray:4 8;animation:dash 1.6s linear infinite}
.hubsat{cursor:pointer}.hubsat:hover rect{stroke-width:2.4}
/* ---------- run page ---------- */
.launch{display:grid;place-items:center;gap:34px;padding:26px 0 16px}
.lbtn{position:relative;width:148px;height:148px;border-radius:50%;cursor:pointer;color:#c4fdfe;font:800 15px var(--mono);letter-spacing:.1em;
 background:radial-gradient(circle,rgba(1,12,14,.25) 0%,rgba(1,12,14,.62) 64%,rgba(62,230,234,.16) 100%);border:1.5px solid rgba(62,230,234,.75);
 text-shadow:0 0 12px rgba(62,230,234,.95);box-shadow:0 0 34px rgba(62,230,234,.38),inset 0 0 34px rgba(62,230,234,.28);transition:transform .25s,box-shadow .25s}
.lbtn:hover{transform:scale(1.05);box-shadow:0 0 56px rgba(62,230,234,.6),inset 0 0 44px rgba(62,230,234,.4)}
.lbtn:disabled{cursor:wait;color:#fde68a;border-color:rgba(251,191,36,.85);background:radial-gradient(circle,rgba(24,14,0,.25) 0%,rgba(24,14,0,.62) 64%,rgba(251,191,36,.16) 100%);
 text-shadow:0 0 12px rgba(251,191,36,.95);box-shadow:0 0 44px rgba(251,191,36,.42),inset 0 0 34px rgba(251,191,36,.3)}
.lbtn .ring{position:absolute;inset:-16px;border-radius:50%;border:1px dashed rgba(62,230,234,.55);animation:spin 18s linear infinite}
.lbtn:disabled .ring{border-color:rgba(251,191,36,.7);animation-duration:2.5s}
@keyframes spin{to{transform:rotate(360deg)}}
.stages{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:10px;margin-top:6px}
@media (max-width:1050px){.stages{grid-template-columns:repeat(2,minmax(0,1fr))}}
.stage{border:1px solid var(--line);border-radius:var(--r);padding:12px;background:var(--panel);position:relative;overflow:hidden;transition:border-color .3s}
.stage .n{font:600 10.5px var(--mono);letter-spacing:.2em;color:var(--dim)}.stage .t{font:600 13px var(--mono);margin:4px 0}.stage .ms{font:12.5px var(--mono);color:var(--mute)}
.stage.run{border-color:rgba(251,191,36,.6)}.stage.run::after{content:"";position:absolute;left:0;bottom:0;height:2px;width:40%;background:var(--amber);box-shadow:0 0 10px var(--amber);animation:slide 1s linear infinite}
.stage.done{border-color:rgba(62,230,234,.4)}.stage.done .ms{color:var(--cyan)}
@keyframes slide{from{left:-40%}to{left:100%}}
.kpi{padding:16px 18px}.kpi .v{font:300 clamp(24px,2.6vw,34px)/1.15 var(--mono);letter-spacing:.01em}.kpi .l{color:var(--mute);font-size:12.5px;margin-top:6px}
.kpi .v small{font-size:14px;color:var(--mute)}.kpi .v .small{font:600 13px var(--mono);letter-spacing:.06em}
.kpi.c .v{color:var(--cyan)}.kpi.g .v{color:var(--green)}.kpi.a .v{color:var(--amber)}.kpi.v .v{color:var(--violet)}.kpi.r .v{color:var(--red)}
/* ---------- shared bits ---------- */
.kv{display:grid;grid-template-columns:minmax(120px,200px) minmax(0,1fr);gap:6px 14px;font-size:13.5px}
.kv .k{color:var(--mute)}.kv>div{min-width:0;overflow-wrap:anywhere}
@media (max-width:600px){.kv{grid-template-columns:minmax(0,1fr)}.kv .k{margin-top:5px}}
.mono{font-family:var(--mono);font-size:12.5px;overflow-wrap:anywhere}
.muted{color:var(--mute)}.small{font-size:12.5px}.err{color:var(--red)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{border-bottom:1px solid rgba(255,255,255,.06);padding:8px;text-align:left;vertical-align:top}
th{color:var(--mute);font:600 11px var(--mono);letter-spacing:.1em;text-transform:uppercase;background:#040707;position:sticky;top:0;z-index:1}
tr.click{cursor:pointer}tr.click:hover td{background:rgba(62,230,234,.05)}
.scroll{overflow:auto;max-height:460px;border-radius:var(--r)}.hscroll{overflow-x:auto}
.pill{display:inline-block;border-radius:4px;padding:1px 8px;font:600 10.5px/1.7 var(--mono);letter-spacing:.04em;border:1px solid;white-space:nowrap}
.pill.ok{color:#6ff0c4;border-color:rgba(52,211,153,.55);background:rgba(52,211,153,.07)}.pill.bad{color:#fca5a5;border-color:rgba(248,113,113,.55);background:rgba(248,113,113,.07)}
.pill.warn{color:#fcd34d;border-color:rgba(251,191,36,.55);background:rgba(251,191,36,.07)}.pill.info{color:#8cf3f5;border-color:rgba(62,230,234,.45);background:rgba(62,230,234,.06)}
.pill.violet{color:#c4b5fd;border-color:rgba(167,139,250,.55);background:rgba(167,139,250,.07)}
pre{white-space:pre-wrap;word-break:break-word;background:#020404;border:1px solid var(--line);border-radius:var(--r);padding:10px 12px;margin:8px 0;font:12px/1.5 var(--mono);color:#cfe9ea;max-height:320px;overflow:auto}
pre.hex{white-space:pre;word-break:normal;overflow-x:auto}
details>summary{cursor:pointer;font:600 12.5px var(--mono);color:var(--steel)}
.alert{border:1px solid rgba(248,113,113,.5);background:rgba(127,29,29,.18);border-radius:var(--r);padding:10px 12px;margin:10px 0}
.alert.warn{border-color:rgba(251,191,36,.45);background:rgba(120,72,6,.16)}.alert ul{margin:4px 0 0 18px;padding:0}.alert b{display:block;font-family:var(--mono);font-size:13px}
.live{margin-top:10px;border-top:1px dashed var(--line2);padding-top:8px}
.tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.tabs button{appearance:none;border:1px solid rgba(255,255,255,.12);background:rgba(0,0,0,.5);color:var(--mute);padding:7px 14px;border-radius:4px;font:600 12.5px var(--mono);cursor:pointer;transition:all .2s}
.tabs button:hover{color:var(--ink);border-color:var(--line2)}
.tabs button.on{color:var(--cyan);border-color:var(--cyan);background:rgba(62,230,234,.08);box-shadow:0 0 18px rgba(62,230,234,.15)}
.legend{display:flex;flex-wrap:wrap;gap:12px;font:12px var(--mono);color:var(--mute);margin:10px 0}
.legend i{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:0}
.bar{height:6px;border-radius:3px;background:rgba(255,255,255,.07);overflow:hidden}.bar>i{display:block;height:100%;border-radius:3px;background:linear-gradient(90deg,var(--teal),var(--cyan));transform-origin:left;animation:grow 1s ease-out}
@keyframes grow{from{transform:scaleX(0)}to{transform:scaleX(1)}}
.hrow{display:grid;grid-template-columns:minmax(120px,200px) minmax(0,1fr) 64px;gap:12px;align-items:center;padding:7px 6px;border-radius:4px;cursor:pointer;font-size:13px}
.hrow:hover{background:rgba(62,230,234,.05)}
.digest{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 10px;padding:12px 14px;border:1px solid var(--line);border-radius:var(--r);background:rgba(0,0,0,.45)}
.digest .nm{font:600 13px var(--mono)}.digest .al{font-size:11.5px;color:var(--dim)}
.copy{appearance:none;border:1px solid rgba(255,255,255,.14);background:transparent;color:var(--mute);border-radius:4px;padding:1px 8px;font:11px var(--mono);cursor:pointer}.copy:hover{color:var(--cyan);border-color:var(--cyan)}
.tl{position:relative;margin-left:8px;padding-left:22px;border-left:1px solid var(--line2)}
.tl .it{position:relative;margin:0 0 14px}.tl .it::before{content:"";position:absolute;left:-29px;top:5px;width:12px;height:12px;border-radius:50%;background:#000;border:1px solid var(--dim)}
.tl .it.ok::before{border-color:var(--cyan);background:rgba(62,230,234,.3);box-shadow:0 0 10px rgba(62,230,234,.5)}
.story{display:grid;grid-template-columns:44px minmax(0,1fr);gap:4px 12px;padding:12px 14px;border:1px solid var(--line);border-radius:var(--r);background:rgba(0,0,0,.45);cursor:pointer;transition:border-color .2s,transform .2s,box-shadow .2s}
.story:hover{border-color:var(--line2);transform:translateX(3px);box-shadow:0 0 22px rgba(62,230,234,.08)}.story.sel{border-color:var(--cyan);background:rgba(62,230,234,.06)}
.story .num{grid-row:span 3;width:38px;height:38px;border-radius:50%;display:grid;place-items:center;font:700 14px var(--mono);color:var(--cyan);border:1px solid rgba(62,230,234,.5);box-shadow:0 0 14px rgba(62,230,234,.15)}
.story.ts .num{color:var(--amber);border-color:rgba(251,191,36,.55)}
.story .what{font-weight:500}.story .meta{display:flex;flex-wrap:wrap;gap:6px;align-items:center;font-size:12px;color:var(--mute)}
.stack>*+*{margin-top:12px}
.graphwrap{border:1px solid var(--line);border-radius:var(--r);background:radial-gradient(800px 300px at 30% 0%,rgba(62,230,234,.05),transparent 70%),#020404;max-height:640px}
svg text{font-family:var(--mono)}
.gnode{cursor:pointer}.gnode:hover rect.box{stroke:#fff}.gedge{cursor:pointer}.gedge:hover path.v{stroke-width:3}
.gnode.sel rect.box{stroke:#fff;stroke-width:2.4}.gedge.sel path.v{stroke:#fff;stroke-width:2.8}
.gedge path.v{stroke-dasharray:6 5;animation:dash 1.4s linear infinite}.gedge.bind path.v{animation:none}
@keyframes dash{to{stroke-dashoffset:-22}}
.checks{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
@media (max-width:760px){.checks{grid-template-columns:minmax(0,1fr)}}
.chk{display:grid;grid-template-columns:30px minmax(0,1fr);gap:4px 10px;padding:12px;border-radius:var(--r);border:1px solid var(--line);background:rgba(0,0,0,.45)}
.chk .i{width:28px;height:28px;border-radius:50%;display:grid;place-items:center;font:700 11.5px var(--mono);border:1px solid}
.chk.SUPPORTS_ATTRIBUTION .i{color:var(--blue);border-color:rgba(96,165,250,.5)}.chk.SUPPORTS_INTRUSION_HYPOTHESIS .i{color:var(--violet);border-color:rgba(167,139,250,.5)}.chk.UNDETERMINED .i{color:var(--amber);border-color:rgba(251,191,36,.5)}
.dl{display:grid;grid-template-columns:52px minmax(0,1fr);gap:4px 14px;align-items:center;transition:transform .25s,border-color .25s,box-shadow .25s}
.dl:hover{transform:translateY(-3px);border-color:var(--line2);box-shadow:0 18px 44px rgba(34,199,207,.12);text-decoration:none}
.dl .ic{grid-row:span 2;width:50px;height:50px;border-radius:6px;display:grid;place-items:center;font-size:22px;border:1px solid var(--line2);background:rgba(62,230,234,.05)}
.dl .t{color:var(--ink);font:700 13.5px var(--mono)}.dl .s{color:var(--mute);font-size:12px;overflow-wrap:anywhere}
.qr{width:180px;height:180px;image-rendering:pixelated;background:#fff;border-radius:6px;padding:6px;box-shadow:0 0 30px rgba(62,230,234,.15)}
.flex{display:flex;gap:16px;flex-wrap:wrap;align-items:flex-start}
.pager{display:flex;justify-content:space-between;gap:10px;margin-top:34px;flex-wrap:wrap}
/* ---------- drawer & dialog ---------- */
.drawer{position:fixed;top:0;right:0;height:100vh;width:min(620px,100vw);z-index:40;background:rgba(2,4,5,.97);border-left:1px solid var(--line2);
 box-shadow:-20px 0 60px rgba(0,0,0,.6),-1px 0 30px rgba(62,230,234,.08);transform:translateX(105%);transition:transform .4s cubic-bezier(.2,.7,.2,1);display:flex;flex-direction:column}
.drawer.on{transform:none}.drawer .hd{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:14px 18px;border-bottom:1px solid var(--line);font-family:var(--mono)}
.drawer .bd{padding:16px 18px;overflow:auto;flex:1}
.scrim{position:fixed;inset:0;z-index:35;background:rgba(0,0,0,.6);opacity:0;pointer-events:none;transition:opacity .3s;backdrop-filter:blur(2px)}.scrim.on{opacity:1;pointer-events:auto}
dialog{background:#030606;color:var(--ink);border:1px solid var(--line2);border-radius:8px;max-width:min(920px,94vw);width:94vw;padding:0;box-shadow:0 0 60px rgba(62,230,234,.12)}
dialog::backdrop{background:rgba(0,0,0,.8)}
dialog .hd{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:12px 16px;border-bottom:1px solid var(--line);font-family:var(--mono)}dialog .bd{padding:12px 16px;max-height:75vh;overflow:auto}
footer{position:relative;z-index:1;max-width:1240px;margin:0 auto;color:var(--dim);font:11.5px/1.7 var(--mono);padding:24px 18px 90px;border-top:1px solid rgba(255,255,255,.05);text-align:center}
.toast{position:fixed;left:50%;bottom:24px;transform:translate(-50%,30px);opacity:0;z-index:60;background:#020909;border:1px solid var(--cyan);border-radius:6px;padding:9px 16px;font:12.5px var(--mono);color:#dffcfd;box-shadow:0 0 24px rgba(62,230,234,.2);transition:all .35s}
.toast.on{opacity:1;transform:translate(-50%,0)}
/* ---------- buddy (docked guide) ---------- */
.buddy{position:fixed;left:18px;bottom:18px;z-index:30;width:70px;height:70px}
body.home .buddy{display:none}
.buddy .bot{width:70px;height:70px;left:0;top:0;cursor:pointer}
.buddy .eye{width:6px;height:16px}
.buddy .bot.think .eye,.chathd .bot.think .eye{width:6px;height:6px}
.buddy .bubble{left:80px;bottom:18px;width:max-content;max-width:min(320px,calc(100vw - 120px))}
@media (max-width:640px){.buddy{left:10px;bottom:10px;width:54px;height:54px}.buddy .bot{width:54px;height:54px}.buddy .bubble{left:62px;bottom:8px;font-size:11.5px}}
/* ---------- chat ---------- */
.fab{position:fixed;right:20px;bottom:20px;z-index:31;width:52px;height:52px;border-radius:50%;border:1.5px solid var(--cyan);background:rgba(0,0,0,.75);color:var(--cyan);cursor:pointer;display:grid;place-items:center;
 box-shadow:0 0 20px rgba(62,230,234,.3),inset 0 0 14px rgba(62,230,234,.15);transition:transform .2s,box-shadow .2s}
.fab:hover{transform:scale(1.07);box-shadow:0 0 30px rgba(62,230,234,.5)}.fab svg{width:22px;height:22px}
.fab::after{content:"";position:absolute;right:6px;top:6px;width:8px;height:8px;border-radius:50%;background:var(--cyan);box-shadow:0 0 8px var(--cyan)}
.chat{position:fixed;right:20px;bottom:84px;z-index:45;width:min(410px,calc(100vw - 24px));height:min(580px,calc(100vh - 110px));display:flex;flex-direction:column;
 background:rgba(1,3,4,.97);border:1px solid var(--line2);border-radius:8px;box-shadow:0 0 50px rgba(62,230,234,.14),0 30px 80px rgba(0,0,0,.8);
 opacity:0;transform:translateY(16px) scale(.98);pointer-events:none;transition:opacity .3s,transform .3s}
.chat.on{opacity:1;transform:none;pointer-events:auto}
@media (max-width:640px){.chat{right:12px;bottom:80px}}
.chathd{position:relative;display:flex;align-items:center;gap:12px;padding:12px 14px;border-bottom:1px solid var(--line)}
.chathd .bot{position:relative;width:44px;height:44px;animation:none;flex:none}.chathd .eye{width:5px;height:12px}
.chathd b{font:700 14px var(--mono);display:block}.chathd span{font-size:11.5px;color:var(--mute)}
.chathd .x{margin-left:auto;appearance:none;background:none;border:0;color:var(--cyan);font:300 26px/1 var(--sans);cursor:pointer;padding:0 4px}
.chatbd{flex:1;overflow:auto;padding:14px;display:flex;flex-direction:column;gap:10px}
.msg{max-width:88%;padding:9px 12px;border-radius:8px;font:12.5px/1.6 var(--mono);white-space:pre-wrap;overflow-wrap:anywhere}
.msg.ai{align-self:flex-start;border:1px solid rgba(62,230,234,.45);background:rgba(2,16,18,.8);color:#dffcfd}
.msg.me{align-self:flex-end;background:rgba(62,230,234,.14);border:1px solid rgba(62,230,234,.3);color:var(--ink)}
.msg .act{display:flex;width:fit-content;margin-top:10px;padding:7px 14px;font-size:12px}
.typing{display:inline-flex;gap:4px}.typing i{width:6px;height:6px;border-radius:50%;background:var(--cyan);animation:tdot 1s infinite}.typing i:nth-child(2){animation-delay:.15s}.typing i:nth-child(3){animation-delay:.3s}
@keyframes tdot{0%,100%{opacity:.25;transform:translateY(0)}50%{opacity:1;transform:translateY(-3px)}}
.chips{display:flex;flex-direction:column;gap:6px}.chips .lab{font:10.5px var(--mono);letter-spacing:.2em;color:var(--cyan);text-align:center;text-transform:uppercase;margin:4px 0}
.chip{appearance:none;text-align:left;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.02);color:var(--ink);border-radius:20px;padding:7px 14px;font:12px var(--mono);cursor:pointer;transition:all .2s}
.chip:hover{border-color:var(--cyan);background:rgba(62,230,234,.08)}
.chatin{display:flex;gap:8px;padding:12px 14px 6px;border-top:1px solid var(--line)}
.chatin input{flex:1;min-width:0;background:#000;border:1px solid rgba(255,255,255,.14);border-radius:20px;color:var(--ink);padding:9px 14px;font:12.5px var(--mono);outline:none}
.chatin input:focus{border-color:var(--cyan);box-shadow:0 0 14px rgba(62,230,234,.2)}
.chatin button{appearance:none;width:38px;height:38px;border-radius:50%;border:1px solid var(--cyan);background:rgba(62,230,234,.12);color:var(--cyan);cursor:pointer;display:grid;place-items:center}
.chatin button svg{width:16px;height:16px}
.chatft{font:10.5px var(--mono);color:var(--teal);text-align:center;padding:2px 10px 10px;opacity:.8}
/* ---------- r5: Holo-Core, spotlight cards, bento, live canvases, graph pan/zoom ---------- */
.holo,.holofx{position:absolute;inset:0;width:100%;height:100%;display:block}
.holofx{z-index:1;touch-action:none;cursor:grab}
.scene .holofx{z-index:1}
#heroBot{left:auto;right:0;top:0;width:92px;height:92px;z-index:3}
#heroBot .eye{width:8px;height:20px}
#heroBubble{left:auto;right:104px;top:16px;z-index:3;max-width:250px}
@media (max-width:900px){#heroBot{right:2%;top:2px;width:70px;height:70px}#heroBot .eye{width:6px;height:15px}#heroBubble{left:0;right:auto;top:2px;max-width:calc(100% - 92px)}}
.launch{gap:12px;padding:4px 0 10px}
.launchcore{position:relative;width:100%;height:360px;display:grid;place-items:center}
@media (max-width:640px){.launchcore{height:300px}}
.launchcore .lbtn{z-index:2}
.card,.story,.chk,.digest{position:relative;isolation:isolate}
.stage{isolation:isolate}
.card::before,.stage::before,.story::before,.chk::before,.digest::before{content:"";position:absolute;inset:0;border-radius:inherit;pointer-events:none;z-index:-1;opacity:0;transition:opacity .45s;
 background:radial-gradient(600px circle at var(--mx,-9999px) var(--my,-9999px),rgba(0,229,255,0.08),transparent 40%)}
.card:hover::before,.stage:hover::before,.story:hover::before,.chk:hover::before,.digest:hover::before{opacity:1}
.card::after,.story::after,.chk::after,.digest::after{content:"";position:absolute;inset:0;border-radius:inherit;padding:1px;pointer-events:none;
 background:radial-gradient(220px circle at var(--mx,-9999px) var(--my,-9999px),rgba(140,250,252,.9),rgba(62,230,234,.28) 38%,transparent 72%);
 -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude}
.bento{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));grid-auto-flow:row dense;gap:14px;margin-top:34px}
.bento .w2{grid-column:span 2}.bento .tall{grid-row:span 2;display:flex;flex-direction:column}
@media (max-width:900px){.bento{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:520px){.bento{grid-template-columns:minmax(0,1fr)}.bento .w2{grid-column:auto}.bento .tall{grid-row:auto}}
.stream{flex:1;min-height:250px;max-height:300px;overflow:hidden;margin-top:12px;font:11.5px/1.8 var(--mono);display:flex;flex-direction:column;justify-content:flex-end;
 -webkit-mask-image:linear-gradient(transparent,#000 24%,#000 100%);mask-image:linear-gradient(transparent,#000 24%,#000 100%)}
.sline{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#9ffbfc;text-shadow:0 0 8px rgba(62,230,234,.35);animation:sline .45s ease-out}
.sline .st{color:var(--dim)}.sline.bad{color:#fca5a5;text-shadow:0 0 8px rgba(248,113,113,.4)}
@keyframes sline{from{opacity:0;transform:translateY(10px)}}
.live-cv{display:block;width:100%;margin:8px 0 4px}
.tile-go{position:absolute;right:16px;top:14px;font:12px var(--mono);color:var(--dim)}.tile-go:hover{color:var(--cyan)}
rect.mule{transition:fill .35s,stroke .35s}rect.mule.hit{fill:rgba(239,68,68,.32);stroke:#f87171}
.graphwrap{position:relative;overflow:hidden;height:clamp(420px,74vh,800px);max-height:none}
.graphwrap>svg{display:block;width:100%;height:100%;touch-action:none;cursor:grab;user-select:none;-webkit-user-select:none}
.graphwrap>svg.panning{cursor:grabbing}
.gtools{position:absolute;right:10px;top:10px;z-index:2;display:flex;gap:6px}
.gtools button{appearance:none;min-width:34px;height:30px;padding:0 10px;border-radius:6px;border:1px solid var(--line2);background:rgba(0,0,0,.72);color:var(--cyan);font:600 12.5px var(--mono);cursor:pointer;transition:border-color .2s,box-shadow .2s}
.gtools button:hover{border-color:var(--cyan);box-shadow:0 0 14px rgba(62,230,234,.3)}
.ghint{position:absolute;left:12px;bottom:9px;font:11px var(--mono);color:var(--dim);pointer-events:none}
.gnode,.gedge{transition:opacity .35s}
.gnode.dim,.gedge.dim{opacity:.16}
.gedge.onpath path.v{stroke:#9ffbfc;stroke-width:2.6}
.gedge path.halo{stroke:rgba(62,230,234,.22);stroke-width:8;stroke-linecap:round}
.gnode.onpath rect.box{stroke-width:2.4}
pre.term{position:relative;background:#010605;border-color:rgba(62,230,234,.38);color:#a8fbfc;text-shadow:0 0 6px rgba(62,230,234,.55);
 box-shadow:inset 0 0 34px rgba(62,230,234,.07),0 0 22px rgba(62,230,234,.08);min-height:60px}
pre.term .cmd{color:#6ff0c4}
pre.term .cur{display:inline-block;width:8px;height:14px;margin-left:2px;vertical-align:-2px;background:#3ee6ea;box-shadow:0 0 8px #3ee6ea;animation:caret 1s steps(1) infinite}
.dcore{position:relative;width:44px;height:44px;flex:none;margin-right:4px}
.drawer .hd{justify-content:flex-start}.drawer .hd .btn{margin-left:auto}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}.rv{opacity:1;transform:none;filter:none}}
</style>
</head>
<body class="home">
<nav class="top">
  <a class="logo" href="#/" aria-label="SUTRA-TRACE home">
    <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden="true"><path d="M16 2 L28 7 V16 C28 23 22.5 28 16 30 C9.5 28 4 23 4 16 V7 Z" fill="none" stroke="#3ee6ea" stroke-width="2"/><circle cx="16" cy="15" r="4" fill="#3ee6ea"/><path d="M16 19 V24 M11 12 L8 10 M21 12 L24 10" stroke="#3ee6ea" stroke-width="1.8"/></svg>
    <span><b>SUTRA</b>-TRACE</span></a>
  <div class="navlinks" id="navlinks"></div>
  <div class="runchip"><span class="dot" id="dot"></span><span class="lbl" id="runlbl">connecting…</span></div>
</nav>
<main>
<!-- ======================= HOME ======================= -->
<section class="page" id="pg-home">
  <div class="hero">
    <div class="rv">
      <div class="eyebrow">SUTRAM 2026 · PS-01</div>
      <h1 class="htitle"><span class="gt">Trace every byte.</span><br><span class="gt">Prove every claim.</span></h1>
      <div class="tag"><b>SUTRA-TRACE</b> · Autonomous Neuro-Symbolic Digital Forensics Framework</div>
      <p>From a seized device to a court-ready Section 63 BSA 2023 certificate. Every finding is tied to the exact bytes it came from, re-hashed live and proved against the evidence vault.</p>
      <div class="cta"><a class="btn primary" href="#/run">Start an investigation</a><a class="btn" href="#/graph">See the attack story</a></div>
      <div class="badges">
        <span class="badge">IGDTUW · MeitY ISEA Phase-III · NFSU Gandhinagar Lead Partner</span>
        <span class="badge">Section 63 BSA 2023 &amp; Section 105/106 BNSS</span>
        <span class="badge">Zero-egress · air-gapped · runs on a 16 GB police laptop</span>
      </div>
    </div>
    <div class="scene" aria-hidden="true">
      <svg class="ridge" viewBox="0 0 800 170" preserveAspectRatio="none"><defs><linearGradient id="rg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#1a2629"/><stop offset=".45" stop-color="#070b0c"/><stop offset="1" stop-color="#000"/></linearGradient>
        <linearGradient id="rl" x1="0" x2="1"><stop offset="0" stop-color="#3ee6ea" stop-opacity="0"/><stop offset=".5" stop-color="#3ee6ea" stop-opacity=".55"/><stop offset="1" stop-color="#3ee6ea" stop-opacity="0"/></linearGradient></defs>
        <path d="M0 150 C80 140 120 118 190 112 C250 106 270 84 330 78 C370 74 392 52 430 50 C470 48 500 74 540 82 C600 92 640 104 700 120 C740 130 770 140 800 146 V170 H0 Z" fill="url(#rg)"/>
        <path d="M0 150 C80 140 120 118 190 112 C250 106 270 84 330 78 C370 74 392 52 430 50 C470 48 500 74 540 82 C600 92 640 104 700 120 C740 130 770 140 800 146" fill="none" stroke="url(#rl)" stroke-width="1.2"/></svg>
      <div class="mist"></div>
      <canvas class="holo" id="holoHero"></canvas><canvas class="holofx" id="holoHeroFx" title="Drag to spin the evidence core; click a node to open that sector"></canvas>
      <div class="bot" id="heroBot"><div class="eyes"><i class="eye"></i><i class="eye"></i></div></div>
      <div class="bubble" id="heroBubble"><span class="tx"></span><span class="caret"></span></div>
    </div>
  </div>
  <div class="scrollcue">scroll</div>
  <section class="band rv">
    <div class="center"><div class="eyebrow">This run, live</div><h2 class="mono-h">Byte-anchored. Air-gapped. Court-ready.</h2>
      <p class="lead">Every number below comes from the pipeline that just ran on this laptop.</p></div>
    <div class="bento" id="homeStats"></div>
  </section>
  <section class="band rv">
    <div class="ph" data-ghost="SECTORS"><div><div class="eyebrow">Sectors</div><h2 class="mono-h">What each sector does</h2><p class="lead">From seizure to signature: open any sector to see its evidence.</p></div></div>
    <div class="flow" id="feats"></div>
  </section>
  <section class="band rv">
    <div class="center"><div class="eyebrow">Pipeline</div><h2 class="mono-h">How it fits together</h2><p class="lead">Each sector hands the next one evidence it can re-check. Click a node to jump there.</p></div>
    <div id="hub"></div>
  </section>
  <section class="band rv center">
    <h2 class="mono-h">Let's crack the case</h2>
    <p class="lead">Run the whole pipeline again from scratch and watch every sector report in.</p>
    <div class="cta jc"><a class="btn primary" href="#/run">Start an investigation</a></div>
  </section>
</section>

<!-- ======================= RUN ======================= -->
<section class="page" id="pg-run">
  <div class="ph" data-ghost="RUN"><div><div class="eyebrow">Mission control</div><h1>Run the investigation</h1>
    <p class="lead">One click runs every sector for real: Sector A vaults the evidence, B triages it, C builds the attack graph and D drafts the court documents. Nothing here is pre-filled.</p></div></div>
  <div class="grid g73">
    <div class="card"><div class="launch"><div class="launchcore"><canvas class="holo" id="holoRun"></canvas><canvas class="holofx" id="holoRunFx"></canvas><button class="lbtn" id="btnRun"><span class="ring"></span><span id="btnRunTxt">RUN<br>PIPELINE</span></button></div>
      <div class="small muted" id="runNote">The last completed run is shown below.</div></div></div>
    <div class="card"><h2>Active case</h2><div id="caseCard">Loading…</div></div>
  </div>
  <h3 class="eyebrow mt">Pipeline stages</h3>
  <div class="stages" id="stages"></div>
  <div class="grid g5 mt" id="kpis"></div>
  <div class="card mt"><h2>Where to next</h2><div class="grid g3" id="nextCards"></div></div>
</section>

<!-- ======================= VAULT ======================= -->
<section class="page" id="pg-vault">
  <div class="ph" data-ghost="VAULT"><div><div class="eyebrow">Sector A · Evidence vault</div><h1>Evidence integrity &amp; custody</h1>
    <p class="lead">Hash receipts for the seized handset image, the Section 105 BNSS seizure recording with its 50 Hz mains-hum continuity check, and the Section 106 BNSS seal chain.</p></div></div>
  <div class="grid g4" id="vaultKpis"></div>
  <div class="grid g73 mt">
    <div class="card"><h2>Hash receipts <span class="sub">each re-checked by Sector D</span></h2><div id="vault"></div></div>
    <div class="stack"><div class="card"><h2>Section 105 BNSS recording</h2><div id="enf"></div></div>
      <div class="card"><h2>Section 106 BNSS seal chain</h2><div id="seals"></div></div></div>
  </div>
  <div class="card mt"><h2>Second exhibit · victim PC disk</h2><div id="pcVault"></div></div>
</section>

<!-- ======================= TRIAGE ======================= -->
<section class="page" id="pg-triage">
  <div class="ph" data-ghost="TRIAGE"><div><div class="eyebrow">Sector B · Neural triage</div><h1>What the evidence flagged</h1>
    <p class="lead">Leads are triage priorities, not proof. Click any lead to open the exact bytes it came from.</p></div></div>
  <div class="grid g4" id="triKpis"></div>
  <div class="card mt"><h2>Lead scores <span class="sub">click a bar for its byte anchor</span></h2><div id="leadBars"></div></div>
  <div class="tabs mt" id="triTabs"></div>
  <div id="triBody"></div>
</section>

<!-- ======================= GRAPH ======================= -->
<section class="page" id="pg-graph">
  <div class="ph" data-ghost="STORY"><div><div class="eyebrow">Sector C · PCST attack storyline</div><h1>How the attack unfolded</h1>
    <p class="lead">The provenance graph and its chronological storyline. Click any node, arrow or step to open the Physical Offset Inspector.</p></div></div>
  <div class="tabs" id="exTabs"></div>
  <div class="muted small" id="exSources"></div>
  <div class="legend" id="legend"></div>
  <div class="graphwrap" id="graph"></div>
  <div class="grid g73 mt">
    <div class="card"><h2>Storyline</h2><div class="stack" id="story"></div></div>
    <div class="stack"><div class="card"><h2>Five-invariant anti-timestomping</h2><div id="timestomp"></div></div>
      <div class="card"><h2>T-PKG graph store</h2><div id="tpkg"></div></div></div>
  </div>
</section>

<!-- ======================= DEFENCE ======================= -->
<section class="page" id="pg-defence">
  <div class="ph" data-ghost="DEFENCE"><div><div class="eyebrow">Section 45 BSA · Trojan-defence screen</div><h1>Could someone else have done it?</h1>
    <p class="lead" id="s45note"></p></div></div>
  <div class="grid g73"><div class="card"><h2>14-point exculpatory intrusion ledger</h2><div id="s45checks"></div></div>
    <div class="stack"><div class="card"><h2>Result mix</h2><div id="s45donut"></div></div><div class="card"><h2>Ratios</h2><div id="s45ratio"></div></div></div></div>
  <div class="card mt"><h2>Defence challenge matrix <span class="sub">Sector C</span></h2><div id="s45matrix"></div></div>
</section>

<!-- ======================= COURT ======================= -->
<section class="page" id="pg-court">
  <div class="ph" data-ghost="COURT"><div><div class="eyebrow">Sector D · Statutory outputs</div><h1>Court-ready documents</h1>
    <p class="lead">The Section 63 BSA 2023 certificate, the FIU-IND suspicious transaction report and the Section 106 BNSS freeze notice, generated from this run.</p></div></div>
  <div id="readyBanner"></div>
  <div class="grid g3" id="dlCards"></div>
  <div class="grid g73 mt"><div class="card"><h2>Certificate verification QR</h2><div id="qrBox"></div></div>
    <div class="card"><h2>Section 106 BNSS freeze notice</h2><div id="freezeBox"></div></div></div>
</section>
<div class="pager" id="pager"></div>
</main>
<footer id="foot"></footer>
<div class="buddy" id="buddy" aria-live="polite"><div class="bot" id="buddyBot" title="Ask Sutra"><div class="eyes"><i class="eye"></i><i class="eye"></i></div></div>
  <div class="bubble hide" id="buddyBubble"><span class="tx"></span><span class="caret"></span></div></div>
<button class="fab" id="chatFab" aria-label="Ask Sutra about this run"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a8 8 0 0 1-11.6 7.1L4 20l1-4.6A8 8 0 1 1 21 12z"/><path d="M9 11h.01M12 11h.01M15 11h.01"/></svg></button>
<section class="chat" id="chat" aria-label="Ask Sutra">
  <div class="chathd"><div class="bot" id="chatBot"><div class="eyes"><i class="eye"></i><i class="eye"></i></div></div><div><b>Ask Sutra</b><span>Answers from this run's data, on this laptop</span></div><button class="x" id="chatClose" aria-label="Close">×</button></div>
  <div class="chatbd" id="chatBody"></div>
  <form class="chatin" id="chatForm"><input id="chatInput" autocomplete="off" placeholder="Ask about this case…" aria-label="Your question"><button type="submit" aria-label="Send"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9-9-4z"/></svg></button></form>
  <div class="chatft">Offline guide · nothing leaves this machine</div>
</section>
<div class="scrim" id="scrim"></div>
<aside class="drawer" id="drawer" aria-label="Physical Offset Inspector"><div class="hd"><span class="dcore" aria-hidden="true"><canvas class="holo" id="holoDrw"></canvas><canvas class="holofx" id="holoDrwFx"></canvas></span><b>Physical Offset Inspector</b><button class="btn plain" id="drawerClose">Close</button></div><div class="bd" id="inspector"></div></aside>
<dialog id="dlg"><div class="hd"><b id="dlgTitle">Freeze notice</b><button class="btn plain" id="dlgClose">Close</button></div><div class="bd" id="dlgBody"></div></dialog>
<div class="toast" id="toast"></div>
<script nonce="__NONCE__">
"use strict";
const $=id=>document.getElementById(id);
function h(tag,attrs,...kids){const e=document.createElement(tag);if(attrs)for(const[k,v]of Object.entries(attrs)){if(v==null||v===false)continue;
 if(k==="cls")e.className=v;else if(k==="on")for(const[ev,fn]of Object.entries(v))e.addEventListener(ev,fn);else e.setAttribute(k,v===true?"":String(v));}
 for(const c of kids.flat(Infinity)){if(c==null||c===false)continue;e.appendChild(c instanceof Node?c:document.createTextNode(String(c)));}return e;}
const NS="http://www.w3.org/2000/svg";
function s(tag,attrs,...kids){const e=document.createElementNS(NS,tag);if(attrs)for(const[k,v]of Object.entries(attrs)){if(v==null)continue;
 if(k==="on")for(const[ev,fn]of Object.entries(v))e.addEventListener(ev,fn);else if(k==="cls")e.setAttribute("class",v);else e.setAttribute(k,String(v));}
 for(const c of kids.flat(Infinity)){if(c==null)continue;e.appendChild(c instanceof Node?c:document.createTextNode(String(c)));}return e;}
function clear(e){while(e.firstChild)e.removeChild(e.firstChild);return e;}
function put2(el,...kids){clear(el);kids.flat(Infinity).forEach(k=>k!=null&&k!==false&&el.appendChild(k instanceof Node?k:document.createTextNode(String(k))));}
function put(id,...kids){put2($(id),...kids);}
function kv(rows){return h("div",{cls:"kv"},rows.filter(Boolean).map(([k,v,mono])=>[h("div",{cls:"k"},k),h("div",{cls:mono?"mono":""},v==null?"—":v)]));}
function pill(text,kind){return h("span",{cls:"pill "+(kind||"info")},text);}
function okPill(ok,yes,no){return pill(ok?yes:no,ok?"ok":"bad");}
function txt(w){return typeof w==="string"?w:(w&&(w.message||w.detail||w.reason))||JSON.stringify(w);}
function warnList(title,ws){ws=ws||[];return ws.length?h("div",{cls:"alert warn"},h("b",null,title),h("ul",{cls:"small"},ws.map(w=>h("li",null,txt(w))))):null;}
function inr(x){if(x==null||isNaN(x))return"—";const n=Math.round(Number(x)*100)/100;let[i,f]=n.toFixed(2).split(".");
 let last=i.slice(-3),rest=i.slice(0,-3);if(rest)last=","+last;rest=rest.replace(/\B(?=(\d{2})+(?!\d))/g,",");return"₹"+rest+last+(f!=="00"?"."+f:"");}
function short(hx,n){if(!hx)return"—";n=n||16;return hx.length>2*n?hx.slice(0,n)+"…"+hx.slice(-8):hx;}
async function j(url,opt){const r=await fetch(url,Object.assign({cache:"no-store"},opt||{}));const t=await r.json();if(!r.ok)throw new Error(t.error||("HTTP "+r.status));return t;}
function toast(msg){const t=$("toast");t.textContent=msg;t.classList.add("on");clearTimeout(toast.t);toast.t=setTimeout(()=>t.classList.remove("on"),2200);}
function copyBtn(text){return h("button",{cls:"copy",title:"Copy",on:{click:ev=>{ev.stopPropagation();try{navigator.clipboard.writeText(text).then(()=>toast("Copied"),()=>toast("Copy blocked by the browser"));}catch(e){toast("Copy unavailable");}}}},"copy");}
function countUp(el,to,dec,suffix){dec=dec||0;suffix=suffix||"";const reduce=window.matchMedia&&matchMedia("(prefers-reduced-motion: reduce)").matches;
 if(reduce||!isFinite(to)){el.textContent=(isFinite(to)?Number(to).toFixed(dec):to)+suffix;return;}const t0=performance.now(),d=900;
 (function f(t){const p=Math.min(1,(t-t0)/d),e=1-Math.pow(1-p,3);el.textContent=(to*e).toFixed(dec)+suffix;if(p<1)requestAnimationFrame(f);})(t0);}
function kpi(label,val,cls,dec,suffix){const v=h("div",{cls:"v"});const c=h("div",{cls:"card kpi "+(cls||"")},v,h("div",{cls:"l"},label));
 if(typeof val==="number")countUp(v,val,dec,suffix);else put2(v,val);return c;}
let S={},GRAPH=null,EX="PC",SEL=null,TRI=null,TRITAB="cmd";

/* ---------------- routing ---------------- */
const PAGES=[["home","Home"],["run","Run"],["vault","Evidence vault"],["triage","Triage"],["graph","Attack story"],["defence","Section 45 defence"],["court","Court outputs"]];
function route(){let p=(location.hash||"#/").replace(/^#\/?/,"").split("/")[0]||"home";if(!PAGES.some(([k])=>k===p))p="home";
 PAGES.forEach(([k])=>$("pg-"+k).classList.toggle("on",k===p));
 put("navlinks",PAGES.map(([k,l])=>h("a",{href:"#/"+(k==="home"?"":k),cls:k===p?"on":""},l)));
 const i=PAGES.findIndex(([k])=>k===p),prev=PAGES[i-1],next=PAGES[i+1];
 put("pager",prev?h("a",{cls:"btn",href:"#/"+(prev[0]==="home"?"":prev[0])},"← "+prev[1]):h("span"),next?h("a",{cls:"btn primary",href:"#/"+next[0]},next[1]+" →"):h("span"));
 document.body.classList.toggle("home",p==="home");window.scrollTo(0,0);if(p==="graph"&&GRAPH)renderGraph();if(typeof speakPage==="function")speakPage();}
window.addEventListener("hashchange",route);

/* ---------------- home ---------------- */
const ICON={vault:"M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z M9 12l2 2 4-4",triage:"M3 12h4l2-6 4 12 2-6h6",
 graph:"M4 6a2 2 0 1 0 4 0a2 2 0 1 0-4 0 M16 6a2 2 0 1 0 4 0a2 2 0 1 0-4 0 M10 18a2 2 0 1 0 4 0a2 2 0 1 0-4 0 M8 6h8 M7 8l4 8 M17 8l-4 8",
 defence:"M12 3v18 M6 21h12 M4 7h16 M7 7l-3 7a3 3 0 0 0 6 0z M17 7l-3 7a3 3 0 0 0 6 0z",court:"M7 3h7l5 5v13H7z M14 3v5h5 M10 13h6 M10 17h6"};
function icon(k){return s("svg",{viewBox:"0 0 24 24",fill:"none",stroke:"currentColor","stroke-width":1.6,"stroke-linecap":"round","stroke-linejoin":"round"},s("path",{d:ICON[k]}));}
const FEATS=[["A","Evidence vault","SHA-256, BLAKE2b and Merkle receipts, seizure video hum check, seal chain","vault","#3ee6ea"],
 ["B","Neural triage","Hidden commands, deepfake video calls, mule-account money trails","triage","#fbbf24"],
 ["C","Attack story","Byte-anchored provenance graph with timestomp repair","graph","#a78bfa"],
 ["45","Defence screen","14 checks against the 'my phone was hacked' defence","defence","#f472b6"],
 ["D","Court outputs","s.63 BSA certificate, FIU-IND STR, s.106 BNSS freeze notice","court","#34d399"]];
put("feats",FEATS.map(([k,t,d,pg,c])=>{const ic=h("div",{cls:"ic"},icon(pg));ic.style.color=c;
 return h("div",{cls:"card feat",role:"link",tabindex:"0",on:{click:()=>{location.hash="#/"+pg;},keydown:e=>{if(e.key==="Enter")location.hash="#/"+pg;}}},h("span",{cls:"go"},"→"),ic,h("div",{cls:"k"},k==="45"?"Section 45":"Sector "+k),h("h3",null,t),h("p",null,d));}));

/* ---------------- run page ---------------- */
const STAGES=[["A_vault_handset","A","Vault handset"],["B_triage_handset","B","Triage"],["C_graph_handset","C","Graph handset"],["D_legal_handset","D","Court documents"],
 ["A_vault_pc","A","Vault PC disk"],["C_graph_pc","C","Graph PC"],["E_views_and_proofs","E","Merkle proofs"]];
function renderStages(t,state){put("stages",STAGES.map(([k,n,l],i)=>{const st=state==="run"?"run":(t&&t[k]!=null?"done":"");
 return h("div",{cls:"stage "+st},h("div",{cls:"n"},"SECTOR "+n),h("div",{cls:"t"},l),h("div",{cls:"ms"},st==="run"?"running…":t&&t[k]!=null?t[k]+" ms":"—"));}));}
function renderRun(st,tri,gr){
 put("caseCard",kv([["Case",h("b",null,st.case_reference+" ("+st.case_title+")")],["Examiner",st.examiner_id],["Workstation",st.workstation],
  ["Exhibits",Object.values(st.exhibits).map(e=>h("div",null,e.title+" · "+e.storyline_steps+" storyline steps"))],
  ["Last run","#"+st.run_id+" finished "+st.run_finished_utc],["Web engine",st.web_backend||"?"]]));
 renderStages(st.timings_ms,"done");
 const leads=(tri.summary_metrics||{}).total_leads,hi=(tri.summary_metrics||{}).high_priority_leads_flagged,steps=gr.exhibits.PC.storyline.length+gr.exhibits.HANDSET.storyline.length;
 const L=st.legal.anchors;
 put("kpis",kpi("pipeline seconds ("+(st.within_demo_target?"within":"over")+" the "+st.demo_target_seconds+" s target)",st.pipeline_seconds,st.within_budget?"c":"r",2," s"),
  kpi("leads flagged ("+hi+" high priority)",leads,"a"),kpi("storyline steps across both exhibits",steps,"v"),
  kpi("byte anchors re-verified by Sector D",h("span",null,L.verified+"",h("small",null," / "+L.total)),"g"),
  kpi("certificate readiness",h("span",{cls:"small"},st.readiness.replace(/_/g," ")),st.readiness==="READY_FOR_SIGNATURE"?"g":st.readiness==="NOT_FIT_FOR_FILING"?"r":"a"));
 put("nextCards",FEATS.map(([k,t,d,pg,c])=>h("a",{cls:"btn",href:"#/"+pg},t+" →")));}
async function rerun(){const b=$("btnRun");if(b.disabled)return;b.disabled=true;holoBusy(true);holoPulse("run");put("btnRunTxt","RUNNING…");$("dot").className="dot busy";put("runNote","Sectors A → B → C → D are running on this laptop now.");say(["Running Sectors A → B → C → D on this laptop…","Hashing, triaging, graphing. Hold tight."],{mood:"think"});
 renderStages(null,"run");
 try{const r=await j("/api/run",{method:"POST",headers:{"X-SUTRA-Action":"run"}});await loadAll();
  put("runNote","Run #"+r.run_id+" finished in "+r.pipeline_seconds.toFixed(2)+" s.");toast("Run #"+r.run_id+" complete");holoBusy(false);holoPulse("ok");const LA=S.status.legal.anchors;say(["Done! Run #"+r.run_id+" finished in "+r.pipeline_seconds.toFixed(2)+" s.",LA.verified+"/"+LA.total+" byte anchors re-verified."],{mood:"happy"});}
 catch(err){holoBusy(false);holoPulse("bad");put("runNote",h("span",{cls:"err"},"Run failed: "+err.message));$("dot").className="dot bad";say(["That run failed: "+err.message],{mood:"alert"});if(S.status)renderStages(S.status.timings_ms,"done");}
 finally{holoBusy(false);b.disabled=false;put("btnRunTxt",h("span",null,"RUN",h("br"),"AGAIN"));}}

/* ---------------- vault ---------------- */
function renderVault(v){S.v=v;
 const e=v.enf||{};const sealsOk=v.seal_chain.filter(c=>c.ok).length;
 put("vaultKpis",kpi("evidence bytes · "+v.filename,v.size_bytes,"c"),kpi("Sector A status",h("span",{cls:"small"},v.admissibility.status.replace(/_/g," ")),v.admissibility.status==="READY_FOR_COURT"?"g":v.admissibility.status==="PROVISIONAL"?"a":"r"),
  kpi("50 Hz mains-hum continuity",h("span",{cls:"small"},e.status||"—"),e.status==="LOCKED_CONTINUOUS"?"g":"r"),kpi("seal-chain points verified",h("span",null,sealsOk+"",h("small",null," / "+v.seal_chain.length)),sealsOk===v.seal_chain.length?"g":"r"));
 put("vault",kv([["Evidence ID",v.evidence_id,1],["Device",v.telemetry.make_model||"—"],["Ingested",v.ingestion_timestamp_utc+" on "+v.workstation]]),
  warnList("Sector A warnings for this exhibit",v.admissibility.warnings),
  h("div",{cls:"stack mt"},v.digests.map(d=>h("div",{cls:"digest"},h("div",null,h("div",{cls:"nm"},d.label),h("div",{cls:"al"},d.algorithm||"")),
   h("div",null,d.sector_d_check?pill(d.sector_d_check.split(" - ")[0],d.sector_d_check.startsWith("MATCH")?"ok":"bad"):null," ",d.value?copyBtn(d.value):null),
   h("div",{cls:"mono"},d.value||"—"),h("div",{cls:"small muted"},d.sector_d_check?d.sector_d_check.split(" - ").slice(1).join(" - "):"")))),
  h("div",{cls:"small muted mt"},"Merkle tree: "+v.merkle.leaves+" leaves of "+v.merkle.sub_block_bytes+" B in "+v.merkle.chunk_roots.length+" chunk(s) of "+(v.merkle.chunk_size_bytes/1048576)+" MiB · bad sectors "+v.bad_sectors.length+" · RFC 3161: "+v.rfc3161+" · NavIC: "+v.navic));
 put("enf",h("div",null,pill("["+(e.status||"—")+"]",e.status==="LOCKED_CONTINUOUS"?"ok":"bad")),enfLive(e),
  kv([["Mean frequency",e.mean_freq_hz+" Hz"],["Max phase jump Δφ",e.max_phase_jump_rad+" rad at "+e.max_jump_at_s+" s"],["Threshold",e.threshold_rad+" rad"],["Hum presence",e.hum_presence_ratio],["Windows analysed",e.windows_analyzed],["Recording",(v.sec105_recording.verified?"verified":"NOT verified")+" · "+v.sec105_recording.audio_decoder]]));
 put("seals",h("div",{cls:"tl"},v.seal_chain.map(c=>h("div",{cls:"it"+(c.ok?" ok":"")},h("b",null,c.point+". "+c.title)," ",okPill(c.ok,"OK","FAIL"),
   h("div",{cls:"small muted"},c.detail),h("div",{cls:"mono"},"h = "+short(c.hash,20))))),
  h("div",{cls:"small"},"Chain head ",h("span",{cls:"mono"},short(v.seal_chain_head,20))," · officer signatures: "+v.seal_signatures));
 const p=v.pc_exhibit;
 put("pcVault",kv([["File",p.filename+" · "+p.size_bytes.toLocaleString("en-IN")+" bytes"],["SHA-256",h("span",null,h("span",{cls:"mono"},p.sha256_linear_primary)," ",copyBtn(p.sha256_linear_primary))],["Merkle root",p.sha256_merkle_root_4mb,1],
  ["Sector A status",pill(p.admissibility,p.admissibility==="READY_FOR_COURT"?"ok":p.admissibility==="PROVISIONAL"?"warn":"bad")]]),warnList("Sector A warnings for the PC exhibit",p.admissibility_warnings),h("div",{cls:"small muted"},p.note));}
function enfGauge(e){const W=320,H=64,thr=e.threshold_rad||0.08,val=e.max_phase_jump_rad||0,max=Math.max(thr*1.5,val*1.1);const x=v=>12+(W-24)*Math.min(v,max)/max;
 return s("svg",{width:"100%",height:H,viewBox:"0 0 "+W+" "+H,role:"img","aria-label":"ENF phase jump gauge"},
  s("rect",{x:12,y:24,width:W-24,height:12,rx:6,fill:"rgba(120,160,230,.14)"}),s("rect",{x:12,y:24,width:x(thr)-12,height:12,rx:6,fill:"rgba(16,185,129,.55)"}),
  s("line",{x1:x(thr),x2:x(thr),y1:16,y2:44,stroke:"#ef4444","stroke-width":2}),s("text",{x:x(thr)-30,y:58,fill:"#fca5a5","font-size":11},"limit "+thr+" rad"),
  s("circle",{cx:x(val),cy:30,r:8,fill:"#e8f0fc",stroke:"#10b981","stroke-width":3}),s("text",{x:12,y:13,fill:"#93a8c9","font-size":11},"measured Δφ "+val+" rad"));}

/* ---------------- triage ---------------- */
function scoreBar(v,col){const i=h("i");i.style.width=Math.round(100*v)+"%";if(col)i.style.background=col;return h("div",{cls:"bar"},i);}
function sevCol(s){return s==="CRITICAL"?"linear-gradient(90deg,#f472b6,#ef4444)":s==="HIGH"?"linear-gradient(90deg,#f59e0b,#ef4444)":"linear-gradient(90deg,#22d3ee,#3b82f6)";}
function anchorLink(a,label){if(!a||!a.source_file)return h("span",{cls:"muted"},"—");return h("a",{href:"#",on:{click:ev=>{ev.preventDefault();showAnchor(label||"Anchor",a);}}},a.source_file+" @ "+a.byte_offset_hex);}
function renderTriage(t){TRI=t;const m=t.summary_metrics||{};
 put("triKpis",kpi("telemetry events scanned",m.total_telemetry_events_scanned||0,"c"),kpi("leads raised",m.total_leads||t.all_leads.length,"a"),kpi("high-priority leads",m.high_priority_leads_flagged||0,"r"),
  kpi("anchors verified at run",h("span",null,t.all_leads.filter(l=>l.anchor.status==="VERIFIED").length+"",h("small",null," / "+t.all_leads.length)),"g"));
 put("leadBars",t.all_leads.slice().sort((a,b)=>b.threat_score-a.threat_score).map(l=>h("div",{cls:"hrow",on:{click:()=>showAnchor(l.lead_id+" · "+l.category,l.anchor)}},
  h("div",null,h("div",{cls:"small"},l.category.replace(/_/g," ")),h("div",{cls:"mono muted"},l.lead_id)),scoreBar(l.threat_score,sevCol(l.severity)),h("div",{cls:"mono"},l.threat_score.toFixed(3)))));
 renderTriTab();}
function renderTriTab(){const t=TRI;if(!t)return;const tabs=[["cmd","Hidden commands"],["deep","Deepfake call"],["money","Money trail"],["all","All leads"]];
 put("triTabs",tabs.map(([k,l])=>h("button",{cls:k===TRITAB?"on":"",on:{click:()=>{TRITAB=k;renderTriTab();}}},l)));
 const B=$("triBody");
 if(TRITAB==="cmd")put2(B,h("div",{cls:"grid g2"},t.lolbins.map(l=>h("div",{cls:"card"},h("h2",null,l.image+" ",h("span",{cls:"sub"},"← "+(l.parent_image||"?"))," ",pill(l.severity,l.threat_score>=0.85?"bad":"warn")),
  h("div",{cls:"small"},"threat score "+l.threat_score.toFixed(4)),scoreBar(l.threat_score,sevCol(l.severity)),h("div",{cls:"small muted mt"},(l.mitre_techniques||[]).join(" · ")),
  h("pre",null,l.command_line),l.decoded_layers.length?[h("div",{cls:"small"},"Decoded ("+l.decoded_layers.map(d=>d.encoding).join(" → ")+")"),h("pre",null,l.decoded_layers.map(d=>d.text).join("\n"))]:null,
  l.encoded_token?h("div",{cls:"small"},"Independent UTF-16LE re-decode ",okPill(l.independent_decode_matches,"matches Sector B","differs")):null,
  h("div",{cls:"small"},"Shannon entropy of "+l.entropy_input+": H = "+l.entropy_bits_per_char+" bits/char ",pill(l.entropy_at_or_above_threshold?"≥ "+l.entropy_threshold:"below "+l.entropy_threshold+" · flagged by indicators",l.entropy_at_or_above_threshold?"bad":"info")),
  h("div",{cls:"small mt"},"Anchor ",anchorLink(l.anchor,l.lead_id))))));
 else if(TRITAB==="deep"){const d=t.deepfake;
  put2(B,h("div",{cls:"grid g2"},h("div",{cls:"card"},h("h2",null,"Pulse-transit test"),d?[h("div",null,pill(d.verdict,d.ptt_in_physiological_window?"ok":"bad")," score "+d.threat_score),pttLive(d),
    kv([["PTT phase delay",d.ptt_delay_ms+" ms"],["Real faces",d.physiological_window_ms[0]+"–"+d.physiological_window_ms[1]+" ms"],["Heart rate",d.heart_rate_bpm+" bpm · pulse SNR "+d.pulse_snr],["Phase jitter",d.subwindow_phase_jitter_rad+" rad"]]),
    h("div",{cls:"small mt"},"Anchor ",anchorLink(d.anchor,d.lead_id))]:h("div",{cls:"muted"},"No deepfake lead in this run."),
    h("h3",null,"2D-DCT spectral decay"),dctBlock(t.dct_spectrum),t.virtual_camera.map(v=>h("div",{cls:"small mt"},pill("virtual camera","warn")," "+v.friendly_name+" · score "+v.threat_score))),
   h("div",{cls:"card"},h("h2",null,"WhatsApp WebRTC caller"),t.webrtc.length?t.webrtc.map(w=>h("div",null,h("div",{cls:"mono"},w.candidate_type+"  "+w.endpoint+"/"+w.transport),h("div",{cls:"small muted"},"base "+w.related_address+" · call "+w.call_id+" at "+w.timestamp_utc),
    w.sec94_requisition?h("details",{open:true},h("summary",null,"Section 94 BNSS CGNAT / IPDR requisition"),h("pre",null,w.sec94_requisition.notice_text),h("div",{cls:"small"},"Addressee: "+w.sec94_requisition.addressee),
     h("ul",{cls:"small"},(w.sec94_requisition.data_sought||[]).map(x=>h("li",null,x)))):null,h("div",{cls:"small"},"Anchor ",anchorLink(w.anchor,w.lead_id)))):h("div",{cls:"muted"},"No srflx candidate in this run."))));}
 else if(TRITAB==="money"){const u=t.upi_smurfing[0];
  put2(B,h("div",{cls:"grid g73"},h("div",{cls:"card"},h("h2",null,"UPI fan-out"),u?[animateFan(fanOut(u),u),kv([["Hub VPA",u.hub_vpa],["Inflow",inr(u.inflow.amount_inr)+" from "+u.inflow.payer_vpa+" (RRN "+u.inflow.rrn+")"],["Dispersal",u.mules.length+" mule VPAs in "+u.dispersal_span_s+" s · ratio "+u.dispersion_ratio]])]:h("div",{cls:"muted"},"No smurfing cluster.")),
   h("div",{cls:"stack"},h("div",{cls:"card"},h("h2",null,"Mirror-hawala note serial"),t.mirror_hawala.length?t.mirror_hawala.map(m=>h("div",null,h("div",{cls:"mono"},m.serial),h("div",{cls:"small muted"},"“"+m.context+"”"),anchorLink(m.anchor,m.lead_id))):h("div",{cls:"muted"},"None found.")),
    h("div",{cls:"card"},h("h2",null,"Cross-chain DeFi bridge"),t.cross_chain_bridge.map(b=>h("div",{cls:"small"},inr(b.upi.amount_inr)+" "+b.upi.payer_vpa+" → "+b.upi.payee_vpa+" ↔ "+b.chain.amount_usdt+" USDT on "+b.chain.chain+" · Δt "+b.delta_t_s+" s ",okPill(b.within_escrow_window,"within 300 s escrow","outside window"))),
     t.invalid_rrn.map(r=>h("div",{cls:"small mt"},pill("invalid RRN","warn")," "+r.rrn+": "+r.reasons.join("; ")))))));}
 else put2(B,h("div",{cls:"card"},h("div",{cls:"scroll"},h("table",null,h("tr",null,["Lead","Category","Score","Severity","MITRE","Anchor (file @ Ω)","Re-hash (at run)","Merkle (at run)"].map(x=>h("th",null,x))),
  t.all_leads.map(l=>h("tr",{cls:"click",on:{click:()=>showAnchor(l.lead_id+" · "+l.category,l.anchor)}},h("td",{cls:"mono"},l.lead_id),h("td",null,l.category),h("td",null,l.threat_score),h("td",null,l.severity),h("td",null,l.mitre||"—"),
   h("td",{cls:"mono"},l.anchor.source_file+" @ "+l.anchor.byte_offset+" ("+l.anchor.byte_offset_hex+")"),h("td",null,okPill(l.anchor.rehash==="MATCH","MATCH",l.anchor.rehash)),
   h("td",null,pill(l.anchor.merkle.status,l.anchor.merkle.status==="INCLUSION_VERIFIED"?"ok":l.anchor.merkle.status==="PROOF_FAILED"?"bad":l.anchor.merkle.status==="INCLUSION_SAMPLED"?"warn":"info"))))))));}
function pttGauge(d){const W=340,H=70,lo=-10,hi=60,x=v=>14+(W-28)*(Math.max(lo,Math.min(hi,v))-lo)/(hi-lo);
 return s("svg",{width:"100%",height:H,viewBox:"0 0 "+W+" "+H,role:"img","aria-label":"Pulse transit time gauge"},
  s("rect",{x:14,y:26,width:W-28,height:12,rx:6,fill:"rgba(120,160,230,.14)"}),
  s("rect",{x:x(d.physiological_window_ms[0]),y:26,width:x(d.physiological_window_ms[1])-x(d.physiological_window_ms[0]),height:12,rx:3,fill:"rgba(16,185,129,.6)"}),
  s("text",{x:x(d.physiological_window_ms[0]),y:18,fill:"#6ee7b7","font-size":11},"real arterial transit 12–45 ms"),
  s("line",{x1:x(0),x2:x(0),y1:20,y2:46,stroke:"#ef4444","stroke-dasharray":"3 2"}),s("text",{x:x(0)-6,y:58,fill:"#fca5a5","font-size":11},"≈0 ms shader"),
  s("circle",{cx:x(d.ptt_delay_ms),cy:32,r:8,fill:"#e8f0fc",stroke:"#ef4444","stroke-width":3}),s("text",{x:x(d.ptt_delay_ms)+12,y:68,fill:"#e8f0fc","font-size":11},"measured "+d.ptt_delay_ms+" ms"));}
function dctBlock(c){if(!c||c.status!=="RUN")return h("div",{cls:"small muted"},c?c.reason:"—");
 const W=300,H=110,a=c.spectral_alpha||2,pts=[];for(let i=1;i<=40;i++){const f=i/40;pts.push([12+(W-24)*f,H-14-(H-28)*Math.min(1,Math.pow(f,-a)/Math.pow(1/40,-a))]);}
 return h("div",null,s("svg",{width:"100%",height:H,viewBox:"0 0 "+W+" "+H},s("polyline",{points:pts.map(p=>p.join(",")).join(" "),fill:"none",stroke:"#22d3ee","stroke-width":2}),
   s("text",{x:14,y:12,fill:"#93a8c9","font-size":10},"fitted E(f) ∝ f^-"+a)),kv([["Verdict",c.verdict],["HF excess",c.hf_energy_excess_ratio+" (threshold "+c.hf_threshold_applied+")"],["Nyquist peak",c.nyquist_peak_excess_ratio+" (threshold "+c.nyquist_peak_threshold_applied+")"],["QP",c.qp_estimate+" · relaxation "+c.qp_relaxation_factor]]));}
function fanOut(u){const W=420,H=260,hub=[190,130],src=[40,130];const g=s("svg",{width:"100%",viewBox:"0 0 "+W+" "+H,role:"img","aria-label":"UPI fan-out"});
 g.appendChild(s("defs",null,s("marker",{id:"ar",viewBox:"0 0 10 10",refX:9,refY:5,markerWidth:6,markerHeight:6,orient:"auto-start-reverse"},s("path",{d:"M0,0L10,5L0,10z",fill:"#f59e0b"}))));
 g.appendChild(s("path",{d:"M"+(src[0]+24)+","+src[1]+" L"+(hub[0]-42)+","+hub[1],stroke:"#22d3ee","stroke-width":3,fill:"none","marker-end":"url(#ar)",cls:"flowline"}));
 g.appendChild(s("text",{x:80,y:118,fill:"#93c5fd","font-size":11},inr(u.inflow.amount_inr)));
 const n=u.outflows.length;u.outflows.forEach((o,i)=>{const y=28+i*(H-56)/Math.max(1,n-1),x=318;
  g.appendChild(s("path",{d:"M"+(hub[0]+42)+","+hub[1]+" C"+(hub[0]+80)+","+hub[1]+" "+(x-80)+","+y+" "+(x-58)+","+y,fill:"none",stroke:"#f59e0b","stroke-width":2.2,"marker-end":"url(#ar)","stroke-dasharray":"6 5",cls:"flowline"}));
  g.appendChild(s("rect",{x:x-56,y:y-17,width:154,height:34,rx:9,fill:"rgba(120,72,6,.35)",stroke:"#f59e0b",cls:"mule"}));
  g.appendChild(s("text",{x:x-48,y:y-2,fill:"#fde68a","font-size":11.5},o.payee_vpa));
  g.appendChild(s("text",{x:x-48,y:y+12,fill:"#fcd34d","font-size":10},inr(o.amount_inr)+" · +"+o.seconds_after_inflow+" s"));});
 g.appendChild(s("circle",{cx:src[0],cy:src[1],r:24,fill:"rgba(8,145,178,.3)",stroke:"#22d3ee","stroke-width":2}));g.appendChild(s("text",{x:src[0],y:src[1]+4,"text-anchor":"middle",fill:"#e8f0fc","font-size":10.5},"victim"));
 g.appendChild(s("text",{x:src[0]-30,y:src[1]+42,fill:"#93c5fd","font-size":10},u.inflow.payer_vpa));
 g.appendChild(s("rect",{x:hub[0]-42,y:hub[1]-24,width:84,height:48,rx:12,fill:"rgba(127,29,29,.45)",stroke:"#ef4444","stroke-width":2}));
 g.appendChild(s("text",{x:hub[0],y:hub[1]-4,"text-anchor":"middle",fill:"#fecaca","font-size":12,"font-weight":700},"HUB"));g.appendChild(s("text",{x:hub[0],y:hub[1]+12,"text-anchor":"middle",fill:"#fecaca","font-size":10},u.hub_vpa));
 g.appendChild(s("text",{x:130,y:H-6,fill:"#93a8c9","font-size":11},n+" mules in "+u.dispersal_span_s+" s"));return g;}

/* ---------------- graph ---------------- */
const KIND_COLOR={IDENTITY:"#a78bfa",PROCESS:"#22d3ee",FILE:"#f59e0b",SOCKET:"#ef4444",UPI_ACCOUNT:"#10b981",DEVICE:"#64748b",APP_PACKAGE:"#2dd4bf",CALL_SESSION:"#f472b6",REGISTRY_KEY:"#eab308",HOST:"#94a3b8"};
function kc(k){return KIND_COLOR[k]||"#94a3b8";}
function layout(ex){const nodes=ex.nodes.map(n=>Object.assign({},n)),byId={};nodes.forEach(n=>byId[n.id]=n);
 const steps=ex.edges.filter(e=>e.kind==="step").sort((a,b)=>a.step-b.step);
 nodes.forEach(n=>n.col=0);for(let it=0;it<nodes.length;it++){let ch=false;steps.forEach(e=>{const a=byId[e.source],b=byId[e.target];if(b.col<=a.col&&b.first_step>=e.step){b.col=a.col+1;ch=true;}});if(!ch)break;}
 ex.edges.filter(e=>e.kind!=="step").forEach(e=>{const a=byId[e.source],b=byId[e.target];if(a.first_step==null&&b.first_step!=null)a.col=Math.max(0,b.col-1);});
 const kinds=[...new Set(nodes.map(n=>n.kind))].sort((a,b)=>Object.keys(KIND_COLOR).indexOf(a)-Object.keys(KIND_COLOR).indexOf(b));
 const lanes=[];kinds.forEach(k=>{const inK=nodes.filter(n=>n.kind===k);const perCol={};inK.forEach(n=>{perCol[n.col]=(perCol[n.col]||0)+1;n.sub=perCol[n.col]-1;});lanes.push({kind:k,depth:Math.max(...Object.values(perCol))});});
 let y=40;lanes.forEach(l=>{l.y=y;y+=l.depth*62+20;});const laneY={};lanes.forEach(l=>laneY[l.kind]=l.y);
 const CW=200;nodes.forEach(n=>{n.x=24+n.col*CW;n.y=laneY[n.kind]+n.sub*62;});
 return{nodes,byId,lanes,W:48+(Math.max(...nodes.map(n=>n.col))+1)*CW,H:y+10};}
function renderGraph(){const ex=GRAPH.exhibits[EX];put("exSources",ex.title+" · "+ex.sources);
 put("exTabs",Object.keys(GRAPH.exhibits).map(k=>h("button",{cls:k===EX?"on":"",on:{click:()=>{EX=k;SEL=null;renderGraph();}}},GRAPH.exhibits[k].title+" · "+GRAPH.exhibits[k].storyline.length+" steps")));
 const L=layout(ex);put("legend",[...new Set(ex.nodes.map(n=>n.kind))].map(k=>{const i=h("i");i.style.background=kc(k);return h("span",null,i,k.replace(/_/g," "));}),h("span",null,"· dashed grey = identity binding · amber = timestomped"));
 const P=causalPath(ex,SEL),same=GV.key===EX&&GV.vb;GV.path=P;GV.L=L;
 const g=s("svg",{viewBox:same?GV.vb.x+" "+GV.vb.y+" "+GV.vb.w+" "+GV.vb.h:"0 0 "+L.W+" "+L.H,role:"img","aria-label":"Attack graph: drag to pan, scroll to zoom, double-click to fit"});
 g.appendChild(s("defs",null,s("marker",{id:"ah",viewBox:"0 0 10 10",refX:10,refY:5,markerWidth:7,markerHeight:7,orient:"auto-start-reverse"},s("path",{d:"M0,0L10,5L0,10z",fill:"#cbd5e1"})),
  s("filter",{id:"glow",x:"-30%",y:"-30%",width:"160%",height:"160%"},s("feGaussianBlur",{stdDeviation:"4",result:"b"}),s("feMerge",null,s("feMergeNode",{in:"b"}),s("feMergeNode",{in:"SourceGraphic"})))));
 L.lanes.forEach(l=>{g.appendChild(s("rect",{x:4,y:l.y-22,width:L.W-8,height:l.depth*62+16,rx:12,fill:"rgba(62,230,234,.025)"}));g.appendChild(s("text",{x:12,y:l.y-8,fill:kc(l.kind),"font-size":10.5,"font-weight":700,opacity:.8},l.kind.replace(/_/g," ")));});
 const NW=160,NH=40,fan={};
 ex.edges.forEach(e=>{const a=L.byId[e.source],b=L.byId[e.target];const k=fan[e.source]=(fan[e.source]||0)+1;const x1=a.x+NW,y1=a.y+NH/2,x2=b.x,y2=b.y+NH/2;
  let d;if(b.x>a.x){const mx=(x1+x2)/2;d="M"+x1+","+y1+" C"+mx+","+y1+" "+mx+","+y2+" "+(x2-2)+","+y2;}else{const up=Math.min(a.y,b.y)-20;d="M"+(a.x+NW/2)+","+a.y+" C"+(a.x+NW/2)+","+up+" "+(b.x+NW/2)+","+up+" "+(b.x+NW/2)+","+(b.y-2);}
  const col=e.kind==="binding"?"#64748b":(e.flags||[]).includes("TIMESTOMP_INVERTED")?"#f59e0b":"#cbd5e1";
  const grp=s("g",{cls:"gedge"+(e.kind==="binding"?" bind":"")+(SEL===e.id?" sel":"")+(P?(P.E.has(e.id)?" onpath":" dim"):""),on:{click:()=>selectEdge(e.id)}},s("title",null,e.narrative||""),s("path",{d,fill:"none",stroke:"transparent","stroke-width":14}),
   P&&P.E.has(e.id)?s("path",{cls:"halo",d,fill:"none"}):null,s("path",{cls:"v",d,fill:"none",stroke:col,"stroke-width":1.9,"marker-end":"url(#ah)"}));
  if(e.step!=null){const mx=(b.x>a.x?(x1+x2)/2:(a.x+b.x+NW)/2)+(k-1)*14,my=b.x>a.x?(y1+y2)/2:Math.min(a.y,b.y)-16;grp.appendChild(s("circle",{cx:mx,cy:my,r:10,fill:"#020505",stroke:col,"stroke-width":1.5}));grp.appendChild(s("text",{x:mx,y:my+3.8,fill:"#e8f0fc","font-size":10.5,"text-anchor":"middle","font-weight":700},e.step));}
  g.appendChild(grp);});
 L.nodes.forEach(n=>{const lab=n.label.length>25?n.label.slice(0,23)+"…":n.label;
  g.appendChild(s("g",{cls:"gnode"+(SEL===n.id?" sel":"")+(P?(P.N.has(n.id)?" onpath":" dim"):""),on:{click:()=>selectNode(n.id)}},s("title",null,n.kind+": "+n.label),
   s("rect",{x:n.x,y:n.y,width:NW,height:NH,rx:11,fill:"rgba(3,7,8,.96)",stroke:kc(n.kind),"stroke-width":1.7,cls:"box",filter:SEL===n.id?"url(#glow)":null}),
   s("circle",{cx:n.x+13,cy:n.y+NH/2,r:5,fill:kc(n.kind)}),
   s("text",{x:n.x+24,y:n.y+17,fill:"#e8f0fc","font-size":11.5,"font-weight":600},lab),s("text",{x:n.x+24,y:n.y+31,fill:"#93a8c9","font-size":9.5},n.kind.replace(/_/g," ")+(n.prize?" · prize "+Number(n.prize).toFixed(2):""))));});
 put("graph",graphTools(),g,h("div",{cls:"ghint"},"drag to pan · scroll to zoom · double-click to fit"));GV.svg=g;bindPanZoom(g);
 {const asp=vbAspect();if(!same||Math.abs((GV.asp||0)-asp)>0.02){GV.key=EX;GV.asp=asp;setVB(P?fitVB(pathBox(L,P),48):initVB());}else setVB(GV.vb);}
 put("story",ex.edges.filter(e=>e.kind==="step").sort((a,b)=>a.step-b.step).map(e=>h("div",{cls:"story"+(SEL===e.id?" sel":"")+((e.flags||[]).includes("TIMESTOMP_INVERTED")?" ts":""),on:{click:()=>selectEdge(e.id)}},
  h("div",{cls:"num"},e.step),h("div",{cls:"what"},e.narrative),
  h("div",{cls:"meta"},h("span",{cls:"mono"},e.timestamp_utc||"time unknown"),e.mitre?pill(e.mitre,"violet"):null,pill(e.relation.replace(/_/g," "),"info")),
  h("div",{cls:"meta"},okPill(e.anchor.status==="VERIFIED","anchor verified",e.anchor.status),h("span",{cls:"mono"},e.anchor.source_file+" @ Ω="+e.anchor.byte_offset+" ("+e.anchor.byte_offset_hex+")"),h("span",null,"· "+e.anti_timestomp)))));
 const ts=ex.anti_timestomp,c=ts.causality||{};
 put("timestomp",ts.findings.length?h("div",{cls:"hscroll"},h("table",null,h("tr",null,["Inv.","Rule","Grade","File"].map(x=>h("th",null,x))),ts.findings.map(f=>h("tr",null,h("td",null,f.invariant),h("td",{cls:"mono"},f.rule),h("td",null,pill(f.grade,f.grade==="PROVEN"?"bad":"warn")),h("td",{cls:"mono"},f.path||f.source_file))))):h("div",{cls:"muted small"},"No NTFS timestamp sources in this exhibit, so no findings."),
  kv([["Causality",(c.paradoxes_detected||0)+" inversion(s) found · "+(c.repaired||0)+" repaired · "+(c.unresolved||0)+" unresolved"],["Journal append-only",ts.journal_append_only_ok==null?"n/a":String(ts.journal_append_only_ok)],["Audit ledger",(ts.audit_ledger_count||0)+" entries · head "+short(ts.audit_ledger_head_sha256,12)]]),
  (c.paradoxes||[]).map(p=>h("div",{cls:"small mt"},pill(p.rule,"warn")," "+p.parent+" → "+p.child+": recorded "+p.recorded_utc+", repaired to not before "+p.repaired_utc+" ("+p.basis+")")));
 const st=ex.t_pkg.statistics||{};
 put("tpkg",kv([["Edges exported",ex.t_pkg.edges_total+" ("+ex.t_pkg.edges_anchored+" with a byte anchor)"],["Edge record",st.edge_record_bytes+" bytes · arena "+(st.arena_bytes||0).toLocaleString("en-IN")+" B"],["Anchors re-hashed by C",st.anchors_reverified+" · "+st.anchor_verification],["Graph SHA-256",ex.t_pkg.graph_sha256,1],["Storyline SHA-256",ex.storyline_sha256,1],["Solver",(ex.solver||{}).algorithm]]),
  (ex.warnings||[]).map(w=>h("div",{cls:"small mt"},pill("warning","warn")," "+w)));}
function selectEdge(id){SEL=id;const ex=GRAPH.exhibits[EX],e=ex.edges.find(x=>x.id===id);if(!e)return;renderGraph();focusPath();
 openDrawer(h("div",null,h("div",{cls:"eyebrow"},e.step!=null?"Storyline step "+e.step:"Identity binding"),h("h3",null,e.narrative),
  h("div",{cls:"small muted"},e.relation+" · "+(e.timestamp_utc||"time unknown")+" ("+e.timestamp_basis+") · "+(e.mitre||"no MITRE mapping")),
  h("div",{cls:"small"},"Anti-timestomping: "+e.anti_timestomp),e.timestamp_repair?h("div",{cls:"small"},"Recorded "+e.timestamp_repair.recorded_utc+" → "+e.timestamp_repair.semantics+" "+e.timestamp_repair.repaired_utc+" from "+e.timestamp_repair.basis_anchor.source_file+" @ "+e.timestamp_repair.basis_anchor.byte_offset):null),
  anchorDetail(e.anchor),e.secondary_anchors.map(x=>[h("h3",null,"Secondary anchor · "+x.name),anchorDetail(x.anchor)]));}
function selectNode(id){SEL=id;renderGraph();focusPath();const ex=GRAPH.exhibits[EX],n=ex.nodes.find(x=>x.id===id);const inc=ex.edges.filter(e=>e.source===id||e.target===id);
 openDrawer(h("div",null,h("div",{cls:"eyebrow"},n.kind.replace(/_/g," ")),h("h3",null,n.label),h("div",{cls:"small muted"},(n.prize!=null?"PCST prize "+n.prize+" · ":"")+inc.length+" storyline edge(s)")),
  h("table",null,inc.map(e=>h("tr",{cls:"click",on:{click:()=>selectEdge(e.id)}},h("td",null,e.step!=null?"#"+e.step:"bind"),h("td",null,e.narrative),h("td",{cls:"mono"},e.anchor.source_file+" @ "+e.anchor.byte_offset_hex)))),
  inc[0]?anchorDetail(inc[0].anchor):null);}

/* ---------------- inspector ---------------- */
function openDrawer(...kids){put("inspector",...kids);if(curPage()!=="home")say(["These are the exact bytes behind that claim.","Re-reading them from disk right now…"],{mood:"think"});$("drawer").classList.add("on");$("scrim").classList.add("on");}
function closeDrawer(){$("drawer").classList.remove("on");$("scrim").classList.remove("on");}
function showAnchor(title,a){openDrawer(h("h3",null,title),anchorDetail(a));}
function merkleText(m){if(!m||!m.status)return h("span",{cls:"muted"},"—");
 if(m.status==="NOT_IN_VAULTED_IMAGE")return h("span",null,pill(m.status,"info")," ",h("span",{cls:"small muted"},m.note||""));
 const kind=m.status==="INCLUSION_VERIFIED"?"ok":m.status==="INCLUSION_SAMPLED"?"warn":"bad";
 return h("span",null,pill(m.status.replace(/_/g," "),kind)," "+m.proved+"/"+m.checked+" proof(s) for sub-block(s) "+m.sub_blocks[0]+"–"+m.sub_blocks[1]+
  (m.sampled?" (sampled: first and last sub-block of each 4 MB chunk; "+m.needed+" spanned)":"")+" across "+(m.chunks_spanned||[]).length+" chunk(s), root ",h("span",{cls:"mono"},short(m.root,12)),
  (m.failed_sub_blocks||[]).length?h("div",{cls:"small err"},"failed sub-block(s): "+m.failed_sub_blocks.join(", ")):null);}
function chunkRows(m){const cs=(m&&m.chunks_spanned)||[];if(!cs.length)return null;
 return h("div",{cls:"hscroll"},h("table",null,h("tr",null,["4 MB chunk","Sub-blocks","Proved","First leaf · audit path","Last leaf · audit path"].map(x=>h("th",null,x))),
  cs.map(c=>h("tr",null,h("td",null,c.chunk_index),h("td",null,c.first_sub_block+"–"+c.last_sub_block),h("td",null,c.proved+"/"+c.checked),
   h("td",{cls:"mono"},short(c.first_leaf_hash,10)+" · "+(c.first_audit_path||[]).length+" sib."),h("td",{cls:"mono"},short(c.last_leaf_hash,10)+" · "+(c.last_audit_path||[]).length+" sib.")))));}
function anchorDetail(a){if(!a||!a.source_file)return h("div",{cls:"muted"},"No anchor.");const m=a.merkle||{};
 const live=h("div",{cls:"live"});
 const box=h("div",null,kv([["Target file",a.source_file+" ("+(a.source_type||"")+")"],["Physical offset Ω",a.byte_offset+" (dec) · "+a.byte_offset_hex+" (hex) → "+a.end_offset_hex,1],["Length",a.length+" bytes"],
  ["Disk sector Ω // 512",a.sector_512+(a.sector_512_last!==a.sector_512?" – "+a.sector_512_last:"")+" · 4 KB sector "+a.sector_4096+" · 1 KB sub-block "+a.sub_block_1k],
  ["Record SHA-256",a.sha256_recorded,1],
  ["Re-hashed at run",h("span",null,okPill(a.rehash==="MATCH","MATCH",a.rehash)," ",h("span",{cls:"mono"},short(a.sha256_now,20)),h("span",{cls:"small muted"}," · snapshot "+(a.verified_at_utc||"")))],
  ["Merkle at run (Sector A)",merkleText(m)]]),chunkRows(m),
  live,a.text_preview?h("pre",null,a.text_preview):null,a.hexdump&&a.hexdump.length?termHex(a):null);
 liveVerify(a,live);return box;}
async function liveVerify(a,el){
 if(!a.anchor_id||!a.exhibit){put2(el,h("span",{cls:"small muted"},"Live re-verification unavailable for this anchor."));return;}
 put2(el,h("span",{cls:"small muted"},"Live re-verification: reading "+a.length+" bytes of "+a.source_file+" from disk now…"));
 holoBusy(true);
 try{const r=await j("/api/verify_anchor?exhibit="+encodeURIComponent(a.exhibit)+"&id="+encodeURIComponent(a.anchor_id)+"&run="+encodeURIComponent(S.status?S.status.run_id:""));
  const ok=r.status==="VERIFIED",lbl=ok?"VERIFIED NOW":r.rehash==="MISMATCH"?"TAMPERED / MISMATCH":r.rehash==="UNREADABLE"?"EVIDENCE UNREADABLE":r.status.replace(/_/g," ");
  el.className="live"+(ok?"":" alert");holoBusy(false);holoPulse(ok?"ok":r.status==="VERIFIED_MERKLE_SAMPLED"?"run":"bad");if(ok)say(["Verified just now: the bytes on disk still match."],{mood:"happy"});else say(["Careful! The bytes on disk no longer match this run."],{mood:"alert"});
  put2(el,kv([["Live re-verification",h("span",null,pill(lbl,ok?"ok":r.status==="VERIFIED_MERKLE_SAMPLED"?"warn":"bad")," at "+r.verified_at_utc+" (run #"+r.run_id+")")],
   ["Re-hashed now",h("span",null,okPill(r.rehash==="MATCH","MATCH",r.rehash)," ",h("span",{cls:"mono"},short(r.sha256_now,20)))],
   ["Merkle now",merkleText(r.merkle)]]),
   ok?null:h("div",{cls:"small"},"The bytes on disk no longer match what this run recorded. The run snapshot above is historical; treat this anchor as unverified until the evidence is re-imaged and the pipeline re-run."));}
 catch(err){holoBusy(false);el.className="live alert warn";put2(el,h("div",{cls:"small"},"Live re-verification could not run: "+err.message));}}

/* ---------------- section 45 ---------------- */
function renderS45(x){S.x=x;const res=r=>r==="SUPPORTS_ATTRIBUTION"?"info":r==="SUPPORTS_INTRUSION_HYPOTHESIS"?"violet":"warn";
 $("s45note").textContent=x.judicial_note;
 const openCh=Object.values(x.defense_challenge_matrix||{}).reduce((n,m)=>n+(m?m.rows.filter(r=>r.status==="OPEN").length:0),0);
 put("s45checks",x.needs_reconciliation?h("div",{cls:"alert warn"},h("b",null,"Examiner reconciliation required"),
   h("div",{cls:"small"},x.supports_intrusion_hypothesis+" indicator(s) support the intrusion hypothesis and "+(x.checks_evaluated-x.checks_determined)+" are undetermined; the examiner must address each in testimony (Section 45 BSA 2023).")):null,
  openCh?h("div",{cls:"alert warn"},h("b",null,openCh+" defence challenge(s) still OPEN"),h("div",{cls:"small"},"See the defence challenge matrix below.")):null,
  h("div",{cls:"checks"},x.checks.map((c,i)=>h("div",{cls:"chk "+c.result},h("div",{cls:"i"},i+1),h("div",null,h("div",{cls:"mono small"},c.check),h("div",{cls:"small"},c.question),h("div",null,pill(c.result.replace(/_/g," "),res(c.result))))))),
  x.examiner_reconciliation?h("details",{open:!!x.needs_reconciliation,cls:"mt"},h("summary",null,"Examiner reconciliation (required where indicators favour intrusion or are undetermined)"),h("pre",null,x.examiner_reconciliation)):null,
  h("details",null,h("summary",null,"Method note"),h("pre",null,x.method_note)));
 const att=x.supports_attribution||0,intr=x.supports_intrusion_hypothesis||0,und=(x.checks_evaluated||0)-(x.checks_determined||0);
 put("s45donut",donut([[att,"#3b82f6","support attribution"],[intr,"#8b5cf6","support intrusion"],[und,"#f59e0b","undetermined"]],x.checks_evaluated));
 put("s45ratio",kv([["Statute",x.statute],["Session",x.session_class+" · logon type "+x.logon_type],["Trojan-defence field",String(x.trojan_defense_probability)+" (intrusion / determined)"],["Exculpatory indicator ratio",x.ratio_display]]),
  h("div",{cls:"legend"},h("span",null,"These are neutral categories; neither is an error or a pass.")));
 put("s45matrix",Object.entries(x.defense_challenge_matrix).map(([k,m])=>m?h("details",{open:true},h("summary",null,(GRAPH?GRAPH.exhibits[k].title:k)+(m.rows.some(r=>r.status==="OPEN")?" · "+m.rows.filter(r=>r.status==="OPEN").length+" open":"")),
  h("div",{cls:"hscroll"},h("table",null,h("tr",null,["ID","Challenge","Status","Basis"].map(t=>h("th",null,t))),m.rows.map(r=>h("tr",null,h("td",null,r.id),h("td",null,r.challenge),h("td",null,pill(r.status,r.status==="REBUTTED"?"ok":r.status==="OPEN"?"warn":"info")),h("td",{cls:"small"},r.basis)))))):null));}
function donut(parts,total){const R=62,C=2*Math.PI*R;let off=0;const g=s("svg",{width:"100%",height:190,viewBox:"0 0 360 190",role:"img","aria-label":"Indicator results"});
 g.appendChild(s("circle",{cx:95,cy:95,r:R,fill:"none",stroke:"rgba(120,160,230,.12)","stroke-width":22}));
 parts.forEach(([v,c])=>{if(!v)return;const len=C*v/total;const arc=s("circle",{cx:95,cy:95,r:R,fill:"none",stroke:c,"stroke-width":22,"stroke-dasharray":len+" "+(C-len),"stroke-dashoffset":-off,transform:"rotate(-90 95 95)"});off+=len;g.appendChild(arc);});
 g.appendChild(s("text",{x:95,y:92,"text-anchor":"middle",fill:"#e8f0fc","font-size":26,"font-weight":800},total));g.appendChild(s("text",{x:95,y:112,"text-anchor":"middle",fill:"#93a8c9","font-size":11},"indicators"));
 parts.forEach(([v,c,l],i)=>{g.appendChild(s("rect",{x:190,y:50+i*34,width:14,height:14,rx:4,fill:c}));g.appendChild(s("text",{x:212,y:62+i*34,fill:"#e8f0fc","font-size":13},v+"  "+l));});return g;}

/* ---------------- court ---------------- */
function renderCourt(st){const L=st.legal,f=L.files||{},blk=st.readiness_blocking||[],notes=st.readiness_notes||[];
 const rk=st.readiness==="READY_FOR_SIGNATURE"?"ok":st.readiness==="NOT_FIT_FOR_FILING"?"bad":"warn";
 put("readyBanner",h("div",{cls:"card"},h("div",{cls:"flex"},h("div",null,h("div",{cls:"eyebrow"},"Certificate readiness"),h("div",null,pill(st.readiness.replace(/_/g," "),rk))),
   h("div",{cls:"small muted"},"Track "+L.track+" · "+L.scenario+" · anchors re-verified by D: "+L.anchors.verified+"/"+L.anchors.total+" · PDF engine "+L.pdf_engine+" · QR "+L.qr_engine)),
  blk.length?h("div",{cls:"alert"},h("b",null,"Blocking: the certificate is not fit to file until these are resolved"),h("ul",{cls:"small"},blk.map(b=>h("li",null,txt(b))))):null,
  notes.length?h("details",{open:true,cls:"mt"},h("summary",null,notes.length+" readiness note(s)"),h("ul",{cls:"small"},notes.map(n=>h("li",null,txt(n))))):null),h("div",{cls:"mt"}));
 const D=[["📄","Section 63 BSA 2023 certificate","BSA_2023_Sec63_Certificate.pdf","/download/certificate"],["⚡","FIU-IND STR (FINnet 2.0 XML)","FIU_IND_STR_FINnet2.xml","/download/str_xml"],
  ["🔒","Section 106 BNSS freeze notice","BNSS_106_107_Freeze_Notice.json","/download/freeze_notice?attachment=1"]];
 put("dlCards",D.map(([ic,t,n,u])=>h("a",{cls:"card dl",href:u},h("div",{cls:"ic"},ic),h("div",{cls:"t"},t),h("div",{cls:"s"},n+(f[n]?" · "+f[n].bytes.toLocaleString("en-IN")+" B · sha256 "+short(f[n].sha256,10):"")))));
 put("qrBox",h("div",{cls:"flex"},h("img",{cls:"qr",src:"/api/qr?run="+st.run_id,alt:"Section 63 BSA verification QR"}),
  h("div",{cls:"stack"},kv([["Certificate SHA-256",h("span",null,h("span",{cls:"mono"},L.certificate_sha256)," ",copyBtn(L.certificate_sha256))]]),h("details",null,h("summary",null,"QR payload"),h("pre",null,JSON.stringify(L.qr_payload,null,1))),
   h("div",{cls:"small"},"STR schema check ",okPill(!L.str_validation_errors.length,"valid","errors")))));
 put("freezeBox",kv([["Statute",L.freeze_notice.statute],["Aggregate lien",inr(L.freeze_notice.aggregate_lien_inr)+" (cap "+inr(L.freeze_notice.principal_loss_cap_inr)+")"],["Accounts",L.freeze_notice.targets],["Addressees",(L.freeze_notice.addressees||[]).join(", ")]]),
  h("div",{cls:"cta"},h("button",{cls:"btn primary",on:{click:openFreeze}},"🔒 View Section 106 BNSS Freeze Notice")));}
async function openFreeze(){const dlg=$("dlg");put("dlgBody","Loading…");dlg.showModal();
 try{const n=await j("/download/freeze_notice");$("dlgTitle").textContent=n.notice_id+" · "+n.case_reference;
  put("dlgBody",h("pre",null,n.text),h("h3",null,"Lien targets"),h("div",{cls:"hscroll"},h("table",null,h("tr",null,["VPA","Tier","Bank / IFSC","Credited","Out","Lien"].map(x=>h("th",null,x))),
   (n.targets||[]).map(t=>h("tr",null,h("td",{cls:"mono"},t.vpa),h("td",null,t.tier),h("td",null,(t.bank||"")+" / "+(t.ifsc||"")),h("td",null,inr(t.amount_credited_inr)),h("td",null,inr(t.amount_outflow_inr)),h("td",null,inr(t.lien_amount_inr)))))),
   h("p",null,h("a",{href:"/download/freeze_notice?attachment=1"},"Save the notice as JSON")));}
 catch(err){put("dlgBody",h("div",{cls:"err"},String(err)));}}

/* ---------------- load ---------------- */
function renderFoot(st){put("foot",h("div",null,"SUTRA-Trace · Sector E cockpit · SUTRAM 2026 · "+st.cockpit+" · Python "+st.python+" · "+st.statutes.join(" · ")),
  h("div",{cls:"mono"},st.modules.map(m=>"Sector "+m.sector+" "+(m.version||"NOT LOADED")+" sha256 "+short(m.sha256,10)).join("  |  ")));}
async function loadAll(){try{const[st,v,t,g,x]=await Promise.all(["/api/status","/api/vault","/api/triage","/api/graph","/api/exculpatory"].map(u=>j(u)));
 S.status=st;GRAPH=g;if(!GRAPH.exhibits[EX])EX=GRAPH.primary;
 $("dot").className="dot "+(st.health==="OK"?"ok":"bad");$("runlbl").textContent="Run #"+st.run_id+" · "+st.pipeline_seconds.toFixed(2)+" s · "+st.case_reference;
 renderRun(st,t,g);renderVault(v);renderTriage(t);renderS45(x);renderCourt(st);renderFoot(st);renderHomeStats(st,t,g);holoInfo(st,v,t,g);if(!S.spoke){S.spoke=1;if(curPage()!=="home")speakPage();}if(document.getElementById("pg-graph").classList.contains("on"))renderGraph();}
 catch(err){$("dot").className="dot bad";$("runlbl").textContent="load failed: "+err.message;}}
$("btnRun").addEventListener("click",rerun);$("dlgClose").addEventListener("click",()=>$("dlg").close());
$("drawerClose").addEventListener("click",closeDrawer);$("scrim").addEventListener("click",closeDrawer);document.addEventListener("keydown",e=>{if(e.key==="Escape")closeDrawer();});

/* ---------------- home: live stats & hub ---------------- */
function ring(frac,col){const R=34,C=2*Math.PI*R,len=C*Math.max(0,Math.min(1,frac));
 return s("svg",{viewBox:"0 0 200 84",height:84},s("circle",{cx:160,cy:42,r:R,fill:"none",stroke:"rgba(255,255,255,.07)","stroke-width":7}),
  s("circle",{cx:160,cy:42,r:R,fill:"none",stroke:col,"stroke-width":7,"stroke-linecap":"round","stroke-dasharray":len+" "+(C-len),transform:"rotate(-90 160 42)",filter:"url(#sglow)"}),
  s("defs",null,s("filter",{id:"sglow",x:"-50%",y:"-50%",width:"200%",height:"200%"},s("feGaussianBlur",{stdDeviation:"2.2",result:"b"}),s("feMerge",null,s("feMergeNode",{in:"b"}),s("feMergeNode",{in:"SourceGraphic"})))));}
function stageBars(t){const ks=STAGES.map(x=>x[0]),vals=ks.map(k=>(t&&t[k])||0),mx=Math.max(1,...vals),W=200,H=60,bw=W/ks.length;
 return s("svg",{viewBox:"0 0 "+W+" "+H,height:60},vals.map((v,i)=>{const hh=Math.max(2,(H-8)*v/mx);
  return s("rect",{x:i*bw+3,y:H-hh,width:bw-6,height:hh,rx:2,fill:"url(#sbar)"},s("title",null,STAGES[i][2]+": "+v+" ms"));}),
  s("defs",null,s("linearGradient",{id:"sbar",x1:0,y1:0,x2:0,y2:1},s("stop",{offset:0,"stop-color":"#3ee6ea"}),s("stop",{offset:1,"stop-color":"#3ee6ea","stop-opacity":".15"}))));}
function wave(){const pts=[];for(let i=0;i<=60;i++){const x=i*200/60,y=42+Math.sin(i/3.2)*10*Math.exp(-Math.pow((i-30)/14,2));pts.push(x.toFixed(1)+","+y.toFixed(1));}
 return s("svg",{viewBox:"0 0 200 84",height:84},s("polyline",{points:pts.join(" "),fill:"none",stroke:"#3ee6ea","stroke-width":1.6,filter:"url(#sglow)"}),
  s("line",{x1:0,x2:200,y1:42,y2:42,stroke:"rgba(62,230,234,.15)"}));}
function stat(lab,big,cap,art){return h("div",{cls:"card stat"},h("div",{cls:"lab"},lab),h("div",{cls:"big"},big),h("div",{cls:"cap"},cap),art);}
function renderHomeStats(st,tri,gr){const L=st.legal.anchors,m=tri.summary_metrics||{};
 const steps=gr.exhibits.PC.storyline.length+gr.exhibits.HANDSET.storyline.length;
 const b1=h("span"),b2=h("span"),b3=h("span"),b4=h("span");
 put("homeStats",stat("Pipeline",h("span",null,b1,h("small",null," s")),"all sectors, run #"+st.run_id,stageBars(st.timings_ms)),
  stat("Anchors verified",h("span",null,b2,h("small",null," / "+L.total)),"bytes re-hashed by Sector D",ring(L.total?L.verified/L.total:0,"#3ee6ea")),
  stat("Leads flagged",b3,(m.high_priority_leads_flagged||0)+" high priority",ring((m.high_priority_leads_flagged||0)/Math.max(1,m.total_leads||1),"#fbbf24")),
  stat("Storyline steps",b4,"across both exhibits",wave()),bentoStream(),bentoEnf(),bentoPtt(tri));
 countUp(b1,st.pipeline_seconds,2);countUp(b2,L.verified);countUp(b3,m.total_leads||tri.all_leads.length);countUp(b4,steps);}
function bentoStream(){const el=h("div",{cls:"stream"});const c=h("div",{cls:"card stat w2 tall"},h("a",{cls:"tile-go",href:"#/graph"},"open →"),h("div",{cls:"lab"},"Anchor ledger · this run"),
  h("div",{cls:"cap"},"Byte anchors that Sectors B and C recorded, with the status each had at run time. Open any one to re-hash it live."),el);anchorStream(el);return c;}
function bentoEnf(){const e=S.v&&S.v.enf;return h("div",{cls:"card stat w2"},h("a",{cls:"tile-go",href:"#/vault"},"open →"),h("div",{cls:"lab"},"Seizure video · 50 Hz mains hum"),
  e&&e.status?enfLive(e):h("div",{cls:"cap"},"No ENF result in this run."));}
function bentoPtt(t){const d=t&&t.deepfake;return h("div",{cls:"card stat w2"},h("a",{cls:"tile-go",href:"#/triage"},"open →"),h("div",{cls:"lab"},"Video call · pulse-transit test"),
  d&&d.physiological_window_ms?pttLive(d):h("div",{cls:"cap"},"No deepfake lead in this run."));}
function renderHub(){const W=820,H=460,cx=410,cy=215;
 const sats=[["A","Evidence vault","vault","#3ee6ea",150,80],["B","Neural triage","triage","#fbbf24",670,80],["C","Attack story","graph","#a78bfa",110,330],
  ["45","Defence screen","defence","#f472b6",710,330],["D","Court outputs","court","#34d399",410,385]];
 const g=s("svg",{viewBox:"0 0 "+W+" "+H,role:"img","aria-label":"How sectors A to D feed the cockpit"});
 g.appendChild(s("defs",null,s("filter",{id:"hglow",x:"-50%",y:"-50%",width:"200%",height:"200%"},s("feGaussianBlur",{stdDeviation:"6",result:"b"}),s("feMerge",null,s("feMergeNode",{in:"b"}),s("feMergeNode",{in:"SourceGraphic"}))),
  s("radialGradient",{id:"hcore",cx:".4",cy:".35",r:".75"},s("stop",{offset:0,"stop-color":"#e6ffff"}),s("stop",{offset:.35,"stop-color":"#3ee6ea"}),s("stop",{offset:1,"stop-color":"#065c64"}))));
 sats.forEach(([k,l,pg,c,x,y])=>{const mx=(cx+x)/2,my=(cy+y)/2;
  g.appendChild(s("path",{d:"M"+cx+","+cy+" Q"+(x<cx?mx-40:mx+40)+","+my+" "+x+","+y,fill:"none",stroke:"rgba(62,230,234,.22)","stroke-width":1.2}));
  g.appendChild(s("path",{cls:"hubline",d:"M"+cx+","+cy+" Q"+(x<cx?mx-40:mx+40)+","+my+" "+x+","+y,fill:"none",stroke:c,"stroke-width":1.6,opacity:.75}));});
 g.appendChild(s("rect",{x:cx-58,y:cy-58,width:116,height:116,rx:14,fill:"#020606",stroke:"#3ee6ea","stroke-width":1.4,filter:"url(#hglow)"}));
 g.appendChild(s("circle",{cx:cx,cy:cy-6,r:30,fill:"url(#hcore)",filter:"url(#hglow)"}));
 g.appendChild(s("text",{x:cx,y:cy+2,"text-anchor":"middle",fill:"#012628","font-size":24,"font-weight":800},"E"));
 g.appendChild(s("text",{x:cx,y:cy+46,"text-anchor":"middle",fill:"#8d999c","font-size":11,"letter-spacing":"3"},"COCKPIT"));
 sats.forEach(([k,l,pg,c,x,y])=>{g.appendChild(s("g",{cls:"hubsat",role:"link",tabindex:"0",on:{click:()=>{location.hash="#/"+pg;},keydown:e=>{if(e.key==="Enter")location.hash="#/"+pg;}}},
  s("title",null,"Open "+l),s("rect",{x:x-30,y:y-30,width:60,height:60,rx:10,fill:"#030707",stroke:c,"stroke-width":1.4}),
  s("text",{x:x,y:y+7,"text-anchor":"middle",fill:c,"font-size":k.length>1?17:21,"font-weight":800},k),
  s("text",{x:x,y:y+50,"text-anchor":"middle",fill:"#e4eef0","font-size":12.5},l)));});
 put("hub",g);}

/* ---------------- Sutra: the guide orb ---------------- */
const RM=!!(window.matchMedia&&matchMedia("(prefers-reduced-motion: reduce)").matches);
const SAY={tok:0};
function curPage(){return document.body.classList.contains("home")?"home":((location.hash||"").replace(/^#\/?/,"").split("/")[0]||"home");}
function mood(m){["heroBot","buddyBot","chatBot"].forEach(id=>{const b=$(id);b.classList.remove("think","happy","alert");if(m)b.classList.add(m);});}
function say(lines,opt){opt=opt||{};const tok=++SAY.tok;const home=curPage()==="home";const bub=$(home?"heroBubble":"buddyBubble"),tx=bub.querySelector(".tx");
 if(opt.mood!==undefined)mood(opt.mood);clearTimeout(SAY.hide);bub.classList.remove("hide");
 (async function(){for(let li=0;;li++){const line=lines[li%lines.length];if(li>=lines.length&&!opt.loop)break;
   if(RM){tx.textContent=line;}else{tx.textContent="";for(let i=1;i<=line.length;i++){if(tok!==SAY.tok)return;tx.textContent=line.slice(0,i);await new Promise(r=>setTimeout(r,24));}}
   await new Promise(r=>setTimeout(r,opt.hold||2400));if(tok!==SAY.tok)return;}
  if(!home)SAY.hide=setTimeout(()=>{if(tok===SAY.tok)bub.classList.add("hide");},5000);})();}
function plural(n,w){return n+" "+w+(n===1?"":"s");}
function pageLines(p){const st=S.status,t=TRI,x=S.x;
 if(p==="home")return["Hey there… welcome to SUTRA-Trace.","I'm Sutra. I'll walk you through the evidence.","Scroll down, or press Start an investigation."];
 if(!st)return["Loading this run…"];const L=st.legal.anchors;
 if(p==="run")return["Press the glowing button and I'll run Sectors A → D for real.","Last run: #"+st.run_id+" in "+st.pipeline_seconds.toFixed(2)+" s."];
 if(p==="vault"){const v=S.v;return v?[plural(v.digests.length,"hash receipt")+" for "+v.filename+".","Mains-hum check: "+((v.enf||{}).status||"—").replace(/_/g," ").toLowerCase()+"."]:["Loading the vault…"];}
 if(p==="triage"&&t){const m=t.summary_metrics||{};return[plural(m.total_leads||t.all_leads.length,"lead")+" flagged, "+(m.high_priority_leads_flagged||0)+" high priority.","Click any bar to see the exact bytes."];}
 if(p==="graph"&&GRAPH)return[GRAPH.exhibits[EX].storyline.length+" steps in this attack story.","Click a node or a step to open the inspector."];
 if(p==="defence"&&x)return[x.supports_intrusion_hypothesis+" of "+x.checks_evaluated+" checks favour intrusion.","The examiner has to answer each one in court."];
 if(p==="court")return["Certificate: "+st.readiness.replace(/_/g," ").toLowerCase()+".",L.verified+"/"+L.total+" byte anchors re-verified by Sector D."];
 return["Loading this run…"];}
function speakPage(){const p=curPage();mood(null);say(pageLines(p),{loop:p==="home",hold:p==="home"?2600:2400});}
(function eyes(){let raf=0,mx=0,my=0;document.addEventListener("pointermove",e=>{mx=e.clientX;my=e.clientY;if(raf)return;raf=requestAnimationFrame(()=>{raf=0;
 document.querySelectorAll(".bot").forEach(b=>{const r=b.getBoundingClientRect();if(!r.width)return;const dx=mx-(r.left+r.width/2),dy=my-(r.top+r.height/2),d=Math.hypot(dx,dy)||1,k=Math.min(1,d/300)*r.width*0.07;
  b.querySelector(".eyes").style.transform="translate(calc(-50% + "+(dx/d*k).toFixed(1)+"px),calc(-50% + "+(dy/d*k).toFixed(1)+"px))";});});});})();
(function reveal(){const els=document.querySelectorAll(".rv");if(RM||!("IntersectionObserver" in window)){els.forEach(e=>e.classList.add("in"));return;}
 const io=new IntersectionObserver(es=>es.forEach(e=>{if(e.isIntersecting){e.target.classList.add("in");io.unobserve(e.target);}}),{threshold:.12});els.forEach(e=>io.observe(e));})();

/* ---------------- Ask Sutra (offline, answers from this run) ---------------- */
function goBtn(label,hash){return h("a",{cls:"btn act",href:hash,on:{click:()=>$("chat").classList.remove("on")}},label);}
function answer(q){const st=S.status,t=TRI,x=S.x;if(!st||!t)return["The run is still loading. Ask me again in a moment."];
 const L=st.legal,m=t.summary_metrics||{};
 if(/defen[cs]e|trojan|hack|someone else|45|challenge|intrusion/i.test(q)&&x){
  const und=(x.checks_evaluated||0)-(x.checks_determined||0);const open=Object.values(x.defense_challenge_matrix||{}).reduce((n,mm)=>n+(mm?mm.rows.filter(r=>r.status==="OPEN").length:0),0);
  return[x.checks_evaluated+" Section 45 checks ran: "+(x.supports_attribution||0)+" support attribution, "+(x.supports_intrusion_hypothesis||0)+" support the intrusion hypothesis and "+und+" are undetermined. "+plural(open,"defence challenge")+" still open.",goBtn("Open the defence screen","#/defence")];}
 if(/money|upi|mule|hub|fund|paid|pay|transfer|freeze|rupee|₹|bank/i.test(q)){const u=(t.upi_smurfing||[])[0],f=L.freeze_notice||{};
  return u?[inr(u.inflow.amount_inr)+" went from "+u.inflow.payer_vpa+" to the hub "+u.hub_vpa+", which split it across "+plural(u.mules.length,"mule account")+" in "+u.dispersal_span_s+" s. The Section 106 BNSS freeze notice asks for a lien of "+inr(f.aggregate_lien_inr)+".",goBtn("See the money trail","#/triage")]:["No mule-account fan-out was found in this run."];}
 if(/deep ?fake|video|call|face|fake|webrtc|caller/i.test(q)){const d=t.deepfake,w=(t.webrtc||[])[0];
  return[(d?"The video call was scored "+d.verdict.replace(/_/g," ").toLowerCase()+": its pulse transit is "+d.ptt_delay_ms+" ms, while real faces sit between "+d.physiological_window_ms[0]+" and "+d.physiological_window_ms[1]+" ms.":"No deepfake lead in this run.")+
   (w?" The caller's WebRTC endpoint was "+w.endpoint+", and a Section 94 BNSS requisition is drafted for it.":""),goBtn("Open the deepfake tab","#/triage")];}
 if(/ready|certificate|court|sign|file|filing|63|document|str|fiu/i.test(q)){const blk=st.readiness_blocking||[],notes=st.readiness_notes||[];
  return["The Section 63 BSA certificate is "+st.readiness.replace(/_/g," ").toLowerCase()+". "+(blk.length?plural(blk.length,"blocking issue")+" must be fixed before filing.":"Nothing blocks filing.")+" "+plural(notes.length,"note")+" to read first, and the FIU-IND STR "+(L.str_validation_errors.length?"has schema errors.":"passes its schema check."),goBtn("Open court outputs","#/court")];}
 if(/verif|byte|hash|anchor|tamper|offset|merkle|proof|check/i.test(q))
  return["Sector D re-verified "+L.anchors.verified+" of "+L.anchors.total+" byte anchors in this run. Click any lead, node or story step: the inspector shows the file, offset and SHA-256, then re-reads those bytes from disk and re-proves them against Sector A's Merkle tree.",goBtn("Try it on the attack story","#/graph")];
 if(/find|found|result|summary|happen|what|run|overview|case/i.test(q))
  return["Run #"+st.run_id+" took "+st.pipeline_seconds.toFixed(2)+" s. Sector B raised "+plural(m.total_leads||t.all_leads.length,"lead")+" ("+(m.high_priority_leads_flagged||0)+" high priority), Sector C rebuilt "+GRAPH.exhibits.PC.storyline.length+" attack steps on the victim PC and "+GRAPH.exhibits.HANDSET.storyline.length+" on the handset, and Sector D re-verified "+L.anchors.verified+"/"+L.anchors.total+" byte anchors.",goBtn("Walk the attack story","#/graph")];
 if(/^\s*(hi|hello|hey|yo|namaste)\b|who are you|help/i.test(q))return["Hi! I'm Sutra, the cockpit's guide. I answer from this run's data only, and nothing leaves this laptop. Try one of the questions below."];
 return["I only know what this run found. Try asking about the findings, the money trail, the deepfake call, the certificate, byte verification or the Section 45 defence."];}
async function chatAsk(q){q=String(q||"").trim();if(!q)return;const B=$("chatBody");B.appendChild(h("div",{cls:"msg me"},q));
 const m=h("div",{cls:"msg ai"},h("span",{cls:"typing"},h("i"),h("i"),h("i")));B.appendChild(m);B.scrollTop=B.scrollHeight;mood("think");
 await new Promise(r=>setTimeout(r,RM?0:650));const [text,...extra]=answer(q);clear(m);const tx=h("span");m.appendChild(tx);
 if(RM)tx.textContent=text;else for(let i=1;i<=text.length;i+=2){tx.textContent=text.slice(0,i);B.scrollTop=B.scrollHeight;await new Promise(r=>setTimeout(r,10));}
 tx.textContent=text;extra.forEach(e=>m.appendChild(e));B.scrollTop=B.scrollHeight;mood("happy");setTimeout(()=>mood(null),1600);}
const QUICK=["What did this run find?","Is the certificate ready to file?","Where did the money go?","Was the video call a deepfake?","How do I check a byte myself?","What's still open for the defence?"];
function chatInit(){put("chatBody",h("div",{cls:"msg ai"},"Hey human 👋 I'm Sutra. Ask me anything about this case, its evidence or its court documents."),
 h("div",{cls:"chips"},h("div",{cls:"lab"},"Quick questions"),QUICK.map(q=>h("button",{cls:"chip",type:"button",on:{click:()=>chatAsk(q)}},q))));}
function chatToggle(on){const c=$("chat");on=on==null?!c.classList.contains("on"):on;c.classList.toggle("on",on);if(on)setTimeout(()=>$("chatInput").focus(),200);}
$("chatFab").addEventListener("click",()=>chatToggle());$("chatClose").addEventListener("click",()=>chatToggle(false));$("buddyBot").addEventListener("click",()=>chatToggle(true));
$("heroBot").addEventListener("click",()=>chatToggle(true));
$("chatForm").addEventListener("submit",e=>{e.preventDefault();const i=$("chatInput");chatAsk(i.value);i.value="";});
document.addEventListener("keydown",e=>{if(e.key==="Escape")chatToggle(false);});
chatInit();

/* ---------------- shared animation ticker (pauses off-screen and in hidden tabs) ---------------- */
const TICK=new Set();let TICKING=false;
function tickLoop(t){if(document.hidden||!TICK.size){TICKING=false;return;}TICK.forEach(f=>{try{f(t);}catch(e){TICK.delete(f);console.error(e);}});requestAnimationFrame(tickLoop);}
function tickOn(f){TICK.add(f);if(!TICKING&&!document.hidden){TICKING=true;requestAnimationFrame(tickLoop);}}
function tickOff(f){TICK.delete(f);}
document.addEventListener("visibilitychange",()=>{if(!document.hidden&&TICK.size&&!TICKING){TICKING=true;requestAnimationFrame(tickLoop);}});
const VIS_IO=("IntersectionObserver" in window)?new IntersectionObserver(es=>es.forEach(e=>{const f=e.target.__tick;if(!f)return;if(e.isIntersecting&&!RM)tickOn(f);else tickOff(f);}),{threshold:0}):null;
function whenVisible(el,f){const g=t=>{if(!el.isConnected&&g.started){tickOff(g);if(VIS_IO)VIS_IO.unobserve(el);return;}g.started=1;f(t);};g.el=el;el.__tick=g;
 if(RM){requestAnimationFrame(t=>f(t));return;}if(VIS_IO)VIS_IO.observe(el);else tickOn(g);}
function fitCanvas(cv){const r=cv.getBoundingClientRect(),d=Math.min(2,window.devicePixelRatio||1),w=Math.max(1,Math.round(r.width*d)),hh=Math.max(1,Math.round(r.height*d));
 if(cv.width!==w||cv.height!==hh){cv.width=w;cv.height=hh;}return{w,h:hh,d,cw:r.width,ch:r.height};}

/* ---------------- Holo-Core: native WebGL forensic evidence core ---------------- */
const HOLO=[];
const HOLO_VS=`attribute vec3 aP;attribute vec2 aK;
uniform mat3 uR;uniform float uT,uPulse,uAsp,uFit,uDpr,uBusy;uniform vec3 uPC,uPD;
varying vec3 vC;varying float vA;
void main(){vec3 p=aP;float k=aK.x,s=aK.y;
 if(k<0.5||k>2.5){p*=1.0+0.022*sin(uT*1.7+s*40.0);}
 else if(k<1.5){float a=aP.z+uT*(0.22+0.6*uBusy);vec3 q=vec3(cos(a)*aP.x,0.0,sin(a)*aP.x);float ci=cos(aP.y),si=sin(aP.y);p=vec3(q.x,-q.z*si,q.z*ci);}
 else{p*=0.86+0.14*sin(uT*(2.2+3.0*uBusy)+s*20.0);}
 vec3 w=uR*p;float z=3.4-w.z;vec2 sp=w.xy*2.25/z;
 gl_Position=vec4(sp.x*uFit/uAsp,sp.y*uFit,0.0,1.0);
 float depth=clamp((w.z+1.7)/3.4,0.0,1.0);float wave=0.0;
 if(uPulse>=0.0){vec3 n=normalize(k>0.5&&k<1.5?p:aP);float d=acos(clamp(dot(n,uPD),-1.0,1.0));wave=exp(-pow((d-uPulse*3.4)/0.24,2.0))*clamp(1.0-uPulse/1.05,0.0,1.0);}
 vec3 base=k<0.5?vec3(0.22,0.86,0.9):(k<1.5?vec3(0.5,0.98,1.0):(k<2.5?vec3(0.85,1.0,1.0):vec3(0.2,0.75,0.8)));
 base=mix(base,vec3(1.0,0.74,0.22),uBusy*0.65);
 vC=mix(base,uPC,min(1.0,wave*1.4));
 vA=(k<0.5?(0.3+0.7*depth):(k<1.5?(0.38+0.55*depth):(k<2.5?0.9:(0.08+0.26*depth))))+wave*0.9;
 gl_PointSize=uDpr*((k<0.5?2.5:(k<1.5?2.7:3.0))+3.4*wave)*(3.4/z)*max(uFit,0.55);}`;
const HOLO_FS=`precision mediump float;varying vec3 vC;varying float vA;uniform float uLine;
void main(){float a=vA;if(uLine<0.5){vec2 d=gl_PointCoord-0.5;a*=1.0-smoothstep(0.22,0.5,length(d));}gl_FragColor=vec4(vC,a);}`;
function holoGeometry(){const P=[],K=[],N=1500,ga=Math.PI*(3-Math.sqrt(5));
 for(let i=0;i<N;i++){const y=1-2*(i+0.5)/N,r=Math.sqrt(1-y*y),t=ga*i;P.push(Math.cos(t)*r,y,Math.sin(t)*r);K.push(0,(i*0.61803)%1);}
 [[1.28,0.42,0],[1.42,-0.7,2.1],[1.16,1.25,4.2]].forEach(([R,inc,ph],ri)=>{for(let i=0;i<150;i++){P.push(R,inc,ph+i*2*Math.PI/150);K.push(1,ri/3);}});
 for(let i=0;i<220;i++){const u=Math.acos(2*((i*0.7548)%1)-1),v=2*Math.PI*((i*0.5698)%1),rr=0.08+0.27*((i*0.3819)%1);P.push(rr*Math.sin(u)*Math.cos(v),rr*Math.cos(u),rr*Math.sin(u)*Math.sin(v));K.push(2,(i*0.137)%1);}
 const L=[],LK=[];const seg=56;
 for(let m=0;m<12;m++){const ph=m*Math.PI/12;for(let j=0;j<seg;j++){for(const jj of[j,j+1]){const th=jj*2*Math.PI/seg;L.push(Math.cos(th)*Math.cos(ph),Math.sin(th),Math.cos(th)*Math.sin(ph));LK.push(3,m/12);}}}
 for(const lat of[-0.66,-0.33,0,0.33,0.66]){const r=Math.sqrt(1-lat*lat);for(let j=0;j<seg;j++){for(const jj of[j,j+1]){const th=jj*2*Math.PI/seg;L.push(Math.cos(th)*r,lat,Math.sin(th)*r);LK.push(3,0.5);}}}
 return{P:new Float32Array(P),K:new Float32Array(K),L:new Float32Array(L),LK:new Float32Array(LK)};}
function rotM(yaw,pitch){const cy=Math.cos(yaw),sy=Math.sin(yaw),cp=Math.cos(pitch),sp=Math.sin(pitch);return[cy,0,sy, sp*sy,cp,-sp*cy, -cp*sy,sp,cp*cy];}
function mulM(m,x,y,z){return[m[0]*x+m[1]*y+m[2]*z,m[3]*x+m[4]*y+m[5]*z,m[6]*x+m[7]*y+m[8]*z];}
const HOLO_NODES=[["DISK","vault"],["VIDEO","vault"],["NETWORK","triage"],["MEMORY","graph"],["LEDGER","court"]];
class HoloCore{
 constructor(cv,fx,opt){this.cv=cv;this.fx=fx;this.opt=opt||{};this.sub={};this.st={auto:0.6,yawO:0,pitO:0,vy:0,vp:0,spin:0,busy:0,busyT:0,pulse:-1,pc:[0.4,1,1],pd:[0,0,1],rings:[]};
  this.hover=-1;this.proj=[];this.t0=performance.now();this.last=this.t0;this.gl=null;
  try{this.gl=cv.getContext("webgl",{alpha:true,antialias:true,premultipliedAlpha:false})||cv.getContext("experimental-webgl");}catch(e){this.gl=null;}
  if(this.gl&&!this.initGL())this.gl=null;
  if(!this.gl)this.geo2d=holoGeometry();
  this.bind();HOLO.push(this);const f=t=>this.frame(t);whenVisible(cv,f);}
 initGL(){const gl=this.gl,mk=(type,src)=>{const sh=gl.createShader(type);gl.shaderSource(sh,src);gl.compileShader(sh);if(!gl.getShaderParameter(sh,gl.COMPILE_STATUS)){console.warn(gl.getShaderInfoLog(sh));return null;}return sh;};
  const vs=mk(gl.VERTEX_SHADER,HOLO_VS),fs=mk(gl.FRAGMENT_SHADER,HOLO_FS);if(!vs||!fs)return false;
  const pr=gl.createProgram();gl.attachShader(pr,vs);gl.attachShader(pr,fs);gl.linkProgram(pr);if(!gl.getProgramParameter(pr,gl.LINK_STATUS))return false;
  this.pr=pr;const g=holoGeometry();this.n=g.P.length/3;this.nl=g.L.length/3;
  const buf=d=>{const b=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,b);gl.bufferData(gl.ARRAY_BUFFER,d,gl.STATIC_DRAW);return b;};
  this.bP=buf(g.P);this.bK=buf(g.K);this.bL=buf(g.L);this.bLK=buf(g.LK);
  this.aP=gl.getAttribLocation(pr,"aP");this.aK=gl.getAttribLocation(pr,"aK");
  this.u={};["uR","uT","uPulse","uAsp","uFit","uDpr","uBusy","uPC","uPD","uLine"].forEach(k=>this.u[k]=gl.getUniformLocation(pr,k));return true;}
 bind(){const cv=this.fx;let drag=null;
  cv.addEventListener("pointerdown",e=>{drag={x:e.clientX,y:e.clientY,moved:0};try{cv.setPointerCapture(e.pointerId);}catch(_){}});
  cv.addEventListener("pointermove",e=>{const r=cv.getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top;
   if(drag){const dx=e.clientX-drag.x,dy=e.clientY-drag.y;drag.moved+=Math.abs(dx)+Math.abs(dy);this.st.spin+=dx*0.012;this.st.vp+=dy*0.02;drag.x=e.clientX;drag.y=e.clientY;}
   let best=-1,bd=22;this.proj.forEach((p,i)=>{const d=Math.hypot(p.x-x,p.y-y);if(d<bd){bd=d;best=i;}});this.hover=best;cv.style.cursor=best>=0?"pointer":(drag?"grabbing":"grab");});
  cv.addEventListener("pointerup",e=>{const click=drag&&drag.moved<6;drag=null;if(click&&this.hover>=0){location.hash="#/"+HOLO_NODES[this.hover][1];}
   else if(click&&this.opt.onCore){const r=cv.getBoundingClientRect();if(Math.hypot(e.clientX-r.left-r.width/2,e.clientY-r.top-r.height/2)<Math.min(r.width,r.height)*0.3)this.opt.onCore();}});
  cv.addEventListener("pointerleave",()=>{this.hover=-1;});}
 setInfo(sub){this.sub=sub||{};}
 setBusy(b){this.st.busyT=b?1:0;}
 pulse(kind){const c=kind==="ok"?[0.35,1,0.62]:kind==="bad"?[1,0.32,0.32]:[0.45,1,1];const m=this.M||rotM(0,0);
  this.st.pulse=0;this.st.pc=c;this.st.pd=[m[6],m[7],m[8]];this.st.rings.push({t:0,c});if(RM)this.frame(performance.now());}
 frame(now){const dt=Math.min(0.05,(now-this.last)/1000);this.last=now;const T=(now-this.t0)/1000,st=this.st;
  const g=window.__ptr||{x:innerWidth/2,y:innerHeight/2},r=this.cv.getBoundingClientRect();
  const tx=Math.max(-1,Math.min(1,(g.x-(r.left+r.width/2))/(innerWidth*0.5))),ty=Math.max(-1,Math.min(1,(g.y-(r.top+r.height/2))/(innerHeight*0.5)));
  const k=16,c=6.5;st.vy+=(k*(tx*0.75-st.yawO)-c*st.vy)*dt;st.yawO+=st.vy*dt;st.vp+=(k*(ty*0.45-st.pitO)-c*st.vp)*dt;st.pitO+=st.vp*dt;
  st.busy+=(st.busyT-st.busy)*Math.min(1,dt*3);st.auto+=dt*(0.16+0.9*st.busy)+st.spin*dt;st.spin*=Math.exp(-dt*1.6);
  if(st.pulse>=0){st.pulse+=dt*0.85;if(st.pulse>1.1)st.pulse=-1;}
  st.rings.forEach(x=>x.t+=dt);st.rings=st.rings.filter(x=>x.t<1.4);
  const M=rotM(st.auto+st.yawO,0.32+st.pitO);this.M=M;
  const s1=fitCanvas(this.cv),s2=fitCanvas(this.fx);const asp=s1.w/s1.h,fit=Math.min(1,asp)*0.92*(this.opt.scale||1)*(s1.cw<520&&!this.opt.nonodes?0.8:1);
  if(this.gl){const gl=this.gl,u=this.u;gl.viewport(0,0,s1.w,s1.h);gl.clearColor(0,0,0,0);gl.clear(gl.COLOR_BUFFER_BIT);gl.useProgram(this.pr);
   gl.enable(gl.BLEND);gl.blendFunc(gl.SRC_ALPHA,gl.ONE);
   gl.uniformMatrix3fv(u.uR,false,new Float32Array([M[0],M[3],M[6],M[1],M[4],M[7],M[2],M[5],M[8]]));
   gl.uniform1f(u.uT,T);gl.uniform1f(u.uPulse,st.pulse);gl.uniform1f(u.uAsp,asp);gl.uniform1f(u.uFit,fit);gl.uniform1f(u.uDpr,s1.d);gl.uniform1f(u.uBusy,st.busy);
   gl.uniform3fv(u.uPC,st.pc);gl.uniform3fv(u.uPD,st.pd);
   const draw=(bp,bk,mode,n,line)=>{gl.uniform1f(u.uLine,line);gl.bindBuffer(gl.ARRAY_BUFFER,bp);gl.enableVertexAttribArray(this.aP);gl.vertexAttribPointer(this.aP,3,gl.FLOAT,false,0,0);
    gl.bindBuffer(gl.ARRAY_BUFFER,bk);gl.enableVertexAttribArray(this.aK);gl.vertexAttribPointer(this.aK,2,gl.FLOAT,false,0,0);gl.drawArrays(mode,0,n);};
   draw(this.bL,this.bLK,gl.LINES,this.nl,1);draw(this.bP,this.bK,gl.POINTS,this.n,0);}
  this.overlay(s2,M,T,fit,asp);}
 overlay(sz,M,T,fit,asp){const ctx=this.fx.getContext("2d"),W=sz.w,H=sz.h,d=sz.d;ctx.setTransform(1,0,0,1,0,0);ctx.clearRect(0,0,W,H);
  const P=(x,y,z)=>{const w=mulM(M,x,y,z),zz=3.4-w[2],sx=w[0]*2.25/zz,sy=w[1]*2.25/zz;return{x:W/2+sx*fit/asp*W/2,y:H/2-sy*fit*H/2,z:w[2],k:3.4/zz};};
  const st=this.st,busy=st.busy;
  if(!this.gl){const g=this.geo2d;ctx.fillStyle="rgba(62,230,234,.55)";for(let i=0;i<g.P.length/3;i+=2){if(g.K[i*2]!==0)continue;const p=P(g.P[i*3],g.P[i*3+1],g.P[i*3+2]);ctx.globalAlpha=0.15+0.6*(p.z+1)/2;ctx.fillRect(p.x,p.y,1.6*d,1.6*d);}ctx.globalAlpha=1;}
  const c0=P(0,0,0),R=Math.abs(P(0,1,0).y-c0.y);
  const halo=ctx.createRadialGradient(c0.x,c0.y,R*0.1,c0.x,c0.y,R*1.5);halo.addColorStop(0,busy>0.3?"rgba(251,191,36,.16)":"rgba(62,230,234,.14)");halo.addColorStop(1,"rgba(0,0,0,0)");ctx.fillStyle=halo;ctx.fillRect(0,0,W,H);
  st.rings.forEach(x=>{const a=Math.max(0,1-x.t/1.4);ctx.strokeStyle="rgba("+x.c.map(v=>Math.round(v*255)).join(",")+","+(a*0.8)+")";ctx.lineWidth=2*d;ctx.beginPath();ctx.arc(c0.x,c0.y,R*(1+x.t*0.9),0,Math.PI*2);ctx.stroke();});
  this.proj=[];if(this.opt.nonodes)return;const inc=0.38,RR=1.42;const nodes=HOLO_NODES.map(([nm],i)=>{const a=i*2*Math.PI/5+T*0.11;let x=Math.cos(a)*RR,y=0,z=Math.sin(a)*RR;const yy=-z*Math.sin(inc),zz=z*Math.cos(inc);return{nm,i,p:P(x,y+yy*1,zz),s:P(x/RR,yy/RR,zz/RR)};});
  ctx.lineWidth=1*d;
  for(let i=0;i<5;i++){const a=nodes[i].p,b=nodes[(i+1)%5].p;ctx.strokeStyle="rgba(62,230,234,.10)";ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();}
  nodes.slice().sort((a,b)=>a.p.z-b.p.z).forEach(n=>{const front=n.p.z>-0.2,al=front?1:0.45,hov=this.hover===n.i;
   const gr=ctx.createLinearGradient(n.p.x,n.p.y,n.s.x,n.s.y);gr.addColorStop(0,"rgba(62,230,234,"+(0.55*al)+")");gr.addColorStop(1,"rgba(62,230,234,0)");
   ctx.strokeStyle=gr;ctx.setLineDash([3*d,4*d]);ctx.lineDashOffset=-T*30*d;ctx.beginPath();ctx.moveTo(n.p.x,n.p.y);ctx.lineTo(n.s.x,n.s.y);ctx.stroke();ctx.setLineDash([]);
   const f=(T*(0.45+n.i*0.07))%1,px=n.p.x+(n.s.x-n.p.x)*f,py=n.p.y+(n.s.y-n.p.y)*f;ctx.fillStyle="rgba(180,255,255,"+(0.9*al)+")";ctx.beginPath();ctx.arc(px,py,1.8*d,0,Math.PI*2);ctx.fill();
   const rad=(hov?8:5.5)*d*Math.max(0.7,n.p.k*0.9);const glow=ctx.createRadialGradient(n.p.x,n.p.y,0,n.p.x,n.p.y,rad*4);glow.addColorStop(0,"rgba(62,230,234,"+(0.55*al)+")");glow.addColorStop(1,"rgba(62,230,234,0)");
   ctx.fillStyle=glow;ctx.beginPath();ctx.arc(n.p.x,n.p.y,rad*4,0,Math.PI*2);ctx.fill();
   ctx.fillStyle=hov?"#ffffff":"rgba(4,10,12,.95)";ctx.strokeStyle=busy>0.3?"rgba(251,191,36,"+al+")":"rgba(62,230,234,"+al+")";ctx.lineWidth=1.5*d;ctx.beginPath();ctx.arc(n.p.x,n.p.y,rad,0,Math.PI*2);ctx.fill();ctx.stroke();
   if(!this.opt.nolabels){ctx.font="600 "+(10.5*d)+"px "+MONO();ctx.textAlign="center";const ly=n.p.y+rad+13*d;
    ctx.fillStyle="rgba(228,238,240,"+(0.95*al)+")";ctx.fillText(n.nm,n.p.x,ly);const sub=this.sub[n.nm];
    if(sub){ctx.font=(9.5*d)+"px "+MONO();ctx.fillStyle="rgba(141,153,156,"+(0.95*al)+")";ctx.fillText(sub,n.p.x,ly+12*d);}ctx.textAlign="left";}
   this.proj[n.i]={x:n.p.x/d,y:n.p.y/d};});}
}
function holoAll(fn){HOLO.forEach(x=>{try{fn(x);}catch(e){console.error(e);}});}
document.addEventListener("pointermove",e=>{window.__ptr={x:e.clientX,y:e.clientY};},{passive:true});

/* ---------------- mouse spotlight + specular card borders ---------------- */
(function spotlight(){let raf=0,mx=-1e4,my=-1e4;const SEL=".page.on .card,.page.on .stage,.page.on .story,.page.on .chk,.page.on .digest";
 document.addEventListener("pointermove",e=>{mx=e.clientX;my=e.clientY;if(raf)return;raf=requestAnimationFrame(()=>{raf=0;
  const els=[...document.querySelectorAll(SEL)],rs=els.map(el=>el.getBoundingClientRect());
  els.forEach((el,i)=>{const r=rs[i];if(r.bottom<-200||r.top>innerHeight+200)return;el.style.setProperty("--mx",(mx-r.left)+"px");el.style.setProperty("--my",(my-r.top)+"px");});});},{passive:true});})();

/* ---------------- living waveforms ---------------- */
function liveCanvas(cls,h,draw){const cv=h_canvas(cls,h);whenVisible(cv,t=>draw(cv,t/1000));return cv;}
function h_canvas(cls,hgt){const cv=document.createElement("canvas");cv.className="live-cv "+(cls||"");cv.height=hgt;cv.style.height=hgt+"px";cv.setAttribute("aria-hidden","true");cv.__h=hgt;return cv;}
function cvCtx(cv){const s=fitCanvas(cv),ctx=cv.getContext("2d");ctx.setTransform(s.d,0,0,s.d,0,0);ctx.clearRect(0,0,s.cw,s.ch);return{ctx,W:s.cw,H:s.ch};}
let MONO_F="";const MONO=()=>MONO_F||(MONO_F=getComputedStyle(document.body).getPropertyValue("--mono").trim()||"monospace");
function enfLive(e){const thr=e.threshold_rad||0.08,val=e.max_phase_jump_rad||0,nw=e.windows_analyzed||0,f0=e.mean_freq_hz||50,ok=e.status==="LOCKED_CONTINUOUS";
 return liveCanvas("enf",168,(cv,T)=>{const{ctx,W}=cvCtx(cv),m=MONO();
  ctx.font="10.5px "+m;ctx.fillStyle="#8d999c";ctx.fillText("CARRIER "+f0+" Hz  (drawn 50× slower)",0,11);
  const mid=40,A=17,cyc=7,ph=T*2*Math.PI*(f0/50);
  for(let pass=0;pass<2;pass++){ctx.beginPath();for(let x=0;x<=W;x+=2){const y=mid+A*Math.sin(x/W*cyc*2*Math.PI-ph);x?ctx.lineTo(x,y):ctx.moveTo(x,y);}
   ctx.strokeStyle=pass?"#9ffbfc":"rgba(62,230,234,.35)";ctx.lineWidth=pass?1.4:5;ctx.stroke();}
  ctx.fillStyle="#8d999c";ctx.fillText(nw+" WINDOWS ANALYSED · HUM PRESENCE "+e.hum_presence_ratio,0,80);
  const scan=(T*14)%(nw+10),bw=W/Math.max(1,nw);for(let i=0;i<nw;i++){const lit=i<scan;ctx.fillStyle=lit?(ok?"rgba(52,211,153,.85)":"rgba(248,113,113,.85)"):"rgba(255,255,255,.08)";ctx.fillRect(i*bw+1,88,Math.max(1,bw-2),10);}
  const gx=v=>W*Math.min(v,thr*1.5)/(thr*1.5);ctx.fillStyle="rgba(255,255,255,.07)";ctx.fillRect(0,128,W,8);ctx.fillStyle="rgba(52,211,153,.45)";ctx.fillRect(0,128,gx(thr),8);
  ctx.strokeStyle="#f87171";ctx.lineWidth=1.5;ctx.beginPath();ctx.moveTo(gx(thr),120);ctx.lineTo(gx(thr),144);ctx.stroke();
  const pul=0.5+0.5*Math.sin(T*3),mx=Math.max(6,gx(val)),gl=ctx.createRadialGradient(mx,132,2,mx,132,14+6*pul);gl.addColorStop(0,"rgba(62,230,234,.55)");gl.addColorStop(1,"rgba(62,230,234,0)");
  ctx.fillStyle=gl;ctx.beginPath();ctx.arc(mx,132,20,0,Math.PI*2);ctx.fill();ctx.fillStyle="#e4eef0";ctx.beginPath();ctx.arc(mx,132,6,0,Math.PI*2);ctx.fill();
  ctx.fillStyle="#8d999c";ctx.fillText("MAX Δφ "+val+" rad",0,118);ctx.textAlign="right";ctx.fillStyle="#fca5a5";ctx.fillText("LIMIT "+thr+" rad",W,118);ctx.textAlign="left";
  ctx.fillStyle=val<thr?"#6ff0c4":"#fca5a5";ctx.fillText(val<thr?"✓ continuous: no splice":"✗ phase jump over limit",0,160);});}
function pulseShape(x){x=((x%1)+1)%1;return Math.exp(-Math.pow((x-0.14)/0.045,2))-0.18*Math.exp(-Math.pow((x-0.33)/0.022,2))+0.38*Math.exp(-Math.pow((x-0.40)/0.06,2))+0.04*Math.sin(x*6.283);}
function pttLive(d){const per=60/(d.heart_rate_bpm||72),dl=(d.ptt_delay_ms||0)/1000,lo=d.physiological_window_ms[0],hi=d.physiological_window_ms[1],ref=(lo+hi)/2000;
 return liveCanvas("ptt",232,(cv,T)=>{const{ctx,W}=cvCtx(cv),m=MONO(),span=0.9;ctx.font="10.5px "+m;
  const row=(y0,lab,delay,col2,ghost)=>{ctx.fillStyle="#8d999c";ctx.fillText(lab,0,y0-36);
   [[0,"#3ee6ea"],[delay,col2]].forEach(([dd,col],j)=>{ctx.beginPath();for(let x=0;x<=W;x+=2){const t=T-span+x/W*span-dd;const y=y0-26*pulseShape(t/per);x?ctx.lineTo(x,y):ctx.moveTo(x,y);}
    ctx.strokeStyle=col;ctx.globalAlpha=ghost&&j?0.8:1;ctx.lineWidth=j?1.4:1.8;if(j)ctx.setLineDash([4,3]);ctx.stroke();ctx.setLineDash([]);ctx.globalAlpha=1;});};
  row(62,"THIS CALL · ROI 2 lags ROI 1 by "+d.ptt_delay_ms+" ms",dl,"#f472b6");
  ctx.fillStyle="rgba(52,211,153,.06)";ctx.fillRect(0,96,W,72);row(158,"REAL FACE · arterial transit "+lo+"–"+hi+" ms (drawn at "+Math.round(ref*1000)+" ms)",ref,"#34d399",true);
  ctx.fillStyle=d.ptt_in_physiological_window?"#6ff0c4":"#fca5a5";ctx.fillText((d.ptt_in_physiological_window?"✓ inside":"✗ outside")+" the "+lo+"–"+hi+" ms window: "+(d.verdict||"").replace(/_/g," ").toLowerCase(),0,190);
  ctx.fillStyle="#58646a";ctx.fillText("pulse shape is a model (systolic peak + dicrotic notch); delays are measured",0,208);
  ctx.fillText("heart rate "+d.heart_rate_bpm+" bpm · pulse SNR "+d.pulse_snr,0,224);});}
function animateFan(svg,u){const paths=[...svg.querySelectorAll("path.flowline")];if(!paths.length)return svg;const span=u.dispersal_span_s||80,LOOP=10,SC=6.5/Math.max(1,span);
 const NS2="http://www.w3.org/2000/svg";let lens=null;const boxes=[...svg.querySelectorAll("rect.mule")];
 const clock=document.createElementNS(NS2,"text");clock.setAttribute("x",8);clock.setAttribute("y",16);clock.setAttribute("fill","#3ee6ea");clock.setAttribute("font-size","11");svg.appendChild(clock);
 const dots=[];paths.forEach((p,i)=>{for(let k=0;k<(i?4:7);k++){const c=document.createElementNS(NS2,"circle");c.setAttribute("r",i?2.6:3.2);c.setAttribute("fill",i?"#fde68a":"#9ffbfc");c.setAttribute("opacity","0");svg.appendChild(c);dots.push({c,i,k});}});
 whenVisible(svg,now=>{if(!lens)lens=paths.map(p=>p.getTotalLength());const t=(now/1000)%LOOP;const sim=Math.max(0,(t-1.2)/SC);clock.textContent=t<1.2?"t = 0 s · inflow "+inr(u.inflow.amount_inr):"t = +"+Math.min(span,Math.round(sim))+" s"+(sim>=span?" · dispersed":"");
  dots.forEach(o=>{let st,dur;if(o.i===0){st=o.k*0.12;dur=1.1;}else{const of=u.outflows[o.i-1];st=1.2+(of?of.seconds_after_inflow:0)*SC+o.k*0.18;dur=1.0;}
   const f=(t-st)/dur;if(f<0||f>1){o.c.setAttribute("opacity","0");return;}const pt=paths[o.i].getPointAtLength(lens[o.i]*f);o.c.setAttribute("cx",pt.x);o.c.setAttribute("cy",pt.y);o.c.setAttribute("opacity",String(1-Math.abs(f-0.5)));});
  boxes.forEach((b,i)=>{const of=u.outflows[i];b.classList.toggle("hit",!!of&&t>1.2+of.seconds_after_inflow*SC+1.0);});});return svg;}

/* ---------------- bento: live anchor stream ---------------- */
function anchorStream(el){const items=[];const seen=new Set();
 const push=(a,tag)=>{if(!a||!a.source_file||seen.has(a.source_file+a.byte_offset+":"+a.length))return;seen.add(a.source_file+a.byte_offset+":"+a.length);
  items.push({ok:(a.rehash||a.status)==="MATCH"||a.status==="VERIFIED",t:(a.rehash==="MATCH"||a.status==="VERIFIED"?"VERIFIED":"CHECK   ")+"  "+a.source_file+" @"+a.byte_offset_hex+"  "+a.length+" B  sha256 "+short(a.sha256_recorded||a.sha256_now||"",6),tag});};
 if(GRAPH)Object.values(GRAPH.exhibits).forEach(ex=>ex.edges.forEach(e=>push(e.anchor,"C")));if(TRI)TRI.all_leads.forEach(l=>push(l.anchor,"B"));
 clear(el);if(!items.length){el.appendChild(h("div",{cls:"sline"},"waiting for the first run…"));return;}
 let i=0,last=0;const add=()=>{const it=items[i++%items.length];const ln=h("div",{cls:"sline"+(it.ok?"":" bad")},h("span",{cls:"st"},"["+it.tag+"] "),it.t);el.appendChild(ln);while(el.childNodes.length>11)el.removeChild(el.firstChild);};
 for(let k=0;k<8;k++)add();el.__tick&&tickOff(el.__tick);whenVisible(el,now=>{if(now-last>520){last=now;add();}});}

/* ---------------- Sector C graph: pan / zoom / causal path ---------------- */
const GV={vb:null,key:"",svg:null,L:null,tw:0,path:null};
function setVB(v){GV.vb=v;if(GV.svg)GV.svg.setAttribute("viewBox",v.x+" "+v.y+" "+v.w+" "+v.h);}
function vbAspect(){const r=GV.svg?GV.svg.getBoundingClientRect():null;return r&&r.height?r.width/r.height:2;}
function fitVB(b,pad){const L=GV.L,asp=vbAspect();b=b||{x:0,y:0,w:L.W,h:L.H};pad=pad==null?20:pad;let w=b.w+2*pad,hh=b.h+2*pad;if(w/hh<asp)w=hh*asp;else hh=w/asp;
 w=Math.max(w,260);hh=w/asp;return{x:b.x+b.w/2-w/2,y:b.y+b.h/2-hh/2,w,h:hh};}
function tweenVB(to,ms){const from=GV.vb||to,t0=performance.now(),id=++GV.tw;if(RM||!ms){setVB(to);return;}
 (function step(now){if(id!==GV.tw)return;const p=Math.min(1,(now-t0)/ms),e=1-Math.pow(1-p,3);setVB({x:from.x+(to.x-from.x)*e,y:from.y+(to.y-from.y)*e,w:from.w+(to.w-from.w)*e,h:from.h+(to.h-from.h)*e});if(p<1)requestAnimationFrame(step);})(t0);}
function zoomBy(f,cx,cy){const v=GV.vb,L=GV.L;if(!v)return;const nw=Math.max(L.W*0.12,Math.min(L.W*2.5,v.w*f)),k=nw/v.w;cx=cx==null?v.x+v.w/2:cx;cy=cy==null?v.y+v.h/2:cy;
 setVB({x:cx-(cx-v.x)*k,y:cy-(cy-v.y)*k,w:nw,h:v.h*k});}
function graphTools(){return h("div",{cls:"gtools"},h("button",{title:"Zoom in",on:{click:()=>{GV.tw++;zoomBy(0.75);}}},"+"),h("button",{title:"Zoom out",on:{click:()=>{GV.tw++;zoomBy(1.33);}}},"−"),
 h("button",{title:"Fit the whole graph",on:{click:()=>tweenVB(fitVB(),420)}},"Fit"),h("button",{title:"Clear the causal path",on:{click:()=>{SEL=null;GV.path=null;renderGraph();tweenVB(fitVB(),420);}}},"Clear"));}
function bindPanZoom(svg){let drag=null;
 svg.addEventListener("wheel",e=>{e.preventDefault();GV.tw++;const r=svg.getBoundingClientRect(),v=GV.vb;zoomBy(Math.exp(e.deltaY*0.0015),v.x+(e.clientX-r.left)/r.width*v.w,v.y+(e.clientY-r.top)/r.height*v.h);},{passive:false});
 svg.addEventListener("pointerdown",e=>{if(e.target.closest(".gnode,.gedge"))return;drag={x:e.clientX,y:e.clientY};svg.classList.add("panning");try{svg.setPointerCapture(e.pointerId);}catch(_){}});
 svg.addEventListener("pointermove",e=>{if(!drag)return;GV.tw++;const r=svg.getBoundingClientRect(),v=GV.vb;setVB({x:v.x-(e.clientX-drag.x)*v.w/r.width,y:v.y-(e.clientY-drag.y)*v.h/r.height,w:v.w,h:v.h});drag={x:e.clientX,y:e.clientY};});
 const end=()=>{drag=null;svg.classList.remove("panning");};svg.addEventListener("pointerup",end);svg.addEventListener("pointercancel",end);
 svg.addEventListener("dblclick",e=>{if(!e.target.closest(".gnode,.gedge"))tweenVB(fitVB(),420);});}
function causalPath(ex,sel){if(!sel)return null;const out={},inn={};ex.edges.forEach(e=>{(out[e.source]=out[e.source]||[]).push(e);(inn[e.target]=inn[e.target]||[]).push(e);});
 const N=new Set(),E=new Set();const walk=(start,adj,next)=>{const q=[start],seen=new Set([start]);while(q.length){const n=q.shift();N.add(n);(adj[n]||[]).forEach(e=>{E.add(e.id);const m=e[next];if(!seen.has(m)){seen.add(m);q.push(m);}});}};
 const e0=ex.edges.find(e=>e.id===sel);if(e0){E.add(e0.id);walk(e0.source,inn,"source");walk(e0.target,out,"target");}else{walk(sel,inn,"source");walk(sel,out,"target");}
 return{N,E};}
function pathBox(L,P){if(!P||!P.N.size)return null;let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;L.nodes.forEach(n=>{if(!P.N.has(n.id))return;x0=Math.min(x0,n.x);y0=Math.min(y0,n.y);x1=Math.max(x1,n.x+160);y1=Math.max(y1,n.y+40);});return{x:x0,y:y0,w:x1-x0,h:y1-y0};}

/* ---------------- inspector: glowing hex terminal ---------------- */
function termHex(a){const pre=h("pre",{cls:"hex term"});const head=h("span",{cls:"cmd"},"$ hexdump -s "+a.byte_offset_hex+" "+a.source_file+"\n");pre.appendChild(head);
 const lines=a.hexdump||[];const cur=h("span",{cls:"cur"});if(RM){pre.appendChild(document.createTextNode(lines.join("\n")));pre.appendChild(cur);return pre;}
 let i=0;const t=setInterval(()=>{if(!pre.isConnected&&i>0){clearInterval(t);return;}if(i>=lines.length){clearInterval(t);pre.appendChild(cur);return;}
  const ln=h("span",{cls:"hl"},lines[i]+(i<lines.length-1?"\n":""));pre.appendChild(ln);i++;},70);return pre;}

/* ---------------- glue: pulses, node sub-labels, graph focus ---------------- */
function holoPulse(kind){const now=performance.now();holoAll(x=>{if(x.cv.getClientRects().length&&(RM||now-x.last<600))x.pulse(kind);});}
function holoBusy(b){holoAll(x=>x.setBusy(b));}
function holoInfo(st,v,t,g){const L=(st.legal||{}).anchors||{},e=(v&&v.enf)||{},m=(t&&t.summary_metrics)||{};
 const steps=Object.values(g.exhibits).reduce((n,x)=>n+x.storyline.length,0),leads=m.total_leads!=null?m.total_leads:(t?t.all_leads.length:0);
 const sz=v?v.size_bytes:0,sub={DISK:v?(sz>=1048576?(sz/1048576).toFixed(1)+" MiB":sz>=1024?(sz/1024).toFixed(1)+" KiB":sz+" B")+" vaulted":"",VIDEO:e.status?"ENF \u0394\u03c6 "+e.max_phase_jump_rad+" rad":"",NETWORK:leads+" leads",MEMORY:steps+" storyline steps",LEDGER:L.total!=null?L.verified+"/"+L.total+" anchors":""};
 holoAll(x=>x.setInfo(sub));}
function initVB(){const f=fitVB(),r=GV.svg.getBoundingClientRect();if(!r.width||r.width/f.w>=0.6)return f;
 const k=0.6;return{x:-8,y:0,w:r.width/k,h:r.height/k};}
function focusPath(){const b=pathBox(GV.L,GV.path);if(b)tweenVB(fitVB(b,48),560);}
window.addEventListener("resize",()=>{clearTimeout(GV.rz);GV.rz=setTimeout(()=>{if(!GV.svg||!GV.svg.isConnected||!GV.svg.getClientRects().length)return;const a=vbAspect();
 if(Math.abs(a-(GV.asp||0))>0.02){GV.asp=a;const b=GV.path?pathBox(GV.L,GV.path):null;setVB(fitVB(b,b?48:20));}},120);});
new HoloCore($("holoHero"),$("holoHeroFx"),{onCore:()=>{location.hash="#/run";}});
new HoloCore($("holoRun"),$("holoRunFx"),{scale:0.9});
new HoloCore($("holoDrw"),$("holoDrwFx"),{nonodes:true,scale:1.25});
renderHub();renderStages(null,"");route();loadAll();
</script>
</body>
</html>
"""


def render_cockpit_html(nonce: str) -> bytes:
    return COCKPIT_HTML.replace("__NONCE__", nonce).encode("utf-8")


# --------------------------------------------------------------------------- #
# Application: run state + one router shared by Flask and http.server         #
# --------------------------------------------------------------------------- #

class Response:
    """content_length is the size of the representation; a HEAD response keeps it while its body is dropped."""
    __slots__ = ("status", "body", "ctype", "headers", "content_length")

    def __init__(self, status: int, body: bytes, ctype: str, headers: Optional[Dict[str, str]] = None):
        self.status, self.body, self.ctype = status, body, ctype
        self.headers = dict(headers or {})
        self.content_length = len(body)


BASE_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                "X-Frame-Options": "DENY", "Cross-Origin-Resource-Policy": "same-origin"}


def _json_resp(obj: Any, status: int = 200, extra: Optional[Dict[str, str]] = None) -> Response:
    return Response(status, _json_bytes(obj), "application/json; charset=utf-8", dict(BASE_HEADERS, **(extra or {})))


def _err(status: int, msg: str, extra: Optional[Dict[str, str]] = None) -> Response:
    return _json_resp({"error": msg, "status": status}, status, extra)


class PipelineBusy(RuntimeError):
    pass


class CockpitApp:
    """Holds the current pipeline run and answers every route. Thread-safe; one pipeline run at a time."""

    ROUTES: Dict[str, Tuple[str, ...]] = {
        "/": ("GET",), "/api/status": ("GET",), "/api/run": ("POST",), "/api/vault": ("GET",),
        "/api/triage": ("GET",), "/api/graph": ("GET",), "/api/exculpatory": ("GET",),
        "/download/certificate": ("GET",), "/download/str_xml": ("GET",), "/download/freeze_notice": ("GET",),
        "/api/qr": ("GET",), "/favicon.ico": ("GET",), "/api/verify_anchor": ("GET",),
    }

    def __init__(self, workdir: Optional[str] = None, keep: bool = False):
        self.owns_dir = workdir is None
        if workdir:
            # Run numbers restart at 1 in every process, so each process writes into its own new session
            # folder under --workdir: a persistent or shared workdir never has another session's or another
            # instance's run folder overwritten, pruned or counted (overnight audit E-04).
            root = os.path.abspath(workdir)
            os.makedirs(root, exist_ok=True)
            self.base = tempfile.mkdtemp(prefix="session_", dir=root)
        else:
            self.base = tempfile.mkdtemp(prefix="sutra_cockpit_")
        self.keep = keep
        self._run_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._run: Optional[Dict[str, Any]] = None
        self._run_no = 0
        self.backend: Optional[str] = None
        self.allowed_hosts: Optional[set] = None     # None = no Host check (in-process test client)
        self.last_error: Optional[str] = None

    # ----- state ------------------------------------------------------------ #

    @property
    def run(self) -> Optional[Dict[str, Any]]:
        with self._state_lock:
            return self._run

    def execute(self) -> Dict[str, Any]:
        if not self._run_lock.acquire(blocking=False):
            raise PipelineBusy("a pipeline run is already in progress")
        try:
            self._run_no += 1
            run_no = self._run_no
            try:
                run = run_pipeline(self.base, run_no)
            except Exception as e:
                # A half-written run folder must never survive to be counted (or kept) by _prune().
                shutil.rmtree(os.path.join(self.base, f"run_{run_no:04d}"), ignore_errors=True)
                self.last_error = f"{type(e).__name__}: {e}"
                raise
            with self._state_lock:
                prev, self._run = self._run, run
            self.last_error = None
            self._prune()
            run["previous_run_id"] = prev["run_id"] if prev else None
            return run
        finally:
            self._run_lock.release()

    def _prune(self) -> None:
        """Keep the KEEP_RUNS newest run folders by number (never the current one); delete the rest."""
        runs = []
        for d in os.listdir(self.base):
            m = re.fullmatch(r"run_(\d{4,})", d)
            if m and os.path.isdir(os.path.join(self.base, d)):
                runs.append((int(m.group(1)), d))
        runs.sort()
        keep = {d for _, d in runs[-KEEP_RUNS:]}
        cur = self.run
        if cur is not None:
            keep.add(os.path.basename(cur["workdir"]))
        for _, d in runs:
            if d not in keep:
                shutil.rmtree(os.path.join(self.base, d), ignore_errors=True)

    def close(self) -> None:
        if self.owns_dir and not self.keep:
            shutil.rmtree(self.base, ignore_errors=True)

    def set_bind(self, host: str, port: int) -> None:
        if host in ("127.0.0.1", "localhost", "::1"):
            self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
            if port == 80:
                self.allowed_hosts |= {"127.0.0.1", "localhost", "[::1]"}
        elif host in ("0.0.0.0", "::", ""):
            # Wildcard bind: pin Host to this machine's own names and addresses, so a DNS-rebound name
            # (attacker.example resolved to this laptop) is refused with 421 (overnight audit E-11).
            names = {"127.0.0.1", "localhost", "[::1]"}
            try:
                hn = socket.gethostname()
            except OSError:
                hn = ""
            cands = [hn]
            if hn:
                try:
                    cands.append(socket.getfqdn(hn))
                except OSError:
                    pass
                try:
                    cands += [ai[4][0] for ai in socket.getaddrinfo(hn, None)]
                except OSError:
                    pass
            for fam, probe in ((socket.AF_INET, ("192.0.2.1", 9)), (socket.AF_INET6, ("2001:db8::1", 9))):
                try:   # the address the default route would use; a UDP connect sends no packet
                    with socket.socket(fam, socket.SOCK_DGRAM) as so:
                        so.connect(probe)
                        cands.append(so.getsockname()[0])
                except OSError:
                    pass
            for c in cands:
                c = str(c or "").split("%", 1)[0].lower()
                if c:
                    names.add(f"[{c}]" if ":" in c else c)
            self.allowed_hosts = {f"{n}:{port}" for n in names} | (names if port == 80 else set())
        else:
            # A specific LAN address: pin Host to exactly that address and port.
            h = host.lower()
            if ":" in h and not h.startswith("["):
                h = f"[{h}]"
            self.allowed_hosts = {f"{h}:{port}"} | ({h} if port == 80 else set())

    # ----- routing ---------------------------------------------------------- #

    def dispatch(self, method: str, target: str, headers: Dict[str, str]) -> Response:
        hdr = {k.lower(): v for k, v in headers.items()}
        try:
            parts = urlsplit(target)
            path = parts.path or "/"
            query = parse_qs(parts.query)
        except ValueError:   # e.g. "GET http://[x/ HTTP/1.1" (overnight audit E-01)
            return _err(400, "malformed request target")
        if self.allowed_hosts is not None and hdr.get("host", "").lower() not in self.allowed_hosts:
            return _err(421, "unexpected Host header (the cockpit only answers on its loopback address)")
        if path not in self.ROUTES:
            return _err(404, f"no route {path}")
        if method == "HEAD" and "GET" in self.ROUTES[path]:
            r = self.dispatch("GET", target, headers)
            r.content_length = len(r.body)   # RFC 9110 s.9.3.2: same Content-Length a GET would send
            r.body = b""
            return r
        if method not in self.ROUTES[path]:
            return _err(405, f"{method} not allowed on {path}", {"Allow": ", ".join(self.ROUTES[path])})
        try:
            if path == "/":
                return self._page()
            if path == "/favicon.ico":
                return Response(204, b"", "image/x-icon", dict(BASE_HEADERS))
            if path == "/api/run":
                return self._post_run(hdr)
            run = self.run
            if run is None:
                return _err(503, "the pipeline has not completed a run yet" +
                            (f" (last error: {self.last_error})" if self.last_error else ""))
            v = run["views"]
            if path == "/api/status":
                st = dict(v["status"], web_backend=self.backend, busy=self._run_lock.locked(),
                          previous_run_id=run.get("previous_run_id"))
                return _json_resp(st)
            if path in ("/api/vault", "/api/triage", "/api/graph", "/api/exculpatory"):
                return _json_resp(v[path.rsplit("/", 1)[1]])
            if path == "/api/verify_anchor":
                return self._verify_anchor(run, query)
            blobs = run["legal"]["blobs"]
            if path == "/download/certificate":
                return self._file(blobs["certificate_pdf"], "application/pdf", "BSA_2023_Sec63_Certificate.pdf")
            if path == "/download/str_xml":
                return self._file(blobs["str_xml"], "application/xml; charset=utf-8", "FIU_IND_STR_FINnet2.xml")
            if path == "/download/freeze_notice":
                att = query.get("attachment", ["0"])[0] in ("1", "true", "yes")
                return self._file(blobs["freeze_notice_json"], "application/json; charset=utf-8",
                                  "BNSS_106_107_Freeze_Notice.json", attachment=att)
            if path == "/api/qr":
                return self._file(blobs["qr_png"], "image/png", None)
        except Exception as e:  # pragma: no cover - surfaced to the client, never a silent 200
            traceback.print_exc()
            return _err(500, f"{type(e).__name__}: {e}")
        return _err(404, f"no route {path}")  # pragma: no cover

    def _page(self) -> Response:
        nonce = secrets.token_urlsafe(18)
        csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; img-src 'self'; "
               "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        return Response(200, render_cockpit_html(nonce), "text/html; charset=utf-8",
                        dict(BASE_HEADERS, **{"Content-Security-Policy": csp}))

    def _verify_anchor(self, run: Dict[str, Any], query: Dict[str, List[str]]) -> Response:
        """Live re-verification of one recorded anchor: re-read, re-hash and re-prove from the disk now."""
        ex = (query.get("exhibit", [""])[0] or "").upper()
        aid = query.get("id", [""])[0] or ""
        page_run = query.get("run", [None])[0]
        if page_run is not None and page_run != str(run["run_id"]):
            return _err(409, f"this page shows run #{page_run} but the current run is #{run['run_id']}; "
                             "reload the cockpit before re-verifying")
        insp = run["inspectors"].get(ex)
        if insp is None:
            return _err(400, "exhibit must be one of " + ", ".join(sorted(run["inspectors"])))
        if not re.fullmatch(r"[0-9a-f]{24}", aid):
            return _err(400, "id must be the 24-hex anchor_id the cockpit reported for this anchor")
        out = insp.inspect_live(aid)
        if out is None:
            return _err(404, f"anchor {aid} is not a recorded anchor of exhibit {ex} in run #{run['run_id']}")
        out["run_id"] = run["run_id"]
        return _json_resp(out)

    def _file(self, blob: Tuple[bytes, str], ctype: str, name: Optional[str], attachment: bool = True) -> Response:
        body, digest = blob
        h = dict(BASE_HEADERS, **{"X-Content-SHA256": digest})
        if name:
            h["Content-Disposition"] = f'{"attachment" if attachment else "inline"}; filename="{name}"'
        return Response(200, body, ctype, h)

    def _post_run(self, hdr: Dict[str, str]) -> Response:
        # A custom header cannot be sent cross-site without a CORS preflight, which this server never
        # grants, so a web page elsewhere cannot make the laptop re-run the pipeline.
        if hdr.get("x-sutra-action", "").lower() != "run":
            return _err(403, "POST /api/run needs the header X-SUTRA-Action: run")
        origin = hdr.get("origin")
        if origin:
            try:
                onet = urlsplit(origin).netloc.lower()
            except ValueError:   # e.g. "Origin: http://[x" (overnight audit E-09)
                return _err(403, "malformed Origin header")
            if self.allowed_hosts is not None:
                same = onet in self.allowed_hosts
            else:   # in-process client (no Host pinning): the page must come from the host it is talking to
                same = bool(onet) and onet == hdr.get("host", "").lower()
            if not same:
                return _err(403, "cross-origin pipeline runs are refused")
        before = self.run
        try:
            run = self.execute()
        except PipelineBusy as e:
            return _err(409, str(e))
        st = run["views"]["status"]
        h_now = run["handset"]["a"]["cryptographic_hashes"]
        h_prev = before["handset"]["a"]["cryptographic_hashes"] if before else None
        return _json_resp({
            "ok": True, "run_id": run["run_id"], "previous_run_id": run.get("previous_run_id"),
            "run_started_utc": run["started_utc"], "run_finished_utc": run["finished_utc"],
            "pipeline_seconds": st["pipeline_seconds"], "within_budget": st["within_budget"],
            "timings_ms": run["timings_ms"], "readiness": st["readiness"], "health": st["health"],
            "sector_d_digest_checks": [r["status"] for r in run["legal"]["verification"]["hash_rows"]],
            # Sector B's synthetic APK is a zip whose entry dates follow the wall clock (2 s resolution), so
            # the handset image, and every digest over it, legitimately changes between runs.
            "evidence_digests_same_as_previous_run": None if h_prev is None else all(
                h_now.get(k) == h_prev.get(k) for k in ("sha256_linear_primary", "blake2b_secondary",
                                                       "sha256_merkle_root_4mb", "bnss_105_seizure_video_sha256",
                                                       "final_bound_evidence_root")),
        })


# --------------------------------------------------------------------------- #
# Web servers                                                                 #
# --------------------------------------------------------------------------- #

class _Handler(BaseHTTPRequestHandler):
    server_version = "SUTRA-Cockpit"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = HANDLER_TIMEOUT_S         # a silent or slow client releases its thread after this many seconds
    quiet = False
    _DRAIN_LIMIT = 4 * 1024 * 1024      # an oversized body up to this size is read and discarded, then closed

    def _handle(self) -> None:
        app: CockpitApp = self.server.app  # type: ignore[attr-defined]
        if self.headers.get("Transfer-Encoding"):
            resp = _err(411, "chunked request bodies are not accepted; send Content-Length")
            self.close_connection = True
        else:
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = -1
            if n < 0 or n > MAX_BODY_BYTES:
                resp = _err(413, "request body too large", {"Connection": "close"})
                self.close_connection = True
                if 0 < n <= self._DRAIN_LIMIT:   # read it off the socket so the client sees the 413, not a reset
                    try:
                        while n > 0:
                            got = self.rfile.read(min(n, 65536))
                            if not got:
                                break
                            n -= len(got)
                    except OSError:
                        pass
            else:
                if n:
                    self.rfile.read(n)
                try:   # no request may end without a response (overnight audit E-01)
                    resp = app.dispatch(self.command, self.path, dict(self.headers.items()))
                except Exception as e:
                    traceback.print_exc()
                    resp = _err(500, f"{type(e).__name__}: {e}")
        try:
            self.send_response(resp.status)
            self.send_header("Content-Type", resp.ctype)
            self.send_header("Content-Length", str(resp.content_length))
            for k, v in resp.headers.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(resp.body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True     # the client went away mid-response (e.g. a cancelled download)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _handle  # type: ignore[assignment]

    # C0 controls, DEL and C1 controls from the request line are written escaped, never raw (overnight audit
    # E-10: an ESC sequence in a request could clear or recolour the console or forge log lines).
    _LOG_ESCAPES = {c: f"\\x{c:02x}" for c in (*range(0x20), *range(0x7F, 0xA0))}

    def log_message(self, fmt: str, *args: Any) -> None:
        if not self.quiet:
            msg = (fmt % args).translate(self._LOG_ESCAPES)
            sys.stderr.write("  %s  %s\n" % (self.log_date_time_string(), msg))


_ON_WINDOWS = os.name == "nt"


def _exclusive_bind_options(sock: socket.socket) -> None:
    """On Windows, claim the port exclusively: SO_REUSEADDR there lets a second socket bind a port that is
    already listening (overnight audit E-05), so a second cockpit must fail instead of sharing the port."""
    if _ON_WINDOWS:
        excl = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if excl is not None:
            sock.setsockopt(socket.SOL_SOCKET, excl, 1)


def _host_family(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def _bind_host(host: str) -> str:
    """'' means every IPv4 interface; '[::1]' is accepted for '::1'."""
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host or "0.0.0.0"


def _cockpit_url(host: str, port: int) -> str:
    """The URL a browser on this laptop should open (IPv6 literals in brackets, wildcards as loopback)."""
    h = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(host, host)
    return f"http://{'[' + h + ']' if ':' in h else h}:{port}/"


def _probe_port(host: str, port: int) -> None:
    """Fail now, with an OSError, when host:port cannot be bound (used before the Flask engine starts)."""
    with socket.socket(_host_family(host), socket.SOCK_STREAM) as so:
        if _ON_WINDOWS:
            _exclusive_bind_options(so)
        else:
            so.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # what Werkzeug does on POSIX
        so.bind((host, port))


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a cap on simultaneous connections; extra connections are closed at once."""

    daemon_threads = True
    max_threads = MAX_HANDLER_THREADS

    def server_bind(self) -> None:
        if _ON_WINDOWS:   # never SO_REUSEADDR on Windows: see _exclusive_bind_options()
            self.allow_reuse_address = False
            if hasattr(self, "allow_reuse_port"):
                self.allow_reuse_port = False
            _exclusive_bind_options(self.socket)
        super().server_bind()

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._slots = threading.BoundedSemaphore(self.max_threads)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def make_stdlib_server(app: CockpitApp, host: str, port: int, quiet: bool = False) -> ThreadingHTTPServer:
    handler = type("SutraHandler", (_Handler,), {"quiet": quiet})
    host = _bind_host(host)
    cls = _BoundedThreadingHTTPServer
    if _host_family(host) == socket.AF_INET6:   # --host ::1 / :: (overnight audit E-07)
        cls = type("_BoundedThreadingHTTPServer6", (_BoundedThreadingHTTPServer,), {"address_family": socket.AF_INET6})
    srv = cls((host, port), handler)
    srv.app = app  # type: ignore[attr-defined]
    return srv


def make_flask_app(app: CockpitApp):
    if _flask is None:
        raise CockpitError("Flask is not installed")
    fl = _flask.Flask("sutra_cockpit")
    fl.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]

    def _out(resp: Response, head: bool = False):
        r = _flask.Response(resp.body, status=resp.status, headers=resp.headers, content_type=resp.ctype)
        if head:   # set after construction: Werkzeug's set_data() overwrites it with len(b"") otherwise
            r.headers["Content-Length"] = str(resp.content_length)
        return r

    @fl.errorhandler(413)
    def _too_large(_e):  # noqa: ARG001
        return _out(_err(413, "request body too large"))

    @fl.route("/", defaults={"p": ""}, methods=methods)
    @fl.route("/<path:p>", methods=methods)
    def _all(p: str):  # noqa: ARG001
        req = _flask.request
        if req.content_length is not None and req.content_length > MAX_BODY_BYTES:
            return _out(_err(413, "request body too large", {"Connection": "close"}))
        qs = req.query_string.decode("latin-1")
        resp = app.dispatch(req.method, req.path + ("?" + qs if qs else ""), dict(req.headers.items()))
        return _out(resp, head=req.method == "HEAD")

    return fl


def choose_backend(pref: str) -> str:
    if pref == "flask" and _flask is None:
        raise CockpitError("--backend flask requested but Flask is not installed (pip install flask)")
    if pref == "auto":
        return "flask" if _flask is not None else "stdlib"
    return pref


def serve(app: CockpitApp, host: str, port: int, backend: str, open_browser: bool) -> int:
    srv: Optional[ThreadingHTTPServer] = None
    try:   # the run folder is removed however serve() ends, even on a failed or interrupted first run (E-08)
        backend = choose_backend(backend)
        app.backend = backend
        host = _bind_host(host)
        app.set_bind(host, port)
        # Bind (or, for Flask, probe) the port before the pipeline runs and before the URL is printed or a
        # browser is opened, so a taken port or an unusable address fails at once (overnight audit E-07).
        if backend == "flask":
            _probe_port(host, port)
            if _ON_WINDOWS:   # Werkzeug sets SO_REUSEADDR, which on Windows can share a listening port (E-05)
                try:
                    import werkzeug.serving as _wz  # type: ignore
                    _wz.BaseWSGIServer.allow_reuse_address = False
                except Exception:  # pragma: no cover - Werkzeug layout changed; the probe above still ran
                    pass
        else:
            srv = make_stdlib_server(app, host, port)
        if host not in ("127.0.0.1", "localhost", "::1"):
            print(f"WARNING: binding to {host} exposes the cockpit beyond this laptop.")
        print("Running Sectors A -> B -> C -> D ...")
        run = app.execute()
        st = run["views"]["status"]
        print(f"  run #{run['run_id']} in {st['pipeline_seconds']:.2f} s · readiness {st['readiness']} · "
              f"schema gates {st['health']}")
        url = _cockpit_url(host, port)
        print(f"SUTRA-Trace cockpit ({backend}) on {url}  ·  Ctrl+C to stop")
        if open_browser:
            timer = threading.Timer(0.8, lambda: webbrowser.open(url))
            timer.daemon = True
            timer.start()
        if backend == "flask":
            fl = make_flask_app(app)
            fl.run(host=host, port=port, threaded=True, use_reloader=False, debug=False)
        else:
            srv.serve_forever()  # type: ignore[union-attr]
    except KeyboardInterrupt:
        pass
    finally:
        if srv is not None:
            srv.server_close()
        app.close()
    return 0


# --------------------------------------------------------------------------- #
# Headless self-test                                                          #
# --------------------------------------------------------------------------- #

class _Client:
    """Same calls over the Flask test client or a real loopback http.server."""

    def __init__(self, app: CockpitApp, backend: str):
        self.backend = backend
        self._srv = None
        if backend == "flask":
            self._fl = make_flask_app(app).test_client()
        else:
            self._srv = make_stdlib_server(app, "127.0.0.1", 0, quiet=True)
            self.port = self._srv.server_address[1]
            app.set_bind("127.0.0.1", self.port)
            threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def request(self, method: str, path: str, headers: Optional[Dict[str, str]] = None,
                body: Optional[bytes] = None) -> Tuple[int, Dict[str, str], bytes]:
        headers = dict(headers or {})
        if self.backend == "flask":
            r = self._fl.open(path, method=method, headers=headers, data=body)
            return r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.get_data()
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        try:
            conn.request(method, path, body=body if body is not None else (b"" if method == "POST" else None),
                         headers=headers)
            r = conn.getresponse()
            return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
        finally:
            conn.close()

    def get(self, path: str, headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], bytes]:
        return self.request("GET", path, headers)

    def close(self) -> None:
        if self._srv is not None:
            self._srv.shutdown()
            self._srv.server_close()


def _self_test(workdir: Optional[str], backend_pref: str = "auto", keep: bool = False) -> int:
    t_start = time.perf_counter()
    results: Dict[int, Tuple[str, bool, str]] = {}

    def check(n: int, name: str, fn: Callable[[], Tuple[Any, str]]) -> None:
        try:
            ok, detail = fn()
            ok = bool(ok)
        except Exception as e:  # a crash is a failed check, never a silent pass
            ok, detail = False, f"{type(e).__name__}: {e}"
        results[n] = (name, ok, detail)
        print(f"  [{'PASS' if ok else 'FAIL'}] {n:>2}. {name}" + (f"  ({detail})" if detail else ""))

    print("=" * 78)
    print(f"SUTRA-Trace Sector E self-test  ·  {COCKPIT_VERSION} {COCKPIT_REVISION}  ·  Python {sys.version.split()[0]}")
    for m in _modules_report():
        print(f"  Sector {m['sector']}: {m['file']}  {m['version'] or 'NOT LOADED'}  sha256 {(m['sha256'] or '-')[:16]}")
    try:
        backend = choose_backend(backend_pref)
    except CockpitError as e:
        print(f"  {e}")
        return 2
    print(f"  Web backend under test: {backend}" + ("" if _flask else " (Flask not installed; standard-library server)"))
    print("=" * 78)
    try:
        _require_sectors()
    except CockpitError as e:
        print(f"  {e}")
        return 2

    try:
        app = CockpitApp(workdir, keep=keep)
    except OSError as e:   # e.g. --workdir names a file (overnight audit E-08)
        print(f"  cannot use the work folder: {e}")
        return 2
    app.backend = backend
    client: Optional[_Client] = None
    bodies: Dict[str, str] = {}
    try:
        print("Running Sectors A -> B -> C -> D on both exhibits ...")
        run = app.execute()
        tm = run["timings_ms"]
        print("  " + " · ".join(f"{k} {v:.0f} ms" for k, v in tm.items()))
        print("\nChecks")

        def c1():
            s = tm["pipeline_total"] / 1000.0
            return (s < PIPELINE_BUDGET_S and all(not v for v in run["schema"].values()),
                    f"{s:.2f} s for A+B+C+D on the handset and A+C on the PC exhibit; "
                    f"{'within' if s <= DEMO_TARGET_S else 'over'} the {DEMO_TARGET_S:.0f} s demo target; "
                    f"sector schema validators clean")
        check(1, f"Full end-to-end pipeline finishes in under {PIPELINE_BUDGET_S:.1f} seconds", c1)

        def c2():
            nonlocal client
            client = _Client(app, backend)
            st, _, body = client.get("/api/status")
            ok = st == 200 and json.loads(body)["run_id"] == run["run_id"]
            detail = f"{backend} client; /api/status 200"
            if backend == "flask":  # also prove the standard-library fallback serves the same data
                alt = _Client(app, "stdlib")
                try:
                    s2, _, b2 = alt.get("/api/status", {"Host": f"127.0.0.1:{alt.port}"})
                    ok = ok and s2 == 200 and json.loads(b2)["run_id"] == run["run_id"]
                    detail += "; stdlib fallback answers identically"
                finally:
                    alt.close()
                    app.allowed_hosts = None
            return ok, detail
        check(2, "HTTP test client initialises (Flask test client, or stdlib server on a loopback port)", c2)
        assert client is not None

        def get_json(path: str) -> Dict[str, Any]:
            st, hd, body = client.get(path)
            if st != 200 or not hd.get("content-type", "").startswith("application/json"):
                raise AssertionError(f"{path}: HTTP {st} {hd.get('content-type')}")
            bodies[path] = body.decode("utf-8")
            return json.loads(body)

        html_box: Dict[str, str] = {}

        def c3():
            st, hd, body = client.get("/")
            html = body.decode("utf-8")
            html_box["html"] = html
            bodies["/"] = html
            csp = hd.get("content-security-policy", "")
            ext = re.findall(r"""(?:src|href)\s*=\s*["'](?:https?:)?//""", html)
            return (st == 200 and hd.get("content-type", "").startswith("text/html") and "SUTRA-TRACE" in html
                    and html.lstrip().lower().startswith("<!doctype html>") and "nonce-" in csp and not ext,
                    f"{len(body):,} bytes; CSP with per-response nonce; external URLs: {len(ext)}")
        check(3, "GET / returns HTTP 200 with valid HTML containing SUTRA-TRACE", c3)

        def c4():
            html = html_box["html"]
            need = ("IGDTUW", "ISEA Phase-III", "NFSU")
            return all(k in html for k in need), ", ".join(need)
        check(4, "Dashboard HTML carries the institutional badges (IGDTUW, ISEA Phase-III, NFSU)", c4)

        def c5():
            html = html_box["html"]
            need = ("Section 63 BSA 2023", "Section 105/106 BNSS", "Section 45 BSA", "Section 106 BNSS")
            return all(k in html for k in need), ", ".join(need)
        check(5, "Dashboard HTML carries the statutory citations (Section 63 BSA 2023, Section 105 BNSS)", c5)

        def c6():
            st = get_json("/api/status")
            return (st["case_reference"] == CASE_ID and st["examiner_id"] == EXAMINER_ID
                    and st["run_finished_utc"] and st["timings_ms"] and st["health"] == "OK"
                    and all(m["loaded"] for m in st["modules"]),
                    f"{st['case_reference']} · {st['examiner_id']} · readiness {st['readiness']}")
        check(6, "GET /api/status returns the case reference FIR-042/2026-CYBER and run timestamps", c6)

        vault = get_json("/api/vault")

        def c7():
            want = {"sha256_linear_primary": 64, "blake2b_secondary": 128, "sha256_merkle_root_4mb": 64,
                    "bnss_105_seizure_video_sha256": 64, "final_bound_evidence_root": 64}
            got = {d["id"]: d for d in vault["digests"]}
            ok = all(_is_hex(got[k]["value"], n) and str(got[k]["sector_d_check"]).startswith("MATCH")
                     for k, n in want.items())
            # Recompute two of them here, independently of Sectors A and D.
            img = _read_bytes(run["handset"]["image"])
            vid = _read_bytes(run["handset"]["video"])
            ok = ok and _sha256_hex(img) == got["sha256_linear_primary"]["value"] \
                and hashlib.blake2b(img).hexdigest() == got["blake2b_secondary"]["value"] \
                and _sha256_hex(vid) == got["bnss_105_seizure_video_sha256"]["value"] \
                and _sha256_hex(bytes.fromhex(got["sha256_merkle_root_4mb"]["value"]) + bytes.fromhex(
                    got["bnss_105_seizure_video_sha256"]["value"])) == got["final_bound_evidence_root"]["value"]
            return ok, "5 digests, each re-checked by Sector D; SHA-256, BLAKE2b, video and bound root recomputed here"
        check(7, "GET /api/vault returns all 5 digests (SHA-256, BLAKE2b, Merkle, BNSS 105, Bound Root)", c7)

        def c8():
            e = vault["enf"]
            return (e.get("status") == "LOCKED_CONTINUOUS" and e["max_phase_jump_rad"] < e["threshold_rad"] <= 0.08
                    and vault["sec105_recording"]["verified"],
                    f"{e.get('status')}: Δφ max {e['max_phase_jump_rad']} rad < {e['threshold_rad']} rad, "
                    f"{e['mean_freq_hz']} Hz")
        check(8, "Section 105 BNSS 50 Hz ENF power-hum status is LOCKED_CONTINUOUS", c8)

        def c9():
            ch = vault["seal_chain"]
            return (len(ch) == 3 and all(c["ok"] and _is_hex(c["hash"], 64) for c in ch)
                    and ch[0]["rssi_dbm"] <= -110 and ch[1]["receipt"] == "MK-CY-2026/089"
                    and vault["seal_chain_head"] == ch[2]["hash"],
                    f"RSSI {ch[0]['rssi_dbm']} dBm · {ch[1]['receipt']} · lab unseal verified; "
                    f"officer signatures: {vault['seal_signatures']}")
        check(9, "Section 106 BNSS 3-point seal chain (Faraday bag, Malkhana, lab unsealing)", c9)

        tri = get_json("/api/triage")

        def c10():
            ls = tri["lolbins"]
            return (ls and all(l["threat_score"] >= 0.85 for l in ls) and {l["image"] for l in ls} >=
                    {"certutil.exe", "powershell.exe"} and all(l["anchor"]["status"] == "VERIFIED" for l in ls),
                    "; ".join(f"{l['image']} {l['threat_score']:.4f} {l['mitre_primary']}" for l in ls))
        check(10, "GET /api/triage returns flagged LOLBins with threat score >= 0.85", c10)

        def c11():
            ps = [l for l in tri["lolbins"] if l["encoded_token"]]
            l = ps[0]
            return (any(d["encoding"] == "utf-16-le" for d in l["decoded_layers"]) and l["independent_decode_matches"]
                    and "DownloadString" in l["independent_utf16le_decode"],
                    f"{l['independent_utf16le_decode']!r}; H = {l['entropy_bits_per_char']} bits/char "
                    f"({'at/above' if l['entropy_at_or_above_threshold'] else 'below'} {l['entropy_threshold']})")
        check(11, "GET /api/triage includes the decoded UTF-16LE Base64 command line", c11)

        def c12():
            d = tri["deepfake"]
            lo, hi = d["physiological_window_ms"]
            return (d["verdict"] == "SYNTHETIC_RPPG_SHADER_INJECTION" and abs(d["ptt_delay_ms"]) < 1.0
                    and not (lo <= d["ptt_delay_ms"] <= hi) and d["ptt_in_physiological_window"] is False,
                    f"PTT {d['ptt_delay_ms']} ms vs physiological {lo:.0f}-{hi:.0f} ms -> {d['verdict']}")
        check(12, "GET /api/triage shows synthetic shader detection (PTT delay ~ 0 ms)", c12)

        def c13():
            w = tri["webrtc"][0]
            raw = _read_range(run["handset"]["image"], w["anchor"]["byte_offset"], w["anchor"]["length"]) or b""
            return (w["candidate_type"] == "srflx" and w["public"] and str(w["ip"]).encode() in raw
                    and str(w["port"]).encode() in raw and b"srflx" in raw and w["anchor"]["status"] == "VERIFIED",
                    f"{w['endpoint']}/{w['transport']} read back from case_bundle.img @ {w['anchor']['byte_offset_hex']} "
                    f"(manual example 185.220.101.42:3478; the pipeline's evidence holds {w['endpoint']})")
        check(13, "GET /api/triage includes the WhatsApp WebRTC srflx IP:Port candidate", c13)

        def c14():
            w = tri["webrtc"][0]
            q = w["sec94_requisition"]
            return (w["sec94_ready"] and "Section 94 BNSS" in q["notice_text"] and w["ip"] in q["notice_text"]
                    and str(w["port"]) in q["notice_text"] and len(q["data_sought"]) >= 3,
                    f"addressee: {q['addressee']}")
        check(14, "GET /api/triage includes the Section 94 BNSS CGNAT IPDR requisition block", c14)

        def c15():
            u = tri["upi_smurfing"][0]
            return (len(u["mules"]) >= 4 and u["dispersal_span_s"] <= 80 and len(u["outflows"]) >= 4
                    and all(o["anchor"]["status"] == "VERIFIED" for o in u["outflows"])
                    and max(o["seconds_after_inflow"] for o in u["outflows"]) <= 80,
                    f"{u['hub_vpa']} received INR {u['inflow']['amount_inr']:,.0f}, fanned out to "
                    f"{len(u['mules'])} mules in {u['dispersal_span_s']} s")
        check(15, "GET /api/triage returns a rapid UPI smurfing cluster with 4+ mule accounts", c15)

        def c16():
            rx = getattr(_sector_b, "_NOTE_SERIAL", re.compile(r"^[0-9]{2}[A-HJ-NP-Z]\s?[0-9]{6}$"))
            hs = tri["mirror_hawala"]
            raw = _read_range(run["handset"]["image"], hs[0]["anchor"]["byte_offset"], hs[0]["anchor"]["length"]) or b""
            return (hs and all(rx.match(h["serial"]) for h in hs) and raw.decode("utf-8", "replace").replace(" ", "")
                    == hs[0]["normalized"],
                    f"serial {hs[0]['serial']} read back from the chat transcript (manual example 72B 948102; "
                    f"the pipeline's evidence holds {hs[0]['serial']})")
        check(16, "GET /api/triage includes the mirror-hawala currency note serial token", c16)

        gr = get_json("/api/graph")
        pc = gr["exhibits"]["PC"]
        exp = run["pc"]["expected"]

        def c17():
            n = gr["nodes"]
            kinds = sorted({x["kind"] for x in n})
            return len(n) >= 8 and len(kinds) >= 4, f"{len(n)} nodes of kinds {', '.join(kinds)}"
        check(17, "GET /api/graph returns at least 8 multi-modal entities", c17)

        def c18():
            ids = {x["id"] for x in gr["nodes"]}
            rels = set(gr["relation_names"])
            es = gr["edges"]
            steps = [e for e in es if e["kind"] == "step"]
            return (es and all(e["source"] in ids and e["target"] in ids and e["relation"] in rels for e in es)
                    and len(steps) == len(pc["storyline"]),
                    f"{len(es)} directed edges ({len(steps)} storyline steps + {len(es) - len(steps)} bindings)")
        check(18, "GET /api/graph returns edges with directed causal relations", c18)

        def c19():
            tot = anch = 0
            for ex in gr["exhibits"].values():
                for e in ex["edges"]:
                    tot += 1
                    anch += e["anchor"]["status"] == "VERIFIED" and isinstance(e["anchor"]["byte_offset"], int)
                tot += ex["t_pkg"]["edges_total"]
                anch += ex["t_pkg"]["edges_anchored"]
            merk = sum(1 for e in gr["exhibits"]["HANDSET"]["edges"]
                       if e["anchor"]["merkle"]["status"] == "INCLUSION_VERIFIED")
            return (tot and anch == tot,
                    f"{anch}/{tot} edges carry Ω (storyline edges re-hashed now; {merk} handset edges also "
                    f"proved into the Sector A Merkle root)")
        check(19, "100% of graph edges carry physical byte offsets (Ω)", c19)

        def c20():
            rows = pc["storyline"]
            known = [r["timestamp_utc"] for r in rows if r["timestamp_utc"]]
            return (len(rows) >= 10 and known == sorted(known) and [r["step"] for r in rows] ==
                    list(range(1, len(rows) + 1)),
                    f"PC exhibit {len(rows)} steps, HANDSET exhibit {len(gr['exhibits']['HANDSET']['storyline'])} steps")
        check(20, "GET /api/graph returns a chronological PCST storyline of 10+ steps", c20)

        def bind(key: str, pred: Callable[[Dict[str, Any]], bool]) -> Tuple[bool, str]:
            f, off, ln = exp[key]
            hits = [e for e in pc["edges"] if e["kind"] == "step" and e["anchor"]["source_file"] == f
                    and e["anchor"]["byte_offset"] == off and pred(e)]
            ok = len(hits) >= 1 and all(e["anchor"]["status"] == "VERIFIED" for e in hits)
            e = hits[0] if hits else None
            return ok, (f"storyline step {e['step']}: {e['narrative']} -> {f} @ Ω={off} ({off:#x}), sector {off // 512}"
                        if e else f"no step anchored at {f} @ {off}")

        check(21, "Storyline binds the fake CBI WhatsApp call to its whatsapp log offset",
              lambda: bind("call", lambda e: e["relation"] == "IMPERSONATED_CALL"
                           and b"CBI" in (_read_range(os.path.join(run["pc"]["dir"], e["anchor"]["source_file"]),
                                                      e["anchor"]["byte_offset"], e["anchor"]["length"]) or b"")))
        check(22, "Storyline binds Chrome spawning PowerShell to its Sysmon event offset",
              lambda: bind("chrome_ps", lambda e: e["relation"] == "SPAWNED"
                           and gr_label(pc, e["source"]).startswith("chrome.exe")
                           and gr_label(pc, e["target"]).startswith("powershell.exe")))
        check(23, "Storyline binds the Trojan's creation to its disk-image $MFT record offset",
              lambda: bind("mft_a_exe", lambda e: e["relation"] == "WROTE_FILE"
                           and gr_label(pc, e["target"]).endswith("a.exe") and "TIMESTOMP_INVERTED" in e["flags"]))
        check(24, "Storyline binds the C2 socket connection to its PCAP packet offset",
              lambda: bind("c2", lambda e: e["relation"] == "CONNECTED_TO"
                           and gr_label(pc, e["target"]).endswith(":443")))
        check(25, "Storyline binds the victim's funds transfer to its bank statement offset",
              lambda: bind("bank", lambda e: e["relation"] == "UPI_TRANSFER"
                           and gr_label(pc, e["target"]) == "hub.kyc@ybl"))
        check(26, "Storyline binds hub smurfing to its NPCI switch log offset",
              lambda: bind("npci_hub", lambda e: e["relation"] == "UPI_TRANSFER"
                           and gr_label(pc, e["source"]) == "hub.kyc@ybl"))

        exc = get_json("/api/exculpatory")

        def c27():
            cs = exc["checks"]
            return (len(cs) == 14 == exc["checks_evaluated"] and len({c["check"] for c in cs}) == 14
                    and all(c["result"] in ("SUPPORTS_ATTRIBUTION", "SUPPORTS_INTRUSION_HYPOTHESIS", "UNDETERMINED")
                            for c in cs),
                    f"{exc['supports_attribution']} support attribution, {exc['supports_intrusion_hypothesis']} "
                    f"support intrusion, {14 - exc['checks_determined']} undetermined")
        check(27, "GET /api/exculpatory returns 14 evaluated checklist points", c27)

        def c28():
            p = exc["trojan_defense_probability"]
            recomputed = round(exc["supports_intrusion_hypothesis"] / exc["checks_determined"], 4)
            return (isinstance(p, float) and 0.0 <= p <= 1.0 and abs(p - recomputed) < 5e-4 and exc["ratio_consistent"]
                    and exc["exculpatory_indicator_ratio_strict"] is not None,
                    f"trojan_defense_probability {p} (= {exc['supports_intrusion_hypothesis']}/"
                    f"{exc['checks_determined']}); {exc['ratio_display']}")
        check(28, "GET /api/exculpatory reports the Trojan-defence probability", c28)

        pdf_box: Dict[str, bytes] = {}

        def c29():
            st, hd, body = client.get("/download/certificate")
            pdf_box["pdf"] = body
            return (st == 200 and hd.get("content-type", "").startswith("application/pdf")
                    and "attachment" in hd.get("content-disposition", ""),
                    f"{hd.get('content-type')} · {hd.get('content-disposition')}")
        check(29, "GET /download/certificate returns HTTP 200 with content-type application/pdf", c29)

        def c30():
            body = pdf_box["pdf"]
            files = run["views"]["status"]["legal"]["files"]
            rec = files.get("BSA_2023_Sec63_Certificate.pdf", {})
            pages = len(re.findall(rb"/Type\s*/Page(?![s\w])", body))
            return (body[:5] == b"%PDF-" and len(body) > 10 * 1024 and _sha256_hex(body) == rec.get("sha256")
                    and body.rstrip().endswith(b"%%EOF") and pages >= 2,
                    f"{len(body):,} bytes, {pages} pages, sha256 matches Sector D's bundle manifest")
        check(30, "Downloaded certificate PDF begins with %PDF- and is > 10 KB", c30)

        def c31():
            st, hd, body = client.get("/download/str_xml")
            root = ET.fromstring(body)
            errs = _sector_d.validate_str_xml(body.decode("utf-8"))
            bodies["/download/str_xml"] = body.decode("utf-8")
            return (st == 200 and "xml" in hd.get("content-type", "") and root.tag.endswith("}FINnet2_STR")
                    and not errs, f"root {root.tag}; Sector D schema check: {len(errs)} errors")
        check(31, "GET /download/str_xml returns HTTP 200 with a valid <FINnet2_STR> root", c31)

        def c32():
            n = get_json("/download/freeze_notice")
            st2, hd2, _ = client.get("/download/freeze_notice?attachment=1")
            return (n["statute"].startswith("Section 106, Bharatiya Nagarik Suraksha Sanhita") and n["targets"]
                    and n["case_reference"] == CASE_ID and "SECTION 106" in n["text"]
                    and n["pmla_referral"]["order_issued_by_police"] is False and st2 == 200
                    and "attachment" in hd2.get("content-disposition", ""),
                    f"{n['notice_id']}: {len(n['targets'])} lien targets, aggregate INR "
                    f"{n['aggregate_lien_inr']:,.0f}; PMLA s.17(1A) left to the ED via s.66(2) intimation")
        check(32, "GET /download/freeze_notice returns HTTP 200 with the Section 106 BNSS freeze order", c32)

        def c33():
            st, hd, png = client.get("/api/qr")
            w, h = struct.unpack(">II", png[16:24])
            gen = run["legal"]["gen"]
            dec = _sector_d.qr_decode(_sector_d.matrix_from_png(png))
            return (st == 200 and hd.get("content-type") == "image/png" and png[:8] == b"\x89PNG\r\n\x1a\n"
                    and w == h and dec == gen._qr_bytes(),
                    f"{w}x{h} px; decodes back to the certificate's QR payload")
        check(33, "GET /api/qr returns a valid PNG of the verification QR code", c33)

        def c34():
            pats = _forbidden_patterns()
            lp = run["legal"]["paths"]
            bodies["certificate_data.json (Sector D)"] = _read_text(lp["certificate_json"])
            bodies["freeze notice text (Sector D)"] = _read_text(lp["freeze_notice_txt"])
            hits = []
            for name, text in bodies.items():
                for p in pats:
                    m = p.search(text)
                    if m:
                        hits.append(f"{name}: {text[max(0, m.start() - 20):m.end() + 20]!r}")
            return not hits and len(bodies) >= 10, (f"{len(bodies)} HTML/JSON/XML/text outputs scanned"
                                                   if not hits else "; ".join(hits[:3]))
        check(34, "Zero occurrences of the repealed evidence provision across all HTML/JSON outputs", c34)

        def c35():
            before = run["run_id"]
            st0, _, _ = client.request("POST", "/api/run")
            st, hd, body = client.request("POST", "/api/run", {"X-SUTRA-Action": "run"})
            r = json.loads(body)
            bodies["/api/run"] = body.decode("utf-8")
            st2 = get_json("/api/status")
            g405, _, _ = client.get("/api/run")
            return (st0 == 403 and st == 200 and r["ok"] and r["run_id"] == before + 1 and st2["run_id"] == before + 1
                    and all(x.startswith("MATCH") for x in r["sector_d_digest_checks"]) and r["within_budget"]
                    and g405 == 405
                    and st2["run_finished_utc"] != run["finished_utc"],
                    f"run #{before} -> #{r['run_id']} in {r['pipeline_seconds']:.2f} s; fresh digests re-verified by Sector D "
                    f"(same as previous run: {r['evidence_digests_same_as_previous_run']}); "
                    f"POST without X-SUTRA-Action refused (403); GET refused (405)")
        check(35, "POST /api/run re-executes the pipeline and returns updated status", c35)

        def c36():
            cur = app.run
            hs = cur["views"]["graph"]["exhibits"]["HANDSET"]
            pool = [e["anchor"] for e in hs["edges"]] + [l["anchor"] for l in cur["views"]["triage"]["all_leads"]]
            a = next(x for x in pool if x.get("source_file") == "case_bundle.img" and x.get("length", 0) > 0
                     and x.get("status") == "VERIFIED" and x["merkle"]["status"] == "INCLUSION_VERIFIED")
            q = f"/api/verify_anchor?exhibit=HANDSET&id={a['anchor_id']}&run={cur['run_id']}"
            r1 = get_json(q)
            img, off = cur["handset"]["image"], a["byte_offset"]
            with open(img, "r+b") as f:
                f.seek(off)
                orig = f.read(1)
                f.seek(off)
                f.write(bytes([orig[0] ^ 0xFF]))
            try:
                r2 = get_json(q)
            finally:
                with open(img, "r+b") as f:
                    f.seek(off)
                    f.write(orig)
            r3 = get_json(q)
            s409, _, _ = client.get(f"/api/verify_anchor?exhibit=HANDSET&id={a['anchor_id']}&run={cur['run_id'] - 1}")
            s404, _, _ = client.get(f"/api/verify_anchor?exhibit=HANDSET&id={'0' * 24}&run={cur['run_id']}")
            return (r1["mode"] == "LIVE" and r1["status"] == "VERIFIED" and r2["rehash"] == "MISMATCH"
                    and r2["status"] == "FAILED" and r3["status"] == "VERIFIED" and s409 == 409 and s404 == 404
                    and r3["verified_at_utc"] >= r1["verified_at_utc"],
                    f"{a['source_file']} @ {a['byte_offset_hex']}: live {r1['status']} -> one byte flipped on disk -> "
                    f"{r2['rehash']} (Merkle now {r2['merkle']['status']}) -> restored -> {r3['status']}; "
                    f"stale run 409, unknown anchor 404")
        check(36, "Live anchor re-verification reads the disk now and catches a tampered byte", c36)

        def c37():
            cur = app.run
            cands = [(k, cur[k.lower()]["image"], os.path.basename(cur[k.lower()]["image"])) for k in ("HANDSET", "PC")]
            ex, path, fname = max(cands, key=lambda c: os.path.getsize(c[1]))
            size = os.path.getsize(path)
            chunk = 4 << 20
            ln = min(size, 96 * 1024)
            off = chunk - ln // 2 if size >= chunk + ln // 2 else 0          # straddle a 4 MB boundary if possible
            rec = _sha256_hex(_read_range(path, off, ln) or b"")
            out = cur["inspectors"][ex].inspect({"source_file": fname, "byte_offset": off, "length": ln, "sha256": rec})
            m = out["merkle"]
            big = m["needed"] > 64
            return (out["status"] == "VERIFIED" and m["status"] == "INCLUSION_VERIFIED" and m["proved"] == m["needed"]
                    and sum(c["proved"] for c in m["chunks_spanned"]) == m["needed"] and (big or size <= 66 * 1024),
                    f"{fname}: {ln:,} B anchor @ {off:#x}, {m['proved']}/{m['needed']} sub-blocks proved across "
                    f"{len(m['chunks_spanned'])} chunk(s) (pre-fix cap was 64)")
        check(37, "Anchors over 64 KB prove every sub-block, with an audit path per 4 MB chunk", c37)

        def c38():
            cur = app.run
            body, digest = cur["legal"]["blobs"]["certificate_pdf"]
            st, hd, got = client.request("HEAD", "/download/certificate")
            st2, hd2, got2 = client.get("/download/certificate")
            return (st == 200 and got == b"" and int(hd.get("content-length", "-1")) == len(body) == len(got2)
                    and hd.get("x-content-sha256") == digest == _sha256_hex(got2) and st2 == 200,
                    f"HEAD Content-Length {hd.get('content-length')} = GET body {len(got2):,} B; served from memory")
        check(38, "HEAD reports the real Content-Length; downloads come from the in-memory run copy", c38)

        def c39():
            before = app.run["run_id"]
            st, hd, body = client.request("POST", "/api/run", {"X-SUTRA-Action": "run"}, body=b"x" * (MAX_BODY_BYTES + 1))
            r = json.loads(body)
            return (st == 413 and r["status"] == 413 and app.run["run_id"] == before,
                    f"{backend}: {MAX_BODY_BYTES + 1:,} B body refused with 413; no pipeline run started")
        check(39, f"Request bodies over {MAX_BODY_BYTES // 1024} KB are refused (413) on the {backend} engine", c39)

        def c40():
            html = html_box["html"]
            feats = {
                "WebGL Holo-Core": 'getContext("webgl"' in html and "class HoloCore" in html,
                "2D fallback": "if(!this.gl)this.geo2d=holoGeometry()" in html,
                "cursor spotlight": "--mx" in html and "radial-gradient(600px circle at var(--mx" in html,
                "live ENF/PTT/UPI": all(f in html for f in ("function enfLive", "function pttLive", "function animateFan")),
                "graph pan/zoom": "function bindPanZoom" in html and "function causalPath" in html,
                "hex terminal": "function termHex" in html,
            }
            urls = set(re.findall(r"https?://[^\s\"'<>)]+", html))
            egress = sorted(u for u in urls if u != "http://www.w3.org/2000/svg")
            imports = re.findall(r"@import|<link\b|url\(\s*['\"]?(?:https?:)?//|new\s+(?:WebSocket|EventSource)\b", html, re.I)
            tags = re.findall(r"<(script|style)\b([^>]*)>", html, re.I)
            unnonced = [t for t, attrs in tags if "nonce=" not in attrs]
            missing = [k for k, v in feats.items() if not v]
            ok = not missing and not egress and not imports and tags and not unnonced
            return ok, (f"{len(feats) - len(missing)}/{len(feats)} r5 features inline; network URLs: {len(egress)}; "
                        f"@import/link/external url(): {len(imports)}; {len(tags)} script/style tags, all nonce'd: {not unnonced}"
                        + (f"; missing {missing}" if missing else "") + (f"; egress {egress[:3]}" if egress else ""))
        check(40, "Cockpit r5 is self-contained: WebGL core, live canvases and graph pan/zoom inline, zero egress", c40)
    finally:
        if client is not None:
            client.close()
        app.close()

    passed = sum(1 for _, ok, _ in results.values() if ok)
    total = len(results)
    print("-" * 78)
    for n, (name, ok, detail) in sorted(results.items()):
        if not ok:
            print(f"  FAILED {n}. {name}: {detail}")
    print(f"{passed}/{total} checks passed  ·  {time.perf_counter() - t_start:.2f} s")
    reg_passed, reg_total = _overnight_audit_checks(keep)
    return 0 if passed == total == EXPECTED_CHECKS and reg_passed == reg_total > 0 else 1


def _overnight_audit_checks(keep: bool = False) -> Tuple[int, int]:
    """
    Regression checks for the overnight audit of this file (findings E-01 ... E-12, E-SIG01; E-ESC01 is
    E-06). Each one failed on the code before its fix. Runs on its own pipeline run in a fresh shared work
    folder, after the 39 numbered checks, and returns (passed, total).
    """
    import contextlib
    results: List[Tuple[str, bool, str]] = []

    def check(fid: str, name: str, fn: Callable[[], Tuple[Any, str]]) -> None:
        try:
            ok, detail = fn()
            ok = bool(ok)
        except Exception as e:  # a crash is a failed check, never a silent pass
            ok, detail = False, f"{type(e).__name__}: {e}"
        results.append((f"{fid}: {name}", ok, detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {fid:<7} {name}" + (f"  ({detail})" if detail else ""))

    print("\nOvernight audit regression checks")
    root = tempfile.mkdtemp(prefix="sutra_cockpit_audit_")
    apps: List[CockpitApp] = []
    try:
        app = CockpitApp(root)
        apps.append(app)
        run = app.execute()

        def raw(port: int, data: bytes) -> bytes:
            with socket.create_connection(("127.0.0.1", port), timeout=20) as so:
                so.sendall(data)
                buf = b""
                while True:
                    got = so.recv(65536)
                    if not got:
                        return buf
                    buf += got

        def r_e01():
            srv = make_stdlib_server(app, "127.0.0.1", 0, quiet=True)
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            old_err, sys.stderr = sys.stderr, io.StringIO()
            try:
                d = app.dispatch("GET", "http://[x/api/status", {})
                r1 = raw(port, b"GET http://[x/api/status HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n" % port)

                def boom(*_a: Any, **_k: Any) -> Response:
                    raise RuntimeError("simulated route failure")
                app.dispatch = boom  # type: ignore[assignment]
                try:
                    r2 = raw(port, b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n" % port)
                finally:
                    del app.dispatch
            finally:
                sys.stderr = old_err
                srv.shutdown()
                srv.server_close()
            return (d.status == 400 and r1.startswith(b"HTTP/1.1 400") and r2.startswith(b"HTTP/1.1 500"),
                    f"dispatch {d.status}; raw 'GET http://[x/...' -> {r1[:12].decode('latin-1') or 'no reply'}; "
                    f"a route that raises -> {r2[:12].decode('latin-1') or 'no reply'}")
        check("E-01", "A malformed request target gets 400; no request ends without a response", r_e01)

        def r_e02():
            insp = run["inspectors"]["PC"]
            fname = "victim_disk.img"
            vault, manifest, path = insp.vaults[fname]
            ln = min(os.path.getsize(path), MAX_ANCHOR_READ)
            prov = {"source_file": fname, "byte_offset": 0, "length": ln,
                    "sha256": _sha256_hex(_read_range(path, 0, ln) or b"")}
            aid = insp.inspect(prov)["anchor_id"]
            wb = vault.write_blocker
            opens = [0]
            real_open = wb.open_read_only

            def counting(p: str) -> int:
                opens[0] += 1
                return real_open(p)
            wb.open_read_only = counting
            try:
                t0 = time.perf_counter()
                out = insp.inspect_live(aid)
                dt = time.perf_counter() - t0
            finally:
                del wb.open_read_only
            m = out["merkle"]  # type: ignore[index]
            idxs = sorted({0, 1, m["needed"] // 2, m["needed"] - 1})
            same = insp._proofs_for(fname, idxs, cache=False) == [vault.prove_sub_block(path, manifest, i) for i in idxs]
            chunks = len(m["chunks_spanned"])
            return (out["status"] == "VERIFIED" and m["proved"] == m["needed"] > 512 and opens[0] == chunks and same,  # type: ignore[index]
                    f"{ln:,} B anchor: {m['proved']}/{m['needed']} sub-blocks proved with {opens[0]} chunk read(s) "
                    f"for {chunks} chunk(s) in {dt:.2f} s; proofs identical to prove_sub_block(): {same}")
        check("E-02", "Proving an anchor reads and hashes each 4 MB chunk once, not once per sub-block", r_e02)

        def r_e03():
            insp = run["inspectors"]["HANDSET"]
            aid = next(a for a, p in insp._index.items() if str(p.get("source_file") or "") in insp.vaults)
            log = insp.vaults[str(insp._index[aid].get("source_file"))][0].write_blocker.log
            n0 = len(log)
            outs = [insp.inspect_live(aid) for _ in range(50)]
            return (len(log) == n0 and all(o and o["status"] == "VERIFIED" for o in outs),
                    f"write-blocker log {n0} -> {len(log)} entries after 50 live re-verifications")
        check("E-03", "Live re-verification does not grow Sector A's write-blocker log", r_e03)

        def r_e04():
            other = CockpitApp(root)
            apps.append(other)
            run_b = other.execute()
            insp = run["inspectors"]["HANDSET"]
            aid = next(a for a, p in insp._index.items() if str(p.get("source_file") or "") in insp.vaults)
            live = insp.inspect_live(aid)
            return (run["workdir"] != run_b["workdir"] and os.path.isdir(run["workdir"])
                    and os.path.isfile(run["handset"]["image"]) and live is not None and live["status"] == "VERIFIED",
                    f"two cockpits on one --workdir: {os.path.relpath(run['workdir'], root)} and "
                    f"{os.path.relpath(run_b['workdir'], root)}; the first one's live check after the second ran: "
                    f"{live and live['status']}")
        check("E-04", "Each process keeps its own run folders under a shared --workdir", r_e04)

        def r_e05():
            global _ON_WINDOWS
            was = globals().get("_ON_WINDOWS", os.name == "nt")
            _ON_WINDOWS = True    # simulate Windows: SO_REUSEADDR must not be set there
            try:
                s1 = make_stdlib_server(app, "127.0.0.1", 0, quiet=True)
                win = s1.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
                s1.server_close()
            finally:
                _ON_WINDOWS = was
            s2 = make_stdlib_server(app, "127.0.0.1", 0, quiet=True)
            here = s2.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
            s2.server_close()
            return (win == 0 and (here != 0) == (os.name != "nt"),
                    f"SO_REUSEADDR with Windows simulated: {win}; on this {os.name} host: {here}")
        check("E-05", "On Windows the stdlib engine never binds with SO_REUSEADDR", r_e05)

        def r_e06():
            det = _sector_b.FinancialMuleDetector()
            a = det.bridge_affinity({"epoch": 1000, "amount_inr": 59000}, {"epoch": 990, "amount_usdt": 665.2})
            b2 = json.loads(json.dumps(run["handset"]["b"]))
            lead = next(l for l in b2["symbolic_anchors"] if l.get("threat_category") == "CROSS_CHAIN_BRIDGE")
            lead["lead_details"]["delta_t_s"] = a["delta_t_s"]
            view = triage_view(dict(run, handset=dict(run["handset"], b=b2)))
            row = next(r for r in view["cross_chain_bridge"] if r["lead_id"] == lead["lead_id"])
            return (a["affinity"] > 0 and row["within_escrow_window"] is True
                    and row["escrow_window_bounds_s"] == [-det.CLOCK_SKEW_S, det.TAU_ESCROW_S],
                    f"Sector B matches dt {a['delta_t_s']} s (affinity {a['affinity']}); cockpit window "
                    f"{row.get('escrow_window_bounds_s')} -> within {row['within_escrow_window']}")
        check("E-06", "The cockpit escrow window is Sector B's [-clock skew, tau_escrow]", r_e06)

        def r_e07():
            fmt_ok = (_cockpit_url("::1", 5077) == "http://[::1]:5077/" and _cockpit_url("0.0.0.0", 80) ==
                      "http://127.0.0.1:80/" and _bind_host("") == "0.0.0.0" and _bind_host("[::1]") == "::1"
                      and _host_family("::1") == socket.AF_INET6)
            v6 = "IPv6 not available on this host"
            try:
                socket.socket(socket.AF_INET6, socket.SOCK_STREAM).close()
                s6 = make_stdlib_server(app, "::1", 0, quiet=True)
                v6 = f"bound {s6.server_address[0]} port {s6.server_address[1]}"
                s6.server_close()
            except OSError as e:
                if not isinstance(e, socket.gaierror) and getattr(e, "errno", None) in (97, 99, 10047, 10049):
                    v6 = "IPv6 not available on this host"
                else:
                    raise
            fails = []
            hold = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            hold.bind(("127.0.0.1", 0))
            hold.listen(1)
            port = hold.getsockname()[1]
            calls: List[str] = []
            real_open = webbrowser.open
            webbrowser.open = lambda *a, **k: calls.append("browser") or True  # type: ignore[assignment]
            try:
                for be in ["stdlib"] + (["flask"] if _flask is not None else []):
                    probe = CockpitApp()

                    def no_run() -> Dict[str, Any]:
                        calls.append("pipeline")
                        raise RuntimeError("the pipeline ran before the port was bound")
                    probe.execute = no_run  # type: ignore[assignment]
                    try:
                        with contextlib.redirect_stdout(io.StringIO()):
                            serve(probe, "127.0.0.1", port, be, True)
                        fails.append(f"{be}: no error")
                    except OSError:
                        pass
                    except Exception as e:
                        fails.append(f"{be}: {type(e).__name__}: {e}")
                    finally:
                        probe.close()
            finally:
                webbrowser.open = real_open  # type: ignore[assignment]
                hold.close()
            return (fmt_ok and not fails and not calls,
                    f"URL/host forms ok: {fmt_ok}; ::1 {v6}; taken port refused before the pipeline or a "
                    f"browser: {not fails and not calls}{' ' + '; '.join(fails) if fails else ''}")
        check("E-07", "IPv6 hosts bind and print as URLs; the port is bound before the run and browser", r_e07)

        def r_e08():
            probe = CockpitApp()

            def interrupted() -> Dict[str, Any]:
                raise KeyboardInterrupt
            probe.execute = interrupted  # type: ignore[assignment]
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    rc_serve = serve(probe, "127.0.0.1", 0, "stdlib", False)
            except KeyboardInterrupt:
                rc_serve = "KeyboardInterrupt escaped"
            leaked = os.path.isdir(probe.base)
            probe.close()
            real_serve = globals()["serve"]

            def failing_serve(a: CockpitApp, *_x: Any) -> int:
                a.close()
                raise ValueError("a sector raised a non-OSError")
            globals()["serve"] = failing_serve
            err = io.StringIO()
            try:
                with contextlib.redirect_stderr(err):
                    rc_main = _main(["--serve", "--no-browser", "--port", "5099"])
            finally:
                globals()["serve"] = real_serve
            afile = os.path.join(root, "afile")
            with open(afile, "w", encoding="utf-8") as f:
                f.write("x")
            with contextlib.redirect_stdout(io.StringIO()):
                rc_self = _self_test(afile)
            msg = err.getvalue().strip()
            return (rc_serve == 0 and not leaked and rc_main == 2 and msg.startswith("cannot start the cockpit:")
                    and "Traceback" not in msg and rc_self == 2,
                    f"interrupted first run: serve -> {rc_serve}, temp folder left: {leaked}; sector ValueError: "
                    f"_main -> {rc_main} '{msg}'; --workdir is a file: self-test -> {rc_self}")
        check("E-08", "A failed or interrupted start cleans up and ends in one line, not a traceback", r_e08)

        def r_e09():
            before = app.run["run_id"]  # type: ignore[index]
            r = app.dispatch("POST", "/api/run", {"X-SUTRA-Action": "run", "Origin": "http://[x", "Host": "127.0.0.1:5000"})
            return (r.status == 403 and app.run["run_id"] == before,  # type: ignore[index]
                    f"Origin 'http://[x' -> {r.status}; no pipeline run started")
        check("E-09", "A malformed Origin on POST /api/run is refused with 403", r_e09)

        def r_e10():
            h = object.__new__(_Handler)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                h.log_message('"%s" %s %s', "GET /\x1b[2J\x1b[31mFAKE-LOG-LINE\x1b[0m\x9b HTTP/1.1", "404", "-")
            out = err.getvalue()
            return ("\x1b" not in out and "\x9b" not in out and "\\x1b[2J" in out,
                    "logged as " + out.strip().split("  ", 1)[-1])
        check("E-10", "Request-line control characters are escaped in the console log", r_e10)

        def r_e11():
            saved = app.allowed_hosts
            before = app.run["run_id"]  # type: ignore[index]
            try:
                app.set_bind("0.0.0.0", 5000)
                bad = "rebind.attacker.example:5000"
                s1 = app.dispatch("GET", "/api/vault", {"Host": bad}).status
                s2 = app.dispatch("POST", "/api/run", {"Host": bad, "Origin": f"http://{bad}",
                                                       "X-SUTRA-Action": "run"}).status
                s3 = app.dispatch("GET", "/api/status", {"Host": "127.0.0.1:5000"}).status
                hn = socket.gethostname().lower()
                s4 = app.dispatch("GET", "/api/status", {"Host": f"{hn}:5000"}).status if hn else 200
            finally:
                app.allowed_hosts = saved
            return (s1 == 421 and s2 == 421 and s3 == 200 and s4 == 200 and app.run["run_id"] == before,  # type: ignore[index]
                    f"--host 0.0.0.0: rebound Host GET {s1}, POST /api/run {s2}; 127.0.0.1 {s3}; "
                    f"this machine's name {s4}")
        check("E-11", "A wildcard bind still refuses a DNS-rebound Host header (421)", r_e11)

        def r_e12():
            insp = run["inspectors"]["PC"]
            gone = os.path.join(root, "no_such_image.img")
            other = next(n for n in insp.roots if n not in insp.vaults)
            insp2 = AnchorInspector("PC", dict(insp.roots, **{"victim_disk.img": gone, other: gone}), insp.vaults)
            o1 = insp2.inspect({"source_file": "victim_disk.img", "byte_offset": 0, "length": 64, "sha256": "0" * 64})
            o2 = insp2.inspect({"source_file": other, "byte_offset": 0, "length": 64, "sha256": "0" * 64})
            return (o1["status"] == "FAILED" and o1["rehash"] == "UNREADABLE" and o1["merkle"]["status"] == "NOT_EVALUATED"
                    and o2["merkle"]["status"] == "NOT_IN_VAULTED_IMAGE",
                    f"vaulted image missing: {o1['status']} / rehash {o1['rehash']} / Merkle {o1['merkle']['status']}; "
                    f"other source missing: Merkle {o2['merkle']['status']}")
        check("E-12", "A missing vaulted image is reported as not evaluated, not as another file", r_e12)

        def r_sig():
            a2 = json.loads(json.dumps(run["handset"]["a"]))
            seal = a2["bnss_verification"]["sec_106_malkhana_seal_ledger"]
            seal["signatures"] = {
                "field": {"signer_id": "SI-X", "algorithm": "Ed25519", "public_key_hex": "11" * 32,
                          "signature_hex": "22" * 64, "status": "INVALID"},
                "malkhana": {"signer_id": "HC-Y", "algorithm": "Ed25519", "public_key_hex": "33" * 32,
                             "signature_hex": "44" * 64, "status": "VALID"}}
            v = vault_view(dict(run, handset=dict(run["handset"], a=a2)))
            ch = v["seal_chain"]
            return (ch[0]["signed"] is False and ch[0]["signature_status"] == "INVALID" and ch[1]["signed"] is True
                    and ch[2]["signed"] is False and "field INVALID" in v["seal_signatures"],
                    f"signed {[c['signed'] for c in ch]}; officer signatures: {v['seal_signatures']}")
        check("E-SIG01", "A s.106 milestone counts as signed only when Sector A verified it VALID", r_sig)
    except Exception as e:  # the group itself could not run: that is a failure, never a silent pass
        results.append(("overnight audit group", False, f"{type(e).__name__}: {e}"))
        print(f"  [FAIL] overnight audit group could not run: {type(e).__name__}: {e}")
    finally:
        for a in apps:
            a.close()
        if not keep:
            shutil.rmtree(root, ignore_errors=True)
    passed = sum(1 for _, ok, _ in results if ok)
    for name, ok, detail in results:
        if not ok:
            print(f"  FAILED {name}: {detail}")
    print(f"{passed}/{len(results)} overnight audit regression checks passed")
    return passed, len(results)


def gr_label(ex: Dict[str, Any], node_id: str) -> str:
    for n in ex["nodes"]:
        if n["id"] == node_id:
            return n["label"]
    return ""


# --------------------------------------------------------------------------- #
# Entry point                                                                 #
# --------------------------------------------------------------------------- #

def _main(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(prog="sector_e_dashboard.py",
                                 description="SUTRA-Trace Sector E: self-test (default) or interactive cockpit.")
    ap.add_argument("--serve", action="store_true", help="start the web cockpit")
    ap.add_argument("--port", type=int, default=None, help=f"port for the cockpit (default {DEFAULT_PORT}; implies --serve)")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1, loopback only)")
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    ap.add_argument("--backend", choices=("auto", "flask", "stdlib"), default="auto",
                    help="web server: Flask when installed (auto), or the standard library")
    ap.add_argument("--workdir", default=None, help="where runs are written (default: a temporary folder)")
    ap.add_argument("--keep", action="store_true", help="keep the temporary run folder on exit")
    args = ap.parse_args(list(argv))
    if args.serve or args.port is not None:
        port = args.port if args.port is not None else DEFAULT_PORT
        if not 0 < port < 65536:
            ap.error("--port must be 1-65535")
        try:
            _require_sectors()
            return serve(CockpitApp(args.workdir, keep=args.keep), args.host, port, args.backend,
                         not args.no_browser)
        except KeyboardInterrupt:
            return 130
        except (CockpitError, OSError) as e:
            print(f"cannot start the cockpit: {e}", file=sys.stderr)
            return 2
        except Exception as e:   # a sector's own error: one line, never a traceback (overnight audit E-08)
            print(f"cannot start the cockpit: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
    return _self_test(args.workdir, args.backend, args.keep)


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
