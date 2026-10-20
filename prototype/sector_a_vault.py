#!/usr/bin/env python3
"""
SUTRA-Trace · Sector A: Deterministic Evidence Vault & Cryptographic Anchoring
==============================================================================

Foundational acquisition layer of the SUTRA-Trace digital forensics framework
(SUTRAM 2026, PS-01). Sectors B-E import this module; it imports none of them.

Revision 2 hardens the first build against a hostile Section 63 BSA audit:

  Statutory guards
    * Every manifest carries an admissibility verdict (READY_FOR_COURT,
      PROVISIONAL or REJECTED_FOR_COURT) with the exact blocking issues. An
      unverified Section 105 video, an edit-listed (trimmed/spliced) MP4, missing
      Section 106 seals, a broken Faraday seal or a lab/field seal mismatch all
      reject the acquisition; strict=True raises StatutoryViolationError.
    * Custody milestones are length-prefix encoded (no delimiter injection) and
      can carry Ed25519 signatures from the officers' own keys; they are
      verified when the optional `cryptography` package is present.
    * Time is anchored by a real RFC 3161 TimeStampReq sent to a configured TSA.
      The .tsq/.tsr pair is saved so `openssl ts -verify` can check it
      independently. Without a TSA the manifest says NOT_ANCHORED.

  Acquisition safety
    * One descriptor is opened (O_RDONLY | O_BINARY | O_NOFOLLOW) and every check
      uses it, closing the stat/open/stat race; the path is re-checked against
      the descriptor's identity at the end.
    * Block devices: size from lseek(SEEK_END), kernel read-only flag (BLKROGET)
      required and mounted devices refused, unless explicitly overridden.
    * Known-bad sectors are never read. A read error marks only the failing
      sector and reading resumes after it (no second timeout on the same sector).
    * Page cache is released after every 4 MB chunk (posix_fadvise DONTNEED).
    * Optional acquired image output, so `sha256sum image` reproduces the
      linear hash even when bad sectors were filled with 0xDEADBEEF.

  Cryptography
    * RFC 6962 Merkle tree: 0x00 leaf / 0x01 node prefixes, odd nodes promoted
      (never duplicated). The disk root equals the RFC 6962 tree head over all
      1 KB sub-blocks. Proofs are index-based; duplicate leaves never confuse them.
    * The secondary tree hash and master root record the algorithm actually used
      (BLAKE3 or the stdlib BLAKE2s fallback), and verification uses the recorded
      one. A BLAKE2s digest is never stored under a BLAKE3 field name.
    * Canonical JSON rejects NaN/Infinity and encodes floats by their shortest
      round-trip form, so manifests hash identically on every platform.

  Section 105 video
    * Streams the audio (no whole-track load), decimates to 1 kHz and tracks the
      50 Hz ENF phase in bounded memory. AAC/Opus tracks are decoded by ffmpeg
      when available, otherwise the video is marked unverified.
    * Edit lists (edts/elst), fragmented MP4, duplicate moov and oversized moov
      are detected; frame-rate continuity is checked against both the previous
      frame and the median frame (catches gradual ramps), ignoring the final
      stop-button frame.

Still simulation hooks, and labelled so in the manifest: the eBPF NVMe/SCSI
filter, NVMe APST quiescence, NavIC clock discipline, the VBS/HVCI physical
memory conduit and F2FS checkpoint diffing.
"""

from __future__ import annotations

import array
import base64
import datetime
import hashlib
import json
import math
import operator
import os
import shutil
import stat
import struct
import subprocess
import sys
import time
import urllib.request
import uuid
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Set, Tuple

try:  # Optional accelerator; never required.
    import blake3 as _blake3_mod  # type: ignore
except Exception:  # pragma: no cover - depends on host
    _blake3_mod = None

try:  # Optional, only for Ed25519 custody signatures.
    from cryptography.exceptions import InvalidSignature  # type: ignore
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # type: ignore
        Ed25519PrivateKey, Ed25519PublicKey)
except Exception:  # pragma: no cover - depends on host
    Ed25519PublicKey = None  # type: ignore

VAULT_VERSION = "SUTRA-VAULT-2026.3-SUPREME-r2"
MANIFEST_FILENAME = "evidence_manifest.json"
O_READ_ONLY = os.O_RDONLY | getattr(os, "O_BINARY", 0)
MAX_MOOV_BYTES = 256 * 1024 * 1024

READY = "READY_FOR_COURT"
PROVISIONAL = "PROVISIONAL"
REJECTED = "REJECTED_FOR_COURT"


class StatutoryViolationError(RuntimeError):
    """Raised by strict ingestion when the manifest is REJECTED_FOR_COURT."""

    def __init__(self, manifest: Dict[str, Any]):
        self.manifest = manifest
        super().__init__("; ".join(manifest["admissibility"]["blocking_issues"]))


class WriteProtectionError(PermissionError):
    """Raised when a block device is not protected against writes."""


# --------------------------------------------------------------------------- #
# Hash and encoding helpers
# --------------------------------------------------------------------------- #

def _sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _lp_hash(domain: bytes, *fields: bytes) -> bytes:
    """SHA-256 over length-prefixed fields: no delimiter can shift a boundary."""
    h = hashlib.sha256()
    for f in (domain,) + fields:
        h.update(struct.pack(">Q", len(f)))
        h.update(f)
    return h.digest()


def default_tree_algorithm() -> str:
    return "blake3" if _blake3_mod is not None else "blake2s-256"


def _new_tree_hasher(alg: str):
    if alg == "blake3":
        if _blake3_mod is None:
            raise RuntimeError("manifest uses BLAKE3 but the blake3 package is not installed here")
        return _blake3_mod.blake3()
    if alg == "blake2s-256":
        return hashlib.blake2s(digest_size=32)
    raise ValueError(f"unknown tree hash algorithm {alg!r}")


def _tree_hex(alg: str, *parts: bytes) -> str:
    h = _new_tree_hasher(alg)
    for p in parts:
        h.update(p)
    return h.hexdigest()


def _canonicalize(obj: Any) -> Any:
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError("NaN/Infinity are not allowed in a canonical manifest")
        return {"$float": repr(obj)}
    if isinstance(obj, dict):
        return {str(k): _canonicalize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_canonicalize(v) for v in obj]
    return obj


def _canonical_json(obj: Any) -> bytes:
    """Sorted, compact, NaN-free JSON with floats in shortest round-trip form."""
    return json.dumps(_canonicalize(obj), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _hash_file_streaming(path: str, block: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for buf in iter(lambda: f.read(block), b""):
            h.update(buf)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# RFC 6962 Merkle primitives
# --------------------------------------------------------------------------- #

def _leaf_hash(data: bytes) -> bytes:
    return _sha256(b"\x00", data)


def _node_hash(left: bytes, right: bytes) -> bytes:
    return _sha256(b"\x01", left, right)


def _merkle_levels(nodes: Sequence[bytes]) -> List[List[bytes]]:
    """All levels, bottom first. An unpaired last node is promoted unchanged (RFC 6962)."""
    if not nodes:
        return [[_sha256(b"")]]
    levels = [list(nodes)]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = [_node_hash(cur[i], cur[i + 1]) for i in range(0, len(cur) - 1, 2)]
        if len(cur) % 2:
            nxt.append(cur[-1])
        levels.append(nxt)
    return levels


def _proof_from_levels(levels: List[List[bytes]], index: int) -> List[Dict[str, str]]:
    proof = []
    for level in levels[:-1]:
        sib = index ^ 1
        if sib < len(level):
            proof.append({"position": "right" if index % 2 == 0 else "left", "hash": level[sib].hex()})
        index //= 2
    return proof


def verify_merkle_proof(leaf_hash: str, proof: List[Dict[str, str]], root_hash: str) -> bool:
    """Recompute a root from a (domain-separated) leaf hash and its audit path."""
    cur = bytes.fromhex(leaf_hash)
    for step in proof:
        sib = bytes.fromhex(step["hash"])
        cur = _node_hash(sib, cur) if step["position"] == "left" else _node_hash(cur, sib)
    return cur.hex() == root_hash


def bad_sectors_from_bitmask(mask: Sequence[int]) -> List[int]:
    """Convert a health bitmask M (1 = healthy, 0 = unreadable) to bad-sector indices."""
    return [i for i, m in enumerate(mask) if not m]


class MerkleNode:
    """
    A node of a Merkle tree. Trees from build_merkle_tree() keep their hashes in
    compact per-level lists and create child nodes only when they are visited.
    """

    def __init__(self, hash_val: str, left: Optional["MerkleNode"] = None, right: Optional["MerkleNode"] = None):
        self.hash_val = hash_val
        self._left = left
        self._right = right
        self._levels: Optional[List[List[bytes]]] = None
        self._lvl = 0
        self._idx = 0

    @classmethod
    def _from_levels(cls, levels: List[List[bytes]], lvl: int, idx: int) -> "MerkleNode":
        node = cls(levels[lvl][idx].hex())
        node._levels, node._lvl, node._idx = levels, lvl, idx
        return node

    @property
    def left(self) -> Optional["MerkleNode"]:
        if self._levels is None:
            return self._left
        return MerkleNode._from_levels(self._levels, self._lvl - 1, 2 * self._idx) if self._lvl else None

    @property
    def right(self) -> Optional["MerkleNode"]:
        if self._levels is None:
            return self._right
        if not self._lvl or 2 * self._idx + 1 >= len(self._levels[self._lvl - 1]):
            return None
        return MerkleNode._from_levels(self._levels, self._lvl - 1, 2 * self._idx + 1)

    @property
    def is_leaf(self) -> bool:
        return self.left is None and self.right is None


# --------------------------------------------------------------------------- #
# 2.1 Write protection
# --------------------------------------------------------------------------- #

def _get_fd_size(fd: int) -> int:
    """Byte size of a file or block device (fstat reports 0 for block devices)."""
    st = os.fstat(fd)
    if stat.S_ISBLK(st.st_mode) or stat.S_ISCHR(st.st_mode):
        size = os.lseek(fd, 0, os.SEEK_END)
        os.lseek(fd, 0, os.SEEK_SET)
        return size
    return st.st_size


def _drop_page_cache(fd: int, offset: int, length: int) -> None:
    if hasattr(os, "posix_fadvise") and hasattr(os, "POSIX_FADV_DONTNEED"):
        try:
            os.posix_fadvise(fd, offset, length, os.POSIX_FADV_DONTNEED)
        except OSError:
            pass


class DualBusWriteBlocker:
    """
    Forensic hardware write-blocking for NVMe and SCSI buses.

    Enforced here: a single read-only descriptor, an identity and size/mtime
    check of the source on that descriptor, and for Linux block devices the
    kernel read-only flag (blockdev --setro) and a not-mounted check.
    Simulation hook only: the eBPF opcode filter and NVMe APST quiescence, which
    need a kernel component. The manifest reports them as not applied.
    """

    NVME_BLOCKED_OPCODES = {
        0x01: "Write",
        0x08: "Write Zeroes",
        0x09: "Dataset Management (Deallocate/TRIM)",
        0x80: "Format NVM",
        0x84: "Sanitize",
    }
    SCSI_BLOCKED_OPCODES = {
        0x2A: "WRITE(10)",
        0x8A: "WRITE(16)",
        0x42: "UNMAP",
    }
    BLKROGET = 0x125E

    def __init__(self) -> None:
        self.log: List[str] = []

    def kernel_filter_plan(self) -> Dict[str, Any]:
        """The opcode policy a kernel filter would enforce. Nothing is attached."""
        return {
            "status": "NOT_APPLIED (simulation hook; requires an eBPF/kernel write blocker)",
            "nvme_opcodes_to_deny": {f"0x{k:02X}": v for k, v in self.NVME_BLOCKED_OPCODES.items()},
            "scsi_opcodes_to_deny": {f"0x{k:02X}": v for k, v in self.SCSI_BLOCKED_OPCODES.items()},
            "nvme_apst_quiesce": "NOT_APPLIED (simulation hook)",
        }

    def is_opcode_permitted(self, bus: str, opcode: int) -> bool:
        table = self.NVME_BLOCKED_OPCODES if bus.lower() == "nvme" else self.SCSI_BLOCKED_OPCODES
        permitted = opcode not in table
        if not permitted:
            self.log.append(f"policy: deny {bus.upper()} opcode 0x{opcode:02X} ({table[opcode]})")
        return permitted

    def open_read_only(self, path: str) -> int:
        fd = os.open(path, O_READ_ONLY | getattr(os, "O_NOFOLLOW", 0))
        self.log.append(f"Opened {os.path.basename(path)} read-only (O_RDONLY|O_BINARY|O_NOFOLLOW)")
        return fd

    @staticmethod
    def identity(st: os.stat_result) -> Tuple[int, int, int, int]:
        return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)

    def check_block_device(self, fd: int, path: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {"kernel_read_only": None, "mounted": None}
        try:
            import fcntl
            buf = fcntl.ioctl(fd, self.BLKROGET, struct.pack("i", 0))
            info["kernel_read_only"] = bool(struct.unpack("i", buf)[0])
        except Exception as e:  # non-Linux or ioctl unsupported
            info["kernel_read_only_error"] = str(e)
        try:
            real = os.path.realpath(path)
            with open("/proc/mounts", "r") as f:
                mounted = [ln.split()[0] for ln in f if ln.startswith("/dev/")]
            info["mounted"] = any(os.path.realpath(m) == real or os.path.realpath(m).startswith(real)
                                  for m in mounted)
        except OSError:
            pass
        self.log.append(f"Block device check: {info}")
        return info


# --------------------------------------------------------------------------- #
# 2.7 RFC 3161 (minimal DER, stdlib only)
# --------------------------------------------------------------------------- #

def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + length + content


def _der_int(v: int) -> bytes:
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
    return _der(0x02, b)


_SHA256_ALG_ID = _der(0x30, bytes.fromhex("0609608648016503040201") + b"\x05\x00")


def build_timestamp_request(digest: bytes, nonce: int) -> bytes:
    """DER TimeStampReq (RFC 3161 section 2.4.1) for a SHA-256 message imprint."""
    imprint = _der(0x30, _SHA256_ALG_ID + _der(0x04, digest))
    return _der(0x30, _der_int(1) + imprint + _der_int(nonce) + _der(0x01, b"\xff"))


def _der_read(buf: bytes, pos: int) -> Tuple[int, int, int]:
    """Return (tag, content_start, content_end) of the DER element at pos."""
    tag = buf[pos]
    n = buf[pos + 1]
    pos += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[pos:pos + k], "big")
        pos += k
    return tag, pos, pos + n


def parse_timestamp_response_status(tsr: bytes) -> int:
    """PKIStatus of a TimeStampResp: 0 granted, 1 granted with mods, >1 refused."""
    _, s, _ = _der_read(tsr, 0)          # TimeStampResp
    _, s2, _ = _der_read(tsr, s)         # PKIStatusInfo
    tag, s3, e3 = _der_read(tsr, s2)     # status INTEGER
    if tag != 0x02:
        raise ValueError("malformed TimeStampResp")
    return int.from_bytes(tsr[s3:e3], "big", signed=True)


# --------------------------------------------------------------------------- #
# 2.4 ISO-BMFF parsing and streaming ENF analysis
# --------------------------------------------------------------------------- #

_CONTAINER_BOXES = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"udta", b"dinf"}


def _iter_boxes(buf: bytes, start: int = 0, end: Optional[int] = None) -> Iterator[Tuple[bytes, int, int]]:
    """Yield (type, payload_start, payload_end) for boxes inside buf[start:end]."""
    end = len(buf) if end is None else end
    pos = start
    while pos + 8 <= end:
        size, btype = struct.unpack(">I4s", buf[pos:pos + 8])
        header = 8
        if size == 1:
            size = struct.unpack(">Q", buf[pos + 8:pos + 16])[0]
            header = 16
        elif size == 0:
            size = end - pos
        if size < header or pos + size > end:
            break
        yield btype, pos + header, pos + size
        pos += size


def _top_level_boxes(fd: int, file_size: int) -> List[Tuple[bytes, int, int]]:
    """All top-level boxes, in order, located by seeking (mdat is never loaded)."""
    boxes: List[Tuple[bytes, int, int]] = []
    pos = 0
    while pos + 8 <= file_size:
        hdr = _read_exact(fd, pos, 16)
        if len(hdr) < 8:
            break
        size, btype = struct.unpack(">I4s", hdr[:8])
        header = 8
        if size == 1:
            size = struct.unpack(">Q", hdr[8:16])[0]
            header = 16
        elif size == 0:
            size = file_size - pos
        if size < header or pos + size > file_size:
            boxes.append((b"!bad", pos, file_size))
            break
        boxes.append((btype, pos + header, pos + size))
        pos += size
    return boxes


def _read_exact(fd: int, offset: int, length: int) -> bytes:
    os.lseek(fd, offset, os.SEEK_SET)
    out = bytearray()
    while len(out) < length:
        block = os.read(fd, length - len(out))
        if not block:
            break
        out += block
    return bytes(out)


def _parse_track(buf: bytes, start: int, end: int) -> Dict[str, Any]:
    trk: Dict[str, Any] = {"boxes": []}

    def walk(s: int, e: int) -> None:
        for btype, ps, pe in _iter_boxes(buf, s, e):
            trk["boxes"].append(btype.decode("latin-1"))
            p = buf[ps:pe]
            if btype in _CONTAINER_BOXES:
                walk(ps, pe)
            elif btype == b"tkhd":
                trk["track_id"] = struct.unpack(">I", p[12:16] if p[0] == 0 else p[20:24])[0]
            elif btype == b"mdhd":
                if p[0] == 1:
                    trk["timescale"], trk["duration"] = struct.unpack(">IQ", p[20:32])
                else:
                    trk["timescale"], trk["duration"] = struct.unpack(">II", p[12:20])
            elif btype == b"hdlr":
                # The media handler (mdia) comes first; QuickTime adds a data handler in minf.
                trk.setdefault("handler", p[8:12].decode("latin-1"))
            elif btype == b"elst":
                n = struct.unpack(">I", p[4:8])[0]
                if p[0] == 1:
                    trk["elst"] = [struct.unpack(">Qqi", p[8 + 20 * i:28 + 20 * i]) for i in range(n)]
                else:
                    trk["elst"] = [struct.unpack(">Iii", p[8 + 12 * i:20 + 12 * i]) for i in range(n)]
            elif btype == b"stsd":
                entries = list(_iter_boxes(p, 8))
                if entries:
                    etype, es, ee = entries[0]
                    trk["codec"] = etype.decode("latin-1")
                    entry = p[es:ee]
                    if trk.get("handler") == "soun" and len(entry) >= 28:
                        trk["channels"], trk["sample_bits"] = struct.unpack(">HH", entry[16:20])
                        trk["sample_rate"] = struct.unpack(">I", entry[24:28])[0] >> 16
            elif btype == b"stts":
                n = struct.unpack(">I", p[4:8])[0]
                trk["stts"] = [struct.unpack(">II", p[8 + 8 * i:16 + 8 * i]) for i in range(n)]
            elif btype == b"ctts":
                n = struct.unpack(">I", p[4:8])[0]
                trk["ctts"] = [struct.unpack(">Ii", p[8 + 8 * i:16 + 8 * i]) for i in range(n)]
            elif btype == b"stss":
                trk["sync_samples"] = struct.unpack(">I", p[4:8])[0]
            elif btype == b"stsz":
                size, count = struct.unpack(">II", p[4:12])
                trk["stsz"] = (size, count, None if size else
                               array.array("I", struct.unpack(f">{count}I", p[12:12 + 4 * count])))
            elif btype == b"stsc":
                n = struct.unpack(">I", p[4:8])[0]
                trk["stsc"] = [struct.unpack(">III", p[8 + 12 * i:20 + 12 * i]) for i in range(n)]
            elif btype == b"stco":
                n = struct.unpack(">I", p[4:8])[0]
                trk["chunk_offsets"] = struct.unpack(f">{n}I", p[8:8 + 4 * n])
            elif btype == b"co64":
                n = struct.unpack(">I", p[4:8])[0]
                trk["chunk_offsets"] = struct.unpack(f">{n}Q", p[8:8 + 8 * n])

    walk(start, end)
    return trk


def _assess_edit_list(trk: Dict[str, Any], movie_timescale: int) -> List[str]:
    """Return blocking findings for edit lists that trim or splice the track."""
    edits = trk.get("elst")
    if not edits:
        return []
    issues = []
    media = [(d, t) for d, t, _r in edits if t != -1]
    empty = sum(d for d, t, _r in edits if t == -1)
    if len(media) > 1:
        issues.append(f"Edit list splices track {trk.get('track_id')} into {len(media)} segments")
    if media:
        seg_dur, media_time = media[0]
        ts = trk.get("timescale") or 1
        if media_time / ts > 0.1:
            issues.append(f"Edit list skips the first {media_time / ts:.2f} s of track {trk.get('track_id')}")
        remaining = (trk.get("duration", 0) - media_time) / ts
        if movie_timescale and remaining - seg_dur / movie_timescale > 0.5:
            issues.append(f"Edit list hides the last {remaining - seg_dur / movie_timescale:.2f} s "
                          f"of track {trk.get('track_id')}")
    if movie_timescale and empty / movie_timescale > 0.1:
        issues.append(f"Edit list delays track {trk.get('track_id')} by {empty / movie_timescale:.2f} s")
    return issues


class EnfAnalyzer:
    """
    Streaming Electrical Network Frequency continuity analyzer.

    Feed PCM samples in any number of pieces. Audio is block-averaged down to
    about 1 kHz, then each window's phase at the grid frequency is measured
    against absolute time. A steady grid gives a constant phase advance per
    window; an edit (a removed or inserted span) shows as a step in it.
    Memory is bounded by the window count, not the recording length.
    """

    def __init__(self, sample_rate: int, nominal_hz: float = 50.0, window_s: float = 0.2,
                 target_rate: int = 1000):
        self.rate = sample_rate
        self.nominal = nominal_hz
        self.window_s = window_s
        self.decim = max(1, sample_rate // target_rate)
        self.fs = sample_rate / self.decim
        self.n_win = int(round(window_s * self.fs))
        self.omega = 2.0 * math.pi * nominal_hz / self.fs
        self.cos_t = [math.cos(self.omega * k) for k in range(self.n_win)]
        self.sin_t = [math.sin(self.omega * k) for k in range(self.n_win)]
        self._pending = array.array("d")
        self._win: List[float] = []
        self._win_start = 0
        self.input_samples = 0
        self.phases: List[float] = []
        self.amps: List[float] = []
        self.rms: List[float] = []

    def feed(self, samples: Sequence[float]) -> None:
        self.input_samples += len(samples)
        x = self._pending + array.array("d", samples)
        d = self.decim
        usable = len(x) // d * d
        if d > 1:
            dec = [sum(x[i:i + d]) / d for i in range(0, usable, d)]
        else:
            dec = x[:usable].tolist()
        self._pending = x[usable:]
        self._win.extend(dec)
        n = self.n_win
        while len(self._win) >= n:
            seg = self._win[:n]
            del self._win[:n]
            re = sum(map(operator.mul, seg, self.cos_t))
            im = -sum(map(operator.mul, seg, self.sin_t))
            self.phases.append(math.atan2(im, re) + self.omega * self._win_start)
            self.amps.append(2.0 * math.hypot(re, im) / n)
            self.rms.append(math.sqrt(sum(map(operator.mul, seg, seg)) / n) or 1e-12)
            self._win_start += n

    def result(self, threshold_rad: float = 0.08) -> Dict[str, Any]:
        if len(self.phases) < 3:
            return {"status": "INSUFFICIENT_AUDIO", "threshold_rad": threshold_rad}

        def wrap(a: float) -> float:
            return (a + math.pi) % (2.0 * math.pi) - math.pi

        hum_ratio = sorted(a / (r * math.sqrt(2)) for a, r in zip(self.amps, self.rms))[len(self.amps) // 2]
        deltas = [wrap(self.phases[i] - self.phases[i - 1]) for i in range(1, len(self.phases))]
        median_d = sorted(deltas)[len(deltas) // 2]
        jumps = [abs(wrap(dl - median_d)) for dl in deltas]
        max_jump = max(jumps)
        mean_freq = self.nominal + median_d / (2.0 * math.pi * self.window_s)
        if hum_ratio < 0.05:
            status = "ENF_NOT_DETECTED"
        elif max_jump >= threshold_rad:
            status = "PHASE_DISCONTINUITY"
        elif not (self.nominal - 0.05 <= mean_freq <= self.nominal + 0.05):
            status = "OUT_OF_BAND"
        else:
            status = "LOCKED_CONTINUOUS"
        return {
            "status": status,
            "mean_freq_hz": round(mean_freq, 3),
            "max_phase_jump_rad": round(max_jump, 3),
            "max_jump_at_s": round((jumps.index(max_jump) + 1) * self.window_s, 2),
            "threshold_rad": threshold_rad,
            "hum_presence_ratio": round(hum_ratio, 3),
            "windows_analyzed": len(self.phases),
        }


def analyze_enf_pcm(samples: Sequence[float], sample_rate: int, nominal_hz: float = 50.0,
                    window_s: float = 0.2, threshold_rad: float = 0.08) -> Dict[str, Any]:
    """ENF continuity of an in-memory PCM sample sequence (see EnfAnalyzer for streams)."""
    enf = EnfAnalyzer(sample_rate, nominal_hz, window_s)
    enf.feed(samples)
    return enf.result(threshold_rad)


def _stream_pcm_track(fd: int, trk: Dict[str, Any], sink: Callable[[array.array], None]) -> bool:
    """Stream a 16-bit PCM ('sowt'/'twos') track, first channel only, into sink."""
    if trk.get("codec") not in ("sowt", "twos") or trk.get("sample_bits") != 16:
        return False
    size, count, sizes = trk.get("stsz", (0, 0, None))
    stsc, offsets = trk.get("stsc", []), trk.get("chunk_offsets", ())
    if not stsc or not offsets:
        return False
    channels = max(1, trk.get("channels", 1))
    frame = 2 * channels
    swap = (trk["codec"] == "twos") != (sys.byteorder == "big")
    carry = b""
    sample_idx, entry = 0, 0
    piece = 4 * 1024 * 1024
    for ci, off in enumerate(offsets, start=1):
        while entry + 1 < len(stsc) and stsc[entry + 1][0] <= ci:
            entry += 1
        n = min(stsc[entry][1], count - sample_idx)
        nbytes = n * size if size else sum(sizes[sample_idx:sample_idx + n])
        sample_idx += n
        for p in range(0, nbytes, piece):
            raw = carry + _read_exact(fd, off + p, min(piece, nbytes - p))
            usable = len(raw) // frame * frame
            carry = raw[usable:]
            pcm = array.array("h")
            pcm.frombytes(raw[:usable])
            if swap:
                pcm.byteswap()
            sink(pcm[::channels] if channels > 1 else pcm)
    return True


def _stream_ffmpeg_audio(ffmpeg: str, path: str, rate: int, sink: Callable[[array.array], None]) -> bool:
    """Decode the first audio stream to mono 16-bit PCM with ffmpeg, streaming."""
    cmd = [ffmpeg, "-v", "error", "-nostdin", "-i", path, "-map", "0:a:0", "-vn",
           "-ac", "1", "-ar", str(rate), "-f", "s16le", "-"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    carry = b""
    assert proc.stdout is not None
    for raw in iter(lambda: proc.stdout.read(1 << 20), b""):
        raw = carry + raw
        usable = len(raw) // 2 * 2
        carry = raw[usable:]
        pcm = array.array("h")
        pcm.frombytes(raw[:usable])
        if sys.byteorder == "big":
            pcm.byteswap()
        sink(pcm)
    return proc.wait() == 0


# --------------------------------------------------------------------------- #
# 2.6 Volatile memory & mobile filesystem conduits (simulation hooks)
# --------------------------------------------------------------------------- #

class VolatileMemoryConduit:
    """
    Windows 11 VBS/HVCI acquisition conduit. Describes authorized physical address
    translation of VTL0 pages and lawful key escrow of BitLocker FVEKs under a
    search warrant. Simulation only: no driver is loaded and no memory is read.
    """

    POOL_TAGS = ("FVEc", "Cngb")

    def acquire_physical_memory(self, warrant_reference: str) -> Dict[str, Any]:
        return {
            "mode": "SIMULATED_CONDUIT",
            "warrant_reference": warrant_reference,
            "interface": "NtSystemDebugControl(37) / MmCopyMemory(MM_COPY_MEMORY_PHYSICAL)",
            "scope": "Authorized physical address translation of VTL0 pages",
            "key_escrow": f"Lawful FVEK escrow via pool tags {', '.join(self.POOL_TAGS)} (AES-XTS-256)",
            "pages_acquired": 0,
        }


class F2FSCheckpointConduit:
    """
    Android 14+ F2FS dual-checkpoint conduit. The superblock at 0x400 is parsed
    for real; GC freeze, CP1/CP2 NAT/SIT diffing and SSA orphan scanning are
    simulation hooks.
    """

    SUPERBLOCK_OFFSET = 0x400
    F2FS_MAGIC = 0xF2F52010

    def parse_superblock(self, image_path: str) -> Dict[str, Any]:
        fd = os.open(image_path, O_READ_ONLY)
        try:
            sb = _read_exact(fd, self.SUPERBLOCK_OFFSET, 0x50)
        finally:
            os.close(fd)
        if len(sb) < 0x50:
            return {"is_f2fs": False, "reason": "image shorter than superblock"}
        magic, major, minor, _lss, _lspb, log_blocksize = struct.unpack("<IHHIII", sb[:20])
        if magic != self.F2FS_MAGIC:
            return {"is_f2fs": False, "magic": f"0x{magic:08X}"}
        return {
            "is_f2fs": True,
            "magic": f"0x{magic:08X}",
            "version": f"{major}.{minor}",
            "block_size": 1 << log_blocksize,
            "cp_blkaddr": struct.unpack("<I", sb[0x4C:0x50])[0],
        }

    def checkpoint_rollback_analysis(self, image_path: str) -> Dict[str, Any]:
        return {
            "mode": "SIMULATED_CONDUIT",
            "superblock": self.parse_superblock(image_path),
            "gc_urgent": 0,
            "cp1_cp2_nat_sit_diff": "simulated",
            "ssa_orphan_inodes": [],
        }


# --------------------------------------------------------------------------- #
# Custody signatures (optional Ed25519)
# --------------------------------------------------------------------------- #

def ed25519_available() -> bool:
    return Ed25519PublicKey is not None


def ed25519_sign(private_key_raw: bytes, digest_hex: str) -> Tuple[str, str]:
    """Sign a milestone digest; returns (public_key_hex, signature_hex). Needs `cryptography`."""
    if not ed25519_available():
        raise RuntimeError("Ed25519 signing needs the cryptography package")
    key = Ed25519PrivateKey.from_private_bytes(private_key_raw)
    pub = key.public_key().public_bytes_raw()
    return pub.hex(), key.sign(bytes.fromhex(digest_hex)).hex()


def _verify_ed25519(public_key_hex: str, signature_hex: str, digest_hex: str) -> str:
    if not ed25519_available():
        return "UNVERIFIABLE (cryptography package not installed)"
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            bytes.fromhex(signature_hex), bytes.fromhex(digest_hex))
        return "VALID"
    except (InvalidSignature, ValueError):
        return "INVALID"


# --------------------------------------------------------------------------- #
# Sector A vault
# --------------------------------------------------------------------------- #

class SutraEvidenceVault:
    CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB bounded streaming window
    SUB_CHUNK_SIZE = 1024         # 1 KB Merkle sub-blocks
    SECTOR_SIZE = 4096            # LBA unit for the bad-sector mask
    BAD_FILL = (b"\xDE\xAD\xBE\xEF" * (4096 // 4))
    MILESTONES = ("field", "malkhana", "lab")

    def __init__(self, case_id: str = "FIR-042/2026-CYBER", examiner_id: str = "EX-79A-NFSU",
                 workstation_id: str = "LEA-FORENSIC-WS01",
                 hardware_telemetry: Optional[Dict[str, str]] = None,
                 output_dir: Optional[str] = None,
                 navic_clock_source: Optional[Callable[[], Dict[str, Any]]] = None,
                 tsa_url: Optional[str] = None,
                 ffmpeg_path: Optional[str] = None,
                 tree_algorithm: Optional[str] = None):
        self.case_id = case_id
        self.examiner_id = examiner_id
        self.workstation_id = workstation_id
        self.hardware_telemetry = hardware_telemetry or {
            "make_model": "NOT_SUPPLIED", "serial_number": "NOT_SUPPLIED", "firmware_rev": "NOT_SUPPLIED"}
        self.output_dir = output_dir or os.getcwd()
        self.navic_clock_source = navic_clock_source or self._unattached_navic_clock
        self.tsa_url = tsa_url
        self.ffmpeg_path = ffmpeg_path if ffmpeg_path is not None else shutil.which("ffmpeg")
        self.tree_algorithm = tree_algorithm or default_tree_algorithm()
        self.write_blocker = DualBusWriteBlocker()
        self.custody: Optional[Dict[str, Any]] = None
        self.fir_document_path: Optional[str] = None

    # ----- 2.3 Merkle tree ------------------------------------------------- #

    def build_merkle_tree(self, chunk_hashes: List[str]) -> Tuple[str, MerkleNode]:
        """
        RFC 6962 tree over already-hashed nodes (chunk roots or leaf hashes) and
        returns (root_hash, root_node). Hashes are held in compact level lists.
        """
        levels = _merkle_levels([bytes.fromhex(h) for h in chunk_hashes])
        top = len(levels) - 1
        return levels[top][0].hex(), MerkleNode._from_levels(levels, top, 0)

    def generate_merkle_proof(self, root_node: MerkleNode, target_hash: str,
                              leaf_index: Optional[int] = None) -> List[Dict[str, str]]:
        """
        Sibling audit path (leaf to root) for one leaf. Identical leaves (such as
        all-zero chunks) are ambiguous by hash alone, so leaf_index is then required.
        """
        if root_node._levels is not None:
            leaves = root_node._levels[0]
            if leaf_index is None:
                target = bytes.fromhex(target_hash)
                matches = [i for i, h in enumerate(leaves) if h == target]
                if not matches:
                    raise KeyError(f"Leaf {target_hash} not present in tree")
                if len(matches) > 1:
                    raise ValueError(f"{len(matches)} leaves share this hash; pass leaf_index")
                leaf_index = matches[0]
            elif leaves[leaf_index].hex() != target_hash:
                raise ValueError("leaf_index does not hold target_hash")
            return _proof_from_levels(root_node._levels, leaf_index)

        paths: List[List[Dict[str, str]]] = []

        def search(node: MerkleNode, acc: List[Dict[str, str]]) -> None:
            if node.is_leaf:
                if node.hash_val == target_hash:
                    paths.append(list(reversed(acc)))
                return
            if node.left is not None:
                search(node.left, acc + ([{"position": "right", "hash": node.right.hash_val}] if node.right else []))
            if node.right is not None:
                search(node.right, acc + [{"position": "left", "hash": node.left.hash_val}])

        search(root_node, [])
        if not paths:
            raise KeyError(f"Leaf {target_hash} not present in tree")
        if len(paths) > 1:
            raise ValueError(f"{len(paths)} leaves share this hash; pass leaf_index")
        return paths[0]

    def prove_sub_block(self, file_path: str, manifest: Dict[str, Any], sub_block_index: int) -> Dict[str, Any]:
        """
        Inclusion proof for one 1 KB sub-block against the disk Merkle root, reading
        only the 4 MB chunk that contains it.
        """
        per_chunk = self.CHUNK_SIZE // self.SUB_CHUNK_SIZE
        chunk_index, local = divmod(sub_block_index, per_chunk)
        bad = set(manifest["bad_sector_manifest"]["bad_sectors"])
        fd = self.write_blocker.open_read_only(file_path)
        try:
            data, _, _ = self._read_chunk(fd, chunk_index, bad, _get_fd_size(fd))
        finally:
            os.close(fd)
        leaves = self._sub_block_leaves(data)
        if local >= len(leaves):
            raise IndexError("sub-block index beyond end of evidence")
        root = manifest["cryptographic_hashes"]["sha256_merkle_root_4mb"]
        top_levels = _merkle_levels([bytes.fromhex(h) for h in manifest["merkle_tree"]["chunk_roots"]])
        proof = _proof_from_levels(_merkle_levels(leaves), local) + _proof_from_levels(top_levels, chunk_index)
        leaf_hash = leaves[local].hex()
        return {
            "sub_block_index": sub_block_index,
            "byte_offset": sub_block_index * self.SUB_CHUNK_SIZE,
            "chunk_index": chunk_index,
            "leaf_hash": leaf_hash,
            "proof": proof,
            "root": root,
            "verified": verify_merkle_proof(leaf_hash, proof, root),
        }

    # ----- 2.4 Section 105 BNSS -------------------------------------------- #

    def verify_seizure_video_enf(self, video_path: str) -> Dict[str, Any]:
        """
        ISO-BMFF stts/ctts/elst analysis and 50 Hz Indian power-grid hum continuity
        verification (delta-phi < 0.08 rad) under Section 105 BNSS 2023.
        """
        result: Dict[str, Any] = {"verified": False, "findings": []}
        findings: List[str] = result["findings"]
        fd = os.open(video_path, O_READ_ONLY)
        try:
            size = _get_fd_size(fd)
            sha = hashlib.sha256()
            for off in range(0, size, self.CHUNK_SIZE):
                sha.update(_read_exact(fd, off, min(self.CHUNK_SIZE, size - off)))
                _drop_page_cache(fd, off, self.CHUNK_SIZE)
            result["sha256"] = sha.hexdigest()

            top = _top_level_boxes(fd, size)
            types = [b for b, _, _ in top]
            result["top_level_boxes"] = [b.decode("latin-1") for b in types]
            if b"!bad" in types:
                findings.append("Malformed top-level box (size runs past end of file)")
            if types.count(b"moov") != 1:
                findings.append(f"Expected exactly one moov box, found {types.count(b'moov')}")
            if b"moof" in types:
                findings.append("Fragmented MP4 (moof) cannot be verified for continuity")
            if not types or types[0] != b"ftyp" or findings:
                if not types or types[0] != b"ftyp":
                    findings.append("Not an ISO-BMFF file starting with ftyp")
                return result
            fs, _ = next((s, e) for b, s, e in top if b == b"ftyp")
            result["major_brand"] = _read_exact(fd, fs, 4).decode("latin-1")
            ms, me = next((s, e) for b, s, e in top if b == b"moov")
            if me - ms > MAX_MOOV_BYTES:
                findings.append(f"moov box of {me - ms} bytes exceeds the {MAX_MOOV_BYTES}-byte safety limit")
                return result
            moov = _read_exact(fd, ms, me - ms)

            movie_ts = 0
            for bt, ps, pe in _iter_boxes(moov):
                if bt == b"mvhd":
                    p = moov[ps:pe]
                    movie_ts = struct.unpack(">I", p[20:24] if p[0] == 1 else p[12:16])[0]
            tracks = [_parse_track(moov, ps, pe) for bt, ps, pe in _iter_boxes(moov) if bt == b"trak"]
            video = next((t for t in tracks if t.get("handler") == "vide"), None)
            audio = next((t for t in tracks if t.get("handler") == "soun"), None)
            result["boxes_present"] = {
                "ftyp": True, "mvhd": bool(movie_ts),
                "tkhd": bool(tracks) and all("tkhd" in t["boxes"] for t in tracks),
                "stts": bool(video and "stts" in video), "ctts": bool(video and "ctts" in video),
                "stss": bool(video and "stss" in video), "elst": any("elst" in t for t in tracks),
            }
            edit_issues = [i for t in tracks for i in _assess_edit_list(t, movie_ts)]
            result["edit_list_issues"] = edit_issues
            findings.extend(edit_issues)

            vfr_ok = self._check_frame_timing(video, result)

            enf: Dict[str, Any] = {"status": "NO_AUDIO_TRACK", "threshold_rad": 0.08}
            if audio:
                enf = self._enf_for_track(fd, video_path, audio, result)
                if "audio_duration_s" in result and "video_duration_s" in result and \
                        abs(result["audio_duration_s"] - result["video_duration_s"]) > 0.25:
                    findings.append("Audio and video durations disagree by more than 250 ms")
                    vfr_ok = False
            result["indian_enf_power_hum_50hz"] = enf
            if enf["status"] != "LOCKED_CONTINUOUS":
                findings.append(f"ENF status {enf['status']}")
            result["verified"] = vfr_ok and enf["status"] == "LOCKED_CONTINUOUS" and not edit_issues
        finally:
            os.close(fd)
        return result

    @staticmethod
    def _check_frame_timing(video: Optional[Dict[str, Any]], result: Dict[str, Any]) -> bool:
        findings = result["findings"]
        if not video or not video.get("stts") or not video.get("timescale"):
            findings.append("No video track timing (stts) found")
            return False
        runs = list(video["stts"])
        sample_count = sum(c for c, _ in runs)
        result["video_samples"] = sample_count
        result["video_duration_s"] = round(sum(c * d for c, d in runs) / video["timescale"], 3)
        result["keyframes"] = video.get("sync_samples")
        # The final frame ends when the operator presses stop; its duration is arbitrary.
        c, d = runs[-1]
        runs = runs[:-1] + ([(c - 1, d)] if c > 1 else [])
        runs = [(c, d) for c, d in runs if c]
        if not runs:
            findings.append("Too few frames to assess timing")
            return False
        if any(d == 0 for _, d in runs):
            findings.append("Zero-duration frames in stts")
            return False
        adjacent = max([1.0] + [max(b / a, a / b) for (_, a), (_, b) in zip(runs, runs[1:])])
        total = sum(c for c, _ in runs)
        acc, median = 0, runs[0][1]
        for c, d in sorted(runs, key=lambda r: r[1]):
            acc += c
            if acc * 2 >= total:
                median = d
                break
        vs_median = max(max(d / median, median / d) for _, d in runs)
        result["vfr_stts_ctts_ratio"] = round(adjacent, 3)
        result["vfr_max_vs_median_ratio"] = round(vs_median, 3)
        ok = True
        if adjacent > 2.0:
            findings.append(f"Adjacent frame duration ratio {adjacent:.2f} exceeds 2.0")
            ok = False
        if vs_median > 2.0:
            findings.append(f"Frame duration drifts {vs_median:.2f}x from the median (limit 2.0)")
            ok = False
        if "ctts" in video and sum(c for c, _ in video["ctts"]) != sample_count:
            findings.append("ctts sample count disagrees with stts")
            ok = False
        return ok

    def _enf_for_track(self, fd: int, video_path: str, audio: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        rate = audio.get("sample_rate") or audio.get("timescale") or 0
        if audio.get("codec") in ("sowt", "twos") and rate:
            analyzer = EnfAnalyzer(rate)
            if not _stream_pcm_track(fd, audio, analyzer.feed):
                return {"status": "PCM_TRACK_UNREADABLE", "threshold_rad": 0.08}
            result["audio_decoder"] = "in-file 16-bit PCM"
        elif self.ffmpeg_path:
            rate = 8000
            analyzer = EnfAnalyzer(rate)
            if not _stream_ffmpeg_audio(self.ffmpeg_path, video_path, rate, analyzer.feed):
                return {"status": "FFMPEG_DECODE_FAILED", "codec": audio.get("codec"), "threshold_rad": 0.08}
            result["audio_decoder"] = f"ffmpeg ({self.ffmpeg_path}) -> 8 kHz mono PCM"
        else:
            return {"status": "CODEC_NOT_DECODABLE_WITHOUT_FFMPEG", "codec": audio.get("codec"),
                    "threshold_rad": 0.08}
        result["audio_sample_rate_hz"] = rate
        result["audio_duration_s"] = round(analyzer.input_samples / rate, 3)
        return analyzer.result()

    # ----- 2.5 Section 106 BNSS custody ledger ------------------------------ #

    def set_custody_seals(self, field_seal_barcode: str, field_seal_rssi_dbm: int,
                          malkhana_receipt: str, malkhana_timestamp_utc: str,
                          lab_unseal_barcode: str) -> Dict[str, Any]:
        """
        Record the three Section 106 custody milestones as a length-prefixed hash
        chain. Each milestone digest can then be signed by the responsible officer
        (attach_custody_signature).
        """
        rssi = int(field_seal_rssi_dbm)
        h_field = _lp_hash(b"SUTRA/SEC106/FIELD", field_seal_barcode.encode(), str(rssi).encode())
        h_malkhana = _lp_hash(b"SUTRA/SEC106/MALKHANA", h_field, malkhana_receipt.encode(),
                              malkhana_timestamp_utc.encode())
        h_lab = _lp_hash(b"SUTRA/SEC106/LAB", h_malkhana, lab_unseal_barcode.encode())
        self.custody = {
            "field_seal_barcode_sha256": _sha256(field_seal_barcode.encode()).hex(),
            "field_seal_rssi_dbm": rssi,
            "field_seal_rf_isolated": rssi <= -110,
            "malkhana_register_receipt": malkhana_receipt,
            "malkhana_deposit_utc": malkhana_timestamp_utc,
            "lab_unseal_verified": lab_unseal_barcode == field_seal_barcode,
            "h_seal_field": h_field.hex(),
            "h_malkhana": h_malkhana.hex(),
            "h_lab": h_lab.hex(),
            "h_sec106_seal_chain": h_lab.hex(),
            "signatures": {},
        }
        return self.custody

    def attach_custody_signature(self, milestone: str, signer_id: str,
                                 public_key_hex: str, signature_hex: str) -> str:
        """Attach an Ed25519 signature over a milestone digest (h_seal_field, h_malkhana or h_lab)."""
        if self.custody is None:
            raise RuntimeError("set_custody_seals() first")
        if milestone not in self.MILESTONES:
            raise ValueError(f"milestone must be one of {self.MILESTONES}")
        digest = self.custody[self._milestone_key(milestone)]
        status = _verify_ed25519(public_key_hex, signature_hex, digest)
        self.custody["signatures"][milestone] = {
            "signer_id": signer_id, "algorithm": "Ed25519",
            "public_key_hex": public_key_hex, "signature_hex": signature_hex, "status": status}
        return status

    @staticmethod
    def _milestone_key(milestone: str) -> str:
        return {"field": "h_seal_field", "malkhana": "h_malkhana", "lab": "h_lab"}[milestone]

    # ----- 2.7 Time ---------------------------------------------------------- #

    @staticmethod
    def _unattached_navic_clock() -> Dict[str, Any]:
        return {
            "source": "ISRO NavIC 1-PPS / UTC(NPL)",
            "clock_discipline_status": "NOT_ATTACHED (no NavIC receiver; host clock only)",
            "host_utc": _utc_now_iso(),
        }

    def _anchor_time(self, digest_hex: str, stem: str) -> Dict[str, Any]:
        nonce = int.from_bytes(os.urandom(8), "big")
        tsq = build_timestamp_request(bytes.fromhex(digest_hex), nonce)
        anchor: Dict[str, Any] = {"message_imprint_sha256": digest_hex, "nonce": str(nonce),
                                  "tsq_base64": base64.b64encode(tsq).decode()}
        if not self.tsa_url:
            anchor["status"] = "NOT_ANCHORED (no TSA configured; time rests on the host clock)"
            return anchor
        anchor["tsa_url"] = self.tsa_url
        try:
            req = urllib.request.Request(self.tsa_url, data=tsq,
                                         headers={"Content-Type": "application/timestamp-query"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                tsr = resp.read()
            status = parse_timestamp_response_status(tsr)
        except Exception as e:
            anchor["status"] = f"TSA_UNREACHABLE ({type(e).__name__}: {e})"
            return anchor
        anchor["pki_status"] = status
        anchor["tsr_base64"] = base64.b64encode(tsr).decode()
        anchor["status"] = "ANCHORED" if status in (0, 1) else f"TSA_REFUSED (PKIStatus {status})"
        for ext, blob in (("tsq", tsq), ("tsr", tsr)):
            with open(os.path.join(self.output_dir, f"{stem}.{ext}"), "wb") as f:
                f.write(blob)
        anchor["independent_check"] = (f"openssl ts -verify -in {stem}.tsr -queryfile {stem}.tsq "
                                       f"-CAfile <tsa_ca_chain.pem>")
        return anchor

    # ----- Streaming core --------------------------------------------------- #

    def _sub_block_leaves(self, data: bytes) -> List[bytes]:
        s = self.SUB_CHUNK_SIZE
        return [_leaf_hash(data[i:i + s]) for i in range(0, len(data), s)]

    def _read_chunk(self, fd: int, chunk_index: int, bad: Set[int], file_size: int
                    ) -> Tuple[bytes, List[Tuple[int, int]], List[int]]:
        """
        Read one chunk. Known-bad sectors are never touched. A read error marks
        the failing sector bad and reading resumes at the next sector, so no
        sector is retried. Returns (filled_data, healthy_spans, bad_sectors).
        """
        ss = self.SECTOR_SIZE
        off = chunk_index * self.CHUNK_SIZE
        length = min(self.CHUNK_SIZE, file_size - off)
        end = off + length
        first, last = off // ss, (end - 1) // ss
        known = {s for s in range(first, last + 1) if s in bad}
        failed: Set[int] = set()
        data = bytearray(length)

        # Readable extents between known-bad sectors
        extents, start = [], off
        for s in sorted(known):
            if s * ss > start:
                extents.append((start, s * ss))
            start = (s + 1) * ss
        if start < end:
            extents.append((start, end))

        for a, b in extents:
            pos = a
            while pos < b:
                try:
                    os.lseek(fd, pos, os.SEEK_SET)
                    blk = os.read(fd, b - pos)
                except OSError:
                    sec = pos // ss
                    failed.add(sec)
                    self.write_blocker.log.append(f"Read error at sector {sec}; isolated, not retried")
                    pos = (sec + 1) * ss
                    continue
                if not blk:
                    raise IOError(f"Unexpected end of media at byte {pos}")
                data[pos - off:pos - off + len(blk)] = blk
                pos += len(blk)

        chunk_bad = sorted(known | failed)
        spans: List[Tuple[int, int]] = []
        cursor = 0
        for s in chunk_bad:
            b0 = max(s * ss - off, 0)
            b1 = min(b0 + ss, length)
            data[b0:b1] = self.BAD_FILL[:b1 - b0]
            if b0 > cursor:
                spans.append((cursor, b0))
            cursor = b1
        if cursor < length:
            spans.append((cursor, length))
        return bytes(data), spans, chunk_bad

    def _stream(self, fd: int, bad: Set[int], tree_alg: str,
                image_out: Optional[Any] = None) -> Dict[str, Any]:
        lin, valid = hashlib.sha256(), hashlib.sha256()
        b2b, tree = hashlib.blake2b(), _new_tree_hasher(tree_alg)
        chunk_roots: List[str] = []
        all_bad: List[int] = []
        size = _get_fd_size(fd)
        n_chunks = (size + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
        for ci in range(n_chunks):
            data, spans, chunk_bad = self._read_chunk(fd, ci, bad, size)
            _drop_page_cache(fd, ci * self.CHUNK_SIZE, len(data))
            lin.update(data)
            b2b.update(data)
            tree.update(data)
            if image_out is not None:
                image_out.write(data)
            mv = memoryview(data)
            for a, b in spans:
                valid.update(mv[a:b])
            chunk_roots.append(_merkle_levels(self._sub_block_leaves(data))[-1][0].hex())
            all_bad.extend(chunk_bad)
        merkle_root, _ = self.build_merkle_tree(chunk_roots)
        return {
            "size": size, "chunks": len(chunk_roots), "chunk_roots": chunk_roots,
            "linear": lin.hexdigest(), "valid": valid.hexdigest(),
            "blake2b": b2b.hexdigest(), "tree": tree.hexdigest(),
            "merkle_root": merkle_root, "bad_sectors": all_bad,
        }

    @staticmethod
    def _bound_root(merkle_root: str, video_sha: Optional[str]) -> str:
        video = bytes.fromhex(video_sha) if video_sha else bytes(32)
        return _sha256(bytes.fromhex(merkle_root), video).hex()

    @staticmethod
    def _master_root(alg: str, merkle_root: str, video_sha: Optional[str], fir_hash: str,
                     seal_chain: str, navic_hash: str) -> str:
        video = bytes.fromhex(video_sha) if video_sha else bytes(32)
        return _tree_hex(alg, bytes.fromhex(merkle_root), video, bytes.fromhex(fir_hash),
                         bytes.fromhex(seal_chain), bytes.fromhex(navic_hash))

    # ----- Admissibility ----------------------------------------------------- #

    def _assess(self, video: Optional[Dict[str, Any]], custody: Optional[Dict[str, Any]],
                anchor: Dict[str, Any], navic: Dict[str, Any], bad: List[int],
                device: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        blocking: List[str] = []
        warnings: List[str] = []
        if video is None:
            blocking.append("Sec 105 BNSS: no seizure video was bound to this acquisition")
        elif not video["verified"]:
            blocking.append("Sec 105 BNSS: seizure video failed continuity verification ("
                            + "; ".join(video["findings"]) + ")")
        if custody is None:
            blocking.append("Sec 106 BNSS: custody seals were not recorded")
        else:
            if not custody["field_seal_rf_isolated"]:
                blocking.append(f"Sec 106 BNSS: Faraday seal RSSI {custody['field_seal_rssi_dbm']} dBm "
                                f"is above -110 dBm (device was not RF-isolated)")
            if not custody["lab_unseal_verified"]:
                blocking.append("Sec 106 BNSS: lab unseal barcode does not match the field seal")
            for m in self.MILESTONES:
                sig = custody["signatures"].get(m)
                if sig is None:
                    warnings.append(f"Sec 106 BNSS: {m} milestone is not signed by its officer")
                elif sig["status"] == "INVALID":
                    blocking.append(f"Sec 106 BNSS: {m} milestone signature is INVALID")
                elif sig["status"] != "VALID":
                    warnings.append(f"Sec 106 BNSS: {m} signature {sig['status']}")
        if not anchor["status"].startswith("ANCHORED"):
            warnings.append(f"RFC 3161: {anchor['status']}")
        if not str(navic.get("clock_discipline_status", "")).startswith("LOCKED"):
            warnings.append(f"NavIC: {navic.get('clock_discipline_status')}")
        if bad:
            warnings.append(f"{len(bad)} unreadable sectors isolated with 0xDEADBEEF fill")
        if device is not None and device.get("override"):
            warnings.append("Block device write-protection checks were overridden by the examiner")
        warnings.append("Kernel eBPF NVMe/SCSI write filter is a simulation hook and was not applied")
        status = REJECTED if blocking else (READY if not warnings else PROVISIONAL)
        return {"status": status, "blocking_issues": blocking, "warnings": warnings}

    # ----- Primary entrypoint ----------------------------------------------- #

    def ingest_evidence(self,
                        file_path: str,
                        seizure_video_path: Optional[str] = None,
                        bad_sector_mask: Optional[List[int]] = None,
                        acquired_image_path: Optional[str] = None,
                        strict: bool = False,
                        allow_writable_device: bool = False) -> Dict[str, Any]:
        """
        Primary ingestion entrypoint. bad_sector_mask lists bad 4 KB sector
        indices (bad_sectors_from_bitmask() converts a health bitmask M).
        acquired_image_path, when given, receives the acquired image with bad
        sectors filled, so `sha256sum` on it reproduces sha256_linear_primary.
        Writes evidence_manifest.json, then raises StatutoryViolationError if
        strict and the acquisition is REJECTED_FOR_COURT.
        """
        ingestion_ts = _utc_now_iso()
        path_st = os.stat(file_path)
        if not (stat.S_ISREG(path_st.st_mode) or stat.S_ISBLK(path_st.st_mode)):
            raise ValueError("Evidence must be a regular file or block device")
        os.makedirs(self.output_dir, exist_ok=True)

        fd = self.write_blocker.open_read_only(file_path)
        device: Optional[Dict[str, Any]] = None
        try:
            before = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (path_st.st_dev, path_st.st_ino):
                raise RuntimeError("Evidence path changed between stat and open")
            if stat.S_ISBLK(before.st_mode):
                device = self.write_blocker.check_block_device(fd, file_path)
                unsafe = device["kernel_read_only"] is not True or device["mounted"] is not False
                if unsafe and not allow_writable_device:
                    raise WriteProtectionError(
                        f"{file_path} is not kernel read-only or is mounted ({device}); run "
                        f"`blockdev --setro {file_path}` and unmount it, or pass allow_writable_device=True")
                device["override"] = bool(unsafe)

            image_out = open(acquired_image_path, "xb") if acquired_image_path else None
            try:
                s = self._stream(fd, set(bad_sector_mask or []), self.tree_algorithm, image_out)
            finally:
                if image_out is not None:
                    image_out.close()

            after = os.fstat(fd)
            if DualBusWriteBlocker.identity(before)[:3] != DualBusWriteBlocker.identity(after)[:3] or \
                    (stat.S_ISREG(before.st_mode) and before.st_mtime_ns != after.st_mtime_ns):
                raise RuntimeError("Source evidence changed during acquisition; aborting")
            path_now = os.stat(file_path)
            if (path_now.st_dev, path_now.st_ino) != (after.st_dev, after.st_ino):
                raise RuntimeError("Evidence path was replaced during acquisition; aborting")
            self.write_blocker.log.append("Source identity, size and mtime unchanged on the same descriptor")
        finally:
            os.close(fd)

        video = self.verify_seizure_video_enf(seizure_video_path) if seizure_video_path else None
        video_sha = video["sha256"] if video else None
        bound_root = self._bound_root(s["merkle_root"], video_sha)

        fir_hash = (_hash_file_streaming(self.fir_document_path) if self.fir_document_path
                    else hashlib.sha256(self.case_id.encode()).hexdigest())
        custody = self.custody
        seal_chain = custody["h_sec106_seal_chain"] if custody else bytes(32).hex()
        navic = self.navic_clock_source()
        navic_hash = _sha256(_canonical_json(navic)).hex()
        alg = self.tree_algorithm
        master = self._master_root(alg, s["merkle_root"], video_sha, fir_hash, seal_chain, navic_hash)
        evidence_id = str(uuid.uuid4())
        anchor = self._anchor_time(master, f"{evidence_id}_rfc3161")

        bad_manifest: Dict[str, Any] = {
            "sector_size_bytes": self.SECTOR_SIZE,
            "fill_pattern": "0xDEADBEEF",
            "bad_sectors": s["bad_sectors"],
            "bad_byte_offsets": [b * self.SECTOR_SIZE for b in s["bad_sectors"]],
        }
        bad_manifest["manifest_sha256"] = _sha256(_canonical_json(bad_manifest)).hex()

        manifest: Dict[str, Any] = {
            "version": VAULT_VERSION,
            "evidence_id": evidence_id,
            "case_reference": self.case_id,
            "examiner_id": self.examiner_id,
            "ingestion_workstation": self.workstation_id,
            "ingestion_timestamp_utc": ingestion_ts,
            "navic_stratum1_sync": navic,
            "evidence_media": {
                "filename": os.path.basename(file_path),
                "size_bytes": s["size"],
                "total_chunks_4mb": s["chunks"],
                "acquired_image": os.path.basename(acquired_image_path) if acquired_image_path else None,
                "hardware_telemetry": dict(self.hardware_telemetry, **{
                    "ebpf_write_block_applied": False,
                    "nvme_apst_quiesced": False,
                    "kernel_filter_plan": self.write_blocker.kernel_filter_plan(),
                    "read_only_descriptor": True,
                    "source_unchanged_during_acquisition": True,
                    "block_device_checks": device,
                }),
            },
            "cryptographic_hashes": {
                "sha256_linear_primary": s["linear"],
                "sha256_piecewise_valid_extent": s["valid"],
                "blake2b_secondary": s["blake2b"],
                "blake3_root_dag": s["tree"] if alg == "blake3" else None,
                "blake2s_256_fallback": s["tree"] if alg == "blake2s-256" else None,
                "sha256_merkle_root_4mb": s["merkle_root"],
                "bnss_105_seizure_video_sha256": video_sha,
                "final_bound_evidence_root": bound_root,
                "fir_sha256": fir_hash,
                "navic_clock_sha256": navic_hash,
                "master_case_root_v3": master,
            },
            "hash_algorithms": {
                "secondary_tree_hash": alg,
                "master_case_root_v3": alg,
                "blake2b_secondary": "blake2b-512",
                "merkle": "RFC 6962: leaf=SHA-256(0x00||1KB sub-block), node=SHA-256(0x01||L||R), "
                          "unpaired node promoted; disk root = tree head over all 1KB sub-blocks",
                "bound_root": "SHA-256(merkle_root || video_sha256 or 32 zero bytes)",
                "custody_chain": "SHA-256 over 8-byte big-endian length-prefixed fields",
                "manifest_canonicalization": "sorted keys, compact, NaN/Inf rejected, floats as {\"$float\": repr}",
            },
            "merkle_tree": {"chunk_size_bytes": self.CHUNK_SIZE, "sub_block_bytes": self.SUB_CHUNK_SIZE,
                            "chunk_roots": s["chunk_roots"]},
            "bad_sector_manifest": bad_manifest,
            "bnss_verification": {
                "sec_105_video_continuity": None if video is None else {
                    "verified": video["verified"],
                    "vfr_stts_ctts_ratio": video.get("vfr_stts_ctts_ratio"),
                    "vfr_max_vs_median_ratio": video.get("vfr_max_vs_median_ratio"),
                    "edit_list_issues": video.get("edit_list_issues", []),
                    "audio_decoder": video.get("audio_decoder"),
                    "indian_enf_power_hum_50hz": video.get("indian_enf_power_hum_50hz"),
                    "findings": video["findings"],
                },
                "sec_106_malkhana_seal_ledger": custody,
            },
            "rfc3161_timestamp_token": anchor.get("tsr_base64"),
            "rfc3161_time_anchor": anchor,
            "acquisition_log": list(self.write_blocker.log),
            "statutory_compliance": {
                "iso_iec_standard": "ISO/IEC 27037:2012 Read-Only Non-Destructive Acquisition",
                "evidence_statute": "Section 63 Bharatiya Sakshya Adhiniyam, 2023 (BSA)",
                "search_seizure_statute": "Section 105 & 106 Bharatiya Nagarik Suraksha Sanhita, 2023 (BNSS)",
                "it_act_authority": "Section 79A IT Act, 2000 Notified Forensic Laboratory",
            },
        }
        manifest["admissibility"] = self._assess(video, custody, anchor, navic, s["bad_sectors"], device)
        manifest["manifest_canonical_sha256"] = _sha256(_canonical_json(manifest)).hex()

        with open(os.path.join(self.output_dir, MANIFEST_FILENAME), "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False, allow_nan=False)
        if strict and manifest["admissibility"]["status"] == REJECTED:
            raise StatutoryViolationError(manifest)
        return manifest

    # ----- Verifier ---------------------------------------------------------- #

    def verify_integrity(self, file_path: str, manifest: Dict,
                         simulated_new_bad_sectors: Optional[List[int]] = None) -> Tuple[bool, str]:
        """
        Verifies currently stored file against the immutable manifest, using the
        hash algorithms the manifest records.

        If sectors have become unreadable since acquisition (real read errors, or
        simulated_new_bad_sectors for testing), each chunk not touched by the new
        damage is verified against its stored Merkle chunk root. At least one
        chunk must verify.
        """
        body = {k: v for k, v in manifest.items() if k != "manifest_canonical_sha256"}
        if _sha256(_canonical_json(body)).hex() != manifest.get("manifest_canonical_sha256"):
            return False, "MANIFEST_TAMPERED: canonical digest mismatch"
        h = manifest["cryptographic_hashes"]
        alg = manifest["hash_algorithms"]["secondary_tree_hash"]
        try:
            _new_tree_hasher(alg)
        except RuntimeError as e:
            return False, f"UNVERIFIABLE_ON_THIS_WORKSTATION: {e}"
        custody = manifest["bnss_verification"]["sec_106_malkhana_seal_ledger"]
        seal_chain = custody["h_sec106_seal_chain"] if custody else bytes(32).hex()
        if self._bound_root(h["sha256_merkle_root_4mb"], h["bnss_105_seizure_video_sha256"]) != h["final_bound_evidence_root"]:
            return False, "MANIFEST_INCONSISTENT: bound root does not recompute"
        if self._master_root(alg, h["sha256_merkle_root_4mb"], h["bnss_105_seizure_video_sha256"], h["fir_sha256"],
                             seal_chain, h["navic_clock_sha256"]) != h["master_case_root_v3"]:
            return False, "MANIFEST_INCONSISTENT: master case root does not recompute"
        if _merkle_levels([bytes.fromhex(x) for x in manifest["merkle_tree"]["chunk_roots"]])[-1][0].hex() \
                != h["sha256_merkle_root_4mb"]:
            return False, "MANIFEST_INCONSISTENT: chunk roots do not produce the Merkle root"
        anchor = manifest["rfc3161_time_anchor"]
        if anchor["message_imprint_sha256"] != h["master_case_root_v3"]:
            return False, "MANIFEST_INCONSISTENT: timestamp imprint is not the master case root"
        if anchor.get("tsr_base64") and bytes.fromhex(h["master_case_root_v3"]) not in base64.b64decode(anchor["tsr_base64"]):
            return False, "TIMESTAMP_MISMATCH: TSA token does not carry the master case root"
        if custody:
            for m, sig in custody.get("signatures", {}).items():
                if _verify_ed25519(sig["public_key_hex"], sig["signature_hex"], custody[self._milestone_key(m)]) == "INVALID":
                    return False, f"CUSTODY_SIGNATURE_INVALID: {m}"

        original_bad = set(manifest["bad_sector_manifest"]["bad_sectors"])
        fd = self.write_blocker.open_read_only(file_path)
        try:
            s = self._stream(fd, original_bad | set(simulated_new_bad_sectors or []), alg)
        finally:
            os.close(fd)
        if s["size"] != manifest["evidence_media"]["size_bytes"]:
            return False, f"SIZE_MISMATCH: {s['size']} != {manifest['evidence_media']['size_bytes']}"

        tree_field = "blake3_root_dag" if alg == "blake3" else "blake2s_256_fallback"
        new_bad = sorted(set(s["bad_sectors"]) - original_bad)
        if not new_bad:
            checks = {
                "sha256_linear_primary": s["linear"] == h["sha256_linear_primary"],
                "sha256_piecewise_valid_extent": s["valid"] == h["sha256_piecewise_valid_extent"],
                "blake2b_secondary": s["blake2b"] == h["blake2b_secondary"],
                tree_field: s["tree"] == h[tree_field],
                "sha256_merkle_root_4mb": s["merkle_root"] == h["sha256_merkle_root_4mb"],
            }
            failed = [k for k, ok in checks.items() if not ok]
            if failed:
                bad_chunks = [i for i, (a, b) in enumerate(zip(s["chunk_roots"], manifest["merkle_tree"]["chunk_roots"])) if a != b]
                return False, f"INTEGRITY_FAILURE: {', '.join(failed)} mismatch; altered 4MB chunks {bad_chunks}"
            return True, f"VERIFIED: all five digests and the Merkle root match ({alg})"

        per_chunk = self.CHUNK_SIZE // self.SECTOR_SIZE
        damaged = {b // per_chunk for b in new_bad}
        stored = manifest["merkle_tree"]["chunk_roots"]
        healthy = [i for i in range(len(stored)) if i not in damaged]
        mismatched = [i for i in healthy if s["chunk_roots"][i] != stored[i]]
        if mismatched:
            return False, f"INTEGRITY_FAILURE: readable chunks {mismatched} differ from manifest"
        if not healthy:
            return False, f"UNVERIFIABLE: all {len(stored)} chunks contain newly unreadable sectors"
        return True, (f"VERIFIED_DEGRADED: {len(healthy)}/{len(stored)} chunks match their Merkle roots; "
                      f"sectors {new_bad} became unreadable after acquisition, so chunks {sorted(damaged)} "
                      f"cannot be re-verified")


# --------------------------------------------------------------------------- #
# Self-test: synthetic evidence
# --------------------------------------------------------------------------- #

def _box(btype: bytes, payload: bytes) -> bytes:
    return struct.pack(">I4s", 8 + len(payload), btype) + payload


def _full_box(btype: bytes, payload: bytes, version: int = 0, flags: int = 0) -> bytes:
    return _box(btype, struct.pack(">I", (version << 24) | flags) + payload)


_MATRIX = struct.pack(">9I", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000)


def _write_synthetic_mp4(path: str, cut_ms: float = 0.0, seed: int = 105,
                         stts: Optional[List[Tuple[int, int]]] = None,
                         elst: Optional[List[Tuple[int, int]]] = None) -> None:
    """Small ISO-BMFF file: a VFR video track and a 16-bit PCM track with 50 Hz hum."""
    import random
    rng = random.Random(seed)
    v_ts = 30000
    # 30 fps, low-light drop to ~26 fps (ratio 1.15), back to 30 fps, short stop-button frame
    stts = stts or [(150, 1000), (100, 1150), (49, 1000), (1, 120)]
    n_frames = sum(c for c, _ in stts)
    v_dur = sum(c * d for c, d in stts)
    frame_bytes = 32
    video_data = rng.randbytes(n_frames * frame_bytes)

    rate = 48000
    n_samples = int(round(v_dur / v_ts * rate))
    w = 2 * math.pi * 49.982 / rate
    samples = [int(3000 * math.sin(w * n + 0.4) + rng.gauss(0, 600)) for n in range(n_samples)]
    if cut_ms:
        cut = int(rate * cut_ms / 1000)
        mid = n_samples // 2 + 1234
        samples = samples[:mid] + samples[mid + cut:]
    audio_data = struct.pack(f"<{len(samples)}h", *samples)

    def track(track_id: int, handler: bytes, timescale: int, duration: int, stsd_entry: bytes,
              stts_entries, sample_size: int, count: int, chunk_offset: int, extra: bytes = b"",
              edts: bytes = b"") -> bytes:
        tkhd = _full_box(b"tkhd", struct.pack(">IIIII", 0, 0, track_id, 0, duration) + bytes(8)
                         + struct.pack(">hhhH", 0, 0, 0x100 if handler == b"soun" else 0, 0) + _MATRIX
                         + struct.pack(">II", (1280 << 16) if handler == b"vide" else 0,
                                       (720 << 16) if handler == b"vide" else 0), flags=3)
        mdhd = _full_box(b"mdhd", struct.pack(">IIIIHH", 0, 0, timescale, duration, 0x55C4, 0))
        hdlr = _full_box(b"hdlr", struct.pack(">I4s", 0, handler) + bytes(12) + b"SUTRA\x00")
        stbl = _box(b"stbl",
                    _full_box(b"stsd", struct.pack(">I", 1) + stsd_entry)
                    + _full_box(b"stts", struct.pack(">I", len(stts_entries))
                                + b"".join(struct.pack(">II", c, d) for c, d in stts_entries))
                    + extra
                    + _full_box(b"stsc", struct.pack(">IIII", 1, 1, count, 1))
                    + _full_box(b"stsz", struct.pack(">II", sample_size, count))
                    + _full_box(b"stco", struct.pack(">II", 1, chunk_offset)))
        return _box(b"trak", tkhd + edts + _box(b"mdia", mdhd + hdlr + _box(b"minf", stbl)))

    vis_entry = _box(b"avc1", bytes(6) + struct.pack(">H", 1) + bytes(16) + struct.pack(">HHIIIH", 1280, 720,
                     0x480000, 0x480000, 0, 1) + bytes(32) + struct.pack(">Hh", 0x18, -1))
    aud_entry = _box(b"sowt", bytes(6) + struct.pack(">H", 1) + bytes(8)
                     + struct.pack(">HHHHI", 1, 16, 0, 0, rate << 16))
    v_extra = (_full_box(b"ctts", struct.pack(">III", 1, n_frames, 0))
               + _full_box(b"stss", struct.pack(">I", n_frames // 30)
                           + b"".join(struct.pack(">I", 1 + 30 * i) for i in range(n_frames // 30))))
    v_edts = b""
    if elst:  # entries of (segment_duration in movie ticks, media_time in video ticks)
        v_edts = _box(b"edts", _full_box(b"elst", struct.pack(">I", len(elst))
                                         + b"".join(struct.pack(">Iii", d, t, 0x10000) for d, t in elst)))
    ftyp = _box(b"ftyp", b"isom" + struct.pack(">I", 512) + b"isomiso2mp41")

    def build_moov(v_off: int, a_off: int) -> bytes:
        mvhd = _full_box(b"mvhd", struct.pack(">IIII", 0, 0, 1000, v_dur * 1000 // v_ts) + struct.pack(">IH", 0x10000, 0x100)
                         + bytes(10) + _MATRIX + bytes(24) + struct.pack(">I", 3))
        return _box(b"moov", mvhd
                    + track(1, b"vide", v_ts, v_dur, vis_entry, stts, frame_bytes, n_frames, v_off, v_extra, v_edts)
                    + track(2, b"soun", rate, len(samples), aud_entry, [(len(samples), 1)], 2, len(samples), a_off))

    moov_len = len(build_moov(0, 0))
    mdat_payload = len(ftyp) + moov_len + 8
    moov = build_moov(mdat_payload, mdat_payload + len(video_data))
    with open(path, "wb") as f:
        f.write(ftyp + moov + _box(b"mdat", video_data + audio_data))


def _write_synthetic_disk(path: str, size: int = 12015024, seed: int = 63) -> None:
    import random
    rng = random.Random(seed)
    with open(path, "wb") as f:
        written = 0
        while written < size:
            n = min(1 << 20, size - written)
            f.write(rng.randbytes(n) if (written // (1 << 20)) % 3 else bytes(n))  # include zeroed regions
            written += n


def _write_synthetic_f2fs(path: str) -> None:
    img = bytearray(8192)
    struct.pack_into("<IHHIIIII", img, 0x400, F2FSCheckpointConduit.F2FS_MAGIC, 1, 16, 9, 3, 12, 9, 1024)
    struct.pack_into("<I", img, 0x400 + 0x4C, 512)
    with open(path, "wb") as f:
        f.write(img)


def _self_test(workdir: str, tsa_url: Optional[str] = None) -> int:
    os.makedirs(workdir, exist_ok=True)
    p = lambda name: os.path.join(workdir, name)  # noqa: E731
    disk, video = p("evidence_disk_dump.raw"), p("seizure_recording_sec105.mp4")
    results: List[Tuple[str, Optional[bool]]] = []

    def check(name: str, ok: Optional[bool], detail: str = "") -> None:
        results.append((name, ok))
        tag = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
        print(f"  [{tag}] {name}" + (f"  ({detail})" if detail else ""))

    print("=" * 78)
    print(f"SUTRA-Trace Sector A self-test  ·  {VAULT_VERSION}  ·  Python {sys.version.split()[0]}")
    print(f"Tree hash: {default_tree_algorithm()}  ·  Ed25519: {ed25519_available()}  ·  "
          f"ffmpeg: {shutil.which('ffmpeg') or 'not found'}")
    print("=" * 78)
    print("Generating synthetic evidence ...")
    for name in os.listdir(workdir):  # each run starts clean
        shutil.rmtree(p(name)) if os.path.isdir(p(name)) else os.remove(p(name))
    _write_synthetic_disk(disk)
    _write_synthetic_mp4(video)
    _write_synthetic_mp4(p("video_cut_7ms.mp4"), cut_ms=7.0)
    _write_synthetic_mp4(p("video_ramp.mp4"), stts=[(60, 1000), (60, 1500), (60, 2250), (60, 3375), (60, 5062)])
    _write_synthetic_mp4(p("video_elst_splice.mp4"), elst=[(3000, 0), (4000, 150000)])
    _write_synthetic_f2fs(p("android_userdata_f2fs.img"))

    def make_vault(sub: str) -> SutraEvidenceVault:
        v = SutraEvidenceVault(
            hardware_telemetry={"make_model": "Dell Latitude 5420 · NVMe PCIe SSD 512GB",
                                "serial_number": "8F92K12-NVME-001", "firmware_rev": "EDF004"},
            output_dir=p(sub), tsa_url=tsa_url)
        v.set_custody_seals("OPT-PUF-7Q2X-91A0", -112, "MK-CY-2026/089",
                            "2026-10-18T09:30:00.000Z", "OPT-PUF-7Q2X-91A0")
        return v

    vault = make_vault("main")
    signed = ed25519_available()
    if signed:
        for i, m in enumerate(SutraEvidenceVault.MILESTONES):
            pub, sig = ed25519_sign(bytes([i + 1]) * 32, vault.custody[vault._milestone_key(m)])
            vault.attach_custody_signature(m, f"OFFICER-{m.upper()}", pub, sig)

    t0 = time.perf_counter()
    m = vault.ingest_evidence(disk, seizure_video_path=video)
    print(f"\nIngestion finished in {time.perf_counter() - t0:.2f}s; manifest at {p('main/' + MANIFEST_FILENAME)}")
    print(json.dumps({k: m[k] for k in ("cryptographic_hashes", "bnss_verification", "admissibility")},
                     indent=2, ensure_ascii=False))

    print("\nChecks")
    h = m["cryptographic_hashes"]
    with open(disk, "rb") as f:
        ref = hashlib.sha256(f.read()).hexdigest()
    check("Linear SHA-256 matches hashlib reference", h["sha256_linear_primary"] == ref)
    check("Piecewise = linear when no bad sectors", h["sha256_piecewise_valid_extent"] == h["sha256_linear_primary"])
    check("Tree hash stored under the field of the algorithm used",
          (h["blake3_root_dag"] is None) == (default_tree_algorithm() != "blake3"),
          m["hash_algorithms"]["secondary_tree_hash"])
    sec105 = m["bnss_verification"]["sec_105_video_continuity"]
    enf = sec105["indian_enf_power_hum_50hz"]
    check("Sec 105 video verified despite short stop-button frame", sec105["verified"],
          f"adjacent {sec105['vfr_stts_ctts_ratio']}, vs median {sec105['vfr_max_vs_median_ratio']}, "
          f"{enf['mean_freq_hz']} Hz, max dphi {enf['max_phase_jump_rad']} rad")
    check("No blocking issues with verified video and seals", not m["admissibility"]["blocking_issues"],
          m["admissibility"]["status"])
    check("Custody signatures verify" if signed else "Custody signatures (cryptography not installed)",
          all(s["status"] == "VALID" for s in m["bnss_verification"]["sec_106_malkhana_seal_ledger"]["signatures"].values())
          if signed else None)

    ok, msg = vault.verify_integrity(disk, m)
    check("Integrity verifies on untouched evidence", ok, msg)

    proof = vault.prove_sub_block(disk, m, 5000)
    check("1 KB sub-block 5000 Merkle proof verifies", proof["verified"], f"{len(proof['proof'])} siblings")
    flat = SutraEvidenceVault().build_merkle_tree([_leaf_hash(b"x" * 1024).hex()] * 1)[0]
    check("Forged leaf fails the proof", not verify_merkle_proof(flat, proof["proof"], proof["root"]))
    A, B, C = (_leaf_hash(x).hex() for x in (b"A", b"B", b"C"))
    r3, _ = vault.build_merkle_tree([A, B, C])
    r4, _ = vault.build_merkle_tree([A, B, C, C])
    check("RFC 6962: [A,B,C] and [A,B,C,C] have different roots", r3 != r4)
    zero = _leaf_hash(bytes(1024)).hex()
    root, node = vault.build_merkle_tree([A, zero, B, zero])
    try:
        vault.generate_merkle_proof(node, zero)
        ambiguous = False
    except ValueError:
        ambiguous = True
    check("Duplicate leaves need an explicit index", ambiguous and
          verify_merkle_proof(zero, vault.generate_merkle_proof(node, zero, leaf_index=3), root))

    ok, msg = vault.verify_integrity(disk, m, simulated_new_bad_sectors=[1800])
    check("Degraded media still verifies unaffected chunks", ok and msg.startswith("VERIFIED_DEGRADED"), msg)
    ok, msg = vault.verify_integrity(disk, m, simulated_new_bad_sectors=[10, 1100, 2100])
    check("All chunks damaged is not reported as verified", not ok, msg)

    with open(disk, "rb") as f:
        buf = bytearray(f.read())
    buf[9_000_000] ^= 0x01
    with open(p("evidence_disk_dump_TAMPERED.raw"), "wb") as f:
        f.write(buf)
    ok, msg = vault.verify_integrity(p("evidence_disk_dump_TAMPERED.raw"), m)
    check("Single flipped bit is detected", not ok, msg)

    forged_manifest = json.loads(json.dumps(m))
    forged_manifest["case_reference"] = "FIR-999/2026-CYBER"
    ok, msg = vault.verify_integrity(disk, forged_manifest)
    check("Edited manifest is detected", not ok, msg)

    v_cut = vault.verify_seizure_video_enf(p("video_cut_7ms.mp4"))
    e_cut = v_cut["indian_enf_power_hum_50hz"]
    check("7 ms audio cut breaks ENF phase continuity", e_cut["status"] == "PHASE_DISCONTINUITY",
          f"max dphi {e_cut['max_phase_jump_rad']} rad at {e_cut['max_jump_at_s']} s")
    v_ramp = vault.verify_seizure_video_enf(p("video_ramp.mp4"))
    check("Gradual 5x frame-rate ramp is rejected", not v_ramp["verified"],
          f"adjacent {v_ramp.get('vfr_stts_ctts_ratio')}, vs median {v_ramp.get('vfr_max_vs_median_ratio')}")
    v_elst = vault.verify_seizure_video_enf(p("video_elst_splice.mp4"))
    check("Edit-list splice is rejected", not v_elst["verified"] and bool(v_elst["edit_list_issues"]),
          "; ".join(v_elst["edit_list_issues"]))

    if shutil.which("ffmpeg"):
        aac = p("video_aac.mp4")
        # A real encoded file: ffmpeg test pattern video (MPEG-4) + the hum audio re-encoded as AAC
        subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc=size=320x240:rate=30",
                        "-i", video, "-map", "0:v", "-map", "1:a", "-c:v", "mpeg4", "-c:a", "aac",
                        "-b:a", "128k", "-shortest", aac], check=False)
        v_aac = vault.verify_seizure_video_enf(aac) if os.path.exists(aac) else {"verified": False, "findings": ["ffmpeg remux failed"]}
        e_aac = v_aac.get("indian_enf_power_hum_50hz") or {}
        check("AAC seizure video decoded through ffmpeg and verified", v_aac["verified"],
              f"{e_aac.get('status')}, max dphi {e_aac.get('max_phase_jump_rad')} rad" if e_aac else "; ".join(v_aac["findings"]))
    else:
        check("AAC seizure video via ffmpeg (ffmpeg not installed)", None)

    rej = make_vault("rejected_video")
    mr = rej.ingest_evidence(disk, seizure_video_path=p("video_cut_7ms.mp4"))
    check("Tampered video makes the manifest REJECTED_FOR_COURT", mr["admissibility"]["status"] == REJECTED)
    try:
        make_vault("strict").ingest_evidence(disk, seizure_video_path=p("video_cut_7ms.mp4"), strict=True)
        raised = False
    except StatutoryViolationError:
        raised = True
    check("strict=True raises StatutoryViolationError", raised)

    no_seal = SutraEvidenceVault(output_dir=p("no_seals"))
    mn = no_seal.ingest_evidence(disk, seizure_video_path=video)
    check("Missing Sec 106 seals reject the acquisition",
          any("custody seals were not recorded" in i for i in mn["admissibility"]["blocking_issues"]))
    leaky = make_vault("leaky")
    leaky.set_custody_seals("OPT-PUF-7Q2X-91A0", -40, "MK-CY-2026/089", "2026-10-18T09:30:00.000Z", "OPT-PUF-OTHER")
    ml = leaky.ingest_evidence(disk, seizure_video_path=video)
    check("Weak Faraday seal and seal mismatch both block", len(ml["admissibility"]["blocking_issues"]) == 2)
    a = SutraEvidenceVault().set_custody_seals("X", -112, "MK|1", "2026", "X")["h_malkhana"]
    b = SutraEvidenceVault().set_custody_seals("X", -112, "MK", "1|2026", "X")["h_malkhana"]
    check("Delimiter injection cannot collide custody hashes", a != b)
    if signed:
        pub, sig = ed25519_sign(b"\x09" * 32, "00" * 32)
        st = vault.attach_custody_signature("lab", "OFFICER-LAB", pub, sig)
        check("Signature over the wrong digest is INVALID", st == "INVALID")
    else:
        check("Signature tamper check (cryptography not installed)", None)

    bad_vault = make_vault("bad_sector_run")
    image = p("bad_sector_run/acquired.img")
    mb = bad_vault.ingest_evidence(disk, seizure_video_path=video, bad_sector_mask=[10, 11, 2500],
                                   acquired_image_path=image)
    hb = mb["cryptographic_hashes"]
    check("Bad sectors split linear and piecewise digests",
          hb["sha256_piecewise_valid_extent"] != hb["sha256_linear_primary"],
          f"{len(mb['bad_sector_manifest']['bad_sectors'])} sectors isolated with 0xDEADBEEF")
    check("sha256sum of the acquired image reproduces the linear hash",
          _hash_file_streaming(image) == hb["sha256_linear_primary"])
    ok, msg = bad_vault.verify_integrity(disk, mb)
    check("Bad-sector manifest re-verifies", ok, msg)

    tsq = build_timestamp_request(bytes.fromhex(h["master_case_root_v3"]), 12345)
    check("RFC 3161 request carries the master root imprint", bytes.fromhex(h["master_case_root_v3"]) in tsq,
          f"{len(tsq)}-byte DER TimeStampReq")
    anchor = m["rfc3161_time_anchor"]["status"]
    check("Unanchored time is reported, not hidden", tsa_url is not None or anchor.startswith("NOT_ANCHORED"), anchor)
    try:
        _canonical_json({"x": float("nan")})
        nan_ok = False
    except ValueError:
        nan_ok = True
    check("Canonical JSON rejects NaN", nan_ok)

    check("Write-block policy denies NVMe TRIM (0x09)", not vault.write_blocker.is_opcode_permitted("nvme", 0x09))
    check("Write-block policy permits NVMe Read (0x02)", vault.write_blocker.is_opcode_permitted("nvme", 0x02))
    check("F2FS superblock parsed at 0x400", F2FSCheckpointConduit().parse_superblock(p("android_userdata_f2fs.img"))["is_f2fs"])
    check("RAM conduit reports simulation mode",
          VolatileMemoryConduit().acquire_physical_memory("SW-2026/CY/042")["mode"] == "SIMULATED_CONDUIT")

    run = [ok for _, ok in results if ok is not None]
    print(f"\n{sum(run)}/{len(run)} checks passed, {len(results) - len(run)} skipped")
    return 0 if all(run) else 1


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--tsa=")]
    tsa = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--tsa=")), None)
    sys.exit(_self_test(args[0] if args else os.path.join(os.getcwd(), "sutra_vault_selftest"), tsa))
