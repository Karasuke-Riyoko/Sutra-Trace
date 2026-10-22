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
    * A symbolic link in the evidence path is resolved explicitly (and logged)
      on every OS, then one descriptor is opened (O_RDONLY, plus O_BINARY and
      O_NOFOLLOW where the OS has them) and every check uses it, closing the
      stat/open/stat race; the path is re-checked against the descriptor's
      identity at the end.
    * Block devices: size from lseek(SEEK_END), kernel read-only flag (BLKROGET)
      required and mounted devices refused, unless explicitly overridden.
    * Known-bad sectors are never read. A failed multi-sector read is retried
      one sector at a time, so a read error marks only the sector that fails on
      its own (never the good sectors read in the same request), and reading
      resumes after it; a sector marked bad is not read again.
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
import copy
import datetime
import hashlib
import itertools
import json
import math
import operator
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import threading
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
_OPEN_FLAG_NAMES = ["O_RDONLY"] + [n for n in ("O_BINARY", "O_NOFOLLOW") if hasattr(os, n)]
MAX_MOOV_BYTES = 64 * 1024 * 1024    # parsed in memory; real recordings stay far below this
MAX_MOOV_BOXES = 100_000              # boxes walked inside one moov
MAX_BOX_DEPTH = 16                    # container nesting accepted inside moov
MAX_STTS_ENTRIES = 2_000_000          # frame-timing runs (about 9 h of 60 fps variable-rate video)
MAX_ELST_ENTRIES = 10_000
RSSI_FLOOR_DBM, RSSI_CEILING_DBM = -150, 30          # physically reportable signal strengths
EARLIEST_PLAUSIBLE_DEPOSIT_UTC = datetime.datetime(1990, 1, 1, tzinfo=datetime.timezone.utc)
CUSTODY_CLOCK_SKEW = datetime.timedelta(minutes=5)   # tolerated between malkhana and lab clocks

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


def _display_name(name: str) -> str:
    """A file name as valid UTF-8 text for the manifest: bytes that are not UTF-8
    (lone surrogates on Linux or Windows) become \\xNN escapes instead of crashing
    the canonical JSON encoder."""
    try:
        name.encode("utf-8")
        return name
    except UnicodeEncodeError:
        pass
    try:
        return os.fsencode(name).decode("utf-8", "backslashreplace")
    except UnicodeError:
        return name.encode("utf-8", "backslashreplace").decode("utf-8")


_ISO_UTC_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?"
                         r"\s*(Z|[+-]\d{2}:?\d{2})?", re.IGNORECASE)


def _parse_utc(text: Any) -> Optional[datetime.datetime]:
    """An ISO-8601 timestamp as an aware UTC datetime (no offset means UTC), or None.
    Parsed by hand so Python 3.10 and 3.14 accept exactly the same strings."""
    if not isinstance(text, str):
        return None
    m = _ISO_UTC_RE.fullmatch(text.strip())
    if not m:
        return None
    y, mo, d, h, mi, s, frac, tz = m.groups()
    try:
        dt = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s or 0),
                               int((frac or "0")[:6].ljust(6, "0")), tzinfo=datetime.timezone.utc)
        if tz and tz.upper() != "Z":
            digits = tz[1:].replace(":", "")
            shift = datetime.timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
            dt = dt - shift if tz[0] == "+" else dt + shift
    except (ValueError, OverflowError):
        return None
    return dt


def _check_readable_file(label: str, path: str) -> None:
    """Open and close an input now, so a missing or unreadable file fails before acquisition."""
    try:
        st = os.stat(path)
        if stat.S_ISREG(st.st_mode):
            os.close(os.open(path, O_READ_ONLY))
    except OSError as e:
        raise type(e)(e.errno, f"{label} cannot be opened (checked before acquisition): {e.strerror or e}",
                      path) from None
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"{label} {path!r} is not a regular file (checked before acquisition)")


def _set_aside_partial_image(path: str) -> None:
    """Rename an acquired image that no manifest describes to <name>.partial, so a rerun can recreate it."""
    try:
        os.replace(path, path + ".partial")
    except OSError:
        pass


def _manifest_tag(path: str) -> str:
    """The evidence_id of the manifest at path (a canonical UUID), else a digest of its bytes."""
    with open(path, "rb") as f:
        raw = f.read()
    try:
        return str(uuid.UUID(str(json.loads(raw.decode("utf-8")).get("evidence_id"))))
    except (ValueError, AttributeError, TypeError):
        return "sha256-" + hashlib.sha256(raw).hexdigest()[:16]


def _find_ffmpeg() -> Optional[str]:
    """
    Absolute path of ffmpeg from the absolute PATH entries only. Relative entries
    and the current directory are skipped: Windows' default search (and
    shutil.which there) tries the current directory first, which is usually the
    case or evidence folder, and that folder must never supply the decoder.
    On Windows only ffmpeg.exe is accepted (no .bat/.cmd wrappers).
    """
    exe = "ffmpeg.exe" if os.name == "nt" else "ffmpeg"
    try:
        cwd = os.path.normcase(os.path.realpath(os.getcwd()))
    except OSError:
        cwd = None
    for d in os.environ.get("PATH", "").split(os.pathsep):
        d = d.strip().strip('"')
        if not d or not os.path.isabs(d):
            continue
        cand = os.path.join(d, exe)
        if not (os.path.isfile(cand) and os.access(cand, os.X_OK)):
            continue
        if os.path.normcase(os.path.realpath(d)) == cwd:  # the current folder, listed by its full path
            continue
        return cand
    return None


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
        """
        Open read-only. A symbolic link (such as /dev/disk/by-id/...) is resolved
        explicitly and logged, the same way on every OS; the resolved path is then
        opened with O_NOFOLLOW where the OS has it, so a link swapped in afterwards
        is refused. The log names only the flags actually applied.
        """
        real = os.path.realpath(path)
        if os.path.islink(path) or os.path.basename(real) != os.path.basename(os.path.abspath(path)):
            self.log.append(f"Path {_display_name(os.path.basename(path))} resolves to "
                            f"{_display_name(os.path.basename(real))} (link resolved before opening)")
        fd = os.open(real, O_READ_ONLY | getattr(os, "O_NOFOLLOW", 0))
        self.log.append(f"Opened {_display_name(os.path.basename(path))} read-only ({'|'.join(_OPEN_FLAG_NAMES)})")
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
            # Binary read: mount points need not be valid text in any encoding.
            with open("/proc/mounts", "rb") as f:
                mounted = [os.fsdecode(ln.split()[0]) for ln in f if ln.startswith(b"/dev/")]
            info["mounted"] = any(os.path.realpath(m) == real or os.path.realpath(m).startswith(real)
                                  for m in mounted)
        except (OSError, ValueError):
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
# What corrupt or hostile ISO-BMFF metadata can raise while it is parsed; each becomes a finding.
_MALFORMED_MEDIA_ERRORS = (struct.error, ValueError, TypeError, IndexError, KeyError, OverflowError,
                           RecursionError, ZeroDivisionError)


def _iter_boxes(buf: Any, start: int = 0, end: Optional[int] = None) -> Iterator[Tuple[bytes, int, int]]:
    """Yield (type, payload_start, payload_end) for boxes inside buf[start:end] (bytes or memoryview)."""
    end = len(buf) if end is None else end
    pos = start
    while pos + 8 <= end:
        size, btype = struct.unpack(">I4s", buf[pos:pos + 8])
        header = 8
        if size == 1:
            if pos + 16 > end:  # 64-bit size field cut off
                break
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
            if len(hdr) < 16:  # 64-bit size field cut off by the end of the file
                boxes.append((b"!bad", pos, file_size))
                break
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
    if length <= 0:
        return b""
    os.lseek(fd, offset, os.SEEK_SET)
    block = os.read(fd, length)
    if len(block) == length or not block:  # the usual case: no second copy of the data
        return block
    out = bytearray(block)
    while len(out) < length:
        block = os.read(fd, length - len(out))
        if not block:
            break
        out += block
    return bytes(out)


def _be_table(p: Any, start: int, count: int, width: int, name: str) -> array.array:
    """count big-endian unsigned integers of width 4 or 8 bytes from p[start:], as a
    compact array. The count comes from the file, so it is checked against the box."""
    avail = max(0, len(p) - start)
    if count * width > avail:
        raise ValueError(f"{name} declares {count} values but its box holds {avail // width}")
    a = array.array("I" if width == 4 else "Q")
    if a.itemsize != width:  # pragma: no cover - exotic C ABI without a 4-byte array type
        return array.array("L" if width == 4 else "Q",
                           struct.unpack(f">{count}{'I' if width == 4 else 'Q'}", p[start:start + count * width]))
    a.frombytes(p[start:start + count * width])
    if sys.byteorder == "little":
        a.byteswap()
    return a


def _parse_track(buf: Any, start: int, end: int, budget: Optional[List[int]] = None) -> Dict[str, Any]:
    """
    Parse one trak. buf may be a memoryview: container boxes are walked in place
    (never copied), every table count from the file is checked against its box,
    tables are compact arrays (stts/ctts/stsc entries interleaved), nesting is
    capped at MAX_BOX_DEPTH and the number of boxes at the shared budget. Any
    inconsistency raises ValueError or struct.error.
    """
    trk: Dict[str, Any] = {"boxes": []}
    budget = budget if budget is not None else [MAX_MOOV_BOXES]

    def walk(s: int, e: int, depth: int) -> None:
        if depth > MAX_BOX_DEPTH:
            raise ValueError(f"boxes nested deeper than {MAX_BOX_DEPTH} levels")
        for btype, ps, pe in _iter_boxes(buf, s, e):
            budget[0] -= 1
            if budget[0] < 0:
                raise ValueError(f"moov holds more than {MAX_MOOV_BOXES} boxes")
            trk["boxes"].append(btype.decode("latin-1"))
            if btype in _CONTAINER_BOXES:
                walk(ps, pe, depth + 1)
                continue
            p = buf[ps:pe]
            if btype == b"tkhd":
                trk["track_id"] = struct.unpack(">I", p[12:16] if p[0] == 0 else p[20:24])[0]
            elif btype == b"mdhd":
                if p[0] == 1:
                    trk["timescale"], trk["duration"] = struct.unpack(">IQ", p[20:32])
                else:
                    trk["timescale"], trk["duration"] = struct.unpack(">II", p[12:20])
            elif btype == b"hdlr":
                # The media handler (mdia) comes first; QuickTime adds a data handler in minf.
                trk.setdefault("handler", bytes(p[8:12]).decode("latin-1"))
            elif btype == b"elst":
                n = struct.unpack(">I", p[4:8])[0]
                if n > MAX_ELST_ENTRIES:
                    raise ValueError(f"elst declares {n} edits (limit {MAX_ELST_ENTRIES})")
                fmt, width = (">Qqi", 20) if p[0] == 1 else (">Iii", 12)
                if 8 + n * width > len(p):
                    raise ValueError(f"elst declares {n} edits but its box holds {(len(p) - 8) // width}")
                trk["elst"] = list(struct.iter_unpack(fmt, p[8:8 + n * width]))
            elif btype == b"stsd":
                entries = list(_iter_boxes(p, 8))
                if entries:
                    etype, es, ee = entries[0]
                    trk["codec"] = etype.decode("latin-1")
                    entry = p[es:ee]
                    if trk.get("handler") == "soun" and len(entry) >= 28:
                        trk["channels"], trk["sample_bits"] = struct.unpack(">HH", entry[16:20])
                        trk["sample_rate"] = struct.unpack(">I", entry[24:28])[0] >> 16
            elif btype == b"stts":   # (sample_count, sample_delta) pairs, interleaved
                n = struct.unpack(">I", p[4:8])[0]
                if n > MAX_STTS_ENTRIES:
                    raise ValueError(f"stts declares {n} runs (limit {MAX_STTS_ENTRIES})")
                trk["stts"] = _be_table(p, 8, 2 * n, 4, "stts")
            elif btype == b"ctts":   # (sample_count, offset) pairs, interleaved
                n = struct.unpack(">I", p[4:8])[0]
                trk["ctts"] = _be_table(p, 8, 2 * n, 4, "ctts")
            elif btype == b"stss":
                trk["sync_samples"] = struct.unpack(">I", p[4:8])[0]
            elif btype == b"stsz":
                size, count = struct.unpack(">II", p[4:12])
                trk["stsz"] = (size, count, None if size else _be_table(p, 12, count, 4, "stsz"))
            elif btype == b"stsc":   # (first_chunk, samples_per_chunk, description) triples, interleaved
                n = struct.unpack(">I", p[4:8])[0]
                trk["stsc"] = _be_table(p, 8, 3 * n, 4, "stsc")
            elif btype == b"stco":
                n = struct.unpack(">I", p[4:8])[0]
                trk["chunk_offsets"] = _be_table(p, 8, n, 4, "stco")
            elif btype == b"co64":
                n = struct.unpack(">I", p[4:8])[0]
                trk["chunk_offsets"] = _be_table(p, 8, n, 8, "co64")

    walk(start, end, 0)
    return trk


def _weighted_median(values: Sequence[int], weights: Sequence[int]) -> int:
    """
    Smallest value v (an unsigned 32-bit int) whose runs, together with all shorter
    ones, hold at least half the total weight: the median frame duration of an
    stts table. Found with two 16-bit histogram passes, so memory stays bounded
    however many runs a (hostile) table declares; no per-run Python objects are kept.
    """
    total = sum(weights)
    high: Dict[int, int] = {}
    for v, w in zip(values, weights):
        high[v >> 16] = high.get(v >> 16, 0) + w
    acc, top = 0, 0
    for top in sorted(high):
        if (acc + high[top]) * 2 >= total:
            break
        acc += high[top]
    low: Dict[int, int] = {}
    for v, w in zip(values, weights):
        if v >> 16 == top:
            low[v & 0xFFFF] = low.get(v & 0xFFFF, 0) + w
    for bottom in sorted(low):
        acc += low[bottom]
        if acc * 2 >= total:
            return (top << 16) | bottom
    return values[0]  # only reached when every weight is zero


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
        if not sample_rate >= 4 * nominal_hz:
            raise ValueError(f"sample rate {sample_rate} Hz is too low to measure {nominal_hz:g} Hz mains hum")
        self.rate = sample_rate
        self.nominal = nominal_hz
        self.window_s = window_s
        self.decim = max(1, sample_rate // target_rate)
        self.fs = sample_rate / self.decim
        self.n_win = int(round(window_s * self.fs))
        if self.n_win < 2:
            raise ValueError(f"a {window_s} s window holds fewer than 2 samples at {self.fs:g} Hz")
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


def _pcm_chunk_extents(trk: Dict[str, Any]) -> Iterator[Tuple[int, int]]:
    """(file_offset, byte_count) of every audio chunk, from stco/co64, stsc and stsz."""
    size, count, sizes = trk["stsz"]
    stsc, offsets = trk["stsc"], trk["chunk_offsets"]
    n_entries = len(stsc) // 3
    sample_idx, entry = 0, 0
    for ci, off in enumerate(offsets, start=1):
        while entry + 1 < n_entries and stsc[3 * (entry + 1)] <= ci:
            entry += 1
        n = min(stsc[3 * entry + 1], count - sample_idx)
        nbytes = n * size if size else sum(sizes[sample_idx:sample_idx + n])
        sample_idx += n
        yield off, nbytes


def _stream_pcm_track(fd: int, trk: Dict[str, Any], sink: Callable[[array.array], None],
                      file_size: Optional[int] = None) -> bool:
    """
    Stream a 16-bit PCM ('sowt'/'twos') track, first channel only, into sink.
    Returns False when the track is not readable PCM. The sample tables come from
    the file, so before anything is read every chunk is checked to lie inside the
    file; a table that points past the end (or a short read) raises ValueError.
    """
    if trk.get("codec") not in ("sowt", "twos") or trk.get("sample_bits") != 16:
        return False
    size, count, sizes = trk.get("stsz", (0, 0, None))
    stsc, offsets = trk.get("stsc") or (), trk.get("chunk_offsets") or ()
    if not stsc or not offsets or (not size and sizes is None):
        return False
    file_size = _get_fd_size(fd) if file_size is None else file_size
    for off, nbytes in _pcm_chunk_extents(trk):
        if off + nbytes > file_size:
            raise ValueError(f"audio chunk at byte {off} declares {nbytes} bytes, past the end of the "
                             f"{file_size}-byte file")
    channels = max(1, trk.get("channels", 1))
    frame = 2 * channels
    swap = (trk["codec"] == "twos") != (sys.byteorder == "big")
    carry = b""
    piece = 4 * 1024 * 1024
    for off, nbytes in _pcm_chunk_extents(trk):
        for p in range(0, nbytes, piece):
            want = min(piece, nbytes - p)
            got = _read_exact(fd, off + p, want)
            if len(got) < want:
                raise ValueError(f"short read of audio at byte {off + p} (file changed while reading?)")
            raw = carry + got
            usable = len(raw) // frame * frame
            carry = raw[usable:]
            pcm = array.array("h")
            pcm.frombytes(raw[:usable])
            if swap:
                pcm.byteswap()
            sink(pcm[::channels] if channels > 1 else pcm)
    return True


def _stream_ffmpeg_audio(ffmpeg: str, path: str, rate: int, sink: Callable[[array.array], None],
                         timeout_s: Optional[float] = None) -> bool:
    """
    Decode the first audio stream to mono 16-bit PCM with ffmpeg, streaming. The
    pipe is always closed and the child always reaped; if the sink raises, or the
    decode runs longer than timeout_s seconds, ffmpeg is killed (TimeoutError then).
    """
    cmd = [ffmpeg, "-v", "error", "-nostdin", "-i", path, "-map", "0:a:0", "-vn",
           "-ac", "1", "-ar", str(rate), "-f", "s16le", "-"]
    fired: List[bool] = []
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:

        def expire() -> None:
            fired.append(True)
            proc.kill()

        timer = threading.Timer(timeout_s, expire) if timeout_s else None
        if timer is not None:
            timer.daemon = True
            timer.start()
        try:
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
            rc = proc.wait()
        except BaseException:
            proc.kill()
            raise
        finally:
            if timer is not None:
                timer.cancel()
    if fired and rc != 0:
        raise TimeoutError(f"ffmpeg did not finish within {timeout_s:g} s and was stopped")
    return rc == 0


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
        if not 9 <= log_blocksize <= 16:  # F2FS uses 4 KB blocks (12); 1 << (corrupt u32) could need 512 MB
            return {"is_f2fs": False, "magic": f"0x{magic:08X}",
                    "reason": f"corrupt superblock: log_blocksize={log_blocksize}"}
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
                 tree_algorithm: Optional[str] = None,
                 ffmpeg_timeout_s: Optional[float] = None):
        self.case_id = case_id
        self.examiner_id = examiner_id
        self.workstation_id = workstation_id
        self.hardware_telemetry = hardware_telemetry or {
            "make_model": "NOT_SUPPLIED", "serial_number": "NOT_SUPPLIED", "firmware_rev": "NOT_SUPPLIED"}
        self.output_dir = output_dir or os.getcwd()
        self.navic_clock_source = navic_clock_source or self._unattached_navic_clock
        self.tsa_url = tsa_url
        # Never shutil.which("ffmpeg"): on Windows it searches the current (case/evidence) folder first.
        self.ffmpeg_path = ffmpeg_path if ffmpeg_path is not None else _find_ffmpeg()
        self.ffmpeg_timeout_s = ffmpeg_timeout_s  # None: 2 min plus the track's duration
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
            elif not 0 <= leaf_index < len(leaves):
                raise IndexError(f"leaf_index {leaf_index} is outside 0..{len(leaves) - 1}")
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
        return self.prove_sub_blocks(file_path, manifest, [sub_block_index])[0]

    def prove_sub_blocks(self, file_path: str, manifest: Dict[str, Any],
                         sub_block_indices: Sequence[int]) -> List[Dict[str, Any]]:
        """
        Inclusion proofs for many 1 KB sub-blocks (in the order given), reading and
        hashing each 4 MB chunk once however many of its sub-blocks are asked for.
        Indices outside the manifest's evidence raise IndexError. The reads are not
        added to the acquisition log.
        """
        per_chunk = self.CHUNK_SIZE // self.SUB_CHUNK_SIZE
        n_sub = -(-int(manifest["evidence_media"]["size_bytes"]) // self.SUB_CHUNK_SIZE)
        idxs = [operator.index(i) for i in sub_block_indices]
        for i in idxs:
            if not 0 <= i < n_sub:
                raise IndexError(f"sub-block index {i} is outside 0..{n_sub - 1} of the evidence")
        bad = set(manifest["bad_sector_manifest"]["bad_sectors"])
        root = manifest["cryptographic_hashes"]["sha256_merkle_root_4mb"]
        top_levels = _merkle_levels([bytes.fromhex(h) for h in manifest["merkle_tree"]["chunk_roots"]])
        by_chunk: Dict[int, List[int]] = {}
        for pos, i in enumerate(idxs):
            by_chunk.setdefault(i // per_chunk, []).append(pos)
        out: List[Dict[str, Any]] = [{} for _ in idxs]
        scratch = DualBusWriteBlocker()
        fd = scratch.open_read_only(file_path)
        try:
            size = _get_fd_size(fd)
            for chunk_index in sorted(by_chunk):
                data, _, _ = self._read_chunk(fd, chunk_index, bad, size, scratch.log)
                leaves = self._sub_block_leaves(data)
                levels = _merkle_levels(leaves)
                for pos in by_chunk[chunk_index]:
                    local = idxs[pos] - chunk_index * per_chunk
                    if local >= len(leaves):
                        raise IndexError("sub-block index beyond end of evidence")
                    proof = _proof_from_levels(levels, local) + _proof_from_levels(top_levels, chunk_index)
                    leaf_hash = leaves[local].hex()
                    out[pos] = {
                        "sub_block_index": idxs[pos],
                        "byte_offset": idxs[pos] * self.SUB_CHUNK_SIZE,
                        "chunk_index": chunk_index,
                        "leaf_hash": leaf_hash,
                        "proof": proof,
                        "root": root,
                        "verified": verify_merkle_proof(leaf_hash, proof, root),
                    }
        finally:
            os.close(fd)
        return out

    # ----- 2.4 Section 105 BNSS -------------------------------------------- #

    def verify_seizure_video_enf(self, video_path: str) -> Dict[str, Any]:
        """
        ISO-BMFF stts/ctts/elst analysis and 50 Hz Indian power-grid hum continuity
        verification (delta-phi < 0.08 rad) under Section 105 BNSS 2023.
        Corrupt or hostile metadata never raises: it becomes a finding and the
        recording is reported unverified.
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
            try:
                self._verify_video_structure(fd, video_path, size, result)
            except _MALFORMED_MEDIA_ERRORS as e:
                result["verified"] = False
                findings.append(f"Malformed ISO-BMFF metadata ({type(e).__name__}: {e})")
            except OSError as e:
                result["verified"] = False
                findings.append(f"Seizure video could not be read after hashing ({type(e).__name__}: {e})")
        finally:
            os.close(fd)
        return result

    def _verify_video_structure(self, fd: int, video_path: str, size: int, result: Dict[str, Any]) -> None:
        findings: List[str] = result["findings"]
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
            return
        fs, _ = next((s, e) for b, s, e in top if b == b"ftyp")
        result["major_brand"] = _read_exact(fd, fs, 4).decode("latin-1")
        ms, me = next((s, e) for b, s, e in top if b == b"moov")
        if me - ms > MAX_MOOV_BYTES:
            findings.append(f"moov box of {me - ms} bytes exceeds the {MAX_MOOV_BYTES}-byte safety limit")
            return
        moov = memoryview(_read_exact(fd, ms, me - ms))  # walked in place, never copied per level

        movie_ts = 0
        tracks: List[Dict[str, Any]] = []
        budget = [MAX_MOOV_BOXES]
        for bt, ps, pe in _iter_boxes(moov):
            budget[0] -= 1
            if budget[0] < 0:
                raise ValueError(f"moov holds more than {MAX_MOOV_BOXES} boxes")
            if bt == b"mvhd":
                p = moov[ps:pe]
                movie_ts = struct.unpack(">I", p[20:24] if p[0] == 1 else p[12:16])[0]
            elif bt == b"trak":
                tracks.append(_parse_track(moov, ps, pe, budget))
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
            enf = self._enf_for_track(fd, video_path, audio, result, size)
            if "audio_duration_s" in result and "video_duration_s" in result and \
                    abs(result["audio_duration_s"] - result["video_duration_s"]) > 0.25:
                findings.append("Audio and video durations disagree by more than 250 ms")
                vfr_ok = False
        result["indian_enf_power_hum_50hz"] = enf
        if enf["status"] != "LOCKED_CONTINUOUS":
            findings.append(f"ENF status {enf['status']}")
        result["verified"] = vfr_ok and enf["status"] == "LOCKED_CONTINUOUS" and not edit_issues

    @staticmethod
    def _check_frame_timing(video: Optional[Dict[str, Any]], result: Dict[str, Any]) -> bool:
        findings = result["findings"]
        if not video or not video.get("stts") or not video.get("timescale"):
            findings.append("No video track timing (stts) found")
            return False
        counts, durs = video["stts"][0::2], video["stts"][1::2]  # compact copies of the runs
        sample_count = sum(counts)
        result["video_samples"] = sample_count
        result["video_duration_s"] = round(sum(map(operator.mul, counts, durs)) / video["timescale"], 3)
        result["keyframes"] = video.get("sync_samples")
        # The final frame ends when the operator presses stop; its duration is arbitrary.
        if counts[-1] > 1:
            counts[-1] -= 1
        else:
            counts.pop()
            durs.pop()
        if 0 in counts:  # drop empty runs
            durs = array.array(durs.typecode, itertools.compress(durs, counts))
            counts = array.array(counts.typecode, itertools.compress(counts, counts))
        if not counts:
            findings.append("Too few frames to assess timing")
            return False
        if 0 in durs:
            findings.append("Zero-duration frames in stts")
            return False
        adjacent = max(1.0, max((max(b / a, a / b) for a, b in zip(durs, itertools.islice(durs, 1, None))),
                                default=1.0))
        median = _weighted_median(durs, counts)
        vs_median = max(max(d / median, median / d) for d in durs)
        result["vfr_stts_ctts_ratio"] = round(adjacent, 3)
        result["vfr_max_vs_median_ratio"] = round(vs_median, 3)
        ok = True
        if adjacent > 2.0:
            findings.append(f"Adjacent frame duration ratio {adjacent:.2f} exceeds 2.0")
            ok = False
        if vs_median > 2.0:
            findings.append(f"Frame duration drifts {vs_median:.2f}x from the median (limit 2.0)")
            ok = False
        if "ctts" in video and sum(video["ctts"][0::2]) != sample_count:
            findings.append("ctts sample count disagrees with stts")
            ok = False
        return ok

    def _ffmpeg_deadline(self, audio: Dict[str, Any]) -> float:
        if self.ffmpeg_timeout_s:
            return float(self.ffmpeg_timeout_s)
        ts, dur = audio.get("timescale") or 0, audio.get("duration") or 0
        media_s = min(dur / ts, 12 * 3600.0) if ts and dur else 3600.0
        return 120.0 + media_s

    def _enf_for_track(self, fd: int, video_path: str, audio: Dict[str, Any], result: Dict[str, Any],
                       file_size: Optional[int] = None) -> Dict[str, Any]:
        rate = audio.get("sample_rate") or audio.get("timescale") or 0
        if audio.get("codec") in ("sowt", "twos") and rate:
            try:
                analyzer = EnfAnalyzer(rate)
            except ValueError as e:
                return {"status": "INVALID_SAMPLE_RATE", "sample_rate_hz": rate, "detail": str(e),
                        "threshold_rad": 0.08}
            try:
                if not _stream_pcm_track(fd, audio, analyzer.feed, file_size):
                    return {"status": "PCM_TRACK_UNREADABLE", "threshold_rad": 0.08}
            except ValueError as e:
                return {"status": "PCM_TABLE_INCONSISTENT", "detail": str(e), "threshold_rad": 0.08}
            result["audio_decoder"] = "in-file 16-bit PCM"
        elif self.ffmpeg_path:
            rate = 8000
            analyzer = EnfAnalyzer(rate)
            deadline = self._ffmpeg_deadline(audio)
            try:
                decoded = _stream_ffmpeg_audio(self.ffmpeg_path, video_path, rate, analyzer.feed, deadline)
            except TimeoutError:
                return {"status": "FFMPEG_TIMEOUT", "codec": audio.get("codec"), "timeout_s": deadline,
                        "threshold_rad": 0.08}
            except OSError as e:  # ffmpeg could not be started
                return {"status": "FFMPEG_DECODE_FAILED", "codec": audio.get("codec"),
                        "detail": f"{type(e).__name__}: {e}", "threshold_rad": 0.08}
            if not decoded:
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
        # Ledger entries that cannot describe a real chain of custody (each blocks the acquisition).
        issues: List[str] = []
        barcodes_present = bool(field_seal_barcode.strip()) and bool(lab_unseal_barcode.strip())
        if not field_seal_barcode.strip():
            issues.append("field seal barcode is empty")
        if not lab_unseal_barcode.strip():
            issues.append("lab unseal barcode is empty")
        if not malkhana_receipt.strip():
            issues.append("malkhana register receipt is empty")
        deposit = _parse_utc(malkhana_timestamp_utc)
        if deposit is None:
            issues.append(f"malkhana deposit time {malkhana_timestamp_utc!r} is not an ISO-8601 UTC timestamp")
        elif deposit < EARLIEST_PLAUSIBLE_DEPOSIT_UTC:
            issues.append(f"malkhana deposit time {malkhana_timestamp_utc} is implausibly early "
                          f"(before {EARLIEST_PLAUSIBLE_DEPOSIT_UTC.date()})")
        rssi_plausible = RSSI_FLOOR_DBM <= rssi <= RSSI_CEILING_DBM
        if not rssi_plausible:
            issues.append(f"Faraday seal RSSI {rssi} dBm is outside the physical range {RSSI_FLOOR_DBM}.."
                          f"+{RSSI_CEILING_DBM} dBm (sensor fault or sentinel value)")
        self.custody = {
            "field_seal_barcode_sha256": _sha256(field_seal_barcode.encode()).hex(),
            "field_seal_rssi_dbm": rssi,
            "field_seal_rf_isolated": rssi_plausible and rssi <= -110,
            "malkhana_register_receipt": malkhana_receipt,
            "malkhana_deposit_utc": malkhana_timestamp_utc,
            "lab_unseal_verified": barcodes_present and lab_unseal_barcode == field_seal_barcode,
            "seal_barcodes_present": barcodes_present,
            "ledger_validation_issues": issues,
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
        if status not in (0, 1):
            anchor["status"] = f"TSA_REFUSED (PKIStatus {status})"
            anchor["rejected_tsr_base64"] = base64.b64encode(tsr).decode()
            return anchor
        # A granted response must be the token for THIS request: our imprint and our nonce
        # (a stale, replayed or misrouted token is not an anchor of this manifest).
        missing = [what for what, der in (("message imprint", _der(0x04, bytes.fromhex(digest_hex))),
                                          ("nonce", _der_int(nonce))) if der not in tsr]
        if missing:
            anchor["status"] = f"TSA_TOKEN_MISMATCH (token does not carry this request's {' or '.join(missing)})"
            anchor["rejected_tsr_base64"] = base64.b64encode(tsr).decode()
            return anchor
        anchor["tsr_base64"] = base64.b64encode(tsr).decode()
        anchor["status"] = "ANCHORED"
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

    def _read_chunk(self, fd: int, chunk_index: int, bad: Set[int], file_size: int,
                    log: Optional[List[str]] = None) -> Tuple[bytes, List[Tuple[int, int]], List[int]]:
        """
        Read one chunk. Known-bad sectors are never touched. When a multi-sector
        read fails (Windows fails the whole ReadFile request on a CRC error), the
        span is re-read one sector at a time, so only a sector that fails on its
        own is marked bad; reading then resumes at the next sector and a sector
        marked bad is not read again. Read errors go to log (default: the
        acquisition log). Returns (filled_data, healthy_spans, bad_sectors).
        """
        log = self.write_blocker.log if log is None else log
        ss = self.SECTOR_SIZE
        off = chunk_index * self.CHUNK_SIZE
        length = max(0, min(self.CHUNK_SIZE, file_size - off))
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
            probing = False  # True: one sector per read, after a multi-sector read failed
            while pos < b:
                sector_end = min(b, (pos // ss + 1) * ss)
                want = (sector_end if probing else b) - pos
                try:
                    os.lseek(fd, pos, os.SEEK_SET)
                    blk = os.read(fd, want)
                except OSError:
                    if not probing and want > sector_end - pos:
                        probing = True  # the failing request spanned several sectors: find the bad one
                        continue
                    sec = pos // ss
                    failed.add(sec)
                    log.append(f"Read error at sector {sec}; isolated, not retried")
                    pos = (sec + 1) * ss
                    probing = False
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
                image_out: Optional[Any] = None, log: Optional[List[str]] = None) -> Dict[str, Any]:
        lin, valid = hashlib.sha256(), hashlib.sha256()
        b2b, tree = hashlib.blake2b(), _new_tree_hasher(tree_alg)
        chunk_roots: List[str] = []
        all_bad: List[int] = []
        size = _get_fd_size(fd)
        n_chunks = (size + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
        for ci in range(n_chunks):
            data, spans, chunk_bad = self._read_chunk(fd, ci, bad, size, log)
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
                device: Optional[Dict[str, Any]], ingestion_utc: Optional[str] = None) -> Dict[str, Any]:
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
            for issue in custody.get("ledger_validation_issues") or []:
                blocking.append(f"Sec 106 BNSS: {issue}")
            rssi = custody["field_seal_rssi_dbm"]
            if not custody["field_seal_rf_isolated"] and RSSI_FLOOR_DBM <= rssi <= RSSI_CEILING_DBM:
                blocking.append(f"Sec 106 BNSS: Faraday seal RSSI {custody['field_seal_rssi_dbm']} dBm "
                                f"is above -110 dBm (device was not RF-isolated)")
            if not custody["lab_unseal_verified"] and custody.get("seal_barcodes_present", True):
                blocking.append("Sec 106 BNSS: lab unseal barcode does not match the field seal")
            deposited, acquired = _parse_utc(custody.get("malkhana_deposit_utc")), _parse_utc(ingestion_utc)
            if deposited is not None and acquired is not None and deposited - acquired > CUSTODY_CLOCK_SKEW:
                blocking.append(f"Sec 106 BNSS: malkhana deposit time {custody.get('malkhana_deposit_utc')} is "
                                f"after this lab acquisition ({ingestion_utc})")
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
        Writes evidence_manifest.json (atomically; a manifest of an earlier
        acquisition already there is kept as evidence_manifest.superseded.<id>.json),
        then raises StatutoryViolationError if strict and the acquisition is
        REJECTED_FOR_COURT. The seizure video and FIR are opened before the
        acquisition starts, and an acquired image that ends up without a manifest
        is renamed <name>.partial.
        """
        ingestion_ts = _utc_now_iso()
        path_st = os.stat(file_path)
        if not (stat.S_ISREG(path_st.st_mode) or stat.S_ISBLK(path_st.st_mode)):
            raise ValueError("Evidence must be a regular file or block device")
        for label, extra in (("Seizure video", seizure_video_path), ("FIR document", self.fir_document_path)):
            if extra:
                _check_readable_file(label, extra)
        evidence_name = _display_name(os.path.basename(file_path))
        image_name = _display_name(os.path.basename(acquired_image_path)) if acquired_image_path else None
        os.makedirs(self.output_dir, exist_ok=True)
        manifest_path = os.path.join(self.output_dir, MANIFEST_FILENAME)
        if os.path.exists(manifest_path) and os.path.samefile(manifest_path, file_path):
            raise ValueError(f"The evidence itself is {manifest_path}; choose another output_dir")
        self.write_blocker.log = []  # each acquisition carries only its own log
        created: List[str] = []      # acquired image, once this call has created it
        try:
            return self._ingest(file_path, path_st, ingestion_ts, evidence_name, image_name, seizure_video_path,
                                bad_sector_mask, acquired_image_path, strict, allow_writable_device, created)
        except StatutoryViolationError:
            raise  # the manifest was written: the image it describes stays
        except BaseException:
            for path in created:
                _set_aside_partial_image(path)
            raise

    def _ingest(self, file_path: str, path_st: os.stat_result, ingestion_ts: str, evidence_name: str,
                image_name: Optional[str], seizure_video_path: Optional[str],
                bad_sector_mask: Optional[List[int]], acquired_image_path: Optional[str], strict: bool,
                allow_writable_device: bool, created: List[str]) -> Dict[str, Any]:
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
            if image_out is not None:
                created.append(acquired_image_path)  # type: ignore[arg-type]
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
        # Copies: a later attach_custody_signature() or a reused clock dict must not
        # change the manifest after it has been sealed.
        custody = copy.deepcopy(self.custody)
        seal_chain = custody["h_sec106_seal_chain"] if custody else bytes(32).hex()
        navic = copy.deepcopy(self.navic_clock_source())
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
                "filename": evidence_name,
                "size_bytes": s["size"],
                "total_chunks_4mb": s["chunks"],
                "acquired_image": image_name,
                "hardware_telemetry": dict(copy.deepcopy(self.hardware_telemetry), **{
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
        manifest["admissibility"] = self._assess(video, custody, anchor, navic, s["bad_sectors"], device,
                                                 ingestion_ts)
        manifest["manifest_canonical_sha256"] = _sha256(_canonical_json(manifest)).hex()

        self._write_manifest(manifest)
        if strict and manifest["admissibility"]["status"] == REJECTED:
            raise StatutoryViolationError(manifest)
        return manifest

    def _write_manifest(self, manifest: Dict[str, Any]) -> str:
        """
        Write evidence_manifest.json atomically (temp file, fsync, os.replace). The
        manifest of an earlier acquisition already in output_dir is never lost: it
        is renamed evidence_manifest.superseded.<its evidence_id>.json first.
        """
        target = os.path.join(self.output_dir, MANIFEST_FILENAME)
        tmp = f"{target}.{os.getpid()}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2, ensure_ascii=False, allow_nan=False)
                f.flush()
                os.fsync(f.fileno())
            if os.path.exists(target):
                previous = _manifest_tag(target)
                if previous != manifest["evidence_id"]:
                    stem, ext = os.path.splitext(MANIFEST_FILENAME)
                    os.replace(target, os.path.join(self.output_dir, f"{stem}.superseded.{previous}{ext}"))
            os.replace(tmp, target)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
        return target

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
            signatures = custody.get("signatures") or {}
            # The canonical digest is unkeyed, so the officers' signatures are the only thing a
            # forger cannot recompute: a workstation that cannot check them must not say VERIFIED.
            if signatures and not ed25519_available():
                return False, ("UNVERIFIABLE_ON_THIS_WORKSTATION: custody signatures need the cryptography "
                               "package to be checked")
            for m, sig in signatures.items():
                if _verify_ed25519(sig["public_key_hex"], sig["signature_hex"], custody[self._milestone_key(m)]) == "INVALID":
                    return False, f"CUSTODY_SIGNATURE_INVALID: {m}"

        original_bad = set(manifest["bad_sector_manifest"]["bad_sectors"])
        scratch = DualBusWriteBlocker()  # verification reads stay out of the acquisition log
        try:
            fd = scratch.open_read_only(file_path)
            try:
                s = self._stream(fd, original_bad | set(simulated_new_bad_sectors or []), alg, log=scratch.log)
            finally:
                os.close(fd)
        except OSError as e:
            return False, f"UNREADABLE: {type(e).__name__}: {e}"
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


_SELFTEST_MARKER = ".sutra_vault_selftest"
_SELFTEST_NAMES = frozenset({
    "evidence_disk_dump.raw", "evidence_disk_dump_TAMPERED.raw", "seizure_recording_sec105.mp4",
    "video_cut_7ms.mp4", "video_ramp.mp4", "video_elst_splice.mp4", "video_aac.mp4",
    "android_userdata_f2fs.img", "main", "rejected_video", "strict", "no_seals", "leaky",
    "bad_sector_run", "overnight_audit"})


def _prepare_selftest_workdir(workdir: str) -> bool:
    """
    Empty the self-test folder before a run. Only a folder the self-test owns is
    emptied: one carrying its marker file, or (folders from before the marker
    existed) one holding the self-test's synthetic disk and nothing but the
    self-test's own file names. Any other non-empty folder, such as a case folder
    passed by mistake, is refused (returns False) and nothing in it is touched.
    """
    os.makedirs(workdir, exist_ok=True)
    names = os.listdir(workdir)
    legacy = "evidence_disk_dump.raw" in names and set(names) <= _SELFTEST_NAMES
    if names and _SELFTEST_MARKER not in names and not legacy:
        return False
    for name in names:
        path = os.path.join(workdir, name)
        if name == _SELFTEST_MARKER:
            continue
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
    with open(os.path.join(workdir, _SELFTEST_MARKER), "w", encoding="utf-8") as f:
        f.write("Created by the SUTRA-Trace Sector A self-test. Everything in this folder is deleted "
                "at the start of each self-test run.\n")
    return True


def _self_test(workdir: str, tsa_url: Optional[str] = None) -> int:
    workdir = os.path.abspath(workdir)
    if not _prepare_selftest_workdir(workdir):  # each run starts clean, in a folder it owns
        print(f"Refusing to run the self-test in {workdir}: the folder holds files the self-test did not "
              f"create (no {_SELFTEST_MARKER} marker). Nothing was deleted; pass a new or empty folder.",
              file=sys.stderr)
        return 2
    p = lambda name: os.path.join(workdir, name)  # noqa: E731
    disk, video = p("evidence_disk_dump.raw"), p("seizure_recording_sec105.mp4")
    results: List[Tuple[str, Optional[bool]]] = []

    def check(name: str, ok: Optional[bool], detail: str = "") -> None:
        results.append((name, ok))
        tag = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
        print(f"  [{tag}] {name}" + (f"  ({detail})" if detail else ""))

    print("=" * 78)
    print(f"SUTRA-Trace Sector A self-test  ·  {VAULT_VERSION}  ·  Python {sys.version.split()[0]}")
    ffmpeg = _find_ffmpeg()
    print(f"Tree hash: {default_tree_algorithm()}  ·  Ed25519: {ed25519_available()}  ·  "
          f"ffmpeg: {ffmpeg or 'not found'}")
    print("=" * 78)
    print("Generating synthetic evidence ...")
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

    if ffmpeg:
        aac = p("video_aac.mp4")
        # A real encoded file: ffmpeg test pattern video (MPEG-4) + the hum audio re-encoded as AAC
        subprocess.run([ffmpeg, "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc=size=320x240:rate=30",
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
    audit_ok = _overnight_audit_selftest(workdir)
    return 0 if all(run) and audit_ok else 1


# --------------------------------------------------------------------------- #
# Self-test: overnight audit regressions
# --------------------------------------------------------------------------- #

def _moov_layout(data: bytes) -> List[Tuple[int, bytes, int, int]]:
    """(track number, box type, payload_start, payload_end) of every box under moov
    (track 0 = movie level), in file order. Test helper for building corrupt files."""
    out: List[Tuple[int, bytes, int, int]] = []
    tracks = [0]

    def walk(s: int, e: int, trk: int) -> None:
        for bt, ps, pe in _iter_boxes(data, s, e):
            t = trk
            if bt == b"trak":
                tracks[0] += 1
                t = tracks[0]
            out.append((t, bt, ps, pe))
            if bt in _CONTAINER_BOXES:
                walk(ps, pe, t)

    for bt, ps, pe in _iter_boxes(data):
        if bt == b"moov":
            out.append((0, bt, ps, pe))
            walk(ps, pe, 0)
    return out


def _overnight_audit_selftest(workdir: str) -> bool:
    """
    Regression checks for the overnight audit of this module (findings A-H01 ..
    A-PRF01, plus console safety). Every check failed on the code before the
    fixes; an exception escaping a check counts as a failure. Works in
    <workdir>/overnight_audit.
    """
    import builtins
    import errno
    import gc
    import io
    import random
    import tracemalloc

    base = os.path.join(workdir, "overnight_audit")
    os.makedirs(base, exist_ok=True)
    q = lambda *names: os.path.join(base, *names)  # noqa: E731
    results: List[bool] = []

    def attempt(name: str, fn: Callable[[], Tuple[Any, str]]) -> None:
        try:
            ok, detail = fn()
            ok = bool(ok)
        except Exception as e:  # an escaping exception is itself a failed regression
            ok, detail = False, f"{type(e).__name__}: {e}"
        results.append(ok)
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))

    def write(path: str, data: bytes) -> str:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def find(layout: List[Tuple[int, bytes, int, int]], trk: int, btype: bytes) -> Tuple[int, int]:
        return next((ps, pe) for t, bt, ps, pe in layout if t == trk and bt == btype)

    def flipped(data: bytes, offset: int, bit: int) -> bytes:
        d = bytearray(data)
        d[offset] ^= 1 << bit
        return bytes(d)

    def enf_status(r: Dict[str, Any]) -> Optional[str]:
        return (r.get("indian_enf_power_hum_50hz") or {}).get("status")

    print("\nOvernight audit regression checks")
    rng = random.Random(2026)
    disk = write(q("exhibit_64k.raw"), rng.randbytes(64 * 1024))
    video = q("sec105.mp4")
    _write_synthetic_mp4(video)
    short_video = q("sec105_short.mp4")
    _write_synthetic_mp4(short_video, stts=[(10, 1000), (1, 120)])
    with open(video, "rb") as f:
        good = f.read()
    layout = _moov_layout(good)
    recent = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    reader = SutraEvidenceVault(output_dir=base, ffmpeg_path="")

    # A-H01: corrupt moov metadata becomes a finding, never an exception
    def h01_flips() -> Tuple[bool, str]:
        with open(short_video, "rb") as f:
            data = f.read()
        lay = _moov_layout(data)
        targets = [(find(lay, t, bt)[0] + 4, 7) for t, bt in
                   ((1, b"stts"), (1, b"ctts"), (1, b"stsc"), (1, b"stco"), (2, b"stsc"), (2, b"stco"))]
        targets.append((find(lay, 1, b"mdhd")[0], 0))  # version 0 -> 1: 64-bit fields run past the box
        ms, me = find(lay, 0, b"moov")
        cases = targets + [(o, b) for o in range(ms, me, 11) for b in (0, 7)]
        escaped, silent = [], []
        for i, (off, bit) in enumerate(cases):
            path = write(q("flip.mp4"), flipped(data, off, bit))
            try:
                r = reader.verify_seizure_video_enf(path)
            except Exception as e:
                escaped.append(f"byte {off} bit {bit}: {type(e).__name__}")
                continue
            if i < len(targets) and (r["verified"] or not any("Malformed ISO-BMFF" in x for x in r["findings"])):
                silent.append(f"byte {off} bit {bit}")
        return (not escaped and not silent,
                f"{len(cases)} single-bit flips in the moov ({len(targets)} on table counts/versions); "
                f"exceptions {len(escaped)} {escaped[:3]}, targeted flips without a finding {silent[:3]}")
    attempt("A-H01 bit-flipped moov tables give a finding, not an exception", h01_flips)

    def h01_crafted() -> Tuple[bool, str]:
        got: Dict[str, Any] = {}
        ftyp = _box(b"ftyp", b"isom" + struct.pack(">I", 512) + b"isom")
        r = reader.verify_seizure_video_enf(write(q("trunc64.mp4"), ftyp + struct.pack(">I4s", 1, b"mdat") + b"\0\0\0"))
        got["64-bit size cut off by EOF"] = (not r["verified"]
                                             and any("Malformed top-level box" in x for x in r["findings"]))
        got["64-bit size cut off inside moov"] = list(_iter_boxes(struct.pack(">I4s", 1, b"free") + b"\0\0")) == []
        nest = b""
        for _ in range(3000):
            nest = _box(b"mdia", nest)
        r = reader.verify_seizure_video_enf(write(q("deep.mp4"), ftyp + _box(b"moov", _box(b"trak", nest))
                                                  + _box(b"mdat", b"")))
        got["3000 nested boxes"] = not r["verified"] and any("nested deeper" in x for x in r["findings"])
        es, ee = find(layout, 2, b"stsd")
        _, entry_start, _ = next(_iter_boxes(good, es + 8, ee))
        rate_at = entry_start + 24
        d = good[:rate_at] + struct.pack(">I", 2 << 16) + good[rate_at + 4:]
        r = reader.verify_seizure_video_enf(write(q("rate2.mp4"), d))
        got["2 Hz sample rate"] = not r["verified"] and enf_status(r) == "INVALID_SAMPLE_RATE"
        zs, _ = find(layout, 2, b"stsz")
        d = good[:zs - 4] + b"free" + good[zs:]
        r = reader.verify_seizure_video_enf(write(q("no_stsz.mp4"), d))
        got["audio track without stsz"] = not r["verified"] and enf_status(r) == "PCM_TRACK_UNREADABLE"
        try:
            analyze_enf_pcm([0.0] * 64, 2)
            got["analyze_enf_pcm at 2 Hz"] = False
        except ValueError:
            got["analyze_enf_pcm at 2 Hz"] = True
        bad = [k for k, v in got.items() if not v]
        return not bad, f"{len(got) - len(bad)}/{len(got)} handled" + (f"; not handled: {bad}" if bad else "")
    attempt("A-H01 truncated box sizes, deep nesting, 2 Hz rate and missing stsz are findings", h01_crafted)

    def h01_ingest() -> Tuple[bool, str]:
        out = q("h01_ingest")
        bad_video = write(q("h01_ingest", "flipped_stts.mp4"), flipped(good, find(layout, 1, b"stts")[0] + 4, 7))
        v = SutraEvidenceVault(output_dir=out, ffmpeg_path="")
        v.set_custody_seals("SEAL-H01", -112, "MK-H01", recent, "SEAL-H01")
        m = v.ingest_evidence(disk, seizure_video_path=bad_video)
        with open(os.path.join(out, MANIFEST_FILENAME), encoding="utf-8") as f:
            on_disk = json.load(f)["evidence_id"] == m["evidence_id"]
        adm = m["admissibility"]
        flagged = any("Malformed ISO-BMFF" in b for b in adm["blocking_issues"])
        return on_disk and adm["status"] == REJECTED and flagged, f"manifest written: {on_disk}; {adm['status']}"
    attempt("A-H01 one flipped bit in the Sec 105 moov still yields a REJECTED_FOR_COURT manifest", h01_ingest)

    # A-H02: an audio table that points past the end of the file is not streamed
    def h02() -> Tuple[bool, str]:
        zs, _ = find(layout, 2, b"stsz")
        seen = []
        for bit in (1, 7):  # sample_size 0x00000002 -> 0x02000002 / 0x80000002
            t0 = time.perf_counter()
            r = reader.verify_seizure_video_enf(write(q("h02.mp4"), flipped(good, zs + 4, bit)))
            seen.append((not r["verified"], enf_status(r), round(time.perf_counter() - t0, 2)))
        ok = all(nv and st == "PCM_TABLE_INCONSISTENT" and dt < 5.0 for nv, st, dt in seen)
        return ok, "; ".join(f"{st} in {dt} s" for _, st, dt in seen)
    attempt("A-H02 audio sample table past EOF is PCM_TABLE_INCONSISTENT, without a long read loop", h02)

    # A-H03: a granted RFC 3161 token must carry this request's imprint and nonce
    def h03() -> Tuple[bool, str]:
        mode = {"m": "good"}

        def fake_urlopen(req: Any, timeout: Optional[float] = None) -> Any:
            tsq = req.data
            _, s, e = _der_read(tsq, 0)
            elems = []
            while s < e:
                tag, cs, ce = _der_read(tsq, s)
                elems.append(tsq[cs:ce])
                s = ce
            digest, nonce = elems[1][-32:], int.from_bytes(elems[2], "big", signed=True)
            if mode["m"] == "imprint":
                digest = hashlib.sha256(b"another exhibit").digest()
            elif mode["m"] == "nonce":
                nonce ^= 1  # a stale token replayed from an earlier request
            token = _der(0x30, _der(0x30, _SHA256_ALG_ID + _der(0x04, digest)) + _der_int(nonce))
            return io.BytesIO(_der(0x30, _der(0x30, _der_int(0)) + token))

        out = q("h03")
        os.makedirs(out, exist_ok=True)
        v = SutraEvidenceVault(output_dir=out, tsa_url="https://tsa.invalid/rfc3161")
        real_urlopen = urllib.request.urlopen
        urllib.request.urlopen = fake_urlopen
        try:
            st = {}
            for m in ("good", "imprint", "nonce"):
                mode["m"] = m
                st[m] = v._anchor_time(hashlib.sha256(b"SUTRA audit").hexdigest(), f"audit_{m}")["status"]
            mode["m"] = "imprint"
            mi = v.ingest_evidence(disk)
        finally:
            urllib.request.urlopen = real_urlopen
        warned = any(w.startswith("RFC 3161: TSA_TOKEN_MISMATCH") for w in mi["admissibility"]["warnings"])
        agree, msg = v.verify_integrity(disk, mi)
        ok = (st["good"] == "ANCHORED" and st["imprint"].startswith("TSA_TOKEN_MISMATCH")
              and st["nonce"].startswith("TSA_TOKEN_MISMATCH") and warned and mi["rfc3161_timestamp_token"] is None
              and agree)
        return ok, f"matching token {st['good']}; other imprint {st['imprint'][:18]}; stale nonce {st['nonce'][:18]}"
    attempt("A-H03 TSA token with another imprint or nonce is not recorded as ANCHORED", h03)

    # A-H04: custody signatures that cannot be checked here never give VERIFIED
    def h04() -> Tuple[bool, str]:
        v = SutraEvidenceVault(output_dir=q("h04", "signed"))
        v.set_custody_seals("SEAL-H04", -112, "MK-H04", recent, "SEAL-H04")
        pub, sig = (ed25519_sign(b"\x07" * 32, v.custody["h_lab"]) if ed25519_available()
                    else ("11" * 32, "22" * 64))
        v.attach_custody_signature("lab", "OFFICER-LAB", pub, sig)
        forged = json.loads(json.dumps(v.ingest_evidence(disk)))
        lab = forged["bnss_verification"]["sec_106_malkhana_seal_ledger"]["signatures"]["lab"]
        lab["signer_id"], lab["signature_hex"] = "IMPOSTOR", "00" * 64
        body = {k: x for k, x in forged.items() if k != "manifest_canonical_sha256"}
        forged["manifest_canonical_sha256"] = _sha256(_canonical_json(body)).hex()
        u = SutraEvidenceVault(output_dir=q("h04", "unsigned"))
        u.set_custody_seals("SEAL-H04", -112, "MK-H04", recent, "SEAL-H04")
        unsigned = u.ingest_evidence(disk)
        g = globals()
        saved = g["Ed25519PublicKey"]
        g["Ed25519PublicKey"] = None  # a workstation without the cryptography package
        try:
            f_ok, f_msg = v.verify_integrity(disk, forged)
            u_ok, u_msg = v.verify_integrity(disk, unsigned)
        finally:
            g["Ed25519PublicKey"] = saved
        ok = not f_ok and f_msg.startswith("UNVERIFIABLE_ON_THIS_WORKSTATION") and u_ok
        return ok, f"forged lab signature: {f_msg.split(':')[0]}; unsigned manifest: {u_msg.split(':')[0]}"
    attempt("A-H04 forged custody signature is not VERIFIED where Ed25519 cannot be checked", h04)

    # A-H05: the s.106 ledger must describe a possible chain of custody
    def h05() -> Tuple[bool, str]:
        cases = {
            "empty barcodes and receipt": ("", -112, "", "", ""),
            "deposit after the acquisition": ("SEAL-1", -112, "MK-1", "2099-12-31T23:59:59Z", "SEAL-1"),
            "deposit at the epoch": ("SEAL-1", -112, "MK-1", "1970-01-01T00:00:00Z", "SEAL-1"),
            "deposit not a timestamp": ("SEAL-1", -112, "MK-1", "yesterday-ish", "SEAL-1"),
            "RSSI -9999 dBm": ("SEAL-1", -9999, "MK-1", recent, "SEAL-1"),
            "RSSI INT_MIN": ("SEAL-1", -2147483648, "MK-1", recent, "SEAL-1"),
        }
        missed: Dict[str, str] = {}
        for i, (label, args) in enumerate(cases.items()):
            v = SutraEvidenceVault(output_dir=q("h05", str(i)))
            ledger = v.set_custody_seals(*args)
            m = v.ingest_evidence(disk)
            if m["admissibility"]["status"] != REJECTED or not any(
                    b.startswith("Sec 106 BNSS") for b in m["admissibility"]["blocking_issues"]):
                missed[label] = "not blocked"
            if label.startswith("RSSI") and ledger["field_seal_rf_isolated"]:
                missed[label] = "counted as RF-isolated"
            if label.startswith("empty") and ledger["lab_unseal_verified"]:
                missed[label] = "counted as a verified unsealing"
        v = SutraEvidenceVault(output_dir=q("h05", "valid"))
        v.set_custody_seals("SEAL-1", -112, "MK-1", recent, "SEAL-1")
        valid = [b for b in v.ingest_evidence(disk)["admissibility"]["blocking_issues"] if b.startswith("Sec 106")]
        return (not missed and not valid,
                f"{len(cases) - len(missed)}/{len(cases)} impossible ledgers block; valid ledger blocks: {len(valid)}"
                + (f"; missed: {missed}" if missed else ""))
    attempt("A-H05 empty seals, impossible deposit times and sentinel RSSI block the acquisition", h05)

    # A-H06: the self-test CLI never empties a folder it did not create
    def h06() -> Tuple[bool, str]:
        cli = q("cli")
        case = os.path.join(cli, "case_folder")
        exhibit = write(os.path.join(case, "exhibits", "phone_image.E01"), b"exhibit")
        notes = write(os.path.join(case, "case_notes.txt"), b"notes")
        me = os.path.abspath(__file__)
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        r1 = subprocess.run([sys.executable, me, case], cwd=cli, capture_output=True, timeout=900, env=env)
        intact = os.path.isfile(exhibit) and os.path.isfile(notes) and sorted(os.listdir(case)) == ["case_notes.txt",
                                                                                                    "exhibits"]
        r2 = subprocess.run([sys.executable, me, "--help"], cwd=cli, capture_output=True, timeout=900, env=env)
        helped = r2.returncode == 0 and b"usage" in r2.stdout and not os.path.exists(os.path.join(cli, "--help"))
        return (r1.returncode != 0 and intact and helped,
                f"case folder: exit {r1.returncode}, contents intact {intact}; --help: exit {r2.returncode}")
    attempt("A-H06 self-test CLI refuses a case folder and answers --help", h06)

    # A-M01: the returned manifest is a sealed copy
    def m01() -> Tuple[bool, str]:
        clock = {"source": "audit clock", "clock_discipline_status": "NOT_ATTACHED (audit)", "host_utc": _utc_now_iso()}
        v = SutraEvidenceVault(output_dir=q("m01"), navic_clock_source=lambda: clock)
        v.set_custody_seals("SEAL-M01", -112, "MK-M01", recent, "SEAL-M01")
        m = v.ingest_evidence(disk)
        first, _ = v.verify_integrity(disk, m)
        v.attach_custody_signature("lab", "OFFICER-LAB", "11" * 32, "22" * 64)
        clock["clock_discipline_status"] = "LOCKED (edited after sealing)"
        second, msg = v.verify_integrity(disk, m)
        sigs = m["bnss_verification"]["sec_106_malkhana_seal_ledger"]["signatures"]
        return first and second and sigs == {}, f"after a later lab signature: {msg.split(':')[0]}; signatures {sorted(sigs)}"
    attempt("A-M01 a signature attached after ingest does not alter the returned manifest", m01)

    # A-M02: per-acquisition log; an earlier manifest is kept, not overwritten
    def m02() -> Tuple[bool, str]:
        out = q("m02")
        second = write(q("second_exhibit.raw"), rng.randbytes(32 * 1024))
        v = SutraEvidenceVault(output_dir=out)
        m1 = v.ingest_evidence(disk)
        v.verify_integrity(disk, m1)
        v.prove_sub_block(disk, m1, 3)
        v.prove_sub_block(disk, m1, 7)
        try:
            v.prove_sub_block(disk, m1, -1)
        except IndexError:
            pass
        m2 = v.ingest_evidence(second)
        foreign = [ln for ln in m2["acquisition_log"] if os.path.basename(disk) in ln or "Read error" in ln]
        stem, ext = os.path.splitext(MANIFEST_FILENAME)
        kept = os.path.join(out, f"{stem}.superseded.{m1['evidence_id']}{ext}")
        with open(kept, encoding="utf-8") as f:
            kept_id = json.load(f)["evidence_id"]
        with open(os.path.join(out, MANIFEST_FILENAME), encoding="utf-8") as f:
            current_id = json.load(f)["evidence_id"]
        leftovers = [n for n in os.listdir(out) if n.endswith(".tmp")]
        ok = not foreign and kept_id == m1["evidence_id"] and current_id == m2["evidence_id"] and not leftovers
        return ok, (f"2nd manifest log: {len(m2['acquisition_log'])} lines, {len(foreign)} from other work; "
                    f"1st manifest kept: {kept_id == m1['evidence_id']}")
    attempt("A-M02 a manifest logs only its own acquisition; the earlier manifest is kept", m02)

    # A-M03: inputs are checked before acquisition; a failed run does not block the rerun
    def m03() -> Tuple[bool, str]:
        out = q("m03")
        os.makedirs(out, exist_ok=True)
        img = os.path.join(out, "acquired.img")
        try:
            SutraEvidenceVault(output_dir=out).ingest_evidence(
                disk, seizure_video_path=os.path.join(out, "no_such_video.mp4"), acquired_image_path=img)
            early = False
        except OSError:
            early = not os.path.exists(img)

        def broken(path: str) -> Dict[str, Any]:
            raise OSError(errno.EIO, "simulated read error on the seizure video")
        v = SutraEvidenceVault(output_dir=out)
        v.verify_seizure_video_enf = broken  # type: ignore[assignment]
        try:
            v.ingest_evidence(disk, seizure_video_path=short_video, acquired_image_path=img)
            set_aside = False
        except OSError:
            set_aside = not os.path.exists(img) and os.path.exists(img + ".partial")
        m = SutraEvidenceVault(output_dir=out).ingest_evidence(disk, seizure_video_path=short_video,
                                                               acquired_image_path=img)
        rerun = _hash_file_streaming(img) == m["cryptographic_hashes"]["sha256_linear_primary"]
        return (early and set_aside and rerun,
                f"missing video refused before acquisition: {early}; failed image set aside: {set_aside}; rerun: {rerun}")
    attempt("A-M03 a missing video fails before acquisition and a failed image does not block the rerun", m03)

    # A-M04: a read that fails as a whole (Windows ERROR_CRC) marks only the bad sector
    def m04() -> Tuple[bool, str]:
        out = q("m04")
        os.makedirs(out, exist_ok=True)
        img = os.path.join(out, "acquired.img")
        ss, bad_sector = SutraEvidenceVault.SECTOR_SIZE, 10
        ident = (os.stat(disk).st_dev, os.stat(disk).st_ino)
        real_read = os.read

        def whole_request_fails(fd: int, n: int) -> bytes:
            try:
                st = os.fstat(fd)
                ours = (st.st_dev, st.st_ino) == ident
            except OSError:
                ours = False
            if ours:
                pos = os.lseek(fd, 0, os.SEEK_CUR)
                if pos < (bad_sector + 1) * ss and pos + n > bad_sector * ss:
                    raise OSError(errno.EIO, "simulated CRC error: the whole request fails")
            return real_read(fd, n)
        os.read = whole_request_fails
        try:
            m = SutraEvidenceVault(output_dir=out).ingest_evidence(disk, acquired_image_path=img)
        finally:
            os.read = real_read
        with open(disk, "rb") as f:
            src = f.read()
        with open(img, "rb") as f:
            acq = f.read()
        changed = [s for s in range(-(-len(src) // ss)) if src[s * ss:(s + 1) * ss] != acq[s * ss:(s + 1) * ss]]
        bad = m["bad_sector_manifest"]["bad_sectors"]
        return bad == [bad_sector] and changed == [bad_sector], f"bad sectors {bad}; sectors filled in the image {changed}"
    attempt("A-M04 a read that fails as a whole marks only the unreadable sector", m04)

    # A-M05: moov tables are parsed in place into compact arrays
    def m05() -> Tuple[bool, str]:
        def hdr(btype: bytes, payload_len: int) -> bytes:
            return struct.pack(">I4s", 8 + payload_len, btype)

        def big_moov(path: str, stts_runs: int, stsz_entries: int) -> int:
            mvhd = _full_box(b"mvhd", struct.pack(">IIII", 0, 0, 1000, 1000) + bytes(80))
            mdhd = _full_box(b"mdhd", struct.pack(">IIIIHH", 0, 0, 30000, 30000, 0, 0))
            hdlr = _full_box(b"hdlr", struct.pack(">I4s", 0, b"vide") + bytes(12) + b"x\x00")
            stts_len, stsz_len = 8 + 8 * stts_runs, 12 + 4 * stsz_entries
            stbl_len = 8 + stts_len + 8 + stsz_len
            mdia_len = len(mdhd) + len(hdlr) + 8 + 8 + stbl_len
            moov_len = len(mvhd) + 8 + 8 + mdia_len
            with open(path, "wb") as f:
                f.write(_box(b"ftyp", b"isom" + struct.pack(">I", 512) + b"isom") + hdr(b"moov", moov_len) + mvhd
                        + hdr(b"trak", 8 + mdia_len) + hdr(b"mdia", mdia_len) + mdhd + hdlr
                        + hdr(b"minf", 8 + stbl_len) + hdr(b"stbl", stbl_len)
                        + hdr(b"stts", stts_len) + struct.pack(">II", 0, stts_runs))
                pattern = b"".join(struct.pack(">II", 1, 1000 + (i % 97)) for i in range(4096))
                for i in range(0, stts_runs, 4096):
                    f.write(pattern[:8 * min(4096, stts_runs - i)])
                f.write(hdr(b"stsz", stsz_len) + struct.pack(">III", 0, 0, stsz_entries))
                for i in range(0, 4 * stsz_entries, 1 << 20):
                    f.write(bytes(min(1 << 20, 4 * stsz_entries - i)))
                f.write(_box(b"mdat", b""))
            return 8 + moov_len

        peaks = []
        tracing = tracemalloc.is_tracing()
        for runs, entries, limit in ((1, 4_000_000, 3.0), (50_000, 1, 5.0)):
            path = q("big_moov.mp4")
            moov_bytes = big_moov(path, runs, entries)
            gc.collect()
            if not tracing:
                tracemalloc.start()
            tracemalloc.reset_peak()
            start = tracemalloc.get_traced_memory()[0]
            try:
                r = reader.verify_seizure_video_enf(path)
                peak = tracemalloc.get_traced_memory()[1] - start
            finally:
                if not tracing:
                    tracemalloc.stop()
            os.remove(path)
            peaks.append((peak / moov_bytes, limit, moov_bytes, r.get("video_samples")))
        sample = [rng.randrange(1, 5000) for _ in range(301)]
        weights = [rng.randrange(1, 40) for _ in range(301)]
        ref, acc = 0, 0
        for d, c in sorted(zip(sample, weights)):
            acc += c
            if acc * 2 >= sum(weights):
                ref = d
                break
        median_ok = _weighted_median(array.array("I", sample), array.array("I", weights)) == ref
        ok = all(ratio < limit for ratio, limit, _, _ in peaks) and median_ok and peaks[0][3] == 1 \
            and peaks[1][3] == 50_000
        return ok, "; ".join(f"{mb / 2 ** 20:.1f} MB moov peaked at {ratio:.1f}x (limit {limit:g}x)"
                             for ratio, limit, mb, _ in peaks) + f"; weighted median exact: {median_ok}"
    attempt("A-M05 large moov tables parse without per-level copies or per-entry objects", m05)

    # A-M06: a file name that is not valid UTF-8 is escaped, not fatal
    def m06() -> Tuple[bool, str]:
        out = q("m06")
        os.makedirs(out, exist_ok=True)
        name = "Fran\udce7ois_phone.img" if os.name == "nt" else os.fsdecode(b"Fran\xe7ois_phone.img")
        path = os.path.join(out, name)
        try:
            write(path, rng.randbytes(8192))
        except (OSError, UnicodeError, ValueError):
            shown = _display_name(name)  # this file system refuses such names; check the escaping alone
            json_ok = _canonical_json({"filename": shown}).decode("utf-8") is not None
            return shown.startswith("Fran") and "\\x" in shown and json_ok, f"name shown as {shown!r} (not creatable here)"
        m = SutraEvidenceVault(output_dir=out).ingest_evidence(path)
        with open(os.path.join(out, MANIFEST_FILENAME), encoding="utf-8") as f:
            on_disk = json.load(f)["evidence_media"]["filename"]
        shown = m["evidence_media"]["filename"]
        return shown == on_disk and shown.startswith("Fran") and "\\x" in shown, f"manifest filename {shown!r}"
    attempt("A-M06 a non-UTF-8 evidence file name is escaped in the manifest", m06)

    # A-M07: ffmpeg pipe closed, deadline enforced, child killed when the sink fails
    def m07() -> Tuple[bool, str]:
        real_popen = subprocess.Popen
        spawned: List[Any] = []
        script = {"code": ""}

        def fake_popen(cmd: Any, *a: Any, **k: Any) -> Any:
            p = real_popen([sys.executable, "-c", script["code"]], *a, **k)
            spawned.append(p)
            return p
        mp4a = write(q("video_mp4a.mp4"), good.replace(b"sowt", b"mp4a", 1))

        def failing_sink(pcm: Any) -> None:
            raise RuntimeError("sink failed")
        subprocess.Popen = fake_popen  # type: ignore[misc]
        try:
            script["code"] = "import sys; sys.stdout.buffer.write(bytes(16000))"
            decoded = _stream_ffmpeg_audio("ffmpeg", mp4a, 8000, lambda pcm: None)
            pipe = spawned[-1].stdout
            pipe_closed = pipe is None or pipe.closed  # an open pipe here is the ResourceWarning of every run
            script["code"] = "import time; time.sleep(8)"
            t0 = time.perf_counter()
            v = SutraEvidenceVault(output_dir=base, ffmpeg_path="ffmpeg", ffmpeg_timeout_s=1.0)
            status = enf_status(v.verify_seizure_video_enf(mp4a))
            took = time.perf_counter() - t0
            script["code"] = ("import sys, time; sys.stdout.buffer.write(bytes(1 << 21)); sys.stdout.flush(); "
                              "time.sleep(8)")
            try:
                _stream_ffmpeg_audio("ffmpeg", mp4a, 8000, failing_sink)
                raised = False
            except RuntimeError:
                raised = True
            reaped = spawned[-1].poll() is not None
        finally:
            subprocess.Popen = real_popen  # type: ignore[misc]
            for p in spawned:
                if p.poll() is None:
                    p.kill()
                    p.wait()
                if p.stdout is not None and not p.stdout.closed:
                    p.stdout.close()
        ok = decoded and pipe_closed and status == "FFMPEG_TIMEOUT" and took < 6.0 and raised and reaped
        return ok, (f"pipe closed: {pipe_closed}; stalled decoder: {status} after {took:.1f} s; "
                    f"child stopped after a sink error: {reaped}")
    attempt("A-M07 ffmpeg decode closes its pipe, has a deadline and kills the child on error", m07)

    # A-M08: ffmpeg is never taken from the current (case) folder
    def m08() -> Tuple[bool, str]:
        case_dir, bin_dir = q("m08", "case"), q("m08", "bin")
        for d in (case_dir, bin_dir):
            for exe in ("ffmpeg", "ffmpeg.exe", "ffmpeg.bat"):
                os.chmod(write(os.path.join(d, exe), b"#!/bin/sh\nexit 1\n"), 0o755)
        exe = "ffmpeg.exe" if os.name == "nt" else "ffmpeg"
        old_cwd, old_path = os.getcwd(), os.environ.get("PATH")
        try:
            os.chdir(case_dir)
            os.environ["PATH"] = os.pathsep.join([".", ""])
            relative_only = SutraEvidenceVault(output_dir=base).ffmpeg_path
            os.environ["PATH"] = os.pathsep.join([case_dir, bin_dir])
            cwd_first = SutraEvidenceVault(output_dir=base).ffmpeg_path
        finally:
            os.chdir(old_cwd)
            if old_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = old_path
        expected = os.path.join(bin_dir, exe)
        ok = relative_only is None and cwd_first is not None and \
            os.path.normcase(os.path.abspath(cwd_first)) == os.path.normcase(expected)
        return ok, f"PATH '.': {relative_only!r}; PATH case;bin: {'bin' if ok else cwd_first!r}"
    attempt("A-M08 ffmpeg is never resolved from the current (case) folder", m08)

    # A-M09: symlinked evidence is resolved the same way on every OS; the log names real flags
    def m09() -> Tuple[bool, str]:
        out = q("m09")
        os.makedirs(out, exist_ok=True)
        flags = "|".join(["O_RDONLY"] + [n for n in ("O_BINARY", "O_NOFOLLOW") if hasattr(os, n)])
        link = os.path.join(out, "by-id-link.raw")
        try:
            os.symlink(os.path.abspath(disk), link)
            have_link = True
        except (OSError, NotImplementedError, AttributeError):
            have_link = False  # e.g. Windows without the symlink privilege
        v = SutraEvidenceVault(output_dir=out)
        m = v.ingest_evidence(link if have_link else disk)
        log = m["acquisition_log"]
        opened = [ln for ln in log if ln.startswith("Opened ")]
        flags_ok = len(opened) == 1 and opened[0].endswith(f"read-only ({flags})")
        if have_link:
            resolved = any("resolves to" in ln and os.path.basename(disk) in ln for ln in log)
            v_ok, v_msg = v.verify_integrity(link, m)
            link_ok, how = resolved and v_ok, f"ingest and verify through a symlink: {v_msg.split(':')[0]}"
        else:
            link_ok, how = True, "symbolic links cannot be created here"
        return flags_ok and link_ok, f"log flags ({flags}) correct: {flags_ok}; {how}"
    attempt("A-M09 symlinked evidence is resolved and logged; the log names only real open flags", m09)

    # A-M10: a corrupt F2FS log_blocksize is reported, never expanded
    def m10() -> Tuple[bool, str]:
        img = q("f2fs.img")
        conduit = F2FSCheckpointConduit()
        for lbs in (0xFFFF, 0x4000000C):
            buf = bytearray(8192)
            struct.pack_into("<IHHIIIII", buf, 0x400, F2FSCheckpointConduit.F2FS_MAGIC, 1, 16, 9, 3, lbs, 9, 1024)
            r = conduit.parse_superblock(write(img, bytes(buf)))
            json.dumps(r)
            if r.get("is_f2fs") or "log_blocksize" not in str(r.get("reason")):
                return False, f"log_blocksize {lbs:#x} accepted"
        _write_synthetic_f2fs(img)
        good_sb = conduit.parse_superblock(img)
        return good_sb.get("block_size") == 4096, "log_blocksize 0xFFFF and 0x4000000C rejected; 4 KB superblock parses"
    attempt("A-M10 corrupt F2FS log_blocksize is reported, not expanded", m10)

    # A-L01: out-of-range sub-blocks and missing evidence give IndexError / UNREADABLE
    def l01() -> Tuple[bool, str]:
        v = SutraEvidenceVault(output_dir=q("l01"))
        m = v.ingest_evidence(disk)
        n_sub = -(-m["evidence_media"]["size_bytes"] // SutraEvidenceVault.SUB_CHUNK_SIZE)
        seen = []
        for idx in (-1, n_sub, n_sub + 5000, 10 ** 9):
            try:
                v.prove_sub_block(disk, m, idx)
                seen.append(f"{idx}: no error")
            except IndexError:
                seen.append(f"{idx}: IndexError")
            except Exception as e:  # the wrong error type is a failure, not a crash of the check
                seen.append(f"{idx}: {type(e).__name__}")
        last = v.prove_sub_block(disk, m, n_sub - 1)["verified"]
        ok_missing, msg = v.verify_integrity(q("l01", "missing.raw"), m)
        ok = all(s.endswith("IndexError") for s in seen) and last and not ok_missing and msg.startswith("UNREADABLE")
        return ok, f"{'; '.join(seen)}; missing file: {msg.split(':')[0]}"
    attempt("A-L01 out-of-range sub-blocks raise IndexError; missing evidence is UNREADABLE", l01)

    # A-L02: a non-UTF-8 mount point does not break the block-device check
    def l02() -> Tuple[bool, str]:
        mounts = b"/dev/sda1 /media/user/Fran\xe7ois_USB vfat rw 0 0\n/dev/sdb1 /mnt/evidence ext4 ro 0 0\n"

        def fake_open(file: Any, mode: str = "r", *a: Any, **k: Any) -> Any:
            if file == "/proc/mounts":
                raw = io.BytesIO(mounts)
                return raw if "b" in mode else io.TextIOWrapper(raw, encoding=k.get("encoding") or "utf-8")
            return builtins.open(file, mode, *a, **k)
        g = globals()
        had, saved = "open" in g, g.get("open")
        g["open"] = fake_open
        fd = os.open(disk, O_READ_ONLY)
        try:
            info = DualBusWriteBlocker().check_block_device(fd, "/dev/sdb")
        finally:
            os.close(fd)
            if had:
                g["open"] = saved
            else:
                del g["open"]
        return info.get("mounted") is True, f"partition of /dev/sdb seen as mounted: {info.get('mounted')}"
    attempt("A-L02 a non-UTF-8 mount point does not break the block-device check", l02)

    # A-L03: a negative leaf index is refused
    def l03() -> Tuple[bool, str]:
        v = SutraEvidenceVault()
        leaves = [_leaf_hash(bytes([i]) * 8).hex() for i in range(5)]
        root, node = v.build_merkle_tree(leaves)
        try:
            v.generate_merkle_proof(node, leaves[4], leaf_index=-1)
            refused = False
        except IndexError:
            refused = True
        good_proof = verify_merkle_proof(leaves[4], v.generate_merkle_proof(node, leaves[4], leaf_index=4), root)
        return refused and good_proof, f"leaf_index -1 refused: {refused}; leaf_index 4 verifies: {good_proof}"
    attempt("A-L03 generate_merkle_proof refuses a negative leaf_index", l03)

    # A-PRF01: batch proofs read and hash each 4 MB chunk once
    def prf01() -> Tuple[bool, str]:
        two = write(q("two_chunks.raw"), rng.randbytes(SutraEvidenceVault.CHUNK_SIZE + 300 * 1024))
        v = SutraEvidenceVault(output_dir=q("prf01"))
        m = v.ingest_evidence(two)
        per = SutraEvidenceVault.CHUNK_SIZE // SutraEvidenceVault.SUB_CHUNK_SIZE
        idxs = [0, 1, per - 1, per, per + 7, 2, per + 250, 0]
        reads: List[int] = []
        real_read_chunk = v._read_chunk

        def counting(*a: Any, **k: Any) -> Any:
            reads.append(a[1])
            return real_read_chunk(*a, **k)
        v._read_chunk = counting  # type: ignore[assignment]
        try:
            batch = v.prove_sub_blocks(two, m, idxs)
        finally:
            del v._read_chunk
        singles = [v.prove_sub_block(two, m, i) for i in idxs]
        ok = len(reads) == 2 and batch == singles and all(p["verified"] for p in batch)
        return ok, f"{len(idxs)} proofs from {len(reads)} chunk reads; same as single proofs: {batch == singles}"
    attempt("A-PRF01 prove_sub_blocks reads each 4 MB chunk once", prf01)

    # Console: a cp1252 console or redirect cannot stop the self-test
    def console() -> Tuple[bool, str]:
        code = ("import importlib.util\n"
                f"spec = importlib.util.spec_from_file_location('sutra_a_console_check', {os.path.abspath(__file__)!r})\n"
                "mod = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(mod)\n"
                "mod._make_console_safe()\n"
                "print('rupee \\u20b9 arrow \\u2192')\n")
        env = dict(os.environ, PYTHONIOENCODING="cp1252")
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=300, env=env, cwd=base)
        escaped = b"\\u20b9" in r.stdout
        return r.returncode == 0 and escaped, f"exit {r.returncode}; unencodable text escaped: {escaped}"
    attempt("Console output that cp1252 cannot encode is escaped, not fatal", console)

    print(f"\n{sum(results)}/{len(results)} overnight audit regression checks passed")
    return all(results)


_USAGE = """usage: python sector_a_vault.py [WORKDIR] [--tsa=URL]

Runs the Sector A self-test on synthetic evidence in WORKDIR (default:
./sutra_vault_selftest). WORKDIR is emptied first, so it must be new, empty or
a folder the self-test created (it holds a .sutra_vault_selftest marker); any
other folder is refused and left untouched.

  --tsa=URL   also send the RFC 3161 time-stamp request to this TSA"""


def _make_console_safe() -> None:
    """A console or redirect target that cannot encode a character (cp1252, cp437 ...)
    shows an escape instead of stopping the run with UnicodeEncodeError."""
    for stream in (sys.stdout, sys.stderr):
        enc = (getattr(stream, "encoding", None) or "").lower().replace("-", "").replace("_", "")
        if enc not in ("utf8", "utf8sig") and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="backslashreplace")
            except (ValueError, OSError):
                pass


def _main(argv: Sequence[str]) -> int:
    if any(a in ("-h", "--help", "/?") for a in argv):
        print(_USAGE)
        return 0
    tsa = next((a.split("=", 1)[1] for a in argv if a.startswith("--tsa=")), None)
    args = [a for a in argv if not a.startswith("--tsa=")]
    unknown = [a for a in args if a.startswith("-")] or args[1:]
    if unknown:
        print(f"unrecognised argument(s): {' '.join(unknown)}\n\n{_USAGE}", file=sys.stderr)
        return 2
    return _self_test(args[0] if args else os.path.join(os.getcwd(), "sutra_vault_selftest"), tsa)


if __name__ == "__main__":
    _make_console_safe()
    sys.exit(_main(sys.argv[1:]))
