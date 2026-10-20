# SECTOR A: DETERMINISTIC EVIDENCE VAULT & CRYPTOGRAPHIC ANCHORING
## Definitive Engineering Specification & Implementation Manual for Claude
### Project: SUTRA-Trace (Autonomous Neuro-Symbolic Digital Forensics Framework)
**Standard:** ISO/IEC 27037:2012 · Section 63 BSA 2023 · Section 105 & 106 BNSS 2023  
**Target Architecture:** Python 3.11+ · Self-Contained · Edge-Optimized for Commodity 16GB Police Laptops  
**Target Module:** `sector_a_vault.py`

---

## 1. PURPOSE & ARCHITECTURAL SCOPE

Sector A is the **foundational bedrock** of SUTRA-Trace. In digital forensics, if the raw evidence acquisition or hashing fails, all downstream neural triage (Sector B), knowledge graphs (Sector C), and courtroom certificates (Sector D) collapse under defense cross-examination.

Sector A enforces:
1. **Strict Read-Only Non-Destructive Ingestion (ISO/IEC 27037:2012):** Zero bytes written to source evidence media.
2. **Streaming Chunked Dual-Hashing:** High-throughput streaming over 4 MB windows (zero RAM saturation) generating concurrent **Linear SHA-256** and **BLAKE3 Merkle-DAG sub-chunk tree**.
3. **Failing Media Resilience (Piecewise Valid-Extent Hashing):** Solves flash-memory degradation in police Malkhana storage by maintaining an LBA bitmask $M \in \{0, 1\}^N$ and computing Piecewise Valid-Extent digests.
4. **Section 105 BNSS 2023 Audio-Video Seizure Cross-Binding:** Parses field seizure MP4 container metadata (`stts`/`ctts`) and tracks **50 Hz Indian Electrical Network Frequency (ENF) power-grid hum continuity** ($\Delta\phi < 0.08\text{ rad}$) to prove zero video tampering, cryptographically cross-binding the video digest directly into the master Merkle evidence root.
5. **Section 106 BNSS 3-Point Optical PUF Faraday Seal Continuity Ledger:** Links field Faraday bag seal, Police Malkhana register deposit, and laboratory unsealing into a unified master case root $R_{\text{case}}^{\text{V3}}$.
6. **VBS/HVCI & Android 14+ Kernel Conduits:** Software interfaces and simulation hooks for Windows 11 VBS/HVCI physical RAM acquisition, BitLocker FVEK escrow, and Android 14+ F2FS dual-checkpoint rollback parsing.
7. **RFC 3161 PKI & NavIC Stratum-1 Time Discipline:** Generates a cryptographic timestamp token anchored to UTC(NPL).
8. **Canonical JSON Manifest Generation & Standalone Verifier:** Emits `evidence_manifest.json` and provides a built-in verification method.

---

## 2. LOW-LEVEL TECHNICAL SPECIFICATIONS & PRIMITIVES

### 2.1 Dual-Bus eBPF Kernel Write- & Deallocate-Blocker (NVMe & SCSI)
- **Problem:** Modern PCIe NVMe drives bypass legacy SCSI write-blockers. When powered, native NVMe controllers execute autonomous Background Garbage Collection (BGC) via Autonomous Power State Transitions (APST) and Dataset Management (TRIM) opcodes, silently destroying unallocated sectors.
- **Specification:**
  - Block PCIe NVMe Opcodes: `0x01` (Write), `0x08` (Write Zeroes), `0x09` (Dataset Management / Deallocate / TRIM), `0x80` (Format NVM), `0x84` (Sanitize).
  - Block SCSI Opcodes: `0x2A` / `0x8A` (WRITE), `0x42` (UNMAP).
  - Controller Quiescence: Set `APST = 0` to halt firmware background garbage collection while the drive is powered on the forensic workstation.
  - *Python Implementation Note:* Provide a software abstraction `DualBusWriteBlocker` that verifies read-only file/device descriptors (`os.O_RDONLY | getattr(os, 'O_BINARY', 0)`) and simulates/logs kernel eBPF filter attachment.

### 2.2 Piecewise Valid-Extent Hashing over Bitmask $M$ (Degrading Media Survival)
- **Problem:** If a seized NAND flash drive develops new bad sectors during 12 months in the police Malkhana, a standard full-disk linear SHA-256 hash fails, leading to false claims of evidence tampering and technical acquittals.
- **Mathematical Specification:**
  - Given a drive of $N$ sectors:
    $$M = [m_0, m_1, \dots, m_{N-1}], \quad m_i \in \{0, 1\}$$
    where $m_i = 1$ denotes a healthy sector and $m_i = 0$ denotes an unreadable/bad sector.
  - Linear SHA-256 is computed over all readable sectors with unreadable sectors isolated via 4 KB-aligned `0xDEADBEEF` fill.
  - **Piecewise Valid-Extent SHA-256:**
    $$\text{Hash}_{\text{valid}} = \text{SHA-256}\left( \bigcup_{i=0, m_i=1}^{N-1} \text{Sector}_i \right)$$
  - Emits a signed **Bad Sector Manifest** recording bad sector offsets, ensuring 100% cryptographic continuity even if flash sectors physically degrade before trial.

### 2.3 Native 1 KB / 4 MB Merkle-DAG Tree Engine
- **Specification:**
  - Streaming window: Bounded **4 MB chunk streaming** (prevents memory bloat on 16GB laptops).
  - Sub-chunk granularity: Each 4 MB chunk is subdivided into 1 KB sub-blocks for fine-grained Merkle branch proof generation.
  - Deterministic Binary Merkle Tree:
    - Leaf node: $H_{\text{leaf}} = \text{SHA-256}(\text{Chunk\_Data})$ (or native BLAKE3).
    - Internal node: $H_{\text{parent}} = \text{SHA-256}(H_{\text{left}} \,\|\, H_{\text{right}})$.
    - Odd-node handling: Duplicate the last node if the level count is odd.
  - Branch Proof Function: `generate_merkle_proof(chunk_index)` returning the sibling hash audit path $\pi(\Omega, L)$ allowing any 1 KB slice to be independently proven against the master root without rehashing the entire terabyte disk dump!

### 2.4 Section 105 BNSS 2023 Audio-Video Seizure Cross-Binding
- **The Mandate:** Bharatiya Nagarik Suraksha Sanhita, 2023 Section 105 mandates audio-video electronic recording of search and seizure operations.
- **Specification:**
  - Container Check: Parses ISO-BMFF box structure (`ftyp`, `mvhd`, `tkhd`, `stts`, `ctts`, `stss`) from the crime scene seizure MP4.
  - Variable Frame Rate (VFR) Check: Verifies smooth auto-exposure frame transitions:
    $$\frac{\Delta\text{Duration}_i}{\Delta\text{Duration}_{i-1}} \le 2.0$$
    cross-checked against the 48 kHz AAC audio sample clock (`soun`).
  - **50 Hz Indian Power-Grid (ENF) Hum Verifier:** Analyzes background audio track for the 50 Hz Indian electrical network frequency (`49.95 Hz – 50.05 Hz`). A natural low-light VFR drop preserves continuous acoustic phase ($\Delta\phi < 0.08\text{ rad}$), whereas a malicious pause or cut causes an immediate phase discontinuity.
  - **Cross-Binding:** The computed SHA-256 hash of the verified seizure video is cryptographically combined with the disk Merkle root:
    $$\text{Bound\_Root} = \text{SHA-256}(\text{Merkle\_Root}_{\text{disk}} \,\|\, \text{SHA-256}_{\text{seizure\_video}})$$

### 2.5 Section 106 BNSS 3-Point Optical PUF Faraday Seal Continuity Ledger
- **Specification:**
  - Binds 3 distinct physical-to-digital custody milestones into the Unified Master Case Root:
    1. Crime-Scene Faraday Bag Seal: Micro-optic barcode hash + RF attenuation ($\text{RSSI} \le -110\text{ dBm}$) $\to H_{\text{Seal\_Field}}$
    2. Police Malkhana Deposit: Register receipt number + timestamp hash $\to H_{\text{Malkhana}}$
    3. Forensic Laboratory Reception: Unsealing optical verification hash $\to H_{\text{Lab}}$
  - Master Case Root:
    $$R_{\text{case}}^{\text{V3}} = \text{BLAKE3}(\text{Root}_{\text{disk}} \,\|\, \text{Hash}_{\text{seizure\_video}} \,\|\, \text{Hash}_{\text{FIR}} \,\|\, H_{\text{Sec106\_SealChain}} \,\|\, H_{\text{NavIC\_Clock}})$$

### 2.6 Volatile RAM & Mobile F2FS Simulation Hooks
- **Windows 11 VBS/HVCI RAM:** Conduit method simulating `NtSystemDebugControl(Command=37)` / `MmCopyMemory(MM_COPY_MEMORY_PHYSICAL)` to map VTL0 memory pages and carve BitLocker AES-XTS-256 FVEKs (`FVEc`/`Cngb` pool tags).
- **Android 14+ F2FS Dual-Checkpoint:** Method simulating `gc_urgent = 0` (freeze garbage collection), parsing F2FS Superblock at `0x400`, diffing CP1/CP2 NAT/SIT journals, and scanning the Segment Summary Area (SSA) for orphaned `0xF2F5` inodes (RAT APKs, SQLite WAL frames).

---

## 3. DATA CONTRACTS & JSON MANIFEST SCHEMA

Sector A must output a canonical `evidence_manifest.json` conforming to this exact schema:

```json
{
  "version": "SUTRA-VAULT-2026.3-SUPREME",
  "evidence_id": "8941a8e2-c019-4821-b1e9-4089a8109bf2",
  "case_reference": "FIR-042/2026-CYBER",
  "examiner_id": "EX-79A-NFSU",
  "ingestion_workstation": "LEA-FORENSIC-WS01",
  "ingestion_timestamp_utc": "2024-10-19T15:00:00.000Z",
  "navic_stratum1_sync": {
    "source": "ISRO NavIC 1-PPS / UTC(NPL)",
    "allan_variance_ppb": 0.042,
    "clock_discipline_status": "LOCKED"
  },
  "evidence_media": {
    "filename": "evidence_disk_dump.raw",
    "size_bytes": 12015024,
    "total_chunks_4mb": 3,
    "hardware_telemetry": {
      "make_model": "Dell Latitude 5420 · NVMe PCIe SSD 512GB",
      "serial_number": "8F92K12-NVME-001",
      "firmware_rev": "EDF004",
      "ebpf_write_block_applied": true,
      "nvme_apst_quiesced": true
    }
  },
  "cryptographic_hashes": {
    "sha256_linear_primary": "e888906d5a6a4bbacb9bd1633bd3be38bacbddda57f549589674b272ef8b6f6f",
    "sha256_piecewise_valid_extent": "e888906d5a6a4bbacb9bd1633bd3be38bacbddda57f549589674b272ef8b6f6f",
    "blake2b_secondary": "383393d720de81023f2ef50dbaa9e8cedf691e416ad780b4e252005befb9dbd5c...",
    "blake3_root_dag": "9488166b82431611b653ee073646ae39f7c19600c66df9521a4e5407d0d04133",
    "bnss_105_seizure_video_sha256": "ab8d3c72d68ad46278b8737fc5f2b6a9c86fb34f41d18355776da8d9ec70296f",
    "final_bound_evidence_root": "07552db41f2454d28eb0427d8b52eb544523d29894265edf0ce3f05463131875",
    "master_case_root_v3": "f9a2b4c8d1e3759a0b2c4d6e8f1a3b5c7e9f0a2b4c6d8e0f1a3b5c7e9f0a2b4c"
  },
  "bnss_verification": {
    "sec_105_video_continuity": {
      "verified": true,
      "vfr_stts_ctts_ratio": 1.15,
      "indian_enf_power_hum_50hz": {
        "status": "LOCKED_CONTINUOUS",
        "mean_freq_hz": 49.982,
        "max_phase_jump_rad": 0.019,
        "threshold_rad": 0.08
      }
    },
    "sec_106_malkhana_seal_ledger": {
      "field_seal_rssi_dbm": -112,
      "malkhana_register_receipt": "MK-CY-2026/089",
      "lab_unseal_verified": true
    }
  },
  "rfc3161_timestamp_token": "466959f041b4009692c72176bcbfcac5d0bf3dd8f417efb67889a70aa0842583",
  "statutory_compliance": {
    "iso_iec_standard": "ISO/IEC 27037:2012 Read-Only Non-Destructive Acquisition",
    "evidence_statute": "Section 63 Bharatiya Sakshya Adhiniyam, 2023 (BSA)",
    "search_seizure_statute": "Section 105 & 106 Bharatiya Nagarik Suraksha Sanhita, 2023 (BNSS)",
    "it_act_authority": "Section 79A IT Act, 2000 Notified Forensic Laboratory"
  }
}
```

---

## 4. CLASS & METHOD SIGNATURE SPECIFICATION

Claude must implement the following class structure inside `sector_a_vault.py`:

```python
class MerkleNode:
    def __init__(self, hash_val: str, left: Optional['MerkleNode'] = None, right: Optional['MerkleNode'] = None):
        self.hash_val = hash_val
        self.left = left
        self.right = right

class SutraEvidenceVault:
    CHUNK_SIZE = 4 * 1024 * 1024 # 4 MB bounded streaming window
    SUB_CHUNK_SIZE = 1024        # 1 KB Merkle sub-blocks

    def __init__(self, case_id: str = "FIR-042/2026-CYBER", examiner_id: str = "EX-79A-NFSU"):
        ...

    def build_merkle_tree(self, chunk_hashes: List[str]) -> Tuple[str, MerkleNode]:
        """Constructs deterministic binary Merkle tree and returns (root_hash, root_node)."""
        ...

    def generate_merkle_proof(self, root_node: MerkleNode, target_hash: str) -> List[Dict[str, str]]:
        """Returns sibling hash proof path for proving sub-chunk inclusion."""
        ...

    def verify_seizure_video_enf(self, video_path: str) -> Dict[str, Any]:
        """
        Simulates / executes ISO-BMFF stts/ctts VFR analysis and 50 Hz Indian power-grid 
        hum continuity verification (Δϕ < 0.08 rad) under Section 105 BNSS 2023.
        """
        ...

    def ingest_evidence(self, 
                        file_path: str, 
                        seizure_video_path: Optional[str] = None,
                        bad_sector_mask: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Primary ingestion entrypoint. Computes:
        - Full-stream Linear SHA-256
        - Piecewise Valid-Extent SHA-256
        - Secondary BLAKE2b/BLAKE3 digest
        - 4 MB Merkle Tree Root
        - Section 105 BNSS Seizure Video Hash & Cross-Binding
        - Section 106 BNSS 3-Point Malkhana Seal Ledger
        - RFC 3161 Token
        Writes evidence_manifest.json and returns manifest dict.
        """
        ...

    def verify_integrity(self, file_path: str, manifest: Dict) -> Tuple[bool, str]:
        """Verifies currently stored file against the immutable manifest."""
        ...
```

---

## 5. IMPLEMENTATION RULES FOR CLAUDE

1. **Pure Python & Zero Fragile Dependencies:**
   - Must run reliably on standard Python 3.10+ on Windows/Linux using `hashlib`, `os`, `sys`, `json`, `time`, `datetime`, `uuid`.
   - Do not rely on external compiled C libraries that require gcc/msvc toolchains.
2. **Defensive Terminology Only:**
   - When referencing memory or kernel hooks, describe them as *"authorized physical address translation"*, *"forensic hardware write-blocking"*, and *"lawful key escrow under search warrant"*. Avoid exploit buzzwords (*"bypass"*, *"exploit"*, *"rootkit"*) to ensure Claude's safety filters do not trigger.
3. **Stand-Alone Test Runner:**
   - Must include a robust `if __name__ == '__main__':` block creating synthetic disk data (`evidence_disk_dump.raw`) and seizure video (`seizure_recording_sec105.mp4`), executing ingestion, printing complete telemetry, and validating integrity.
4. **Clean Decoupling:**
   - Must not import Sector B, C, D, or E. Sectors B–E will import Sector A!
