# SECTOR C: TEMPORAL PROVENANCE KNOWLEDGE GRAPH (T-PKG) ENGINE
## Definitive Engineering Specification & Implementation Manual for Claude
### Project: SUTRA-Trace (Autonomous Neuro-Symbolic Digital Forensics Framework)
**Standard:** ISO/IEC 27037:2012 · Section 45 & 63 BSA 2023 · Section 105 & 106 BNSS 2023  
**Target Architecture:** Python 3.10+ · Pure Python (Zero Mandatory External Dependencies) · Bounded 32-Byte CSR Memory Arena for Commodity 16GB Police Laptops  
**Target Module:** `prototype/sector_c_graph.py` (and synchronized with root `sector_c_graph.py`)

---

## 1. PURPOSE & ARCHITECTURAL SCOPE

Sector C is the **Deterministic Graph Core** of SUTRA-Trace. While Sector B triages individual suspicious leads in seconds, Sector C connects those disparate forensic artifacts into a unified, mathematically verifiable **Temporal Provenance Knowledge Graph (T-PKG)**:
$$\mathbf{e}_{ij}(t) = \left(v_i, v_j, r, t, \mathbf{x}_{ij}, \mathcal{P}_{\text{sym}}\right)$$

In Indian courtrooms under the **Bharatiya Sakshya Adhiniyam (BSA), 2023**, a prosecutor cannot simply show a correlation between a deepfake video and a victim's money transfer; they must prove an unbroken chain of **monotonic physical causality**:
1. The fake CBI officer initiated the WhatsApp call.
2. The rogue application hijacked the screen overlay.
3. The victim's funds were routed through specific UPI RRNs.
4. Every single link in the storyline is pinned to a deterministic byte offset on physical media.

Sector C eliminates AI hallucinations by enforcing:
1. **Contiguous 32-Byte C-Struct / CSR Ring Arena:** Ingests millions of telemetry events in bounded RAM (< 128 MB for 4,000,000 active edges), preventing Out-Of-Memory (OOM) crashes on 16GB police laptops.
2. **Bijective Harmonic-Logarithmic Time Encoding:** Prevents periodic aliasing and timewarp bugs across multi-week sleeper malware attacks.
3. **Anti-Supernode Gating & Process-Epoch Splitting:** Defeats malware evasion where attackers inject into high-degree brokers (e.g. `svchost.exe`, `system_server`) to dilute graph attention.
4. **5-Invariant Anti-Timestomping & Causality Repair Matrix:** Detects `$MFT` timestamp tampering (`timestomp`, `SetMace`) and restores true physical causality via parent socket and VSS baselines.
5. **Deterministic Prize-Collecting Steiner Tree (PCST) Solver:** Extracts the minimal, bit-identical causal attack storyline ($\le 25$ nodes) with tie-breaking ordered strictly by physical disk byte-offset $\Omega(e)$.

---

## 2. LOW-LEVEL MATHEMATICAL & DATA STRUCTURE SPECIFICATIONS

### 2.1 Bounded 32-Byte C-Struct Compressed Sparse Row (CSR) Ring Arena
- **Problem:** Naive graph implementations (using Python dictionaries or `networkx`) require 1.5 KB to 3.0 KB of memory per edge, causing Python to crash with OOM errors when processing real enterprise Sysmon or auditd logs (10M+ events).
- **Specification:**
  - Contiguous packed binary memory buffer using `struct` format `!IIHHQQI` (32 bytes per edge):
    - `src_id`: uint32 (4 bytes) — Index of source entity in entity table.
    - `dst_id`: uint32 (4 bytes) — Index of target entity.
    - `rel_id`: uint16 (2 bytes) — Canonical relation identifier (e.g. `SPAWNED=1`, `CONNECTED_TO=2`, `WROTE_FILE=3`, `UPI_TRANSFER=4`, `OVERLAY_HIJACK=5`).
    - `flags`: uint16 (2 bytes) — Bitflags: `IS_SUSPICIOUS=0x01`, `TIMESTOMP_INVERTED=0x02`, `CROSS_RAIL=0x04`, `EXCULPATORY=0x08`.
    - `timestamp_ns`: uint64 (8 bytes) — Nanoseconds since Unix epoch.
    - `byte_offset`: uint64 (8 bytes) — Deterministic physical media byte offset $\Omega$.
    - `loss_q16`: uint32 (4 bytes) — Q16.16 fixed-point anomaly score / reconstruction loss.
  - Ring buffer capacity: Default 1,000,000 to 4,000,000 edges ($32\text{ MB} - 128\text{ MB}$ RAM).
  - O(1) edge insertion and sliding window eviction.

### 2.2 Bijective Harmonic-Logarithmic Time Encoding
- **Problem:** Standard sinusoidal positional embeddings $\Phi(\Delta t) = [\cos(\omega \Delta t), \sin(\omega \Delta t)]$ suffer from periodic aliasing: two events separated by exact cycle intervals appear identical to neural graph models, allowing multi-week sleeper attacks to evade detection.
- **Specification:**
  $$\tilde{\Phi}(\Delta t) = \left[ \cos\left(\boldsymbol{\omega}_{\text{geom}}\Delta t + \mathbf{b}\right) \;\Big\|\; \sin\left(\boldsymbol{\omega}_{\text{geom}}\Delta t + \mathbf{b}\right) \;\Big\|\; \frac{\ln(1 + |\Delta t|)}{\ln(1 + \Delta t_{\max})} \;\Big\|\; \text{sign}(\Delta t) \right]$$
  where geometric frequencies $\omega_k = 10^{-9k/d}$ span $k \in [0, d-1]$. The strictly monotonic logarithmic envelope breaks cyclic ambiguity, guaranteeing a mathematical bijection between time delta $\Delta t$ and feature embedding $\tilde{\Phi}$.

### 2.3 Anti-Supernode Gating & Process-Epoch Node Splitting
- **Problem:** When an adversary executes malicious commands through a legitimate system broker (e.g. `svchost.exe`, `explorer.exe`, or Android `system_server`), the broker's enormous in-degree and out-degree dilute edge attention and obscure the intrusion path.
- **Specification:**
  1. **Process-Epoch Splitting:** When an inbound write, IPC, or code injection edge arrives from an untrusted subject into a broker, the broker's node is split into a new versioned epoch node:
     $$v_i^{(k)} \xrightarrow{\text{tainted}} v_i^{(k+1)}$$
     Downstream child processes are attributed exclusively to the tainted epoch $v_i^{(k+1)}$, preserving provenance separation.
  2. **Inverse Log-Degree Attention Gating:**
     $$\alpha_{ij}(t) = \frac{\exp\left(\mathcal{L}_{\text{prior}}(r_{ij})\right)}{\left(1 + \ln\left(1 + \text{deg}_{\Delta W}(v_i, r_{ij})\right)\right)^\gamma}$$
     where $\gamma = 1.5$. High-degree benign background traffic is attenuated automatically without arbitrary graph pruning.

### 2.4 5-Invariant Anti-Timestomping & Causality Repair Matrix
To catch both novice and nation-state timestamp manipulation, Sector C enforces five orthogonal forensic invariants:
1. **Invariant 1: NTFS `$MFT` Header LSN (`0x08`) & `$SI` USN (`0x28`) Monotonicity:**
   Compares `$STANDARD_INFORMATION` (`$SI`) timestamps against the strictly monotonic 64-bit `$LogFile` Sequence Number (LSN) and Update Sequence Number (USN). If file creation timestamp $t_{\$SI.\text{B}}$ is backdated earlier than an older file while having a strictly higher LSN and USN, timestomping is mathematically proven:
   $$\text{Alert}_{\text{LSN}} \iff (t_{\$SI.\text{B}}(i) < t_{\$SI.\text{B}}(j) - \delta) \land (\text{LSN}(i) > \text{LSN}(j)) \land (\text{USN}(i) > \text{USN}(j))$$
2. **Invariant 2: 100-Nanosecond Fractional Tick Entropy:**
   Windows NTFS natively stores timestamps in 100-nanosecond intervals ($10^{-7}\text{s}$). Attack tools (`timestomp`, `SetMace`, PowerShell `.NET` setters) truncate sub-millisecond precision, leaving fractional ticks equal to zero ($t_{\$SI} \bmod 10^7 = 0$), whereas real kernel file operations have high fractional tick entropy.
3. **Invariant 3: Benign Copy vs. Malicious Backdate Discrimination:**
   Distinguishes normal cross-folder copies ($t_{\$SI.\text{M}} < t_{\$FN.\text{B}}$ with $t_{\$SI.\text{B}} \ge t_{\$FN.\text{B}}$) from active timestomping ($t_{\$SI.\text{B}} < t_{\$FN.\text{B}}$ with `$SI` MFT-Modified $t_{\$SI.\text{C}} > t_{\$FN.\text{B}}$).
4. **Invariant 4: Monotonic Sequence in `$UsnJrnl:$J`:**
   Cross-verifies timestamps against the append-only USN Journal record sequence.
5. **Invariant 5: Physical Causality Inversion & Repair:**
   Enforces $t(\text{Child}) \ge t(\text{Parent})$. If an action timestamp predates the creation of the process that spawned it, the engine flags a `TEMPORAL_PARADOX_INVERSION` and restores the true chronological position using parent socket / network handshake timestamps.

### 2.5 Deterministic Prize-Collecting Steiner Tree (PCST) Storyline Solver
- **Problem:** Modern forensic incidents generate thousands of graph nodes. Presenting 10,000 raw graph nodes in court overwhelms judges and juries. Stochastic graph explainers (like `PGExplainer`) generate different explanation subgraphs on every run, violating courtroom reproducibility.
- **Specification:**
  - Implements a **100% Deterministic Combinatorial PCST Solver**:
    $$G_{\text{attack}}^* = \arg\min_{T = (V_T, E_T) \subseteq G, \, |V_T| \le 25} \left( \sum_{e \in E_T} \left(\mathcal{L}_{\max} - \mathcal{L}_{\text{rec}}(e)\right) + \lambda \sum_{v \notin V_T} p(v) \right)$$
  - Node prizes $p(v)$ are derived deterministically from Sector B's triage threat scores.
  - Edge costs are inversely proportional to anomaly scores.
  - **Deterministic Tie-Breaking:** When multiple edges or paths have equal cost, tie-breaking is ordered strictly by physical disk byte-offset $\Omega(e)$!
  - Emits a concise, ordered, courtroom-ready 4-stage narrative ($\le 25$ nodes):
    - Stage 1: Initial Infiltration & Deepfake Contact
    - Stage 2: Sideloaded Execution & Persistence
    - Stage 3: Credential Theft / Screen Overlay Hijack
    - Stage 4: Financial Exfiltration & Multi-Tier Smurfing

---

## 3. INTEGRATION WITH SECTOR A & SECTOR B

Sector C ingests:
1. `evidence_manifest.json` from Sector A (vault metadata, master roots, bad sector mask).
2. `triage_manifest.json` from Sector B (flagged leads, $\mathcal{P}_{\text{sym}}$ anchors).
3. Raw forensic log/telemetry streams (Sysmon JSONL/EVTX, WhatsApp WebRTC logs, UPI CSVs, usagestats).

Sector C emits:
- `attack_graph.json`: Full graph representation for interactive visualization in Sector E's Cockpit.
- `incident_storyline.json`: Ordered, byte-anchored attack narrative ready for Sector D's Section 63 BSA Schedule Certificate.

---

## 4. MINIMUM 35 DETERMINISTIC SELF-TEST SPECIFICATIONS

When executed directly (`python prototype/sector_c_graph.py`), the module must execute at least 35 deterministic assertions covering:
1. Bounded 32-byte CSR arena packing and unpacking (`!IIHHQQI`).
2. CSR ring buffer wraparound and memory bound verification ($\le 128\text{ MB}$).
3. Bijective time encoding: returns fixed vector length and monotonic envelope.
4. Bijective time encoding: identical $\Delta t$ produces bit-identical embedding.
5. Bijective time encoding: distinct $\Delta t$ produce distinct embeddings without aliasing.
6. Process-Epoch node splitting: tainted broker splits into $v_i^{(1)} \to v_i^{(2)}$.
7. Process-Epoch: downstream malicious children are bound exclusively to tainted epoch.
8. Anti-supernode gating: high-degree node edge attention is attenuated by $\gamma = 1.5$.
9. Invariant 1: `$MFT` LSN/USN monotonicity flags backdated file creation ($Alert_{\text{LSN}}$).
10. Invariant 2: 100-ns zero-tick entropy detects user-mode timestomping ($t \bmod 10^7 = 0$).
11. Invariant 3: Benign file copy discriminated from active timestomping.
12. Invariant 4: USN Journal append-only sequence order verified.
13. Invariant 5: Child predating parent triggers temporal paradox alert.
14. Invariant 5: Physical causality repair restores true timestamp from parent socket.
15. Deterministic PCST: extracts connected attack subgraph $\le 25$ nodes.
16. Deterministic PCST: tie-breaking by physical byte offset is 100% reproducible.
17. Mandatory provenance: rejects edge insertion if byte-offset anchor is missing.
18. Multi-modal node registration: supports PROCESS, FILE, SOCKET, UPI_ACCOUNT, IDENTITY.
19. Cross-rail edge support: represents UPI-to-USDT bridge transfer edge with dual anchors.
20. Digital Arrest storyline: Step 1 binds fake CBI WhatsApp call to `whatsapp.log` offset.
21. Digital Arrest storyline: Step 2 binds Chrome spawning PowerShell to `Sysmon.evtx` offset.
22. Digital Arrest storyline: Step 3 binds Trojan download to disk image `$MFT` offset.
23. Digital Arrest storyline: Step 4 binds C2 socket connection to PCAP packet offset.
24. Digital Arrest storyline: Step 5 binds victim bank transfer to statement CSV offset.
25. Digital Arrest storyline: Step 6 binds hub smurfing to NPCI switch log offset.
26. Monotonic causality validator confirms 0 temporal paradoxes on clean storyline.
27. Graph JSON exporter produces valid schema for Sector E dashboard.
28. Storyline exporter outputs all required Section 63 BSA physical metadata fields.
29. Memory usage test: 100,000 edges processed in $< 20\text{ MB}$ RAM.
30. Empty graph handling: graceful empty storyline export without crash.
31. Disconnected graph handling: PCST extracts highest-weight connected component.
32. Ingestion of Sector B's `triage_manifest.json` converts all symbolic anchors to graph nodes/edges.
33. Cross-verification with Sector A: validates that byte offsets fall within healthy sectors in bad sector mask.
34. Defense jury matrix: generates proof certificate explaining why Trojan Defense fails.
35. Full end-to-end pipeline run: outputs valid `attack_graph.json` and `incident_storyline.json`.

---

## 5. CODING GUIDELINES & CONSTRAINTS

- **Standard Library First:** Pure Python standard library (`struct`, `math`, `json`, `datetime`, `collections`, `heapq`, `hashlib`). Use optional `numpy` or `rustworkx` if present, but never fail if they are absent.
- **Zero Hallucination Guarantee:** Every edge in the output storyline **MUST** contain `source_file`, `byte_offset`, `length`, and `sha256`.
- **Strict Adherence to Section 63 BSA & Section 105/106 BNSS.**
