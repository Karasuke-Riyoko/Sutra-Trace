# SUTRA-TRACE: MASTER SYSTEM SPECIFICATION & MODULAR DEVELOPMENT BLUEPRINT
**Target Event:** SUTRAM 2026 National Hackathon (IGDTUW · ISEA Phase-III MeitY · NFSU)  
**Problem Statement ID:** PS-01 (Building an AI-Powered Indigenous Digital Forensics Investigation Framework)  
**Theme:** AI-Powered Cyber Investigation, Incident Response & Digital Forensics Technologies  
**Classification:** Confidential / Competitive Engineering Dossier & Prompt Architecture  

---

## 1. COMPREHENSIVE RESTRICTIONS, STATUTES & SYSTEM BOUNDARIES

Any solution generated for SUTRAM 2026 must adhere to the following rigid statutory, forensic, and architectural boundaries. Violating any of these criteria will lead to immediate disqualification or low scoring by the judging panel (chaired by NFSU Dean Prof. Dr. Parag H. Rughani and cyber investigation practitioners).

### 1.1 Legal & Statutory Restrictions (CRITICAL)
* 🚫 **Strict Prohibition on Old Law:** **NEVER cite Section 65B of the Indian Evidence Act, 1872.** It was repealed on July 1, 2024.
* ⚖️ **Mandatory BSA 2023 Compliance:** All electronic evidence admissibility must strictly cite **Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 (BSA)**.
* 📜 **Mandatory Schedule Certificates:** The system must automatically generate:
  * **Part A Certificate:** Signed by the person in lawful control of the computer/device.
  * **Part B Certificate:** Signed by an authorized forensic expert (certifying hash integrity and tool validation).
* 🛡️ **Non-Destructive Acquisition:** Adherence to **ISO/IEC 27037:2012** (Guidelines for digital evidence identification, collection, acquisition, and preservation). Bit-stream forensic imaging with dual-hashing (SHA-256 + BLAKE3) before any analysis touches the data.

### 1.2 Architectural & Engineering Restrictions
* 🚫 **Zero AI Hallucination Policy:** Standard LLM text generation is inadmissible in court. The system must use a **Neuro-Symbolic Architecture**:
  * *Neural Engine:* Fast triage, pattern recognition, anomaly clustering.
  * *Symbolic Engine:* Deterministic evidence pinning where **every node and edge in the attack graph is hard-anchored to an exact byte-offset on disk, sector address, or PCAP packet index**.
* 💻 **Resource Constraints (Commodity LEA Hardware):**
  * Indian Cyber Police Stations (LEAs) do not possess multi-GPU clusters.
  * The system must execute on standard commodity workstations: **x86_64 CPU, 16 GB RAM, optional single consumer GPU**.
  * Use **INT8 quantization via ONNX Runtime** and **chunked stream-parsing** to prevent Out-Of-Memory (OOM) crashes on large forensic images.
* 🇮🇳 **Real-World Indian Threat Vectors:**
  * Must natively support investigation playbooks for:
    1. **Digital Arrest Scams:** Deepfake video calls impersonating CBI/Customs/Police.
    2. **Multi-Tier UPI Mule Networks:** Fast layering of illicit funds across thousands of UPI handles.
    3. **Sideloaded APK Trojans:** SMS forwarders, OTP stealers (SpyMax, Goldoson variants).

### 1.3 Hackathon Submission Template Restrictions
* **Format:** Single **PDF file only** (the ISEA portal rejects PPTX, DOCX, ZIP).
* **Length:** Exactly **7 content slides + 1 title slide** (Max 10 slides limit). Slide 8 (Instructions) must be removed.
* **Layout:** Must strictly follow the official SUTRAM 2026 8-slide template structure without modifying header titles. Avoid dense text walls; use high-contrast badges, cards, metrics, and architecture flowcharts.

---

## 2. THE 5 MODULAR PROJECT PHASES

To maximize prompt reasoning and prevent Claude/Argon from generating truncated or generic boilerplate, the development is divided into 5 focused modules:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│ MODULE 1: INGESTION, DUAL-HASHING & MERKLE-DAG INTEGRITY LAYER (ISO/IEC 27037)  │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ MODULE 2: MULTI-MODAL NEURAL TRIAGE ENGINES (LOGS, DEEPFAKES, FINANCIALS, RAM)   │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ MODULE 3: TEMPORAL PROVENANCE KNOWLEDGE GRAPH (T-PKG) & STORYLINE RECONSTRUCTION │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ MODULE 4: BSA 2023 SECTION 63 LEGAL CERTIFICATE & REPORT GENERATOR (PDF)        │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ MODULE 5: INTERACTIVE INVESTIGATOR COCKPIT & WORKING PROTOTYPE (STREAMLIT)       │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. READY-TO-USE ARGON / CLAUDE MODULAR PROMPTS

Below are the exact self-contained prompts to feed into Claude/Argon one-by-one.

---

### 🟢 MASTER CONTEXT (Provide this first or keep as System Prompt)

```markdown
SYSTEM CONTEXT:
You are the Principal Cyber Forensics & Incident Response (DFIR) Systems Architect for SUTRA-Trace, an indigenous, neuro-symbolic AI forensics framework designed for the SUTRAM 2026 National Hackathon (IGDTUW · MeitY ISEA-III · NFSU).

STRICT DIRECTIVES:
1. All legal electronic evidence admissibility must cite Section 63 of Bharatiya Sakshya Adhiniyam, 2023 (BSA) with Schedule Certificate Parts A & B. Never mention the repealed Section 65B of Indian Evidence Act.
2. Architecture must follow ISO/IEC 27037:2012 non-destructive evidence standards with SHA-256 + BLAKE3 dual hashing and Merkle-DAG integrity.
3. Zero AI hallucination: every timeline claim must be deterministically anchored to byte-offsets or packet indices.
4. Target threats: Digital Arrest scams, multi-tier UPI mule networks, and sideloaded APK trojans.
5. All code must be production-ready Python 3.11+, typed, modular, and optimized for commodity workstations (16GB RAM).
```

---

### 📦 PROMPT 1: MODULE 1 — EVIDENCE INGESTION & CRYPTOGRAPHIC ANCHORING

```markdown
TASK: Implement Module 1 of SUTRA-Trace: "Deterministic Evidence Ingestion & Cryptographic Merkle-DAG Layer" in Python.

REQUIREMENTS:
1. Non-Destructive Acquisition Engine:
   - Function to ingest forensic raw disk images (.raw/.dd), PCAP network dumps (.pcap), memory dumps, and EVTX logs.
   - Enforce read-only access (ISO/IEC 27037).
2. Dual-Hashing & Merkle-DAG Engine:
   - Implement chunked 4MB streaming dual-hash computing both SHA-256 and BLAKE3 concurrently.
   - Construct an in-memory Merkle Tree where each leaf represents a raw evidence chunk, returning a Merkle Root Hash for immutable evidence anchoring.
3. Cryptographic Provenance Record:
   - Output an immutable JSON artifact containing:
     * evidence_id (UUID4)
     * original_filename, file_size_bytes
     * sha256_hash, blake3_hash, merkle_root
     * ingestion_timestamp_utc (ISO 8601)
     * rfc3161_simulated_token
     * chain_of_custody_log (initial examiner ID, workstation hostname)

DELIVERABLE:
Write a clean, self-contained Python module `sutra_ingest.py` with full docstrings, error handling, and a `__main__` demonstration verifying hash integrity.
```

---

### 📦 PROMPT 2: MODULE 2 — MULTI-MODAL NEURAL TRIAGE ENGINES

```markdown
TASK: Implement Module 2 of SUTRA-Trace: "Multi-Modal Forensic Neural Triage Engines".

REQUIREMENTS:
Create 3 specialized triage detectors optimized for commodity hardware:
1. Log & Command Triage (SecBERT / Heuristic Analyzer):
   - Parse EVTX/Sysmon event records (Event ID 1: Process Creation, ID 3: Network Connection).
   - Detect Living-Off-The-Land Binaries (LOLBins: certutil, powershell -enc, bitsadmin, mshta).
   - Assign threat scores (0.0 to 1.0) with confidence metrics.
2. Synthetic Media / Deepfake Triage Engine:
   - Implement spatial and frequency artifact extraction (Discrete Cosine Transform - DCT simulation) to flag synthetic faces in extortion/Digital Arrest scam video recordings.
   - Output authenticity confidence score and suspicious anomaly heatmap pointers.
3. Financial Trail & Mule Account Extractor:
   - Ingest UPI transaction logs / bank CSVs.
   - Detect rapid fund dispersal / layering patterns (e.g. ₹5,00,000 split across 10 mule UPI handles within 180 seconds).

DELIVERABLE:
Write a Python module `sutra_triage.py` containing modular classes `LogTriageEngine`, `DeepfakeTriageEngine`, and `FinancialMuleDetector`. Provide mock forensic inputs simulating a Digital Arrest case.
```

---

### 📦 PROMPT 3: MODULE 3 — TEMPORAL PROVENANCE KNOWLEDGE GRAPH (T-PKG)

```markdown
TASK: Implement Module 3 of SUTRA-Trace: "Temporal Provenance Knowledge Graph (T-PKG) & Storyline Reconstruction Engine".

REQUIREMENTS:
1. Heterogeneous Graph Schema:
   - Define Graph Node Types: `HOST`, `PROCESS`, `SOCKET`, `IP_DOMAIN`, `FILE_HASH`, `UPI_ACCOUNT`, `PERSON`.
   - Define Edge Types with timestamps: `SPAWNED`, `CONNECTED_TO`, `WROTE_FILE`, `TRANSFERRED_TO`, `EXFILTRATED`.
2. Deterministic Byte-Offset Anchoring (Anti-Hallucination):
   - Every edge must carry a mandatory dictionary `provenance`:
     `{"source_file": "disk_01.raw", "byte_offset": 4505600, "packet_idx": 1422, "rule_trigger": "MITRE_T1059.001"}`
3. Temporal Causality Enforcement:
   - Reject time-paradox edges (edges claiming an effect happened before its causal process spawn).
   - Traverse the graph to construct a chronologically ordered, end-to-end Attack Storyline.
4. MITRE ATT&CK & D3FEND Mapping:
   - Tag each attack phase with MITRE Technique IDs (e.g., T1566 Phishing, T1059 Command Execution, T1041 Exfiltration).

DELIVERABLE:
Write `sutra_graph.py` using `networkx` (compatible with PyTorch Geometric / Neo4j export). Include a function `reconstruct_incident_storyline(graph)` that outputs the verifiable chronological incident timeline.
```

---

### 📦 PROMPT 4: MODULE 4 — STATUTORY COMPLIANCE & BSA 2023 CERTIFICATE GENERATOR

```markdown
TASK: Implement Module 4 of SUTRA-Trace: "Bharatiya Sakshya Adhiniyam, 2023 (BSA) Section 63 Schedule Certificate Generator".

REQUIREMENTS:
1. Legal Standards:
   - Adhere strictly to Section 63 of Bharatiya Sakshya Adhiniyam, 2023 (replacing Section 65B of Indian Evidence Act).
   - Generate official Court-Admissible Schedule Certificates:
     * **PART A (Device Custodian Certificate):** Certification by the person responsible for the computer device/system operations.
     * **PART B (Forensic Expert Certificate):** Certification by the cyber forensic analyst detailing the forensic software, hash integrity, algorithm hashes (SHA-256/BLAKE3), and verification that the hash remained unchanged.
2. Technical Implementation:
   - Use Python (`reportlab` or clean HTML-to-PDF template) to generate a formal, print-ready 2-page legal certificate.
   - Include:
     * Case Crime Number (FIR details)
     * Seizure Memo & Evidence Tag Numbers
     * Digital Device Details (Make, Model, Serial, Storage Media)
     * Hash Verification Table (Acquisition Hash vs. Verification Hash)
     * Cryptographic Merkle Root Stamp
     * Forensic Software Certification Declaration

DELIVERABLE:
Write `sutra_bsa_cert.py` that ingests metadata from Module 1 and Module 3, and generates `BSA_2023_Sec63_Certificate.pdf`.
```

---

### 📦 PROMPT 5: MODULE 5 — INTERACTIVE INVESTIGATOR COCKPIT (PROTOTYPE)

```markdown
TASK: Implement Module 5 of SUTRA-Trace: "Interactive Streamlit Cockpit & Forensic Prototype".

REQUIREMENTS:
Create a single, deployable Streamlit application `app.py` uniting Modules 1 to 4:
1. Tab 1: Evidence Ingestion & Hash Locker (Upload disk/EVTX/PCAP, live SHA-256 + BLAKE3 calculation, Merkle-DAG tree view).
2. Tab 2: AI Neural Triage Matrix (Run automated scans, display LOLBin detections, Deepfake score gauges, and UPI layering flowcharts).
3. Tab 3: Temporal Attack Graph Explorer (Interactive Cytoscape / Pyvis network graph visualizing attack pathways with clickable nodes revealing raw byte-level evidence).
4. Tab 4: BSA 2023 Section 63 Certificate Vault (One-click generation and PDF preview of the official legal certificates).

DELIVERABLE:
Provide `app.py` with high-aesthetic dark cyber forensics styling (Navy/Cyan/Emerald UI), ready to run with `streamlit run app.py` for prototype demo screenshots.
```

---

### 📦 PROMPT 6: MODULE 6 — OFFICIAL 7-SLIDE SUTRAM PPT GENERATOR

```markdown
TASK: Generate the complete 7-slide SUTRAM 2026 Presentation Deck using python-pptx.

REQUIREMENTS:
1. Strict adherence to the official SUTRAM 2026 8-slide template structure (Slides 1 to 7 content, Slide 8 excluded).
2. Professional color palette matching the official template:
   - Primary Deep Navy: #0E2247
   - Accent Cyan: #00A6FB / #0077B6
   - Slate Text: #1E293B / #475569
   - Background Accent: #F8FAFC
3. Slide Layout:
   - Slide 1: Title Slide (PS-01, SUTRA-Trace, Theme, Badges for ISO 27037 & BSA 2023)
   - Slide 2: Team Details (4-Card Competency Grid: Systems Architect, Cryptographer, AI/Graph Lead, Full-Stack UI)
   - Slide 3: Idea Title & Proposed Solution (2-Column Split: The Crisis vs. SUTRA-Trace Innovation)
   - Slide 4: Technical Approach (4-Pillar Pipeline Diagram & Tech Stack Matrix)
   - Slide 5: Feasibility & Viability (Hardware feasibility on commodity PCs, Risk Mitigation Table)
   - Slide 6: Impact and Benefits (Police/LEAs, Courts & Prosecution, Atmanirbhar Bharat)
   - Slide 7: Research & References (BSA 2023, ISO 27037, NFSU Dean Dr. Parag Rughani papers, NIST CFReDS)

DELIVERABLE:
Write `generate_sutram_deck.py` using `python-pptx` to build and save `SUTRAM_2026_SUTRA_Trace_Deck.pptx`.
```
