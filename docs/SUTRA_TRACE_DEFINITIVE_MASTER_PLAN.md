# SUTRA-TRACE: DEFINITIVE MASTER SPECIFICATION & FORENSIC BLUEPRINT
**Target Event:** SUTRAM 2026 National Hackathon (IGDTUW · ISEA Phase-III MeitY · NFSU)  
**Flagship Challenge:** PS-01 (Building an AI-Powered Indigenous Digital Forensics Investigation Framework)  
**Theme:** AI-Powered Cyber Investigation, Incident Response & Digital Forensics Technologies  
**Classification:** Master Architectural Dossier & Statutory Compliance Matrix  

---

## 1. COMPREHENSIVE LEGAL, STATUTORY & FORENSIC MANDATES

To ensure full compliance and top-tier evaluation scores from the judging panel (headed by NFSU Dean Prof. (Dr.) Parag H. Rughani and cybercrime practitioners), every aspect of the solution is grounded in Indian criminal law and international forensic standards:

### 1.1 Indian Criminal & Evidence Statutes
1. **Bharatiya Sakshya Adhiniyam, 2023 (BSA):**
   * *Section 61:* Admissibility of electronic records.
   * *Section 62:* Special provisions regarding evidence relating to electronic records.
   * *Section 63 (CRITICAL):* Strict conditions for electronic evidence admissibility. **Replaces the repealed Section 65B of the Indian Evidence Act, 1872.**
   * *The Schedule Certificate:*
     * **Part A:** Certificate by the person in lawful charge of the computer/device.
     * **Part B:** Certificate by an authorized Cyber Forensic Expert certifying hash integrity, software validation, and hardware parameters.
2. **Bharatiya Nagarik Suraksha Sanhita, 2023 (BNSS):**
   * *Section 105:* Mandatory forensic photography/videography and strict digital seizure protocols during evidence collection.
3. **Bharatiya Nyaya Sanhita, 2023 (BNS):**
   * Covers modern cyber offense charges: Organized Cyber Deception (Digital Arrest scams), Impersonation, and Extortion.
4. **Information Technology Act, 2000 (as amended):**
   * *Section 43 & 66:* Computer-related offenses and hacking.
   * *Section 66C & 66D:* Identity theft and cheating by personation using computer resource.
   * *Section 79:* Intermediary liability and preservation of server traffic logs.
5. **Digital Personal Data Protection Act, 2023 (DPDP):**
   * Privacy-preserving forensic processing: Non-relevant civilian data minimization and investigator role-based access control (RBAC).

### 1.2 International Forensic Standards
* **ISO/IEC 27037:2012:** Guidelines for identification, collection, acquisition, and preservation of digital evidence (read-only loopback mount, zero byte alteration).
* **ISO/IEC 27042:2015:** Guidelines for analysis and interpretation of digital evidence.
* **RFC 3161:** Cryptographic Trusted Timestamping Protocol to prevent anti-forensic timestomping.
* **NIST SP 800-86:** Guide to integrating forensic techniques into incident response.

---

## 2. THE SUTRA-TRACE INNOVATION: PROACTIVE NEURO-SYMBOLIC ARCHITECTURE

Most competing hackathon proposals fail for two reasons:
1. **Black-box AI Hallucination:** Using LLMs that summarize logs without mathematically verifying facts. Indian courts reject unsubstantiated AI claims.
2. **Purely Reactive Analysis:** Looking only at individual logs without connecting the full attack storyline.

### The Solution: "SUTRA-Trace"
SUTRA-Trace is an **Autonomous Neuro-Symbolic Digital Forensics Framework** combining:
* **Neural Component (Speed & Triage):** Deep learning models that scan millions of logs, flag deepfake video/audio artifacts, and detect mule account clusters in seconds.
* **Symbolic Component (Mathematical Certainty):** Deterministic evidence pinning where **every edge in the graph is anchored to an exact raw byte offset on disk, sector address, or PCAP packet index**, verified by dual-hashes (SHA-256 + BLAKE3).

```
   [ RAW EVIDENCE ARTIFACTS ]
   (Disk Images, RAM Dumps, PCAP Traffic, Extortion Video/Audio, Bank Statements)
                     │
                     ▼
   [ PILLAR 1: DETERMINISTIC INGESTION & INTEGRITY VAULT ]
   ├─► Read-Only Loopback Mounting (ISO/IEC 27037)
   ├─► Dual-Streaming Hash: SHA-256 + BLAKE3
   └─► Chunked In-Memory Merkle-DAG Root Generation
                     │
                     ▼
   [ PILLAR 2: MULTI-MODAL NEURAL TRIAGE MATRIX ]
   ├─► Log Engine: SecBERT / LOLBin classifier (certutil, powershell -enc, mshta)
   ├─► Synthetic Media Engine: Spatial & Discrete Cosine Transform (DCT) deepfake detector
   ├─► Mule Account Engine: Graph clustering tracing rapid UPI layering
   └─► Memory Engine: Automated process injection detection
                     │
                     ▼
   [ PILLAR 3: TEMPORAL PROVENANCE KNOWLEDGE GRAPH (T-PKG) ]
   ├─► Nodes: HOST, PROCESS, SOCKET, IP, FILE_HASH, UPI_ACCOUNT, PERSON
   ├─► Edges: SPAWNED, CONNECTED_TO, WROTE_FILE, TRANSFERRED_FUNDS
   ├─► Anti-Hallucination: Every edge carries byte_offset and packet_idx pointers
   └─► Temporal Causality: Enforces physical chronological sequence
                     │
                     ▼
   [ PILLAR 4: COURTROOM ADMISSIBILITY & XAI ]
   ├─► Auto-Generated Schedule Certificate (Part A & B of BSA 2023 Sec 63)
   ├─► MITRE ATT&CK & D3FEND Adversary Kill-Chain Mapping
   └─► Chronological Investigator Storyline
```

---

## 3. INDIAN THREAT PLAYBOOKS NATIVELY SUPPORTED

SUTRA-Trace provides automated investigation playbooks for the 3 largest cybercrime vectors monitored by the Indian Cyber Crime Coordination Centre (I4C) & Ministry of Home Affairs (MHA):
1. **Digital Arrest Scams:** Deepfake video/audio triage, fake police notice extraction, caller IP de-anonymization.
2. **Multi-Tier UPI Mule Networks:** Layered transaction tracing across mule accounts, clustering smurfed payments.
3. **Sideloaded APK Trojans:** Dissecting Android malware (SpyMax, Goldoson) that abuse Accessibility Services and forward OTPs.

---

## 4. EVALUATION CRITERIA MATRIX ALIGNMENT

| Official SUTRAM Criterion | Weight | How SUTRA-Trace Maximizes Score |
| :--- | :--- | :--- |
| **Investigation Accuracy & Explainability** | **25%** | Deterministic byte-offset provenance pinning; zero AI hallucinations. |
| **Cross-Source Evidence Correlation** | **20%** | Temporal Provenance Knowledge Graph (T-PKG) linking disk, network, and financial traces. |
| **Crime Timeline & Reconstruction** | **20%** | Chronological causality engine reconstructing the 4-phase attack storyline. |
| **Presentation & Demonstration** | **20%** | Official 7-slide deck + working Streamlit investigator prototype. |
| **Evidence Processing & Extraction** | **15%** | ISO/IEC 27037 read-only loopback mount + SHA-256/BLAKE3 Merkle-DAG. |
| **Multimedia / Fraud Analysis** | **10%** | DCT frequency-domain deepfake detection + UPI mule network clustering. |
| **Performance & Usability** | **10%** | ONNX INT8 quantization running on commodity 16GB RAM police workstations. |

---

## 5. DECOUPLED IMPLEMENTATION SECTORS

To build this cleanly without circular dependencies:
* **Sector 1 (`vault_sector.py`):** Ingestion, dual-hashing, and Merkle root calculation.
* **Sector 2 (`triage_sector.py`):** Log, Deepfake, and UPI multi-modal triage.
* **Sector 3 (`graph_sector.py`):** Knowledge graph and attack timeline reconstruction.
* **Sector 4 (`legal_sector.py`):** BSA 2023 Section 63 Schedule Certificate PDF generator.
* **Sector 5 (`app.py`):** Streamlit interactive cockpit with pre-loaded case demonstration.
* **Sector 6 (`generate_deck.py`):** Official SUTRAM 7-slide PPTX builder.
