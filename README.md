# SUTRA-Trace: Autonomous Neuro-Symbolic Digital Forensics Framework

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Statute: BSA 2023 Sec 63](https://img.shields.io/badge/Statute-BSA%202023%20Sec%2063-success.svg)](https://www.indiacode.nic.in/)
[![Standard: ISO/IEC 27037](https://img.shields.io/badge/Standard-ISO%2FIEC%2027037%3A2012-orange.svg)](https://www.iso.org/)
[![Evaluation Pass Rate](https://img.shields.io/badge/Test%20Harness-100%25%20PASS-brightgreen.svg)](tests/)

> **Target Event:** SUTRAM 2026 National Hackathon  
> **Organizers:** Indira Gandhi Delhi Technical University for Women (IGDTUW), ISEA Phase-III (MeitY), National Forensic Sciences University (NFSU)  
> **Flagship Challenge:** Problem Statement PS-01 (*Building an AI-Powered Indigenous Digital Forensics Investigation Framework*)  
> **Theme:** AI-Powered Cyber Investigation, Incident Response & Digital Forensics Technologies  
> **Team:** HAVOC  

---

## Executive Summary

**SUTRA-Trace** is an indigenous, edge-optimized, **Neuro-Symbolic Digital Forensics Framework** engineered specifically for Indian Law Enforcement Agencies (LEAs), judicial magistrates, and cyber forensic laboratories.

Modern forensic workflows suffer from two fatal weaknesses:
1. **Black-box AI Hallucinations:** Generative models summarize forensic logs without mathematical fact-checking, making evidence legally inadmissible.
2. **Statutory Non-Compliance:** Tools still generate legacy certificates under the repealed Section 65B of the Indian Evidence Act, 1872.

**SUTRA-Trace bridges this gap through a Neuro-Symbolic Architecture:**
* **Neural Component (Speed & Triage):** Deep-learning and signal-processing engines perform high-recall triage across millions of events, detecting LOLBin abuse, deepfake synthetic media artifacts, multi-tier UPI smurfing, and rogue Android APKs in milliseconds.
* **Symbolic Component (Mathematical Certainty & Legal Proof):** Deterministic evidence pinning where **every node and edge in the attack graph is mathematically anchored to an exact byte-offset on disk, sector address, or packet index**, protected by dual-streaming cryptographic digests (SHA-256 + BLAKE3/BLAKE2s) and Merkle-DAG proofs.

---

## Statutory & Forensic Compliance Matrix

SUTRA-Trace is strictly built around current Indian criminal and digital evidence laws that came into force on **July 1, 2024**:

| Statute / Standard | Relevant Section | How SUTRA-Trace Strictly Complies |
| :--- | :--- | :--- |
| **Bharatiya Sakshya Adhiniyam, 2023 (BSA)** | **Section 63(4)(c) & The Schedule** | Replaces repealed Sec 65B IEA. Automatically generates court-ready **Schedule Part A** (lawful custodian) and **Schedule Part B** (accredited examiner) certificates. |
| **BSA 2023** | **Section 57 Expl. 5 & Section 39** | Implements the **3-Scenario Statutory Custody Selector** (Hostile Suspect, Cooperative Victim, Intermediary/Bank) and Dual-Track Sec 39(1) / 39(2) pathways. |
| **BSA 2023** | **Section 45** | Automates the **14-Point Exculpatory Intrusion Checklist** to defeat the "Trojan Horse Defense" with verifiable mathematical proof. |
| **Bharatiya Nagarik Suraksha Sanhita, 2023 (BNSS)** | **Section 105** | Enforces cryptographic binding with mandatory seizure videography, validating ENF (Electrical Network Frequency) 50Hz grid-hum continuity. |
| **BNSS 2023 / PMLA 2002** | **Section 106 & Sec 17(1A)** | Automatically drafts statutory Bank & Crypto Freeze Notices and schema-validated **FIU-IND FINnet 2.0 STR XML** reports. |
| **ISO/IEC 27037:2012** | Clause 6 & 7 | Non-destructive acquisition with software/eBPF write-blocking policies and chunked Merkle-DAG validation. |

---

## Architectural Sectors

```
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │                RAW FORENSIC EVIDENCE (Disk, RAM, PCAP, Video, UPI)              │
 └────────────────────────────────────────┬────────────────────────────────────────┘
                                          │
                                          ▼
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │ SECTOR A: Deterministic Evidence Vault & Merkle-DAG (ISO/IEC 27037)             │
 │  • Dual-Streaming Hash: SHA-256 + BLAKE2s/BLAKE3                                │
 │  • 4MB Chunked In-Memory Merkle-DAG Root                                        │
 │  • BNSS Sec 105 Seizure Video Verification (ENF 50Hz phase lock)               │
 └────────────────────────────────────────┬────────────────────────────────────────┘
                                          │
                                          ▼
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │ SECTOR B: Multi-Modal Neural Triage Matrix                                      │
 │  • LOLBin/SecBERT Classifier (certutil, powershell -enc, mshta)                 │
 │  • Synthetic Media Engine (2D-DCT spectral Nyquist checkerboard & rPPG phase)   │
 │  • Financial Engine (NPCI RRN parsing, rapid UPI fan-out smurfing, crypto)      │
 │  • Mobile Engine (Android Accessibility abuse, notification listeners, polyglot)│
 └────────────────────────────────────────┬────────────────────────────────────────┘
                                          │
                                          ▼
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │ SECTOR C: Temporal Provenance Knowledge Graph (T-PKG)                           │
 │  • 32-Byte CSR Arena with O(1) ingestion & FIFO eviction                        │
 │  • Deterministic Prize-Collecting Steiner Tree (PCST) storyline solver          │
 │  • Anti-Timestomping Engine ($MFT / $UsnJrnl 5 monotonic invariants)            │
 │  • 100% Deterministic Byte-Offset & Packet-Index Anchoring                     │
 └────────────────────────────────────────┬────────────────────────────────────────┘
                                          │
                                          ▼
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │ SECTOR D: Statutory Compliance & BSA 2023 Sec 63 Certificate Generator          │
 │  • Courtroom PDF/A-1b 2-Page Schedule Certificate (Part A & B)                  │
 │  • Dynamic QR Payload for instant smartphone verification by Magistrates        │
 │  • FIU-IND FINnet 2.0 STR XML Export (PMLA Rule 8)                              │
 │  • Section 106 BNSS Statutory Bank Lien / Account Freeze Notices                │
 └────────────────────────────────────────┬────────────────────────────────────────┘
                                          │
                                          ▼
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │ SECTOR E: Interactive Forensic Cyber Cockpit (Streamlit / Flask Web UI)         │
 │  [Under Active Integration by Core Development Team]                            │
 └─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
sutra-trace/
├── docs/                                 # Architectural specifications & legal dossiers
│   ├── SUTRA_TRACE_MASTER_SYSTEM_ARCHITECTURE.md
│   ├── SUTRA_TRACE_DEFINITIVE_MASTER_PLAN.md
│   ├── SUTRA_TRACE_SYSTEM_SPEC_AND_MODULAR_ROADMAP.md
│   ├── ARGON_ADVERSARIAL_AUDIT_REPORT.md
│   ├── SECTOR_A_SPECIFICATION.md
│   ├── SECTOR_B_SPECIFICATION.md
│   ├── SECTOR_C_SPECIFICATION.md
│   ├── SECTOR_D_SPECIFICATION.md
│   └── SECTOR_E_SPECIFICATION.md
├── prototype/                            # Fortified sector implementations
│   ├── sector_a_vault.py                 # Evidence Vault & Merkle Tree Engine
│   ├── sector_b_triage.py                # Multi-Modal Neural Triage Matrix
│   ├── sector_c_graph.py                 # Temporal Provenance Knowledge Graph (T-PKG)
│   ├── sector_d_legal.py                 # BSA 2023 Sec 63 Certificate & FIU-IND Generator
│   ├── sector_e_dashboard.py             # Offline investigator cockpit (web UI + REST API)
│   └── Start SUTRA-Trace Cockpit.bat     # Windows one-click launcher
├── tests/
│   └── run_all_tests.py                  # Master test harness running all five self-tests
├── main.py                               # Unified CLI entrypoint & orchestrator
├── sutra_pipeline.py                     # 4-stage pipeline coordination engine
├── requirements.txt                      # Project dependencies & optional accelerators
├── .gitignore                            # Clean git exclusion rules
└── LICENSE                               # MIT License
```

---

## Quickstart Guide

### 1. Prerequisites
SUTRA-Trace is built on pure Python standard library primitives and runs out of the box with zero required external binary packages. Optional accelerators are available in `requirements.txt`:

```bash
git clone https://github.com/Karasuke-Riyoko/sutra-trace.git
cd sutra-trace

# Optional: install PDF/A font rendering and numpy acceleration
pip install -r requirements.txt
```

### 2. Run Complete 4-Stage Demonstration
Execute the full end-to-end neuro-symbolic pipeline across Sectors A, B, C, and D:
```bash
python main.py
```
*Outputs generated in `sutra_out/`:*
* `sector_a/evidence_manifest.json` (Cryptographic Merkle-DAG manifest)
* `triage_manifest.json` (Multi-modal leads & Sec 45 exculpatory ratio)
* `sector_c/attack_graph.json` & `incident_storyline.json` (Byte-pinned storyline)
* `legal_package/BSA_2023_Sec63_Certificate.pdf` (Court certificate with QR)
* `legal_package/FIU_IND_STR_FINnet2.xml` (FIU-IND Suspicious Transaction Report)
* `legal_package/Sec106_BNSS_Freeze_Notice.json` (Statutory bank freeze notice)

### 3. Run Cryptographic Integrity Verification
Independently re-verify evidence image digests, chunk proofs, and Merkle root:
```bash
python main.py --verify
```

### 4. Run Complete Sector Self-Tests & Regressions
Execute the comprehensive test harness covering all 350 checks across the 5 sectors:
```bash
python main.py --tests
# or
python tests/run_all_tests.py
```

### 5. Launch Investigator Cockpit (Sector E)
Launch the sovereign, zero-egress Cyber Cockpit at `http://127.0.0.1:5000`:
```bash
python main.py --serve
# or directly
python prototype/sector_e_dashboard.py --serve
```
Features include:
- **Zero-Egress Air-Gapped UI:** 100% self-contained HTML5 Canvas, WebGL, and SVG with CSP nonces.
- **Physical Offset Inspector:** Live inspection of raw physical byte offsets ($\Omega$) proved directly against Sector A's Merkle root.
- **1-Click Court Exports:** Download 2-page Section 63 BSA Certificate PDF, Section 106 BNSS Freeze Notice, and FIU-IND STR XML.
- **Sub-Second Runtime:** a full A→B→C→D run on both exhibits measured 0.94 s (Python 3.13) and 0.70 s (Python 3.10 on the development laptop).

On Windows you can also double-click `prototype\Start SUTRA-Trace Cockpit.bat`: it stops any cockpit already running, finds Python, picks a free port and opens the browser.

---

## Test Verification Matrix

Each self-test prints one summary line per group and exits non-zero if any check fails.
Every "overnight audit" check was written to fail on the code before its fix.

| Sector | Module | Spec checks | Earlier audit regressions | Overnight audit regressions | Total |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Sector A** | `sector_a_vault.py` | 35 | – | 23 | 58 |
| **Sector B** | `sector_b_triage.py` | 35 | 22 | 32 | 89 |
| **Sector C** | `sector_c_graph.py` | 35 | 16 | 25 | 76 |
| **Sector D** | `sector_d_legal.py` | 35 | 12 | 27 | 74 |
| **Sector E** | `sector_e_dashboard.py` | 40 | – | 13 | 53 |
| **Total** | | **180** | **50** | **120** | **350** |

All 350 pass on Python 3.10 and 3.13 (21 Oct 2026). Sector A reports `33/33 checks passed, 2 skipped`
when the optional `cryptography` package is missing (the two Ed25519 signature checks). Cockpit check 40
enforces zero egress: no external URL, `@import`, `<link>` or `url()`, and a nonce on every script and style.

### Known limits
- Test exhibits are synthetic, so Sector A marks the handset bundle `PROVISIONAL` / `REJECTED_FOR_COURT`
  (unsigned seals, no RFC 3161 authority) and certificate readiness is `READY_FOR_SIGNATURE_WITH_NOTES`.
- The eBPF write filter, NavIC clock, APST check and RAM capture are labelled simulations.
- Sector C keeps at most 250,000 edges in memory and exports the 50,000 most suspicious; anchors outside
  the evidence folder are refused (`OUTSIDE_EVIDENCE_ROOT`).
- Closing the cockpit window instead of pressing Ctrl+C can leave its temporary `sutra_cockpit_*` folder behind.

---

## Evaluation Alignment (SUTRAM 2026 PS-01)

* **Investigation Accuracy & Explainability (25%):** 100% deterministic byte-offset physical anchors; zero probabilistic LLM hallucinations.
* **Cross-Source Evidence Correlation (20%):** T-PKG graph linking disk records, PCAP packets, Android APK components, and UPI transactions.
* **Crime Timeline Reconstruction (20%):** Strict causality engine with NTFS $MFT / $UsnJrnl anti-timestomping validation.
* **Presentation & Judicial Usability (20%):** Instant smartphone QR verification for Judicial Magistrates; PDF/A-1b court certificates.
* **Statutory Compliance (15%):** Full alignment with BSA 2023 Section 63, BNSS 2023 Section 105/106, and FIU-IND FINnet 2.0.

---

## Authors & Acknowledgments

* **Team HAVOC** · SUTRAM 2026 National Hackathon
* Developed in accordance with guidelines from **NFSU Gandhinagar**, **MeitY ISEA Phase-III**, and **IGDTUW**.
