# SECTOR E: INTERACTIVE FORENSIC CYBER COCKPIT & PROTOTYPE RUNTIME
## Definitive Engineering Specification & Implementation Manual for Claude
### Project: SUTRA-Trace (Autonomous Neuro-Symbolic Digital Forensics Framework)
**Standard:** ISO/IEC 27037:2012 · Section 45 & 63 BSA 2023 · Section 105 & 106 BNSS 2023 · PMLA 2002  
**Target Architecture:** Python 3.10+ · Dual Mode (Headless Self-Test CLI & Interactive Web Cockpit) · Lightweight Flask/HTTP Server · Zero External Node/NPM Dependencies  
**Target Module:** `prototype/sector_e_dashboard.py` (and synchronized with root `sector_e_dashboard.py`)

---

## 1. PURPOSE & ARCHITECTURAL SCOPE

Sector E is the **Visual Nervous System & Demonstration Cockpit** of SUTRA-Trace. While Sectors A, B, C, and D perform low-level cryptographic vaulting, neural triage, graph provenance, and statutory certificate generation, Sector E unifies all four sectors into a high-impact, interactive **Forensic Cyber Cockpit**.

### The 1-Click Golden Benchmark Demo:
In high-stakes hackathon presentations, judges, jury members, and senior IPS/forensic officers must see the entire neuro-symbolic pipeline execute **in under 2 seconds**:
1. Ingests raw vaulted forensic disk image & Section 105 BNSS seizure MP4.
2. Runs high-recall neural triage over logs, deepfake video, and UPI smurfing transactions.
3. Constructs the deterministic 32-byte CSR Temporal Provenance Knowledge Graph (T-PKG) and extracts the 12-step PCST attack storyline.
4. Generates the court-admissible Section 63 BSA 2023 Schedule Certificate PDF and FIU-IND STR XML bundle.
5. Displays live interactive visualizations with clickable byte-offset back-binding directly to physical sectors.

---

## 2. DUAL-MODE ARCHITECTURAL DESIGN

`sector_e_dashboard.py` must support two operational modes:

### Mode 1: Headless CLI & Automated Self-Test (Default)
- When executed directly without server flags:
  ```bash
  python prototype/sector_e_dashboard.py
  ```
- Executes the full end-to-end pipeline using the fortified `prototype/sector_a_vault.py`, `prototype/sector_b_triage.py`, `prototype/sector_c_graph.py`, and `prototype/sector_d_legal.py`.
- Runs a built-in test suite of **at least 35 deterministic assertions** verifying:
  - Pipeline execution speed (< 3.0 seconds total).
  - API endpoint responses and JSON data structures.
  - Interactive SVG/Canvas attack graph data generation.
  - Dynamic QR verification and certificate PDF download routes.
  - Section 45 BSA 14-point exculpatory checklist rendering.
  - Section 106 BNSS freeze notice and FIU-IND STR XML generation.
  - Prints: `35/35 checks passed` with exit code 0.

### Mode 2: Interactive Web Cockpit Server
- When executed with `--serve` or `--port <port>`:
  ```bash
  python prototype/sector_e_dashboard.py --serve --port 5000
  ```
- Launches the Flask web server and automatically opens the browser to `http://127.0.0.1:5000`.
- Renders an ultra-modern, dark-themed Cyber Cockpit UI with real-time updates and interactive controls.

---

## 3. CYBER COCKPIT UI & VISUALIZATION PANELS

The Web UI must feature five cohesive, high-density panels:

### Panel 1: Top Institutional & Statutory Banner
- Badges:
  - `[IGDTUW · MeitY ISEA Phase-III · NFSU Gandhinagar Lead Partner]`
  - `[100% Section 63 BSA 2023 & Section 105/106 BNSS Compliant]`
  - `[Zero-Egress Air-Gapped Commodity 16GB Police Laptop Ready]`
- Active Case Header: `Case FIR-042/2026-CYBER (Operation Maya)` | `Examiner: EX-79A-NFSU`.
- 1-Click Action Buttons:
  - `[▶ Re-Run Pipeline (2s)]`: Re-executes the 4 sectors live.
  - `[📄 Download Section 63 BSA Certificate (PDF)]`: Instant download of the 2-page court certificate.
  - `[⚡ Download FIU-IND STR XML]`: Instant download of the PMLA FINnet 2.0 package.
  - `[🔒 View Section 106 BNSS Freeze Notice]`: Modal viewing of the emergency bank freeze order.

### Panel 2: Cryptographic Evidence Vault (Sector A Integration)
- Displays live cryptographic digests:
  - Linear SHA-256 Primary Digest
  - BLAKE2b Secondary Digest
  - RFC 6962 Binary Merkle Root (4 MB chunks / 1 KB sub-blocks)
  - Section 105 BNSS Audio-Video Seizure Recording Hash
  - Final Bound Master Evidence Root
- Section 105 BNSS 50 Hz Electrical Network Frequency (ENF) continuity status:
  - `[LOCKED_CONTINUOUS]` $\Delta\phi < 0.08\text{ rad}$
- Section 106 BNSS 3-Point Seal Chain:
  - Crime-scene Faraday bag barcode ($\text{RSSI} \le -110\text{ dBm}$)
  - Malkhana Register deposit receipt (`MK-CY-2026/089`)
  - Laboratory unsealing camera verification

### Panel 3: Multi-Modal Neural Triage Gauges (Sector B Integration)
- **Gauge 1: LOLBins & Command Triage:**
  - Displays flagged processes (`certutil.exe`, `powershell.exe`), MITRE ATT&CK techniques (`T1105`, `T1059.001`), deobfuscated UTF-16LE payloads, and Shannon entropy scores ($H \ge 4.8$).
- **Gauge 2: Deepfake Media Triage:**
  - Carotid-to-Supraorbital Pulse Transit Time (PTT) phase lag indicator: compares authentic physiological arterial transit ($\Delta\tau_{\text{PTT}} \in [12\text{ ms}, 45\text{ ms}]$) against synthetic global shader injection ($\Delta\tau \approx 0\text{ ms}$).
  - 2D-DCT frequency decay anomaly score with $\widehat{\text{QP}}$-gated threshold curve.
  - Extracted WhatsApp WebRTC `srflx` IP:Port candidate and Section 94 BNSS Telecom CGNAT IPDR requisition.
- **Gauge 3: NPCI UPI Mule Smurfing Triage:**
  - Visual fan-out diagram: Hub VPA (`tier1_hub@ybl`, ₹5,00,000 inflow) rapidly fragmented into 4 Tier-2 mule VPAs within 80 seconds.
  - Mirror-Hawala ₹10/₹20 currency note serial token (`72B 948102`).
  - Cross-chain DeFi liquidity bridge matching (UPI RRN matched to TRON USDT within 300s escrow window).

### Panel 4: Interactive PCST Attack Storyline & Provenance Graph (Sector C Integration)
- **Interactive SVG / Canvas Graph:**
  - Visual nodes: `IDENTITY` (Fake CBI Officer, Victim), `PROCESS` (`chrome.exe`, `powershell.exe`), `FILE` (`cbi_warrant.exe`), `SOCKET` (`cbi-court-portal.in`), `UPI_ACCOUNT` (Hub VPA, Mule VPAs).
  - Clickable nodes: Clicking any node or edge opens the **Physical Offset Inspector** showing:
    - Target file path
    - Exact physical byte offset ($\Omega$) in hex and decimal
    - Disk sector index ($\Omega // 512$)
    - SHA-256 chunk digest verified against Sector A's Merkle tree.
- **Chronological 12-Step Incident Storyline Table:**
  - Step number, UTC timestamp, source entity, action relation, target entity, MITRE technique, and physical forensic anchor.
  - 5-Invariant Anti-Timestomping status: proves that backdated file creation was caught and causality repaired.

### Panel 5: Section 45 BSA Exculpatory Intrusion Ledger & Defense Jury Matrix
- **14-Point Exculpatory Checklist Table:**
  - Interactive vs remote session verification
  - Inbound AnyDesk / RDP session analysis
  - Parent PID cryptographic signature checks
  - Defeats the "Trojan Defense" under Section 45 BSA ("Grounds of opinion, when relevant") with clear judicial explanation.

---

## 4. API ENDPOINTS SPECIFICATION

The Flask application must expose these JSON and file endpoints:
1. `GET /`: Renders the full single-page Cyber Cockpit HTML dashboard.
2. `GET /api/status`: Returns current pipeline health, case reference, examiner ID, and execution timestamps.
3. `POST /api/run`: Triggers a live re-execution of Sectors A, B, C, and D, returning updated metrics.
4. `GET /api/vault`: Returns Sector A evidence manifest, hash table, ENF hum status, and seal chain.
5. `GET /api/triage`: Returns Sector B triage alerts, PTT deepfake metrics, and UPI smurfing clusters.
6. `GET /api/graph`: Returns Sector C graph nodes, edges, PCST storyline, and physical byte anchors.
7. `GET /api/exculpatory`: Returns Sector B/C Section 45 BSA 14-point intrusion checklist results.
8. `GET /download/certificate`: Streams `BSA_2023_Sec63_Certificate.pdf` generated by Sector D.
9. `GET /download/str_xml`: Streams `FIU_IND_STR_FINnet2.xml` for FIU-IND reporting.
10. `GET /download/freeze_notice`: Returns the Section 106 BNSS / Section 17(1A) PMLA freeze order JSON.
11. `GET /api/qr`: Returns the embedded Dynamic QR code PNG image.

---

## 5. MINIMUM 35 DETERMINISTIC SELF-TEST SPECIFICATIONS

When executed in headless mode (`python prototype/sector_e_dashboard.py`), the module must execute at least 35 deterministic unit test assertions:
1. Full end-to-end pipeline execution finishes in under 5.0 seconds.
2. Flask test client initializes without error.
3. `GET /` returns HTTP 200 with valid HTML containing "SUTRA-TRACE".
4. Dashboard HTML contains official institutional badges (`IGDTUW`, `ISEA-III`, `NFSU`).
5. Dashboard HTML contains statutory citations (`Section 63 BSA 2023`, `Section 105 BNSS`).
6. `GET /api/status` returns HTTP 200 with valid case reference (`FIR-042/2026-CYBER`).
7. `GET /api/vault` returns all 5 required cryptographic digests (SHA-256, BLAKE2b, Merkle, BNSS 105, Bound Root).
8. `GET /api/vault` verifies Section 105 BNSS 50 Hz ENF power hum status is `LOCKED_CONTINUOUS`.
9. `GET /api/vault` verifies Section 106 BNSS 3-point seal chain entries.
10. `GET /api/triage` returns flagged LOLBins with threat score $\ge 0.85$.
11. `GET /api/triage` includes decoded UTF-16LE Base64 command line.
12. `GET /api/triage` returns deepfake PTT metrics showing synthetic shader detection ($\Delta\tau_{\text{PTT}} \approx 0\text{ ms}$).
13. `GET /api/triage` includes WhatsApp WebRTC `srflx` IP:Port candidate (`185.220.101.42:3478`).
14. `GET /api/triage` includes Section 94 BNSS CGNAT IPDR requisition block.
15. `GET /api/triage` returns rapid UPI smurfing cluster with 4+ mule accounts.
16. `GET /api/triage` includes mirror-hawala currency note serial token (`72B 948102`).
17. `GET /api/graph` returns nodes list with at least 8 multi-modal entities.
18. `GET /api/graph` returns edges list with all directed causal relations.
19. `GET /api/graph` verifies 100% of edges contain physical byte offsets ($\Omega$).
20. `GET /api/graph` returns chronological PCST storyline steps (10+ steps).
21. Storyline step 1 correctly binds fake CBI WhatsApp call to `whatsapp.log` offset.
22. Storyline step 2 correctly binds Chrome spawning PowerShell to Sysmon EVTX offset.
23. Storyline step 3 correctly binds Trojan creation to disk image `$MFT` offset.
24. Storyline step 4 correctly binds C2 socket connection to PCAP packet offset.
25. Storyline step 5 correctly binds victim funds transfer to bank statement offset.
26. Storyline step 6 correctly binds hub smurfing to NPCI switch log offset.
27. `GET /api/exculpatory` returns 14 evaluated checklist points.
28. `GET /api/exculpatory` reports trojan defense probability.
29. `GET /download/certificate` returns HTTP 200 with content-type `application/pdf`.
30. Downloaded certificate PDF begins with `%PDF-` and is $> 10\text{ KB}$.
31. `GET /download/str_xml` returns HTTP 200 with valid `<FINnet2_STR>` root element.
32. `GET /download/freeze_notice` returns HTTP 200 with Section 106 BNSS freeze order.
33. `GET /api/qr` returns valid PNG image of the verification QR code.
34. Zero occurrences of repealed Section 65B of Indian Evidence Act across all HTML/JSON outputs.
35. `POST /api/run` successfully re-executes the pipeline and returns updated status.

---

## 6. CODING GUIDELINES & CONSTRAINTS

- **Zero External UI Build Steps:** Everything must be self-contained in Python and HTML/CSS/JS. Do NOT mandate Webpack, React, NPM, or Node.js.
- **Modern Responsive Cyber Design:** Use a clean, dark navy palette (`#060D1A`, `#0E2247`, `#00A6FB`, `#10B981`, `#EF4444`) with high legibility, crisp borders, and clean typography.
- **Fast Startup:** Headless self-test should finish in under 5 seconds.
