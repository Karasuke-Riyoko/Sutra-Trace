# SECTOR D: STATUTORY COMPLIANCE & BSA 2023 SECTION 63 CERTIFICATE GENERATOR
## Definitive Engineering Specification & Implementation Manual for Claude
### Project: SUTRA-Trace (Autonomous Neuro-Symbolic Digital Forensics Framework)
**Standard:** Bharatiya Sakshya Adhiniyam (BSA), 2023 · Section 63(4)(c) & The Schedule · Section 39(1) & 39(2) · Section 57 Expl. 5 · Section 105 & 106 BNSS 2023 · PMLA 2002 · FIU-IND FINnet 2.0 · ISO 19005-1 PDF/A-1b  
**Target Architecture:** Python 3.10+ · Standard Library + ReportLab + qrcode · Pure Python Fallback for Zero-Crash Execution  
**Target Module:** `prototype/sector_d_legal.py` (and synchronized with root `sector_d_legal.py`)

---

## 1. PURPOSE & STATUTORY ARCHITECTURE

Sector D is the **Legal Bridge & Admissibility Engine** of SUTRA-Trace. In Indian jurisprudence under the **Bharatiya Sakshya Adhiniyam (BSA), 2023**, all technical forensic findings—no matter how mathematically sound—are legally inadmissible unless accompanied by a valid, compliant **Section 63 Schedule Certificate**.

### Critical Statutory Mandates:
1. **Total Repeal of Section 65B of Indian Evidence Act (IEA), 1872:**
   - Section 65B IEA was repealed on 1 July 2024.
   - Any certificate citing Section 65B IEA is **defective on its face** in modern Indian courts.
   - All certificates must strictly cite **Section 63 of the Bharatiya Sakshya Adhiniyam, 2023** and conform to **The Schedule to Section 63(4)(c) BSA 2023**.
2. **Mandatory Two-Part Schedule Structure:**
   - Under Section 63(4)(c) BSA 2023, the Schedule mandates two distinct certifications:
     - **PART A:** Signed by the person in lawful control or management of the computer/device or the activities.
     - **PART B:** Signed by the Examiner of Electronic Evidence (notified u/s 79A IT Act 2000 or forensic expert).
3. **The 3-Scenario Custody Bridge:**
   - A major challenge in Indian criminal trials is that the person in lawful control varies drastically based on the origin of the device. Sector D implements a **3-Scenario Statutory Selector**:
     - **Scenario 1: Cooperative Victim / Complainant Device:**
       - Victim/complainant signs Part A as lawful owner/custodian.
       - Forensic examiner signs Part B for the imaging and laboratory analysis.
     - **Scenario 2: Seized Hostile Suspect Rig / Device:**
       - The device is a primary exhibit under **Section 57 Explanation 5 BSA 2023**.
       - Under Article 20(3) of the Constitution of India (*Selvi v. State of Karnataka*, 2010), the suspect cannot be compelled to sign a certificate against themselves.
       - Therefore, the **Investigating Officer (I.O.)** who seized the device under **Section 105 BNSS 2023** signs Part A certifying lawful seizure and custody of the forensic acquisition workstation.
       - The forensic expert signs Part B certifying bit-stream hash parity and non-alteration.
     - **Scenario 3: Intermediary / Bank / Telecom Nodal Officer Summons:**
       - Part A is executed by the Nodal Officer of the Bank or Telecom Service Provider (TSP) pursuant to a **Section 94 BNSS Summons** or Section 69 IT Act.
       - Part B is executed by the technical expert validating the CDR/IPDR/FINnet 2.0 electronic records.
4. **Dual-Track Section 39(1) / 39(2) Selector:**
   - **Track 1 (Sec. 39(1) Direct Record Route):** Direct physical electronic records (e.g. seized physical memory dump or primary drive clone).
   - **Track 2 (Sec. 39(2) Computer Output Route):** Electronic records generated as outputs, logs, or exports during ordinary business activities.
5. **FIU-IND FINnet 2.0 STR XML & PMLA Section 17(1A) Freeze Notices:**
   - Generates schema-compliant `FIU_IND_STR_FINnet2.xml` under PMLA 2002 Rule 8 for reporting rapid multi-tier UPI smurfing and DeFi bridge layering.
   - Generates formal legal freeze notices under **Section 106 BNSS 2023 read with Section 17(1A) PMLA 2002** for immediate service upon beneficiary banks and crypto exchanges.
6. **ISO 19005-1 PDF/A-1b Archival Document Generator:**
   - Emits a court-ready, beautifully typeset 2-page PDF document.
   - Embeds a dynamic QR code containing the cryptographic verification payload for instant smartphone verification by Judicial Magistrates.
   - Embeds the **Section 45 BSA Exculpatory Intrusion Checklist** to defeat the "Trojan Defense".

---

## 2. DATA CONTRACTS & INPUT MANIFESTS

Sector D consumes inputs from all upstream sectors:
1. `evidence_manifest.json` (from Sector A):
   - `evidence_id`, `case_reference`, `examiner_id`, `ingestion_workstation`, `ingestion_timestamp_utc`
   - `cryptographic_hashes`: `sha256_primary`, `blake2b_secondary`, `merkle_root`, `bnss_105_seizure_video_sha256`, `final_bound_evidence_root`
   - `rfc3161_timestamp_token`
   - `sec_106_malkhana_seal_ledger`: field seal barcode, Malkhana register receipt, lab unseal verification
2. `triage_manifest.json` (from Sector B):
   - `summary_metrics`: `total_leads_flagged`, `exculpatory_checks_evaluated`, `trojan_defense_probability`
   - `symbolic_anchors`: list of leads with physical byte offsets and SHA-256 digests
3. `incident_storyline.json` (from Sector C):
   - `case_id`, `steps`: ordered sequence of incident actions with timestamps, source, action, target, and physical byte-offset anchors.

---

## 3. DETAILED IMPLEMENTATION SPECIFICATIONS

### 3.1 Class Architecture & Module Structure
The module `prototype/sector_d_legal.py` must define:
1. `class ScenarioType(Enum)`: `VICTIM_COOPERATIVE`, `SUSPECT_HOSTILE`, `INTERMEDIARY_NODAL`
2. `class TrackType(Enum)`: `TRACK_39_1_DIRECT`, `TRACK_39_2_OUTPUT`
3. `class BSACertificateGenerator`:
   - `__init__(evidence_manifest, triage_manifest=None, storyline=None, scenario=ScenarioType.SUSPECT_HOSTILE, track=TrackType.TRACK_39_2_OUTPUT)`
   - `generate_qr_payload() -> Dict[str, Any]`
   - `generate_qr_code_image(output_path="cert_qr.png") -> str`
   - `generate_fiu_ind_str_xml(cluster_data=None) -> str`
   - `generate_sec_106_bnss_freeze_notice(cluster_data=None) -> Dict[str, Any]`
   - `build_certificate_pdf(output_pdf="BSA_2023_Sec63_Certificate.pdf") -> str`
   - `export_legal_bundle(output_dir="legal_package") -> Dict[str, str]`

### 3.2 Dynamic QR-Code Payload Specification
The embedded QR code allows magistrates and judges to verify evidence authenticity instantly on their smartphones without forensic software.
The QR payload must be a compact JSON string:
```json
{
  "statute": "BSA 2023 Sec 63(4)(c)",
  "case": "FIR-042/2026-CYBER",
  "evidence_id": "8941a8e2-c019-4821-b1e9-4089a8109bf2",
  "sha256": "e888906d5a6a4bbacb9bd1633bd3be38bacbddda57f549589674b272ef8b6f6f",
  "merkle_root": "9488166b82431611b653ee073646ae39f7c19600c66df9521a4e5407d0d04133",
  "bound_root": "07552db41f2454d28eb0427d8b52eb544523d29894265edf0ce3f05463131875",
  "ts": "2026-10-20T14:30:00.000Z",
  "examiner": "EX-79A-NFSU"
}
```

### 3.3 Visual Layout & Formatting Rules for PDF Generation
The PDF generator must follow these formatting standards:
- **Geometry:** A4 page size (`595.27 x 841.89` points).
- **Margins:** 36pt outer margin, 40pt inner bounding box with double-frame borders.
- **Palette:**
  - Primary Navy: `#0E2247`
  - Dark Slate Text: `#1E293B`
  - Muted Slate: `#64748B`
  - Accent Cyan: `#00A6FB`
  - Border Gray: `#CBD5E1`
  - Light Background: `#F8FAFC`
  - Alert Emerald: `#065F46`
  - Alert Red: `#991B1B`
- **Page 1: PART A — CERTIFICATE BY PERSON IN LAWFUL CONTROL / CUSTODIAN**
  - Header: Court title, statute citation ("THE SCHEDULE — PART A").
  - Section 1: Identifying particulars of electronic record, device serial/IMEI, operating environment, seizure memo reference under Section 105 BNSS.
  - Section 2: Statutory declarations under Section 63(2) & 63(3) BSA 2023 adapted dynamically to the selected scenario:
    - If `SUSPECT_HOSTILE`: Cites Section 57 Expl. 5 BSA, Section 105 BNSS, and certifies custody of the acquisition hardware by the I.O.
    - If `VICTIM_COOPERATIVE`: Certifies personal ownership and lawful use of the computer/phone.
    - If `INTERMEDIARY_NODAL`: Certifies server logs kept in regular course of business under Section 94 BNSS summons.
  - Section 3: QR Code in top right with "Scan for Merkle Proof".
  - Signature block: Custodian name, designation, badge number, police station, date/timestamp.
- **Page 2: PART B — CERTIFICATE BY AUTHORIZED FORENSIC EXPERT**
  - Header: Court title, statute citation ("THE SCHEDULE — PART B").
  - Section 1: Laboratory accreditation, Examiner designation u/s 79A IT Act, ISO/IEC 27037 compliance.
  - Section 2: Mandatory Statutory Hash Integrity & Merkle Notarization Table:
    - Algorithm, Acquisition Hash Digest, Verification Status.
    - Includes SHA-256, BLAKE2b/BLAKE3, Merkle Root, BNSS 105 A/V Seizure Hash, and Master Bound Evidence Root.
  - Section 3: Section 45 BSA Exculpatory Intrusion Checklist Summary (14 points evaluated, trojan defense probability).
  - Section 4: Expert opinion & solemn certification under Section 63(4) BSA 2023.
  - Signature block: Forensic expert name, qualification, notification u/s 79A IT Act, laboratory name, RFC 3161 timestamp token.

### 3.4 FIU-IND FINnet 2.0 STR XML Specification
The module must generate a valid XML file conforming to FIU-IND FINnet 2.0 requirements:
- Root element: `<FINnet2_STR xmlns="http://fiuindia.gov.in/schema/str">`
- Header: `ReportType`, `ReportingEntity`, `TimestampUTC`, `CaseReference`.
- Suspicious Transaction Details: `HubVPA`, `TotalAmountINR`, `MuleAccounts`, `RetrievalReferenceNumbers`, `GroundsForSuspicion`.
- Ready for automated submission to FIU-IND.

### 3.5 Section 106 BNSS / Section 17(1A) PMLA Freeze Notice
The module must output a structured dictionary and plain-text notice for serving on banks:
- Statutory citation: Section 106 BNSS 2023 read with Section 17(1A) PMLA 2002.
- Directs immediate 100% lien attachment on beneficiary VPAs/accounts.
- Lists all flagged mule VPAs, amounts, NPCI RRNs, and FIR reference.

---

## 4. MINIMUM 35 DETERMINISTIC SELF-TEST SPECIFICATIONS

When executed directly (`python prototype/sector_d_legal.py`), the module must execute at least 35 deterministic unit test assertions covering:
1. Default manifest loading and fallback handling.
2. QR payload generation contains all mandatory statutory keys (`statute`, `case`, `sha256`, `merkle_root`).
3. QR code image generation creates valid PNG file with correct dimensions.
4. Scenario 1 (Victim Cooperative): Part A text cites personal lawful custody.
5. Scenario 2 (Hostile Suspect): Part A text cites Section 57 Expl. 5 BSA and Section 105 BNSS without compelling suspect.
6. Scenario 3 (Intermediary Nodal): Part A text cites Section 94 BNSS summons and ordinary business server logs.
7. Track 1 (Sec. 39(1)): Correctly selects documentary primary record certification.
8. Track 2 (Sec. 39(2)): Correctly selects computer output regular operation certification.
9. Hash Integrity Table: Verifies SHA-256 match and displays status.
10. Hash Integrity Table: Verifies BLAKE2b/BLAKE3 match.
11. Hash Integrity Table: Verifies Merkle Root match.
12. Hash Integrity Table: Verifies Section 105 BNSS seizure video hash.
13. Hash Integrity Table: Verifies Final Bound Evidence Root.
14. Section 45 BSA Exculpatory summary: 14 points evaluated and embedded in Part B.
15. Section 45 BSA: Trojan defense probability displayed accurately.
16. Section 106 BNSS freeze notice: generated with target hub VPA and mule list.
17. Section 106 BNSS freeze notice: includes Section 17(1A) PMLA reference.
18. FIU-IND FINnet 2.0 STR XML: well-formed XML with `<FINnet2_STR>` root.
19. FIU-IND STR XML: contains all flagged NPCI RRN tags.
20. FIU-IND STR XML: contains all flagged mule account tags.
21. ReportLab canvas creates valid 2-page PDF document.
22. Generated PDF file size is greater than 10 KB and starts with `%PDF-`.
23. Generated PDF contains Part A on Page 1 and Part B on Page 2.
24. Part A signature block contains custodian name and police station.
25. Part B signature block contains Section 79A IT Act accreditation.
26. Part B signature block contains RFC 3161 cryptographic timestamp token.
27. Dynamic QR code image is correctly embedded into PDF without file leakage.
28. Ingestion of real Sector A manifest: hashes mapped accurately into legal certificate.
29. Ingestion of real Sector B manifest: summary metrics and leads mapped accurately.
30. Ingestion of real Sector C storyline: incident steps formatted cleanly into legal annexure.
31. Bad sector handling: if Sector A reports bad sectors, certificate attaches Bad Sector Manifest note.
32. Legal package export: creates directory with PDF certificate, STR XML, freeze notice JSON, and QR image.
33. Pure Python fallback: operates cleanly even if optional external libraries are missing.
34. Strict statutory citations: 0 occurrences of repealed Section 65B of Indian Evidence Act.
35. Full end-to-end legal bundle generation completed in under 2 seconds.

---

## 5. CODING GUIDELINES & CONSTRAINTS

- **Strict Adherence to Section 63 BSA 2023:** Under no circumstances write "Section 65B" or "Indian Evidence Act 1872".
- **Zero OOM / Pure Python Resilience:** Standard Library (`json`, `os`, `sys`, `re`, `datetime`, `xml.etree.ElementTree`) + `reportlab` + `qrcode`.
- **Courtroom Quality Layout:** Ensure text never collides with frames, fonts are crisp, and tables are perfectly aligned.
