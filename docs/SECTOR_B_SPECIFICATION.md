# SECTOR B: MULTI-MODAL FORENSIC NEURAL TRIAGE & TELEMETRY INGESTION
## Definitive Engineering Specification & Implementation Manual for Claude
### Project: SUTRA-Trace (Autonomous Neuro-Symbolic Digital Forensics Framework)
**Standard:** ISO/IEC 27037:2012 · Section 45 & 63 BSA 2023 · Section 94 & 106 BNSS 2023 · PMLA 2002 · I4C CFCFRMS (1930)  
**Target Architecture:** Python 3.11+ · Pure Python Fallback (Zero Heavy Runtime Dependencies) · Bounded Memory Streaming for Commodity 16GB Police Laptops  
**Target Module:** `prototype/sector_b_triage.py` (and synchronized with root `sector_b_triage.py`)

---

## 1. PURPOSE & ARCHITECTURAL SCOPE

Sector B provides **high-velocity, edge-optimized multi-modal neural triage** across the primary cybercrime threat vectors prioritized by the **Indian Cyber Crime Coordination Centre (I4C)** and the Ministry of Home Affairs (MHA):
1. **"Digital Arrest" Extortion & Deepfake Coercion** (Impersonation of CBI, ED, State Police, Customs).
2. **Multi-Tier UPI Smurfing, Cross-Chain DeFi Bridges & Mirror-Hawala Cash Drops** (Rapid fund dispersal).
3. **Living-Off-The-Land Binaries (LOLBins) & Stealth Attack Commands** (Memory-only, scriptlet, and certutil evasion).
4. **Sideloaded Malicious Android APK Trojans** (CraxsRAT, SpyMax, Goldoson abusing Accessibility & Notification Listeners).

### The Neuro-Symbolic Court Admissibility Rule
In Indian courts under the **Bharatiya Sakshya Adhiniyam (BSA), 2023**, pure probabilistic AI outputs (e.g., *"Model X predicted 94% probability of malware"*) are inadmissible as conclusive proof under defense cross-examination.
Therefore, Sector B enforces the **Neuro-Symbolic Admissibility Doctrine**:
- Neural / heuristic models act strictly as **High-Recall Triage Pre-Filters** ($> 99.0\%$ Recall) to isolate suspicious artifacts from terabytes of disk/memory telemetry in seconds.
- Every flagged lead **MUST** output a deterministic **Symbolic Cryptographic Anchor**:
  $$\mathcal{P}_{\text{sym}} = \left\langle \text{Source\_Type}, \text{Artifact\_ID}, \text{Byte\_Offset } \Omega, \text{Length } L, \text{Digest } H_{\text{chunk}} \right\rangle$$
  allowing downstream Sector C (Temporal Provenance Graph) and Sector D (Section 63 BSA Certificate) to back-bind the lead directly to raw physical disk sectors, SQLite WAL frames, or PCAP packets without relying on AI black-box weights.

---

## 2. SUB-ENGINE 1: LOG & COMMAND TRIAGE (`LogTriageEngine`)

### 2.1 Threat Scope & Mechanics
Detects stealth execution, living-off-the-land binaries (LOLBins), in-memory scriptlets, obfuscated commands, and anomalous parent-child process relationships across Windows Event Logs (Security 4688, Sysmon 1/3/7/11/13/22), Linux auditd/bash history, and terminal logs.

### 2.2 Algorithmic Specifications
1. **LOLBins Signature & Evasion Rulebase:**
   - Detects abuse of dual-use system binaries:
     - `powershell.exe` / `pwsh.exe`: `-enc`, `-encodedcommand`, `downloadstring`, `invoke-expression`, `iex`, `bypass`, `hidden`, `net.webclient`, `system.reflection.assembly`.
     - `certutil.exe`: `-urlcache`, `-split`, `-f`, `-decode`, `-decodehex`.
     - `mshta.exe`: `javascript:`, `vbscript:`, `about:`, `http://`, `https://`.
     - `bitsadmin.exe`: `/transfer`, `/download`, `/priority foreground`.
     - `vssadmin.exe` / `wmic.exe`: `delete shadows`, `shadowcopy delete`, `resize shadowstorage`.
     - `rundll32.exe` / `regsvr32.exe`: `/i:http`, `scrobj.dll`, `javascript:`, `shell32.dll`.
     - `schtasks.exe` / `at.exe`: `/create /tn`, `/sc onlogon`, `/ru system`.
     - `curl.exe` / `wget.exe` / `certreq.exe`: Remote binary download triggers.
2. **Multi-Stage Deobfuscation & Entropy Analysis:**
   - **Base64 Deobfuscation:** Detects and decodes Base64 payloads (both ASCII and UTF-16LE / Unicode commonly used in PowerShell `-enc`).
   - **String Flattening:** Resolves string concatenations (e.g. `'down'+'load'+'string' -> 'downloadstring'`).
   - **Shannon Entropy Calculation:**
     $$H(S) = -\sum_{i=1}^{k} p(c_i) \log_2 p(c_i)$$
     Payloads with $H(S) \ge 4.8$ and length $> 40$ are flagged for high-entropy packing/encryption (`SUSPICIOUS_HIGH_ENTROPY_PACKING`).
3. **Parent-Child Process Lineage Anomaly Matrix:**
   - Flags untrusted parents spawning interactive shells or LOLBins:
     - Office apps (`winword.exe`, `excel.exe`, `powerpnt.exe`) spawning `cmd.exe`, `powershell.exe`, `wscript.exe`.
     - Browsers (`chrome.exe`, `msedge.exe`, `firefox.exe`) spawning CLI tools.
     - Web servers (`w3wp.exe`, `httpd.exe`, `nginx.exe`) spawning shells (Web Shell indicator).
     - Remote tools (`anydesk.exe`, `teamviewer.exe`, `rustdesk.exe`) spawning administrative consoles.
4. **Section 45 BSA Exculpatory Intrusion Checklist Filter:**
   - Evaluates a 14-point checklist to counter the "Trojan Defense" (where suspects claim unauthorized remote access caused the actions). Flags whether commands were run in an interactive desktop session (`LogonType = 2`), network session (`LogonType = 3`), or batch/service (`LogonType = 4/5`), checking for concurrent AnyDesk/RDP traces in the prior 24-hour window.
5. **MITRE ATT&CK Technique Mapping:**
   - Automatically maps flagged events to MITRE techniques: `T1059.001` (PowerShell), `T1105` (Ingress Tool Transfer), `T1218.005` (Mshta), `T1218.011` (Rundll32), `T1490` (Inhibit Recovery), `T1053` (Scheduled Task).

---

## 3. SUB-ENGINE 2: SYNTHETIC MEDIA & DEEPFAKE TRIAGE (`DeepfakeTriageEngine`)

### 3.1 Threat Scope: "Digital Arrest" Extortion Scams
Perpetrators pose as senior law enforcement (CBI, NIA, Mumbai Police, ED) on WhatsApp/Skype/Zoom video calls, using real-time AI face-swapping or full-head latent diffusion to hold victims in fake "custody" and force panic funds transfers.

### 3.2 Physics-Based Hemodynamic & Frequency Specifications
1. **Carotid-to-Supraorbital Pulse Transit Time (PTT) Phase Delay ($\Delta\tau_{\text{PTT}}$):**
   - **Biological Ground Truth:** In an authentic human face, oxygenated blood leaves the carotid artery and reaches the lower perioral/jaw Region-of-Interest (ROI) before traversing facial arterioles to reach the supraorbital/forehead ROI. This introduces a physiological arterial transit delay:
     $$\Delta\tau_{\text{PTT}} \in [12\text{ ms}, 45\text{ ms}] \quad \iff \quad \Delta\phi_{\text{PTT}} \in [0.09\text{ rad}, 0.34\text{ rad}] \text{ at } 1.0 - 1.8\text{ Hz}$$
   - **Synthetic Shader Artifact:** AI face-swap models (DeepFaceLive) and diffusion models (EMO, Hallo, V-Express) apply frame-wide lighting or RGB shifts uniformly across all pixels simultaneously:
     $$\Delta\tau_{\text{PTT}} \approx 0\text{ ms} \quad (\Delta\phi_{\text{PTT}} < 0.04\text{ rad})$$
     When $\Delta\phi_{\text{PTT}} < 0.04\text{ rad}$, the engine immediately flags:
     `SYNTHETIC_RPPG_SHADER_INJECTION` (Confidence: 0.96).
2. **2D-DCT Frequency Decay Anomaly & $\widehat{\text{QP}}$-Gated Compensation:**
   - Natural camera sensors adhere to power-law Fourier spectral decay:
     $$E(f) \propto f^{-\alpha}, \quad \alpha \in [1.5, 2.5]$$
   - Generative upsamplers and neural decoders create checkerboard artifacts and energy spikes in the high-frequency Nyquist zone ($f > 0.75 f_{\text{Nyquist}}$).
   - **$\widehat{\text{QP}}$-Gating:** To prevent false positives from aggressive H.264/H.265 video compression, the engine estimates the macroblock Quantization Parameter $\widehat{\text{QP}}$. If $\widehat{\text{QP}} > 36$, high-frequency thresholds are dynamically relaxed by factor $1 + 0.05(\widehat{\text{QP}} - 36)$.
3. **Windkessel Dicrotic Notch & Multi-Channel $\text{HbO}_2$ Ratios:**
   - Evaluates the second-harmonic energy ratio $E(2f_{\text{HR}})/E(f_{\text{HR}}) \in [0.15, 0.48]$ reflecting the aortic valve dicrotic notch.
   - Evaluates green-to-red chrominance variance ratio $\sigma(\tilde{G})/\sigma(\tilde{R}) \in [1.8, 3.2]$.
4. **Android WhatsApp WebRTC RingRTC & Desktop Artifact Extractor:**
   - **Scenario 1 (Victim Android Smartphone):**
     - Parses `/data/data/com.whatsapp/files/Logs/whatsapp.log` (and `.log.gz` archives) and `msgstore.db` (`call_log` / `call_log_participant_v2`).
     - Extracts WebRTC ICE candidates: STUN/TURN server IPs, Server Reflexive (`srflx`) and Peer Reflexive (`prflx`) IP:Port tuples, session IDs, and codec negotiation strings.
     - **Section 94 BNSS Notice Generation:** Automatically generates a formatted **Section 94 BNSS Telecom CGNAT IPDR Requisition** template targeting the identified `srflx` public IP and UTC timestamp.
   - **Scenario 2 (Seized Scam-Center Desktop Rig):**
     - Checks registry keys for virtual camera injectors:
       `HKLM\SOFTWARE\Classes\CLSID\{860BB310-5D01-11d0-BD3B-00A0C911CE86}\Instance` (OBS VirtualCam, ManyCam, SplitCam, DeepFaceLive).
     - Carves AnyDesk session traces (`%ProgramData%\AnyDesk\connection_trace.txt`) for 9-digit client IDs.

---

## 4. SUB-ENGINE 3: FINANCIAL MULE NETWORK & UPI SMURFING DETECTOR (`FinancialMuleDetector`)

### 4.1 Threat Scope: Multi-Tier Laundering & Cross-Rail Draining
Laundering syndicates drain extorted funds within minutes through multi-tier Indian UPI accounts, convert funds to crypto (USDT) on P2P exchanges, and execute physical cash handovers via mirror-hawala tokens.

### 4.2 Algorithmic & Statutory Specifications
1. **NPCI 12-Digit RRN (Retrieval Reference Number) Primitives:**
   - Syntax validation:
     $$\text{RRN} = \underbrace{Y}_{\text{Last digit of Year}} \; \underbrace{DDD}_{\text{Julian Day (001-366)}} \; \underbrace{HH}_{\text{Hour (00-23)}} \; \underbrace{SSSSSS}_{\text{6-digit STAN}}$$
   - Flags synthetic or malformed RRNs where Julian day $> 366$ or hour $> 23$.
2. **Rapid Fan-Out Mule Smurfing Detection:**
   - **Trigger Conditions:**
     - A large inflow (e.g. $\ge \text{₹}1,00,000$) arrives at a Tier-1 Hub VPA.
     - Within a short temporal window ($\Delta t \le 180\text{ seconds}$), $\ge 3$ outbound transfers occur to distinct Tier-2 VPAs.
     - Dispersion Ratio:
       $$\text{Ratio} = \frac{\sum \text{Amount}_{\text{out}}}{\text{Amount}_{\text{in}}} \in [0.85, 1.05]$$
   - Emits a high-priority alert: `RAPID_FAN_OUT_SMURFING`.
3. **Cross-Chain DeFi Liquidity Bridge Affinity Solver:**
   - Correlates off-chain UPI INR disbursements with on-chain EVM / TRON USDT transfers.
   - Solves the Cross-Rail Affinity:
     $$\mathcal{A}_{\text{bridge}}(e_{\text{UPI}}, e_{\text{chain}}) = \exp\left( -\frac{|t_{\text{chain}} - t_{\text{UPI}}|}{\tau_{\text{escrow}}} \right) \cdot \mathbb{I}\left( \left|\frac{\text{INR}}{\text{USDT}} - R_{\text{USDT/INR}}(1 + \delta_{\text{P2P}})\right| \le \epsilon \right)$$
   - Window: $\tau_{\text{escrow}} = 300\text{ seconds}$; P2P premium spread $\delta_{\text{P2P}} \in [0.015, 0.085]$ (1.5% - 8.5%).
4. **Digital-to-Physical Mirror Hawala Cash-Drop Token Extractor:**
   - Scans text/OCR transcripts for 9-character RBI Indian currency note serial numbers:
     $$\texttt{\^[0-9]\{2\}[A-Z]\textbackslash{}s?[0-9]\{6\}\$}$$
   - Flags currency note serial numbers shared in chat groups as physical handover bearer authentication tokens.
5. **Automated Statutory Freeze & FIU-IND Reporting:**
   - Generates ready-to-serve **Section 106 BNSS / I4C 1930 Helpline Emergency Freeze Notices** containing Bank IFSC, VPA, NPCI RRN, and amount.
   - Generates compliant **FIU-IND FINnet 2.0 Suspicious Transaction Report (STR)** summary blocks.

---

## 5. SUB-ENGINE 4: SIDELOADED ANDROID APK TROJAN TRIAGE (`AndroidTrojanTriageEngine`)

### 5.1 Threat Scope
Fake utility / bank update / challan APKs (CraxsRAT, SpyMax, Goldoson) that steal OTPs, record audio, and draw phishing overlays over banking applications.

### 5.2 Algorithmic Specifications
1. **Tri-Mode Telemetry Ingestion:**
   - **Mode 1 (Rooted Dump):** Parses `/data/system/packages.xml` and `/data/system/users/0/settings_secure.xml`.
   - **Mode 2 (ADB Non-Root Triage):** Parses text outputs of `adb shell dumpsys package`, `adb shell dumpsys usagestats`, and `adb shell settings get secure enabled_accessibility_services`.
   - **Mode 3 (Bugreport Archive):** Ingests and parses `bugreport.txt` or `.zip`.
2. **Dangerous Capability & Permission Scoring:**
   - `BIND_ACCESSIBILITY_SERVICE`: Weight 0.95 (Enables screen scraping, automated clicks, keylogging).
   - `BIND_NOTIFICATION_LISTENER_SERVICE`: Weight 0.90 (Bypasses Android 13/14 restricted SMS permissions to read 2FA OTPs directly from notification shade).
   - `SYSTEM_ALERT_WINDOW`: Weight 0.85 (Enables invisible or deceptive UI overlays).
   - `RECEIVE_BOOT_COMPLETED`, `REQUEST_INSTALL_PACKAGES`, `RECORD_AUDIO`, `READ_CALL_LOG`.
3. **Foreground Overlay Attack Timeline Correlation:**
   - Parses `usagestats` (Event Type 1 = `MOVE_TO_FOREGROUND`).
   - Detects when a suspicious sideloaded package triggers `MOVE_TO_FOREGROUND` within $\Delta t < 500\text{ ms}$ after a legitimate banking application package (`com.sbi.lotusintouch`, `com.snapwork.hdfc`, `net.one97.paytm`, etc.) is opened, establishing automated credential overlay hijacking.
4. **Polyglot & Trailer Slack Analyzer:**
   - Inspects APK files for polyglot headers (e.g. valid JPEG `0xFFD8FF` prepended to a ZIP file) or Dalvik DEX magic (`dex\n035\0`) hidden in file trailer slack space.

---

## 6. MASTER ORCHESTRATOR & DATA CONTRACTS

### 6.1 Class Hierarchy & Module Structure
The module `prototype/sector_b_triage.py` must define:
1. `class LogTriageEngine`
2. `class DeepfakeTriageEngine`
3. `class FinancialMuleDetector`
4. `class AndroidTrojanTriageEngine`
5. `class SutraNeuralTriageOrchestrator` (The unifying pipeline orchestrator)

### 6.2 Canonical Output: `triage_manifest.json` Schema
The orchestrator must output a canonical JSON schema:
```json
{
  "version": "SUTRA-TRIAGE-2026.3-SUPREME",
  "case_id": "FIR-042/2026-CYBER",
  "triage_timestamp_utc": "2026-10-20T14:30:00.000Z",
  "summary_metrics": {
    "total_telemetry_events_scanned": 10542,
    "high_priority_leads_flagged": 4,
    "exculpatory_checks_evaluated": 14,
    "trojan_defense_probability": 0.02
  },
  "symbolic_anchors": [
    {
      "lead_id": "LEAD-B-LOG-001",
      "threat_category": "LOLBINS_COMMAND",
      "severity": "CRITICAL",
      "threat_score": 0.94,
      "mitre_technique": "T1105 - Ingress Tool Transfer",
      "symbolic_anchor": {
        "source_type": "NTFS_MFT_FILE",
        "file_path": "C:\\Windows\\System32\\certutil.exe",
        "byte_offset": 4194304,
        "length": 512,
        "sha256": "80750337eda9f70a6bb7fa2c9bd1c3345bbcb24a4e085db2974f66fd69c2b570"
      },
      "lead_details": { ... }
    },
    {
      "lead_id": "LEAD-B-MEDIA-002",
      "threat_category": "DIGITAL_ARREST_DEEPFAKE",
      "severity": "CRITICAL",
      "threat_score": 0.96,
      "symbolic_anchor": {
        "source_type": "VIDEO_CALL_RTP_STREAM",
        "session_id": "wrtc_call_99182",
        "byte_offset": 8388608,
        "length": 65536,
        "sha256": "7d24832b658d8c38a82dd88e02dd168dfdf73a0035a7f2a61ab47c36c42bfb45"
      },
      "lead_details": { ... },
      "statutory_actions": {
        "bnss_sec_94_requisition_ready": true,
        "target_ip": "185.220.101.5",
        "cgnat_port": 3478
      }
    },
    {
      "lead_id": "LEAD-B-FIN-003",
      "threat_category": "RAPID_UPI_SMURFING",
      "severity": "HIGH",
      "threat_score": 0.92,
      "symbolic_anchor": {
        "source_type": "SQLITE_WAL_FRAME",
        "database": "com.phonepe.app/databases/transactions.db",
        "byte_offset": 1048576,
        "length": 4096,
        "sha256": "55d9cae473bfdc3a7c0aff54dad0cd3164b5d978823cc43404cfdfa3936920e8"
      },
      "lead_details": { ... },
      "statutory_actions": {
        "bnss_sec_106_freeze_ready": true,
        "fiu_ind_str_xml_ready": true,
        "flagged_mules": ["mule1@ybl", "mule2@paytm"]
      }
    }
  ]
}
```

---

## 7. SELF-TEST SUITE SPECIFICATIONS (MINIMUM 35 ASSERTIONS)

When `sector_b_triage.py` is executed directly via `python prototype/sector_b_triage.py`, it must run a built-in test suite covering at least 35 deterministic assertions:
1. `certutil -urlcache -split -f` flagged with $Score \ge 0.85$ and MITRE `T1105`.
2. Base64-encoded PowerShell `-enc` is correctly unpacked and deobfuscated.
3. Unicode UTF-16LE Base64 PowerShell payload is decoded and inspected.
4. Shannon entropy calculation correctly detects high-entropy packed string ($H \ge 4.8$).
5. String concatenation `'down'+'load'` is flattened before signature checking.
6. Suspicious parent-child: `winword.exe` spawning `powershell.exe` adds penalty $\ge 0.20$.
7. Suspicious parent-child: `chrome.exe` spawning `cmd.exe` is flagged.
8. Benign command: `explorer.exe` running clean path gets $Score < 0.30$.
9. Section 45 BSA Exculpatory checklist: confirms interactive vs service logon detection.
10. Authentic human face: physiological PTT phase lag ($\Delta\phi_{\text{PTT}} \in [0.09, 0.34]\text{ rad}$) verified as authentic.
11. Synthetic deepfake: global shader injection ($\Delta\phi_{\text{PTT}} < 0.04\text{ rad}$) flagged as `SYNTHETIC_RPPG_SHADER_INJECTION`.
12. 2D-DCT spectral energy: detects Nyquist boundary checkerboard spikes in synthetic image.
13. $\widehat{\text{QP}}$-gated quantization compensation: high QP video relaxes threshold correctly.
14. Aortic valve dicrotic notch 2nd-harmonic ratio evaluated within $[0.15, 0.48]$.
15. Android WhatsApp `whatsapp.log`: correctly extracts STUN/TURN and `srflx` IP:Port tuple.
16. Section 94 BNSS IPDR Requisition template generated with extracted `srflx` IP and UTC timestamp.
17. Seized rig virtual camera detection: flags OBS VirtualCam / ManyCam registry keys.
18. AnyDesk trace log parsing: extracts 9-digit client ID and session direction.
19. Valid NPCI RRN syntax: `[YDDD+HH+STAN]` format verified (Julian day 1..366, Hour 0..23).
20. Synthetic/corrupt NPCI RRN (Julian day = 400 or Hour = 25) rejected as invalid.
21. Rapid UPI smurfing: 1 inflow followed by 4 outflows in 80s ($Ratio \approx 0.98$) flagged.
22. Smurfing time threshold: outflows after 300s are NOT grouped into the 180s smurfing cluster.
23. Smurfing dispersion ratio: outflows totaling only 20% of inflow do not trigger fan-out smurfing.
24. Mirror-Hawala token: extracts 9-character RBI currency note serial numbers (`[0-9]{2}[A-Z]\s?[0-9]{6}`).
25. Hawala regex rejects invalid currency notes (wrong character count or structure).
26. Cross-Chain DeFi bridge matching: matches UPI RRN to on-chain USDT within 300s and P2P premium window.
27. Cross-Chain bridge matching: rejects match if time delta exceeds $\tau_{\text{escrow}}$ (e.g. 600s).
28. Section 106 BNSS / 1930 Helpline freeze notice data block generated with all required fields.
29. FIU-IND FINnet 2.0 STR XML summary block generated with valid tags.
30. Android APK triage: flags package declaring `BIND_ACCESSIBILITY_SERVICE`.
31. Android APK triage: flags package declaring `BIND_NOTIFICATION_LISTENER_SERVICE`.
32. Foreground overlay attack: flags rogue app `MOVE_TO_FOREGROUND` 200 ms after banking app launch.
33. Polyglot APK: detects JPEG `FF D8 FF` prepended to ZIP/APK file.
34. Symbolic Cryptographic Anchor ($\mathcal{P}_{\text{sym}}$) generated for every flagged lead with byte offset and digest.
35. Full Orchestrator end-to-end run: emits valid canonical `triage_manifest.json` conforming to schema.

---

## 8. CODING GUIDELINES & CONSTRAINTS

- **No Crash on Missing Dependencies:** Do NOT mandate external native packages. Use standard library modules (`math`, `re`, `json`, `hashlib`, `struct`, `datetime`, `collections`, `urllib.parse`, `base64`). If `numpy`, `scipy`, or `onnxruntime` are available, use them optionally; otherwise, use pure-Python mathematical routines.
- **Strict Adherence to Section 63 BSA & BNSS:** Never mention Section 65B of the repealed Indian Evidence Act. Reference Section 63 BSA 2023, Section 94 BNSS 2023, Section 105 BNSS 2023, and Section 106 BNSS 2023.
- **Deterministic Offsets:** Whenever generating synthetic or simulated evidence, always provide mock raw byte offsets and lengths so that downstream Sector C and D can seamlessly consume them.
