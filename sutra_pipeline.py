"""
SUTRA-TRACE UNIFIED FORENSIC PIPELINE ENGINE (sutra_pipeline.py)
Autonomous Neuro-Symbolic Digital Forensics Framework
Flagship Challenge: PS-01 · SUTRAM 2026 National Hackathon
Organized by IGDTUW, MeitY ISEA Phase-III, and NFSU Gandhinagar

Orchestrates:
- Sector A: Deterministic Evidence Vault & Merkle-DAG Ingestion (ISO/IEC 27037:2012)
- Sector B: Multi-Modal Neural Triage Matrix (LOLBins, Deepfake, UPI Smurfing, APK Trojans)
- Sector C: Temporal Provenance Knowledge Graph (T-PKG) with Byte-Offset Provenance
- Sector D: Court-Admissible BSA 2023 Section 63 Schedule Certificate (Part A & B)
"""

from __future__ import annotations

import os
import sys
import json
import time
from typing import Dict, Any, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
PROTOTYPE_DIR = os.path.join(HERE, "prototype")
if PROTOTYPE_DIR not in sys.path:
    sys.path.insert(0, PROTOTYPE_DIR)

import sector_a_vault as sa
import sector_b_triage as sb
import sector_c_graph as sc
import sector_d_legal as sd


class SutraTracePipeline:
    def __init__(self, case_id: str = "FIR-042/2026-CYBER", examiner_id: str = "EX-79A-NFSU", workdir: Optional[str] = None):
        self.case_id = case_id
        self.examiner_id = examiner_id
        self.workdir = workdir or os.path.join(HERE, "sutra_out")
        os.makedirs(self.workdir, exist_ok=True)
        
        self.image_path = os.path.join(self.workdir, "case_bundle.img")
        self.video_path = os.path.join(self.workdir, "seizure_recording_sec105.mp4")
        self.layout: Dict[str, Any] = {}
        
        self.a_manifest_path: Optional[str] = None
        self.b_manifest_path: Optional[str] = None
        self.c_storyline_path: Optional[str] = None
        self.c_graph_path: Optional[str] = None
        self.legal_bundle_dir: Optional[str] = None

    def execute_stage_1_vault(self) -> Dict[str, Any]:
        """Sector A: Ingests raw evidence image, verifies Sec 105 video continuity and creates Merkle-DAG."""
        out_dir = os.path.join(self.workdir, "sector_a")
        os.makedirs(out_dir, exist_ok=True)
        
        # Build synthetic multi-modal forensic bundle
        bundle = sb._build_case_bundle()
        self.layout, blob = {}, bytearray()
        for name, data in bundle.items():
            pos = (len(blob) + 4095) // 4096 * 4096
            blob.extend(bytes(pos - len(blob)))
            self.layout[name] = (pos, len(data))
            blob.extend(data)
        blob.extend(bytes((-len(blob)) % 4096))
        
        with open(self.image_path, "wb") as f:
            f.write(blob)
            
        sa._write_synthetic_mp4(self.video_path)
        
        vault = sa.SutraEvidenceVault(
            case_id=self.case_id,
            output_dir=out_dir,
            hardware_telemetry={
                "make_model": "Android handset (Operation Maya Seized Device)",
                "serial_number": "R58N91XXXXX",
                "firmware_rev": "UP1A.231005"
            }
        )
        vault.set_custody_seals(
            field_seal_barcode="OPT-PUF-7Q2X-91A0",
            field_seal_rssi_dbm=-112,
            malkhana_receipt="MK-CY-2026/089",
            malkhana_timestamp_utc="2026-10-18T09:30:00.000Z",
            lab_unseal_barcode="OPT-PUF-7Q2X-91A0"
        )
        
        manifest = vault.ingest_evidence(self.image_path, seizure_video_path=self.video_path)
        self.a_manifest_path = os.path.join(out_dir, sa.MANIFEST_FILENAME)
        return manifest

    def execute_stage_2_triage(self) -> Dict[str, Any]:
        """Sector B: Multi-Modal Neural Triage Matrix scanning logs, media, UPI flows, and APKs."""
        if not self.a_manifest_path or not os.path.exists(self.a_manifest_path):
            raise RuntimeError("Stage 1 (Vault) must be executed before Stage 2.")
            
        orch = sb.SutraNeuralTriageOrchestrator(
            case_id=self.case_id,
            output_dir=self.workdir,
            device_owner="rahul"
        )
        orch.bind_sector_a_manifest(self.a_manifest_path)
        
        kinds = {
            "events": ("process_events_jsonl", "SYSMON_EVENT_LOG_JSONL"),
            "whatsapp": ("whatsapp_log", "ANDROID_WHATSAPP_LOG"),
            "rppg": ("rppg_trace", "VIDEO_CALL_ROI_TRACE"),
            "registry": ("registry_export", "WINDOWS_REGISTRY_EXPORT"),
            "anydesk": ("anydesk_trace", "ANYDESK_CONNECTION_TRACE"),
            "upi": ("upi_csv", "UPI_TRANSACTION_EXPORT"),
            "chain": ("chain_csv", "BLOCKCHAIN_TRANSFER_EXPORT"),
            "chat": ("chat_transcript", "CHAT_TRANSCRIPT_TEXT"),
            "bugreport": ("bugreport", "ANDROID_BUGREPORT"),
            "apk": ("apk", "ANDROID_APK_FILE")
        }
        for name, (kind, stype) in kinds.items():
            if name in self.layout:
                off, ln = self.layout[name]
                orch.add_artifact(
                    name, kind, stype,
                    path=self.image_path,
                    base_offset=off,
                    length=ln,
                    extent=True,
                    display_path="case_bundle.img"
                )
                
        orch.run(triage_time_utc="2026-10-20T14:30:00.000Z")
        self.b_manifest_path = os.path.join(self.workdir, sb.MANIFEST_FILENAME)
        
        with open(self.b_manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def execute_stage_3_graph(self) -> Dict[str, Any]:
        """Sector C: Builds CSR Graph Arena, detects timestomps, and extracts prize-collecting storyline."""
        if not self.b_manifest_path or not os.path.exists(self.b_manifest_path):
            raise RuntimeError("Stage 2 (Triage) must be executed before Stage 3.")
            
        out_dir = os.path.join(self.workdir, "sector_c")
        os.makedirs(out_dir, exist_ok=True)
        
        sc.build_from_sector_outputs(
            evidence_manifest=self.a_manifest_path,
            triage_manifest=self.b_manifest_path,
            evidence_root=self.workdir,
            output_dir=out_dir,
            case_id=self.case_id,
            generated_utc="2026-10-20T15:00:00.000000000Z"
        )
        
        self.c_graph_path = os.path.join(out_dir, sc.ATTACK_GRAPH_FILENAME)
        self.c_storyline_path = os.path.join(out_dir, sc.STORYLINE_FILENAME)
        
        with open(self.c_storyline_path, "r", encoding="utf-8") as f:
            storyline_data = json.load(f)
        return storyline_data

    def execute_stage_4_legal_cert(self) -> Dict[str, Any]:
        """Sector D: Statutory BSA 2023 Sec 63 PDF/A Certificate, BNSS Sec 106 Freeze Notices & FIU-IND XML."""
        if not self.c_storyline_path or not os.path.exists(self.c_storyline_path):
            raise RuntimeError("Stage 3 (Graph) must be executed before Stage 4.")
            
        self.legal_bundle_dir = os.path.join(self.workdir, "legal_package")
        os.makedirs(self.legal_bundle_dir, exist_ok=True)
        
        custodian = {
            "name": "Inspector A. K. Rathore",
            "relation": "Investigating Officer",
            "address": "Cyber Crime Police Station, Sector 18, Gandhinagar",
            "designation": "Inspector of Police, Investigating Officer",
            "badge": "GJ-CCPS-1127",
            "police_station": "Cyber Crime Police Station, Gandhinagar",
            "organisation": "Gujarat Police",
            "place": "Gandhinagar"
        }
        expert = {
            "name": "Dr. S. Iyer",
            "designation": "Examiner of Electronic Evidence (Sec. 79A IT Act)",
            "organisation": "Central Forensic Science Laboratory (CFSL) / NFSU",
            "accreditation": "NABL ISO/IEC 17025 Accredited Forensic Laboratory",
            "place": "Gandhinagar"
        }
        case_particulars = {
            "court_name": "In the Court of the Chief Judicial Magistrate, Gandhinagar",
            "fir_number": "FIR No. 042/2026",
            "police_station": "Cyber Crime Police Station, Gandhinagar",
            "date": "2026-10-20",
            "victim_name": "Rahul Sharma",
            "suspect_name": "Unknown Syndicate (Operation Maya)"
        }
        
        gen = sd.BSACertificateGenerator(
            scenario=sd.ScenarioType.SUSPECT_HOSTILE,
            track=sd.TrackType.TRACK_39_2_OUTPUT,
            evidence_manifest=self.a_manifest_path,
            triage_manifest=self.b_manifest_path,
            storyline=self.c_storyline_path,
            evidence_path=self.image_path,
            seizure_video_path=self.video_path,
            evidence_root=self.workdir,
            custodian=custodian,
            expert=expert,
            case_particulars=case_particulars,
            generated_utc="2026-10-20T16:00:00.000Z"
        )
        
        bundle = gen.export_legal_bundle(self.legal_bundle_dir)
        return bundle
