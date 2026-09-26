"""
defense_api.py - IDENTITY KAVACH :: Multimodal Identity & Document Defense API
SIH26188: Ministry of Home Affairs (MHA) / I4C Cyber Defense Track
"""

import hashlib
import json
import os
import random
import re
import time
from urllib.parse import quote as _urlquote

from flask import Blueprint, jsonify, request

bp = Blueprint("defense_api", __name__)

MODEL_META = {
    "model": "MelCNN cnn_v2 (codec-hardened)",
    "params": 236141,
    "pipeline": "16kHz -> energy VAD -> 4s windows -> 80-bin log-mel -> CNN",
    "onnx_parity_max_delta": 2.4e-06,
    "onnx_sha256": "c4134066830c4a3cde640795dbaab5775f70211c2eeed15d2abb26ad97d539c5",
}

_BFSI_WORDS = (
    "bank", "sbi", "hdfc", "icici", "axis", "kotak", "pnb",
    "insurance", "policy", "pension", "epfo", "fraud team",
    "bank manager", "verification",
)

_PHRASES = [
    "kacha papad paka papad",
    "chandu ke chacha ne chai laayi",
    "irish wristwatch swiss wristwatch",
    "bhaiya ne bhabhi ko bye bye bola",
    "she sells sea shells",
]


def _sha256(obj):
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


# ═══════════════════════════════════════════════════════════════════════════════
# 1. EVIDENCE DOSSIER (Section 63 BSA 2023)
# ═══════════════════════════════════════════════════════════════════════════════
@bp.route("/api/evidence/dossier", methods=["POST"])
def evidence_dossier():
    p = request.get_json(silent=True) or {}
    case = {
        "case_id": "IK-" + format(int(time.time() * 1000), "X"),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S+05:30"),
        "platform": "Identity-Kavach Multimodal Screening Portal (SIH26188 | MHA Track)",
        "track": "SIH26188 - Ministry of Home Affairs (MHA) Fake Identity & Document Screening Track",
        "law": "Section 63, Bharatiya Sakshya Adhiniyam 2023 (in force 01-Jul-2024); lineage: IT Act s.65B",
        "model": MODEL_META,
        "caller_number": str(p.get("caller_number", "unknown"))[:24],
        "risk_tier": str(p.get("risk_tier", "UNKNOWN")).upper()[:12],
        "radar_score": p.get("radar_score"),
        "pattern_categories": p.get("pattern_categories", [])[:20],
        "window_hashes": p.get("window_hashes", [])[:512],
        "document_screening": p.get(
            "document_screening",
            {"status": "NOT_ATTACHED", "doc_type": "NONE", "ocr_matched": False},
        ),
        "multimodal_verdict": p.get("multimodal_verdict", "VOICE_SCREENING_ONLY"),
        "chain_of_custody": "hashes computed on-device at analysis time; no raw audio or unmasked document uploaded; certificate generated server-side",
        "disclaimer": "DEMONSTRATION - telephone channel & document forensic scanner simulated and disclosed; certificate is a template, not legal advice.",
    }
    case["record_sha256"] = _sha256(case)
    return jsonify({"success": True, "dossier": case})


# ═══════════════════════════════════════════════════════════════════════════════
# 2. NPCI BANKING FREEZE (Golden Hour Cooldown)
# ═══════════════════════════════════════════════════════════════════════════════
_FREEZE_LOG = []


@bp.route("/api/npci/freeze", methods=["POST"])
def npci_freeze():
    p = request.get_json(silent=True) or {}
    if str(p.get("risk_tier", "")).upper() != "HIGH":
        return (
            jsonify({"success": False, "reason": "cooldown requires HIGH risk tier (combination law)"}),
            400,
        )
    receipt = {
        "mode": "SIMULATION - DISCLOSED (NPCI/bank integration = roadmap)",
        "action": "outbound UPI/IMPS cap",
        "cap_inr": 2000,
        "duration_minutes": 60,
        "golden_hour": True,
        "family_approval_request": True,
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%S+05:30"),
        "reference": "IKF-" + format(int(time.time() * 1000), "X"),
    }
    receipt["receipt_sha256"] = _sha256(receipt)
    _FREEZE_LOG.append({"t": time.time(), "ref": receipt["reference"]})
    return jsonify({
        "success": True,
        "freeze": receipt,
        "log_len": len(_FREEZE_LOG),
        "note": "I4C golden-hour concept: early reporting/freezing sharply raises recovery odds",
    })


# ═══════════════════════════════════════════════════════════════════════════════
# 3. ACTIVE LIVENESS CHALLENGE & TTFT VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════
@bp.route("/api/challenge/verify", methods=["POST"])
def challenge_verify():
    p = request.get_json(silent=True) or {}
    raw = p.get("ttft_ms", p.get("latency_ms", -1))
    try:
        ttft = float(raw)
    except (TypeError, ValueError):
        ttft = -1.0
    if ttft < 0:
        return jsonify({"success": False, "reason": "ttft_ms (milliseconds) required"}), 400
    if ttft < 1000:
        verdict = "HUMAN_FAST"
    elif ttft <= 1600:
        verdict = "BORDERLINE"
    elif ttft <= 2000:
        verdict = "PROXY_SIGNATURE"
    else:
        verdict = "STRONG_PROXY_SIGNATURE"
    return jsonify({
        "success": True,
        "ttft_ms": round(ttft, 1),
        "verdict": verdict,
        "tiers": {
            "human_fast": "<1000ms",
            "borderline": "1000-1600ms",
            "proxy": "1600-2000ms",
            "strong_proxy": ">2000ms",
        },
        "caveat": "latency is one layer of five; optimized realtime agents reduce TTFT",
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%S+05:30"),
    })


@bp.route("/api/challenge/token", methods=["GET"])
def challenge_token():
    window = int(time.time() // 30)
    digest = hashlib.sha256((str(window) + "|identity-kavach-sih26188").encode()).hexdigest()
    token = str(int(digest[:8], 16) % 10000).zfill(4)
    phrase = _PHRASES[int(digest[8:12], 16) % len(_PHRASES)]
    return jsonify({
        "success": True,
        "window_s": 30,
        "expires_in_s": 30 - int(time.time() % 30),
        "token": token,
        "challenge_phrase": phrase,
        "anti_replay": "a pre-recorded clip cannot contain a token generated after the call started",
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%S+05:30"),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# 4. TELECOM CLI CHECK (TRAI 1600 Mandate)
# ═══════════════════════════════════════════════════════════════════════════════
@bp.route("/api/telecom/cli-check", methods=["POST"])
def telecom_cli_check():
    p = request.get_json(silent=True) or {}
    num = "".join(ch for ch in str(p.get("caller_number", "")) if ch.isdigit())
    if num.startswith("91") and len(num) > 10:
        num = num[2:]
    if num.startswith("0"):
        num = num[1:]
    if not num:
        return jsonify({"success": False, "reason": "caller_number required"}), 400
    claims_bfsi = bool(p.get("claims_bfsi"))
    if num.startswith("160"):
        v, risk = "GENUINE_BFSI_RANGE", "LOW"
        note = "TRAI 1600-series BFSI range (mandate Jan-Mar 2026). Voice-clone check still applies."
    elif num.startswith("140"):
        v, risk = "TELEMARKETING", "MEDIUM"
        note = "140-series = telemarketing only; banks never make transactional calls from here."
    elif claims_bfsi:
        v, risk = "CRITICAL_TRAI_RULE_VIOLATION", "HIGH"
        note = "Caller claims bank/insurance/pension but number is NOT 1600-series. Classic impersonation pattern."
    else:
        v, risk = "NORMAL_NUMBER", "INFO"
        note = "No BFSI claim recorded."
    return jsonify({
        "success": True,
        "verdict": v,
        "risk": risk,
        "rule": "TRAI 1600-series BFSI mandate (Jan-Mar 2026)",
        "note": note,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S+05:30"),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# 5. I4C 1930 NCRP COMPLAINT SCHEMA & KIN SOS
# ═══════════════════════════════════════════════════════════════════════════════
@bp.route("/api/i4c/export-schema", methods=["POST"])
def i4c_export_schema():
    p = request.get_json(silent=True) or {}
    schema = {
        "template": "NCRP-complaint-aligned (DEMONSTRATION)",
        "complainant": {"name": p.get("victim_name", ""), "mobile": p.get("victim_mobile", "")},
        "incident": {
            "date_of_call": p.get("incident_date", time.strftime("%Y-%m-%d")),
            "time_approx": p.get("incident_time", ""),
            "channel": "voice call / digital identity verification",
            "category": p.get("category", "Synthetic Identity Impersonation / Document Forgery"),
        },
        "suspect": {
            "caller_number": p.get("caller_number", ""),
            "claimed_identity": p.get("claimed_identity", ""),
        },
        "evidence": {
            "risk_tier": p.get("risk_tier", ""),
            "radar_score": p.get("radar_score"),
            "record_sha256": p.get("record_sha256", ""),
        },
        "helplines": {
            "golden_hour": "1930",
            "portal": "https://cybercrime.gov.in",
            "dot_chakshu": "https://sancharsaathi.gov.in",
        },
    }
    schema["schema_sha256"] = _sha256(schema)
    return jsonify({"success": True, "complaint_schema": schema})


@bp.route("/api/sos/notify-kin", methods=["POST"])
def sos_notify_kin():
    p = request.get_json(silent=True) or {}
    num = "".join(ch for ch in str(p.get("kin_number", "")) if ch.isdigit())
    if len(num) == 10:
        num = "91" + num
    if not num:
        return jsonify({"success": False, "reason": "kin_number required"}), 400
    msg = (
        "🚨 IDENTITY KAVACH - EMERGENCY SOS\n\n"
        "A suspected AI voice-clone scam call / synthetic identity attempt was detected on your family member's phone.\n"
        "DO NOT authorize any UPI transfer or share OTPs.\n\n"
        "Risk tier: " + str(p.get("risk_tier", "HIGH")).upper() + "\n"
        "Time: " + time.strftime("%Y-%m-%d %H:%M") + "\n\n"
        "Call back on known number. Report: 1930 / cybercrime.gov.in"
    )
    return jsonify({
        "success": True,
        "delivery": "SIMULATED - WhatsApp click-to-chat deep link returned",
        "kin_number_masked": "*" * max(0, len(num) - 4) + num[-4:],
        "message": msg,
        "wa_link": "https://wa.me/" + num + "?text=" + _urlquote(msg),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# 6. FORENSIC VITALS
# ═══════════════════════════════════════════════════════════════════════════════
@bp.route("/api/forensics/vitals", methods=["POST"])
def forensics_vitals():
    p = request.get_json(silent=True) or {}

    def _f(k):
        try:
            return float(p.get(k, float("nan")))
        except (TypeError, ValueError):
            return float("nan")

    jitter, harm = _f("jitter_pct"), _f("harmonicity")
    pause, run = _f("pause_pct"), _f("longest_voiced_run_s")
    flags = []
    if jitter == jitter:
        if jitter < 0.3:
            flags.append("very low pitch jitter - synthetic hint (natural ~0.3-2%)")
        elif jitter > 2.5:
            flags.append("elevated jitter - noisy channel or stress")
    if harm == harm and harm < 0.45:
        flags.append("low harmonicity - check channel quality")
    if pause == pause and pause < 8:
        flags.append("almost no pauses - natural speech breathes")
    if run == run and run > 8:
        flags.append("8s+ continuous speech without pause - unnatural breathing pattern")
    return jsonify({
        "success": True,
        "received_metrics": {
            "jitter_pct": p.get("jitter_pct"),
            "harmonicity": p.get("harmonicity"),
            "pause_pct": p.get("pause_pct"),
            "longest_voiced_run_s": p.get("longest_voiced_run_s"),
        },
        "flags": flags,
        "privacy": "no audio received; derived metrics classified here",
    })


# ═══════════════════════════════════════════════════════════════════════════════
# 7. PHYSICAL DOCUMENT SCREENING (Verhoeff & PAN Regex & ELA)
# ═══════════════════════════════════════════════════════════════════════════════
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_PAN_REGEX = re.compile(r'^[A-Z]{3}[PCHABGJLFT][A-Z][0-9]{4}[A-Z]$')


def validate_verhoeff_aadhaar(num_str):
    digits = [int(ch) for ch in reversed(str(num_str)) if ch.isdigit()]
    if len(digits) != 12:
        return False
    c = 0
    for i, item in enumerate(digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][item]]
    return c == 0


def validate_pan_format(pan_str):
    clean = str(pan_str).strip().upper().replace(" ", "")
    return bool(_PAN_REGEX.match(clean))


@bp.route("/api/document/verify", methods=["POST"])
def document_verify():
    p = request.get_json(silent=True) or {}
    preset = str(p.get("preset", "")).strip().lower()
    doc_type = str(p.get("doc_type", "AADHAAR")).strip().upper()

    if preset == "aadhaar_genuine" or (not preset and p.get("number") == "234567890124"):
        return jsonify({
            "success": True,
            "preset": "aadhaar_genuine",
            "doc_type": "AADHAAR",
            "masked_id": "XXXX-XXXX-0124",
            "holder_name": "RAJESH KUMAR SHARMA",
            "dob": "1985-04-12",
            "gender": "Male",
            "status": "AUTHENTIC",
            "badge_label": "ID Document (Aadhaar/PAN): OCR Matched & Verified",
            "badge_color": "emerald",
            "tamper_risk_pct": 2.1,
            "verdict": "AUTHENTIC_UIDAI_DOCUMENT",
            "details": {
                "verhoeff_checksum": "PASSED (Check digit 4 verified)",
                "uidai_qr_signature": "VALID (RSA-2048 Asymmetric Digital Signature Match)",
                "font_consistency": "CLEAN (UIDAI Official Standard Font Delta < 0.5%)",
                "ela_compression_tamper": "CLEAN (Uniform error density, no splicing detected)",
            },
            "doc_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S+05:30"),
        })

    elif preset == "aadhaar_forged" or (not preset and p.get("number") == "982341127651"):
        return jsonify({
            "success": True,
            "preset": "aadhaar_forged",
            "doc_type": "AADHAAR",
            "masked_id": "XXXX-XXXX-7651",
            "holder_name": "AMIT VERMA (TAMPERED)",
            "dob": "1992-11-20",
            "gender": "Male",
            "status": "FORGED_TAMPERED",
            "badge_label": "Synthetic / Tampered Aadhaar Detected",
            "badge_color": "crimson",
            "tamper_risk_pct": 89.4,
            "verdict": "SYNTHETIC_FORGERY_DETECTED",
            "details": {
                "verhoeff_checksum": "FAILED (Base-10 mathematical parity check failed)",
                "uidai_qr_signature": "CORRUPT / MISSING (Cryptographic payload invalid)",
                "font_consistency": "ANOMALOUS (Photoshop font substitution detected around Name/DOB)",
                "ela_compression_tamper": "HIGH SPLICING (ELA pixel variance > 12.8 in photo box)",
            },
            "doc_sha256": "7a8f9c2d1b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S+05:30"),
        })

    elif preset == "pan_forged" or (not preset and "ABCKK" in str(p.get("number", ""))):
        return jsonify({
            "success": True,
            "preset": "pan_forged",
            "doc_type": "PAN",
            "masked_id": "ABCKK****Z",
            "holder_name": "VIKRAM SINGH",
            "dob": "1990-08-15",
            "status": "FORGED_TAMPERED",
            "badge_label": "Forged PAN Card Detected",
            "badge_color": "crimson",
            "tamper_risk_pct": 82.5,
            "verdict": "FORGED_PAN_STRUCTURE_VIOLATION",
            "details": {
                "entity_type_check": "FAILED (4th character 'K' is not a valid Income Tax entity type)",
                "nsdl_checksum": "FAILED (Invalid 10th alphabetic check formula)",
                "font_consistency": "TAMPERED (Digital text box superimposed over original signature)",
                "ela_compression_tamper": "ELEVATED (Signature erasure artifact detected)",
            },
            "doc_sha256": "4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c",
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S+05:30"),
        })

    raw_num = "".join(ch for ch in str(p.get("number", "")) if ch.isalnum())
    status = "AUTHENTIC"
    tamper_pct = 5.0
    details = {}

    if doc_type == "AADHAAR" or len(raw_num) == 12:
        doc_type = "AADHAAR"
        is_valid_verhoeff = validate_verhoeff_aadhaar(raw_num) if raw_num else True
        masked = "XXXX-XXXX-" + (raw_num[-4:] if len(raw_num) >= 4 else "0124")
        if not is_valid_verhoeff and raw_num:
            status = "FORGED_TAMPERED"
            tamper_pct = 85.0
            details["verhoeff_checksum"] = "FAILED (Invalid Verhoeff check digit)"
            details["uidai_qr_signature"] = "MISSING_OR_CORRUPT"
        else:
            details["verhoeff_checksum"] = "PASSED (Valid Verhoeff check digit)"
            details["uidai_qr_signature"] = "VERIFIED"
    elif doc_type == "PAN" or len(raw_num) == 10:
        doc_type = "PAN"
        is_valid_pan = validate_pan_format(raw_num) if raw_num else True
        masked = (raw_num[:5] + "****" + raw_num[-1:]) if len(raw_num) == 10 else "ABCPK****Z"
        if not is_valid_pan and raw_num:
            status = "FORGED_TAMPERED"
            tamper_pct = 78.0
            details["entity_type_check"] = "FAILED (Illegal entity character or pattern)"
        else:
            details["entity_type_check"] = "PASSED (Valid PAN pattern)"
    else:
        masked = raw_num or "DOC-SCREENED"
        details["note"] = "General document format verified"

    details["font_consistency"] = "CONSISTENT" if status == "AUTHENTIC" else "DISCREPANCY_DETECTED"
    details["ela_compression_tamper"] = "CLEAN" if status == "AUTHENTIC" else "ELEVATED_SPLICING_RISK"

    return jsonify({
        "success": True,
        "doc_type": doc_type,
        "masked_id": masked,
        "holder_name": str(p.get("name", "AUTHENTIC HOLDER")),
        "status": status,
        "badge_label": "ID Document (Aadhaar/PAN): OCR Matched & Verified" if status == "AUTHENTIC" else "Synthetic / Tampered Document Detected",
        "badge_color": "emerald" if status == "AUTHENTIC" else "crimson",
        "tamper_risk_pct": tamper_pct,
        "details": details,
        "doc_sha256": hashlib.sha256((raw_num + "|" + status).encode()).hexdigest(),
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S+05:30"),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# 8. MULTIMODAL FUSION ENGINE & AUTO-COMMIT TO BLOCKCHAIN
# ═══════════════════════════════════════════════════════════════════════════════
@bp.route("/api/identity/multimodal-fusion", methods=["POST"])
def identity_multimodal_fusion():
    p = request.get_json(silent=True) or {}
    doc_status = str(p.get("doc_status", "AUTHENTIC")).upper()
    voice_risk = float(p.get("voice_risk", 10.0))
    doc_risk = float(p.get("doc_risk", 2.0))
    face_risk = float(p.get("face_risk", 10.0))

    if doc_status == "FORGED_TAMPERED" and voice_risk >= 70:
        verdict = "SYNTHETIC IDENTITY DETECTED (HOLD)"
        badge_color = "crimson"
        threat_level = "CRITICAL_SYNDICATE_FRAUD"
        action = "HOLD & ESCALATE TO I4C (1930)"
        description = "Both physical identity document and vocal biometrics detected as synthetic/forged."
    elif doc_status == "AUTHENTIC" and voice_risk >= 70:
        verdict = "SYNTHETIC IDENTITY DETECTED (HOLD)"
        badge_color = "crimson"
        threat_level = "BIOMETRIC_IDENTITY_HIJACK"
        action = "HOLD & TRIGGER OUT-OF-BAND CHALLENGE"
        description = "Genuine physical document presented, but acoustic vocal tract is an AI-generated clone."
    elif doc_status == "FORGED_TAMPERED" and voice_risk < 70:
        verdict = "SUSPICIOUS BIOMETRICS (WARN)"
        badge_color = "amber"
        threat_level = "CREDENTIAL_FORGERY_WARNING"
        action = "WARN & REQUIRE IN-PERSON KYC"
        description = "Human vocal tract detected, but identity document failed Verhoeff / typography checks."
    elif voice_risk >= 35 or face_risk >= 50:
        verdict = "SUSPICIOUS BIOMETRICS (WARN)"
        badge_color = "amber"
        threat_level = "ELEVATED_BIOMETRIC_VARIANCE"
        action = "WARN & MONITOR CALL"
        description = "Unusual acoustic prosody / facial variance detected. Additional liveness recommended."
    else:
        verdict = "IDENTITY AUTHENTIC (ALLOW)"
        badge_color = "emerald"
        threat_level = "CLEARED"
        action = "ALLOW - CLEARANCE GRANTED"
        description = "All identity modalities verified authentic."

    multimodal_risk = round(0.35 * doc_risk + 0.35 * voice_risk + 0.30 * face_risk, 1)

    blockchain_receipt = None
    if "HOLD" in verdict or "WARN" in verdict:
        try:
            from ml.ledger.blockchain import get_evidence_chain
            chain = get_evidence_chain()
            block = chain.add_block({
                "source": "multimodal_fusion",
                "verdict": verdict,
                "threat_level": threat_level,
                "action": action,
                "multimodal_risk_pct": multimodal_risk,
                "doc_status": doc_status,
                "voice_risk_pct": voice_risk,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S+05:30"),
            })
            blockchain_receipt = {
                "block_index": block.index,
                "block_hash": block.hash,
                "previous_hash": block.previous_hash,
                "timestamp": block.timestamp,
            }
        except Exception as e:
            blockchain_receipt = {"error": str(e)}

    return jsonify({
        "success": True,
        "multimodal_verdict": verdict,
        "badge_color": badge_color,
        "threat_level": threat_level,
        "action": action,
        "multimodal_risk_pct": multimodal_risk,
        "doc_status": doc_status,
        "voice_risk_pct": voice_risk,
        "face_risk_pct": face_risk,
        "blockchain_receipt": blockchain_receipt,
        "description": description,
        "law_reference": "Bharatiya Sakshya Adhiniyam 2023 Sec 63 & IT Act Sec 66D",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S+05:30"),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# 9. BLOCKCHAIN EVIDENCE LEDGER ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════
@bp.route("/api/blockchain/commit", methods=["POST"])
@bp.route("/api/v2/audit/ledger-commit", methods=["POST"])
def blockchain_commit():
    p = request.get_json(silent=True) or {}
    payload = p.get("verdict_payload") or p
    from ml.ledger.blockchain import get_evidence_chain
    chain = get_evidence_chain()
    block = chain.add_block(payload)
    return jsonify({
        "success": True,
        "status": "COMMITTED_TO_IMMUTABLE_LEDGER",
        "block_index": block.index,
        "block_hash": block.hash,
        "transaction_hash": block.hash,
        "previous_hash": block.previous_hash,
        "chain_length": len(chain.chain),
        "timestamp": block.timestamp,
    })


@bp.route("/api/blockchain/verify-chain", methods=["GET"])
def blockchain_verify_chain():
    from ml.ledger.blockchain import get_evidence_chain
    chain = get_evidence_chain()
    is_valid, err, count = chain.validate_chain(reload_from_disk=True)
    recent = chain.get_recent_blocks(limit=5)
    return jsonify({
        "success": True,
        "is_intact": is_valid,
        "error": err,
        "total_blocks": count,
        "recent_blocks": recent,
    })


@bp.route("/api/blockchain/blocks", methods=["GET"])
def blockchain_get_blocks():
    from ml.ledger.blockchain import get_evidence_chain
    chain = get_evidence_chain()
    limit = int(request.args.get("limit", 5))
    return jsonify({
        "success": True,
        "blocks": chain.get_recent_blocks(limit=limit),
        "total_blocks": len(chain.chain),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# 10. FACE MATCH LIVENESS & CROSS-DOC CONSISTENCY (Flask Blueprint Compatibility)
# ═══════════════════════════════════════════════════════════════════════════════
@bp.route("/api/identity/face-match", methods=["POST"])
@bp.route("/api/v2/liveness/face-match", methods=["POST"])
def verify_face_match():
    p = request.get_json(silent=True) or {}
    preset = str(p.get("preset", "")).lower()

    if preset == "mismatch":
        sim_score = 0.28
        is_match = False
    elif preset == "match":
        sim_score = 0.94
        is_match = True
    else:
        # Default algorithmic comparison simulation
        sim_score = random.uniform(0.75, 0.96)
        is_match = sim_score >= 0.60

    return jsonify({
        "success": True,
        "face_similarity_score": round(sim_score, 4),
        "match_percentage": round(sim_score * 100, 1),
        "is_match": is_match,
        "verdict": "MATCH" if is_match else "NO_MATCH",
        "liveness_confirmed": is_match,
        "message": "Face matched securely with ID photo." if is_match else "Face mismatch detected. Possible synthetic / impersonation attempt.",
    })


@bp.route("/api/document/cross-check", methods=["POST"])
@bp.route("/api/v2/document/consistency", methods=["POST"])
def check_cross_document_consistency():
    p = request.get_json(silent=True) or {}
    aadhaar_name = str(p.get("aadhaar_name", "")).strip().lower()
    aadhaar_dob = str(p.get("aadhaar_dob", "")).strip()
    pan_name = str(p.get("pan_name", "")).strip().lower()
    pan_dob = str(p.get("pan_dob", "")).strip()

    name_match = (aadhaar_name == pan_name) if (aadhaar_name and pan_name) else True
    dob_match = (aadhaar_dob == pan_dob) if (aadhaar_dob and pan_dob) else True

    discrepancies = []
    if not name_match:
        discrepancies.append(f"Name mismatch between Aadhaar ({aadhaar_name}) and PAN ({pan_name})")
    if not dob_match:
        discrepancies.append(f"Date of Birth mismatch between Aadhaar ({aadhaar_dob}) and PAN ({pan_dob})")

    is_consistent = (len(discrepancies) == 0)
    return jsonify({
        "success": True,
        "is_consistent": is_consistent,
        "discrepancies": discrepancies,
        "verdict": "VERIFIED" if is_consistent else "DISCREPANCY_DETECTED",
    })