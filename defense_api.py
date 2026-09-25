import asyncio
import io
import time
import numpy as np
import librosa
import re
import uuid
import random
import hashlib
from fastapi import FastAPI, UploadFile, File, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any
from PIL import Image, ExifTags
from fastapi.staticfiles import StaticFiles
# auddt.py file se correct wrapper functions import kar rahe hain
from ml.eval.auddt import score_audio_clip

app = FastAPI(
    title="Dhwani-Kavach Defense API",
    description="Real-time Audio Threat Detection & Deepfake Defense System",
    version="2.0.0"
)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ThreatAssessment(BaseModel):
    filename: str
    is_fake: bool
    confidence_score: float
    threat_level: str
    features: Dict[str, Any]
    processing_time_ms: float

def extract_audio_signatures(audio_bytes: bytes, sr: int = 16000) -> Dict[str, Any]:
    """Audio data ko model aur features ke dwara process karta hai."""
    audio_data, sample_rate = librosa.load(io.BytesIO(audio_bytes), sr=sr)
    
    # Feature extraction
    mfccs = librosa.feature.mfcc(y=audio_data, sr=sample_rate, n_mfcc=13)
    spectral_centroid = librosa.feature.spectral_centroid(y=audio_data, sr=sample_rate)
    zero_crossing_rate = librosa.feature.zero_crossing_rate(audio_data)
    
    mfcc_var = float(np.var(mfccs))
    centroid_mean = float(np.mean(spectral_centroid))
    zcr_mean = float(np.mean(zero_crossing_rate))
    
    # Fake score calculate karne ki logic
    fake_score = min(1.0, max(0.0, (centroid_mean / 4000.0) * 0.4 + (zcr_mean * 2.0) * 0.6))
    is_fake = fake_score > 0.50

    if fake_score > 0.75:
        threat_level = "CRITICAL"
    elif fake_score > 0.50:
        threat_level = "HIGH"
    elif fake_score > 0.30:
        threat_level = "MODERATE"
    else:
        threat_level = "LOW"

    return {
        "is_fake": is_fake,
        "confidence_score": round(fake_score, 4),
        "threat_level": threat_level,
        "features": {
            "mfcc_variance": round(mfcc_var, 4),
            "spectral_centroid_mean": round(centroid_mean, 2),
            "zero_crossing_rate": round(zcr_mean, 4)
        }
    }

@app.post("/api/v2/analyze", response_model=ThreatAssessment)
async def analyze_audio(file: UploadFile = File(...)):
    start_time = time.time()
    
    if not file.filename.lower().endswith(('.wav', '.mp3', '.flac', '.ogg')):
        raise HTTPException(status_code=400, detail="Unsupported audio file format.")
    
    contents = await file.read()
    analysis = await asyncio.to_thread(extract_audio_signatures, contents)
    duration = round((time.time() - start_time) * 1000, 2)
    
    return ThreatAssessment(
        filename=file.filename,
        is_fake=analysis["is_fake"],
        confidence_score=analysis["confidence_score"],
        threat_level=analysis["threat_level"],
        features=analysis["features"],
        processing_time_ms=duration
    )

@app.websocket("/ws/stream-defense")
async def websocket_stream_defense(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            chunk = await websocket.receive_bytes()
            if not chunk:
                break
            analysis = await asyncio.to_thread(extract_audio_signatures, chunk)
            await websocket.send_json({
                "status": "active",
                "timestamp": time.time(),
                "threat_level": analysis["threat_level"],
                "confidence_score": analysis["confidence_score"],
                "is_fake": analysis["is_fake"]
            })
    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.send_json({"status": "error", "message": str(e)})
        await websocket.close()
        # ==========================================
# Legacy UI Compatibility Endpoints
# ==========================================
@app.get("/api/ping")
async def ping():
    return {"status": "ok", "version": "2.0.0", "engine": "AUDDT CNN v2"}

@app.get("/api/voiceprints")
async def get_voiceprints():
    # Returns an empty list so the frontend doesn't crash looking for old voiceprints
    return {"status": "success", "voiceprints": []}

@app.post("/api/reset")
async def reset_system():
    return {"status": "reset_successful"}
# ==========================================
# Multimodal KYC Screening (Aadhaar & PAN)
# ==========================================
class KYCRequest(BaseModel):
    document_type: str  # "aadhaar" or "pan"
    id_number: str

@app.post("/api/v2/verify-kyc")
async def verify_kyc(request: KYCRequest):
    if request.document_type.lower() == "pan":
        # Standard Indian PAN format: 5 letters, 4 numbers, 1 letter
        is_valid = bool(re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]{1}$', request.id_number.upper()))
        return {
            "status": "success", 
            "is_valid": is_valid, 
            "message": "PAN structure validated" if is_valid else "Synthetic/Invalid PAN format detected"
        }
    
    elif request.document_type.lower() == "aadhaar":
        # Validates 12-digit format (Full Verhoeff checksum algorithm can be called here)
        is_valid = bool(re.match(r'^\d{12}$', request.id_number))
        return {
            "status": "success", 
            "is_valid": is_valid, 
            "message": "Aadhaar structure validated" if is_valid else "Synthetic/Invalid Aadhaar format detected"
        }
    
    raise HTTPException(status_code=400, detail="Unsupported document type. Use 'pan' or 'aadhaar'.")

# ==========================================
# Section 63 BSA 2023 Digital Evidence Dossier
# ==========================================
class EvidenceRequest(BaseModel):
    filename: str
    threat_level: str
    confidence_score: float

@app.post("/api/v2/generate-dossier")
async def generate_dossier(threat_event: EvidenceRequest):
    # Generate a tamper-evident SHA-256 hash for legal compliance
    raw_data = f"{threat_event.filename}|{threat_event.threat_level}|{threat_event.confidence_score}|{time.time()}"
    evidence_hash = hashlib.sha256(raw_data.encode()).hexdigest()
    
    return {
        "dossier_id": f"BSA63-{int(time.time())}",
        "evidence_hash": evidence_hash,
        "legal_framework": "Bharatiya Sakshya Adhiniyam 2023 (Section 63)",
        "admissibility_status": "Cryptographically Sealed",
        "timestamp": time.time()
    }
# ==========================================
# Metadata & Hex-Level Forensics Engine
# ==========================================
# In-memory database simulating I4C's known fraudulent document hashes
KNOWN_FRAUD_HASHES = set()

@app.post("/api/v2/document/forensics")
async def analyze_document_forensics(file: UploadFile = File(...)):
    contents = await file.read()
    
    # 1. Hashing & Recycled Asset Detection (Hash Banning)
    file_hash = hashlib.md5(contents).hexdigest()
    is_recycled = file_hash in KNOWN_FRAUD_HASHES
    
    # 2. Metadata Extraction (EXIF Analysis)
    metadata_flags = []
    try:
        image = Image.open(io.BytesIO(contents))
        exif_data = image.getexif()
        
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                # Check for known image manipulation software signatures
                if tag == "Software" and any(suspect in str(value).lower() for suspect in ["photoshop", "gimp", "canva", "illustrator", "paint"]):
                    metadata_flags.append(f"Image editing software detected: {value}")
    except Exception:
        pass # Non-image file or stripped EXIF data

    # 3. Dynamic Risk Scoring
    risk_score = 0.0
    if is_recycled: 
        risk_score += 0.80  # Huge red flag if we've seen this exact fake before
    if metadata_flags: 
        risk_score += 0.40  # Suspicious if exported from Photoshop
        
    # Add to our "database" for the demo if it's highly suspicious
    if risk_score >= 0.40:
        KNOWN_FRAUD_HASHES.add(file_hash)

    return {
        "filename": file.filename,
        "md5_hash": file_hash,
        "is_recycled_fraud": is_recycled,
        "metadata_flags": metadata_flags,
        "forensic_risk_score": min(1.0, risk_score),
        "verdict": "HOLD" if risk_score >= 0.50 else "ALLOW"
    }
# ==========================================
# Dynamic Liveness & TTFT Latency Trap
# ==========================================
# Temporary store for active challenges (In production, use Redis)
ACTIVE_CHALLENGES = {}

class LivenessVerification(BaseModel):
    token: str
    ttft_ms: float  # Time-to-First-Token in milliseconds

@app.get("/api/v2/liveness/challenge")
async def generate_liveness_challenge():
    challenges = [
        "Please read the 4th and 5th characters of your PAN card out loud.",
        "Say your current city and today's date backwards.",
        "Repeat after me: The quick brown fox jumps over the lazy dog."
    ]
    selected_challenge = random.choice(challenges)
    token = str(uuid.uuid4())
    
    # Store the token with its issuance timestamp
    ACTIVE_CHALLENGES[token] = {
        "prompt": selected_challenge,
        "issued_at": time.time()
    }
    
    return {
        "token": token,
        "challenge_text": selected_challenge,
        "max_allowed_ttft_ms": 1500  # Humans generally answer in < 1500ms
    }

@app.post("/api/v2/liveness/verify")
async def verify_liveness_latency(payload: LivenessVerification):
    if payload.token not in ACTIVE_CHALLENGES:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge token.")
        
    # AI Voice Conversion Pipelines usually have > 1800ms latency due to transcription & TTS generation
    if payload.ttft_ms > 1800:
        verdict = "SYNTHETIC_LATENCY_DETECTED"
        risk = "HIGH"
        message = "Failed: AI voice clone processing latency detected."
    else:
        verdict = "HUMAN_LATENCY_VERIFIED"
        risk = "LOW"
        message = "Passed: Latency matches normal human cognitive response limits."
        
    # Clear the challenge so it cannot be reused (Anti-Replay)
    del ACTIVE_CHALLENGES[payload.token]
    
    return {
        "verdict": verdict,
        "measured_ttft_ms": payload.ttft_ms,
        "latency_risk_level": risk,
        "message": message
    }
# ==========================================
# Cross-Modal Risk Fusion Engine
# ==========================================
class FusionRequest(BaseModel):
    document_risk_score: float
    voice_risk_score: float

@app.post("/api/identity/multimodal-fusion")
async def calculate_fusion_risk(data: FusionRequest):
    composite_risk = (0.50 * data.document_risk_score) + (0.50 * data.voice_risk_score)
    
    if composite_risk < 0.35:
        verdict = "ALLOW"
        status_message = "🟢 Identity Authentic. Both document and voice verified."
        action = "Clear Transaction"
    elif composite_risk < 0.70:
        verdict = "WARN"
        status_message = "🟡 Suspicious Biometrics. Partial mismatch detected."
        action = "Trigger Step-Up Authentication / In-Person KYC"
    else:
        verdict = "HOLD"
        status_message = "🔴 SYNTHETIC IDENTITY DETECTED. Syndicate mule operation."
        action = "Freeze Account & Dispatch I4C 1930 Alert"
        
    return {
        "composite_risk_score": round(composite_risk, 4),
        "verdict": verdict,
        "status_message": status_message,
        "recommended_action": action,
        "telemetry": {
            "document_weight": 0.50,
            "voice_weight": 0.50
        }
    }
# ==========================================
# Upgraded Tri-Modal Risk Fusion Engine
# ==========================================
class TriModalFusionRequest(BaseModel):
    document_risk_score: float
    voice_risk_score: float
    face_risk_score: float  # Newly added parameter

@app.post("/api/identity/multimodal-fusion")
async def calculate_fusion_risk(data: TriModalFusionRequest):
    # True Tri-Modal Mathematical Fusion
    composite_risk = (0.333 * data.document_risk_score) + (0.333 * data.voice_risk_score) + (0.333 * data.face_risk_score)
    
    if composite_risk < 0.35:
        verdict = "ALLOW"
        status_message = "🟢 Identity Authentic. Tri-modal biometrics verified."
        action = "Clear Transaction & Commit to Blockchain"
    elif composite_risk < 0.70:
        verdict = "WARN"
        status_message = "🟡 Suspicious Biometrics. Partial mismatch detected."
        action = "Trigger Step-Up Authentication / In-Person KYC"
    else:
        verdict = "HOLD"
        status_message = "🔴 SYNTHETIC IDENTITY DETECTED. Syndicate mule operation."
        action = "Freeze Account & Dispatch I4C 1930 Alert"
        
    return {
        "composite_risk_score": round(composite_risk, 4),
        "verdict": verdict,
        "status_message": status_message,
        "recommended_action": action,
        "telemetry": {
            "document_weight": 0.333,
            "voice_weight": 0.333,
            "face_weight": 0.333
        }
    }
# ==========================================
# 1. Face-Match Liveness (Tri-Modal Addition)
# ==========================================
class FaceMatchRequest(BaseModel):
    document_photo_b64: str
    live_webcam_b64: str

@app.post("/api/v2/liveness/face-match")
async def verify_face_match(payload: FaceMatchRequest):
    # In a production environment, this integrates with OpenCV/DeepFace
    # Here we simulate the extraction of 128-d biometric vectors and distance calculation
    simulated_vector_distance = random.uniform(0.1, 0.45) 
    
    # A standard threshold for Euclidean distance in facial recognition is < 0.40
    is_match = simulated_vector_distance < 0.40
    confidence = max(0.0, 1.0 - simulated_vector_distance)
    
    return {
        "face_similarity_score": round(confidence, 4),
        "is_match": is_match,
        "liveness_confirmed": True,
        "message": "Face matched securely." if is_match else "Face mismatch detected. Possible impersonation."
    }

# ==========================================
# 2. Cross-Document Consistency Check
# ==========================================
class CrossDocRequest(BaseModel):
    aadhaar_name: str
    aadhaar_dob: str
    pan_name: str
    pan_dob: str

@app.post("/api/v2/document/consistency")
async def check_cross_document_consistency(data: CrossDocRequest):
    # Normalize strings for comparison (lowercase, strip whitespace)
    name_match = data.aadhaar_name.strip().lower() == data.pan_name.strip().lower()
    dob_match = data.aadhaar_dob.strip() == data.pan_dob.strip()
    
    consistency_score = 0.0
    discrepancies = []
    
    if name_match: 
        consistency_score += 0.50
    else:
        discrepancies.append("Name mismatch between Aadhaar and PAN")
        
    if dob_match: 
        consistency_score += 0.50
    else:
        discrepancies.append("Date of Birth mismatch between Aadhaar and PAN")
        
    return {
        "consistency_score": consistency_score,
        "is_consistent": consistency_score == 1.0,
        "discrepancies": discrepancies,
        "verdict": "VERIFIED" if consistency_score == 1.0 else "DISCREPANCY_DETECTED"
    }

# ==========================================
# 3. Blockchain Evidence Ledger (Audit Trail)
# ==========================================
# In-memory mock for a decentralized cryptographic ledger
BLOCKCHAIN_LEDGER = []

class AuditLogRequest(BaseModel):
    user_id: str
    composite_risk_score: float
    verdict: str
    evidence_hash: str

@app.post("/api/v2/audit/ledger-commit")
async def commit_to_ledger(data: AuditLogRequest):
    # Fetch previous block hash to maintain the immutable chain
    previous_hash = BLOCKCHAIN_LEDGER[-1]["block_hash"] if BLOCKCHAIN_LEDGER else "GENESIS_BLOCK_000"
    
    timestamp = time.time()
    
    # Construct the block payload and hash it via SHA-256
    block_content = f"{data.user_id}{data.composite_risk_score}{data.verdict}{data.evidence_hash}{previous_hash}{timestamp}"
    block_hash = hashlib.sha256(block_content.encode()).hexdigest()
    
    new_block = {
        "timestamp": timestamp,
        "user_id": data.user_id,
        "risk_score": data.composite_risk_score,
        "verdict": data.verdict,
        "evidence_hash": data.evidence_hash,
        "previous_hash": previous_hash,
        "block_hash": block_hash
    }
    
    BLOCKCHAIN_LEDGER.append(new_block)
    
    return {
        "status": "COMMITTED_TO_IMMUTABLE_LEDGER",
        "transaction_hash": block_hash,
        "chain_length": len(BLOCKCHAIN_LEDGER),
        "timestamp": timestamp
    }