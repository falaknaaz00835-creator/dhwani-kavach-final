# ml/engine/voiceprint.py
# TWIST A - "Is this really Papa?"  Family voiceprint verification.
# With CONSENT, family members record once (enrolment). Their "voiceprint"
# (timbre + pitch signature) is stored ON THIS MACHINE ONLY.
# When a call claims to be Papa, we ask: is this voice closer to Papa,
# or closer to someone else entirely?
# HONEST LIMIT (we say it openly): a high-quality clone copies pitch & timbre,
# so this catches wrong-person and low-effort clone calls best. It is one
# layer, not a magic door lock. That is why our product uses MANY layers.

import os

import numpy as np
import librosa

from ml.audio.io import SR

STORE = os.path.join("data", "voiceprints")
N_MELS = 40          # timbre signature: 40 frequency-band averages


def extract_print(y, sr=SR):
    """Turn a voice clip into one compact vector (the 'fingerprint').
    The timbre profile is normalised per clip (shape matters, not loudness)."""
    S = librosa.feature.melspectrogram(y=y, sr=sr, n_fft=512, hop_length=160,
                                       n_mels=N_MELS, power=2.0)
    Sdb = librosa.power_to_db(S, ref=1.0)
    timbre = Sdb.mean(axis=1)                       # how energy spreads over bands
    timbre = (timbre - timbre.mean()) / (timbre.std() + 1e-9)   # keep the SHAPE only
    f0 = librosa.yin(y, fmin=65, fmax=400, sr=sr,
                     frame_length=1024, hop_length=160)
    voiced = f0[(f0 > 70) & (f0 < 380)]
    if len(voiced) >= 10:
        f0_mean, f0_std = float(voiced.mean()), float(voiced.std())
    else:
        f0_mean, f0_std = 0.0, 0.0
    return np.concatenate([timbre, [f0_mean / 300.0, f0_std / 100.0]]).astype(np.float32)


def _cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na < 1e-9 or nb < 1e-9:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def enrol(name, clips):
    """Store the average print of 'clips' (list of audio arrays) for `name`."""
    os.makedirs(STORE, exist_ok=True)
    prints = [extract_print(c) for c in clips]
    mean_print = np.mean(prints, axis=0)
    np.savez(os.path.join(STORE, name + ".npz"),
             mean=mean_print, n_samples=len(prints))
    return mean_print


def enrolled_names():
    if not os.path.isdir(STORE):
        return []
    return sorted(f[:-4] for f in os.listdir(STORE) if f.endswith(".npz"))


def verify(name, y):
    """Compare clip `y` against enrolled `name` AND everyone else.
    All prints are first centred on the group average, so we compare how each
    voice DIFFERS from the average voice - not absolute loudness levels."""
    path = os.path.join(STORE, name + ".npz")
    if not os.path.exists(path):
        return {"error": f"no enrolment found for '{name}'"}
    probe = extract_print(y)

    stored = {n: np.load(os.path.join(STORE, n + ".npz"))["mean"]
              for n in enrolled_names()}
    centred_mean = np.mean(list(stored.values()), axis=0)      # the 'average voice'
    c = {n: v - centred_mean for n, v in stored.items()}
    p = probe - centred_mean

    sims = {n: _cos(p, cv) for n, cv in c.items()}
    sim_claimed = sims.pop(name, None)
    best_other = max(sims, key=sims.get) if sims else None
    sim_other = sims.get(best_other, 0.0) if best_other else 0.0
    margin = sim_claimed - sim_other

    # margin rule: must be closer to the claimed person than to anyone else,
    # by a safety gap. Threshold is a policy choice - printed so you can tune it.
    MATCH_MARGIN = 0.05
    if best_other is None:
        verdict = "MATCH" if sim_claimed > 0.80 else "UNCERTAIN (only one person enrolled)"
    else:
        verdict = "MATCH" if margin > MATCH_MARGIN else (
            "WRONG PERSON?" if margin < -0.05 else "UNCERTAIN - ask a code word")
    return {"claimed": name, "sim_claimed": round(sim_claimed, 4),
            "best_other": best_other, "sim_other": round(sim_other, 4),
            "margin": round(margin, 4), "verdict": verdict}


# ---------------------------------------------------------------------------
# SCAM-SCRIPT RADAR: Scans transcript text for fraud patterns
# ---------------------------------------------------------------------------
# Fraud calls follow SCRIPTS. We scan what the caller says (as text) for the
# signatures of known Indian fraud scripts - English, Hindi (roman), Hinglish.
# HONEST LIMIT: this needs WORDS. In the live demo the browser's built-in
# speech-to-text provides them; production would use on-premise speech
# recognition (roadmap). Until then we label it clearly.

SCAM_PATTERNS = {
    "digital_arrest": [
        "digital arrest", "cbi", "police station", "warrant", "case filed",
        "case registered", "legal action", "narcotics", "money laundering",
        "custody", "fir", "summons", "cbi officer", "cyber cell",
    ],
    "family_emergency": [
        "accident", "hospital", "icu", "emergency", "kidnap",
        "papa ko", "beta ko", "blood", "operation", "ragging", "thulla",
    ],
    "upi_otp": [
        "otp", "pin", "cvv", "upi", "gpay", "phonepe", "paytm",
        "transfer", "send money", "scan the", "qr code", "account block",
        "account will be", "kyc", "expire", "refund", "blocked",
        "bank manager", "verify your account",
    ],
    "urgency": [
        "abhi", "turant", "jaldi", "immediately", "right now", "urgent",
        "2 minute", "minutes me", "warna", "nahi toh", "only", "last chance",
    ],
}

ADVISORY = {
    "digital_arrest": "Police/CBI never arrest over a call or ask money. Hang up; call the station's official number.",
    "family_emergency": "Possible fake-emergency script. Hang up and call your family member's own number directly.",
    "upi_otp": "No real bank/UPI employee ever asks for OTP, PIN, or a transfer to a new account.",
    "urgency": "Manufactured urgency is a pressure tactic - real institutions give you time.",
}


def scan(text):
    """Return scam-pattern score (0-100), matched phrases, and advisory."""
    t = " " + str(text).lower() + " "
    hits = {}
    for cat, phrases in SCAM_PATTERNS.items():
        found = [p for p in phrases if p in t]
        if found:
            hits[cat] = found

    scam_cats = [c for c in hits if c != "urgency"]
    n_phrases = sum(len(v) for v in hits.values())
    has_urgency = "urgency" in hits

    score = 0
    if scam_cats or has_urgency:
        score = 30 * len(scam_cats) + 8 * n_phrases
        if has_urgency and scam_cats:
            score += 25          # urgency + a scam script = classic combination
    score = min(100, score)

    top = max(scam_cats, key=lambda c: len(hits[c])) if scam_cats else (
        "urgency" if has_urgency else None)
    return {
        "score": score,
        "level": "HIGH" if score >= 70 else ("MEDIUM" if score >= 40 else "LOW"),
        "categories": list(hits.keys()),
        "matched": {c: hits[c] for c in hits},
        "advisory": ADVISORY.get(top, None),
    }