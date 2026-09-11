# ml/engine/scam_radar.py
# TWIST C - Scam-Script Radar (English, Hindi-roman, Hinglish).
# Needs WORDS - browser speech-to-text provides them in the demo.

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
            score += 25
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