# demo_server.py  (v2 - full demo: call screen, context card, voiceprint, radar)
# DHWANI-KAVACH LIVE DEMO SERVER
# Run with the OLD trusted venv (OneDrive one) or any venv with the libs.

import math
import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

import json
import tempfile

try:
    from flask import Flask, request, jsonify, send_file
except ImportError:
    print("flask is not installed. Run 0c_install_flask.py once, then run this.")
    raise SystemExit(0)

import numpy as np
import torch

from ml.audio.io import load, SR, fix_length, energy_vad
from ml.features.dsp import logmel
from ml.models.cnn import MelCNN
from ml.engine.temporal import TemporalEngine, EngineConfig, policy_for
from ml.engine.scam_radar import scan
from ml.engine import voiceprint_falak
from ml.augment.codecs import FFMPEG, run_quiet

torch.set_num_threads(1)

MODEL_PATH, MODEL_NAME = None, None
for cand, name in [("results/cnn_v2/model.pt", "CNN v2 (codec-hardened)"),
                   ("results/cnn_v1/model.pt", "CNN v1 (clean-trained)")]:
    if os.path.exists(cand):
        MODEL_PATH, MODEL_NAME = cand, name
        break
if MODEL_PATH is None:
    print("No trained model found (results/cnn_v1 or cnn_v2).")
    print("Run 7_train_cnn.py first, then start the demo.")
    raise SystemExit(0)

model = MelCNN()
model.load_state_dict(torch.load(MODEL_PATH, map_location="cpu"))
model.eval()
print("demo model:", MODEL_NAME, "<-", MODEL_PATH)

# ---- Block 10 calibration: thresholds + silence gate ----
_CAL_PATH = os.path.join("results", "calibration.json")
CAL = json.load(open(_CAL_PATH)) if os.path.exists(_CAL_PATH) else {}
engine = TemporalEngine(EngineConfig(
    theta_lo=float(CAL.get("theta_lo", 0.62)),
    theta_hi=float(CAL.get("theta_hi", 0.90)),
))
if CAL:
    print(f"calibration: loaded {_CAL_PATH} "
          f"(vad_min={CAL.get('vad_min')}, bias={CAL.get('logit_bias')}, "
          f"theta {CAL.get('theta_lo')}/{CAL.get('theta_hi')})")
else:
    print("calibration: none found - DEFAULTS (run 14_block10_calibrate.py)")
SECONDS = 4.0

# ---- demo whitelist of OFFICIAL helpline numbers ----
OFFICIAL_NUMBERS = {
    "1930": "National Cyber Crime Helpline",
    "112":  "National Emergency Number",
    "100":  "Police",
    "1800111109": "SBI Credit Card (example entry)",
    "18602667766": "HDFC Bank (example entry)",
}

app = Flask(__name__, static_folder="static")

try:
    from flask_cors import CORS
    CORS(app)
    print("CORS: on")
except ImportError:
    print("CORS: flask-cors not installed - other devices may be blocked")


def score_audio(y):
    piece = fix_length(np.asarray(y, dtype=np.float32), int(SECONDS * SR))
    x = logmel(piece)
    x = (x - x.mean()) / (x.std() + 1e-6)
    with torch.no_grad():
        p = float(torch.sigmoid(model(torch.from_numpy(x[None, None, ...]))))
    return p


def decode_to_wav(raw_bytes, suffix):
    tmp = tempfile.mkdtemp(prefix="dk_demo_")
    inp = os.path.join(tmp, "in" + suffix)
    out = os.path.join(tmp, "out.wav")
    with open(inp, "wb") as fh:
        fh.write(raw_bytes)
    run_quiet([FFMPEG, "-hide_banner", "-y", "-i", inp,
               "-ar", str(SR), "-ac", "1", out])
    return load(out)


@app.route("/")
def index():
    return send_file("static/index.html")


@app.route("/api/reset", methods=["POST"])
def reset():
    engine.reset()
    return jsonify({"ok": True})


@app.route("/api/context", methods=["POST"])
@app.route("/api/ping", methods=["GET", "POST"])
def ping():
    return jsonify({"ok": True, "status": "ok", "online": True, "alive": True,
                    "backend": "online", "model": "CNN v1"})
def context():
    d = request.get_json(force=True) if request.is_json else {}
    number = str(d.get("number", "")).replace(" ", "")
    notes = []
    level = "neutral"
    if number.startswith("140"):
        notes.append("Number is in the TRAI 140 telemarketing series")
        level = "warning"
    if number in OFFICIAL_NUMBERS:
        notes.append(f"Matches official listing: {OFFICIAL_NUMBERS[number]}")
        level = "safe" if level == "neutral" else level
    else:
        if len(number) >= 10 and number[0] == "1":
            notes.append("NOT in the official helpline list (bank/police numbers are published)")
            level = "warning" if level == "neutral" else level
    if d.get("claims_bank"):
        notes.append("Caller claims to be from a bank but the number is not the bank's "
                     "official helpline - classic impersonation pattern")
        level = "danger"
    return jsonify({"number": number, "level": level, "notes": notes})


@app.route("/api/radar", methods=["POST"])
def radar():
    d = request.get_json(force=True) if request.is_json else {}
    return jsonify(scan(d.get("text", "")))


@app.route("/api/enrol", methods=["POST"])
def enrol():
    try:
        name = "".join(c for c in request.form.get("name", "") if c.isalnum() or c in " _-").strip()
        if not name:
            return jsonify({"error": "name required"})
        f = request.files.get("audio")
        suffix = os.path.splitext(f.filename)[1] or ".wav"
        y = decode_to_wav(f.read(), suffix)
        voiceprint_falak.enrol(name, [y])
        return jsonify({"ok": True, "name": name,
                        "enrolled": voiceprint_falak.enrolled_names()})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/api/verify", methods=["POST"])
def verify():
    try:
        name = request.form.get("name", "").strip()
        f = request.files.get("audio")
        suffix = os.path.splitext(f.filename)[1] or ".wav"
        y = decode_to_wav(f.read(), suffix)
        return jsonify(voiceprint_falak.verify(name, y))
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/api/voiceprints", methods=["GET"])
def voiceprints():
    return jsonify({"enrolled": voiceprint_falak.enrolled_names()})


@app.route("/api/score", methods=["POST"])
def api_score():
    try:
        ctype = request.headers.get("Content-Type", "")
        if "webm" in ctype or "ogg" in ctype:
            suffix = ".webm"
        elif "wav" in ctype:
            suffix = ".wav"
        elif "mpeg" in ctype or "mp3" in ctype:
            suffix = ".mp3"
        elif "mp4" in ctype or "m4a" in ctype:
            suffix = ".m4a"
        else:
            suffix = ".bin"
        if "multipart/form-data" in ctype:
            f = next(iter(request.files.values()), None)
            raw_bytes = f.read() if f is not None else b""
            if f is not None and f.filename and "." in f.filename:
                suffix = "." + f.filename.rsplit(".", 1)[-1].lower()
        elif "json" in ctype:
            import base64 as _b64
            raw_bytes = b""
            try:
                d = request.get_json(force=True, silent=True) or {}
                s = d.get("audio") or d.get("data") or d.get("blob") or d.get("file") or ""
                if isinstance(s, str) and s:
                    raw_bytes = _b64.b64decode(s.split(",")[-1])
            except Exception:
                raw_bytes = b""
            if not raw_bytes:
                raw_bytes = request.get_data()
        else:
            raw_bytes = request.get_data()
        print(f"[score] in: ctype={ctype}, bytes={len(raw_bytes)}, suffix={suffix}")
        if not raw_bytes:
            return jsonify({"error": "no audio received"})
        y = decode_to_wav(raw_bytes, suffix)       
        if len(y) < SR:
            return jsonify({"error": "too short"})
        vfrac = float(energy_vad(y[-int(SECONDS * SR):]).mean())
        if vfrac < float(CAL.get("vad_min", 0.0)):
            r = engine.update(0.5, 0.0)
        else:
            raw = score_audio(y)
            bias = float(CAL.get("logit_bias", 0.0))
            q = min(max(raw, 1e-4), 1 - 1e-4)
            p = 1.0 / (1.0 + math.exp(-(math.log(q / (1.0 - q)) + bias)))
            r = engine.update(p, vfrac * SECONDS)
        pol = policy_for(r["tier"])
        return jsonify({
            "window_p": round(r["window_p"], 4),
            "call_p": round(r["call_p"], 4),
            "tier": r["tier"],
            "voiced_seconds": r["voiced_seconds"],
            "n_windows": r["n_windows"],
            "action": pol["action"],
            "ui": pol["ui"],
            "step_up": pol["step_up"],
            "allow_sensitive": pol["allow_sensitive_action"],
            "model": MODEL_NAME,
        })
    except Exception as e:
        return jsonify({"error": str(e)})


if __name__ == "__main__":
    import socket
    try:
        _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _s.connect(("8.8.8.8", 80))
        _lan_ip = _s.getsockname()[0]
        _s.close()
    except Exception:
        _lan_ip = "(run ipconfig to find it)"
    print()
    print("DHWANI-KAVACH demo v2. Open in your browser (Chrome recommended):")
    print("       http://127.0.0.1:8000")
    print(f"phones on the same Wi-Fi:  http://{_lan_ip}:8000")
    app.run(host="0.0.0.0", port=8000, debug=False)