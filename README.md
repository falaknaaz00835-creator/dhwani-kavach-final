
# 🛡️ Dhwani Kavach — Real-Time Voice Impersonation Defense

**Detection → Verification → Prevention.** A privacy-first defense system that converts
uncertain audio evidence into calibrated, explainable, and progressively stronger
protective actions — built for India's phone-scam epidemic.

> *We do not promise that one model can detect every synthetic voice. We designed a
> defense system that measures evidence continuously, tests itself against unseen and
> degraded conditions, communicates uncertainty, and escalates protection before a
> voice-based impersonation attack becomes a financial loss.*

**Smart India Hackathon 2026 · Problem Statement SIH26104 · Team VERITAS (all-women engineering team)**

---

## The Problem

Cybercriminals clone a family member's voice from a few seconds of public audio, then
call elders with "emergencies" demanding money or OTPs. India reported **₹22,495 crore
lost to cyber fraud in 2025 (I4C)** — voice-clone scams are among the fastest-growing
attack vectors, and victims realize the fraud only after the transfer.

A detector alone is not enough. **Dhwani Kavach is a full defense pipeline**: detect the
fake voice, verify the caller, recognize the scam script, and **act** — before the loss.

## Architecture & Data Flow

```
Live audio → Decode/Resample 16 kHz → Energy VAD → 4 s sliding windows
   → 80-bin log-mel → MelCNN (per-window AI score)
   → Temporal evidence engine (flicker logic, accumulation)
   → Scam Radar (Indian scam-phrase presets, 0–100)
   → Voiceprint verification (consent-enrolled, on-device)
   → Risk tier (LOW / MEDIUM / HIGH) + Combination law
   → Actions: advisory · challenge · auto-mute · family alert · 1930 dossier
```

| Component | Status |
|---|---|
| MelCNN detector (236,141 params, CPU real-time) | 🟢 Implemented |
| Temporal evidence engine (window smoothing, no false alarms) | 🟢 Implemented |
| Scam Radar v3.1 (Indian scam presets, SIM-deactivation, KYC, OTP) | 🟢 Implemented |
| Voiceprint (consent enrolment, on-device, margin rule) | 🟢 Implemented |
| Link Guard + bank-number impersonation check | 🟢 Implemented |
| Live twister challenge + response-latency trap | 🟢 Implemented |
| Elder Mode (giant Hinglish verdict strip + alert beep) | 🟢 Implemented |
| Family Alert (WhatsApp click-to-chat, pre-filled report) | 🟢 Implemented |
| Forensic Vitals (10 DSP metrics, computed locally in-browser) | 🟢 Implemented |
| Evidence reports (SHA-256 hashed) + 1930 reporting dossier | 🟢 Implemented |
| ONNX export with verified parity | 🟢 Implemented |
| ONNX-runtime inference path · APK packaging (Capacitor scaffold) | 🟡 Integration target |
| SSL-model ablation (RawNet2 / Wav2Vec2 comparison) · Indic dialect calibration · telecom API | 🔵 Planned |

## Verified Evidence (reproducible)

| Metric | Value | Protocol |
|---|---|---|
| EER (seen attacks) | 1.25% | ASVspoof 2019 LA dev subset (n=800) |
| EER (unseen attacks) | 8.5% | ASVspoof 2019 LA eval subset (n=1,200, attack-disjoint) |
| TPR @ 1% false alarm | 98.5% | dev subset; thresholds calibrated on real team-recorded voices |
| Accuracy | 98.75% dev / 91.08% eval | same subsets (see `results/cnn_v1/metrics.json`) |
| Corpus | ASVspoof 2019 LA — 121,461 clips total | Headline metrics on capped subsets: 4,000 train / 800 dev / 1,200 eval; full-corpus runs on roadmap |
| Model | 236,141 params | 80 log-mel, 4 s windows, Adam, 10 epochs, CPU-only training |
| ONNX parity (PyTorch vs ONNX logits) | max Δ 2.4e-06 | `17_export_onnx.py` self-test |
| ONNX artifact | ≈ 1.0 MB (graph + weights) | SHA-256: `c4134066…d97d539c5` |
Hardest attack class: **A17 (EER 42.3%)** — exactly why Dhwani Kavach is a layered defense (radar + challenge + voiceprint), not a single detector.

**Full-scale AUDDT evaluation (cnn_v2, 2026-09-25, git d4c66e3)** -- run `python 18_evaluate_auddt.py` (71,237 clips, ~45 min on CPU):

| Metric | Value | Protocol |
|---|---|---|
| ROC-AUC (full eval) | 0.9489 | ASVspoof2019 LA eval, 71,237 clips (7,355 bonafide / 63,882 spoof) |
| TPR @ 1% FPR (full eval) | 76.94% | same full-eval split |
| Accuracy at shipped operating point (theta=0.62) | 74.43% (FPR 0.38%, recall 71.53%) | calibrated |
| Codec robustness (mu-law / A-law / AMR-NB / Opus 16 / MP3 64) | AUC 0.937-0.947 (dAUC <= 0.006 vs clean) | 1,190 clips per condition |
| 0.5 s duration truncation | AUC 0.9206 (dAUC -0.021) | 1,190 clips, product tile-to-4s pad |
| Noise stress (SNR 10 dB / 5 dB) | AUC 0.36 / 0.25 (ranking inverted) | Reported honestly: heavy noise still defeats the model |
| Hardest attack class (full eval) | A17 (script EER 55.56%, AUC 0.57) | voice-conversion, same family as v1 weakness |
| Decode failures | 0 / 71,237 | - |
| Live-server parity | max |delta| = 0.00 | scores byte-identical to demo_server.py path |

Reproduce the AUDDT full benchmark (writes results/cnn_v2/auddt_evaluation_report.pdf, .md, metrics.json):
```
python 18_evaluate_auddt.py
```

Reproduce the ONNX evidence:
```
pip install onnx onnxruntime onnxscript
python 17_export_onnx.py
```

## Quickstart

```bash
git clone https://github.com/falaknaaz00835-creator/dhwani-kavach-final.git
cd dhwani-kavach-final
python -m venv .venv
.venv\Scripts\activate          # Windows   (Linux/mac: source .venv/bin/activate)
pip install torch torchaudio --index-url https://download.pytorch.org/whl/cpu   # CPU-only torch (avoids 2.5 GB CUDA download on laptops)
pip install -r requirements.txt
python demo_server.py
```
Open **http://127.0.0.1:8000** — the full defense dashboard loads (model weights ship
with the repo under `results/cnn_v1/`).

Key scripts: `1_record_voice.py` (enrol your voice) · `7_train_cnn.py` / `8_train_cnn_v2.py`
(training) · `2_test_codecs.py` (codec robustness) · `13_MAKE_BENCHMARK_PAIR.PY`
(benchmarks) · `17_export_onnx.py` (ONNX self-test) · `test_server_api.py` (API tests).

## Privacy & Ethics

- **On-device / on-premise first** — forensic vitals are computed locally in the browser; audio is not uploaded for telemetry.
- Voiceprint enrolment is **consent-based**; prints stay on the device.
- The live **telephone channel is simulated** in the demo (disclosed openly); real-time PBX/telecom integration is a roadmap item. We do not claim production telephony.
- Family Alert uses WhatsApp **click-to-chat** (official pattern) — no unauthorized API.

## Limitations (stated openly)

Single detector model (ensemble ablation planned) · dialect variance affects calibration
(Indic calibration roadmap) · codec-robustness table in progress · forensic vitals are
supporting telemetry, never a standalone verdict.

## Team VERITAS

| Member | Role |
|---|---|
| Bhoomi | Problem & impact research |
| Falak | Architecture & UI |
| Saniya | ML engine & backend lead |
| Soni | Feasibility & privacy |
| Kajal | Benchmarks & research |
| Yashika | Demo & UX |

*An all-women engineering team building safety for India's elders.*

---
<!-- LIVE_DEMO_LINK (Hugging Face Space) — updated at submission -->