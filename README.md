
# 🛡️ Dhwani-Kavach — Multimodal Synthetic Identity & Document Screening Portal

**Detection → Verification → Prevention.** India's first unified multimodal identity defense system that pairs physical document screening (Aadhaar / PAN tamper analysis) with real-time acoustic voice biometrics — engineered for the Ministry of Home Affairs (MHA) cyber defense ecosystem.

> *Under MHA / I4C classification, AI voice cloning is recognized as "Synthetic Biometric Identity Fraud." By combining offline Verhoeff & ELA document verification with on-device acoustic deepfake detection (ASVspoof benchmarked), Dhwani-Kavach provides comprehensive zero-trust identity screening before financial loss occurs.*

**Smart India Hackathon 2026 · Problem Statement SIH26188 · Ministry of Home Affairs (MHA) · Team VERITAS**

---

## The Problem: Multimodal Identity Fraud

Cybercriminals exploit a two-pronged attack vector:
1. **Forged KYC Credentials:** Altered or synthetic Aadhaar and PAN cards are used to procure illegal SIMs and open mule bank accounts.
2. **Synthetic Vocal Biometrics:** Generative AI voice clones are deployed during tele-verification, banking authorization, and digital arrest extortion calls.

India reported **₹22,495+ crore lost to cyber fraud in 2025 (I4C)** — with over 70% of digital scams originating from fake/mule identities.

## Architecture & Multimodal Flow

```
[MODALITY 1: PHYSICAL DOCUMENT SCREENING]
   Aadhaar / PAN Image → OCR Parsing → Verhoeff Base-10 Checksum
   → Font Consistency Delta → Error Level Analysis (ELA Splicing) → Cryptographic SHA-256 Fingerprint
                                      │
                                      ├──► [MULTIMODAL RISK FUSION ENGINE]
                                      │        Risk = 0.50·R_doc + 0.50·R_voice
[MODALITY 2: ACOUSTIC BIOMETRICS]     │
   Live 16kHz Stream → Energy VAD ────┘        ├─► 🟢 IDENTITY AUTHENTIC (ALLOW)
   → 80-bin Mel-Spectrogram → PyTorch MelCNN  ├─► 🟡 SUSPICIOUS BIOMETRICS (WARN)
   → Temporal Hysteresis & Vocoder Analysis    └─► 🔴 SYNTHETIC IDENTITY DETECTED (HOLD)
   → Sec 63 BSA 2023 Digital Evidence Dossier
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

## 🚀 Live Cloud Deployment & Auto-CI/CD

The repository includes complete auto-deployment support (Render, Hugging Face Spaces, Docker):
- **Continuous Deployment (CI/CD)**: Every `git push` to `main` triggers automated testing and auto-updates the live deployment.
- **Full Guide**: See [DEPLOYMENT.md](DEPLOYMENT.md) for 1-click Render and Hugging Face deployment steps.
- **Docker**: Run locally or in cloud using `docker build -t dhwani-kavach . && docker run -p 8000:8000 dhwani-kavach`.

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