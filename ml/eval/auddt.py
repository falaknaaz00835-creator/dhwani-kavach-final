# ml/eval/auddt.py
"""
AUDDT (Audio Unified Deepfake Detection Benchmark Toolkit) Core Evaluation Engine
for Dhwani-Kavach Voice Impersonation Defense.

Computes:
  - Accuracy (ACC)
  - Area Under the ROC Curve (ROC-AUC)
  - Equal Error Rate (EER) + EER Threshold
  - Precision
  - Recall (Sensitivity / True Positive Rate)
  - F1-Score
  - Specificity (True Negative Rate)
  - Per-Condition & Robustness Breakdown (Clean, Telephony, Codec-Mangled)
  - Confusion Matrix (TP, FP, TN, FN)

Exports:
  - Markdown Report (.md) with formatted benchmark tables
  - Publication-Ready Vector PDF Report (.pdf) with tables, ROC curves, and score distributions
  - Machine-readable JSON (.json) conforming to AUDDT benchmark schema
  - Detailed Sample Predictions (.csv)
"""

import os
import glob
import json
import csv
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple

import numpy as np
import torch
from sklearn.metrics import (
    roc_curve,
    roc_auc_score,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    precision_recall_curve,
    average_precision_score,
)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import matplotlib.gridspec as gridspec

from ml.audio.io import load, SR, fix_length, energy_vad
from ml.features.dsp import logmel
from ml.models.cnn import MelCNN, count_params


@dataclass
class AudioSample:
    """Represents a single evaluated audio item in AUDDT protocol."""
    path: str
    label: int                  # 0: bonafide (real), 1: spoof (fake/synthetic)
    condition: str = "clean"    # clean, mulaw, opus16, alaw, amrnb, mp3, studio, etc.
    speaker: str = "unknown"
    attack: str = "none"        # A01..A19 or specific synthesis engine
    split: str = "eval"         # train, dev, eval, test


@dataclass
class AuddtMetrics:
    """Consolidated AUDDT evaluation metrics."""
    accuracy: float
    roc_auc: float
    eer: float
    eer_threshold: float
    precision: float
    recall: float
    f1: float
    specificity: float
    threshold: float
    tp: int
    fp: int
    tn: int
    fn: int
    total_samples: int
    bonafide_count: int
    spoof_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accuracy": round(self.accuracy, 4),
            "roc_auc": round(self.roc_auc, 4),
            "eer": round(self.eer, 4),
            "eer_threshold": round(self.eer_threshold, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1, 4),
            "specificity": round(self.specificity, 4),
            "operating_threshold": round(self.threshold, 4),
            "confusion_matrix": {
                "tp": self.tp,
                "fp": self.fp,
                "tn": self.tn,
                "fn": self.fn,
            },
            "sample_counts": {
                "total": self.total_samples,
                "bonafide": self.bonafide_count,
                "spoof": self.spoof_count,
            },
        }


def compute_eer(y_true: np.ndarray, scores: np.ndarray) -> Tuple[float, float, np.ndarray, np.ndarray, np.ndarray]:
    """
    Computes Equal Error Rate (EER) and the corresponding decision threshold.
    EER occurs where False Acceptance Rate (FAR) == False Rejection Rate (FRR).
    """
    if len(np.unique(y_true)) < 2:
        return 0.0, 0.5, np.array([0.0, 1.0]), np.array([0.0, 1.0]), np.array([0.5, 0.5])

    fpr, tpr, thresholds = roc_curve(y_true, scores)
    fnr = 1.0 - tpr

    # Find the index where FPR and FNR are closest
    diff = np.abs(fpr - fnr)
    min_idx = int(np.nanargmin(diff))

    # Exact linear interpolation between adjacent points if available
    if min_idx < len(fpr) - 1 and (fpr[min_idx + 1] - fpr[min_idx]) != 0:
        x1, y1 = fpr[min_idx], fnr[min_idx]
        x2, y2 = fpr[min_idx + 1], fnr[min_idx + 1]
        denom = (y2 - y1) - (x2 - x1)
        if denom != 0:
            alpha = (x1 - y1) / denom
            eer = float(x1 + alpha * (x2 - x1))
            eer_threshold = float(thresholds[min_idx] + alpha * (thresholds[min_idx + 1] - thresholds[min_idx]))
        else:
            eer = float((fpr[min_idx] + fnr[min_idx]) / 2.0)
            eer_threshold = float(thresholds[min_idx])
    else:
        eer = float((fpr[min_idx] + fnr[min_idx]) / 2.0)
        eer_threshold = float(thresholds[min_idx])

    # In sklearn roc_curve, thresholds[0] is set to max(scores) + 1.
    # Clamp threshold into valid probability range [0.0, 1.0].
    if eer_threshold > 1.0:
        if len(thresholds) > 1 and thresholds[1] <= 1.0:
            eer_threshold = float(thresholds[1])
        else:
            eer_threshold = float(np.max(scores)) if len(scores) > 0 else 0.5
    eer_threshold = float(np.clip(eer_threshold, 0.0, 1.0))

    eer = min(max(eer, 0.0), 1.0)
    return eer, eer_threshold, fpr, tpr, thresholds


def compute_auddt_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float = 0.5) -> AuddtMetrics:
    """Computes full suite of AUDDT classification and diagnostic metrics."""
    y_true = np.asarray(y_true, dtype=int)
    scores = np.asarray(scores, dtype=float)

    n_samples = len(y_true)
    n_bonafide = int(np.sum(y_true == 0))
    n_spoof = int(np.sum(y_true == 1))

    # Binary predictions using specified threshold with float tolerance
    y_pred = (scores >= (threshold - 1e-6)).astype(int)

    # ACC
    acc = float(accuracy_score(y_true, y_pred))

    # ROC-AUC
    if len(np.unique(y_true)) >= 2:
        auc = float(roc_auc_score(y_true, scores))
        eer, eer_th, _, _, _ = compute_eer(y_true, scores)
    else:
        auc = 1.0 if (n_spoof == 0 and np.all(scores < threshold)) or (n_bonafide == 0 and np.all(scores >= threshold)) else 0.5
        eer, eer_th = 0.0, threshold

    # Confusion matrix
    if len(np.unique(y_true)) >= 2:
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    else:
        # Edge case
        tp = int(np.sum((y_true == 1) & (y_pred == 1)))
        fp = int(np.sum((y_true == 0) & (y_pred == 1)))
        tn = int(np.sum((y_true == 0) & (y_pred == 0)))
        fn = int(np.sum((y_true == 1) & (y_pred == 0)))

    # Precision, Recall, F1
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    # Specificity (True Negative Rate)
    specificity = float(tn / (tn + fp)) if (tn + fp) > 0 else 1.0

    return AuddtMetrics(
        accuracy=acc,
        roc_auc=auc,
        eer=eer,
        eer_threshold=eer_th,
        precision=prec,
        recall=rec,
        f1=f1,
        specificity=specificity,
        threshold=threshold,
        tp=int(tp),
        fp=int(fp),
        tn=int(tn),
        fn=int(fn),
        total_samples=n_samples,
        bonafide_count=n_bonafide,
        spoof_count=n_spoof,
    )


def score_audio_clip(
    model: torch.nn.Module,
    path: str,
    logit_bias: float = 0.0,
    vad_min: float = 0.25,
    need_seconds: float = 4.0,
    hop_seconds: float = 2.0,
    device: str = "cpu",
) -> Dict[str, Any]:
    """
    Extracts logmel windows and computes raw and calibrated scores for an audio clip.
    Follows Dhwani-Kavach real-time windowing pipeline.
    """
    y = load(path, sr=SR)
    need = int(need_seconds * SR)
    hop = int(hop_seconds * SR)

    if len(y) < need:
        y = fix_length(y, need)

    raw_scores = []
    raw_logits = []
    cal_scores = []
    cal_logits = []
    voiced_windows = 0
    total_windows = 0

    for start in range(0, max(len(y) - need + 1, 1), hop):
        w = y[start:start + need]
        if len(w) < need:
            w = np.pad(w, (0, need - len(w)))
        total_windows += 1

        vfrac = float(energy_vad(w).mean())
        if vfrac >= vad_min:
            voiced_windows += 1
            x = logmel(w)
            x = (x - x.mean()) / (x.std() + 1e-6)
            xb = torch.from_numpy(x[None, None, ...]).to(device)

            with torch.no_grad():
                logit_val = float(model(xb).cpu().item())

            raw_prob = float(torch.sigmoid(torch.tensor(logit_val)).item())
            cal_logit_val = logit_val + logit_bias
            cal_prob = float(torch.sigmoid(torch.tensor(cal_logit_val)).item())

            raw_logits.append(logit_val)
            raw_scores.append(raw_prob)
            cal_logits.append(cal_logit_val)
            cal_scores.append(cal_prob)

    # Fallback if no voiced window passed VAD threshold
    if not raw_scores:
        x = logmel(y[:need])
        x = (x - x.mean()) / (x.std() + 1e-6)
        xb = torch.from_numpy(x[None, None, ...]).to(device)
        with torch.no_grad():
            logit_val = float(model(xb).cpu().item())
        raw_prob = float(torch.sigmoid(torch.tensor(logit_val)).item())
        cal_logit_val = logit_val + logit_bias
        cal_prob = float(torch.sigmoid(torch.tensor(cal_logit_val)).item())
        raw_logits.append(logit_val)
        raw_scores.append(raw_prob)
        cal_logits.append(cal_logit_val)
        cal_scores.append(cal_prob)
        voiced_windows = 1

    return {
        "raw_score": float(np.mean(raw_scores)),
        "raw_logit": float(np.mean(raw_logits)),
        "calibrated_score": float(np.mean(cal_scores)),
        "calibrated_logit": float(np.mean(cal_logits)),
        "voiced_windows": voiced_windows,
        "total_windows": total_windows,
        "max_window_raw": float(np.max(raw_scores)),
        "min_window_raw": float(np.min(raw_scores)),
    }


def discover_benchmark_samples(base_dir: str = ".") -> List[AudioSample]:
    """
    Auto-discovers and categorizes available benchmark and test audio clips in the repository.
    Handles demo studio files, team voice recordings, inspect slices, and codec tests.
    """
    samples: List[AudioSample] = []
    seen_paths = set()

    def add_sample(path: str, label: int, condition: str, speaker: str, attack: str):
        abs_p = os.path.abspath(path)
        if os.path.exists(abs_p) and abs_p not in seen_paths:
            seen_paths.add(abs_p)
            samples.append(AudioSample(
                path=abs_p,
                label=label,
                condition=condition,
                speaker=speaker,
                attack=attack,
                split="eval",
            ))

    # 1. Official Demo Studio Pair (Verified reference baseline)
    demo_real = os.path.join(base_dir, "results", "demo", "demo_real_studio.wav")
    demo_fake = os.path.join(base_dir, "results", "demo", "demo_fake_studio.wav")
    add_sample(demo_real, 0, "clean_studio", "studio_speaker", "none")
    add_sample(demo_fake, 1, "clean_studio", "studio_speaker", "neural_clone")

    # 2. Team Voice Enrolments (Real speakers)
    for p in glob.glob(os.path.join(base_dir, "data", "team", "*.wav")):
        bname = os.path.splitext(os.path.basename(p))[0].lower()
        if any(k in bname for k in ["fake", "ai", "clone", "spoof", "tts"]):
            add_sample(p, 1, "team_spoof", bname, "synthetic_team")
        else:
            add_sample(p, 0, "team_real", bname, "none")

    # 3. Personal Voice Enrolment
    my_voice = os.path.join(base_dir, "data", "my_voice.wav")
    add_sample(my_voice, 0, "my_voice", "falak", "none")

    # 4. Codec Robustness Audio Tests
    codec_map = {
        "mulaw": ("telephony_mulaw", 0),
        "alaw": ("telephony_alaw", 0),
        "amrnb": ("telephony_amrnb", 0),
        "opus16": ("voip_opus16", 0),
        "mp3_64": ("lossy_mp3", 0),
        "in": ("clean_reference", 0),
    }
    for p in glob.glob(os.path.join(base_dir, "results", "codec_test", "*.*")):
        if p.endswith((".wav", ".mp3")):
            bname = os.path.basename(p).lower()
            matched_cond = "codec_unknown"
            lbl = 0
            for k, (cname, clbl) in codec_map.items():
                if k in bname:
                    matched_cond = cname
                    lbl = clbl
                    break
            add_sample(p, lbl, matched_cond, "myvoice_codec", "codec_transcode")

    # 5. Inspect Slices (AI vs Real slice benchmarks)
    for p in glob.glob(os.path.join(base_dir, "results", "inspect", "*.wav")):
        bname = os.path.basename(p).lower()
        if "ai" in bname or "fake" in bname:
            add_sample(p, 1, "inspect_ai", "inspect_synth", "tts_slice")
        else:
            add_sample(p, 0, "inspect_real", "saniya_slice", "none")

    return samples


def parse_manifest_or_dir(input_path: str) -> List[AudioSample]:
    """
    Parses an AUDDT manifest CSV, ASVspoof protocol TXT, or recursively scans a directory.
    """
    samples: List[AudioSample] = []
    input_path = os.path.abspath(input_path)

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input path does not exist: {input_path}")

    # Case A: Directory
    if os.path.isdir(input_path):
        for root, _, files in os.walk(input_path):
            for file in files:
                if file.lower().endswith((".wav", ".flac", ".mp3", ".ogg")):
                    full_p = os.path.join(root, file)
                    bname = os.path.splitext(file)[0].lower()
                    rname = os.path.basename(root).lower()

                    # Infer label from folder or file name
                    if any(k in bname for k in ["fake", "ai", "clone", "spoof", "tts", "synthetic"]) or \
                       any(k in rname for k in ["fake", "spoof", "synthetic", "ai"]):
                        lbl = 1
                    else:
                        lbl = 0

                    cond = "clean"
                    if "mulaw" in bname or "mulaw" in rname:
                        cond = "mulaw"
                    elif "opus" in bname or "opus" in rname:
                        cond = "opus16"
                    elif "amr" in bname or "amr" in rname:
                        cond = "amrnb"

                    samples.append(AudioSample(
                        path=full_p,
                        label=lbl,
                        condition=cond,
                        speaker=bname.split("_")[0],
                        attack="unknown" if lbl == 1 else "none",
                        split="eval",
                    ))
        return samples

    # Case B: File (CSV or protocol TXT)
    if input_path.endswith(".csv"):
        with open(input_path, "r", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for r in reader:
                lbl_str = str(r.get("label", "")).lower()
                lbl = 1 if lbl_str in ("spoof", "fake", "1", "synthetic") else 0
                samples.append(AudioSample(
                    path=r.get("path", ""),
                    label=lbl,
                    condition=r.get("condition", "clean"),
                    speaker=r.get("speaker", "unknown"),
                    attack=r.get("attack", "none"),
                    split=r.get("split", "eval"),
                ))
        return samples

    # Case C: ASVspoof Protocol TXT format
    with open(input_path, "r", encoding="utf-8", errors="replace") as fh:
        base_parent = os.path.dirname(input_path)
        for line in fh:
            parts = line.strip().split()
            if len(parts) < 4:
                continue
            lbl_str = parts[-1].lower()
            if lbl_str not in ("bonafide", "spoof"):
                continue
            lbl = 1 if lbl_str == "spoof" else 0
            speaker = parts[0]
            utt = parts[1]
            attack = "none"
            for p in parts[2:-1]:
                if p != "-":
                    attack = p
                    break
            # Look for flac/wav in sibling or standard dirs
            audio_path = os.path.join(base_parent, "flac", utt + ".flac")
            if not os.path.exists(audio_path):
                audio_path = os.path.join(base_parent, utt + ".wav")
            samples.append(AudioSample(
                path=audio_path,
                label=lbl,
                condition="clean",
                speaker=speaker,
                attack=attack,
                split="eval",
            ))

    return samples


def evaluate_model(
    model: torch.nn.Module,
    samples: List[AudioSample],
    calibration_config: Optional[Dict[str, Any]] = None,
    device: str = "cpu",
    vad_min: float = 0.25,
) -> Dict[str, Any]:
    """
    Executes AUDDT benchmark evaluation:
      - Raw Model Metrics (Threshold 0.50)
      - Calibrated Model Metrics (Threshold theta_lo or calibrated bias)
      - Optimal Operating Point Metrics (EER Threshold)
      - Per-Condition & Robustness Breakdown
      - Per-sample Prediction Details
    """
    model.eval()
    model.to(device)

    cal = calibration_config or {}
    logit_bias = float(cal.get("logit_bias", 0.0))
    theta_lo = float(cal.get("theta_lo", 0.62))
    theta_hi = float(cal.get("theta_hi", 0.90))

    y_true_list = []
    raw_scores_list = []
    cal_scores_list = []
    predictions_table = []

    t_start = time.time()

    for idx, s in enumerate(samples):
        if not os.path.exists(s.path):
            continue

        score_dict = score_audio_clip(
            model=model,
            path=s.path,
            logit_bias=logit_bias,
            vad_min=vad_min,
            device=device,
        )

        p_raw = score_dict["raw_score"]
        p_cal = score_dict["calibrated_score"]

        y_true_list.append(s.label)
        raw_scores_list.append(p_raw)
        cal_scores_list.append(p_cal)

        pred_raw_lbl = 1 if p_raw >= 0.50 else 0
        pred_cal_lbl = 1 if p_cal >= theta_lo else 0

        predictions_table.append({
            "index": idx + 1,
            "filename": os.path.basename(s.path),
            "filepath": s.path,
            "condition": s.condition,
            "ground_truth": s.label,
            "ground_truth_str": "SPOOF" if s.label == 1 else "BONAFIDE",
            "raw_score": round(p_raw, 4),
            "raw_logit": round(score_dict["raw_logit"], 4),
            "calibrated_score": round(p_cal, 4),
            "calibrated_logit": round(score_dict["calibrated_logit"], 4),
            "pred_raw": pred_raw_lbl,
            "pred_calibrated": pred_cal_lbl,
            "is_correct_raw": bool(pred_raw_lbl == s.label),
            "is_correct_cal": bool(pred_cal_lbl == s.label),
            "voiced_windows": score_dict["voiced_windows"],
            "total_windows": score_dict["total_windows"],
        })

    eval_duration = time.time() - t_start

    y_true = np.array(y_true_list)
    raw_scores = np.array(raw_scores_list)
    cal_scores = np.array(cal_scores_list)

    if len(y_true) == 0:
        raise ValueError("No valid audio files found for evaluation!")

    # 1. Global Metrics
    raw_metrics_05 = compute_auddt_metrics(y_true, raw_scores, threshold=0.50)
    raw_eer, raw_eer_th, raw_fpr, raw_tpr, raw_th = compute_eer(y_true, raw_scores)
    raw_metrics_eer = compute_auddt_metrics(y_true, raw_scores, threshold=raw_eer_th)

    cal_metrics_th = compute_auddt_metrics(y_true, cal_scores, threshold=theta_lo)
    cal_eer, cal_eer_th, cal_fpr, cal_tpr, cal_th = compute_eer(y_true, cal_scores)

    # 2. Per-Condition Robustness Breakdown
    conditions = sorted(set(s["condition"] for s in predictions_table))
    condition_breakdown = {}

    for cond in conditions:
        c_preds = [p for p in predictions_table if p["condition"] == cond]
        c_y_true = np.array([p["ground_truth"] for p in c_preds])
        c_raw_scores = np.array([p["raw_score"] for p in c_preds])
        c_cal_scores = np.array([p["calibrated_score"] for p in c_preds])

        c_raw_m = compute_auddt_metrics(c_y_true, c_raw_scores, threshold=0.50)
        c_cal_m = compute_auddt_metrics(c_y_true, c_cal_scores, threshold=theta_lo)

        condition_breakdown[cond] = {
            "sample_count": len(c_preds),
            "bonafide_count": int(np.sum(c_y_true == 0)),
            "spoof_count": int(np.sum(c_y_true == 1)),
            "raw": c_raw_m.to_dict(),
            "calibrated": c_cal_m.to_dict(),
        }

    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "eval_duration_sec": round(eval_duration, 2),
        "total_evaluated_samples": len(predictions_table),
        "bonafide_count": int(np.sum(y_true == 0)),
        "spoof_count": int(np.sum(y_true == 1)),
        "model_metadata": {
            "name": "MelCNN v2",
            "parameters": count_params(model),
            "architecture": "4-Block SE-ResNet-Style MelCNN + Adaptive Stats Pooling + MLP Head",
            "input_spec": "16kHz Mono -> 80-bin Log-Mel Spectrogram -> 4.0s Window",
        },
        "calibration_metadata": {
            "logit_bias": logit_bias,
            "theta_lo": theta_lo,
            "theta_hi": theta_hi,
            "vad_min": vad_min,
        },
        "metrics": {
            "raw_uncalibrated_05": raw_metrics_05.to_dict(),
            "raw_uncalibrated_eer_opt": raw_metrics_eer.to_dict(),
            "calibrated_theta_lo": cal_metrics_th.to_dict(),
        },
        "roc_curves": {
            "raw": {
                "fpr": raw_fpr.tolist(),
                "tpr": raw_tpr.tolist(),
                "thresholds": raw_th.tolist(),
                "eer": round(raw_eer, 4),
                "eer_threshold": round(raw_eer_th, 4),
            },
            "calibrated": {
                "fpr": cal_fpr.tolist(),
                "tpr": cal_tpr.tolist(),
                "thresholds": cal_th.tolist(),
                "eer": round(cal_eer, 4),
                "eer_threshold": round(cal_eer_th, 4),
            },
        },
        "condition_breakdown": condition_breakdown,
        "predictions": predictions_table,
    }


def export_markdown_report(results: Dict[str, Any], output_path: str):
    """Generates an AUDDT-standard GitHub-flavored Markdown evaluation report."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    meta = results["model_metadata"]
    cal = results["calibration_metadata"]
    m_raw = results["metrics"]["raw_uncalibrated_05"]
    m_cal = results["metrics"]["calibrated_theta_lo"]
    m_eer = results["metrics"]["raw_uncalibrated_eer_opt"]
    conds = results["condition_breakdown"]

    lines = []
    lines.append("# 🛡️ Dhwani-Kavach :: AUDDT Model Evaluation Report")
    lines.append("")
    lines.append("> **Benchmark Framework:** Audio Unified Deepfake Detection (AUDDT) Protocol  ")
    lines.append(f"> **Evaluation Run Date:** `{results['timestamp']}`  ")
    lines.append(f"> **Model Checkpoint:** `{meta['name']}` ({meta['parameters']:,} parameters)  ")
    lines.append(f"> **Test Corpus Size:** {results['total_evaluated_samples']} audio files "
                 f"({results['bonafide_count']} Bonafide Real, {results['spoof_count']} Spoof Fake)")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 1. Executive Metrics Comparison Table")
    lines.append("")
    lines.append("This table compares the **Raw CNN v2 Model** ($\\tau=0.50$), the **Calibrated Defense System** "
                 f"($\\text{{Bias}}={cal['logit_bias']}, \\tau=\\theta_{{\\text{{lo}}}}={cal['theta_lo']}$), "
                 f"and the **Theoretical Optimal Operating Point** ($\\tau_{{\\text{{EER}}}}={m_eer['operating_threshold']}$).")
    lines.append("")
    lines.append("| Metric | Raw Uncalibrated ($\\tau=0.50$) | Calibrated System ($\\tau=\\theta_{\\text{lo}}$) | Optimal EER Point | AUDDT Target |")
    lines.append("|:---|:---:|:---:|:---:|:---:|")
    lines.append(f"| **Accuracy (ACC)** | `{m_raw['accuracy']*100:.2f}%` | `{m_cal['accuracy']*100:.2f}%` | `{m_eer['accuracy']*100:.2f}%` | $\\ge 90.0\%$ |")
    lines.append(f"| **ROC-AUC** | `{m_raw['roc_auc']:.4f}` | `{m_cal['roc_auc']:.4f}` | `{m_eer['roc_auc']:.4f}` | $\\ge 0.950$ |")
    lines.append(f"| **Equal Error Rate (EER)** | `{m_raw['eer']*100:.2f}%` | `{m_cal['eer']*100:.2f}%` | `{m_eer['eer']*100:.2f}%` | $\\le 10.0\%$ |")
    lines.append(f"| **Precision (Spoof)** | `{m_raw['precision']*100:.2f}%` | `{m_cal['precision']*100:.2f}%` | `{m_eer['precision']*100:.2f}%` | $\\ge 90.0\%$ |")
    lines.append(f"| **Recall (Sensitivity / TPR)** | `{m_raw['recall']*100:.2f}%` | `{m_cal['recall']*100:.2f}%` | `{m_eer['recall']*100:.2f}%` | $\\ge 90.0\%$ |")
    lines.append(f"| **F1-Score** | `{m_raw['f1_score']:.4f}` | `{m_cal['f1_score']:.4f}` | `{m_eer['f1_score']:.4f}` | $\\ge 0.900$ |")
    lines.append(f"| **Specificity (TNR)** | `{m_raw['specificity']*100:.2f}%` | `{m_cal['specificity']*100:.2f}%` | `{m_eer['specificity']*100:.2f}%` | $\\ge 95.0\%$ |")
    lines.append(f"| **Operating Threshold ($\\tau$)** | `{m_raw['operating_threshold']:.2f}` | `{m_cal['operating_threshold']:.2f}` | `{m_eer['operating_threshold']:.2f}` | — |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 2. Confusion Matrix Diagnostics")
    lines.append("")
    lines.append("### A. Raw Model Confusion Matrix")
    lines.append("| True \\ Predicted | Predicted Bonafide (Safe) | Predicted Spoof (Alert) |")
    lines.append("|:---|:---:|:---:|")
    lines.append(f"| **Actual Bonafide (Real)** | **TN = {m_raw['confusion_matrix']['tn']}** | FP = {m_raw['confusion_matrix']['fp']} |")
    lines.append(f"| **Actual Spoof (Fake)** | FN = {m_raw['confusion_matrix']['fn']} | **TP = {m_raw['confusion_matrix']['tp']}** |")
    lines.append("")
    lines.append("### B. Calibrated System Confusion Matrix")
    lines.append("| True \\ Predicted | Predicted Bonafide (Safe) | Predicted Spoof (Alert) |")
    lines.append("|:---|:---:|:---:|")
    lines.append(f"| **Actual Bonafide (Real)** | **TN = {m_cal['confusion_matrix']['tn']}** | FP = {m_cal['confusion_matrix']['fp']} |")
    lines.append(f"| **Actual Spoof (Fake)** | FN = {m_cal['confusion_matrix']['fn']} | **TP = {m_cal['confusion_matrix']['tp']}** |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 3. Subgroup & Codec Robustness Breakdown")
    lines.append("")
    lines.append("| Evaluation Condition | Samples (Real / Fake) | Calibrated ACC | Calibrated Precision | Calibrated Recall | Calibrated F1 |")
    lines.append("|:---|:---:|:---:|:---:|:---:|:---:|")
    for cond_name, c_data in conds.items():
        cm = c_data["calibrated"]
        lines.append(f"| **{cond_name}** | {c_data['sample_count']} ({c_data['bonafide_count']}R / {c_data['spoof_count']}F) | "
                     f"`{cm['accuracy']*100:.1f}%` | `{cm['precision']*100:.1f}%` | `{cm['recall']*100:.1f}%` | `{cm['f1_score']:.4f}` |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 4. Calibration Parameters in Effect")
    lines.append("")
    lines.append(f"- **Logit Bias:** `{cal['logit_bias']}` (shifts real voice logits away from false-alarm trigger point)")
    lines.append(f"- **Warning Threshold ($\\theta_{{\\text{{lo}}}}$):** `{cal['theta_lo']}` (Suspicious verdict)")
    lines.append(f"- **High-Risk Threshold ($\\theta_{{\\text{{hi}}}}$):** `{cal['theta_hi']}` (High-Risk alert trigger)")
    lines.append(f"- **Energy VAD Minimum Fraction:** `{cal['vad_min']}` (discards silent/pause frames)")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 5. Sample-Level Evaluation Audit Log")
    lines.append("")
    lines.append("| File | Condition | Actual Label | Raw Score | Calibrated Score | Calibrated Verdict | Status |")
    lines.append("|:---|:---|:---:|:---:|:---:|:---:|:---:|")
    for p in results["predictions"]:
        status_badge = "✅ PASS" if p["is_correct_cal"] else "⚠️ MISS/FA"
        lines.append(f"| `{p['filename']}` | `{p['condition']}` | `{p['ground_truth_str']}` | `{p['raw_score']:.4f}` | `{p['calibrated_score']:.4f}` | `{'SPOOF' if p['pred_calibrated'] == 1 else 'BONAFIDE'}` | {status_badge} |")
    lines.append("")
    lines.append("---")
    lines.append("*Generated automatically by Dhwani-Kavach AUDDT Evaluation Engine.*")

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def export_pdf_report(results: Dict[str, Any], output_path: str):
    """
    Generates a publication-grade 2-page PDF evaluation report containing
    styled tables, ROC curves, and score distribution diagnostics.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    meta = results["model_metadata"]
    cal = results["calibration_metadata"]
    m_raw = results["metrics"]["raw_uncalibrated_05"]
    m_cal = results["metrics"]["calibrated_theta_lo"]
    m_eer = results["metrics"]["raw_uncalibrated_eer_opt"]
    conds = results["condition_breakdown"]
    roc_data = results["roc_curves"]["raw"]

    with PdfPages(output_path) as pdf:
        # ================= PAGE 1: Executive Dashboard & Tables =================
        fig = plt.figure(figsize=(11, 8.5), dpi=300)
        fig.patch.set_facecolor("#FFFFFF")

        # Titles and banner via fig.text
        fig.text(0.5, 0.945, "DHWANI-KAVACH — AUDDT EVALUATION REPORT",
                 ha="center", va="center", fontsize=18, fontweight="bold", color="#1E3A8A")
        fig.text(0.5, 0.912, "Standardized Audio Deepfake Detection Benchmark (SIH26104)",
                 ha="center", va="center", fontsize=11, color="#475569")
        fig.text(0.5, 0.882, f"Model: {meta['name']} ({meta['parameters']:,} params) | Evaluated Samples: {results['total_evaluated_samples']} | Date: {results['timestamp']}",
                 ha="center", va="center", fontsize=9.5, color="#64748B")

        # Divider line
        line = plt.Line2D([0.06, 0.94], [0.862, 0.862], transform=fig.transFigure, color="#1E3A8A", linewidth=2.0)
        fig.add_artist(line)

        # 1. Primary Metrics Table
        ax_table = fig.add_axes([0.06, 0.50, 0.88, 0.32])
        ax_table.axis("off")
        ax_table.text(0.0, 1.05, "1. Primary Performance Metrics Comparison", fontsize=12, fontweight="bold",
                      color="#1E293B", ha="left")

        table_data = [
            ["Metric", "Raw (τ = 0.50)", "Calibrated (Bias/θ_lo)", "Optimal EER Point", "AUDDT Benchmark Target"],
            ["Accuracy (ACC)", f"{m_raw['accuracy']*100:.2f}%", f"{m_cal['accuracy']*100:.2f}%", f"{m_eer['accuracy']*100:.2f}%", "≥ 90.0%"],
            ["ROC-AUC", f"{m_raw['roc_auc']:.4f}", f"{m_cal['roc_auc']:.4f}", f"{m_eer['roc_auc']:.4f}", "≥ 0.950"],
            ["Equal Error Rate (EER)", f"{m_raw['eer']*100:.2f}%", f"{m_cal['eer']*100:.2f}%", f"{m_eer['eer']*100:.2f}%", "≤ 10.0%"],
            ["Precision (Spoof)", f"{m_raw['precision']*100:.2f}%", f"{m_cal['precision']*100:.2f}%", f"{m_eer['precision']*100:.2f}%", "≥ 90.0%"],
            ["Recall (TPR)", f"{m_raw['recall']*100:.2f}%", f"{m_cal['recall']*100:.2f}%", f"{m_eer['recall']*100:.2f}%", "≥ 90.0%"],
            ["F1-Score", f"{m_raw['f1_score']:.4f}", f"{m_cal['f1_score']:.4f}", f"{m_eer['f1_score']:.4f}", "≥ 0.900"],
            ["Specificity (TNR)", f"{m_raw['specificity']*100:.2f}%", f"{m_cal['specificity']*100:.2f}%", f"{m_eer['specificity']*100:.2f}%", "≥ 95.0%"],
        ]

        t_elem = ax_table.table(cellText=table_data, loc="center", cellLoc="center")
        t_elem.auto_set_font_size(False)
        t_elem.set_fontsize(9.5)
        t_elem.scale(1.0, 1.45)

        for (row_idx, col_idx), cell in t_elem.get_celld().items():
            if row_idx == 0:
                cell.set_facecolor("#1E3A8A")
                cell.get_text().set_color("#FFFFFF")
                cell.get_text().set_weight("bold")
            else:
                cell.set_facecolor("#F8FAFC" if row_idx % 2 == 1 else "#FFFFFF")
                cell.get_text().set_color("#0F172A")
                if col_idx == 0:
                    cell.get_text().set_weight("bold")
                    cell.get_text().set_ha("left")

        # 2. Subgroup / Condition Table (Left)
        ax_sub = fig.add_axes([0.06, 0.08, 0.46, 0.35])
        ax_sub.axis("off")
        ax_sub.text(0.0, 1.05, "2. Robustness Breakdown by Audio Condition", fontsize=11, fontweight="bold",
                    color="#1E293B", ha="left")

        sub_rows = [["Condition", "N", "ACC", "Precision", "Recall", "F1"]]
        for cname, cinfo in list(conds.items())[:6]:
            cm = cinfo["calibrated"]
            sub_rows.append([
                cname[:16],
                str(cinfo["sample_count"]),
                f"{cm['accuracy']*100:.1f}%",
                f"{cm['precision']*100:.1f}%",
                f"{cm['recall']*100:.1f}%",
                f"{cm['f1_score']:.3f}",
            ])

        t_sub = ax_sub.table(cellText=sub_rows, loc="center", cellLoc="center")
        t_sub.auto_set_font_size(False)
        t_sub.set_fontsize(8.5)
        t_sub.scale(1.0, 1.35)
        for (row_idx, col_idx), cell in t_sub.get_celld().items():
            if row_idx == 0:
                cell.set_facecolor("#334155")
                cell.get_text().set_color("#FFFFFF")
                cell.get_text().set_weight("bold")
            else:
                cell.set_facecolor("#F1F5F9" if row_idx % 2 == 1 else "#FFFFFF")

        # 3. Confusion Matrix Cards (Right)
        ax_cm = fig.add_axes([0.56, 0.08, 0.38, 0.35])
        ax_cm.axis("off")
        ax_cm.text(0.0, 1.05, "3. Calibrated Confusion Matrix", fontsize=11, fontweight="bold",
                   color="#1E293B", ha="left")

        cm_rows = [
            ["Actual \\ Pred", "Bonafide (Safe)", "Spoof (Alert)"],
            ["Bonafide (Real)", f"TN = {m_cal['confusion_matrix']['tn']}", f"FP = {m_cal['confusion_matrix']['fp']}"],
            ["Spoof (Fake)", f"FN = {m_cal['confusion_matrix']['fn']}", f"TP = {m_cal['confusion_matrix']['tp']}"],
        ]
        t_cm = ax_cm.table(cellText=cm_rows, loc="center", cellLoc="center")
        t_cm.auto_set_font_size(False)
        t_cm.set_fontsize(9.5)
        t_cm.scale(1.0, 1.6)
        for (r_i, c_i), cell in t_cm.get_celld().items():
            if r_i == 0 or c_i == 0:
                cell.set_facecolor("#E2E8F0")
                cell.get_text().set_weight("bold")
            elif r_i == 1 and c_i == 1:
                cell.set_facecolor("#DCFCE7")  # TN light green
                cell.get_text().set_weight("bold")
            elif r_i == 2 and c_i == 2:
                cell.set_facecolor("#DBEAFE")  # TP light blue
                cell.get_text().set_weight("bold")
            elif (r_i == 1 and c_i == 2) or (r_i == 2 and c_i == 1):
                cell.set_facecolor("#FEE2E2")  # FP/FN light red

        # Footer
        fig.text(0.5, 0.02, "Dhwani-Kavach Team VERITAS · Smart India Hackathon 2026 · Confidential & Reproducible Evidence",
                 ha="center", va="center", fontsize=8.5, color="#64748B", style="italic")

        png_p1 = os.path.splitext(output_path)[0] + "_page1.png"
        fig.savefig(png_p1, dpi=200, bbox_inches="tight")
        pdf.savefig(fig)
        plt.close(fig)

        # ================= PAGE 2: ROC & Score Distribution Diagnostics =================
        fig2, (ax_roc, ax_dist) = plt.subplots(1, 2, figsize=(11, 8.5), dpi=300)
        fig2.patch.set_facecolor("#FFFFFF")
        fig2.suptitle("DHWANI-KAVACH — FORENSIC & DIAGNOSTIC VISUALIZATIONS",
                      fontsize=15, fontweight="bold", color="#1E3A8A", y=0.96)

        # A. ROC Curve
        fpr = np.array(roc_data["fpr"])
        tpr = np.array(roc_data["tpr"])
        auc_val = m_raw["roc_auc"]
        eer_val = m_raw["eer"]

        ax_roc.plot(fpr, tpr, color="#2563EB", linewidth=2.5, label=f"ROC Curve (AUC = {auc_val:.4f})")
        ax_roc.plot([0, 1], [0, 1], color="#94A3B8", linestyle="--", linewidth=1.5, label="Chance Line")
        ax_roc.plot([0, 1], [1, 0], color="#DC2626", linestyle=":", linewidth=1.2, label=f"EER Balance (EER = {eer_val*100:.1f}%)")
        ax_roc.scatter([eer_val], [1 - eer_val], color="#DC2626", s=90, zorder=5, label=f"Operating Point EER")

        ax_roc.set_title("Receiver Operating Characteristic (ROC)", fontsize=12, fontweight="bold", pad=10)
        ax_roc.set_xlabel("False Positive Rate (FPR / False Alarm Rate)", fontsize=10)
        ax_roc.set_ylabel("True Positive Rate (TPR / Sensitivity)", fontsize=10)
        ax_roc.set_xlim([-0.02, 1.02])
        ax_roc.set_ylim([-0.02, 1.02])
        ax_roc.grid(True, linestyle="--", alpha=0.5)
        ax_roc.legend(loc="lower right", fontsize=9)

        # B. Score Distribution & Calibration Thresholds
        raw_bonafide = [p["raw_score"] for p in results["predictions"] if p["ground_truth"] == 0]
        raw_spoof = [p["raw_score"] for p in results["predictions"] if p["ground_truth"] == 1]
        cal_bonafide = [p["calibrated_score"] for p in results["predictions"] if p["ground_truth"] == 0]
        cal_spoof = [p["calibrated_score"] for p in results["predictions"] if p["ground_truth"] == 1]

        bins = np.linspace(0.0, 1.0, 15)
        if raw_bonafide:
            ax_dist.hist(cal_bonafide, bins=bins, alpha=0.6, color="#16A34A", label="Bonafide (Real Voice)")
        if raw_spoof:
            ax_dist.hist(cal_spoof, bins=bins, alpha=0.6, color="#DC2626", label="Spoof (AI/Clone Voice)")

        ax_dist.axvline(x=cal["theta_lo"], color="#D97706", linestyle="--", linewidth=2.0,
                        label=f"Warning (θ_lo = {cal['theta_lo']})")
        ax_dist.axvline(x=cal["theta_hi"], color="#991B1B", linestyle="-.", linewidth=2.0,
                        label=f"High Risk (θ_hi = {cal['theta_hi']})")

        ax_dist.set_title("Calibrated Score Distribution & Thresholds", fontsize=12, fontweight="bold", pad=10)
        ax_dist.set_xlabel("Calibrated AI Impersonation Score", fontsize=10)
        ax_dist.set_ylabel("Sample Frequency Count", fontsize=10)
        ax_dist.set_xlim([0.0, 1.0])
        ax_dist.grid(True, linestyle="--", alpha=0.5)
        ax_dist.legend(loc="upper center", fontsize=9)

        plt.subplots_adjust(top=0.88, bottom=0.12, left=0.10, right=0.92, wspace=0.25)
        png_p2 = os.path.splitext(output_path)[0] + "_page2.png"
        fig2.savefig(png_p2, dpi=200, bbox_inches="tight")
        pdf.savefig(fig2)
        plt.close(fig2)


def export_json_metrics(results: Dict[str, Any], output_path: str):
    """Exports AUDDT-compliant JSON metrics file."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    # Exclude verbose ROC arrays from top-level summary if needed
    clean_dict = {
        "timestamp": results["timestamp"],
        "eval_duration_sec": results["eval_duration_sec"],
        "total_evaluated_samples": results["total_evaluated_samples"],
        "bonafide_count": results["bonafide_count"],
        "spoof_count": results["spoof_count"],
        "model_metadata": results["model_metadata"],
        "calibration_metadata": results["calibration_metadata"],
        "metrics": results["metrics"],
        "condition_breakdown": results["condition_breakdown"],
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(clean_dict, fh, indent=2)


def export_predictions_csv(results: Dict[str, Any], output_path: str):
    """Exports per-sample predictions table to CSV."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    preds = results["predictions"]
    if not preds:
        return
    fieldnames = list(preds[0].keys())
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(preds)
