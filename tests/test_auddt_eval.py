# tests/test_auddt_eval.py
"""
Unit tests for Dhwani-Kavach AUDDT Evaluation Engine.
Verifies metric calculations, EER thresholding, model scoring, and report exports.
"""

import os
import tempfile
import numpy as np
import pytest
import torch

from ml.eval.auddt import (
    compute_eer,
    compute_auddt_metrics,
    score_audio_clip,
    export_markdown_report,
    export_pdf_report,
    export_json_metrics,
    export_predictions_csv,
    AudioSample,
    evaluate_model,
)
from ml.models.cnn import MelCNN


def test_compute_eer_perfect_separation():
    # Bonafide (0) scores: 0.1, 0.2, 0.3
    # Spoof (1) scores: 0.8, 0.9, 1.0
    y_true = np.array([0, 0, 0, 1, 1, 1])
    scores = np.array([0.1, 0.2, 0.3, 0.8, 0.9, 1.0])

    eer, eer_th, fpr, tpr, thresholds = compute_eer(y_true, scores)
    assert eer == 0.0
    assert 0.3 <= eer_th <= 0.8


def test_compute_auddt_metrics_exact_values():
    # 2 true negatives (score 0.1, 0.2), 1 false positive (score 0.7)
    # 2 true positives (score 0.8, 0.9), 1 false negative (score 0.4)
    # threshold = 0.5
    y_true = np.array([0, 0, 0, 1, 1, 1])
    scores = np.array([0.1, 0.2, 0.7, 0.8, 0.9, 0.4])

    m = compute_auddt_metrics(y_true, scores, threshold=0.5)

    assert m.tn == 2
    assert m.fp == 1
    assert m.fn == 1
    assert m.tp == 2

    # Accuracy: (2 + 2) / 6 = 4/6 = 0.6667
    assert pytest.approx(m.accuracy, 0.001) == 4 / 6

    # Precision: TP / (TP + FP) = 2 / (2 + 1) = 2/3
    assert pytest.approx(m.precision, 0.001) == 2 / 3

    # Recall: TP / (TP + FN) = 2 / (2 + 1) = 2/3
    assert pytest.approx(m.recall, 0.001) == 2 / 3

    # F1-score: 2 * (2/3 * 2/3) / (2/3 + 2/3) = 2/3
    assert pytest.approx(m.f1, 0.001) == 2 / 3

    # Specificity: TN / (TN + FP) = 2 / 3
    assert pytest.approx(m.specificity, 0.001) == 2 / 3

    # ROC-AUC must be > 0.5
    assert m.roc_auc > 0.7


def test_report_exports():
    # Create mock results structure
    mock_results = {
        "timestamp": "2026-09-24 20:00:00",
        "eval_duration_sec": 1.23,
        "total_evaluated_samples": 2,
        "bonafide_count": 1,
        "spoof_count": 1,
        "model_metadata": {
            "name": "MelCNN v2",
            "parameters": 236141,
            "architecture": "SE-ResNet MelCNN",
            "input_spec": "16kHz Mono -> LogMel",
        },
        "calibration_metadata": {
            "logit_bias": -3.677,
            "theta_lo": 0.62,
            "theta_hi": 0.90,
            "vad_min": 0.25,
        },
        "metrics": {
            "raw_uncalibrated_05": {
                "accuracy": 1.0,
                "roc_auc": 1.0,
                "eer": 0.0,
                "eer_threshold": 0.5,
                "precision": 1.0,
                "recall": 1.0,
                "f1_score": 1.0,
                "specificity": 1.0,
                "operating_threshold": 0.5,
                "confusion_matrix": {"tp": 1, "fp": 0, "tn": 1, "fn": 0},
            },
            "raw_uncalibrated_eer_opt": {
                "accuracy": 1.0,
                "roc_auc": 1.0,
                "eer": 0.0,
                "eer_threshold": 0.5,
                "precision": 1.0,
                "recall": 1.0,
                "f1_score": 1.0,
                "specificity": 1.0,
                "operating_threshold": 0.5,
                "confusion_matrix": {"tp": 1, "fp": 0, "tn": 1, "fn": 0},
            },
            "calibrated_theta_lo": {
                "accuracy": 1.0,
                "roc_auc": 1.0,
                "eer": 0.0,
                "eer_threshold": 0.62,
                "precision": 1.0,
                "recall": 1.0,
                "f1_score": 1.0,
                "specificity": 1.0,
                "operating_threshold": 0.62,
                "confusion_matrix": {"tp": 1, "fp": 0, "tn": 1, "fn": 0},
            },
        },
        "roc_curves": {
            "raw": {
                "fpr": [0.0, 0.0, 1.0],
                "tpr": [0.0, 1.0, 1.0],
                "thresholds": [1.5, 0.5, 0.0],
                "eer": 0.0,
                "eer_threshold": 0.5,
            },
            "calibrated": {
                "fpr": [0.0, 0.0, 1.0],
                "tpr": [0.0, 1.0, 1.0],
                "thresholds": [1.5, 0.62, 0.0],
                "eer": 0.0,
                "eer_threshold": 0.62,
            },
        },
        "condition_breakdown": {
            "clean": {
                "sample_count": 2,
                "bonafide_count": 1,
                "spoof_count": 1,
                "calibrated": {
                    "accuracy": 1.0,
                    "precision": 1.0,
                    "recall": 1.0,
                    "f1_score": 1.0,
                },
            }
        },
        "predictions": [
            {
                "index": 1,
                "filename": "real.wav",
                "condition": "clean",
                "ground_truth": 0,
                "ground_truth_str": "BONAFIDE",
                "raw_score": 0.05,
                "calibrated_score": 0.01,
                "pred_raw": 0,
                "pred_calibrated": 0,
                "is_correct_cal": True,
            },
            {
                "index": 2,
                "filename": "fake.wav",
                "condition": "clean",
                "ground_truth": 1,
                "ground_truth_str": "SPOOF",
                "raw_score": 0.95,
                "calibrated_score": 0.90,
                "pred_raw": 1,
                "pred_calibrated": 1,
                "is_correct_cal": True,
            },
        ],
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        md_file = os.path.join(tmpdir, "report.md")
        pdf_file = os.path.join(tmpdir, "report.pdf")
        json_file = os.path.join(tmpdir, "metrics.json")
        csv_file = os.path.join(tmpdir, "predictions.csv")

        export_markdown_report(mock_results, md_file)
        assert os.path.exists(md_file)
        with open(md_file, "r", encoding="utf-8") as fh:
            content = fh.read()
            assert "Dhwani-Kavach :: AUDDT Model Evaluation Report" in content
            assert "Accuracy (ACC)" in content
            assert "Equal Error Rate (EER)" in content

        export_pdf_report(mock_results, pdf_file)
        assert os.path.exists(pdf_file)
        assert os.path.getsize(pdf_file) > 1000

        export_json_metrics(mock_results, json_file)
        assert os.path.exists(json_file)

        export_predictions_csv(mock_results, csv_file)
        assert os.path.exists(csv_file)
