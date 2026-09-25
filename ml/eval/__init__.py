# ml/eval/__init__.py
"""
AUDDT (Audio Unified Deepfake Detection) Evaluation Suite for Dhwani-Kavach.
Provides standardized benchmark metrics, protocol ingestion, and report generation.
"""

from .auddt import (
    AudioSample,
    AuddtMetrics,
    compute_eer,
    compute_auddt_metrics,
    evaluate_model,
    export_markdown_report,
    export_pdf_report,
    export_json_metrics,
    export_predictions_csv,
    discover_benchmark_samples,
)

__all__ = [
    "AudioSample",
    "AuddtMetrics",
    "compute_eer",
    "compute_auddt_metrics",
    "evaluate_model",
    "export_markdown_report",
    "export_pdf_report",
    "export_json_metrics",
    "export_predictions_csv",
    "discover_benchmark_samples",
]
