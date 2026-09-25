# Dhwani Kavach - full-scale evaluation report

Protocol: ASVspoof2019 LA `eval` split, one 4 s window per clip (AUDDT/ASVspoof clip protocol). Scores come from the live demo's own feature path; no third-party harness is imported. Every figure below was printed by this run.

| item | value |
|---|---|
| model | `results\cnn_v2\model.pt` (973,515 B, sha256 `a7aeb383a12b09ac`) |
| parameters | 236,141 |
| clips scored | 71,237 (bonafide 7,355 / spoof 63,882) |
| ROC-AUC | 0.9489 |
| EER | 88.40 % (at p=0.0091) |
| TPR @ 1 % FPR | 76.94 % |
| accuracy at tau=0.50 (uncalibrated) | 82.64 % (FPR 2.38 %) |
| accuracy at shipped theta_lo=0.62 | 74.43 % (recall 71.53 %, FPR 0.38 %) |
| calibration | bias -3.677, theta 0.62/0.90, vad_min 0.25, fitted 2026-09-09 on 29 voiced windows from ['falak.wav'] |

## Product policy (what the screen actually shows)

```json
{
  "n_per_class": {
    "0": 750,
    "1": 750
  },
  "tiers_bonafide": {
    "INSUFFICIENT_AUDIO": 1.0
  },
  "tiers_spoof": {
    "INSUFFICIENT_AUDIO": 1.0
  },
  "false_warning_rate_pct_bonafide": 0.0,
  "caught_high_or_suspicious_pct_spoof": 0.0,
  "windows_per_call_mean": 1.0,
  "no_dwell_tiers_bonafide": {
    "SAFE": 0.9987,
    "SUSPICIOUS": 0.0013
  },
  "no_dwell_tiers_spoof": {
    "SUSPICIOUS": 0.5853,
    "SAFE": 0.4147
  },
  "no_dwell_caught_pct_spoof": 58.53,
  "no_dwell_false_warning_pct_bonafide": 0.13,
  "note": "streamed exactly as the browser demo does: 1 s hop over the file, 4 s window, VAD gate, logit bias, EMA + LLR evidence, 2-window dwell. Mechanism worth knowing: the engine starts in INSUFFICIENT_AUDIO and only leaves it after 2 agreeing windows, so a 4 s clip (1 window) can never produce a verdict - that is why tiers_* is ~100% INSUFFICIENT_AUDIO on this corpus. It is a corpus property, not a product failure: real calls stream many windows. no_dwell_* repeats the same thresholds on the final call_p with the dwell rule ignored, purely so the short-clip corpus can still be read."
}
```

## Robustness by channel condition (1200 clips each)

| condition | n | EER % | AUC | dAUC vs clean | recall@theta_lo % | FPR % | note |
|---|---|---|---|---|---|---|---|
| clean | 1190 | 88.24 | 0.9416 | +0.0000 | 70.5 | 1.18 | - |
| snr20 | 1190 | 63.44 | 0.7045 | -0.2371 | 78.5 | 42.35 | - |
| snr10 | 1190 | 35.66 | 0.3574 | -0.5842 | 75.0 | 90.59 | AUC<0.5: ranking inverted, do not publish |
| snr5 | 1190 | 30.59 | 0.2546 | -0.6870 | 71.6 | 96.47 | AUC<0.5: ranking inverted, do not publish |
| dur500 | 1190 | 84.71 | 0.9206 | -0.0210 | 71.5 | 2.35 | - |
| mulaw | 1190 | 88.24 | 0.9371 | -0.0045 | 69.7 | 2.35 | - |
| alaw | 1190 | 88.24 | 0.9378 | -0.0038 | 69.8 | 2.35 | - |
| amrnb | 1190 | 87.06 | 0.9473 | +0.0057 | 74.7 | 1.18 | - |
| opus16 | 1190 | 87.06 | 0.9412 | -0.0004 | 72.9 | 1.18 | - |
| mp3_64 | 1190 | 88.24 | 0.9418 | +0.0002 | 70.8 | 1.18 | - |

## EER by attack family

| attack | n | EER % | AUC |
|---|---|---|---|
| A09 | 12269 | 99.95 | 1.0000 |
| A12 | 12269 | 99.47 | 0.9998 |
| A07 | 12269 | 98.90 | 0.9989 |
| A14 | 12269 | 98.80 | 0.9992 |
| A11 | 12269 | 98.63 | 0.9983 |
| A10 | 12269 | 98.56 | 0.9981 |
| A13 | 12269 | 97.82 | 0.9972 |
| A15 | 12269 | 97.68 | 0.9970 |
| A16 | 12269 | 96.79 | 0.9952 |
| A08 | 12269 | 93.00 | 0.9809 |
| A18 | 12269 | 82.42 | 0.9068 |
| A19 | 12269 | 81.18 | 0.8919 |
| A17 | 12269 | 55.56 | 0.5720 |

## Honest limits of this table

- The clip protocol gives the model one 4 s window. A real phone call is judged over many windows by the temporal engine, so the policy numbers above, not the EER, describe the product.
- `ml.audio.io.fix_length` pads short audio by repeating it, so a 0.5 s clip is measured as an 8x looped clip. That is product behaviour, kept on purpose, and it is why the duration row is read with that in mind.
- The calibration bias was fitted on a small set (see the calibration row). Because it is monotone it cannot move AUC or EER; it only moves the operating point, which is exactly what the two accuracy rows show.
- Bonafide share of the eval split is 10.3 %, so accuracy on its own is a weak metric here; AUC, EER and the confusion counts are the reported figures.

## Gates run by this script

| check | pass | detail |
|---|---|---|
| model-file | PASS | results\cnn_v2\model.pt  973515 B  sha256 a7aeb383a12b09ac  236,141 params |
| calibration | PASS | logit_bias=-3.677 theta_lo=0.62 theta_hi=0.9 vad_min=0.25 (fitted 2026-09-09, source ['falak.wav'], 29 voiced windows) |
| parity-vs-live-server | PASS | max |delta| = 0.00e+00 |
| manifest | PASS | share\manifest.csv -> 71237 rows with split=eval |
| corpus-mounted | PASS | 71237 of 71237 rows readable. If this is 0, C:\dhwani_data is not mounted under this folder - do not 'fix' it, tell Saniya. |
| two-classes | PASS | 7355 bonafide / 63882 spoof |
| decodable | PASS | 0/71237 clips failed to decode |
| ranking-direction | PASS | AUC 0.9489 on 71237 clips (if this is below 0.5 the labels or the checkpoint are wrong) |

_generated 2026-09-25 10:34:19 by 18_evaluate_auddt.py, git d4c66e3, torch 2.14.0+cpu, seed 20260925_
