# ml/engine/voiceprint.py
# TWIST A - family voiceprint verification (consent-first, on-device).

import os

import numpy as np
import librosa

from ml.audio.io import SR

STORE = os.path.join("data", "voiceprints")
N_MELS = 40


def extract_print(y, sr=SR):
    S = librosa.feature.melspectrogram(y=y, sr=sr, n_fft=512, hop_length=160,
                                       n_mels=N_MELS, power=2.0)
    Sdb = librosa.power_to_db(S, ref=1.0)
    timbre = Sdb.mean(axis=1)
    timbre = (timbre - timbre.mean()) / (timbre.std() + 1e-9)
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
    path = os.path.join(STORE, name + ".npz")
    if not os.path.exists(path):
        return {"error": f"no enrolment found for '{name}'"}
    probe = extract_print(y)

    stored = {n: np.load(os.path.join(STORE, n + ".npz"))["mean"]
              for n in enrolled_names()}
    centred_mean = np.mean(list(stored.values()), axis=0)
    c = {n: v - centred_mean for n, v in stored.items()}
    p = probe - centred_mean

    sims = {n: _cos(p, cv) for n, cv in c.items()}
    sim_claimed = sims.pop(name, None)
    best_other = max(sims, key=sims.get) if sims else None
    sim_other = sims.get(best_other, 0.0) if best_other else 0.0
    margin = sim_claimed - sim_other

    MATCH_MARGIN = 0.05
    if best_other is None:
        verdict = "MATCH" if sim_claimed > 0.80 else "UNCERTAIN (only one person enrolled)"
    else:
        verdict = "MATCH" if margin > MATCH_MARGIN else (
            "WRONG PERSON?" if margin < -0.05 else "UNCERTAIN - ask a code word")
    return {"claimed": name, "sim_claimed": round(sim_claimed, 4),
            "best_other": best_other, "sim_other": round(sim_other, 4),
            "margin": round(margin, 4), "verdict": verdict}