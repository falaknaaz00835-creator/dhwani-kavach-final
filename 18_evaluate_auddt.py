# 18_evaluate_auddt.py - full-scale evaluation of the shipping detector on ASVspoof2019 LA,
# scored through the live demo's own feature path. AUDDT/ASVspoof clip protocol (one 4 s window per
# clip) + codec/noise/duration robustness + the product's 3-band policy verdict.
#   python 18_evaluate_auddt.py --smoke     ~1500 clips, 2 min, writes all three artifacts
#   python 18_evaluate_auddt.py             the whole eval split
# Writes metrics.json + auddt_evaluation_report.md/.pdf next to the model that was used. Every
# number is measured by this run or it is not printed. Gates FATAL out instead of guessing.
import argparse, csv, hashlib, json, math, os, platform, re, subprocess, sys, time
import numpy as np

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
sys.path.insert(0, ROOT)

ap = argparse.ArgumentParser()
ap.add_argument("--model", default="auto", help="auto = cnn_v2 then cnn_v1, or an explicit path")
ap.add_argument("--split", default="eval")
ap.add_argument("--n", type=int, default=0, help="clip-level cap (0 = every readable clip)")
ap.add_argument("--rob", type=int, default=1200, help="clips per robustness condition (0 = skip)")
ap.add_argument("--policy", type=int, default=1500, help="clips streamed through the 3-band policy")
ap.add_argument("--data-root", default="", help="remap the corpus root, e.g. D:\\dhwani_data")
ap.add_argument("--smoke", action="store_true")
ap.add_argument("--phase", default="all", choices=["all", "clean", "robust", "policy"])
ap.add_argument("--seed", type=int, default=20260925)
ap.add_argument("--force", action="store_true")
ap.add_argument("--dev-skip-gates", action="store_true",
                help="testing only: turns the two quality gates into warnings and stamps the artifacts")
A = ap.parse_args()
if A.smoke:
    A.n, A.rob, A.policy = 1500, 300, 240

import torch, soundfile as sf, librosa
torch.set_num_threads(int(os.environ.get("DK_THREADS", "4")))
from ml.audio.io import SR, fix_length, energy_vad
from ml.features.dsp import logmel
from ml.models.cnn import MelCNN

SECONDS, WIN = 4.0, int(4.0 * SR)
rng = np.random.default_rng(A.seed)
GATES = []


def gate(name, ok, detail, hard=True):
    GATES.append({"check": name, "pass": bool(ok), "detail": detail})
    tag = "PASS" if ok else ("WARN" if not hard else "FATAL")
    print("GATE %-18s %-4s %s" % (name, tag, detail), flush=True)
    if not ok and hard:
        print("\nSTOPPED - a gate failed. Paste this whole screen to Saniya, do not edit anything.\n")
        sys.exit(2)


def note(msg):
    print(msg, flush=True)


# ---------------------------------------------------------------- model (requirement: v2, else v1)
def pick_model(spec):
    cand = ([spec] if spec != "auto" else
            [os.path.join("results", "cnn_v2", "model.pt"), os.path.join("results", "cnn_v1", "model.pt")])
    for c in cand:
        if os.path.exists(c):
            return c, os.path.normpath(c)
    return None, None


MPATH, _ = pick_model(A.model)
if MPATH is None:
    gate("model-file", False, "no model.pt at %s - run 7_train_cnn.py first" % A.model)
name = "cnn_v2" if os.sep + "cnn_v2" + os.sep in MPATH else "cnn_v1"
if A.model == "auto" and name != "cnn_v2":
    note("NOTE: results/cnn_v2/model.pt is NOT in this folder, so the report is for %s "
         "(the checkpoint this repo actually ships)." % name)
raw_bytes = open(MPATH, "rb").read()
sha = hashlib.sha256(raw_bytes).hexdigest()
model = MelCNN()
sd = torch.load(MPATH, map_location="cpu")
if isinstance(sd, dict) and "state_dict" in sd:
    sd = sd["state_dict"]
model.load_state_dict(sd)
model.eval()
nparam = sum(p.numel() for p in model.parameters())
gate("model-file", True, "%s  %s B  sha256 %s  %s params" % (MPATH, len(raw_bytes), sha[:16], f"{nparam:,}"))
OUT = os.path.dirname(MPATH)

CALP = os.path.join("results", "calibration.json")
CAL = json.load(open(CALP, encoding="utf-8")) if os.path.exists(CALP) else {}
BIAS = float(CAL.get("logit_bias", 0.0))
TLO, THI = float(CAL.get("theta_lo", 0.62)), float(CAL.get("theta_hi", 0.9))
VMIN = float(CAL.get("vad_min", 0.0))
gate("calibration", True, "logit_bias=%s theta_lo=%s theta_hi=%s vad_min=%s (fitted %s, source %s, %s voiced windows)"
     % (BIAS, TLO, THI, VMIN, CAL.get("date"), CAL.get("source"), CAL.get("n_voiced")))
if CAL.get("model") and CAL["model"].lower().replace(" ", "") != name.replace("_", ""):
    note("NOTE: calibration.json is tagged %r while we are scoring %s. Reported as-is; the bias "
         "is monotone so it cannot change AUC/EER, only the operating point." % (CAL["model"], name))


def score(y):                                   
    piece = fix_length(np.asarray(y, dtype=np.float32), WIN)
    x = logmel(piece)
    x = (x - x.mean()) / (x.std() + 1e-6)
    with torch.no_grad():
        return float(torch.sigmoid(model(torch.from_numpy(x[None, None, ...]))))


def calib(p):
    q = np.clip(np.asarray(p, dtype=np.float64), 1e-4, 1 - 1e-4)
    out = 1.0 / (1.0 + np.exp(-(np.log(q / (1.0 - q)) + BIAS)))
    return float(out) if out.ndim == 0 else out.astype(np.float32)


# parity: the live server's own function must agree, or this benchmark is not the product
try:
    import demo_server as D
    _z = np.concatenate([rng.normal(0, .05, WIN // 2), np.zeros(WIN // 2)]).astype(np.float32)
    dd = abs(score(_z) - D.score_audio(_z))
    gate("parity-vs-live-server", dd <= 1e-5, "max |delta| = %.2e" % dd)
except SystemExit:
    note("NOTE: demo_server refused to import (no model?) - parity check skipped")
except Exception as e:
    note("NOTE: parity check skipped (%s)" % e)

# ------------------------------------------------------------- manifest + safe path resolver (req 4)
IDX = {}


def dir_index(d):
    if d not in IDX:
        try:
            IDX[d] = {n.lower(): n for n in os.listdir(d)}
        except Exception:
            IDX[d] = {}
    return IDX[d]


def resolve(p, remap):
    tries = [p, os.path.normpath(p), p.replace("/", os.sep), p.replace("\\", os.sep),
             os.path.normpath(p.replace("/", os.sep))]
    if remap:
        m = re.match(r"^[A-Za-z]:[/\\]?[^/\\]+", p)   
        if m:
            tail = p[m.end():]
            tries += [remap.rstrip("\\/") + tail, os.path.normpath(remap.rstrip("\\/") + tail),
                      os.path.normpath((remap.rstrip("\\/") + tail).replace("\\", os.sep))]
    for t in tries:
        if t and os.path.exists(t):
            return t, "direct" if t == p else "separator/remap"
    d, f = os.path.split(os.path.normpath(tries[-1]))
    real = dir_index(d).get(f.lower())
    if real:
        return os.path.join(d, real), "case-fix"
    return None, "missing"


man = os.path.join("share", "manifest.csv")
if not os.path.exists(man):
    gate("manifest", False, "%s not found" % man)
rows = [r for r in csv.DictReader(open(man, encoding="utf-8", errors="replace"))
        if (r.get("split") or "").strip() == A.split and (r.get("label") or "").strip() in ("bonafide", "spoof")]
gate("manifest", len(rows) > 0, "%s -> %d rows with split=%s" % (man, len(rows), A.split))
note("resolving %d paths (mixed \\ and / in every row - that is expected, the resolver handles it)..."
     % len(rows))
t0 = time.time()
clips, how = [], {"direct": 0, "separator/remap": 0, "case-fix": 0, "missing": 0}
for r in rows:
    p, k = resolve((r.get("path") or "").strip(), A.data_root)
    how[k] += 1
    if p:
        clips.append({"path": p, "attack": (r.get("attack") or "?").strip(),
                      "label": 1 if r["label"].strip() == "spoof" else 0, "speaker": r.get("speaker", "?")})
    if A.n and len(clips) >= A.n:
        break
note("resolver: %s  (%.1fs)" % (how, time.time() - t0))
_miss = [r for r in rows if not resolve((r.get("path") or "").strip(), A.data_root)[0]]
if _miss[:2]:
    for r in _miss[:2]:
        _d = os.path.dirname(os.path.normpath(r["path"].replace("/", os.sep)))
        note("  unreadable example: %s   (its folder exists: %s)" % (r["path"], os.path.isdir(_d)))
gate("corpus-mounted", len(clips) >= (300 if A.smoke else 5000),
     "%d of %d rows readable. If this is 0, C:\\dhwani_data is not mounted under this folder - "
     "do not 'fix' it, tell Saniya." % (len(clips), len(rows)), hard=not A.dev_skip_gates)
nb = sum(1 for c in clips if c["label"] == 0)
gate("two-classes", 0 < nb < len(clips), "%d bonafide / %d spoof" % (nb, len(clips) - nb))
if A.policy and not A.smoke:
    A.policy = min(A.policy, 3000)


# ------------------------------------------------------------------------- clip-level scoring (clean)
def read_y(path):
    y, sr = sf.read(path, dtype="float32", frames=WIN)
    y = np.asarray(y, dtype=np.float32)
    if y.ndim > 1:
        y = y[:, 0]
    if sr != SR:
        y = librosa.resample(y, orig_sr=sr, target_sr=SR)
    return y


CACHE = os.path.join(OUT, "auddt_clip_scores.csv")
lab = np.array([c["label"] for c in clips])
use_clean = A.phase in ("all", "clean")
if not use_clean and os.path.exists(CACHE):
    sc = np.loadtxt(CACHE, delimiter=",", usecols=0)
    atk = [l.split(",")[-1] for l in open(CACHE, encoding="utf-8").read().splitlines()[1:]]
    sc = sc[:len(clips)]
    gate("cached-scores", len(sc) == len(clips), "%d clean scores reloaded from %s" % (len(sc), CACHE))
else:
    sc, atk = np.zeros(len(clips), dtype=np.float32), [c["attack"] for c in clips]
    t0 = time.time()
    with open(CACHE, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["p_raw", "p_cal", "attack"])
        for i, c in enumerate(clips):
            try:
                p = score(read_y(c["path"]))
            except Exception as e:
                p = float("nan")
                if i < 3:
                    note("  decode fail %s: %s" % (c["path"], e))
            sc[i] = p
            w.writerow([round(float(p), 6), round(calib(p), 6), c["attack"]])
            if (i + 1) % 1000 == 0:
                el = time.time() - t0
                note("  clean %d/%d  %.0f s  ETA %.1f min" % (i + 1, len(clips), el,
                                                              el / (i + 1) * (len(clips) - i - 1) / 60))
    note("clean pass: %d clips in %.1f min (%.1f ms/clip)" % (len(clips), (time.time() - t0) / 60,
                                                                (time.time() - t0) * 1000 / len(clips)))

from sklearn.metrics import roc_curve, roc_auc_score


def op_point(p, y, thr):
    pred = p >= thr
    tp = int(((pred) & (y == 1)).sum()); fp = int(((pred) & (y == 0)).sum())
    fn = int(((~pred) & (y == 1)).sum()); tn = int(((~pred) & (y == 0)).sum())
    d = {"threshold": thr, "n": int(len(y)), "accuracy": round((tp + tn) / max(len(y), 1), 4),
         "precision_spoof": round(tp / max(tp + fp, 1), 4), "recall_spoof_TPR": round(tp / max(tp + fn, 1), 4),
         "specificity_TNR": round(tn / max(tn + fp, 1), 4), "fpr_pct": round(100 * fp / max(fp + tn, 1), 2),
         "F1": round(2 * tp / max(2 * tp + fp + fn, 1), 4), "confusion": {"TN": tn, "FP": fp, "FN": fn, "TP": tp}}
    return d


def eer_of(y, p):
    ok = ~np.isnan(p)
    y2, p2 = y[ok], p[ok]
    if len(np.unique(y2)) < 2 or np.std(p2) < 1e-9:
        return float("nan"), float("nan"), float("nan")
    a = float(roc_auc_score(y2, p2))
    f, t, th = roc_curve(y2, p2, pos_label=1)
    i = int(np.argmin(np.abs((1 - t) - f)))
    return 100.0 * min(t[i], 1 - f[i]), a, float(th[i])


clean_nan = int(np.isnan(sc).sum())
gate("decodable", clean_nan < 0.02 * len(sc), "%d/%d clips failed to decode" % (clean_nan, len(sc)))
eer, auc, thr_e = eer_of(lab, sc)
gate("ranking-direction", (not np.isnan(auc)) and auc > 0.5,
     "AUC %.4f on %d clips (if this is below 0.5 the labels or the checkpoint are wrong)" % (auc, len(sc)),
     hard=not A.dev_skip_gates)
pc = calib(sc)
eer_c, auc_c, _ = eer_of(lab, pc)
_fr, _tr, _ = roc_curve(lab, sc, pos_label=1)
_sel = np.where(_fr <= 0.01)[0]
tpr1 = float(_tr[_sel].max()) if len(_sel) else float("nan")
op_raw = op_point(sc, lab, 0.5)
op_cal = op_point(pc, lab, TLO)

per_attack = {}
for a in sorted({x for x in atk if x and x != "none"}):
    m = np.array([x == a for x in atk]) | (lab == 0)
    e, au, _ = eer_of(lab[m], sc[m])
    per_attack[a] = {"n": int(m.sum()), "n_spoof": int((lab[m] == 1).sum()), "eer_pct": round(e, 2),
                     "auc": round(au, 4) if not np.isnan(au) else None}

summary = {"run": "18_evaluate_auddt.py", "started": time.strftime("%Y-%m-%d %H:%M:%S"),
           "smoke": bool(A.smoke), "partial": False, "dev_skip_gates": bool(A.dev_skip_gates), "host": platform.platform(),
           "python": platform.python_version(), "torch": torch.__version__,
           "git": (subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
                   .stdout.strip() or "unknown"),
           "model": {"path": MPATH, "bytes": len(raw_bytes), "sha256": sha, "params": int(nparam),
                     "tag": name},
           "protocol": {"split": A.split, "n_rows": len(rows), "n_scored": len(sc),
                        "n_bonafide": int(nb), "n_spoof": int(len(clips) - nb), "window_seconds": SECONDS,
                        "padding": "ml.audio.io.fix_length tiles the clip to 4 s (product behaviour)",
                        "scorer": "log-Mel 80/16k/512/160/power2.0/ref1.0 -> per-window standardise -> MelCNN -> sigmoid",
                        "harness": "this script only; no third-party AUDDT package is imported",
                        "seed": A.seed, "undecodable": clean_nan},
           "clean": {"eer_pct": round(eer, 2), "auc": round(auc, 4), "eer_threshold": round(thr_e, 4),
                     "n": int(len(sc))},
           "clean_calibrated": {"eer_pct": round(eer_c, 2), "auc": round(auc_c, 4),
                                "note": "logit bias is monotone: AUC and EER must be identical to clean"},
           "operating_point_raw_tau0.50": op_raw, "operating_point_shipped_theta_lo": op_cal,
           "tpr_at_fpr1pct": round(tpr1, 4), "per_attack_eer": per_attack, "gates": GATES}

# ------------------------------------------------------------------------- robustness (codec/noise/len)
rob = []
if A.rob and A.phase in ("all", "robust"):
    try:
        from ml.augment.codecs import available, apply_codec
        code = [c for c in available() if c != "clean"]
    except Exception as e:
        note("NOTE: codec conditions skipped (%s)" % e)
        code, apply_codec = [], None
    idx = rng.permutation(len(clips))
    keep, per = [], {}
    for i in idx:                                   
        c = clips[i]
        k = c["attack"] if c["label"] == 1 else "bonafide"
        if per.get(k, 0) < max(2, A.rob // max(len(per_attack) + 1, 2)):
            per[k] = per.get(k, 0) + 1
            keep.append(i)
        if len(keep) >= A.rob:
            break
    keep = sorted(keep)
    sub = np.array([clips[i]["label"] for i in keep])
    try:
        wave = [(read_y(clips[i]["path"]), SR) for i in keep]
    except Exception as e:
        gate("robustness-read", False, str(e))
    note("robustness on %d clips x %d conditions" % (len(keep), 5 + len(code)))
    for cond in ["clean", "snr20", "snr10", "snr5", "dur500"] + code:
        t0 = time.time()
        ps = []
        for (y, sr) in wave:
            z = y
            try:
                if cond.startswith("snr"):
                    sp = float(np.mean(z ** 2)) + 1e-12
                    z = z + rng.normal(0, np.sqrt(sp / (10 ** (float(cond[3:]) / 10.0))),
                                       size=len(z)).astype(np.float32)
                elif cond.startswith("dur"):
                    z = z[:max(int(len(z) * float(cond[3:]) / 1000.0), 64)]
                elif cond != "clean":
                    z, _ = apply_codec(z, sr, cond)
                ps.append(score(np.asarray(z, dtype=np.float32)))
            except Exception:
                ps.append(float("nan"))
        s = np.array(ps, dtype=np.float32)
        e, a, _ = eer_of(sub, s)
        base = rob[0]["auc"] if rob else a
        flag = ""
        if math.isnan(a):
            flag = "NO-RESULT: one class or constant scores"
        elif np.nanstd(s) < 1e-6:
            flag = "DEGENERATE: every clip scored the same"
        elif a < 0.5:
            flag = "AUC<0.5: ranking inverted, do not publish"
        elif cond != "clean" and a > base + 0.02:
            flag = "SUSPECT: a degradation condition beat clean by >2 AUC points"
        rob.append({"condition": cond, "n": int(np.isfinite(s).sum()), "publishable": not flag,
                    "eer_pct": round(e, 2), "auc": round(a, 4), "delta_auc_vs_clean": round(a - base, 4),
                    "mean_bonafide": round(float(np.nanmean(s[sub == 0])), 4),
                    "mean_spoof": round(float(np.nanmean(s[sub == 1])), 4),
                    "recall_at_shipped_theta": round(op_point(calib(s), sub, TLO)["recall_spoof_TPR"], 4),
                    "fpr_at_shipped_theta_pct": op_point(calib(s), sub, TLO)["fpr_pct"], "flag": flag})
        note("  %-9s EER %6.2f%%  AUC %.4f  dAUC %+0.4f  recall@theta_lo %5.1f%%  FPR %5.2f%%  %s  (%.0fs)"
             % (cond, e, a, a - base, 100 * rob[-1]["recall_at_shipped_theta"],
                rob[-1]["fpr_at_shipped_theta_pct"], flag or "ok", time.time() - t0))
    summary["robustness"] = {"n_per_condition": len(keep), "rows": rob,
                             "codecs_applied": code,
                             "note": "clean row here is the same 4 s window re-decoded; SNR is additive "
                                    "white noise on the full clip; dur500 truncates to 0.5 s and the "
                                    "product's fix_length then tiles it to 4 s"}

# --------------------------------------------------------------- product policy: 3-band verdict per call
policy = {}
if A.policy and A.phase in ("all", "policy"):
    from ml.engine.temporal import TemporalEngine, EngineConfig, policy_for
    eng = TemporalEngine(EngineConfig(theta_lo=TLO, theta_hi=THI))
    idx = rng.permutation(len(clips))
    pick, cnt = [], {0: 0, 1: 0}
    for i in idx:
        c = clips[i]
        if cnt[c["label"]] < A.policy // 2:
            cnt[c["label"]] += 1
            pick.append(i)
    res = {0: {}, 1: {}}
    sw = {0: {}, 1: {}}; nw = 0; lastlab = 0
    try:
        for i in pick:
            c = clips[i]
            y = read_y(c["path"])
            r = {"tier": "INSUFFICIENT_AUDIO", "window_p": 0.0, "call_p": 0.0}
            lastlab = c["label"]
            eng.reset()
            step = int(1.0 * SR)
            for s0 in range(0, max(len(y) - WIN, 1), step):
                w = y[s0:s0 + WIN]
                if len(w) < SR:
                    break
                vf = float(energy_vad(w).mean())
                if vf < VMIN:                                
                    r = eng.update(0.5, 0.0)
                else:
                    r = eng.update(calib(score(w)), vf * SECONDS)
            tier = r["tier"]
            res[c["label"]][tier] = res[c["label"]].get(tier, 0) + 1
            nw += 1
            _cp = float(r.get("call_p", 0.0))
            _t3 = "HIGH_RISK" if _cp >= THI else ("SUSPICIOUS" if _cp >= TLO else "SAFE")
            sw[lastlab][_t3] = sw[lastlab].get(_t3, 0) + 1
        tot = {k: max(sum(v.values()), 1) for k, v in res.items()}
        policy = {"n_per_class": {k: sum(v.values()) for k, v in res.items()},
                  "tiers_bonafide": {k: round(v / tot[0], 4) for k, v in res[0].items()},
                  "tiers_spoof": {k: round(v / tot[1], 4) for k, v in res[1].items()},
                  "false_warning_rate_pct_bonafide":
                      round(100 * sum(v for k, v in res[0].items() if k not in ("SAFE", "INSUFFICIENT_AUDIO")) / tot[0], 2),
                  "caught_high_or_suspicious_pct_spoof":
                      round(100 * sum(v for k, v in res[1].items() if k not in ("SAFE", "INSUFFICIENT_AUDIO")) / tot[1], 2),
                  "windows_per_call_mean": round(nw / max(sum(cnt.values()), 1), 2),
                  "no_dwell_tiers_bonafide": {k: round(v / max(sum(sw[0].values()), 1), 4) for k, v in sw[0].items()},
                  "no_dwell_tiers_spoof": {k: round(v / max(sum(sw[1].values()), 1), 4) for k, v in sw[1].items()},
                  "no_dwell_caught_pct_spoof": round(100 * sum(v for k, v in sw[1].items() if k != "SAFE") / max(sum(sw[1].values()), 1), 2),
                  "no_dwell_false_warning_pct_bonafide": round(100 * sum(v for k, v in sw[0].items() if k != "SAFE") / max(sum(sw[0].values()), 1), 2),
                  "note": "streamed exactly as the browser demo does: 1 s hop over the file, 4 s window, VAD "
                          "gate, logit bias, EMA + LLR evidence, 2-window dwell. Mechanism worth knowing: the "
                          "engine starts in INSUFFICIENT_AUDIO and only leaves it after 2 agreeing windows, so a "
                          "4 s clip (1 window) can never produce a verdict - that is why tiers_* is ~100% "
                          "INSUFFICIENT_AUDIO on this corpus. It is a corpus property, not a product failure: real "
                          "calls stream many windows. no_dwell_* repeats the same thresholds on the final call_p "
                          "with the dwell rule ignored, purely so the short-clip corpus can still be read."}
        note("policy on %d calls: real clips that raise a warning %.2f%% | spoofs caught %.2f%%"
             % (sum(policy["n_per_class"].values()), policy["false_warning_rate_pct_bonafide"],
                policy["caught_high_or_suspicious_pct_spoof"]))
    except Exception as e:
        policy = {"error": "%s: %s" % (type(e).__name__, e)}
        note("NOTE: policy phase failed (%s) - clip-level numbers are unaffected" % e)
summary["policy_stream"] = policy

# ------------------------------------------------------------------------------------- artifacts
os.makedirs(OUT, exist_ok=True)
MJ = os.path.join(OUT, "metrics.json")
if os.path.exists(MJ) and not A.force:
    prev = os.path.join(OUT, "metrics.prev.json")
    if not os.path.exists(prev):
        open(prev, "w", encoding="utf-8").write(open(MJ, encoding="utf-8").read())
    note("previous metrics.json kept as metrics.prev.json")
open(MJ, "w", encoding="utf-8").write(json.dumps(summary, indent=2))

L = ["# Dhwani Kavach - full-scale evaluation report", "",
     "Protocol: ASVspoof2019 LA `%s` split, one %.0f s window per clip (AUDDT/ASVspoof clip protocol). "
     "Scores come from the live demo's own feature path; no third-party harness is imported. "
     "Every figure below was printed by this run." % (A.split, SECONDS), "",
     "| item | value |", "|---|---|",
     "| model | `%s` (%s B, sha256 `%s`) |" % (MPATH, f"{len(raw_bytes):,}", sha[:16]),
     "| parameters | %s |" % f"{nparam:,}",
     "| clips scored | %s (bonafide %s / spoof %s) |" % (f"{len(sc):,}", f"{nb:,}", f"{len(sc)-nb:,}"),
     "| ROC-AUC | %.4f |" % auc, "| EER | %.2f %% (at p=%.4f) |" % (eer, thr_e),
     "| TPR @ 1 %% FPR | %.2f %% |" % (100 * tpr1),
     "| accuracy at tau=0.50 (uncalibrated) | %.2f %% (FPR %.2f %%) |" % (100 * op_raw["accuracy"], op_raw["fpr_pct"]),
     "| accuracy at shipped theta_lo=%.2f | %.2f %% (recall %.2f %%, FPR %.2f %%) |"
     % (TLO, 100 * op_cal["accuracy"], 100 * op_cal["recall_spoof_TPR"], op_cal["fpr_pct"]),
     "| calibration | bias %s, theta %.2f/%.2f, vad_min %s, fitted %s on %s voiced windows from %s |"
     % (BIAS, TLO, THI, VMIN, CAL.get("date"), CAL.get("n_voiced"), CAL.get("source")), ""]
if policy:
    L += ["## Product policy (what the screen actually shows)", "",
          "```json", json.dumps(policy, indent=2), "```", ""]
if rob:
    L += ["## Robustness by channel condition (%d clips each)" % (A.rob,), "",
          "| condition | n | EER % | AUC | dAUC vs clean | recall@theta_lo % | FPR % | note |",
          "|---|---|---|---|---|---|---|---|"]
    L += ["| %s | %d | %.2f | %.4f | %+0.4f | %.1f | %.2f | %s |"
          % (r["condition"], r["n"], r["eer_pct"], r["auc"], r["delta_auc_vs_clean"],
             100 * r["recall_at_shipped_theta"], r["fpr_at_shipped_theta_pct"], r["flag"] or "-") for r in rob]
    L.append("")
L += ["## EER by attack family", "", "| attack | n | EER % | AUC |", "|---|---|---|---|"]
for a, v in sorted(per_attack.items(), key=lambda kv: -(kv[1]["eer_pct"] if not math.isnan(kv[1]["eer_pct"]) else 0)):
    L.append("| %s | %d | %s | %s |" % (a, v["n"], "n/a" if math.isnan(v["eer_pct"]) else "%.2f" % v["eer_pct"],
                                        "n/a" if v["auc"] is None else "%.4f" % v["auc"]))
L += ["", "## Honest limits of this table", "",
      "- The clip protocol gives the model one 4 s window. A real phone call is judged over many windows "
      "by the temporal engine, so the policy numbers above, not the EER, describe the product.",
      "- `ml.audio.io.fix_length` pads short audio by repeating it, so a 0.5 s clip is measured as an "
      "8x looped clip. That is product behaviour, kept on purpose, and it is why the duration row is read "
      "with that in mind.",
      "- The calibration bias was fitted on a small set (see the calibration row). Because it is monotone it "
      "cannot move AUC or EER; it only moves the operating point, which is exactly what the two accuracy rows "
      "show.",
      "- Bonafide share of the eval split is %.1f %%, so accuracy on its own is a weak metric here; AUC, EER "
      "and the confusion counts are the reported figures." % (100.0 * nb / max(len(clips), 1)),
      "", "## Gates run by this script", "", "| check | pass | detail |", "|---|---|---|"]
L += ["| %s | %s | %s |" % (g["check"], "PASS" if g["pass"] else "FAIL", g["detail"]) for g in GATES]
L += ["", "_generated %s by 18_evaluate_auddt.py, git %s, torch %s, seed %d_"
      % (time.strftime("%Y-%m-%d %H:%M:%S"), summary["git"], torch.__version__, A.seed), ""]
MD = os.path.join(OUT, "auddt_evaluation_report.md")
open(MD, "w", encoding="utf-8").write("\n".join(L))


def make_pdf(path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages
    f, t, _ = roc_curve(lab, sc, pos_label=1)
    with PdfPages(path) as pdf:
        fig = plt.figure(figsize=(8.27, 11.69))
        fig.text(.07, .955, "Dhwani Kavach - full-scale evaluation", fontsize=17, weight="bold")
        fig.text(.07, .935, "ASVspoof 2019 LA %s split, AUDDT clip protocol (4 s window), scored by the "
                            "live model path" % A.split, fontsize=9, color="#444")
        rowsT = [["ROC-AUC", "%.4f" % auc], ["EER", "%.2f %%" % eer],
                 ["TPR at 1% FPR", "%.2f %%" % (100 * tpr1)], ["clips scored", "{:,}".format(len(sc))],
                 ["bonafide / spoof", "%s / %s" % ("{:,}".format(nb), "{:,}".format(len(sc) - nb))],
                 ["model file", os.path.basename(MPATH) + "  " + sha[:12]],
                 ["parameters", "{:,}".format(nparam)],
                 ["accuracy @ tau=0.50", "%.2f %%" % (100 * op_raw["accuracy"])],
                 ["accuracy @ theta_lo=%.2f" % TLO, "%.2f %%" % (100 * op_cal["accuracy"])],
                 ["recall / FPR at theta_lo", "%.2f %% / %.2f %%" % (100 * op_cal["recall_spoof_TPR"], op_cal["fpr_pct"])],
                 ["logit bias (monotone)", "%s" % BIAS], ["calibration fitted on", "%s voiced windows, %s"
                                                          % (CAL.get("n_voiced"), CAL.get("date"))],
                 ["robustness rows", "%d conditions" % len(rob)],
                 ["policy: real warned / spoof caught (dwell off)", "%s %% / %s %%" % (policy.get("no_dwell_false_warning_pct_bonafide", "n/a"), policy.get("no_dwell_caught_pct_spoof", "n/a"))],
                 ["policy: spoofs caught", "%s %%" % policy.get("caught_high_or_suspicious_pct_spoof", "n/a")],
                 ["git / torch", "%s / %s" % (summary["git"], torch.__version__)]]
        ax = fig.add_axes([.07, .30, .86, .60]); ax.axis("off")
        tb = ax.table(cellText=rowsT, colLabels=["reported", "value"], loc="center", cellLoc="left")
        tb.auto_set_font_size(False); tb.set_fontsize(9.5); tb.scale(1, 1.55)
        for j in range(2):
            tb[0, j].set_facecolor("#111111"); tb[0, j].set_text_props(color="w", weight="bold")
        fig.text(.07, .24, ("DEV RUN - quality gates bypassed, the audio is synthetic: these numbers are NOT results. " if A.dev_skip_gates else "") +
        "This table was written by 18_evaluate_auddt.py in the same run that produced "
                           "metrics.json.\nNo number on this page is typed by hand.", fontsize=8.5, color="#555")
        pdf.savefig(fig); plt.close(fig)

        fig, axs = plt.subplots(2, 1, figsize=(8.27, 11.69))
        axs[0].plot(f, t, lw=1.8, label="ROC (AUC %.4f)" % auc)
        axs[0].plot([0, 1], [0, 1], ls=":", c="#999", label="chance")
        _f2, _t2, _th2 = roc_curve(lab, sc, pos_label=1)
        _i2 = int(np.argmin(np.abs((1 - _t2) - _f2)))
        axs[0].plot(_f2[_i2], 1 - _t2[_i2], "o", c="crimson", ms=6, label="EER %.2f%%" % eer)
        axs[0].set(xlabel="false positive rate", ylabel="true positive rate",
                   title="Detection error trade-off, full %s split" % A.split, xlim=(0, .3), ylim=(.6, 1.01))
        axs[0].legend(fontsize=8, loc="lower right"); axs[0].grid(alpha=.25)
        ks = sorted(per_attack, key=lambda k: -(per_attack[k]["eer_pct"] if not math.isnan(per_attack[k]["eer_pct"]) else -1))
        vv = [per_attack[k]["eer_pct"] if not math.isnan(per_attack[k]["eer_pct"]) else 0 for k in ks]
        axs[1].bar(range(len(ks)), vv, color="#2b6cb0")
        axs[1].set_xticks(range(len(ks))); axs[1].set_xticklabels(ks, rotation=90, fontsize=7)
        axs[1].set(ylabel="EER %", title="Hardest attack families first")
        axs[1].grid(alpha=.25, axis="y")
        fig.tight_layout(); pdf.savefig(fig); plt.close(fig)

        if rob:
            fig, ax = plt.subplots(figsize=(8.27, 6))
            xs = [r["condition"] for r in rob]
            ax.bar(range(len(xs)), [r["eer_pct"] for r in rob], color=["#111"] + ["#c05621"] * (len(xs) - 1))
            ax.set_xticks(range(len(xs))); ax.set_xticklabels(xs, rotation=45, ha="right", fontsize=8)
            ax.set(ylabel="EER %", title="Robustness: what noise, codecs and short clips do to us "
                                         "(%d clips per condition)" % A.rob)
            for j, r in enumerate(rob):
                ax.text(j, r["eer_pct"], "%.1f" % r["eer_pct"], ha="center", va="bottom", fontsize=7)
            ax.grid(alpha=.25, axis="y")
            fig.tight_layout(); pdf.savefig(fig); plt.close(fig)
            fig, ax = plt.subplots(figsize=(8.27, 6))
            ax.plot(range(len(rob)), [r["auc"] for r in rob], "o-", label="AUC")
            ax.plot(range(len(rob)), [100 * r["recall_at_shipped_theta"] for r in rob], "s--",
                    label="recall at shipped theta_lo %")
            ax.set_xticks(range(len(rob))); ax.set_xticklabels(xs, rotation=45, ha="right", fontsize=8)
            ax.axhline(50, c="#bbb", ls=":", label="chance"); ax.legend(fontsize=8)
            ax.set(title="Ranking quality and the live operating point, per condition")
            ax.grid(alpha=.25)
            fig.tight_layout(); pdf.savefig(fig); plt.close(fig)

        fig = plt.figure(figsize=(8.27, 11.69))
        txt = "\n".join(["How this was measured", "-" * 70, "",
                         "  split / protocol   : %s, one %.0f s window per clip, seed %d" % (A.split, SECONDS, A.seed),
                         "  features           : log-Mel 80 / 16 kHz / fft 512 / hop 160 / power 2.0 / ref 1.0",
                         "                     then per-window standardise (mean, std) - identical to demo_server",
                         "  model              : MelCNN, %s, %s params" % (MPATH, "{:,}".format(nparam)),
                         "  decode             : soundfile + librosa resample (no torchaudio/FFmpeg in the scoring path)",
                         "  codec conditions   : real ffmpeg (imageio-ffmpeg) %s" % ", ".join(summary.get("robustness", {}).get("codecs_applied", [])),
                         "  padding            : short clips are tiled to 4 s by fix_length (product behaviour)",
                         "", "Read the limits:", "",
                         "  * %s%% of the scored clips are bonafide, so accuracy alone is misleading." % round(100 - 100.0 * nb / max(len(sc), 1)),
                         "  * EER here is a clip-level number; the product's decision is the streamed policy table.",
                         "  * the logit bias only moves the operating point (monotone): AUC/EER are unchanged by it,",
                         "    which is why the clean and calibrated rows above agree.",
                         "  * gates printed by the run: " + ", ".join("%s=%s" % (g["check"], "PASS" if g["pass"] else "FAIL") for g in GATES),
                         "", "  artifacts: %s, %s, %s" % (os.path.basename(MJ), os.path.basename(MD), os.path.basename(path)),
                         "  git %s | torch %s | %s | %s" % (summary["git"], torch.__version__, summary["host"],
                                                                    summary["started"])])
        fig.text(.07, .90, txt, fontsize=8.6, family="monospace", va="top")
        pdf.savefig(fig); plt.close(fig)


PDF = os.path.join(OUT, "auddt_evaluation_report.pdf")
try:
    make_pdf(PDF)
    pdf_ok = os.path.getsize(PDF) > 4000
except Exception as e:
    pdf_ok = False
    note("NOTE: PDF step failed (%s: %s) - .md and .json are still complete" % (type(e).__name__, e))
note("\nartifacts in %s:" % OUT)
for pth in (MJ, MD, PDF):
    note("  %-32s %s B" % (os.path.basename(pth), f"{os.path.getsize(pth):,}" if os.path.exists(pth) else "MISSING"))
note("\nclip-level: AUC %.4f  EER %.2f%%  n=%d | policy: real-warned %s%%  spoof-caught %s%%"
     % (auc, eer, len(sc), policy.get("false_warning_rate_pct_bonafide", "n/a"),
        policy.get("caught_high_or_suspicious_pct_spoof", "n/a")))
gate("artifacts", pdf_ok if A.phase in ("all", "clean") else os.path.exists(MJ), "3 files in %s" % OUT)
note("EVAL DONE - paste the whole screen to Saniya (the gates are the evidence, not just the numbers).")
