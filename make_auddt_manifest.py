r"""Our manifest -> AUDDT manifest (audio_path,label). No dataset download needed if
C:\dhwani_data exists: reuses data/processed/asvspoof19la/manifest.csv (or share/manifest.csv).
Reports disk coverage so a run never quietly scores 3% of the split."""
import argparse, csv, os, random, sys

def find_manifest():
    for p in (os.path.join("data","processed","asvspoof19la","manifest.csv"),
              os.path.join("share","manifest.csv")):
        if os.path.exists(p):
            return p
    sys.exit("FATAL: no manifest found. Run this from the repo root (data\\... or share\\manifest.csv).")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default=None)
    ap.add_argument("--split", default="eval", choices=["train","dev","eval"])
    ap.add_argument("--per-class", type=int, default=200, help="0 = whole split")
    ap.add_argument("--out", default=None)
    ap.add_argument("--seed", type=int, default=20260924)
    a = ap.parse_args()

    mp = a.manifest or find_manifest()
    rows = list(csv.DictReader(open(mp, encoding="utf-8", errors="replace")))
    real = [r for r in rows if r.get("split")==a.split and r.get("label")=="bonafide"]
    fake = [r for r in rows if r.get("split")==a.split and r.get("label")=="spoof"]
    rng = random.Random(a.seed); rng.shuffle(real); rng.shuffle(fake)
    if a.per_class:
        real, fake = real[:a.per_class], fake[:a.per_class]

    picked, missing = [], 0
    for r, lab in [(x,"bonafide") for x in real] + [(x,"spoof") for x in fake]:
        p = (r.get("path") or "").strip()
        if not p or not os.path.exists(p):
            missing += 1; continue
        picked.append((p, lab, r.get("attack",""), r.get("speaker","")))
    if not picked:
        sys.exit("FATAL: 0 readable audio files (manifest points at %s...). Mount the corpus or "
                 "use AUDDT/download/get_asvspoof2019-la.sh before quoting any number."
                 % (rows[0].get("path","")[:40] if rows else "empty manifest"))

    out = a.out or os.path.join("AUDDT","data","dhk","manifest_%s.csv" % a.split)
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out,"w",newline="",encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["audio_path","label","attack","speaker"])
        for p,lab,atk,spk in picked: w.writerow([p,lab,atk,spk])

    n_real = sum(1 for _,l,_,_ in picked if l=="bonafide")
    print("manifest in : %s (%d rows)" % (mp, len(rows)))
    print("written     : %s" % out)
    print("clips       : %d (bonafide %d / spoof %d)" % (len(picked), n_real, len(picked)-n_real))
    print("skipped     : %d files not on disk" % missing)
    print("coverage    : %.1f%%" % (100*len(picked)/max(1,len(picked)+missing)))
    if len(picked) < 0.5*(len(picked)+missing):
        print("WARNING: over half the sampled clips are missing. Fix the paths before this run means anything.")
    print("\nconfig data.manifest_path = data/dhk/manifest_%s.csv" % a.split)

main()
