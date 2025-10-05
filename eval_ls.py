import json, glob, os, re
from collections import Counter, defaultdict
from typing import Dict, Tuple
from urllib.parse import urlparse

DATA_DIR = "Dataset/Data"
ANN_PATH = "Dataset/Annotations.json"
IOC_DIR = "results/ioc"
KB_DIR  = "results/kb"

# ---------- Nationality canonicalizer using nationalities.csv ----------
NAT_CSV = os.path.join("Entity-Extraction", "Knowledge-Base", "nationalities.csv")

def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())

def load_natmap():
    """
    Build a map of many aliases -> canonical (e.g., 'chinese','china','prc' -> 'china').
    Accepts flexible column names: tries country/nationality/demonym/aliases.
    """
    natmap = {}
    if not os.path.exists(NAT_CSV):
        return natmap

    import csv
    with open(NAT_CSV, encoding="utf-8") as f:
        r = csv.DictReader(f)
        cols = {k.lower(): k for k in (r.fieldnames or [])}
        country_col = cols.get("country") or cols.get("nation") or cols.get("name") or cols.get("canonical") or cols.get("country_name")
        nat_col     = cols.get("nationality") or cols.get("demonym")
        alias_col   = cols.get("aliases")  # optional, comma/semicolon-separated
        rows = list(r)

    def add_alias(alias, canon):
        if not alias: return
        natmap[_norm(alias)] = _norm(canon)

    for row in rows:
        canon = row.get(country_col, "") if country_col else ""
        dem   = row.get(nat_col, "") if nat_col else ""
        aliases = row.get(alias_col, "") if alias_col else ""

        if not canon and dem:
            canon = dem
        if not canon:
            continue

        # seed
        add_alias(canon, canon)
        if dem:
            add_alias(dem, canon)

        # split aliases if present
        for a in re.split(r"[;,/|]", aliases or ""):
            add_alias(a, canon)

        # common US variants
        if _norm(canon) in {"united states", "united states of america", "usa", "us"}:
            for v in ["u.s.", "u.s.a.", "us", "usa", "america", "united states"]:
                add_alias(v, "united states")

    return natmap

_NATMAP = load_natmap()

def canon_nat(s: str) -> str:
    """Map any nationality/country-ish string to canonical using NATMAP; fallback to normalized."""
    key = _norm(s)
    return _NATMAP.get(key, key)

# ---------- Label Studio → eval labels ----------
LS_TO_EVAL = {
    "CVE": "CVE",
    "EMAIL": "EMAIL",
    "DOMAIN": "DOMAIN",
    "IPV4": "IPV4",
    "ipv4": "IPV4",
    "intrusion-set": "INTRUSION_SET",  # not evaluated here
    "location": "NATIONALITY",
    "tool": "TOOL",
    "malware": "MALWARE",
    "vulnerability": "CVE",
}

# heuristic for nationality-ish tokens
DEM_SUFFIX = ("ese","ish","ian","i","ic","ch","en")

def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())

def is_probable_nationality(s: str) -> bool:
    t = norm(s)
    if " " in t:
        return True  # e.g., "south korean"
    return t.endswith(DEM_SUFFIX)

def read_file(fp: str) -> str:
    return open(fp, encoding="utf-8", errors="ignore").read()

def dataset_files() -> Dict[str, str]:
    out = {}
    for fp in glob.glob(os.path.join(DATA_DIR, "*.txt")):
        out[os.path.basename(fp)] = read_file(fp)
    return out

def match_filename_by_text(snippet: str, files: Dict[str, str]) -> str:
    key = norm(snippet)[:200]
    if not key:
        return ""
    for name, txt in files.items():
        if norm(txt).startswith(key):
            return name
    for name, txt in files.items():
        if key in norm(txt):
            return name
    return ""

def load_annotations() -> Dict[str, Dict[str, set]]:
    """
    Load Label Studio export (list) and return:
    { filename: { EVAL_LABEL: set(strings) } }
    """
    raw = json.load(open(ANN_PATH, encoding="utf-8"))
    files_text = dataset_files()
    gold = defaultdict(lambda: defaultdict(set))

    for task in raw:
        data = task.get("data", {}) if isinstance(task, dict) else {}
        text = data.get("text", "") or data.get("body", "") or ""
        fname = data.get("file") or data.get("filename") or data.get("source") or ""
        if fname:
            fname = os.path.basename(fname)
            if not fname.lower().endswith(".txt"):
                if fname + ".txt" in files_text:
                    fname = fname + ".txt"
        if not fname:
            fname = match_filename_by_text(text, files_text)
        if not fname:
            continue

        anns = task.get("annotations", [])
        for ann in anns:
            for res in ann.get("result", []):
                v = res.get("value", {})
                label_list = v.get("labels") or []
                val_text = v.get("text", "")
                if not label_list or not val_text:
                    continue
                for lab in label_list:
                    tgt = LS_TO_EVAL.get(lab, None)
                    if tgt is None:
                        if lab == "location" and is_probable_nationality(val_text):
                            tgt = "NATIONALITY"
                        else:
                            continue
                    if tgt == "NATIONALITY":
                        gold[fname][tgt].add(canon_nat(val_text))
                    else:
                        gold[fname][tgt].add(norm(val_text))
    return gold

def load_predictions() -> Dict[str, Dict[str, set]]:
    """
    Load predictions from:
      - results/ioc (CVE/EMAIL/DOMAIN/IPV4)
      - results/kb  (NATIONALITY)
    Supports KB files in shapes:
      A) {"file": "...", "kb_matches": {"nationalities": [...], "matches": [...]}}
      B) {"file": "...", "kb_matches": [ {...}, ... ]}
      C) [ {...}, ... ]  # bare list
    And tolerates filenames like APT41.txt.txt.json or APT41.txt.json.
    """
    pred = defaultdict(lambda: defaultdict(set))

    def norm_name_from_path(fp: str) -> str:
        base = os.path.basename(fp)
        if base.endswith(".txt.txt.json"):
            return base[:-len(".txt.txt.json")] + ".txt"
        elif base.endswith(".txt.json"):
            return base[:-len(".txt.json")] + ".txt"
        elif base.endswith(".json"):
            return base[:-5]
        return base

    # --- IOC-Finder predictions ---
    for fp in glob.glob(os.path.join(IOC_DIR, "*.json")):
        name = norm_name_from_path(fp)
        data = json.load(open(fp, encoding="utf-8"))
        iocs = data.get("iocs", {})

        # CVE
        for v in iocs.get("cves", []):
            pred[name]["CVE"].add(norm(v))

        # EMAIL: include both keys
        emails = set(iocs.get("email_addresses", [])) | set(iocs.get("email_addresses_complete", []))
        for v in emails:
            pred[name]["EMAIL"].add(norm(v))

        # DOMAIN: include explicit + URL netlocs
        for v in iocs.get("domains", []):
            pred[name]["DOMAIN"].add(norm(v))
        for u in iocs.get("urls", []):
            try:
                host = urlparse(u).netloc
                if host:
                    pred[name]["DOMAIN"].add(norm(host))
            except Exception:
                pass

        # IPv4: plain + CIDR head
        for v in iocs.get("ipv4s", []):
            pred[name]["IPV4"].add(norm(v))
        for v in iocs.get("ipv4_cidrs", []):
            pred[name]["IPV4"].add(norm(v.split("/", 1)[0]))

    # --- KB Nationalities ---
    def looks_like_nationality(s: str) -> bool:
        t = norm(s)
        if " " in t:
            return True
        return t.endswith(DEM_SUFFIX)

    for fp in glob.glob(os.path.join(KB_DIR, "*.json")):
        name = norm_name_from_path(fp)
        data = json.load(open(fp, encoding="utf-8"))

        # A) dict with dict
        if isinstance(data, dict) and isinstance(data.get("kb_matches"), dict):
            for v in data["kb_matches"].get("nationalities", []):
                pred[name]["NATIONALITY"].add(canon_nat(v))
            if isinstance(data["kb_matches"].get("matches"), list):
                for m in data["kb_matches"]["matches"]:
                    if not isinstance(m, dict): continue
                    t = (m.get("type") or "").lower()
                    txt = m.get("text", "")
                    if t in {"nationality","location"} or looks_like_nationality(txt):
                        pred[name]["NATIONALITY"].add(canon_nat(txt))

        # B) dict with list
        elif isinstance(data, dict) and isinstance(data.get("kb_matches"), list):
            for m in data["kb_matches"]:
                if not isinstance(m, dict): continue
                t = (m.get("type") or "").lower()
                txt = m.get("text", "")
                if t in {"nationality","location"} or looks_like_nationality(txt):
                    pred[name]["NATIONALITY"].add(canon_nat(txt))

        # C) bare list
        elif isinstance(data, list):
            for m in data:
                if not isinstance(m, dict): continue
                t = (m.get("type") or "").lower()
                txt = m.get("text", "")
                if t in {"nationality","location"} or looks_like_nationality(txt):
                    pred[name]["NATIONALITY"].add(canon_nat(txt))

    return pred

def prf(gold: set, pred: set) -> Tuple[float,float,float,int,int,int]:
    tp = len(gold & pred); pp = len(pred); gg = len(gold)
    P = tp / (pp if pp else 1)
    R = tp / (gg if gg else 1)
    F1 = 2*P*R / (P+R if (P+R) else 1e-9)
    return P,R,F1,tp,pp,gg

def main():
    gold = load_annotations()
    pred = load_predictions()

    labels = ["CVE","EMAIL","DOMAIN","IPV4","NATIONALITY"]
    totals = Counter()
    per_label = {lab: Counter() for lab in labels}

    for fname, gdict in gold.items():
        pdict = pred.get(fname, {})
        for lab in labels:
            gset = set(gdict.get(lab, set()))
            pset = set(pdict.get(lab, set()))
            P,R,F1,TP,PP,GG = prf(gset, pset)
            totals["TP"] += TP; totals["PP"] += PP; totals["GG"] += GG
            per_label[lab]["TP"] += TP; per_label[lab]["PP"] += PP; per_label[lab]["GG"] += GG

    microP = totals["TP"]/ (totals["PP"] if totals["PP"] else 1)
    microR = totals["TP"]/ (totals["GG"] if totals["GG"] else 1)
    microF = 2*microP*microR / (microP+microR if (microP+microR) else 1e-9)

    print(f"Micro (covered labels only): P={microP:.3f} R={microR:.3f} F1={microF:.3f}")

    for lab in labels:
        TP,PP,GG = per_label[lab]["TP"], per_label[lab]["PP"], per_label[lab]["GG"]
        P = TP/(PP if PP else 1); R = TP/(GG if GG else 1); F1 = 2*P*R/(P+R if (P+R) else 1e-9)
        print(f"{lab:12s}  P={P:.3f} R={R:.3f} F1={F1:.3f}  (TP={TP}, Pred={PP}, Gold={GG})")

if __name__ == "__main__":
    main()
