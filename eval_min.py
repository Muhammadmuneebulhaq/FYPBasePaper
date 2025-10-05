# eval_min.py
import json, glob, os, re
from collections import Counter

def norm(x): return x.strip().lower()

def prf(gold, pred):
    tp = len(gold & pred); pp = len(pred); gg = len(gold)
    P = tp/max(pp,1); R = tp/max(gg,1); F1 = 2*P*R/max(P+R,1e-9)
    return P,R,F1,tp,pp,gg

def main():
    ann = json.load(open("Dataset/Annotations.json", encoding="utf-8"))
    # gather predictions we produced
    preds = {}
    # IOC-Finder outputs
    for f in glob.glob("results/ioc/*.json"):
        name = os.path.basename(f).replace(".json","")
        data = json.load(open(f))
        lists = data.get("iocs", {})
        preds.setdefault(name, {"CVE":set(),"EMAIL":set(),"DOMAIN":set(),"IPV4":set(),"NATIONALITY":set()})
        for v in lists.get("cves", []): preds[name]["CVE"].add(norm(v))
        for v in lists.get("email_addresses", []): preds[name]["EMAIL"].add(norm(v))
        for v in lists.get("domains", []): preds[name]["DOMAIN"].add(norm(v))
        for v in lists.get("ipv4s", []): preds[name]["IPV4"].add(norm(v))
    # KB nationalities
    for f in glob.glob("results/kb/*.json"):
        name = os.path.basename(f).replace(".json","")
        data = json.load(open(f))
        for v in data.get("kb_matches",{}).get("nationalities",[]):
            preds.setdefault(name, {"CVE":set(),"EMAIL":set(),"DOMAIN":set(),"IPV4":set(),"NATIONALITY":set()})
            preds[name]["NATIONALITY"].add(norm(v))

    totals = Counter()
    rows = []
    for name, gold in ann.items():
        p = preds.get(name, {"CVE":set(),"EMAIL":set(),"DOMAIN":set(),"IPV4":set(),"NATIONALITY":set()})
        for label in ["CVE","EMAIL","DOMAIN","IPV4","NATIONALITY"]:
            gold_set = set(norm(x) for x in gold.get("entities",{}).get(label,[]))
            pred_set = p.get(label, set())
            P,R,F1,TP,PP,GG = prf(gold_set, pred_set)
            totals["tp"]+=TP; totals["pp"]+=PP; totals["gg"]+=GG
            rows.append((name,label,P,R,F1,TP,PP,GG))

    P = totals["tp"]/max(totals["pp"],1)
    R = totals["tp"]/max(totals["gg"],1)
    F1 = 2*P*R/max(P+R,1e-9)
    print(f"Micro: P={P:.3f} R={R:.3f} F1={F1:.3f}")
    for r in rows[:12]:
        print(*r, sep="\t")

if __name__ == "__main__":
    main()
