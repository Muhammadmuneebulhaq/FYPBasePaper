# novel_entities.py
import os, glob, json, spacy, re
from preprocess import load_and_clean_txt
NLP = spacy.load("en_core_web_sm")

PATTERNS = [
    # “dubbed X”, “named X”, “called X”
    re.compile(r"\b(dubbed|named|called)\s+([A-Z][A-Za-z0-9\- ]{2,})"),
    # “we track this group as X / tracked as X”
    re.compile(r"\b(track(?:ed)?\s+(?:as|under)\s+)([A-Z][A-Za-z0-9\- ]{2,})"),
    # “the threat actor X”, “group X”
    re.compile(r"\b(threat actor|group|campaign)\s+([A-Z][A-Za-z0-9\- ]{2,})"),
    # “new malware X”, “malware family X”, “tool X”
    re.compile(r"\b(new|novel)\s+(malware|tool|family)\s+([A-Z][A-Za-z0-9\- ]{2,})"),
]

def extract(text: str):
    doc = NLP(text)
    hits = []
    for pat in PATTERNS:
        for m in pat.finditer(text):
            # choose last captured group as the name
            cand = m.group(m.lastindex).strip()
            st = m.start(m.lastindex); en = m.end(m.lastindex)
            # simple type guess
            low = m.group(0).lower()
            etype = "malware" if "malware" in low or "family" in low else ("intrusion-set" if "group" in low or "actor" in low or "campaign" in low else "malware")
            # require proper noun tokens majority
            span = doc.char_span(st, en, alignment_mode="contract")
            if span and sum(1 for t in span if t.pos_=="PROPN") >= max(1, len(span)//2):
                hits.append({"text": cand, "start": st, "end": en, "type": etype, "source_rule": pat.pattern})
    # dedup by span
    uniq, out = set(), []
    for h in hits:
        k = (h["start"], h["end"])
        if k not in uniq: uniq.add(k); out.append(h)
    return out

def batch():
    os.makedirs("results/novel", exist_ok=True)
    for fp in sorted(glob.glob("Dataset/Data/*.txt")):
        name = os.path.basename(fp)
        text = load_and_clean_txt(fp)
        res = extract(text)
        json.dump({"file": name, "novel": res}, open(os.path.join("results/novel", f"{name}.json"),"w"), indent=2)
        print("✓", name, "-> results/novel/")
    print("Done.")

if __name__ == "__main__":
    batch()
