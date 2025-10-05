# kb_match_ac.py  — AC + spaCy POS gating + overlap priority
import os, csv, json, argparse, ahocorasick, spacy, re

KB_DIR = os.path.join("Entity-Extraction", "Knowledge-Base")
NLP = spacy.load("en_core_web_sm", disable=["ner"])  # we only need tagger/parser

TRIGGER_VERBS = re.compile(r"\b(use[ds]?|leverag(?:e|ed|es)|execut(?:e|ed|es)|deploy(?:ed|s)?|install(?:ed|s)?|employ(?:ed|s)?|perform(?:ed|s)?)\b", re.I)
GENERIC_STOP = {
    "at","dll","domain","domains","malware","file","files","process","processes",
    "network","service","services","tool","tools","command","commands","server",
    "servers","script","scripts","registry","key","keys"
}
SHORT_WHITELIST = {"wmi","rdp","tor","c2","ps"}

PRIORITY = {"intrusion-set":3, "malware":2, "tool":1, "attack-pattern":0}


def is_word_boundary(text, start, end):
    left_ok  = (start == 0) or not re.match(r'\w', text[start-1])
    right_ok = (end   == len(text)) or not re.match(r'\w', text[end])
    return left_ok and right_ok

def dedup_and_filter(matches, text):
    # keep only matches that sit on word boundaries
    filtered = [m for m in matches if is_word_boundary(text, m["start"], m["end"])]

    # prefer longer spans when overlaps occur
    filtered.sort(key=lambda m: (m["start"], -(m["end"] - m["start"])))
    kept, last_end = [], -1
    for m in filtered:
        if m["start"] >= last_end:
            kept.append(m)
            last_end = m["end"]
    return kept




def _load_csv(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))

def _kb_entries():
    out = []
    # intrusion sets
    for r in _load_csv(os.path.join(KB_DIR, "intrusion_sets.csv")):
        out.append(("intrusion-set", r["alias"], r["canonical_name"], r.get("external_id","")))
    # malware
    for r in _load_csv(os.path.join(KB_DIR, "malware.csv")):
        out.append(("malware", r["alias"], r["canonical_name"], r.get("external_id","")))
    # tools
    for r in _load_csv(os.path.join(KB_DIR, "tools.csv")):
        out.append(("tool", r["alias"], r["canonical_name"], r.get("external_id","")))
    # techniques (name -> technique_id)
    for r in _load_csv(os.path.join(KB_DIR, "techniques.csv")):
        if r.get("name") and r.get("technique_id"):
            out.append(("attack-pattern", r["name"], r["name"], r["technique_id"]))
    # filter
    entries = []
    for k, alias, canon, ext in out:
        a = alias.strip()
        al = a.lower()
        if not a:
            continue
        if al in GENERIC_STOP:
            continue
        if len(al) < 4 and al not in SHORT_WHITELIST:
            continue
        needs_gate = (k == "attack-pattern" and not _is_title_like(a))
        entries.append((k, a, canon, ext, needs_gate))
    return entries

def _is_title_like(s: str) -> bool:
    words = s.split()
    if len(words) >= 2:
        return all(w[:1].isupper() for w in words if w)
    return any(c.isupper() for c in s[1:])

def _has_tcode_near(text, start, end, w=40):
    lo, hi = max(0,start-w), min(len(text), end+w)
    return re.search(r"\bT\d{4}(?:\.\d{3})?\b", text[lo:hi]) is not None

def _has_trigger_verb_near(text, start, end, w=40):
    lo, hi = max(0,start-w), min(len(text), end+w)
    return TRIGGER_VERBS.search(text[lo:hi]) is not None

def _pos_gate(doc, start, end, kind, surface):
    # light POS heuristics (optional; keeps performance good)
    if kind != "attack-pattern":
        return True
    # accept if proper noun chunk or verb context nearby
    span = doc.char_span(start, end, alignment_mode="contract")
    if span is None:
        return True
    heads = {t.pos_ for t in span.root.subtree}
    return ("PROPN" in heads) or ("NOUN" in heads) or ("VERB" in heads)

def build_automaton(entries):
    A = ahocorasick.Automaton()
    for idx, (k, alias, canon, ext, needs) in enumerate(entries):
        A.add_word(alias, (k, alias, canon, ext, needs))
    A.make_automaton()
    return A

def match_text(text: str, entries):
    doc = NLP(text)
    A = build_automaton(entries)
    hits = []
    for end_idx, (k, alias, canon, ext, needs) in A.iter(text):
        start = end_idx - len(alias) + 1
        end = end_idx + 1
        if k == "attack-pattern" and needs:
            if not (_has_tcode_near(text,start,end) or _has_trigger_verb_near(text,start,end)):
                continue
        if not _pos_gate(doc, start, end, k, alias):
            continue
        hits.append({"text": text[start:end], "start": start, "end": end,
                     "type": k, "canonical": canon, "external_id": ext})
    # resolve overlaps by priority
    by_span = {}
    for h in hits:
        key = (h["start"], h["end"])
        if key not in by_span or PRIORITY[h["type"]] > PRIORITY[by_span[key]["type"]]:
            by_span[key] = h
    return list(by_span.values())

def main():
    import argparse, os
    from preprocess import load_and_clean_txt
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--out")
    args = ap.parse_args()

    entries = _kb_entries()
    text = load_and_clean_txt(args.file)
    res = match_text(text, entries)
    res = dedup_and_filter(res, text) 
    out = {"file": os.path.basename(args.file), "kb_matches": res}
    if args.out:
        json.dump(out, open(args.out,"w",encoding="utf-8"), indent=2)
    else:
        print(json.dumps(out, indent=2))

if __name__ == "__main__":
    main()
