import os, glob, json, re
from kb_match_ac import _kb_entries, match_text
from preprocess import load_and_clean_txt


def is_word_boundary(text, start, end):
    left_ok  = (start == 0) or not re.match(r'\w', text[start-1])
    right_ok = (end   == len(text)) or not re.match(r'\w', text[end])
    return left_ok and right_ok

_BAD_CANON = {
    # techniques/tools that collide with common words
    "At", "Domains", "Malware", "DLL", "Python", "JavaScript"
}

def _overlap(a, b):
    return not (a["end"] <= b["start"] or b["end"] <= a["start"])

def _longer(a, b):
    return (a["end"] - a["start"]) > (b["end"] - b["start"])

def is_word_boundary(text, start, end):
    left_ok = (start == 0) or not text[start-1].isalnum()
    right_ok = (end == len(text)) or not text[end].isalnum()
    return left_ok and right_ok

def dedup_and_filter(matches, text):
    """
    Input: list of dicts with keys: text,start,end,type,canonical,external_id
    Returns: filtered, deduped list.
    """
    keep = []
    for m in matches:
        if not is_word_boundary(text, m["start"], m["end"]):
            continue

        token = text[m["start"]:m["end"]].strip(" ,.;:()[]{}\"'`")
        if not token:
            continue

        m = dict(m)
        m["text"] = token

        # generic/ambiguous canonicals to skip
        if m.get("canonical") in _BAD_CANON:
            continue

        # very short non-APT tokens are noisy (e.g., “at”)
        if len(token) < 3 and not token.upper().startswith("APT"):
            continue

        keep.append(m)

    # prefer longer spans when overlaps occur at same start
    keep.sort(key=lambda x: (x["start"], -(x["end"] - x["start"])))

    result = []
    for m in keep:
        if result and _overlap(result[-1], m):
            if _longer(m, result[-1]):
                result[-1] = m
            elif (m["end"] - m["start"]) == (result[-1]["end"] - result[-1]["start"]):
                if text[m["start"]:m["end"]] == m["text"]:
                    result[-1] = m
            continue
        result.append(m)

    seen = set()
    final = []
    for m in result:
        key = (m["start"], m["end"], m["canonical"], m["type"], m.get("external_id"))
        if key in seen:
            continue
        seen.add(key)
        final.append(m)

    return final


def main():
    os.makedirs("results/kb", exist_ok=True)
    entries = _kb_entries()
    for fp in sorted(glob.glob("Dataset/Data/*.txt")):
        name = os.path.basename(fp)
        text = load_and_clean_txt(fp)
        res = match_text(text, entries)
        res = dedup_and_filter(res, text)
        with open(os.path.join("results/kb", f"{name}.json"), "w") as f:
            json.dump({"file": name, "kb_matches": res}, f, indent=2)
        print("✓", name, "-> results/kb/")
    print("Done.")
if __name__ == "__main__":
    main()
