#!/usr/bin/env python3
# run_ioc_batch_pre.py
import os, glob, json, importlib, sys, re, logging

# Add the local IOC-Finder package to the module search path
sys.path.insert(0, os.path.join(os.getcwd(), "Entity-Extraction", "IOC-Finder"))

from preprocess import load_and_clean_txt

logging.basicConfig(level=logging.INFO, format="%(message)s")

# ---------- De-defanging helpers ----------
def try_import_fanger():
    try:
        from ioc_fanger import ioc_fanger
        logging.info("ioc_fanger imported — will use de-defang.")
        return ioc_fanger
    except Exception as e:
        logging.info(f"ioc_fanger not available ({e}). Falling back to simple_defang().")
        return None

def simple_defang(txt: str) -> str:
    """
    Extended, conservative de-defang for common IOC obfuscations.
    """
    # hxxp / hxtp / h\xxp / etc.
    txt = re.sub(r'\bhx+\s*tp(s?)\s*[:／]//', r'http\1://', txt, flags=re.I)
    txt = re.sub(r'\bhxxps?\s*[:／]//', lambda m: 'https://' if 's' in m.group(0).lower() else 'http://', txt, flags=re.I)

    # [.] (.) {.} (dot) variants
    txt = re.sub(r'\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}', '.', txt)
    txt = re.sub(r'\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}', '.', txt, flags=re.I)
    txt = re.sub(r'\s+dot\s+', '.', txt, flags=re.I)
    txt = re.sub(r'\s*d0t\s*', '.', txt, flags=re.I)

    # obfuscated ':'
    txt = re.sub(r'\[\s*:\s*\]|\(\s*:\s*\)|\{\s*:\s*\}', ':', txt)

    # [at] → @
    txt = re.sub(r'\s*[\[\(\{]\s*at\s*[\]\)\}]\s*', '@', txt, flags=re.I)
    txt = re.sub(r'\s+at\s+', '@', txt, flags=re.I)  # "name at example" -> "name@example" (helps emails)

    # remove stray spaces inside obvious host patterns: "example . com"
    txt = re.sub(r'(\w)\s*\.\s*(\w)', r'\1.\2', txt)

    return txt

# ---------- Preprocess for IOC-Finder ----------
def preprocess_for_ioc(raw_text: str, fanger_module) -> str:
    text = raw_text

    # 1) Defang
    if fanger_module:
        try:
            text = fanger_module.fang(text)  # hxxp -> http, [.] -> .
        except Exception as e:
            logging.info(f"fanger.fang() failed: {e} — using simple_defang()")
            text = simple_defang(text)
    else:
        text = simple_defang(text)

    # 2) Map generic registry mentions to canonical paths so regex matches fire
    regy_phrases = [
        r'\bregistry\s+run(?:\s+and\s+runonce)?\s+keys?\b',
        r'\brun(?:once)?\s+keys?\b',
        r'\b(run|runonce)\s+key\b',
        r'\bregistry\s+(run|runonce)\b',
    ]
    text = re.sub(
        r'(' + r'|'.join(regy_phrases) + r')',
        r'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        text,
        flags=re.I
    )

    return text

# ---------- Registry normalization ----------
CANON_PREFIX = r'HK[LC]M?U\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?'

def _canon_hive(s: str) -> str:
    s = re.sub(r'^HKLM', 'HKLM', s, flags=re.I)
    s = re.sub(r'^HKCU', 'HKCU', s, flags=re.I)
    return s

def normalize_registry_keys(iocs: dict, located: dict) -> None:
    # Normalize list values
    cleaned = []
    for key in iocs.get("registry_key_paths", []):
        m = re.match(rf'^({CANON_PREFIX})\b', key, flags=re.I)
        if m:
            cleaned.append(_canon_hive(m.group(1)))
    iocs["registry_key_paths"] = sorted(set(cleaned))

    # Normalize located map keys (preserve spans)
    new_loc = {}
    for k, spans in (located.get("registry_key_paths", {}) or {}).items():
        m = re.match(rf'^({CANON_PREFIX})\b', k, flags=re.I)
        if m:
            canon = _canon_hive(m.group(1))
            new_loc.setdefault(canon, [])
            new_loc[canon].extend(spans)
    for k in new_loc:
        new_loc[k] = sorted(set(tuple(s) for s in new_loc[k]))
    located["registry_key_paths"] = new_loc

# ---------- Fallback extractor (regex) ----------
# Reasonable defaults; extend if you see additional patterns.
_DOMAIN_RE = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b',
    re.IGNORECASE
)
_EMAIL_RE = re.compile(
    r'\b[A-Z0-9._%+\-]+@(?:[A-Z0-9\-]+\.)+[A-Z]{2,24}\b',
    re.IGNORECASE
)
_IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
)

def fallback_extract(text: str):
    """
    Extract domains/emails/ipv4s/urls as a safety net if IOC-Finder misses them.
    We keep it conservative to avoid false positives; you can tighten/loosen as needed.
    """
    hits = {
        "domains": set(),
        "email_addresses": set(),
        "ipv4s": set(),
        "urls": set(),
    }
    for m in _EMAIL_RE.finditer(text):
        hits["email_addresses"].add(m.group(0))
    for m in _DOMAIN_RE.finditer(text):
        s = m.group(0)
        # Avoid capturing plain TLD-only or obvious non-host words (rare)
        if '.' in s and not s.endswith('.') and not s.startswith('.'):
            hits["domains"].add(s)
    for m in _IPV4_RE.finditer(text):
        hits["ipv4s"].add(m.group(0))

    # crude URL: scheme://host[/...]
    hits["urls"].update(
        re.findall(r'\bhttps?://[^\s\'")]+', text, flags=re.IGNORECASE)
    )

    # Return as lists
    return {k: sorted(v) for k, v in hits.items()}

def merge_fallback(iocs: dict, fb: dict):
    """
    Merge fallback results into IOC-Finder lists if they’re missing there.
    """
    for key in ("domains", "email_addresses", "ipv4s", "urls"):
        base = set(iocs.get(key, []))
        addl = set(fb.get(key, []))
        if addl:
            iocs[key] = sorted(base | addl)

# ---------- Main ----------
def main():
    os.makedirs("results/ioc", exist_ok=True)

    # Import the local ioc_finder
    m = importlib.import_module("ioc_finder.ioc_finder")
    logging.info(f"Using ioc_finder from: {m.__file__}")

    fanger = try_import_fanger()

    files = sorted(glob.glob("Dataset/Data/*.txt"))
    for fp in files:
        name = os.path.basename(fp)

        # load + clean, then preproc
        raw = load_and_clean_txt(fp)
        txt = preprocess_for_ioc(raw, fanger)

        # run IOC-Finder
        lists, located = m.find_iocs(txt)

        # merge fallback regex hits
        fb = fallback_extract(txt)
        merge_fallback(lists, fb)

        # registry normalization
        normalize_registry_keys(lists, located)

        out = {"file": name, "iocs": lists, "iocs_located": located}
        with open(os.path.join("results", "ioc", f"{name}.json"), "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)

        # quick per-file counts
        i = lists
        cves = len(i.get("cves", []))
        doms = len(i.get("domains", []))
        mails = len(i.get("email_addresses", [])) + len(i.get("email_addresses_complete", []))
        ips = len(i.get("ipv4s", []))
        urls = len(i.get("urls", []))
        logging.info(f"✓ {name} -> results/ioc/  (CVE:{cves} DOMAIN:{doms} EMAIL:{mails} IPV4:{ips} URL:{urls})")

    logging.info("Done.")

if __name__ == "__main__":
    main()
