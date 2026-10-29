"""Rule-based phishing URL detector. Scores URLs and explains each finding."""

import argparse
import csv
import ipaddress
import re
import sys
from datetime import datetime
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
    "work", "zip", "mov", "icu", "buzz", "rest", "support", "loan",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
}

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account",
    "banking", "confirm", "password", "suspend", "unlock", "wallet",
    "invoice", "payment", "billing", "recover", "authenticate",
]


BRANDS = [
    "paypal", "microsoft", "office365", "google", "apple", "amazon",
    "netflix", "facebook", "instagram", "linkedin", "dropbox",
    "docusign", "chase", "wellsfargo", "bankofamerica", "dhl", "fedex",
]


TWO_PART_SUFFIXES = {"co.uk", "com.au", "co.in", "com.np", "co.jp", "com.br", "org.uk"}


LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "$": "s"})

MAX_SUBDOMAINS = 3
MAX_URL_LENGTH = 75
MAX_HYPHENS = 3

LOW_THRESHOLD = 25
HIGH_THRESHOLD = 50

def normalize(url: str) -> str:
    """Add a scheme if missing so urlparse works correctly."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def split_host(host: str):
    """Return (subdomains list, registered domain label, tld)."""
    labels = host.lower().split(".")
    if len(labels) < 2:
        return [], host.lower(), ""
    last_two = ".".join(labels[-2:])
    if last_two in TWO_PART_SUFFIXES and len(labels) >= 3:
        return labels[:-3], labels[-3], last_two
    return labels[:-2], labels[-2], labels[-1]


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def defang(url: str) -> str:
    """Make a URL safe to paste into tickets."""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def analyze(raw_url: str) -> dict:
    """Run all rules against a URL. Returns score, risk level and findings."""
    url = normalize(raw_url)
    findings = [] 

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return {"url": raw_url, "score": 0, "risk": "INVALID",
                "findings": ["Could not parse URL"]}

    if not host:
        return {"url": raw_url, "score": 0, "risk": "INVALID",
                "findings": ["No hostname found"]}

    path_query = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    full_lower = url.lower()

    host_is_ip = is_ip(host)
    if host_is_ip:
        findings.append((30, "Host is a raw IP address instead of a domain name"))

    subdomains, reg_label, tld = ([], host, "") if host_is_ip else split_host(host)

    if len(subdomains) > MAX_SUBDOMAINS:
        findings.append((15, f"Excessive subdomains ({len(subdomains)} levels): "
                             f"often used to bury the real domain"))

    if tld in SUSPICIOUS_TLDS:
        findings.append((15, f"Suspicious top-level domain: .{tld}"))

    if "@" in parsed.netloc:
        findings.append((25, "Contains '@' in the authority section, which can hide the real destination"))

    if host in URL_SHORTENERS:
        findings.append((15, f"URL shortener ({host}) hides the final destination"))

    hits = [k for k in PHISHING_KEYWORDS if k in (host + path_query).lower()]
    if hits:
        pts = min(10 * len(hits), 20)
        findings.append((pts, "Credential-harvesting keywords: " + ", ".join(hits)))

    if len(url) > MAX_URL_LENGTH:
        findings.append((10, f"Very long URL ({len(url)} characters)"))

    if host.count("-") >= MAX_HYPHENS:
        findings.append((10, f"Many hyphens in hostname ({host.count('-')})"))

    if "xn--" in host:
        findings.append((20, "Punycode domain (xn--): possible lookalike/homograph attack"))

    if not host_is_ip:
        for label in [reg_label] + subdomains:
            for part in re.split(r"-", label):
                swapped = part.translate(LEET_MAP)
                if swapped != part and swapped in BRANDS:
                    findings.append((20, f"Lookalike of brand '{swapped}' using character "
                                         f"substitution ('{part}')"))
                    break

    if parsed.scheme != "https":
        findings.append((10, f"Does not use HTTPS (scheme: {parsed.scheme})"))

    if not host_is_ip:
        for brand in BRANDS:
            in_host_or_path = brand in host or brand in path_query.lower()
            if in_host_or_path and brand not in reg_label:
                findings.append((25, f"Brand '{brand}' appears in the URL but the real "
                                     f"domain is '{reg_label}.{tld}'"))
                break

    if "//" in parsed.path:
        findings.append((10, "Double slash in path, possible redirect trick"))

  
    if parsed.port and parsed.port not in (80, 443):
        findings.append((10, f"Non-standard port: {parsed.port}"))

    score = min(sum(p for p, _ in findings), 100)
    if score >= HIGH_THRESHOLD:
        risk = "HIGH"
    elif score >= LOW_THRESHOLD:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "url": raw_url,
        "score": score,
        "risk": risk,
        "findings": [f"(+{p}) {msg}" for p, msg in findings],
    }


def print_result(result: dict) -> None:
    print("=" * 70)
    print(f"URL   : {defang(result['url'])}")
    print(f"RISK  : {result['risk']}  (score {result['score']}/100)")
    if result["findings"]:
        print("WHY   :")
        for f in result["findings"]:
            print(f"   - {f}")
    else:
        print("WHY   : No suspicious indicators triggered")


def write_csv(results: list, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["timestamp", "url_defanged", "score", "risk", "findings"])
        now = datetime.now().isoformat(timespec="seconds")
        for r in results:
            writer.writerow([now, defang(r["url"]), r["score"], r["risk"],
                             " | ".join(r["findings"])])
    print(f"\nResults saved to {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Rule-based phishing URL detector")
    parser.add_argument("url", nargs="?", help="A single URL to analyze")
    parser.add_argument("-f", "--file", help="Text file with one URL per line")
    parser.add_argument("-o", "--output", help="Save results to a CSV file")
    args = parser.parse_args()

    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                urls += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except OSError as exc:
            print(f"Error reading {args.file}: {exc}", file=sys.stderr)
            return 1

    if not urls:
        parser.print_help()
        return 1

    results = [analyze(u) for u in urls]
    for r in results:
        print_result(r)

    counts = {k: sum(1 for r in results if r["risk"] == k) for k in ("HIGH", "MEDIUM", "LOW")}
    print("=" * 70)
    print(f"Summary: {len(results)} URLs | HIGH {counts['HIGH']} | "
          f"MEDIUM {counts['MEDIUM']} | LOW {counts['LOW']}")

    if args.output:
        write_csv(results, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())