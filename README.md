# Phishing URL Detector

A Python tool that scores URLs for phishing indicators using rule-based heuristics and explains why each URL was flagged.

## Features
- Applies 12 detection rules with weighted scoring (0-100)
- Classifies each URL as LOW, MEDIUM, or HIGH risk
- Gives a plain-English explanation for every rule that fires
- Defangs output URLs (`hxxp://example[.]com`) so they are safe to paste into tickets
- Supports single URLs, bulk files, and CSV export
- Standard library only, so there is nothing to install

## Requirements
- Python 3.8+

## Usage
```
python phishing_url_detector.py "http://paypa1-login.secure.example.xyz/verify"
python phishing_url_detector.py -f urls.txt
python phishing_url_detector.py -f urls.txt -o results.csv
```

For bulk mode, `urls.txt` contains one URL per line. Lines starting with `#` are ignored.

## Example Output
```
URL   : hxxp://paypa1-login[.]secure[.]example[.]xyz/verify
RISK  : HIGH  (score 65/100)
WHY   :
   - (+15) Suspicious top-level domain: .xyz
   - (+20) Credential-harvesting keywords: login, verify, secure
   - (+20) Lookalike of brand 'paypal' using character substitution ('paypa1')
   - (+10) Does not use HTTPS (scheme: http)
```

## Detection Rules

| # | Rule | Points |
|---|------|--------|
| 1 | Raw IP address as host | 30 |
| 2 | More than 3 subdomains | 15 |
| 3 | Suspicious TLD (.xyz, .top, .tk, ...) | 15 |
| 4 | `@` in the URL authority | 25 |
| 5 | URL shortener (bit.ly, tinyurl, ...) | 15 |
| 6 | Phishing keywords (login, verify, secure, ...) | 10 each, max 20 |
| 7 | URL over 75 characters / 3+ hyphens in host | 10 each |
| 8 | Punycode / digit-substitution lookalike (`paypa1`) | 20 each |
| 9 | No HTTPS | 10 |
| 10 | Brand name present but not the real domain | 25 |
| 11 | Double slash in path | 10 |
| 12 | Non-standard port | 10 |

**Thresholds:** 0-24 LOW, 25-49 MEDIUM, 50+ HIGH.

[Explain here why you chose these weights and thresholds.]

## Testing
Tested on [X] URLs ([X] phishing samples from PhishTank/OpenPhish, [X] legitimate URLs):
- Detection rate: [X]%
- False positive rate: [X]%

## Limitations
- Rule-based, so it can miss phishing hosted on compromised legitimate sites
- May flag legitimate long or unusual URLs
- Does not check live reputation or page content

## Future Improvements
- VirusTotal / URLScan.io lookups for MEDIUM+ results
- Domain age check via WHOIS
- Configurable rules via a config file

## Disclaimer
For educational and defensive use only.