# **XTRACTOR**
XTRACTOR is a fast, pluggable, and vulnerability-focused scanner built to extract exploitable HTML, JS, and CSS terms across web domains. Designed for bug bounty recon, red teaming, and offensive security automation.

## **Why XTRACTOR?**
- Web applications expose clues through their markup — things like <script>, onerror, or target="_blank" can signal real risks.

- XTRACTOR automates the detection and classification of these indicators, allowing ethical hackers to focus on chaining attack vectors instead of manually reviewing source code.

## **Key Capabilities**
- 🔍 Scans single or multiple domains

- 🧠 Links each found term to its possible vulnerability type

- 🛡 Detects missing headers like Content-Security-Policy and X-Frame-Options

- 🎨 Color-coded terminal output with optional file report

- 🧩 Easily extensible for other languages or frameworks

---
## Usage

```python
python3 xtractor.py -html -js -css -a -U urls.txt -o report.txt
```
## Options:

- -h, --help  show this help message and exit
- -html       Scan HTML terms
- -js         Scan JavaScript terms
- -css        Scan CSS terms
- -a          Scan all additional languages and logic maps
- -u U        Single URL to scan
- -U U        File containing list of URLs
- -o O        Output file to save results
![usage_ref](https://github.com/user-attachments/assets/f37dfdd8-24c9-4657-9b5d-cb2ea1ef31fb)
