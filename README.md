# **XTRACTOR**
XTRACTOR is a fast, pluggable, and vulnerability-focused scanner built to extract exploitable HTML, JS, and CSS terms across web domains. Designed for bug bounty recon, red teaming, and offensive security automation.

## **Why XTRACTOR?**
- Web applications expose clues through their markup — things like <script>, onerror, or target="_blank" can signal real risks.

- XTRACTOR automates the detection and classification of these indicators, allowing ethical hackers to focus on chaining attack vectors instead of manually reviewing source code.

## **Key Capabilities**
- 🔍 Scans single or multiple domains

- 📦 Modular VULN_MAP system (HTML, JS, CSS, PHP, SQL)

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

-u : Scan single domain

-U : Scan from file

-html, -js, -css, -a : Enable different VULN_MAPs

-o : Output results to a file
