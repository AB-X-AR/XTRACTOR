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
- git clone https://github.com/AB-X-AR/XTRACTOR.git
- cd XTRACTOR
- pip -r install requirements.txt
- chmod +x xtractor.py
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
- -f          Scan raw HTML files offline
- --json      Save results as structured JSON
- --html      Export a styled HTML report
---
## Use `-u` for single url or use `-U` for a list of urls 
![image](https://github.com/user-attachments/assets/a4d0ff83-d94c-436b-8361-0eb0c4ed988a)

## Use `-f` for Offline usage
![image](https://github.com/user-attachments/assets/ea3a9dd1-ea0a-4e9d-82b3-25ba92bbfe0e)


